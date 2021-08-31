//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of congestion control.

use std::{
    cmp::{max, min},
    pin::Pin,
    task::Poll,
};

use async_stream::stream;
use futures::{
    pin_mut,
    stream::{Stream, StreamExt},
    FutureExt,
};

use crate::{
    common::{exponential_moving_average, DataRate, DataSize, Duration, Instant, Square},
    transportcc::Ack,
};

mod ack_rates;
use ack_rates::*;

mod delay_directions;
use delay_directions::*;

mod feedback_rtts;
use feedback_rtts::*;

mod stream;
use stream::StreamExt as OurStreamExt;

pub struct CongestionController {
    acks_sender1: Sender<Vec<Ack>>,
    acks_sender2: Sender<Vec<Ack>>,
    acks_sender3: Sender<Vec<Ack>>,
    target_send_rates: Pin<Box<dyn Stream<Item = DataRate> + Send>>,
}

impl CongestionController {
    pub fn new(initial_target_send_rate: DataRate, now: Instant) -> Self {
        //                                       Acks
        //                                        |
        //             +--------------------------+--------------------------+
        //             |                          |                          |
        // +-----------v------------+ +-----------v------------+ +-----------v-----------+
        // | estimate_feedback_rtts | | accumulate_acked_sizes | | accumulate_ack_groups |
        // +-----------+------------+ +-----------+------------+ +-----------+-----------+
        //             |                          |                          |
        //             |               +----------v-----------+   +----------v-----------+
        //             |               | estimate_acked_rates |   | calculate_ack_deltas |
        //             |               +----------+-----------+   +----------+-----------+
        //             |                          |                          |
        //             |                          |             +------------v-----------+
        //             |                          |             | calculate_delay_slopes |
        //             |                          |             +------------+-----------+
        //             +---------------+          |                          |
        //                             |          |         +----------------v-----------+
        //                             |          |         | calculate_delay_directions |
        //                             |          |         +----------------+-----------+
        //                             |          |                          |
        //                             |          |        +-----------------+
        //                             |          |        |
        //                        +----v----------v--------v----+
        //                        | calculate_target_send_rates |
        //                        +-----------------------------+
        let (acks_sender1, ack_reports1) = unbounded_channel_that_must_not_fail();
        let (acks_sender2, ack_reports2) = unbounded_channel_that_must_not_fail();
        let (acks_sender3, ack_reports3) = unbounded_channel_that_must_not_fail();
        let feedback_rtts = estimate_feedback_rtts(ack_reports1);
        let acked_rates = estimate_acked_rates(ack_reports2.flat_map(futures::stream::iter));
        let delay_directions =
            calculate_delay_directions(ack_reports3.flat_map(futures::stream::iter));
        let target_send_rates = calculate_target_send_rates(
            initial_target_send_rate,
            now,
            feedback_rtts.latest_only(),
            acked_rates.latest_only(),
            delay_directions.latest_only(),
        );

        Self {
            acks_sender1,
            acks_sender2,
            acks_sender3,
            target_send_rates: Box::pin(target_send_rates.latest_only()),
        }
    }

    pub fn recalculate_target_send_rate(&mut self, mut acks: Vec<Ack>) -> Option<DataRate> {
        if acks.is_empty() {
            return None;
        }

        // TODO: See if we can get rid of these clones.
        acks.sort_by_key(|ack| ack.arrival);
        self.acks_sender1.send(acks.clone());
        self.acks_sender2.send(acks.clone());
        self.acks_sender3.send(acks);
        self.target_send_rates
            .next()
            .now_or_never()
            .map(|next| next.expect("stream should never end"))
    }
}

// Yields target send rates
fn calculate_target_send_rates(
    initial_target_send_rate: DataRate,
    start_time: Instant,
    feedback_rtts: impl Stream<Item = Duration>,
    acked_rates: impl Stream<Item = DataRate>,
    delay_directions: impl Stream<Item = (Instant, DelayDirection)>,
) -> impl Stream<Item = DataRate> {
    // TODO: Maybe make some of these configurable (especially min/max bitrates)
    let min_target_send_rate = DataRate::from_kbps(5);
    let max_target_send_rate = DataRate::from_kbps(5000);
    let multiplicative_increase_per_second: f64 = 0.08;
    let min_multiplicative_increase = DataRate::from_kbps(1);
    let additive_increase_per_rtt = DataSize::from_bytes(1200);
    let additive_increase_rtt_pad = Duration::from_millis(100);
    let min_additive_increase_per_second = DataRate::from_kbps(4);
    let min_rtt_for_decrease = Duration::from_millis(10);
    let max_rtt_for_decrease = Duration::from_millis(200);
    let decrease_from_acked_rate_multiplier = 0.85;

    // If we didn't have an initial_rate, we'd have to do something like this:
    // let first_acked_rate_time = None
    // if target_send_rate.is_none() && acked_rate.is_some() {
    //     let acked_rate_age = now - first_acked_rate_time.get_or_insert(now);
    //     if acked_rate_age > Duration::from_secs(5) {
    //         target_send_rate = acked_rate;
    //     }
    // }

    stream! {
        let mut rtt = Duration::from_millis(100); // This shouldn't ever be used.
        let mut acked_rate = None;
        let mut previous_direction = None;
        let mut acked_rate_when_overusing = RateAverager::new();
        let mut target_send_rate = initial_target_send_rate;
        let mut target_send_rate_updated = start_time;

        pin_mut!(feedback_rtts);
        pin_mut!(acked_rates);
        pin_mut!(delay_directions);
        while let Some((now, direction)) = delay_directions.next().await {
            // Allow either of these streams to still be pending, in which case we use the
            // value recorded from the last loop.
            rtt = feedback_rtts
                .next()
                .now_or_never()
                .map(|next| next.expect("stream should not end before delay_directions"))
                .unwrap_or(rtt);
            acked_rate = acked_rates
                .next()
                .now_or_never()
                .map(|next| next.expect("stream should not end before delay_directions"))
                .or(acked_rate);
            match direction {
                DelayDirection::Decreasing => {
                    // While the delay is decreasing, hold the target rate to let the queues drain.
                    // The non-update of target_send_rate_updated is intentional.
                }
                DelayDirection::Steady => {
                    // While delay is steady, increase the target rate.
                    if let Some(acked_rate) = acked_rate {
                        acked_rate_when_overusing.reset_if_sample_out_of_bounds(acked_rate);
                    }

                    let increase_duration = if previous_direction != Some(DelayDirection::Steady) {
                        // This is a strange thing where the first "steady" we have after an
                        // increase/decrease basically only increases the rate a little or not at
                        // all. This is because we don't know how long it's been steady.
                        Duration::default()
                    } else {
                        now.saturating_duration_since(target_send_rate_updated)
                    };
                    // If we don't have a good average acked_rate when overusing, use a faster increase (8% per second)
                    // Otherwise, use a slower increase (1200 bytes per RTT).
                    let should_do_multiplicative_increase =
                        acked_rate_when_overusing.average().is_none();
                    let increase = if should_do_multiplicative_increase {
                        let multiplier = (1.0 + multiplicative_increase_per_second)
                            .powf(increase_duration.as_secs_f64().min(1.0))
                            - 1.0;
                        max(min_multiplicative_increase, target_send_rate * multiplier)
                    } else {
                        let padded_rtt = rtt + additive_increase_rtt_pad;
                        let increase_per_second = max(
                            min_additive_increase_per_second,
                            additive_increase_per_rtt / padded_rtt,
                        );
                        increase_per_second * increase_duration.as_secs_f64()
                    };
                    let mut increased_rate = target_send_rate + increase;
                    // If we have an acked_rate, never increase over 150% of it.
                    if let Some(acked_rate) = acked_rate {
                        let acked_rate_based_limit = (acked_rate * 1.5) + DataRate::from_kbps(10);
                        increased_rate = min(acked_rate_based_limit, increased_rate);
                    }
                    // Don't end up decreasing when we were supposed to increase.
                    increased_rate = max(target_send_rate, increased_rate);
                    target_send_rate =
                        increased_rate.clamp(min_target_send_rate, max_target_send_rate);
                    target_send_rate_updated = now;
                    yield target_send_rate;
                }
                DelayDirection::Increasing => {
                    // If the delay is increasing, decrease the rate.
                    if let Some(acked_rate) = acked_rate {
                        // We have an acked rate, so reduce based on that.
                        if (now
                            >= target_send_rate_updated
                                + rtt.clamp(min_rtt_for_decrease, max_rtt_for_decrease))
                            || (acked_rate <= target_send_rate * 0.5)
                        {
                            let mut decreased_rate =
                                acked_rate * decrease_from_acked_rate_multiplier;
                            if decreased_rate > target_send_rate {
                                if let Some(average_acked_rate_when_overusing) =
                                    acked_rate_when_overusing.average()
                                {
                                    decreased_rate = average_acked_rate_when_overusing
                                        * decrease_from_acked_rate_multiplier;
                                }
                            }
                            // Don't accidentally increase the estimated rate!
                            decreased_rate = min(target_send_rate, decreased_rate);

                            target_send_rate =
                                decreased_rate.clamp(min_target_send_rate, max_target_send_rate);
                            target_send_rate_updated = now;
                            yield target_send_rate;

                            acked_rate_when_overusing.reset_if_sample_out_of_bounds(acked_rate);
                            acked_rate_when_overusing.add_sample(acked_rate);
                        } else {
                            // Wait until the next period that we're increasing to decrease (or until the acked_rate drops).
                            // The non-update of the estimate_updated is intentional.
                        }
                    } else {
                        // We're increasing before we even have an acked rate.  Aggressively reduce.
                        let half_rate = target_send_rate / 2.0;
                        target_send_rate =
                            half_rate.clamp(min_target_send_rate, max_target_send_rate);
                        target_send_rate_updated = now;
                        yield target_send_rate;
                    }
                }
            }

            previous_direction = Some(direction);
        }
    }
}

#[cfg(test)]
mod calculate_target_send_rates_tests {
    use futures::future::ready;
    use unzip3::Unzip3;

    use super::*;

    fn instants_at_regular_intervals(
        start: Instant,
        interval: Duration,
    ) -> impl Stream<Item = Instant> {
        futures::stream::iter(std::iter::successors(Some(start), move |now| {
            Some(*now + interval)
        }))
    }

    // These are glass-box tests; they should not fail if the implementation is changed,
    // but additional tests may be necessary to regain coverage.
    // Many of them include contrived scenarios that aren't possible with real Acks.

    #[test]
    fn decrease_holds_steady() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::from_millis(100)),
            futures::stream::repeat(initial_rate),
            futures::stream::repeat((start_time, DelayDirection::Decreasing)).take(100),
        );

        assert_eq!(
            &[] as &[DataRate],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );

        // Try again without any acks.
        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::from_millis(100)),
            futures::stream::pending(),
            futures::stream::repeat((start_time, DelayDirection::Decreasing)).take(100),
        );

        assert_eq!(
            &[] as &[DataRate],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );
    }

    #[test]
    fn increase_without_acks_cuts_aggressively() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::from_millis(100)),
            futures::stream::pending(),
            futures::stream::repeat((start_time, DelayDirection::Increasing)).take(10),
        );

        assert_eq!(
            &[50_000, 25_000, 12_500, 6_250, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_is_okay_for_short_intervals_if_acks_are_keeping_up() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::from_millis(100)),
            futures::stream::repeat(initial_rate),
            // "short intervals" in this case is "zero interval"
            futures::stream::repeat((start_time, DelayDirection::Increasing)).take(5),
        );

        assert_eq!(
            &[] as &[DataRate],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );
    }

    #[test]
    fn increase_over_long_intervals_cuts_based_on_ack_rate() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(initial_rate),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::repeat(DelayDirection::Increasing))
                .take(10),
        );

        assert_eq!(
            &[85_000, 85_000, 85_000, 85_000, 85_000, 85_000, 85_000, 85_000, 85_000, 85_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_with_low_ack_rate_cuts_based_on_ack_rate() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(initial_rate / 2.0),
            futures::stream::repeat((start_time, DelayDirection::Increasing)).take(5),
        );

        assert_eq!(
            &[42_500],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_with_single_high_ack_rate_should_still_cut() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::iter([10, 10, 10, 10, 100]).map(DataRate::from_kbps),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::repeat(DelayDirection::Increasing))
                .take(5),
        );

        // This isn't conclusive: it might be using the average rate,
        // or it might just be checking that the rate shouldn't increase.
        // Tests below mix "increasing" and "steady" feedback to check more precisely.
        assert_eq!(
            &[8_500, 8_500, 8_500, 8_500, 8_500],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_should_never_grow_the_target_rate() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            // ...no matter how nonsense our acks are.
            futures::stream::repeat(DataRate::from_kbps(1_000)),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::repeat(DelayDirection::Increasing))
                .take(5),
        );

        assert_eq!(
            &[100_000, 100_000, 100_000, 100_000, 100_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_rtt_determines_interval() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(DataRate::from_kbps(100)),
            futures::stream::once(ready((
                start_time + interval - Duration::from_millis(1),
                DelayDirection::Increasing,
            ))),
        );

        assert_eq!(
            &[] as &[DataRate],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval / 2),
            futures::stream::repeat(DataRate::from_kbps(100)),
            futures::stream::once(ready((
                start_time + (interval / 2),
                DelayDirection::Increasing,
            ))),
        );

        assert_eq!(
            &[85_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );

        // There is a minimum, though...
        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::ZERO),
            futures::stream::repeat(DataRate::from_kbps(100)),
            futures::stream::once(ready((start_time, DelayDirection::Increasing))),
        );

        assert_eq!(
            &[] as &[DataRate],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );

        // ...as well as a maximum.
        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(Duration::from_secs(1)),
            futures::stream::repeat(DataRate::from_kbps(100)),
            futures::stream::once(ready((
                start_time + Duration::from_millis(500),
                DelayDirection::Increasing,
            ))),
        );

        assert_eq!(
            &[85_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn increase_can_cut_by_average_if_current_ack_rate_is_too_high() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let (rates, directions, expected_bps): (Vec<_>, Vec<_>, Vec<_>) = [
            (100, DelayDirection::Increasing, 85_000), // cut based on current (no average)
            (85, DelayDirection::Steady, 85_000),      // hold steady for one interval
            (85, DelayDirection::Steady, 89_800),      // increase additively
            (110, DelayDirection::Increasing, 85_000), // cut based on prior ack average instead of current
        ]
        .iter()
        .copied()
        .unzip3();

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::iter(rates).map(DataRate::from_kbps),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::iter(directions)),
        );

        assert_eq!(
            &expected_bps,
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()
        );
    }

    #[test]
    fn steady_should_grow_multiplicatively_without_acks() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::pending(),
            instants_at_regular_intervals(start_time + Duration::SECOND, Duration::SECOND)
                .zip(futures::stream::repeat(DelayDirection::Steady))
                .take(5),
        );

        assert_eq!(
            // The first "Steady" is treated specially since we don't know how long
            // it's been since it went steady. We get a default increase instead.
            &[101_000, 109_080, 117_806, 127_230, 137_408],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn steady_growth_is_limited_by_ack_rate() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(DataRate::from_kbps(67)),
            instants_at_regular_intervals(start_time + Duration::SECOND, Duration::SECOND)
                .zip(futures::stream::repeat(DelayDirection::Steady))
                .take(5),
        );

        assert_eq!(
            // Can't go higher because of the ack rate.
            &[101_000, 109_080, 110_500, 110_500, 110_500],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );

        // Try again with an even lower ack rate.
        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(DataRate::from_kbps(50)),
            instants_at_regular_intervals(start_time + Duration::SECOND, Duration::SECOND)
                .zip(futures::stream::repeat(DelayDirection::Steady))
                .take(5),
        );

        assert_eq!(
            // Can't go higher because of the ack rate.
            // Can't go lower than the start rate.
            &[100_000, 100_000, 100_000, 100_000, 100_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn steady_growth_has_maximum() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::pending(),
            instants_at_regular_intervals(start_time + Duration::SECOND, Duration::SECOND)
                .zip(futures::stream::repeat(DelayDirection::Steady))
                .take(10_000),
        );

        async move {
            pin_mut!(stream);
            let mut prev = stream.next().await.unwrap();
            let mut has_stopped_increasing = false;
            while let Some(next) = stream.next().await {
                match prev.cmp(&next) {
                    std::cmp::Ordering::Less => {
                        assert!(!has_stopped_increasing, "rate should never increase again");
                    }
                    std::cmp::Ordering::Equal => {
                        has_stopped_increasing = true;
                    }
                    std::cmp::Ordering::Greater => {
                        panic!("rate should never decrease")
                    }
                }
                prev = next;
            }
            assert!(has_stopped_increasing);
        }
        .now_or_never()
        .unwrap();
    }

    #[test]
    fn steady_should_grow_additively_after_overuse() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::repeat(initial_rate),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(
                    futures::stream::once(ready(DelayDirection::Increasing))
                        .chain(futures::stream::repeat(DelayDirection::Steady)),
                )
                .take(7),
        );

        assert_eq!(
            // Reduce for the first "Increasing", pause for the first "Steady",
            // then increase additively from then on.
            &[85_000, 85_000, 89_800, 94_600, 99_400, 104_200, 109_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn steady_should_grow_additively_after_overuse_with_minimum() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::from_millis(100);

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            // One proper RTT for the "Increasing" feedback, then some ridiculous RTT for "Steady"
            futures::stream::once(ready(interval))
                .chain(futures::stream::repeat(Duration::from_secs(10))),
            futures::stream::repeat(initial_rate),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(
                    futures::stream::once(ready(DelayDirection::Increasing))
                        .chain(futures::stream::repeat(DelayDirection::Steady)),
                )
                .take(7),
        );

        assert_eq!(
            // Reduce for the first "Increasing", pause for the first "Steady",
            // then increase additively from then on.
            &[85_000, 85_000, 85_400, 85_800, 86_200, 86_600, 87_000],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn acked_rate_resets_on_outliers() {
        let start_time = Instant::now();
        let initial_rate = DataRate::from_kbps(100);
        let interval = Duration::SECOND;

        let (rates, directions, expected_bps): (Vec<_>, Vec<_>, Vec<_>) = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (0, DelayDirection::Steady, 85_000),       // hold steady for one interval
            (100, DelayDirection::Steady, 91_800), // increase multiplicatively due to ack rate outlier
            (100, DelayDirection::Steady, 99_144), // increase multiplicatively due to ack rate outlier
        ]
        .iter()
        .copied()
        .unzip3();

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::iter(rates).map(DataRate::from_kbps),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::iter(directions)),
        );

        assert_eq!(
            &expected_bps,
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()
        );

        let (rates, directions, expected_bps): (Vec<_>, Vec<_>, Vec<_>) = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (100_000, DelayDirection::Steady, 86_000), // minimum multiplicative increase for the first interval
            (100, DelayDirection::Steady, 92_880), // increase multiplicatively due to ack rate outlier
            (100, DelayDirection::Steady, 100_310), // increase multiplicatively due to ack rate outlier
        ]
        .iter()
        .copied()
        .unzip3();

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::iter(rates).map(DataRate::from_kbps),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::iter(directions)),
        );

        assert_eq!(
            &expected_bps,
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()
        );

        // We can't (separately) test the case when the ack rate drops drastically while the delay
        // is still increasing because once it goes steady, a low ack rate will limit the growth,
        // and a high ack rate will count as an outlier again. But we can test the case where it
        // *jumps* drastically.
        let (rates, directions, expected_bps): (Vec<_>, Vec<_>, Vec<_>) = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (100_000, DelayDirection::Increasing, 85_000), // ack rate went up so we don't actually decrease
            (100_000, DelayDirection::Steady, 85_000),     // hold steady for one interval
            (100_000, DelayDirection::Steady, 93_727), // ack rate was reset but it's still present
            (100_000, DelayDirection::Steady, 102_454), // so these increase additively
        ]
        .iter()
        .copied()
        .unzip3();

        let stream = calculate_target_send_rates(
            initial_rate,
            start_time,
            futures::stream::repeat(interval),
            futures::stream::iter(rates).map(DataRate::from_kbps),
            instants_at_regular_intervals(start_time + interval, interval)
                .zip(futures::stream::iter(directions)),
        );

        assert_eq!(
            &expected_bps,
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()
        );
    }
}

struct RateAverager {
    average: Option<DataRate>,
    // Note that this is the *relative* variance, equal to the variance divided by the mean.
    // The values for the initial, min, and max are calibrated for kbps.
    variance: DataRate,
}

// Maybe make these things configurable: alpha, initial/min/max variance, number
// of standard deviations for the "reset bounds"
impl RateAverager {
    fn new() -> Self {
        Self {
            average: None,
            variance: DataRate::from_bps(400),
        }
    }

    fn add_sample(&mut self, sample: DataRate) {
        let alpha = 0.05;
        let average = if let Some(average) = self.average {
            exponential_moving_average(average, alpha, sample)
        } else {
            sample
        };

        self.average = Some(average);
        self.variance = {
            // Do the calculation in bps f64 space.
            let var = self.variance.as_bps() as f64;
            let avg = average.as_bps() as f64;
            let sample = sample.as_bps() as f64;
            let var = (((1.0 - alpha) * var) + (alpha * (avg - sample).square() / avg.max(1.0)))
                .clamp(400.0, 2500.0);
            DataRate::from_bps(var as u64)
        };
    }

    // Does not add sample.
    fn reset_if_sample_out_of_bounds(&mut self, sample: DataRate) {
        if let Some(average) = self.average {
            let relative_bound = {
                // Do the calculation in bps f64 space.
                let var = self.variance.as_bps() as f64;
                let avg = average.as_bps() as f64;
                let bound = 3.0 * (var * avg).sqrt();
                DataRate::from_bps(bound as u64)
            };
            if sample > (average + relative_bound)
                || sample < average.saturating_sub(relative_bound)
            {
                *self = Self::new();
            }
        }
    }

    fn average(&self) -> Option<DataRate> {
        self.average
    }
}

#[cfg(test)]
mod rate_averager_tests {
    use super::*;

    #[test]
    fn new_has_no_average() {
        let averager = RateAverager::new();
        assert_eq!(None, averager.average());
    }

    #[test]
    fn first_sample_sets_baseline() {
        let mut averager = RateAverager::new();
        let sample = DataRate::from_bps(1_234_567);
        averager.add_sample(sample);
        assert_eq!(Some(sample), averager.average());
    }

    #[test]
    fn further_samples_converge() {
        let mut averager = RateAverager::new();

        averager.add_sample(DataRate::from_bps(1_000));
        averager.add_sample(DataRate::from_bps(2_000));
        let average = averager.average().unwrap();
        assert!(average > DataRate::from_bps(1_000), "{:?}", average);
        // Assume we never want to bias towards new samples over our running average.
        assert!(average < DataRate::from_bps(1_500), "{:?}", average);

        // Continue sampling 2,000 until we get as close as interpolation will let us.
        let mut i = 0;
        while averager.average().unwrap() < DataRate::from_bps(1_980) {
            assert!(i < 10_000, "not converging fast enough");
            averager.add_sample(DataRate::from_bps(2_000));
            i += 1;
        }
    }

    #[test]
    fn non_outliers_do_not_reset() {
        let mut averager = RateAverager::new();
        averager.add_sample(DataRate::from_bps(10_000));
        assert!(averager.average().is_some());

        averager.reset_if_sample_out_of_bounds(DataRate::from_bps(10_000));
        assert!(averager.average().is_some());
        averager.reset_if_sample_out_of_bounds(DataRate::from_bps(9_000));
        assert!(averager.average().is_some());
        averager.reset_if_sample_out_of_bounds(DataRate::from_bps(11_000));
        assert!(averager.average().is_some());
    }

    #[test]
    fn obvious_outliers_cause_reset() {
        let mut averager = RateAverager::new();

        averager.add_sample(DataRate::from_bps(10_000));
        assert!(averager.average().is_some());
        averager.reset_if_sample_out_of_bounds(DataRate::from_bps(1_000));
        assert_eq!(None, averager.average());

        averager.add_sample(DataRate::from_bps(10_000));
        assert!(averager.average().is_some());
        averager.reset_if_sample_out_of_bounds(DataRate::from_bps(100_000));
        assert_eq!(None, averager.average());
    }
}

fn unbounded_channel_that_must_not_fail<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = futures::channel::mpsc::unbounded();
    (Sender(sender), Receiver(receiver))
}

struct Sender<T>(futures::channel::mpsc::UnboundedSender<T>);

impl<T> Sender<T> {
    fn send(&mut self, msg: T) {
        self.0
            .unbounded_send(msg)
            .expect("channel closed (maybe the receiver was dropped)")
    }
}

struct Receiver<T>(futures::channel::mpsc::UnboundedReceiver<T>);

impl<T> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx)
    }
}
