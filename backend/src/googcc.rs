//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of congestion control.

use std::cmp::{max, min};

use calling_common::{exponential_moving_average, DataRate, DataSize, Duration, Instant, Square};

use crate::transportcc::Ack;

mod ack_rates;
use ack_rates::*;

mod delay_directions;
use delay_directions::*;

mod feedback_rtts;
use feedback_rtts::*;

#[derive(Clone, Debug)]
pub struct Config {
    pub initial_target_send_rate: DataRate,
    pub min_target_send_rate: DataRate,
    pub max_target_send_rate: DataRate,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // This is also used when we go from limited by the ideal send rate
            // to not limited by the ideal send rate.
            // We want it high enough to get a good experience,
            // but not too high to risk overuse.
            // Seeing one video at VGA is around 800kbps.
            // Seeing 4 videos at QVGA is around 800kbps total.
            // Seeing 16 videos at QQVGA is around 800kbps total.
            initial_target_send_rate: DataRate::from_kbps(800),
            min_target_send_rate: DataRate::from_kbps(100),
            max_target_send_rate: DataRate::from_kbps(30000),
        }
    }
}

impl Config {
    fn clamp_target_send_rate(&self, target_send_rate: DataRate) -> DataRate {
        target_send_rate.clamp(self.min_target_send_rate, self.max_target_send_rate)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Request {
    // If we're below this, try to ramp up to it quickly.
    pub base: DataRate,
    // There's no point going much above this.
    // It's effectively a max, but we have to leave some
    // headroom above it so that fluctuations in the
    // rate won't cause us to send below rate when
    // we otherwise would be able to.  Doing so can cause
    // annoying flucutations in which video layer
    // is forwarded.
    pub ideal: DataRate,
}

pub struct CongestionController {
    current_request: Option<Request>,
    acked_rates: AckRatePipeline,
    feedback_rtt: FeedbackRttEstimator,
    delay_directions: DelayDirectionPipeline,
    calculator: TargetCalculator,
}

impl CongestionController {
    pub fn new(config: Config, now: Instant) -> Self {
        //                                       Acks                                    Latest Request
        //                                        |                                            |
        //             +--------------------------+--------------------------+                 |
        //             |                          |                          |                 |
        // +-----------v------------+ +-----------v------------+ +-----------v-----------+     |
        // | estimate_feedback_rtts | | accumulate_acked_sizes | | accumulate_ack_groups |     |
        // +-----------+------------+ +-----------+------------+ +-----------+-----------+     |
        //             |                          |                          |                 |
        //             |               +----------v-----------+   +----------v-----------+     |
        //             |               | estimate_acked_rates |   | calculate_ack_deltas |     |
        //             |               +----------+-----------+   +----------+-----------+     |
        //             |                          |                          |                 |
        //             |                          |             +------------v-----------+     |
        //             |                          |             | calculate_delay_slopes |     |
        //             |                          |             +------------+-----------+     |
        //             +---------------+          |                          |                 |
        //                             |          |         +----------------v-----------+     |
        //                             |          |         | calculate_delay_directions |     |
        //                             |          |         +----------------+-----------+     |
        //                             |          |                          |                 |
        //                             |          |        +-----------------+                 |
        //                             |          |        |                                   |
        //                        +----v----------v--------v----+                              |
        //                        | calculate_target_send_rates <------------------------------+
        //                        +-----------------------------+
        let feedback_rtt = FeedbackRttEstimator::new();
        let acked_rates = AckRatePipeline::default();
        let delay_directions = DelayDirectionPipeline::default();
        let calculator = TargetCalculator::new(config, now);

        Self {
            current_request: None,
            feedback_rtt,
            acked_rates,
            delay_directions,
            calculator,
        }
    }

    pub fn request(&mut self, request: Request) {
        self.current_request = Some(request);
    }

    pub fn recalculate_target_send_rate(&mut self, mut acks: Vec<Ack>) -> Option<DataRate> {
        if acks.is_empty() {
            return None;
        }

        acks.sort_by_key(|ack| ack.arrival);
        let delay_direction = self.delay_directions.next(&acks);
        let rtt = self.feedback_rtt.next(&acks);
        let acked_rate = self.acked_rates.next(&acks);

        self.calculator
            .next(&mut self.current_request, delay_direction, rtt, acked_rate)
    }

    pub fn rtt(&self) -> Duration {
        self.calculator.rtt
    }
}

struct TargetCalculator {
    acked_rate: Option<DataRate>,
    acked_rate_when_overusing: RateAverager,
    config: Config,
    previous_direction: Option<DelayDirection>,
    requested: Request,
    rtt: Duration,
    target_send_rate: DataRate,
    target_send_rate_updated: Instant,
}

impl TargetCalculator {
    fn new(config: Config, start_time: Instant) -> Self {
        Self {
            acked_rate: None,
            acked_rate_when_overusing: RateAverager::new(),
            previous_direction: None,
            requested: Request {
                // Basically use the config.initial_target_send_rate instead.
                base: DataRate::ZERO,
                // Basically uncapped until we receive a request.
                ideal: config.max_target_send_rate,
            },
            rtt: FEEDBACK_RTTS_DEFAULT,
            target_send_rate: config.initial_target_send_rate,
            target_send_rate_updated: start_time,
            config,
        }
    }

    fn next(
        &mut self,
        request: &mut Option<Request>,
        delay_directions: Option<(Instant, DelayDirection)>,
        rtt: Duration,
        acked_rate: Option<DataRate>,
    ) -> Option<DataRate> {
        const MULTIPLICATIVE_INCREASE_PER_SECOND: f64 = 0.08;
        const MIN_MULTIPLICATIVE_INCREASE: DataRate = DataRate::from_kbps(1);
        const ADDITIVE_INCREASE_PER_RTT: DataSize = DataSize::from_bytes(1200);
        const ADDITIVE_INCREASE_RTT_PAD: Duration = Duration::from_millis(100);
        const MIN_ADDITIVE_INCREASE_PER_SECOND: DataRate = DataRate::from_kbps(4);
        const MIN_RTT_FOR_DECREASE: Duration = Duration::from_millis(10);
        const MAX_RTT_FOR_DECREASE: Duration = Duration::from_millis(200);
        const DECREASE_FROM_ACKED_RATE_MULTIPLIER: f64 = 0.85;

        self.rtt = rtt;

        if let Some(acked_rate) = acked_rate {
            self.acked_rate = Some(acked_rate);
        }

        if let Some((now, direction)) = delay_directions {
            let mut reset_to_initial = false;
            if let Some(request) = request.take() {
                let previously_requested = std::mem::replace(&mut self.requested, request);
                // We pick a value that is a common threshold for a client requesting very little,
                // such as one video at the lowest resolution.  Anything smaller than that is
                // considered low enough that googcc can't operate well (at least until we add probing)
                // So when we transition out of such a state, we reset googcc.
                let tiny_send_rate: DataRate = DataRate::from_kbps(150);
                let previous_ideal_was_tiny = previously_requested.ideal <= tiny_send_rate;
                let current_ideal_is_tiny = self.requested.ideal <= tiny_send_rate;
                let initial_target_send_rate = max(
                    self.config.initial_target_send_rate,
                    self.requested.base * 0.5,
                );
                let target_below_initial = self.target_send_rate < initial_target_send_rate;
                if previous_ideal_was_tiny && !current_ideal_is_tiny && target_below_initial {
                    // We were previously limited by a tiny ideal send rate,
                    // but are no longer, and we're below the initial send
                    // rate, so it's like we've started all over.
                    // Might as well just jump up to the initial rate.
                    self.target_send_rate = initial_target_send_rate;
                    reset_to_initial = true;
                }
            }

            let changed_target_send_rate: Option<DataRate> = match direction {
                DelayDirection::Decreasing => {
                    // While the delay is decreasing, hold the target rate to let the queues drain.
                    // The non-update of target_send_rate_updated is intentional.
                    None
                }
                DelayDirection::Steady => {
                    // While delay is steady, increase the target rate.
                    if let Some(acked_rate) = self.acked_rate {
                        self.acked_rate_when_overusing
                            .reset_if_sample_out_of_bounds(acked_rate);
                    }

                    let increase_duration =
                        if self.previous_direction != Some(DelayDirection::Steady) {
                            // This is a strange thing where the first "steady" we have after an
                            // increase/decrease basically only increases the rate a little or not at
                            // all. This is because we don't know how long it's been steady.
                            Duration::ZERO
                        } else {
                            now.saturating_duration_since(self.target_send_rate_updated)
                        };
                    // If we don't have a good average acked_rate when overusing,
                    // use a faster increase (8%-16% per second)
                    // Otherwise, use a slower increase (1200 bytes per RTT).
                    let should_do_multiplicative_increase =
                        self.acked_rate_when_overusing.average().is_none();
                    let increase = if should_do_multiplicative_increase {
                        let multiplicative_increase_per_second =
                            if self.target_send_rate < self.requested.base {
                                // If we're below the requested base rate, increase more aggressively
                                MULTIPLICATIVE_INCREASE_PER_SECOND * 2.0
                            } else {
                                MULTIPLICATIVE_INCREASE_PER_SECOND
                            };
                        let multiplier = (1.0 + multiplicative_increase_per_second)
                            .powf(increase_duration.as_secs_f64().min(1.0))
                            - 1.0;
                        max(
                            MIN_MULTIPLICATIVE_INCREASE,
                            self.target_send_rate * multiplier,
                        )
                    } else {
                        let padded_rtt = rtt + ADDITIVE_INCREASE_RTT_PAD;
                        let increase_per_second = max(
                            MIN_ADDITIVE_INCREASE_PER_SECOND,
                            ADDITIVE_INCREASE_PER_RTT / padded_rtt,
                        );
                        increase_per_second * increase_duration.as_secs_f64()
                    };
                    let mut increased_rate = self.target_send_rate + increase;
                    // If we have an acked_rate, never increase over 150% of it.
                    if let Some(acked_rate) = self.acked_rate {
                        let acked_rate_based_limit = (acked_rate * 1.5) + DataRate::from_kbps(10);
                        increased_rate = min(acked_rate_based_limit, increased_rate);
                    }
                    // Don't end up decreasing when we were supposed to increase.
                    let increased_rate = max(self.target_send_rate, increased_rate);
                    Some(increased_rate)
                }
                DelayDirection::Increasing => {
                    // If the delay is increasing, decrease the rate.
                    if let Some(acked_rate) = self.acked_rate {
                        // We have an acked rate, so reduce based on that.
                        if (now
                            >= self.target_send_rate_updated
                                + rtt.clamp(MIN_RTT_FOR_DECREASE, MAX_RTT_FOR_DECREASE))
                            || (acked_rate <= self.target_send_rate * 0.5)
                        {
                            let mut decreased_rate =
                                acked_rate * DECREASE_FROM_ACKED_RATE_MULTIPLIER;
                            if decreased_rate > self.target_send_rate {
                                if let Some(average_acked_rate_when_overusing) =
                                    self.acked_rate_when_overusing.average()
                                {
                                    decreased_rate = average_acked_rate_when_overusing
                                        * DECREASE_FROM_ACKED_RATE_MULTIPLIER;
                                }
                            }
                            self.acked_rate_when_overusing
                                .reset_if_sample_out_of_bounds(acked_rate);
                            self.acked_rate_when_overusing.add_sample(acked_rate);

                            // Don't accidentally increase the estimated rate!
                            let decreased_rate = min(self.target_send_rate, decreased_rate);
                            Some(decreased_rate)
                        } else {
                            // Wait until the next period that we're increasing to decrease (or until the acked_rate drops).
                            // The non-update of the target_send_rate_updated is intentional.
                            None
                        }
                    } else {
                        // We're increasing before we even have an acked rate.  Aggressively reduce.
                        let decreased_rate = self.target_send_rate / 2.0;
                        Some(decreased_rate)
                    }
                }
            };

            // Apply clamping to any change, including a change because of resetting to initial.
            self.previous_direction = Some(direction);

            if changed_target_send_rate.is_some() || reset_to_initial {
                self.target_send_rate = self.config.clamp_target_send_rate(
                    changed_target_send_rate.unwrap_or(self.target_send_rate),
                );
                self.target_send_rate_updated = now;
                return Some(self.target_send_rate);
            }
        }
        None
    }
}

#[cfg(test)]
mod calculate_target_send_rates_tests {
    use super::*;

    fn config() -> Config {
        Config {
            min_target_send_rate: DataRate::from_kbps(5),
            initial_target_send_rate: DataRate::from_kbps(100),
            ..Default::default()
        }
    }

    // These are glass-box tests; they should not fail if the implementation is changed,
    // but additional tests may be necessary to regain coverage.
    // Many of them include contrived scenarios that aren't possible with real Acks.

    #[test]
    fn decrease_holds_steady() {
        let config = config();
        let start_time = Instant::now();

        let mut controller = CongestionController::new(config.clone(), start_time);

        for _ in 0..100 {
            assert_eq!(
                None,
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time, DelayDirection::Decreasing)),
                    FEEDBACK_RTTS_DEFAULT,
                    Some(config.initial_target_send_rate)
                )
            );
        }

        // Try again without any acks.

        let mut controller = CongestionController::new(config.clone(), start_time);

        for _ in 0..100 {
            assert_eq!(
                None,
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time, DelayDirection::Decreasing)),
                    FEEDBACK_RTTS_DEFAULT,
                    None
                )
            );
        }
    }

    #[test]
    fn increase_without_acks_cuts_aggressively() {
        let config = config();
        let start_time = Instant::now();

        let mut controller = CongestionController::new(config.clone(), start_time);

        for expected in [
            50_000, 25_000, 12_500, 6_250, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000,
        ]
        .into_iter()
        {
            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time, DelayDirection::Increasing)),
                        FEEDBACK_RTTS_DEFAULT,
                        None
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn increase_is_okay_for_short_intervals_if_acks_are_keeping_up() {
        let config = config();
        let start_time = Instant::now();

        let mut controller = CongestionController::new(config.clone(), start_time);

        for _ in 0..5 {
            assert_eq!(
                None,
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time, DelayDirection::Increasing)),
                    FEEDBACK_RTTS_DEFAULT,
                    Some(config.initial_target_send_rate)
                )
            );
        }
    }

    #[test]
    fn increase_over_long_intervals_cuts_based_on_ack_rate() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        for i in 1..=10 {
            assert_eq!(
                85_000,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + i * interval, DelayDirection::Increasing)),
                        interval,
                        Some(config.initial_target_send_rate)
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn increase_with_low_ack_rate_cuts_based_on_ack_rate() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        assert_eq!(
            42_500,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((start_time, DelayDirection::Increasing)),
                    interval,
                    Some(config.initial_target_send_rate / 2.0)
                )
                .unwrap()
                .as_bps()
        );
    }

    #[test]
    fn increase_with_single_high_ack_rate_should_still_cut() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        // This isn't conclusive: it might be using the average rate,
        // or it might just be checking that the rate shouldn't increase.
        // Tests below mix "increasing" and "steady" feedback to check more precisely.

        let mut controller = CongestionController::new(config.clone(), start_time);

        for i in 1..=4 {
            assert_eq!(
                8_500,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + i * interval, DelayDirection::Increasing)),
                        interval,
                        Some(DataRate::from_kbps(10))
                    )
                    .unwrap()
                    .as_bps()
            );
        }

        assert_eq!(
            8_500,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((start_time + 5 * interval, DelayDirection::Increasing)),
                    interval,
                    Some(DataRate::from_kbps(100))
                )
                .unwrap()
                .as_bps()
        );
    }

    #[test]
    fn increase_should_never_grow_the_target_rate() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        for i in 1..=5 {
            assert_eq!(
                100_000,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + i * interval, DelayDirection::Increasing)),
                        interval,
                        Some(DataRate::from_kbps(1_000))
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn increase_rtt_determines_interval() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        assert_eq!(
            None,
            controller.calculator.next(
                &mut controller.current_request,
                Some((
                    start_time + interval - Duration::from_millis(1),
                    DelayDirection::Increasing
                )),
                interval,
                Some(DataRate::from_kbps(100))
            )
        );

        assert_eq!(
            85_000,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((start_time + interval / 2, DelayDirection::Increasing)),
                    interval / 2,
                    Some(DataRate::from_kbps(100))
                )
                .unwrap()
                .as_bps()
        );

        // There is a minimum, though...
        assert_eq!(
            None,
            controller.calculator.next(
                &mut controller.current_request,
                Some((start_time, DelayDirection::Increasing)),
                Duration::ZERO,
                Some(DataRate::from_kbps(100))
            )
        );

        // ...as well as a maximum.
        assert_eq!(
            85_000,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((
                        start_time + Duration::from_millis(500),
                        DelayDirection::Increasing
                    )),
                    Duration::from_secs(1),
                    Some(DataRate::from_kbps(100))
                )
                .unwrap()
                .as_bps()
        );
    }

    #[test]
    fn increase_can_cut_by_average_if_current_ack_rate_is_too_high() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        let conditions = [
            (100, DelayDirection::Increasing, 85_000), // cut based on current (no average)
            (85, DelayDirection::Steady, 85_000),      // hold steady for one interval
            (85, DelayDirection::Steady, 89_800),      // increase additively
            (110, DelayDirection::Increasing, 85_000), // cut based on prior ack average instead of current
        ];

        for (i, (rate, direction, expected_bps)) in conditions.into_iter().enumerate() {
            assert_eq!(
                expected_bps,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + interval * (i + 1) as u32, direction)),
                        interval,
                        Some(DataRate::from_kbps(rate))
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn steady_should_grow_multiplicatively_without_acks() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        // The first "Steady" is treated specially since we don't know how long
        // it's been since it went steady. We get a default increase instead.

        for (i, expected) in [101_000, 109_080, 117_806, 127_230, 137_408]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + Duration::SECOND * (i + 1) as u32,
                            DelayDirection::Steady
                        )),
                        interval,
                        None
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn steady_should_grow_aggressively_without_acks() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        // Increases at double the rate until exceeding 250_000, the base requested
        for (i, expected) in [
            101_000, 117_159, 135_904, 157_648, 182_871, 212_130, 246_070, 285_441, 308_276,
            332_938,
        ]
        .into_iter()
        .enumerate()
        {
            controller.request(Request {
                base: DataRate::from_bps(250_000),
                ideal: DataRate::from_bps(3_000_000),
            });

            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + Duration::SECOND * (i + 1) as u32,
                            DelayDirection::Steady
                        )),
                        interval,
                        None
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn steady_growth_is_limited_by_ack_rate() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        // Can't go higher because of the ack rate.
        for (i, expected) in [101_000, 109_080, 110_500, 110_500, 110_500]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + Duration::SECOND * (i + 1) as u32,
                            DelayDirection::Steady
                        )),
                        interval,
                        Some(DataRate::from_kbps(67))
                    )
                    .unwrap()
                    .as_bps()
            );
        }

        // Try again with an even lower ack rate.
        // Can't go higher because of the ack rate.
        // Can't go lower than the start rate.
        let mut controller = CongestionController::new(config.clone(), start_time);
        for i in 0..5 {
            assert_eq!(
                100_000,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + Duration::SECOND * (i + 1) as u32,
                            DelayDirection::Steady
                        )),
                        interval,
                        Some(DataRate::from_kbps(50))
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn steady_growth_has_maximum() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);
        let mut prev = controller
            .calculator
            .next(
                &mut controller.current_request,
                Some((start_time + Duration::SECOND, DelayDirection::Steady)),
                interval,
                None,
            )
            .unwrap();
        let mut has_stopped_increasing = false;

        for i in 0..10_000 {
            let next = controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((
                        start_time + Duration::SECOND * (i + 2) as u32,
                        DelayDirection::Steady,
                    )),
                    interval,
                    None,
                )
                .unwrap();
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
    }

    #[test]
    fn steady_should_grow_additively_after_overuse() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);

        // Reduce for the first "Increasing".
        assert_eq!(
            85_000,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((start_time + interval, DelayDirection::Increasing)),
                    interval,
                    Some(config.initial_target_send_rate)
                )
                .unwrap()
                .as_bps()
        );

        // Pause for the first "Steady", then increase additively from then on.
        for (i, expected) in [85_000, 89_800, 94_600, 99_400, 104_200, 109_000]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + interval * (i + 1) as u32,
                            DelayDirection::Steady
                        )),
                        interval,
                        Some(config.initial_target_send_rate)
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn steady_should_grow_additively_after_overuse_with_minimum() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::from_millis(100);

        let mut controller = CongestionController::new(config.clone(), start_time);
        // Reduce for the first "Increasing".
        assert_eq!(
            85_000,
            controller
                .calculator
                .next(
                    &mut controller.current_request,
                    Some((start_time + interval, DelayDirection::Increasing)),
                    interval, // One proper RTT for the "Increasing" feedback
                    Some(config.initial_target_send_rate)
                )
                .unwrap()
                .as_bps()
        );

        // Pause for the first "Steady", then increase additively from then on.
        for (i, expected) in [85_000, 85_400, 85_800, 86_200, 86_600, 87_000]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                expected,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((
                            start_time + interval * (i + 2) as u32,
                            DelayDirection::Steady
                        )),
                        Duration::from_secs(10), // some ridiculous RTT for "Steady"
                        Some(config.initial_target_send_rate)
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn acked_rate_resets_on_outliers() {
        let config = config();
        let start_time = Instant::now();
        let interval = Duration::SECOND;

        let conditions = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (0, DelayDirection::Steady, 85_000),       // hold steady for one interval
            (100, DelayDirection::Steady, 91_800), // increase multiplicatively due to ack rate outlier
            (100, DelayDirection::Steady, 99_144), // increase multiplicatively due to ack rate outlier
        ];

        let mut controller = CongestionController::new(config.clone(), start_time);
        for (i, (rate, direction, expected_bps)) in conditions.into_iter().enumerate() {
            assert_eq!(
                expected_bps,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + interval * (i + 1) as u32, direction)),
                        interval,
                        Some(DataRate::from_kbps(rate))
                    )
                    .unwrap()
                    .as_bps()
            );
        }

        let conditions = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (100_000, DelayDirection::Steady, 86_000), // minimum multiplicative increase for the first interval
            (100, DelayDirection::Steady, 92_880), // increase multiplicatively due to ack rate outlier
            (100, DelayDirection::Steady, 100_310), // increase multiplicatively due to ack rate outlier
        ];

        let mut controller = CongestionController::new(config.clone(), start_time);
        for (i, (rate, direction, expected_bps)) in conditions.into_iter().enumerate() {
            assert_eq!(
                expected_bps,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + interval * (i + 1) as u32, direction)),
                        interval,
                        Some(DataRate::from_kbps(rate))
                    )
                    .unwrap()
                    .as_bps()
            );
        }

        // We can't (separately) test the case when the ack rate drops drastically while the delay
        // is still increasing because once it goes steady, a low ack rate will limit the growth,
        // and a high ack rate will count as an outlier again. But we can test the case where it
        // *jumps* drastically.

        let conditions = [
            (100, DelayDirection::Increasing, 85_000), // record an initial ack rate
            (100_000, DelayDirection::Increasing, 85_000), // ack rate went up so we don't actually decrease
            (100_000, DelayDirection::Steady, 85_000),     // hold steady for one interval
            (100_000, DelayDirection::Steady, 93_727), // ack rate was reset but it's still present
            (100_000, DelayDirection::Steady, 102_454), // so these increase additively
        ];

        let mut controller = CongestionController::new(config.clone(), start_time);
        for (i, (rate, direction, expected_bps)) in conditions.into_iter().enumerate() {
            assert_eq!(
                expected_bps,
                controller
                    .calculator
                    .next(
                        &mut controller.current_request,
                        Some((start_time + interval * (i + 1) as u32, direction)),
                        interval,
                        Some(DataRate::from_kbps(rate))
                    )
                    .unwrap()
                    .as_bps()
            );
        }
    }

    #[test]
    fn ideal_send_rate_without_acked_rates() {
        let config = Config {
            initial_target_send_rate: DataRate::from_bps(1_000_000),
            min_target_send_rate: DataRate::from_bps(200_000),
            ..config()
        };
        let start_time = Instant::now();
        let interval = Duration::from_millis(1000);
        let mut controller = CongestionController::new(config.clone(), start_time);

        let conditions = [
            // Ideal is tiny, but that doesn't prevent normal behavior
            (100_000, DelayDirection::Steady, Some(1_001_000)),
            (100_000, DelayDirection::Decreasing, None),
            (100_000, DelayDirection::Steady, Some(1_002_000)),
            (100_000, DelayDirection::Steady, Some(1_082_160)),
            (100_000, DelayDirection::Increasing, Some(541_080)),
            // Ideal switches from tiny to not tiny, so reset to initial.
            (10_000_000, DelayDirection::Steady, Some(1_001_000)),
            // Then normal behavior
            (10_000_000, DelayDirection::Steady, Some(1_081_080)),
            (10_000_000, DelayDirection::Decreasing, None),
            (10_000_000, DelayDirection::Increasing, Some(540_540)),
        ];

        for (i, (ideal_send_rate_bps, direction, expected_bps)) in
            conditions.into_iter().enumerate()
        {
            controller.request(Request {
                base: DataRate::from_bps(1000),
                ideal: DataRate::from_bps(ideal_send_rate_bps),
            });

            assert_eq!(
                expected_bps.map(DataRate::from_bps),
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time + interval * (i + 1) as u32, direction)),
                    interval,
                    None
                )
            );
        }
    }

    #[test]
    fn ideal_send_rate_with_acked_rate() {
        let config = Config {
            initial_target_send_rate: DataRate::from_bps(500_000),
            min_target_send_rate: DataRate::from_bps(200_000),
            ..config()
        };
        let start_time = Instant::now();
        let interval = Duration::from_millis(1000);
        let mut controller = CongestionController::new(config.clone(), start_time);

        let conditions = [
            // Ideal is tiny, but that doesn't prevent normal behavior
            (100_000, DelayDirection::Steady, Some(501_000)),
            (100_000, DelayDirection::Decreasing, None),
            (100_000, DelayDirection::Steady, Some(502_000)),
            (100_000, DelayDirection::Steady, Some(542_160)),
            (100_000, DelayDirection::Increasing, Some(425_000)),
            // Ideal switches from tiny to not tiny, so reset to initial.
            (10_000_000, DelayDirection::Steady, Some(500_000)),
            // Then normal behavior
            (10_000_000, DelayDirection::Steady, Some(508_727)),
            (10_000_000, DelayDirection::Decreasing, None),
            (10_000_000, DelayDirection::Increasing, Some(425_000)),
        ];

        for (i, (ideal_send_rate_bps, direction, expected_bps)) in
            conditions.into_iter().enumerate()
        {
            controller.request(Request {
                base: DataRate::from_bps(1000),
                ideal: DataRate::from_bps(ideal_send_rate_bps),
            });

            assert_eq!(
                expected_bps.map(DataRate::from_bps),
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time + interval * (i + 1) as u32, direction)),
                    interval,
                    Some(DataRate::from_kbps(500)),
                )
            );
        }
    }

    #[test]
    fn ideal_send_rate_with_base_requested_rate() {
        let config = Config {
            initial_target_send_rate: DataRate::from_bps(500_000),
            min_target_send_rate: DataRate::from_bps(200_000),
            ..config()
        };
        let start_time = Instant::now();
        let interval = Duration::from_millis(1000);
        let mut controller = CongestionController::new(config.clone(), start_time);

        let conditions = [
            // Ideal is tiny, but that doesn't prevent normal behavior
            (100_000, DelayDirection::Steady, Some(501_000)),
            (100_000, DelayDirection::Decreasing, None),
            (100_000, DelayDirection::Steady, Some(502_000)),
            (100_000, DelayDirection::Steady, Some(582_319)),
            (100_000, DelayDirection::Increasing, Some(291_159)),
            // Ideal switches from tiny to not tiny, so reset to half of base requested rate
            (10_000_000, DelayDirection::Steady, Some(1_501_000)),
            // Then normal behavior
            (10_000_000, DelayDirection::Steady, Some(1_741_159)),
            (10_000_000, DelayDirection::Decreasing, None),
            (10_000_000, DelayDirection::Increasing, Some(870_579)),
        ];

        for (i, (ideal_send_rate_bps, direction, expected_bps)) in
            conditions.into_iter().enumerate()
        {
            controller.request(Request {
                base: DataRate::from_bps(3_000_000),
                ideal: DataRate::from_bps(ideal_send_rate_bps),
            });

            assert_eq!(
                expected_bps.map(DataRate::from_bps),
                controller.calculator.next(
                    &mut controller.current_request,
                    Some((start_time + interval * (i + 1) as u32, direction)),
                    interval,
                    None
                )
            );
        }
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
