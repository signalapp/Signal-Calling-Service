//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_stream::stream;
use futures::{pin_mut, Stream, StreamExt};

use crate::{
    common::{AbsDiff, DataRate, DataSize, Duration, Square},
    transportcc::Ack,
};

// Break up the series of acks into groups of accumulated (size, duration).
// To be passed into estimate_acked_rates for estimateing the rate over time.
fn accumulate_acked_sizes(
    acks: impl Stream<Item = Ack>,
) -> impl Stream<Item = (DataSize, Duration)> {
    // TODO: Maybe make some of these configurable
    let initial_ack_group_duration = Duration::from_millis(500);
    let subsequent_ack_group_duration = Duration::from_millis(150);

    stream! {
        pin_mut!(acks);
        if let Some(mut ack1) = acks.next().await {
            let mut accumulated_size = ack1.size;
            let mut accumulated_duration = Duration::default();
            let mut target_ack_group_duration = initial_ack_group_duration;
            while let Some(ack2) = acks.next().await {
                if ack2.arrival < ack1.arrival {
                    // Reset when we hit out-of-order packets
                    accumulated_size = DataSize::default();
                    accumulated_duration = Duration::default();
                } else {
                    let arrival_delta = ack2.arrival.saturating_duration_since(ack1.arrival);
                    accumulated_duration += arrival_delta;
                    if arrival_delta > target_ack_group_duration {
                        // Reset if it's been too long since we've received an ACK
                        accumulated_size = DataSize::default();
                        accumulated_duration = Duration::from_micros(
                            accumulated_duration.as_micros() as u64
                                % target_ack_group_duration.as_micros() as u64,
                        );
                    } else if accumulated_duration >= target_ack_group_duration {
                        yield (accumulated_size, target_ack_group_duration);

                        // Use what's "left over" for the next group.
                        accumulated_size = Default::default();
                        accumulated_duration =
                            accumulated_duration.saturating_sub(target_ack_group_duration);

                        // Now that we have a group, we can use a smaller window.
                        target_ack_group_duration = subsequent_ack_group_duration;
                    }
                }
                accumulated_size += ack2.size;
                ack1 = ack2;
            }
        }
    }
}

#[cfg(test)]
mod accumulate_acked_sizes_tests {
    use futures::FutureExt;

    use super::*;
    use crate::{common::Instant, transportcc::RemoteInstant};

    /// Creates an `Ack` for each duration with a size of 10.
    ///
    /// The departure and feedback-arrival times should be ignored.
    fn acks_from_arrival_durations(
        durations: impl IntoIterator<Item = u64>,
    ) -> impl Stream<Item = Ack> {
        let start_time = Instant::now();

        futures::stream::iter(durations.into_iter().map(move |duration| Ack {
            size: DataSize::from_bytes(10),
            departure: start_time,
            arrival: RemoteInstant::from_millis(duration),
            feedback_arrival: start_time,
        }))
    }

    #[test]
    fn every_millisecond() {
        let acks = acks_from_arrival_durations(0..1000);
        let stream = accumulate_acked_sizes(acks);
        pin_mut!(stream);
        assert_eq!(
            &[(5000, 500), (1500, 150), (1500, 150), (1500, 150)],
            &stream
                .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn every_hundred_ms() {
        let acks = acks_from_arrival_durations((0..20).map(|x| x * 100));
        let stream = accumulate_acked_sizes(acks);
        pin_mut!(stream);
        assert_eq!(
            &[
                (50, 500),
                (20, 150),
                (10, 150),
                (20, 150),
                (10, 150),
                (20, 150),
                (10, 150),
                (20, 150),
                (10, 150),
                (20, 150)
            ],
            &stream
                .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn start_time_does_not_matter() {
        let acks = acks_from_arrival_durations(1000..2000);
        let stream = accumulate_acked_sizes(acks);
        pin_mut!(stream);
        assert_eq!(
            &[(5000, 500), (1500, 150), (1500, 150), (1500, 150)],
            &stream
                .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn reset_on_out_of_order() {
        let acks = acks_from_arrival_durations(vec![
            0, 1, // reset!
            0, // first group
            500, 600, // reset!
            550, 600, 650, // second group
            700, // force the second group to be emitted
        ]);
        let stream = accumulate_acked_sizes(acks);
        pin_mut!(stream);
        assert_eq!(
            &[(10, 500), (30, 150)],
            &stream
                .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn reset_on_large_gap() {
        let acks = acks_from_arrival_durations(vec![
            0, // reset!
            1001, 1500, // first group
            // reset!
            1651, 1700, 1750, // second group
            1800, // force the second group to be emitted
        ]);
        let stream = accumulate_acked_sizes(acks);
        pin_mut!(stream);
        assert_eq!(
            &[(10, 500), (30, 150)],
            &stream
                .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }
}

// TODO: Make initial variance and other variance numbers (10.0 and 5.0) below configurable
fn estimate_acked_rates_from_groups(
    ack_groups: impl Stream<Item = (DataSize, Duration)>,
) -> impl Stream<Item = DataRate> {
    stream! {
        pin_mut!(ack_groups);
        if let Some((size, duration)) = ack_groups.next().await {
            let mut estimate: DataRate = size / duration;
            let mut variance: f64 = 50.0;

            yield estimate;

            while let Some((size, duration)) = ack_groups.next().await {
                let sample: DataRate = size / duration;
                let sample_variance = ((sample.abs_diff(estimate) / estimate) * 10.0).square();
                let pred_variance = variance + 5.0;
                estimate = ((estimate * sample_variance) + (sample * pred_variance))
                    / (sample_variance + pred_variance);
                variance = (sample_variance * pred_variance) / (sample_variance + pred_variance);

                yield estimate;
            }
        }
    }
}

#[cfg(test)]
mod estimate_acked_rates_from_groups_tests {
    use std::{cmp::Ordering, future::ready};

    use futures::FutureExt;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::common::RANDOM_SEED_FOR_TESTS;

    /// Creates a stream of size groups with the given bits-per-second ratio.
    fn size_groups_from_bps(
        ratios: impl IntoIterator<Item = u64>,
    ) -> impl Stream<Item = (DataSize, Duration)> {
        futures::stream::iter(ratios).map(|bps| (DataSize::from_bits(bps), Duration::from_secs(1)))
    }

    #[test]
    fn first_result_is_simple_division() {
        let stream = estimate_acked_rates_from_groups(stream! {
            yield (DataSize::from_bits(100), Duration::from_secs(2))
        });
        pin_mut!(stream);
        assert_eq!(
            &[50],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn reference_rates() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(vec![
            500, 1000, 1000, 500, 2000, 2000, 2000, 2000, 2000,
        ]));
        pin_mut!(stream);
        // These values came from running the test and seeing the output.
        assert_eq!(
            &[500, 677, 883, 687, 737, 813, 928, 1100, 1355],
            &stream
                .map(|rate| rate.as_bps())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn eventually_converges_upward() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(
            std::iter::once(0).chain(std::iter::repeat(2000)),
        ));
        pin_mut!(stream);
        assert!(stream
            .take(20_000)
            .take_while(|rate| ready(rate < &DataRate::from_bps(1990)))
            .next()
            .now_or_never()
            .unwrap()
            .is_some());
    }

    #[test]
    fn eventually_converges_downward() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(
            std::iter::once(10_000).chain(std::iter::repeat(2000)),
        ));
        pin_mut!(stream);
        assert!(stream
            .take(20_000)
            .take_while(|rate| ready(rate > &DataRate::from_bps(2010)))
            .next()
            .now_or_never()
            .unwrap()
            .is_some());
    }

    #[test]
    fn direction_follows_samples() {
        let mut rng = StdRng::seed_from_u64(*RANDOM_SEED_FOR_TESTS);
        let rates = std::iter::from_fn(move || Some(rng.gen_range(0..100_000)));
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(rates.clone()));
        pin_mut!(stream);
        stream
            .zip(futures::stream::iter(rates))
            .take(10_000)
            .fold(
                DataRate::default(),
                |previous_estimate, (current_estimate, previous_sample)| {
                    // If the previous sample went up, the estimate goes up.
                    // If it went down, the estimate goes down.
                    // Except...we're doing this in floating-point math,
                    // so we could have rounding errors when we go back to integers.
                    if previous_estimate.as_bps().abs_diff(previous_sample) > 1 {
                        let change = previous_estimate.cmp(&current_estimate);
                        // And estimate_acked_rates weights by variance to avoid outliers,
                        // so a sample can end up not making a change.
                        if change != Ordering::Equal {
                            assert_eq!(
                                previous_estimate.cmp(&DataRate::from_bps(previous_sample)),
                                change,
                                "pe: {:?}, ce: {:?}, ps: {:?}",
                                previous_estimate,
                                current_estimate,
                                previous_sample
                            );
                        }
                    }
                    ready(current_estimate)
                },
            )
            .now_or_never()
            .unwrap();
    }
}

pub fn estimate_acked_rates(acks: impl Stream<Item = Ack>) -> impl Stream<Item = DataRate> {
    estimate_acked_rates_from_groups(accumulate_acked_sizes(acks))
}
