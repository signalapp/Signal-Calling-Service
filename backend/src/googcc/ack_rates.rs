//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::max;

use calling_common::{DataRate, DataSize, Duration};

use crate::transportcc::{Ack, RemoteInstant};

// Break up the series of acks into groups of accumulated (size, duration).
// To be passed into estimate_acked_rates for estimateing the rate over time.
#[derive(Default)]
enum AckGroupSizeAccumulator {
    #[default]
    None,
    Some {
        accumulated_size: DataSize,
        accumulated_duration: Duration,
        last_arrival: RemoteInstant,
    },
}

impl AckGroupSizeAccumulator {
    const TARGET_DURATION: Duration = Duration::from_millis(50);
    const MINIMUM_DURATION: Duration = Duration::from_millis(10);
    const MAXIMUM_INTERPACKET_DURATION: Duration = Duration::from_millis(150);

    fn next(&mut self, ack: &Ack) -> Option<(DataSize, Duration)> {
        match self {
            Self::None => {
                *self = Self::Some {
                    accumulated_size: ack.size,
                    accumulated_duration: Duration::ZERO,
                    last_arrival: ack.arrival,
                };
                None
            }
            Self::Some {
                accumulated_size,
                accumulated_duration,
                last_arrival,
            } => {
                let ret = if ack.arrival < *last_arrival {
                    // Reset when we hit out-of-order packets
                    *accumulated_size = DataSize::ZERO;
                    *accumulated_duration = Duration::ZERO;
                    None
                } else {
                    let arrival_delta = ack.arrival.saturating_duration_since(*last_arrival);
                    *accumulated_duration += arrival_delta;
                    if arrival_delta > Self::MAXIMUM_INTERPACKET_DURATION {
                        // Reset if it's been too long since we've received an ACK
                        *accumulated_size = DataSize::ZERO;
                        *accumulated_duration = Duration::from_micros(
                            accumulated_duration.as_micros() as u64
                                % Self::TARGET_DURATION.as_micros() as u64,
                        );
                        None
                    } else if *accumulated_duration >= Self::TARGET_DURATION {
                        let ret = Some((*accumulated_size, Self::TARGET_DURATION));

                        // Use what's "left over" for the next group.
                        *accumulated_size = DataSize::ZERO;
                        *accumulated_duration =
                            accumulated_duration.saturating_sub(Self::TARGET_DURATION);

                        ret
                    } else {
                        // Haven't reached the threshold
                        None
                    }
                };
                *accumulated_size += ack.size;
                *last_arrival = ack.arrival;
                ret
            }
        }
    }

    fn residue(&mut self) -> Option<(DataSize, Duration)> {
        match self {
            Self::None => None,
            Self::Some {
                accumulated_size,
                accumulated_duration,
                ..
            } => {
                if *accumulated_duration > Self::MINIMUM_DURATION {
                    let ret = Some((*accumulated_size, *accumulated_duration));

                    *accumulated_size = DataSize::ZERO;
                    *accumulated_duration = Duration::ZERO;
                    ret
                } else {
                    None
                }
            }
        }
    }

    fn use_acks(&mut self, acks: &[Ack]) -> Vec<(DataSize, Duration)> {
        let mut ret: Vec<_> = acks.iter().filter_map(|ack| self.next(ack)).collect();
        if let Some(residue) = self.residue() {
            ret.push(residue);
        }
        ret
    }
}

#[cfg(test)]
mod accumulate_acked_sizes_tests {
    use calling_common::Instant;

    use super::*;
    use crate::transportcc::RemoteInstant;

    /// Creates an `Ack` for each duration with a size of 10.
    ///
    /// The departure and feedback-arrival times should be ignored.
    fn ack_groups_from_arrival_durations(
        durations: impl IntoIterator<Item = u64>,
    ) -> Vec<(u64, u128)> {
        let start_time = Instant::now();
        let mut accumulator = AckGroupSizeAccumulator::default();

        durations
            .into_iter()
            .filter_map(move |duration| {
                accumulator.next(&Ack {
                    size: DataSize::from_bytes(10),
                    departure: start_time,
                    arrival: RemoteInstant::from_millis(duration),
                    feedback_arrival: start_time,
                })
            })
            .map(|(size, duration)| (size.as_bytes(), duration.as_millis()))
            .collect()
    }

    #[test]
    fn every_millisecond() {
        let ack_groups = ack_groups_from_arrival_durations(0..1000);
        assert_eq!(
            ack_groups,
            [
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50)
            ]
        );
    }

    #[test]
    fn every_hundred_ms() {
        let ack_groups = ack_groups_from_arrival_durations((0..20).map(|x| x * 100));
        assert_eq!(
            ack_groups,
            [
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50),
                (10, 50)
            ]
        );
    }

    #[test]
    fn start_time_does_not_matter() {
        let ack_groups = ack_groups_from_arrival_durations(1000..2000);
        assert_eq!(
            ack_groups,
            [
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50),
                (500, 50)
            ]
        );
    }

    #[test]
    fn reset_on_out_of_order() {
        let ack_groups = ack_groups_from_arrival_durations(vec![
            0, 1, // reset!
            0, 50, // first group
            60, 65, // reset!
            55, 60, 75,  // second group
            105, // force the second group to be emitted
        ]);
        assert_eq!(ack_groups, [(10, 50), (30, 50)]);
    }

    #[test]
    fn reset_on_large_gap() {
        let ack_groups = ack_groups_from_arrival_durations(vec![
            0, // reset!
            1001, 1500, // reset!
            // reset!
            1651, 1700, // first group
        ]);
        assert_eq!(ack_groups, [(10, 50)]);
    }
}

#[derive(Default)]
enum AckRateEstimator {
    #[default]
    None,
    Some {
        estimate: DataRate,
    },
}

impl AckRateEstimator {
    const WINDOW_SECONDS: f64 = 0.150;

    fn next(&mut self, size: DataSize, duration: Duration) -> DataRate {
        match self {
            Self::None => {
                let estimate = calc_sample(size, duration);
                *self = Self::Some { estimate };
                estimate
            }
            Self::Some { estimate } => {
                let sample: DataRate = calc_sample(size, duration);
                let window_portion =
                    (duration.as_secs_f64() / Self::WINDOW_SECONDS).clamp(0.0, 1.0);

                *estimate = *estimate * (1.0 - window_portion) + sample * window_portion;
                *estimate
            }
        }
    }
}

// Set a minumum bitrate for the sample; if the estimate goes below 5 bps,
// the estimate can not increase.
const MINIMUM_BITRATE: DataRate = DataRate::from_bps(5);
fn calc_sample(size: DataSize, duration: Duration) -> DataRate {
    let sample = size / duration;
    max(sample, MINIMUM_BITRATE)
}

#[cfg(test)]
mod estimate_acked_rates_from_groups_tests {
    use std::cmp::Ordering;

    use calling_common::AbsDiff;
    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    use super::*;

    /// Creates a stream of size groups with the given bits-per-second ratio.
    fn size_groups_from_bps(ratios: impl IntoIterator<Item = u64>) -> Vec<(DataSize, Duration)> {
        ratios
            .into_iter()
            .map(|bps| (DataSize::from_bits(bps), Duration::from_secs(1)))
            .collect()
    }

    fn estimate_acked_rates_from_groups(data: Vec<(DataSize, Duration)>) -> Vec<u64> {
        let mut estimator = AckRateEstimator::default();
        data.iter()
            .map(|(data_size, duration)| estimator.next(*data_size, *duration))
            .map(|rate| rate.as_bps())
            .collect()
    }

    #[test]
    fn first_result_is_simple_division() {
        let s = estimate_acked_rates_from_groups(vec![(
            DataSize::from_bits(100),
            Duration::from_secs(2),
        )]);
        assert_eq!(s, [50]);
    }

    #[test]
    fn reference_rates() {
        let s = estimate_acked_rates_from_groups(size_groups_from_bps(vec![
            500, 1000, 1000, 500, 2000, 2000, 2000, 2000, 2000,
        ]));
        assert_eq!(s, [500, 1000, 1000, 500, 2000, 2000, 2000, 2000, 2000]);
    }

    #[test]
    fn eventually_converges_upward() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(
            std::iter::once(0)
                .chain(std::iter::repeat_n(2000, 20_000))
                .collect::<Vec<_>>(),
        ));

        assert!(stream.into_iter().take(20_000).any(|rate| rate >= 1990));
    }

    #[test]
    fn eventually_converges_upward_really_low() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(
            std::iter::once(0)
                .chain(std::iter::repeat_n(100, 20_000))
                .collect::<Vec<_>>(),
        ));

        assert!(stream.into_iter().take(20_000).any(|rate| rate >= 90));
    }

    #[test]
    fn eventually_converges_downward() {
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(
            std::iter::once(10_000).chain(std::iter::repeat_n(2000, 20_000)),
        ));
        assert!(stream.into_iter().take(20_000).any(|rate| rate <= 2010));
    }

    #[test]
    fn direction_follows_samples() {
        let seed: u64 = match std::env::var("RANDOM_SEED") {
            Ok(v) => v.parse().unwrap(),
            Err(_) => thread_rng().gen(),
        };
        let mut rng = StdRng::seed_from_u64(seed);
        let rates: Vec<_> = std::iter::from_fn(move || Some(rng.gen_range(0..100_000)))
            .take(10_000)
            .collect();
        let stream = estimate_acked_rates_from_groups(size_groups_from_bps(rates.clone()));
        stream.into_iter().zip(rates).fold(
            0,
            |previous_estimate, (current_estimate, previous_sample)| {
                // If the previous sample went up, the estimate goes up.
                // If it went down, the estimate goes down.
                // Except...we're doing this in floating-point math,
                // so we could have rounding errors when we go back to integers.
                if AbsDiff::abs_diff(previous_estimate, previous_sample) > 1 {
                    let change = previous_estimate.cmp(&current_estimate);
                    // And estimate_acked_rates weights by variance to avoid outliers,
                    // so a sample can end up not making a change.
                    if change != Ordering::Equal {
                        assert_eq!(
                            previous_estimate.cmp(&previous_sample),
                            change,
                            "pe: {:?}, ce: {:?}, ps: {:?}",
                            previous_estimate,
                            current_estimate,
                            previous_sample
                        );
                    }
                }
                current_estimate
            },
        );
    }
}

#[derive(Default)]
pub struct AckRatePipeline {
    ack_group_sizes: AckGroupSizeAccumulator,
    acked_rate_estimator: AckRateEstimator,
}

impl AckRatePipeline {
    pub fn next(&mut self, acks: &[Ack]) -> Option<DataRate> {
        self.ack_group_sizes
            .use_acks(acks)
            .into_iter()
            .map(|(data_size, duration)| self.acked_rate_estimator.next(data_size, duration))
            .last()
    }
}
