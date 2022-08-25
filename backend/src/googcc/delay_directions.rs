//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::{max, min};

use async_stream::stream;
use calling_common::{exponential_moving_average, Duration, Instant, RingBuffer};
use futures::{pin_mut, Stream, StreamExt};

use crate::transportcc::{Ack, RemoteInstant};

mod time_delta;
use time_delta::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DelayDirection {
    Increasing,
    Decreasing,
    Steady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AckGroupSummary {
    latest_departure: Instant,
    latest_arrival: RemoteInstant,
    latest_feedback_arrival: Instant,
}

impl AckGroupSummary {
    fn add(&mut self, ack: &Ack) {
        self.latest_departure = max(self.latest_departure, ack.departure);
        self.latest_arrival = max(self.latest_arrival, ack.arrival);
        self.latest_feedback_arrival = max(self.latest_feedback_arrival, ack.feedback_arrival);
    }
}

impl<'a> From<&'a Ack> for AckGroupSummary {
    fn from(ack: &'a Ack) -> AckGroupSummary {
        AckGroupSummary {
            latest_departure: ack.departure,
            latest_arrival: ack.arrival,
            latest_feedback_arrival: ack.feedback_arrival,
        }
    }
}

// Yields (group_summary, next_after_group)
fn accumulate_ack_groups(
    acks: impl Stream<Item = Ack>,
) -> impl Stream<Item = (AckGroupSummary, Ack)> {
    // TODO: Maybe make some of these configurable
    let ack_group_min_duration = TimeDelta::from_millis(5.0);
    let ack_group_max_duration = TimeDelta::from_millis(100.0);

    stream! {
        let acks = acks.peekable();
        pin_mut!(acks);
        while let Some(first) = acks.next().await {
            let mut group = AckGroupSummary::from(&first);
            while let Some(next) = acks.as_mut().peek().await {
                if next.departure >= first.departure {
                    // Allow out-of-order packets within groups, but not crossing group
                    // boundaries.
                    let departed_at_same_time = next.departure == group.latest_departure;
                    let departure_gap = next.departure.time_delta_since(group.latest_departure);
                    let arrival_gap = next.arrival.time_delta_since(group.latest_arrival);
                    let departure_duration_would_be_small =
                        next.departure.time_delta_since(first.departure) <= ack_group_min_duration;
                    let arrival_gap_is_small =
                        (arrival_gap < departure_gap) && (arrival_gap <= ack_group_min_duration);
                    let arrival_duration_wouldnt_be_big =
                        next.arrival.time_delta_since(first.arrival) < ack_group_max_duration;
                    if departed_at_same_time
                        || departure_duration_would_be_small
                        || (arrival_gap_is_small && arrival_duration_wouldnt_be_big)
                    {
                        // Combine into existing group
                        group.add(next);
                    } else {
                        // Start a new group.
                        yield (group, next.clone());
                        break;
                    }
                }

                acks.next().await.unwrap();
            }
        }
    }
}

#[cfg(test)]
mod accumulate_ack_groups_tests {
    use futures::FutureExt;

    use super::*;
    use crate::transportcc::RemoteInstant;

    pub(super) const TIMESTAMP_GROUP_LENGTH: Duration = Duration::from_millis(5);
    pub(super) const MIN_STEP: Duration = Duration::from_micros(20);
    pub(super) const NEW_GROUP_INTERVAL: Duration = Duration::from_micros(
        TIMESTAMP_GROUP_LENGTH.as_micros() as u64 + MIN_STEP.as_micros() as u64,
    );
    pub(super) const BURST_THRESHOLD: Duration = Duration::from_millis(5);

    /// Creates an `Ack` for each departure/arrival offset.
    ///
    /// The size and feedback-arrival time should be ignored.
    pub(super) fn acks_from_departure_and_arrival(
        pairs: impl IntoIterator<Item = (Instant, RemoteInstant)>,
    ) -> impl Stream<Item = Ack> {
        futures::stream::iter(pairs.into_iter().map(move |(departure, arrival)| Ack {
            size: Default::default(),
            departure,
            arrival,
            feedback_arrival: departure,
        }))
    }

    // From WebRTC's InterArrivalTest::FirstPacket.
    #[test]
    fn first_packet() {
        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(vec![(
            Instant::now(),
            RemoteInstant::from_millis(17),
        )]));
        pin_mut!(stream);
        assert!(stream.next().now_or_never().unwrap().is_none());
    }

    // From WebRTC's InterArrivalTest::SecondGroup.
    #[test]
    fn groups() {
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_arrival_time = g1_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;
        let g3_arrival_time = g2_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;
        let g4_arrival_time = g3_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;

        let start = Instant::now();

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(vec![
            (start, g1_arrival_time),
            (start + NEW_GROUP_INTERVAL, g2_arrival_time),
            (start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time),
            (start + 3 * NEW_GROUP_INTERVAL, g4_arrival_time),
        ]));
        pin_mut!(stream);
        assert_eq!(
            &[
                (g1_arrival_time, g2_arrival_time),
                (g2_arrival_time, g3_arrival_time),
                (g3_arrival_time, g4_arrival_time),
            ],
            &stream
                .map(|(group, ack)| (group.latest_arrival, ack.arrival))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::AccumulatedGroup.
    #[test]
    fn accumulated_group() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_first_arrival_time = g1_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;

        let mut pairs = vec![
            (start, g1_arrival_time),
            (start + NEW_GROUP_INTERVAL, g2_first_arrival_time),
        ];

        let mut current_timestamp = start + NEW_GROUP_INTERVAL;
        let mut current_arrival_time = g2_first_arrival_time;
        for _ in 0..10 {
            current_timestamp += MIN_STEP;
            current_arrival_time += BURST_THRESHOLD + Duration::MILLISECOND;
            pairs.push((current_timestamp, current_arrival_time));
        }
        let g2_last_arrival_time = current_arrival_time;

        let g3_arrival_time = RemoteInstant::from_millis(500);
        pairs.push((start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time));

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(pairs));
        pin_mut!(stream);
        assert_eq!(
            &[
                (g1_arrival_time, g2_first_arrival_time),
                (g2_last_arrival_time, g3_arrival_time),
            ],
            &stream
                .map(|(group, ack)| (group.latest_arrival, ack.arrival,))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::OutOfOrderPacket.
    #[test]
    fn out_of_order_packet() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_first_arrival_time = g1_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;

        let mut pairs = vec![
            (start, g1_arrival_time),
            (start + NEW_GROUP_INTERVAL, g2_first_arrival_time),
        ];

        let mut current_timestamp = start + NEW_GROUP_INTERVAL;
        let mut current_arrival_time = g2_first_arrival_time;
        for _ in 0..10 {
            current_timestamp += MIN_STEP;
            current_arrival_time += BURST_THRESHOLD + Duration::MILLISECOND;
            pairs.push((current_timestamp, current_arrival_time));
        }
        let g2_last_arrival_time = current_arrival_time;

        // The out-of-order packet, which will be dropped.
        pairs.push((start, RemoteInstant::from_millis(281)));

        let g3_arrival_time = RemoteInstant::from_millis(500);
        pairs.push((start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time));

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(pairs));
        pin_mut!(stream);
        assert_eq!(
            &[
                (g1_arrival_time, g2_first_arrival_time),
                (g2_last_arrival_time, g3_arrival_time),
            ],
            &stream
                .map(|(group, ack)| (group.latest_arrival, ack.arrival))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::OutOfOrderWithinGroup.
    #[test]
    fn out_of_order_within_group() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_first_arrival_time = g1_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;

        let mut pairs = vec![
            (start, g1_arrival_time),
            (start + NEW_GROUP_INTERVAL, g2_first_arrival_time),
        ];

        let mut current_timestamp = start + NEW_GROUP_INTERVAL + 10 * MIN_STEP;
        let mut current_arrival_time = g2_first_arrival_time;
        for _ in 0..10 {
            current_timestamp -= MIN_STEP;
            current_arrival_time += BURST_THRESHOLD + Duration::MILLISECOND;
            pairs.push((current_timestamp, current_arrival_time));
        }
        let g2_last_arrival_time = current_arrival_time;

        // This packet is still out-of-order and should be dropped.
        pairs.push((start, RemoteInstant::from_millis(281)));

        let g3_arrival_time = RemoteInstant::from_millis(500);
        pairs.push((start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time));

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(pairs));
        pin_mut!(stream);
        assert_eq!(
            &[
                (g1_arrival_time, g2_first_arrival_time),
                (g2_last_arrival_time, g3_arrival_time),
            ],
            &stream
                .map(|(group, ack)| (group.latest_arrival, ack.arrival))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::TwoBursts.
    #[test]
    fn two_bursts() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        // No packets arriving for a while.
        let g2_first_arrival_time = RemoteInstant::from_millis(100);

        let mut pairs = vec![(start, g1_arrival_time)];

        let mut current_timestamp = start + NEW_GROUP_INTERVAL;
        let mut current_arrival_time = g2_first_arrival_time
            .checked_sub(TIMESTAMP_GROUP_LENGTH)
            .unwrap();
        for _ in 0..10 {
            // A bunch of packets arriving in one burst (within 5 ms apart).
            current_timestamp += Duration::from_millis(30_000);
            current_arrival_time += TIMESTAMP_GROUP_LENGTH;
            pairs.push((current_timestamp, current_arrival_time));
        }
        let g2_last_arrival_time = current_arrival_time;

        let g3_arrival_time = current_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;
        pairs.push((
            current_timestamp + Duration::from_millis(30_000),
            g3_arrival_time,
        ));

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(pairs));
        pin_mut!(stream);
        assert_eq!(
            &[
                (g1_arrival_time, g2_first_arrival_time),
                (g2_last_arrival_time, g3_arrival_time),
            ],
            &stream
                .map(|(group, ack)| (group.latest_arrival, ack.arrival))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn max_within_groups() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_arrival_time = g1_arrival_time + 10 * BURST_THRESHOLD;
        let g3_arrival_time = g2_arrival_time + 10 * BURST_THRESHOLD;
        let g4_arrival_time = g3_arrival_time + 10 * BURST_THRESHOLD;
        let g5_arrival_time = g4_arrival_time + 10 * BURST_THRESHOLD;

        let stream = accumulate_ack_groups(acks_from_departure_and_arrival(vec![
            (start, g1_arrival_time),
            // Same departure, earlier arrival.
            (
                start + NEW_GROUP_INTERVAL,
                g2_arrival_time + Duration::MILLISECOND,
            ),
            (start + NEW_GROUP_INTERVAL, g2_arrival_time),
            // Earlier departure, later arrival.
            // Can't be earlier than the start of the group, but can be later.
            (start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time),
            (
                start + 2 * NEW_GROUP_INTERVAL + Duration::from_millis(2),
                g3_arrival_time,
            ),
            (
                start + 2 * NEW_GROUP_INTERVAL + Duration::from_millis(1),
                g3_arrival_time + Duration::MILLISECOND,
            ),
            (
                start + 2 * NEW_GROUP_INTERVAL + Duration::from_millis(3),
                g3_arrival_time,
            ),
            // Later departure, earlier arrival.
            (
                start + 3 * NEW_GROUP_INTERVAL,
                g4_arrival_time + Duration::MILLISECOND,
            ),
            (
                start + 3 * NEW_GROUP_INTERVAL + Duration::MILLISECOND,
                g4_arrival_time,
            ),
            // One more to flush.
            (start + 4 * NEW_GROUP_INTERVAL, g5_arrival_time),
        ]));
        pin_mut!(stream);
        assert_eq!(
            &[
                (
                    Duration::ZERO,
                    g1_arrival_time,
                    g2_arrival_time + Duration::MILLISECOND
                ),
                (
                    NEW_GROUP_INTERVAL,
                    g2_arrival_time + Duration::MILLISECOND,
                    g3_arrival_time
                ),
                (
                    2 * NEW_GROUP_INTERVAL + Duration::from_millis(3),
                    g3_arrival_time + Duration::MILLISECOND,
                    g4_arrival_time + Duration::MILLISECOND
                ),
                (
                    3 * NEW_GROUP_INTERVAL + Duration::MILLISECOND,
                    g4_arrival_time + Duration::MILLISECOND,
                    g5_arrival_time
                ),
            ],
            &stream
                .inspect(|(group, _ack)| {
                    assert_eq!(group.latest_departure, group.latest_feedback_arrival);
                })
                .map(|(group, ack)| (
                    group
                        .latest_departure
                        .checked_duration_since(start)
                        .unwrap(),
                    group.latest_arrival,
                    ack.arrival
                ))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }
}

// TODO: Maybe make some of these configurable
const MAX_ARRIVAL_CHANGE: Duration = Duration::from_secs(3);
const MAX_CONSECUTIVE_REORDERINGS: u16 = 3;

// Yields (latest_ack, departure_delta, arrival_delta)
fn calculate_ack_deltas(
    groups: impl Stream<Item = (AckGroupSummary, Ack)>,
) -> impl Stream<Item = (Ack, Duration, TimeDelta)> {
    stream! {
        let groups = groups.fuse();
        pin_mut!(groups);
        while let Some((mut group1, _)) = groups.next().await {
            let mut consecutive_reorderings = 0u16;
            while let Some((group2, latest_ack)) = groups.next().await {
                // TODO: If it's over 2 seconds since we saw a packet, reset this state and everything in
                // calculate_delay_slopes and calculate_delay_directions.

                if group2.latest_departure > group1.latest_departure {
                    let departure_delta = group2
                        .latest_departure
                        .saturating_duration_since(group1.latest_departure);
                    // These can be negative!
                    let arrival_delta = group2
                        .latest_arrival
                        .time_delta_since(group1.latest_arrival);
                    // We assume that we can't process ACKs that arrived out of order.
                    let feedback_delta = group2
                        .latest_feedback_arrival
                        .saturating_duration_since(group1.latest_feedback_arrival);

                    if group2.latest_arrival < group1.latest_arrival {
                        consecutive_reorderings += 1;
                        if consecutive_reorderings >= MAX_CONSECUTIVE_REORDERINGS {
                            // Throw out both of these groups and start over.
                            break;
                        } else {
                            // Drop the new group and hope the next one is better.
                            continue;
                        }
                    } else {
                        consecutive_reorderings = 0;
                    }

                    let arrival_delta_increased_too_much = arrival_delta.as_secs()
                        >= (feedback_delta + MAX_ARRIVAL_CHANGE).as_secs_f64();
                    if arrival_delta_increased_too_much {
                        // Throw out both of these groups and start over.
                        break;
                    }

                    yield (latest_ack, departure_delta, arrival_delta);
                    group1 = group2;
                } else {
                    // Ignore packets that arrived out of order.
                }
            }
        }
    }
}

#[cfg(test)]
const RTT_FOR_ACKS_AT_REGULAR_INTERVALS: Duration = Duration::from_millis(100);

/// Generates 1200-byte Acks at regular intervals.
///
/// Why 1200 bytes? Because it makes some tests come out to ~1Mbps.
///
/// Note that the `feedback_arrival` for each packet is a fixed interval after
/// `departure`, [`RTT_FOR_ACKS_AT_REGULAR_INTERVALS`]. This is not realistic,
/// since it does not take `arrival_interval` into account.
/// However, `feedback_arrival` is not used in this part of the congestion control
/// computation, except as a "now" timestamp and to set an upper bound on RTT.
/// Therefore, it doesn't matter exactly what's in this field,
/// as long as the deltas aren't *too* far off from `arrival_interval`.
/// Providing a regular rate makes it easier to write tests that check
/// when a particular change has occurred.
#[cfg(test)]
fn acks_at_regular_intervals(
    mut departure: Instant,
    departure_interval: Duration,
    mut arrival: RemoteInstant,
    arrival_interval: Duration,
) -> impl Stream<Item = Ack> {
    use calling_common::DataSize;

    futures::stream::repeat_with(move || {
        let result = Ack {
            departure,
            arrival,
            feedback_arrival: departure + RTT_FOR_ACKS_AT_REGULAR_INTERVALS,
            size: DataSize::from_bytes(1200),
        };
        departure += departure_interval;
        arrival += arrival_interval;
        result
    })
}

#[cfg(test)]
mod calculate_ack_deltas_tests {
    use std::future::ready;

    use futures::FutureExt;

    use super::{
        accumulate_ack_groups_tests::{
            acks_from_departure_and_arrival, BURST_THRESHOLD, NEW_GROUP_INTERVAL,
        },
        *,
    };
    use crate::transportcc::RemoteInstant;

    /// Converts a stream of Acks into a stream of groups by assuming every Ack
    /// is in its own group.
    fn ack_groups_from_acks(
        mut acks: impl Stream<Item = Ack> + Unpin,
    ) -> impl Stream<Item = (AckGroupSummary, Ack)> {
        let first_ack = acks
            .next()
            .now_or_never()
            .expect("ready")
            .expect("non-empty");
        acks.scan(first_ack, |current, next| {
            let prev = std::mem::replace(current, next);
            ready(Some((AckGroupSummary::from(&prev), current.clone())))
        })
    }

    // From WebRTC's InterArrivalTest::SecondGroup.
    #[test]
    fn groups() {
        let start = Instant::now();
        let g1_arrival_time = RemoteInstant::from_millis(17);
        let g2_arrival_time = g1_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;
        let g3_arrival_time = g2_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;
        let g4_arrival_time = g3_arrival_time + BURST_THRESHOLD + Duration::MILLISECOND;

        let acks = acks_from_departure_and_arrival(vec![
            (start, g1_arrival_time),
            (start + NEW_GROUP_INTERVAL, g2_arrival_time),
            (start + 2 * NEW_GROUP_INTERVAL, g3_arrival_time),
            (start + 3 * NEW_GROUP_INTERVAL, g4_arrival_time),
        ]);
        let stream = calculate_ack_deltas(ack_groups_from_acks(acks));
        pin_mut!(stream);
        assert_eq!(
            &[
                (
                    g3_arrival_time,
                    NEW_GROUP_INTERVAL,
                    g2_arrival_time.time_delta_since(g1_arrival_time)
                ),
                (
                    g4_arrival_time,
                    NEW_GROUP_INTERVAL,
                    g3_arrival_time.time_delta_since(g2_arrival_time)
                ),
            ],
            &stream
                .map(|(ack, departure_delta, arrival_delta)| (
                    ack.arrival,
                    departure_delta,
                    arrival_delta
                ))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::PositiveArrivalTimeJump.
    #[test]
    fn positive_arrival_time_jump() {
        let interval = Duration::from_millis(30);
        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(20_000);

        // The original test provides 5 packets after the change, not 4,
        // but our implementation only resets the delta logic, not the group collection logic.
        // (And we're not actually running the group collection logic in this test;
        // we're just treating each Ack as a standalone group.)
        let acks =
            acks_at_regular_intervals(initial_departure, interval, initial_arrival, interval)
                .take(2)
                .chain(
                    acks_at_regular_intervals(
                        initial_departure + 2 * interval,
                        interval,
                        initial_arrival + 2 * interval + MAX_ARRIVAL_CHANGE,
                        interval,
                    )
                    .take(4),
                );

        let stream = calculate_ack_deltas(ack_groups_from_acks(acks));
        pin_mut!(stream);
        assert_eq!(
            &[
                (
                    initial_arrival + 2 * interval + MAX_ARRIVAL_CHANGE,
                    interval,
                    TimeDelta::from_secs(interval.as_secs_f64()),
                ),
                (
                    initial_arrival + 5 * interval + MAX_ARRIVAL_CHANGE,
                    interval,
                    TimeDelta::from_secs(interval.as_secs_f64()),
                ),
            ],
            &stream
                .map(|(ack, departure_delta, arrival_delta)| (
                    ack.arrival,
                    departure_delta,
                    arrival_delta
                ))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    // From WebRTC's InterArrivalTest::NegativeArrivalTimeJump.
    #[test]
    fn negative_arrival_time_jump() {
        let interval = Duration::from_millis(30);
        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(20_000);

        let first_departure_after_jump = initial_departure + 2 * interval;
        let first_arrival_after_jump = initial_arrival
            .checked_sub(Duration::from_millis(1_000))
            .unwrap()
            + 2 * interval;
        let number_of_packets_after_jump = MAX_CONSECUTIVE_REORDERINGS as usize + 4;

        let acks =
            acks_at_regular_intervals(initial_departure, interval, initial_arrival, interval)
                .take(3)
                .chain(
                    acks_at_regular_intervals(
                        first_departure_after_jump,
                        interval,
                        first_arrival_after_jump,
                        interval,
                    )
                    .take(number_of_packets_after_jump),
                );

        let stream = calculate_ack_deltas(ack_groups_from_acks(acks));
        pin_mut!(stream);
        assert_eq!(
            &[
                (
                    initial_arrival + 2 * interval,
                    interval,
                    TimeDelta::from_secs(interval.as_secs_f64()),
                ),
                // The original test does not include this expected delta,
                // but our implementation only resets the delta logic,
                // not the group collection logic, and so the first packet after the jump
                // is *not* considered part of the previous group.
                // Arguably this is a bug in WebRTC's implementation.
                // (And we're not actually running the group collection logic in this test;
                // we're just treating each Ack as a standalone group.)
                (
                    first_arrival_after_jump,
                    interval,
                    TimeDelta::from_secs(interval.as_secs_f64()),
                ),
                // This is the one WebRTC expects after the jump.
                (
                    first_arrival_after_jump + (number_of_packets_after_jump as u32 - 1) * interval,
                    interval,
                    TimeDelta::from_secs(interval.as_secs_f64()),
                ),
            ],
            &stream
                .map(|(ack, departure_delta, arrival_delta)| (
                    ack.arrival,
                    departure_delta,
                    arrival_delta
                ))
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }
}

// Yields (now, delay_slope, duration, sample_count)
fn calculate_delay_slopes(
    ack_deltas: impl Stream<Item = (Ack, Duration, TimeDelta)>,
) -> impl Stream<Item = (Instant, f64, Duration, usize)> {
    // TODO: Maybe make some of these configurable
    let history_len: usize = 20;
    let moving_average_alpha: f64 = 0.9;
    let max_sample_count = 1000;

    stream! {
        pin_mut!(ack_deltas);
        if let Some((first_ack, first_departure_delta, first_arrival_delta)) =
            ack_deltas.next().await
        {
            let mut sample_count = 1;
            let mut accumulated_delay: TimeDelta = (first_arrival_delta - first_departure_delta);
            let mut smoothed_delay: TimeDelta = accumulated_delay;
            // Put secs in the history because it makes it easier to do the linear_regression without a bunch of generics.
            let mut history: RingBuffer<(f64, f64)> = RingBuffer::new(history_len);
            history.push((0.0, smoothed_delay.as_secs()));

            yield (
                first_ack.feedback_arrival,
                0.0,
                first_departure_delta,
                sample_count,
            );

            while let Some((latest_ack, departure_delta, arrival_delta)) = ack_deltas.next().await {
                if sample_count < max_sample_count {
                    sample_count += 1;
                }
                let relative_arrival = latest_ack.arrival.time_delta_since(first_ack.arrival);
                accumulated_delay = accumulated_delay + (arrival_delta - departure_delta);
                smoothed_delay = exponential_moving_average(
                    smoothed_delay,
                    moving_average_alpha,
                    accumulated_delay,
                );
                history.push((relative_arrival.as_secs(), smoothed_delay.as_secs()));
                if history.is_full() {
                    let delay_slope = linear_regression(history.iter().copied())
                        .expect("after the first group, the history should never have all departure times the same");
                    yield (
                        latest_ack.feedback_arrival,
                        delay_slope,
                        departure_delta,
                        sample_count,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod calculate_delay_slopes_tests {
    use std::future::ready;

    use futures::FutureExt;

    use super::*;

    // Tests calculate_delay_slopes based on the stack of prior transformers.
    fn calculate_delay_slopes_from_acks(
        acks: impl Stream<Item = Ack>,
    ) -> impl Stream<Item = (Instant, f64, Duration, usize)> {
        calculate_delay_slopes(calculate_ack_deltas(accumulate_ack_groups(acks)))
    }

    // From WebRTC's TrendlineEstimatorTest::Normal.
    #[test]
    #[allow(clippy::float_cmp)]
    fn normal() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(20),
            RemoteInstant::from_millis(17),
            Duration::from_millis(20),
        )
        .take(25);
        let stream = calculate_delay_slopes_from_acks(acks);
        pin_mut!(stream);
        stream
            .for_each(|(_now, slope, _duration, _count)| {
                assert_eq!(0.0, slope);
                ready(())
            })
            .now_or_never()
            .unwrap();
    }

    // From WebRTC's TrendlineEstimatorTest::Overusing.
    #[test]
    fn overusing() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(20),
            RemoteInstant::from_millis(17),
            Duration::from_millis(22),
        )
        .take(25);
        let stream = calculate_delay_slopes_from_acks(acks);
        pin_mut!(stream);
        stream
            .skip_while(|(_now, slope, _duration, _count)| ready(*slope == 0.0))
            .for_each(|(_now, slope, _duration, _count)| {
                assert!(slope > 0.0);
                ready(())
            })
            .now_or_never()
            .unwrap();
    }

    // From WebRTC's TrendlineEstimatorTest::Underusing.
    #[test]
    fn underusing() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(20),
            RemoteInstant::from_millis(17),
            Duration::from_millis(17),
        )
        .take(25);
        let stream = calculate_delay_slopes_from_acks(acks);
        pin_mut!(stream);
        stream
            .skip_while(|(_now, slope, _duration, _count)| ready(*slope == 0.0))
            .for_each(|(_now, slope, _duration, _count)| {
                assert!(slope < 0.0);
                ready(())
            })
            .now_or_never()
            .unwrap();
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn eventually_drops_history() {
        let initial_departure = Instant::now();
        let interval = Duration::from_millis(20);
        let initial_arrival = RemoteInstant::from_millis(20_000);

        let acks = acks_at_regular_intervals(
            initial_departure,
            interval,
            initial_arrival,
            interval.saturating_sub(Duration::from_millis(3)),
        )
        .take(25);
        let later_acks = acks_at_regular_intervals(
            initial_departure + 25 * interval,
            interval,
            initial_arrival + 25 * interval,
            interval,
        )
        .take(100);
        let stream = calculate_delay_slopes_from_acks(acks.chain(later_acks));
        pin_mut!(stream);

        let mut slopes = stream.map(|(_now, slope, _duration, _count)| slope);
        assert_eq!(
            0.0,
            slopes.next().now_or_never().expect("ready").expect("next")
        );

        let mut slopes = slopes.skip_while(|slope| ready(0.0 == *slope));
        assert!(
            0.0 > slopes
                .next()
                .now_or_never()
                .expect("ready")
                .expect("has next")
        );

        let mut slopes = slopes.skip_while(|slope| ready(0.0 > *slope));
        assert!(
            0.0 < slopes
                .next()
                .now_or_never()
                .expect("ready")
                .expect("has next")
        );

        let mut slopes = slopes.skip_while(|slope| ready(0.0 < *slope));
        assert_eq!(
            0.0,
            slopes
                .next()
                .now_or_never()
                .expect("ready")
                .expect("has next")
        );
    }
}

// These constants are taken from WebRTC's TrendlineEstimator, but divided by
// sample_count_for_slope_shrinking, and then again by 4 to ignore
// WebRTC's "threshold gain", which does not seem to serve any purpose.
// This means they're all on the same scale as the incoming delay slopes.
// TODO: Maybe make some of these configurable
const INITIAL_DELAY_SLOPE_THRESHOLD: f64 = 0.052; // 52ms/s

// TODO: If this is set to 2.5ms/s, the low bitrate tests from WebRTC start passing.
// But is that a safe change?
const MIN_DELAY_SLOPE_THRESHOLD: f64 = 0.025; // 25ms/s
const MAX_DELAY_SLOPE_THRESHOLD: f64 = 2.5; // 2.5s/s

const SLOPE_THRESHOLD_ADAPTATION_MAX_DIFFERENCE: f64 = 0.0625; // 62.5ms/s

// Yields (latest_ack, direction)
fn calculate_delay_directions_from_slopes(
    delay_slopes: impl Stream<Item = (Instant, f64, Duration, usize)>,
) -> impl Stream<Item = (Instant, DelayDirection)> {
    // TODO: Maybe make some of these configurable
    let sample_count_for_slope_shrinking = 60;
    let increasing_duration_threshold = Duration::from_millis(10);

    let slope_threshold_adaptation_max_duration = Duration::from_millis(100);
    // Note that these are always multiplied by a duration that is at most
    // slope_threshold_adaption_max_duration above,
    // so the values aren't as extreme as they seem.
    let slope_threshold_adapt_up_diff_part_per_second = 8.7;
    let slope_threshold_adapt_down_diff_part_per_second = 39.0;

    stream! {
        pin_mut!(delay_slopes);
        if let Some((start_time, mut prev_delay_slope, _, _)) = delay_slopes.next().await {
            // Until we have 2 samples
            let mut direction = DelayDirection::Steady;
            let mut increasing_count = 0u64;
            let mut increasing_duration = None;
            let mut slope_threshold = INITIAL_DELAY_SLOPE_THRESHOLD;
            let mut slope_threshold_updated = start_time;

            yield (start_time, direction);

            while let Some((now, delay_slope, departure_delta, sample_count)) =
                delay_slopes.next().await
            {
                // We shrink the delay slope while we have few samples to make the threshold look bigger.
                // But it effectively shrinks as we get more samples.
                let shrunk_delay_slope = delay_slope
                    * min(sample_count_for_slope_shrinking, sample_count) as f64
                    / sample_count_for_slope_shrinking as f64;
                if shrunk_delay_slope > slope_threshold {
                    increasing_count += 1;
                    increasing_duration =
                        if let Some(previous_increasing_duration) = increasing_duration {
                            Some(previous_increasing_duration + departure_delta)
                        } else {
                            Some(departure_delta / 2)
                        };
                    if (increasing_count > 1)
                        && (increasing_duration.unwrap() > increasing_duration_threshold)
                        && (delay_slope >= prev_delay_slope)
                    {
                        direction = DelayDirection::Increasing;
                        increasing_count = 0;
                        increasing_duration = Some(Duration::ZERO);
                    } else {
                        // Yield the existing direction and wait for more "increasing" signals.
                    }
                } else if shrunk_delay_slope < -slope_threshold {
                    direction = DelayDirection::Decreasing;
                    increasing_count = 0;
                    increasing_duration = None;
                } else {
                    direction = DelayDirection::Steady;
                    increasing_count = 0;
                    increasing_duration = None;
                }

                let slope_threshold_diff = shrunk_delay_slope.abs() - slope_threshold;
                if slope_threshold_diff < SLOPE_THRESHOLD_ADAPTATION_MAX_DIFFERENCE {
                    let adaption_duration = min(
                        slope_threshold_adaptation_max_duration,
                        now.saturating_duration_since(slope_threshold_updated),
                    );
                    let adaptation_diff_part_per_second = if slope_threshold_diff > 0.0 {
                        slope_threshold_adapt_up_diff_part_per_second // up toward the slope (shrink the gap)
                    } else {
                        slope_threshold_adapt_down_diff_part_per_second // down toward the slope (shrink the gap)
                    };
                    let adaptation = adaptation_diff_part_per_second
                        * slope_threshold_diff
                        * adaption_duration.as_secs_f64();
                    slope_threshold = (slope_threshold + adaptation)
                        .clamp(MIN_DELAY_SLOPE_THRESHOLD, MAX_DELAY_SLOPE_THRESHOLD);
                }
                slope_threshold_updated = now;

                // We always yield a direction, even if it's the same as last time.
                // This is because we adjust the bitrate up or down further on repeated increases or decreases.
                yield (now, direction);

                prev_delay_slope = delay_slope;
            }
        }
    }
}

pub fn calculate_delay_directions(
    acks: impl Stream<Item = Ack>,
) -> impl Stream<Item = (Instant, DelayDirection)> {
    calculate_delay_directions_from_slopes(calculate_delay_slopes(calculate_ack_deltas(
        accumulate_ack_groups(acks),
    )))
}

#[cfg(test)]
mod calculate_delay_directions_from_slopes_tests {
    use std::future::ready;

    use futures::FutureExt;
    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    use super::*;
    use crate::googcc::stream::StreamExt as _;

    // From WebRTC's OveruseDetectorTest::SimpleNonOveruse30fps.
    #[test]
    fn simple_non_overuse_30_fps() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(33),
            RemoteInstant::from_millis(17),
            Duration::from_millis(33),
        );
        let stream = calculate_delay_directions(acks.take(1_000));
        pin_mut!(stream);
        assert_eq!(
            DelayDirection::Steady,
            stream
                .last()
                .now_or_never()
                .expect("ready")
                .expect("non-empty")
                .1
        );
    }

    // From WebRTC's OveruseDetectorTest::SimpleNonOveruseWithReceiveVariance.
    #[test]
    fn simple_non_overuse_with_arrival_variance() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(33),
            RemoteInstant::from_millis(17),
            Duration::from_millis(33),
        )
        .scan(false, |is_odd, ack| {
            let mut result = ack;
            if *is_odd {
                result.arrival += Duration::from_millis(10);
            }
            *is_odd = !*is_odd;
            ready(Some(result))
        });
        let stream = calculate_delay_directions(acks.take(1_000));
        pin_mut!(stream);
        assert_eq!(
            DelayDirection::Steady,
            stream
                .last()
                .now_or_never()
                .expect("ready")
                .expect("non-empty")
                .1
        );
    }

    // From WebRTC's OveruseDetectorTest::SimpleNonOveruseWithRtpTimestampVariance.
    #[test]
    fn simple_non_overuse_with_departure_variance() {
        let acks = acks_at_regular_intervals(
            Instant::now(),
            Duration::from_millis(33),
            RemoteInstant::from_millis(17),
            Duration::from_millis(33),
        )
        .scan(false, |is_odd, ack| {
            let mut result = ack;
            if *is_odd {
                result.departure += Duration::from_millis(10);
            }
            *is_odd = !*is_odd;
            ready(Some(result))
        });
        let stream = calculate_delay_directions(acks.take(1_000));
        pin_mut!(stream);
        assert_eq!(
            DelayDirection::Steady,
            stream
                .last()
                .now_or_never()
                .expect("ready")
                .expect("non-empty")
                .1
        );
    }

    // From WebRTC's OveruseDetectorTest::SimpleOveruse2000Kbit30fps.
    #[test]
    fn simple_overuse_2000_kbit_30_fps() {
        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(17);
        let interval = Duration::from_millis(33);

        let initial_acks =
            acks_at_regular_intervals(initial_departure, interval, initial_arrival, interval)
                .take(100_000);

        let next_departure = initial_departure + 100_000 * interval;
        let next_arrival = initial_arrival + 100_000 * interval;

        let delayed_acks = acks_at_regular_intervals(
            next_departure,
            interval,
            next_arrival,
            interval + Duration::MILLISECOND,
        )
        .take(1_000);

        let stream = calculate_delay_directions(
            initial_acks
                .chain(delayed_acks)
                // Six packets per frame.
                .flat_map(|ack| futures::stream::repeat(ack).take(6)),
        );
        pin_mut!(stream);
        assert_eq!(
            // Ten frames (sixty packets) past WebRTC because calculate_delay_slopes doesn't start
            // yielding until its window is full.
            Some(100_017 * interval + RTT_FOR_ACKS_AT_REGULAR_INTERVALS),
            stream
                .skip_while(|(_, direction)| ready(*direction != DelayDirection::Increasing))
                .map(|(instant, _)| instant.checked_duration_since(initial_departure).unwrap())
                .next()
                .now_or_never()
                .unwrap()
        );
    }

    // From WebRTC's OveruseDetectorTest::SimpleOveruse100kbit10fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn simple_overuse_100_kbit_10_fps() {
        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(17);
        let interval = Duration::from_millis(100);

        let initial_acks =
            acks_at_regular_intervals(initial_departure, interval, initial_arrival, interval)
                .take(100_000);

        let next_departure = initial_departure + 100_000 * interval;
        let next_arrival = initial_arrival + 100_000 * interval;

        let delayed_acks = acks_at_regular_intervals(
            next_departure,
            interval,
            next_arrival,
            interval + Duration::MILLISECOND,
        )
        .take(1_000);

        let stream = calculate_delay_directions(initial_acks.chain(delayed_acks));
        pin_mut!(stream);
        assert_eq!(
            Some(100_017 * interval + RTT_FOR_ACKS_AT_REGULAR_INTERVALS),
            stream
                .skip_while(|(_, direction)| ready(*direction != DelayDirection::Increasing))
                .map(|(instant, _)| instant.checked_duration_since(initial_departure).unwrap())
                .next()
                .now_or_never()
                .unwrap(),
            "XFAIL: should detect increasing delay"
        );
    }

    // From WebRTC's OveruseDetectorTest::OveruseWithLowVariance2000Kbit30fps.
    #[test]
    fn overuse_with_low_variance_2000_kbit_30_fps() {
        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(17);
        let interval = Duration::from_millis(33);

        let initial_acks =
            acks_at_regular_intervals(initial_departure, interval, initial_arrival, interval)
                .scan(false, |is_odd, ack| {
                    let mut result = ack;
                    if *is_odd {
                        result.arrival += Duration::from_millis(2);
                    }
                    *is_odd = !*is_odd;
                    ready(Some(result))
                })
                .take(1_000);

        let next_departure = initial_departure + 1_000 * interval;
        let next_arrival = initial_arrival + 1_000 * interval;

        let delayed_acks = acks_at_regular_intervals(
            next_departure,
            interval,
            next_arrival,
            interval + Duration::from_millis(6),
        )
        .take(1_000);

        let stream = calculate_delay_directions(
            initial_acks
                .chain(delayed_acks)
                // Six packets per frame.
                .flat_map(|ack| futures::stream::repeat(ack).take(6)),
        );
        pin_mut!(stream);
        assert_eq!(
            Some(1_007 * interval + RTT_FOR_ACKS_AT_REGULAR_INTERVALS),
            stream
                .skip_while(|(_, direction)| ready(*direction != DelayDirection::Increasing))
                .map(|(instant, _)| instant.checked_duration_since(initial_departure).unwrap())
                .next()
                .now_or_never()
                .unwrap()
        );
    }

    /// Runs a simulation that WebRTC is fond of.
    ///
    /// The estimator receives 100,000 frames with departures `frame_interval` apart,
    /// and arrivals offset by an extra Gaussian-chosen variance based on `arrival_std_dev`.
    /// Each frame may have multiple acks (`acks_per_frame`). Following those initial acks,
    /// the arrival times start to increase by `arrival_drift_per_frame`; for the test to succeed
    /// this increase must be detected.
    fn assert_increasing_after_drift_with_variance(
        frame_interval: Duration,
        arrival_std_dev: Duration,
        acks_per_frame: usize,
        arrival_drift_per_frame: Duration,
        assertion_tag: &str,
    ) {
        let variance = stream! {
            let gaussian = rand_distr::Normal::new(0.005, arrival_std_dev.as_secs_f64()).unwrap();
            let seed: u64 = match std::env::var("RANDOM_SEED") {
                Ok(v) => v.parse().unwrap(),
                Err(_) => thread_rng().gen(),
            };
            let mut rng = StdRng::seed_from_u64(seed);
            loop {
                yield rng.sample(gaussian);
            }
        };

        let initial_departure = Instant::now();
        let initial_arrival = RemoteInstant::from_millis(17);

        let initial_acks = acks_at_regular_intervals(
            initial_departure,
            frame_interval,
            initial_arrival,
            frame_interval,
        )
        .take(100_000);

        let next_departure = initial_departure + 100_000 * frame_interval;
        let next_arrival = initial_arrival + 100_000 * frame_interval;

        let delayed_acks = acks_at_regular_intervals(
            next_departure,
            frame_interval,
            next_arrival,
            frame_interval + arrival_drift_per_frame,
        )
        .take(1_000);

        let stream = calculate_delay_directions(
            initial_acks
                .chain(delayed_acks)
                .zip(variance)
                .map(|(mut ack, variance)| {
                    ack.arrival += Duration::from_millis(variance as u64);
                    ack
                })
                .flat_map(|ack| futures::stream::repeat(ack).take(acks_per_frame)),
        );
        pin_mut!(stream);
        let first_after_change = stream
            .skip_while(|(_, direction)| ready(*direction != DelayDirection::Increasing))
            .map(|(instant, _)| instant.checked_duration_since(initial_departure).unwrap())
            .next()
            .now_or_never()
            .expect("stream is synchronous");
        if let Some(first_after_change) = first_after_change {
            assert!(
                100_000 * frame_interval + RTT_FOR_ACKS_AT_REGULAR_INTERVALS < first_after_change,
            );
        } else {
            panic!("{}: never changed", assertion_tag)
        }
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance30Kbit3fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn low_gaussian_variance_30_kbit_3_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(333),
            Duration::from_millis(3),
            1,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVarianceFastDrift30Kbit3fps.
    #[test]
    fn low_gaussian_variance_fast_drift_30_kbit_3_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(333),
            Duration::from_millis(3),
            1,
            Duration::from_millis(100),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance30Kbit3fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn high_gaussian_variance_30_kbit_3_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(333),
            Duration::from_millis(10),
            1,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVarianceFastDrift30Kbit3fps.
    #[test]
    fn high_gaussian_variance_fast_drift_30_kbit_3_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(333),
            Duration::from_millis(10),
            1,
            Duration::from_millis(100),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance100Kbit5fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn low_gaussian_variance_100_kbit_5_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(200),
            Duration::from_millis(3),
            2,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance100Kbit5fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn high_gaussian_variance_100_kbit_5_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(200),
            Duration::from_millis(10),
            2,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance100Kbit10fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn low_gaussian_variance_100_kbit_10_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(100),
            Duration::from_millis(3),
            1,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance100Kbit10fps.
    #[test]
    #[should_panic(expected = "XFAIL")]
    fn high_gaussian_variance_100_kbit_10_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(100),
            Duration::from_millis(10),
            1,
            Duration::from_millis(1),
            "XFAIL",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance300Kbit30fps.
    #[test]
    fn low_gaussian_variance_300_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            1,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVarianceFastDrift300Kbit30fps.
    #[test]
    fn low_gaussian_variance_fast_drift_300_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            1,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance300Kbit30fps.
    #[test]
    fn high_gaussian_variance_300_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            1,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVarianceFastDrift300Kbit30fps.
    #[test]
    fn high_gaussian_variance_fast_drift_300_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            1,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance1000Kbit30fps.
    #[test]
    fn low_gaussian_variance_1000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            3,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVarianceFastDrift1000Kbit30fps.
    #[test]
    fn low_gaussian_variance_fast_drift_1000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            3,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance1000Kbit30fps.
    #[test]
    fn high_gaussian_variance_1000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            3,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVarianceFastDrift1000Kbit30fps.
    #[test]
    fn high_gaussian_variance_fast_drift_1000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            3,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVariance2000Kbit30fps.
    #[test]
    fn low_gaussian_variance_2000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            6,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::LowGaussianVarianceFastDrift2000Kbit30fps.
    #[test]
    fn low_gaussian_variance_fast_drift_2000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(3),
            6,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVariance2000Kbit30fps.
    #[test]
    fn high_gaussian_variance_2000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            6,
            Duration::from_millis(1),
            "",
        );
    }

    // From WebRTC's OveruseDetectorTest::HighGaussianVarianceFastDrift2000Kbit30fps.
    #[test]
    fn high_gaussian_variance_fast_drift_2000_kbit_30_fps() {
        assert_increasing_after_drift_with_variance(
            Duration::from_millis(33),
            Duration::from_millis(10),
            6,
            Duration::from_millis(10),
            "",
        );
    }

    // From WebRTC's OveruseDetectorExperimentTest::ThresholdAdapts.
    #[test]
    fn threshold_adapts() {
        let mut start_time = Instant::now();
        let incrementing_times = futures::stream::repeat_with(move || {
            start_time += Duration::from_millis(5);
            start_time
        });
        let slopes = stream! {
            let slope: f64 = 1.02 * INITIAL_DELAY_SLOPE_THRESHOLD;
            yield slope;
            yield 1.1 * slope;
            yield slope;
            for _ in 0..15usize {
                yield 0.7 * slope;
            }
            yield slope;
        };
        let batch_size = 10;
        let slope_tuples = slopes
            .flat_map(|slope| futures::stream::repeat(slope).take(batch_size))
            .zip(incrementing_times)
            .map(|(slope, now)| (now, slope, Duration::from_secs(3), 60));
        let stream = calculate_delay_directions_from_slopes(slope_tuples).chunks(batch_size);
        pin_mut!(stream);
        // First batch is increasing.
        assert!(stream
            .next()
            .now_or_never()
            .expect("ready")
            .expect("stream not ended")
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
        // Second batch is also increasing, but should raise the threshold...
        assert!(stream
            .next()
            .now_or_never()
            .expect("ready")
            .expect("stream not ended")
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
        // ...so that the third batch is not considered increasing.
        assert!(!stream
            .next()
            .now_or_never()
            .expect("ready")
            .expect("stream not ended")
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
        // But after many rounds of a lower value...
        let mut stream = stream.skip(14);
        assert!(!stream
            .next()
            .now_or_never()
            .expect("ready")
            .expect("stream not ended")
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
        // ...the last batch should be increasing again.
        assert!(stream
            .next()
            .now_or_never()
            .expect("ready")
            .expect("stream not ended")
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
    }

    // From WebRTC's OveruseDetectorExperimentTest::DoesntAdaptToSpikes.
    #[test]
    fn does_not_adapt_to_spikes() {
        let mut start_time = Instant::now();
        let incrementing_times = futures::stream::repeat_with(move || {
            start_time += Duration::from_millis(5);
            start_time
        });
        let slopes = stream! {
            let slope: f64 = 1.02 * INITIAL_DELAY_SLOPE_THRESHOLD;
            for _ in 0..10usize {
                yield slope;
            }
            for _ in 0..3usize {
                yield 20.0 * slope;
            }
            for _ in 0..10usize {
                yield slope;
            }
        };
        let slope_tuples = slopes
            .zip(incrementing_times)
            .map(|(slope, now)| (now, slope, Duration::from_secs(3), 60));
        let stream_output: Vec<_> = calculate_delay_directions_from_slopes(slope_tuples)
            .collect()
            .now_or_never()
            .unwrap();
        // After a few slopes, the increase should be detected.
        assert!(stream_output
            .iter()
            .any(|(_now, direction)| direction == &DelayDirection::Increasing));
        // Make sure that the spike does not update the threshold,
        // i.e. even the slopes after the spikes are still considered increasing.
        stream_output
            .into_iter()
            .skip_while(|(_now, direction)| direction == &DelayDirection::Steady)
            .for_each(|(now, direction)| {
                assert_eq!(
                    DelayDirection::Increasing,
                    direction,
                    "{:?}",
                    now.saturating_duration_since(start_time)
                );
            });
    }
}

fn mean(values: impl ExactSizeIterator<Item = f64>) -> Option<f64> {
    let count = values.len();
    if count == 0 {
        None
    } else {
        Some(values.sum::<f64>() / count as f64)
    }
}

/// Fits a slope to a number of (x, y) pairs
///
/// Returns `None` if there isn't enough data (zero or one pairs),
/// or if the slope would be infinite.
fn linear_regression(xys: impl ExactSizeIterator<Item = (f64, f64)> + Clone) -> Option<f64> {
    let xs = xys.clone().map(|(x, _y)| x);
    let ys = xys.map(|(_x, y)| y);
    let x_avg = mean(xs.clone())?;
    let y_avg = mean(ys.clone())?;
    let x_diffs = xs.map(|x_i| x_i - x_avg);
    let y_diffs = ys.map(|y_i| y_i - y_avg);
    let numerator: f64 = x_diffs
        .clone()
        .zip(y_diffs)
        .map(|(x_diff, y_diff)| x_diff * y_diff)
        .sum();
    let denominator: f64 = x_diffs.map(|x_diff| x_diff * x_diff).sum();
    if denominator == 0.0 {
        None // Would only happen if all the xs are the same, which means we don't have enough data.
    } else {
        Some(numerator / denominator)
    }
}

#[cfg(test)]
mod linear_regression_tests {
    use calling_common::AbsDiff;

    fn linear_regression(xys: &[(f64, f64)]) -> Option<f64> {
        super::linear_regression(xys.iter().copied())
    }

    #[test]
    fn none_on_empty() {
        assert_eq!(None, linear_regression(&[]));
    }

    #[test]
    fn none_on_single() {
        assert_eq!(None, linear_regression(&[(0.0, 0.0)]));
    }

    #[test]
    fn none_on_infinite_slope() {
        assert_eq!(None, linear_regression(&[(0.0, 0.0), (0.0, 1.0)]));
        assert_eq!(None, linear_regression(&[(0.0, 0.0), (0.0, -1.0)]));
        assert_eq!(
            None,
            linear_regression(&[(0.0, 0.0), (0.0, 1.0), (0.0, -1.0)])
        );
        assert_eq!(None, linear_regression(&[(1.0, 0.0), (1.0, 1.0)]));
    }

    #[test]
    fn flat_slope() {
        assert_eq!(Some(0.0), linear_regression(&[(0.0, 0.0), (1.0, 0.0)]));
        assert_eq!(Some(0.0), linear_regression(&[(0.0, 0.0), (-1.0, 0.0)]));
        assert_eq!(
            Some(0.0),
            linear_regression(&[(0.0, 0.0), (1.0, 0.0), (-1.0, 0.0)])
        );
        assert_eq!(Some(0.0), linear_regression(&[(0.0, 5.0), (1.0, 5.0)]));
    }

    #[test]
    fn linear() {
        assert_eq!(Some(1.0), linear_regression(&[(0.0, 0.0), (1.0, 1.0)]));
        assert_eq!(Some(1.0), linear_regression(&[(0.0, 0.0), (-1.0, -1.0)]));
        assert_eq!(
            Some(1.0),
            linear_regression(&[(0.0, 0.0), (1.0, 1.0), (-1.0, -1.0)])
        );
        assert_eq!(Some(1.0), linear_regression(&[(0.0, 5.0), (1.0, 6.0)]));
        assert_eq!(Some(1.0), linear_regression(&[(0.0, 0.0), (10.0, 10.0)]));

        assert_eq!(Some(0.5), linear_regression(&[(0.0, 0.0), (1.0, 0.5)]));
        assert_eq!(Some(0.5), linear_regression(&[(0.0, 0.0), (-1.0, -0.5)]));
        assert_eq!(
            Some(0.5),
            linear_regression(&[(0.0, 0.0), (1.0, 0.5), (-1.0, -0.5)])
        );
        assert_eq!(Some(0.5), linear_regression(&[(0.0, 5.0), (1.0, 5.5)]));
        assert_eq!(Some(0.5), linear_regression(&[(0.0, 0.0), (10.0, 5.0)]));
    }

    #[test]
    fn example_from_wikipedia() {
        // https://en.wikipedia.org/wiki/Simple_linear_regression#Numerical_example
        let samples = [
            (1.47, 52.21),
            (1.50, 53.12),
            (1.52, 54.48),
            (1.55, 55.84),
            (1.57, 57.20),
            (1.60, 58.57),
            (1.63, 59.93),
            (1.65, 61.29),
            (1.68, 63.11),
            (1.70, 64.47),
            (1.73, 66.28),
            (1.75, 68.10),
            (1.78, 69.92),
            (1.80, 72.19),
            (1.83, 74.46),
        ];
        let expected = 61.272;
        // We don't need a fully-general floating-point comparison here
        // because we know what we're comparing against, but if we get 61.273
        // or 61.271 out of our algorithm, that's probably still okay.
        let epsilon = 0.0015;

        match linear_regression(&samples) {
            Some(value) => assert!(
                expected.abs_diff(value) < epsilon,
                "expected: {}, actual: {}",
                expected,
                value
            ),
            None => panic!("should have found a slope"),
        }

        let mut samples_out_of_order = samples;
        samples_out_of_order[3..].rotate_left(5);
        match linear_regression(&samples_out_of_order) {
            Some(value) => assert!(
                expected.abs_diff(value) < epsilon,
                "expected: {}, actual: {}",
                expected,
                value
            ),
            None => panic!("should have found a slope"),
        }
    }
}
