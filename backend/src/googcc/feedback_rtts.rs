//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_stream::stream;
use calling_common::{Duration, RingBuffer};
use futures::{pin_mut, Stream, StreamExt};

use crate::transportcc::Ack;

// TODO: Consider making this configurable
const FEEDBACK_RTTS_HISTORY_LEN: usize = 32;

pub fn estimate_feedback_rtts(
    ack_reports: impl Stream<Item = Vec<Ack>>,
) -> impl Stream<Item = Duration> {
    stream! {
        let mut history: RingBuffer<Duration> = RingBuffer::new(FEEDBACK_RTTS_HISTORY_LEN);
        pin_mut!(ack_reports);
        while let Some(acks) = ack_reports.next().await {
            if let Some(max_feedback_rtt) = acks
                .iter()
                .map(|ack| {
                    ack.feedback_arrival
                        .saturating_duration_since(ack.departure)
                })
                .max()
            {
                history.push(max_feedback_rtt);
                let mean_feedback_rtt: Duration =
                    history.iter().sum::<Duration>() / (history.len() as u32);
                yield mean_feedback_rtt;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;
    use crate::transportcc::RemoteInstant;
    use calling_common::Instant;

    /// Creates an `Ack` for each RTT, setting the departure and feedback-arrival times.
    ///
    /// The size and arrival duration should be ignored.
    fn acks_from_rtts(rtts: &[u64]) -> Vec<Ack> {
        let start_time = Instant::now();

        rtts.iter()
            .map(|rtt| Ack {
                size: Default::default(),
                departure: start_time,
                arrival: RemoteInstant::from_millis(0),
                feedback_arrival: start_time + Duration::from_millis(*rtt),
            })
            .collect()
    }

    #[test]
    fn running_average_of_max() {
        let stream = estimate_feedback_rtts(stream! {
            yield acks_from_rtts(&[10, 20, 30]);
            yield acks_from_rtts(&[60, 50, 40]);
            yield acks_from_rtts(&[60, 50]);
        });
        pin_mut!(stream);
        assert_eq!(
            &[30, 45, 50],
            &stream
                .map(|d| d.as_millis())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn no_update_for_no_acks() {
        let stream = estimate_feedback_rtts(stream! {
            yield vec![];
            yield acks_from_rtts(&[20]);
            yield vec![];
            yield acks_from_rtts(&[30]);
            yield vec![];
        });
        pin_mut!(stream);
        assert_eq!(
            &[20, 25],
            &stream
                .map(|d| d.as_millis())
                .collect::<Vec<_>>()
                .now_or_never()
                .unwrap()[..]
        );
    }

    #[test]
    fn bounded_history() {
        let stream = estimate_feedback_rtts(stream! {
            yield acks_from_rtts(&[1000]);
            loop {
                yield acks_from_rtts(&[1]);
            }
        });
        pin_mut!(stream);
        assert_eq!(
            1,
            stream
                .skip(FEEDBACK_RTTS_HISTORY_LEN)
                .next()
                .now_or_never()
                .expect("stream is ready")
                .expect("and not complete")
                .as_millis(),
        );
    }

    #[test]
    fn handles_negative_rtt() {
        let start_time = Instant::now();

        let acks = vec![Ack {
            size: Default::default(),
            departure: start_time,
            arrival: RemoteInstant::from_millis(0),
            feedback_arrival: start_time - Duration::from_millis(1),
        }];

        let stream = estimate_feedback_rtts(stream! {
            yield acks;
        });
        pin_mut!(stream);
        assert_eq!(
            0,
            stream
                .next()
                .now_or_never()
                .expect("stream is ready")
                .expect("and not complete")
                .as_millis(),
        );
    }
}
