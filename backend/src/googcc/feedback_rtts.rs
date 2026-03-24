//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use calling_common::{Duration, RingBuffer};

use crate::transportcc::Ack;

// TODO: Consider making this configurable
const FEEDBACK_RTTS_HISTORY_LEN: usize = 32;
pub const FEEDBACK_RTTS_DEFAULT: Duration = Duration::from_millis(100);

pub struct FeedbackRttEstimator {
    history: RingBuffer<Duration>,
}

impl FeedbackRttEstimator {
    pub fn new() -> Self {
        let history = RingBuffer::new(FEEDBACK_RTTS_HISTORY_LEN);
        Self { history }
    }

    pub fn next(&mut self, acks: &[Ack]) -> Duration {
        if let Some(max_feedback_rtt) = acks
            .iter()
            .map(|ack| {
                ack.feedback_arrival
                    .saturating_duration_since(ack.departure)
            })
            .max()
        {
            self.history.push(max_feedback_rtt);
        }

        if !self.history.is_empty() {
            self.history.iter().sum::<Duration>() / (self.history.len() as u32)
        } else {
            FEEDBACK_RTTS_DEFAULT
        }
    }
}

#[cfg(test)]
mod tests {
    use calling_common::Instant;

    use super::*;
    use crate::transportcc::RemoteInstant;

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
        let mut feedback = FeedbackRttEstimator::new();
        assert_eq!(
            30,
            feedback.next(&acks_from_rtts(&[10, 20, 30])).as_millis()
        );
        assert_eq!(
            45,
            feedback.next(&acks_from_rtts(&[60, 50, 40])).as_millis()
        );
        assert_eq!(50, feedback.next(&acks_from_rtts(&[60, 50])).as_millis());
    }

    #[test]
    fn no_update_for_no_acks() {
        let mut feedback = FeedbackRttEstimator::new();
        assert_eq!(FEEDBACK_RTTS_DEFAULT, feedback.next(&acks_from_rtts(&[])));
        assert_eq!(20, feedback.next(&acks_from_rtts(&[20])).as_millis());
        assert_eq!(20, feedback.next(&acks_from_rtts(&[])).as_millis());
        assert_eq!(25, feedback.next(&acks_from_rtts(&[30])).as_millis());
        assert_eq!(25, feedback.next(&acks_from_rtts(&[])).as_millis());
    }

    #[test]
    fn bounded_history() {
        let mut feedback = FeedbackRttEstimator::new();
        assert_eq!(1000, feedback.next(&acks_from_rtts(&[1000])).as_millis());
        for _ in 1..FEEDBACK_RTTS_HISTORY_LEN {
            feedback.next(&acks_from_rtts(&[1]));
        }
        assert_eq!(1, feedback.next(&acks_from_rtts(&[1])).as_millis());
    }

    #[test]
    fn handles_negative_rtt() {
        let mut feedback = FeedbackRttEstimator::new();
        let start_time = Instant::now();

        let acks = vec![Ack {
            size: Default::default(),
            departure: start_time,
            arrival: RemoteInstant::from_millis(0),
            feedback_arrival: start_time - Duration::from_millis(1),
        }];

        assert_eq!(0, feedback.next(&acks).as_millis());
    }
}
