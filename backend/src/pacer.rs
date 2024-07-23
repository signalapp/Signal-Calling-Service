//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    cmp::{max, min},
    collections::VecDeque,
};

use calling_common::{DataRate, DataSize, Duration, Instant};
use log::error;

use crate::rtp;

#[derive(Default)]
pub struct Config {
    /// The rate to send media (not padding)
    pub media_send_rate: DataRate,
    /// The rate to send padding (when no media is available)
    pub padding_send_rate: DataRate,
    /// The SSRC to use when sending padding.  If None, we can't send padding.
    pub padding_ssrc: Option<rtp::Ssrc>,
}

type Queue = VecDeque<rtp::Packet<Vec<u8>>>;

/// The maximum debt level, in terms of time, capped when sending packets.
/// Use same value as WebRTC.
const MAX_DEBT_IN_TIME: Duration = Duration::from_millis(500);

/// A Pacer smooths out the sending of packets such that we send packets at a regular interval
/// instead of in bursts.  It does so by queuing packets and then leaking them out.  If there
/// is nothing to leak out, it generates padding.  The padding send rate can be lower than the
/// media send rate to allow for cases where we want only want to pad up to some rate
/// (such as the ideal send rate) but can use the full target send rate when draining the queue.
pub struct Pacer {
    config: Config,

    video_queue: Queue,
    rtx_queue: Queue,
    queued_size: DataSize,
    last_sent: Option<Instant>,
    media_debt: DataSize,
    padding_debt: DataSize,
}

impl Pacer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            video_queue: Default::default(),
            rtx_queue: Default::default(),
            queued_size: Default::default(),
            last_sent: None,
            media_debt: Default::default(),
            padding_debt: Default::default(),
        }
    }

    pub fn set_config(&mut self, config: Config, now: Instant) -> Option<Instant> {
        let old_schedule = self.calculate_next_send_time(now);
        self.config = config;
        // Record a zero byte send which limits the maximum media and padding debt
        // so that the maximum wait time is MAX_DEBT_IN_TIME
        self.update_budget_with_sent_data(DataSize::ZERO);

        // Setting the last sent to a specific time below cleans up the
        // dequeue_delay metrics tracked in dequeue().

        if let Some(new_schedule) = self.calculate_next_send_time(now) {
            match old_schedule {
                None => {
                    if new_schedule < now {
                        // Old last sent could have been a long time ago.
                        self.update_budget_with_time(now);
                        Some(now)
                    } else {
                        // Leave last sent, it is recent enough that sending
                        // now would be above the configured rate.
                        Some(new_schedule)
                    }
                }
                Some(old_schedule) => {
                    if new_schedule <= now {
                        if old_schedule > now {
                            // The old timer wasn't late, this shouldn't be considered late either.
                            self.update_budget_with_time(now);
                        } else {
                            // Reset to previous scheduled time, so that the delay
                            // is tracked from when the previous timer was set.
                            self.update_budget_with_time(old_schedule);
                        }
                        Some(now)
                    } else {
                        Some(new_schedule)
                    }
                }
            }
        } else {
            None
        }
    }

    fn calculate_next_send_time(&self, now: Instant) -> Option<Instant> {
        if self.queue_is_empty() {
            self.calculate_next_padding_send_time(now)
        } else {
            self.calculate_next_media_send_time(now)
        }
    }

    fn calculate_next_media_send_time(&self, now: Instant) -> Option<Instant> {
        if self.config.media_send_rate > DataRate::ZERO {
            if let Some(last_sent_time) = self.last_sent {
                let drain_time = self.media_debt / self.config.media_send_rate;
                Some(last_sent_time + drain_time)
            } else {
                // We haven't sent anything, so go ahead and send now.
                Some(now)
            }
        } else {
            None
        }
    }

    fn calculate_next_padding_send_time(&self, now: Instant) -> Option<Instant> {
        if self.config.padding_send_rate > DataRate::ZERO
            && self.config.media_send_rate > DataRate::ZERO
        {
            if let Some(last_sent_time) = self.last_sent {
                let media_drain_time = self.media_debt / self.config.media_send_rate;
                let padding_drain_time = self.padding_debt / self.config.padding_send_rate;
                let drain_time = max(media_drain_time, padding_drain_time);
                Some(last_sent_time + drain_time)
            } else {
                // We haven't sent anything, so go ahead and send now.
                Some(now)
            }
        } else {
            None
        }
    }

    fn update_budget_with_time(&mut self, now: Instant) {
        if let Some(last_sent) = self.last_sent {
            if let Some(delta) = now.checked_duration_since(last_sent) {
                self.media_debt = self
                    .media_debt
                    .saturating_sub(min(self.media_debt, self.config.media_send_rate * delta));
                self.padding_debt = self.padding_debt.saturating_sub(min(
                    self.padding_debt,
                    self.config.padding_send_rate * delta,
                ));
                self.last_sent = Some(now);
            }
        } else {
            self.last_sent = Some(now);
        }
    }

    fn update_budget_with_sent_data(&mut self, size: DataSize) {
        self.media_debt += size;
        if self.config.media_send_rate != DataRate::ZERO {
            self.media_debt = min(
                self.media_debt,
                self.config.media_send_rate * MAX_DEBT_IN_TIME,
            );
        }
        // Any time a media packet is sent, the size is added to the media
        // debt *and* the padding debt.
        self.update_budget_with_sent_padding(size);
    }

    fn update_budget_with_sent_padding(&mut self, size: DataSize) {
        self.padding_debt += size;
        if self.config.padding_send_rate != DataRate::ZERO {
            self.padding_debt = min(
                self.padding_debt,
                self.config.padding_send_rate * MAX_DEBT_IN_TIME,
            );
        }
    }

    fn past_send_time(send_time: Option<Instant>, now: Instant) -> bool {
        if let Some(send_time) = send_time {
            now >= send_time
        } else {
            // None means "never"
            false
        }
    }

    pub fn enqueue(
        &mut self,
        media: rtp::Packet<Vec<u8>>,
        now: Instant,
    ) -> (Option<rtp::Packet<Vec<u8>>>, Option<Instant>) {
        let next_media_send_time = self.calculate_next_media_send_time(now);
        let was_empty = self.queue_is_empty();
        if was_empty && Self::past_send_time(next_media_send_time, now) {
            // Skip the queue
            self.update_budget_with_time(now);
            self.update_budget_with_sent_data(media.size());
            (Some(media), self.calculate_next_send_time(now))
        } else {
            self.queued_size += media.size();
            match media.is_rtx() {
                false => self.video_queue.push_back(media),
                true => self.rtx_queue.push_back(media),
            }
            if was_empty {
                (None, self.calculate_next_send_time(now))
            } else {
                // The next dequeue time shouldn't change because this isn't at the front of the queue.
                // So don't waste cycles scheduling it.
                (None, None)
            }
        }
    }

    fn queue_is_empty(&self) -> bool {
        self.video_queue.is_empty() && self.rtx_queue.is_empty()
    }

    pub fn queued_size(&self) -> DataSize {
        self.queued_size
    }

    pub fn queue_delay(&self, now: Instant) -> Option<Duration> {
        // padding ssrc is Some and padding rate is non-zero when there is video available to forward
        if self.config.padding_ssrc.is_some() && self.config.padding_send_rate > DataRate::ZERO {
            if let Some(next_send) = self.calculate_next_media_send_time(now) {
                // Ignore RTX queue, due to complexity
                if let Some(media) = self.video_queue.iter().next() {
                    if let Some(entry_time) = media.entry_time() {
                        return Some(next_send.saturating_duration_since(entry_time));
                    }
                } else {
                    return Some(now.saturating_duration_since(next_send));
                }
            }
        }
        None
    }

    fn pop_queue(
        queue: &mut Queue,
        queued_size: &mut DataSize,
        now: Instant,
    ) -> Option<rtp::Packet<Vec<u8>>> {
        while let Some(media) = queue.pop_front() {
            *queued_size = queued_size.saturating_sub(media.size());
            if media.is_past_deadline(now) {
                event!("calling.pacer.pop_queue_skip");
            } else {
                return Some(media);
            }
        }
        None
    }

    fn pop_rtx(&mut self, now: Instant) -> Option<rtp::Packet<Vec<u8>>> {
        Self::pop_queue(&mut self.rtx_queue, &mut self.queued_size, now)
    }
    fn pop_video(&mut self, now: Instant) -> Option<rtp::Packet<Vec<u8>>> {
        Self::pop_queue(&mut self.video_queue, &mut self.queued_size, now)
    }

    pub fn dequeue(
        &mut self,
        generate_padding: impl FnOnce(rtp::Ssrc) -> Option<rtp::Packet<Vec<u8>>>,
        now: Instant,
    ) -> (Option<rtp::Packet<Vec<u8>>>, Option<Instant>) {
        let was_empty = self.queue_is_empty();
        if !was_empty {
            // Maybe send media
            let next_media_send_time = self.calculate_next_media_send_time(now);
            if Self::past_send_time(next_media_send_time, now) {
                if let Some(next_send) = next_media_send_time {
                    let dequeue_delay = now.saturating_duration_since(next_send).as_micros();
                    if let Ok(dequeue_delay) = dequeue_delay.try_into() {
                        sampling_histogram!("calling.pacer.dequeue_delay_us.with_data", || {
                            dequeue_delay
                        });
                    }
                }
                if let Some(media) = self.pop_rtx(now).or_else(|| self.pop_video(now)) {
                    self.update_budget_with_time(now);
                    self.update_budget_with_sent_data(media.size());
                    return (Some(media), self.calculate_next_send_time(now));
                }
            } else {
                // Wait to send the front of the queue.
                // This doesn't require a reschedule because this can only happen if
                // a dequeue happened too early, which can only happen if we have more than
                // one outstanding scheduled dequeue, in which case there should be
                // another one coming up.
                event!("calling.pacer.dequeue.data.early");
                return (None, None);
            }
        }

        // Maybe send padding
        if let Some(padding_ssrc) = self.config.padding_ssrc {
            let next_padding_send_time = self.calculate_next_padding_send_time(now);
            if Self::past_send_time(next_padding_send_time, now) {
                if was_empty {
                    if let Some(next_send) = next_padding_send_time {
                        let dequeue_delay = now.saturating_duration_since(next_send).as_micros();
                        if let Ok(dequeue_delay) = dequeue_delay.try_into() {
                            sampling_histogram!("calling.pacer.dequeue_delay_us.padding", || {
                                dequeue_delay
                            });
                        }
                    }
                }
                if let Some(padding) = generate_padding(padding_ssrc) {
                    self.update_budget_with_time(now);
                    self.update_budget_with_sent_padding(padding.size());
                    (Some(padding), self.calculate_next_send_time(now))
                } else {
                    // For some reason padding generation failed.
                    error!("padding generation failed");
                    (None, None)
                }
            } else if !was_empty {
                // Reschedule, we're too early for padding, because we thought we had media, but it expired
                event!("calling.pacer.dequeue.padding.expired_data");
                (None, self.calculate_next_send_time(now))
            } else {
                // Wait to send padding.
                // This doesn't require a reschedule because this can only happen if
                // a dequeue happened too early, which can only happen if we have more than
                // one outstanding scheduled dequeue, in which case there should be
                // another one coming up.
                event!("calling.pacer.dequeue.padding.early");
                (None, None)
            }
        } else {
            // Can't send padding because it's not configured.
            (None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{cmp::Reverse, collections::BinaryHeap};

    use calling_common::Duration;

    // Wrap the Pacer to make it easier to use for testing.
    struct TestPacer {
        epoch: Instant,
        pacer: Pacer,
        scheduled_dequeue_times: BinaryHeap<Reverse<Instant>>,
    }

    impl TestPacer {
        fn new(config: Config) -> Self {
            let pacer = Pacer::new(config);
            Self {
                epoch: Instant::now(),
                pacer,
                scheduled_dequeue_times: BinaryHeap::new(),
            }
        }

        fn time_from_ms(&self, ms: u64) -> Instant {
            self.epoch + Duration::from_millis(ms)
        }

        fn time_as_ms(&self, time: Instant) -> u64 {
            time.saturating_duration_since(self.epoch).as_millis() as u64
        }

        fn push_scheduled_dequeue_time(&mut self, scheduled_dequeue_time: Instant) {
            self.scheduled_dequeue_times
                .push(Reverse(scheduled_dequeue_time));
        }

        fn pop_scheduled_dequeue_time_if_before(&mut self, deadline: Instant) -> Option<Instant> {
            let next_scheduled_dequeue_time = self.scheduled_dequeue_times.peek()?.0;
            if next_scheduled_dequeue_time < deadline {
                Some(self.scheduled_dequeue_times.pop()?.0)
            } else {
                None
            }
        }

        fn configure(
            &mut self,
            media_send_rate_kbps: u64,
            padding_send_rate_kbps: u64,
            padding_ssrc: Option<u32>,
            now_ms: u64,
        ) {
            if let Some(schedule) = self.pacer.set_config(
                Config {
                    media_send_rate: DataRate::from_kbps(media_send_rate_kbps),
                    padding_send_rate: DataRate::from_kbps(padding_send_rate_kbps),
                    padding_ssrc,
                },
                self.time_from_ms(now_ms),
            ) {
                self.push_scheduled_dequeue_time(schedule);
            }
        }

        fn queued_size(&self) -> DataSize {
            self.pacer.queued_size()
        }

        fn dequeue_until(
            &mut self,
            deadline_ms: u64,
            padding: &rtp::Packet<Vec<u8>>,
            media_sent_times_ms: &mut Vec<(rtp::FullSequenceNumber, u64)>,
            padding_sent_times_ms: &mut Vec<u64>,
        ) {
            let deadline = self.time_from_ms(deadline_ms);
            while let Some(dequeue_time) = self.pop_scheduled_dequeue_time_if_before(deadline) {
                let generate_padding = Box::new(|_| Some(padding.clone()));
                let (sent, schedule) = self.pacer.dequeue(generate_padding, dequeue_time);

                if let Some(sent) = sent {
                    let dequeue_time_ms = self.time_as_ms(dequeue_time);
                    if Some(sent.ssrc()) == self.pacer.config.padding_ssrc {
                        padding_sent_times_ms.push(dequeue_time_ms);
                    } else {
                        media_sent_times_ms.push((sent.seqnum(), dequeue_time_ms));
                    }
                }
                if let Some(schedule) = schedule {
                    self.push_scheduled_dequeue_time(schedule);
                }
            }
        }

        fn send(
            &mut self,
            send_times_ms: &[(rtp::FullSequenceNumber, u64)],
            media: &rtp::Packet<Vec<u8>>,
            padding: &rtp::Packet<Vec<u8>>,
        ) -> (Vec<(rtp::FullSequenceNumber, u64)>, Vec<u64>) {
            let mut media_sent_times_ms = Vec::new();
            let mut padding_sent_times_ms = Vec::new();
            for (seqnum, send_time_ms) in send_times_ms {
                self.dequeue_until(
                    *send_time_ms,
                    padding,
                    &mut media_sent_times_ms,
                    &mut padding_sent_times_ms,
                );

                let send_time = self.time_from_ms(*send_time_ms);
                let mut media = media.clone();
                media.set_seqnum_in_header(*seqnum);
                let (sent, schedule) = self.pacer.enqueue(media.clone(), send_time);
                if let Some(_sent) = sent {
                    media_sent_times_ms.push((*seqnum, *send_time_ms));
                }
                if let Some(schedule) = schedule {
                    self.push_scheduled_dequeue_time(schedule);
                }
            }
            (media_sent_times_ms, padding_sent_times_ms)
        }
    }

    #[test]
    fn test_pacer() {
        let mut pacer = TestPacer::new(Config::default());

        let media = {
            let pt = 108;
            let seqnum = 1;
            let timestamp = 1000;
            let ssrc = 10_000;
            let tcc_seqnum = 1;
            let payload = &[0u8; 1214];
            rtp::Packet::with_empty_tag(
                pt,
                seqnum,
                timestamp,
                ssrc,
                Some(tcc_seqnum),
                Some(pacer.epoch),
                payload,
            )
        };
        let padding_ssrc = 10_001;
        let padding = {
            let pt = 109;
            let seqnum = 2;
            let timestamp = 1001;
            let ssrc = padding_ssrc;
            let tcc_seqnum = 2;
            let payload = &[0u8; 1214];
            rtp::Packet::with_empty_tag(
                pt,
                seqnum,
                timestamp,
                ssrc,
                Some(tcc_seqnum),
                None,
                payload,
            )
        };
        // Each packet is 10kbit, which is a convenient number (each packet per 1ms makes 10mbps)
        assert_eq!(media.size().as_bytes(), 1250);
        assert_eq!(padding.size().as_bytes(), 1250);

        pacer.configure(10_000, 10_000, Some(padding_ssrc), 0);
        // If we send at or above the target rate, no padding is sent.
        let (media_sent_times_ms, padding_sent_times_ms) = pacer.send(
            &[
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (5, 5),
                (6, 6),
                (7, 7),
                (8, 8),
                (9, 9),
                (10, 10),
            ],
            &media,
            &padding,
        );
        assert_eq!(
            vec![
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (5, 5),
                (6, 6),
                (7, 7),
                (8, 8),
                (9, 9),
                (10, 10)
            ],
            media_sent_times_ms
        );
        // Reconfiguring triggers a packet being sent
        assert_eq!(vec![0], padding_sent_times_ms);

        // If we send lower than the targer rate, padding is sent
        let (media_sent_times_ms, padding_sent_times_ms) = pacer.send(
            &[(11, 12), (12, 14), (13, 16), (14, 18), (15, 20)],
            &media,
            &padding,
        );
        assert_eq!(
            vec![(11, 12), (12, 14), (13, 16), (14, 18), (15, 20)],
            media_sent_times_ms
        );
        assert_eq!(vec![11, 13, 15, 17, 19], padding_sent_times_ms);

        // If we lower the padding rate, we still send padding, but at a lower rate, but can still spike media up to a higher rate.
        pacer.configure(10_000, 5_000, Some(padding_ssrc), 20);
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(16, 29), (17, 30)], &media, &padding);
        assert_eq!(vec![(16, 29), (17, 30)], media_sent_times_ms);
        assert_eq!(vec![22, 24, 26, 28], padding_sent_times_ms);

        // If we lower the media rate, we will queue and then drain
        pacer.configure(5_000, 5_000, Some(padding_ssrc), 30);
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(18, 31), (19, 32), (20, 33), (21, 34)], &media, &padding);
        assert_eq!(vec![(18, 32)], media_sent_times_ms);
        assert_eq!(0, padding_sent_times_ms.len());
        assert_eq!(media.size() * 3.0, pacer.queued_size());
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(22, 40), (23, 50)], &media, &padding);
        assert_eq!(
            vec![(19, 34), (20, 36), (21, 38), (22, 40), (23, 50)],
            media_sent_times_ms
        );
        // No padding at t: 42, because data packets 16 and 17 (t: 29, 30) was beyond padding rate.
        // Padding debt will take 4 ms to pay off, before padding begins to be sent
        assert_eq!(vec![44, 46, 48], padding_sent_times_ms);
        assert_eq!(0, pacer.queued_size().as_bytes());

        // Edge case: send a padding packet and then queue media. Media is
        // sent immediately, as there is no media debt.
        pacer.configure(5_000, 2_500, Some(padding_ssrc), 50);
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(24, 55)], &media, &padding);
        assert_eq!(vec![54], padding_sent_times_ms);
        assert_eq!(vec![(24, 55)], media_sent_times_ms);

        let mut media_sent_times_ms = Vec::new();
        let mut padding_sent_times_ms = Vec::new();
        pacer.dequeue_until(
            60,
            &padding,
            &mut media_sent_times_ms,
            &mut padding_sent_times_ms,
        );
        assert_eq!(0, media_sent_times_ms.len());
        assert_eq!(0, padding_sent_times_ms.len());

        // Disable sending
        pacer.configure(0, 0, None, 60);
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(25, 60)], &media, &padding);
        assert_eq!(0, media_sent_times_ms.len());
        assert_eq!(0, padding_sent_times_ms.len());

        // Re-enable sending a little before 3 seconds out
        pacer.configure(1000, 500, Some(padding_ssrc), 2990);
        let (media_sent_times_ms, padding_sent_times_ms) =
            pacer.send(&[(26, 2990), (27, 2990)], &media, &padding);

        assert_eq!(0, padding_sent_times_ms.len());
        assert_eq!(0, media_sent_times_ms.len());

        let mut media_sent_times_ms = Vec::new();
        let mut padding_sent_times_ms = Vec::new();
        pacer.dequeue_until(
            3050,
            &padding,
            &mut media_sent_times_ms,
            &mut padding_sent_times_ms,
        );

        // pacer will discard packets over 3 seconds old, so packet 27 doesn't get sent at 3010
        // padding will be timed from the last send (3000)
        assert_eq!(vec![(25, 2990), (26, 3000)], media_sent_times_ms);
        assert_eq!(vec![3030], padding_sent_times_ms);
    }
}
