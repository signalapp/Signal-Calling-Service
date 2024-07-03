//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use byteorder::{ReadBytesExt, BE};
use calling_common::{Bits, Duration, Instant, KeySortedCache, Writer};

use super::{FullSequenceNumber, Ssrc, TruncatedSequenceNumber};

const MAX_NACK_RETRY_COUNT: u8 = 10;

pub(super) struct NackSender {
    limit: usize,
    sent_by_seqnum: KeySortedCache<FullSequenceNumber, Option<(Instant, Instant, u8)>>,
    max_received: Option<FullSequenceNumber>,
}

impl NackSender {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            sent_by_seqnum: KeySortedCache::new(limit),
            max_received: None,
        }
    }

    // If there are any new unreceived seqnums (the need to send nacks), returns the necessary seqnums to nack.
    pub fn remember_received(&mut self, seqnum: FullSequenceNumber) {
        use std::cmp::Ordering::*;

        if let Some(max_received) = &mut self.max_received {
            match seqnum.cmp(max_received) {
                Equal => {
                    // We already received it, so nothing to do.
                }
                Less => {
                    // We likely already sent a NACK, so make sure we don't
                    // send a NACK any more.
                    self.sent_by_seqnum.remove(&seqnum);
                }
                Greater => {
                    let prev_max_received = std::mem::replace(max_received, seqnum);
                    let mut missing_range = prev_max_received.saturating_add(1)..seqnum;
                    let missing_count = missing_range.end - missing_range.start;
                    if missing_count > (self.limit as u64) {
                        // Everything is going to get removed anyway, so this is a bit faster.
                        self.sent_by_seqnum = KeySortedCache::new(self.limit);
                        // Only insert the last ones.  The beginning ones would get pushed out anyway.
                        missing_range =
                            (missing_range.end - (self.limit as u64))..missing_range.end;
                    }
                    for missing_seqnum in missing_range {
                        // This marks it as needing to be sent the next call to send_nacks()
                        self.sent_by_seqnum.insert(missing_seqnum, None);
                    }
                }
            }
        } else {
            // This is the first seqnum, so there is nothing to NACK and it's the max.
            self.max_received = Some(seqnum);
        }
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn send_nacks<'sender>(
        &'sender mut self,
        now: Instant,
        rtt: Duration,
    ) -> Option<impl Iterator<Item = FullSequenceNumber> + 'sender> {
        let mut send_any = false;
        self.sent_by_seqnum.retain(|_seqnum, sent| {
            if let Some((first_sent, last_sent, retry_count)) = sent {
                if now.saturating_duration_since(*first_sent) >= Duration::from_secs(3)
                    || *retry_count >= MAX_NACK_RETRY_COUNT
                {
                    // Expire it.
                    false
                } else if now.saturating_duration_since(*last_sent) >= rtt {
                    // It has already been sent, but should be sent again.
                    send_any = true;
                    *last_sent = now;
                    *retry_count += 1;
                    true
                } else {
                    // It has already been sent and does not need to be sent again yet.
                    true
                }
            } else {
                // It hasn't been sent yet but should be.
                send_any = true;
                *sent = Some((
                    now,
                    now,
                    sent.map(|(_, _, retry_count)| retry_count).unwrap_or(0) + 1,
                ));
                true
            }
        });

        if send_any {
            Some(
                self.sent_by_seqnum
                    .iter()
                    .filter_map(move |(seqnum, sent)| {
                        if now == sent.unwrap().1 {
                            Some(*seqnum)
                        } else {
                            None
                        }
                    }),
            )
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nack {
    pub ssrc: Ssrc,
    pub seqnums: Vec<TruncatedSequenceNumber>,
}

pub fn parse_nack(rtcp_payload: &[u8]) -> std::io::Result<Nack> {
    let mut reader = rtcp_payload;
    let ssrc = reader.read_u32::<BE>()?;
    let mut seqnums = Vec::new();
    while !reader.is_empty() {
        let first_seqnum = reader.read_u16::<BE>()?;
        let mask = reader.read_u16::<BE>()?;
        let entry_seqnums =
            std::iter::once(first_seqnum).chain((0..16u16).filter_map(move |index| {
                if mask.ls_bit(index as u8) {
                    Some(first_seqnum.wrapping_add(index + 1))
                } else {
                    None
                }
            }));
        seqnums.extend(entry_seqnums);
    }
    Ok(Nack { ssrc, seqnums })
}

// This will only work well if the iterator provides seqnums in order.
// pub for tests
pub fn write_nack(
    ssrc: Ssrc,
    mut seqnums: impl Iterator<Item = FullSequenceNumber>,
) -> impl Writer {
    let mut items: Vec<(TruncatedSequenceNumber, u16)> = vec![];
    if let Some(mut first_seqnum) = seqnums.next() {
        let mut mask = 0u16;
        for seqnum in seqnums {
            let diff = seqnum.saturating_sub(first_seqnum);
            if (1..=16).contains(&diff) {
                let index = (diff - 1) as u8;
                mask = mask.set_ls_bit(index);
            } else {
                // Record this item and reset to another item
                items.push((first_seqnum as u16, mask));
                first_seqnum = seqnum;
                mask = 0u16;
            }
        }
        items.push((first_seqnum as u16, mask))
    }
    (ssrc, items)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_write_parse_nack() {
        assert!(parse_nack(&[]).is_err());
        // invalid SSRC
        assert!(parse_nack(&[1u8, 2, 3,]).is_err());
        // invalid nack item
        assert!(parse_nack(&[1u8, 2, 3, 4, 5,]).is_err());

        // convenience function
        fn expand_seqnums(
            seqnums: &[TruncatedSequenceNumber],
        ) -> impl Iterator<Item = FullSequenceNumber> + '_ {
            seqnums.iter().map(|seqnum| *seqnum as FullSequenceNumber)
        }

        let ssrc = 0x1020304;
        let seqnums = vec![];
        let payload = vec![1u8, 2, 3, 4];
        assert_eq!(payload, write_nack(ssrc, expand_seqnums(&seqnums)).to_vec());
        assert_eq!(Nack { ssrc, seqnums }, parse_nack(&payload).unwrap());

        // Example from WebRTC modules/rtp_rtcp/source/rtcp_packet/nack_unittest.cc.
        let seqnums = vec![0, 1, 3, 8, 16];
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x80, 0x85];
        assert_eq!(payload, write_nack(ssrc, expand_seqnums(&seqnums)).to_vec());
        assert_eq!(Nack { ssrc, seqnums }, parse_nack(&payload).unwrap());

        let seqnums = vec![
            // First item
            0x0506, 0x0508, 0x0509, 0x050B, 0x050C, 0x050E, 0x050F, 0x0511, 0x0513, 0x0515, 0x0516,
            // Second item
            0x0518, 0x0519, 0x051B, 0x051C, 0x051D, 0x0525, 0x0526, 0x0527, 0x0528,
        ];
        let payload = vec![
            1u8, 2, 3, 4, // SSRC
            5, 6, // First seqnum
            0b11010101, 0b10110110, // First bitmask
            5, 0x18, // Second seqnum
            0b11110000, 0b00011101, // Second bitmask
        ];
        assert_eq!(payload, write_nack(ssrc, expand_seqnums(&seqnums)).to_vec());
        assert_eq!(Nack { ssrc, seqnums }, parse_nack(&payload).unwrap());

        // Make sure rollover works
        let seqnums = vec![0xFFFF, 0, 1];
        let payload = [
            1u8,
            2,
            3,
            4,
            0xFF,
            0xFF, // First seqnum
            0b000000000,
            0b000000011,
        ];
        assert_eq!(Nack { ssrc, seqnums }, parse_nack(&payload).unwrap());
    }

    #[test]
    fn test_nack_sender() {
        let mut nack_sender = NackSender::new(5);
        fn collect_seqnums(
            seqnums: Option<impl Iterator<Item = FullSequenceNumber>>,
        ) -> Option<Vec<FullSequenceNumber>> {
            seqnums.map(|seqnums| seqnums.collect::<Vec<_>>())
        }

        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(0), Duration::from_millis(200)))
        );

        nack_sender.remember_received(3);
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(30), Duration::from_millis(200)))
        );

        nack_sender.remember_received(4);
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(40), Duration::from_millis(200)))
        );

        // 5 went missing
        nack_sender.remember_received(6);
        assert_eq!(
            Some(vec![5]),
            collect_seqnums(nack_sender.send_nacks(at(60), Duration::from_millis(200)))
        );

        // Not long enough for a resend
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(70), Duration::from_millis(200)))
        );
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(80), Duration::from_millis(200)))
        );

        nack_sender.remember_received(9);
        assert_eq!(
            Some(vec![7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(90), Duration::from_millis(200)))
        );

        // Long enough for a resend of 5 but not 7 or 8
        assert_eq!(
            Some(vec![5]),
            collect_seqnums(nack_sender.send_nacks(at(260), Duration::from_millis(200)))
        );

        // Resending all of them
        assert_eq!(
            Some(vec![5, 7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(460), Duration::from_millis(200)))
        );
        assert_eq!(
            Some(vec![5, 7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(1860), Duration::from_millis(200)))
        );

        // 5 has timed out but not 7 or 8
        assert_eq!(
            Some(vec![7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(3070), Duration::from_millis(200)))
        );

        // Now they have all timed out
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(3090), Duration::from_millis(200)))
        );

        // And there's a limited history window
        nack_sender.remember_received(208);
        assert_eq!(
            Some(vec![203, 204, 205, 206, 207]),
            collect_seqnums(nack_sender.send_nacks(at(3080), Duration::from_millis(200)))
        );

        nack_sender.remember_received(60000);
        assert_eq!(
            Some(vec![59995, 59996, 59997, 59998, 59999]),
            collect_seqnums(nack_sender.send_nacks(at(4000), Duration::from_millis(200)))
        );

        // All are timed out now
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(8000), Duration::from_millis(200)))
        );

        // The number of retries is limited
        nack_sender.remember_received(60002);
        for i in 0..10 {
            assert_eq!(
                Some(vec![60001]),
                collect_seqnums(
                    nack_sender.send_nacks(at(8000 + (i * 100)), Duration::from_millis(100))
                )
            );
        }
        assert_eq!(
            None,
            collect_seqnums(nack_sender.send_nacks(at(9000), Duration::from_millis(100)))
        );
    }
}
