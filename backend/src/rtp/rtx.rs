//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use calling_common::{Duration, Instant, TwoGenerationCache};
use metrics::event;

use super::{types::*, Packet};
use crate::rtp::tcc;

const RTX_PAYLOAD_TYPE_OFFSET: PayloadType = 10;
const RTX_SSRC_OFFSET: Ssrc = 1;

// Keeps a cache of previously sent packets over a limited time window
// and can be asked to create an RTX packet from one of those packets
// based on SSRC and seqnum.  The cache is across SSRCs, not per SSRC.
pub(super) struct RtxSender {
    // The key includes an SSRC because we send packets with many SSRCs
    // and a truncated seqnum because we need to look them up by
    // seqnums in NACKs which are truncated.
    previously_sent_by_seqnum: TwoGenerationCache<(Ssrc, TruncatedSequenceNumber), Packet<Vec<u8>>>,
    next_outgoing_seqnum_by_ssrc: HashMap<Ssrc, FullSequenceNumber>,
}

impl RtxSender {
    pub(super) fn new(limit: Duration) -> Self {
        Self {
            previously_sent_by_seqnum: TwoGenerationCache::new(limit, Instant::now()),
            next_outgoing_seqnum_by_ssrc: HashMap::new(),
        }
    }

    fn get_next_seqnum_mut(&mut self, rtx_ssrc: Ssrc) -> &mut FullSequenceNumber {
        self.next_outgoing_seqnum_by_ssrc
            .entry(rtx_ssrc)
            .or_insert(1)
    }

    pub(super) fn increment_seqnum(&mut self, rtx_ssrc: Ssrc) -> FullSequenceNumber {
        let next_seqnum = self.get_next_seqnum_mut(rtx_ssrc);
        let seqnum = *next_seqnum;
        *next_seqnum += 1;
        seqnum
    }

    pub(super) fn remember_sent(&mut self, outgoing: Packet<Vec<u8>>, departed: Instant) {
        if !outgoing.is_past_deadline(departed) {
            self.previously_sent_by_seqnum.insert(
                (
                    outgoing.ssrc(),
                    outgoing.seqnum() as TruncatedSequenceNumber,
                ),
                outgoing,
                departed,
            );
        }
    }

    pub(super) fn resend_as_rtx(
        &mut self,
        ssrc: Ssrc,
        seqnum: TruncatedSequenceNumber,
        now: Instant,
        get_tcc_seqnum: impl FnOnce() -> tcc::FullSequenceNumber,
    ) -> Option<Packet<Vec<u8>>> {
        let rtx_ssrc = to_rtx_ssrc(ssrc);
        let rtx_seqnum = *self.get_next_seqnum_mut(rtx_ssrc);

        let previously_sent = self.previously_sent_by_seqnum.get_mut(&(ssrc, seqnum))?;
        if previously_sent.is_past_deadline(now) && previously_sent.pending_retransmission {
            event!("calling.rtp.rtx_expired_duplicate_skip");
            return None;
        }
        if previously_sent.pending_retransmission {
            event!("calling.rtp.rtx_duplicate_skip");
            return None;
        }
        if previously_sent.is_past_deadline(now) {
            event!("calling.rtp.rtx_resend_skip");
            return None;
        }
        previously_sent.pending_retransmission = true;
        let mut rtx = previously_sent.to_rtx(rtx_seqnum);
        // This has to go after the use of previously_sent.to_rtx because previously_sent
        // has a ref to self.previously_sent_by_seqnum until then, and so we can't
        // get a mut ref to self.next_outgoing_seqnum until after we release that.
        // But we don't want to call self.increment_seqnum() before we call self.previously_sent_by_seqnum.get
        // because it might return None, in which case we don't want to waste a seqnum.
        self.increment_seqnum(rtx_ssrc);
        rtx.set_tcc_seqnum_in_header_if_present(get_tcc_seqnum);
        Some(rtx)
    }

    pub(super) fn send_padding(
        &mut self,
        rtx_ssrc: Ssrc,
        tcc_seqnum: tcc::FullSequenceNumber,
    ) -> Packet<Vec<u8>> {
        // TODO: Use RTX packets from the cache if there are any.

        // This just needs to be something the clients won't try and decode as video.
        const PADDING_PAYLOAD_TYPE: PayloadType = 99;
        // These aren't used; they just need to take up space.
        const PADDING_TIMESTAMP: TruncatedTimestamp = 0;
        const PADDING_PAYLOAD: [u8; 1136] = [0u8; 1136];

        let rtx_seqnum = self.increment_seqnum(rtx_ssrc);
        Packet::with_empty_tag(
            PADDING_PAYLOAD_TYPE,
            rtx_seqnum,
            PADDING_TIMESTAMP,
            rtx_ssrc,
            Some(tcc_seqnum),
            None,
            &PADDING_PAYLOAD[..],
        )
    }

    pub(super) fn remembered_packet_stats(&self) -> (usize, usize) {
        let mut count = 0usize;
        let mut sum_of_packets = 0usize;
        self.previously_sent_by_seqnum
            .iter()
            .for_each(|(_, packet)| {
                count += 1;
                sum_of_packets += packet.serialized().len()
            });
        (count, sum_of_packets)
    }

    pub(super) fn mark_as_sent(&mut self, ssrc: Ssrc, seqnum: TruncatedSequenceNumber) {
        if let Some(packet) = self.previously_sent_by_seqnum.get_mut(&(ssrc, seqnum)) {
            packet.pending_retransmission = false;
        }
    }
}

pub(super) fn to_rtx_payload_type(pt: PayloadType) -> PayloadType {
    pt.wrapping_add(RTX_PAYLOAD_TYPE_OFFSET)
}

pub fn to_rtx_ssrc(ssrc: Ssrc) -> Ssrc {
    ssrc.wrapping_add(RTX_SSRC_OFFSET)
}

pub(super) fn from_rtx_payload_type(rtx_pt: PayloadType) -> PayloadType {
    rtx_pt.wrapping_sub(RTX_PAYLOAD_TYPE_OFFSET)
}

pub(super) fn from_rtx_ssrc(rtx_ssrc: Ssrc) -> Ssrc {
    rtx_ssrc.wrapping_sub(RTX_SSRC_OFFSET)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rtp::VP8_PAYLOAD_TYPE;

    const VP8_RTX_PAYLOAD_TYPE: PayloadType = 118;

    #[test]
    fn test_rtx_sender() {
        let history_limit = Duration::from_millis(10000);
        let mut rtx_sender = RtxSender::new(history_limit);

        fn sent_packet(ssrc: Ssrc, seqnum: FullSequenceNumber, now: Instant) -> Packet<Vec<u8>> {
            let timestamp = seqnum as TruncatedTimestamp;
            let tcc_seqnum = seqnum;
            let payload = &[];
            Packet::with_empty_tag(
                VP8_PAYLOAD_TYPE,
                seqnum,
                timestamp,
                ssrc,
                Some(tcc_seqnum),
                Some(now),
                payload,
            )
        }

        fn rtx_packet(
            ssrc: Ssrc,
            seqnum: FullSequenceNumber,
            rtx_seqnum: FullSequenceNumber,
            tcc_seqnum: tcc::FullSequenceNumber,
            now: Instant,
            pending_retransmission: bool,
        ) -> Packet<Vec<u8>> {
            let timestamp = seqnum as TruncatedTimestamp;
            let payload = &(seqnum as u16).to_be_bytes();
            let mut rtx = Packet::with_empty_tag(
                VP8_RTX_PAYLOAD_TYPE,
                rtx_seqnum,
                timestamp,
                ssrc + 1,
                Some(tcc_seqnum),
                Some(now),
                payload,
            );
            rtx.seqnum_in_payload = Some(seqnum);
            rtx.pending_retransmission = pending_retransmission;
            rtx
        }

        fn padding_packet(
            rtx_ssrc: Ssrc,
            rtx_seqnum: FullSequenceNumber,
            tcc_seqnum: tcc::FullSequenceNumber,
        ) -> Packet<Vec<u8>> {
            const PAYLOAD: [u8; 1136] = [0u8; 1136];
            let timestamp = 0;
            Packet::with_empty_tag(
                99,
                rtx_seqnum,
                timestamp,
                rtx_ssrc,
                Some(tcc_seqnum),
                None,
                &PAYLOAD[..],
            )
        }

        let now = Instant::now();
        rtx_sender.remember_sent(sent_packet(2, 11, now), now);
        rtx_sender.remember_sent(sent_packet(4, 21, now), now + Duration::from_millis(2000));
        assert_eq!(
            Some(rtx_packet(2, 11, 1, 101, now, true)),
            rtx_sender.resend_as_rtx(2, 11, now, || 101)
        );
        // The same packet can't be sent again while the previous send is pending.
        assert_eq!(None, rtx_sender.resend_as_rtx(2, 11, now, || 102));
        // Once the packet has been sent, another retransmission can be made.
        rtx_sender.mark_as_sent(2, 11);
        assert_eq!(
            Some(rtx_packet(2, 11, 2, 102, now, true)),
            rtx_sender.resend_as_rtx(2, 11, now, || 102)
        );
        // Make sure wrong SSRC or seqnum is ignored.
        assert_eq!(None, rtx_sender.resend_as_rtx(0, 11, now, || 101));
        assert_eq!(None, rtx_sender.resend_as_rtx(2, 12, now, || 101));

        // Push some things out of the history
        rtx_sender.remember_sent(
            sent_packet(2, 12, now + Duration::from_millis(14000)),
            now + Duration::from_millis(14000),
        );
        rtx_sender.remember_sent(
            sent_packet(4, 22, now + Duration::from_millis(16000)),
            now + Duration::from_millis(16000),
        );
        rtx_sender.remember_sent(
            sent_packet(2, 13, now + Duration::from_millis(18000)),
            now + Duration::from_millis(18000),
        );
        rtx_sender.remember_sent(
            sent_packet(4, 23, now + Duration::from_millis(20000)),
            now + Duration::from_millis(20000),
        );
        rtx_sender.remember_sent(
            sent_packet(2, 14, now + Duration::from_millis(22000)),
            now + Duration::from_millis(22000),
        );
        rtx_sender.remember_sent(
            sent_packet(4, 24, now + Duration::from_millis(24000)),
            now + Duration::from_millis(24000),
        );

        assert_eq!(None, rtx_sender.resend_as_rtx(2, 11, now, || 103));
        assert_eq!(None, rtx_sender.resend_as_rtx(4, 21, now, || 103));
        assert_eq!(
            Some(rtx_packet(
                2,
                12,
                3,
                103,
                now + Duration::from_millis(14000),
                true,
            )),
            rtx_sender.resend_as_rtx(2, 12, now, || 103)
        );
        assert_eq!(
            Some(rtx_packet(
                4,
                22,
                1,
                104,
                now + Duration::from_millis(16000),
                true,
            )),
            rtx_sender.resend_as_rtx(4, 22, now, || 104)
        );
        assert_eq!(
            Some(rtx_packet(
                4,
                24,
                2,
                105,
                now + Duration::from_millis(24000),
                true,
            )),
            rtx_sender.resend_as_rtx(4, 24, now, || 105)
        );

        // Make sure the marker bit survives the process
        let mut sent = sent_packet(2, 15, now + Duration::from_millis(16000));
        sent.marker = true;
        sent.serialized_mut()[1] = (1 << 7) | VP8_PAYLOAD_TYPE;
        let mut rtx = rtx_packet(2, 15, 4, 106, now + Duration::from_millis(16000), true);
        rtx.marker = true;
        rtx.serialized_mut()[1] = (1 << 7) | VP8_RTX_PAYLOAD_TYPE;
        rtx_sender.remember_sent(sent, now + Duration::from_millis(16000));
        assert_eq!(
            Some(rtx),
            rtx_sender.resend_as_rtx(2, 15, now + Duration::from_millis(16000), || 106)
        );

        // Make sure the padding RTX seqnums are not reused
        assert_eq!(padding_packet(3, 5, 107), rtx_sender.send_padding(3, 107));
        assert_eq!(padding_packet(5, 3, 108), rtx_sender.send_padding(5, 108));
        assert_eq!(padding_packet(7, 1, 109), rtx_sender.send_padding(7, 109));

        // Try resending an RTX packet.
        let packet = rtx_packet(2, 16, 37, 40, now + Duration::from_millis(17_000), false);
        rtx_sender.remember_sent(packet, now + Duration::from_millis(17_000));
        assert_eq!(
            Some(rtx_packet(
                2,
                16,
                6,
                107,
                now + Duration::from_millis(17_000),
                true,
            )),
            rtx_sender.resend_as_rtx(2, 16, now + Duration::from_millis(17_000), || 107)
        );
    }
}
