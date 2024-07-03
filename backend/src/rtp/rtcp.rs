//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::{OPUS_PAYLOAD_TYPE, VP8_PAYLOAD_TYPE};

use std::{
    convert::TryFrom,
    ops::{Range, RangeInclusive},
};

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes_gcm::{AeadInPlace, Aes128Gcm};
use calling_common::{
    parse_u16, parse_u32, round_up_to_multiple_of, CheckedSplitAt, Instant, Writer, U24,
};
use log::*;

use crate::transportcc as tcc;

use super::{
    nack::{parse_nack, Nack},
    srtp::{Iv, Key, Salt, SRTP_AUTH_TAG_LEN, SRTP_IV_LEN},
    types::*,
    VERSION,
};

const RTCP_HEADER_LEN: usize = 8;
pub const RTCP_PAYLOAD_TYPE_OFFSET: usize = 1;
const RTCP_PAYLOAD_LEN_RANGE: Range<usize> = 2..4;
const RTCP_SENDER_SSRC_RANGE: Range<usize> = 4..8;
const SRTCP_FOOTER_LEN: usize = 4;
const RTCP_TYPE_SENDER_REPORT: u8 = 200;
pub const RTCP_TYPE_RECEIVER_REPORT: u8 = 201;
const RTCP_TYPE_EXTENDED_REPORT: u8 = 207;
const RTCP_TYPE_SDES: u8 = 202;
pub const RTCP_TYPE_BYE: u8 = 203;
const SEQNUM_GAP_THRESHOLD: u32 = 500;
const RTCP_FORMAT_LOSS_NOTIFICATION: u8 = 15;
pub const RTCP_PAYLOAD_TYPES: RangeInclusive<u8> = 64..=95;
pub const RTCP_TYPE_GENERIC_FEEDBACK: u8 = 205;
pub const RTCP_FORMAT_NACK: u8 = 1;
pub const RTCP_FORMAT_TRANSPORT_CC: u8 = 15;
pub const RTCP_TYPE_SPECIFIC_FEEDBACK: u8 = 206;
pub const RTCP_FORMAT_PLI: u8 = 1;

#[derive(Default, Debug)]
pub struct ControlPacket<'packet> {
    // pub for tests
    pub key_frame_requests: Vec<KeyFrameRequest>,
    // pub for tests
    pub tcc_feedbacks: Vec<&'packet [u8]>,
    pub nacks: Vec<Nack>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct KeyFrameRequest {
    pub ssrc: Ssrc,
}

impl<'packet> ControlPacket<'packet> {
    // pub for tests
    pub fn parse_and_decrypt_in_place(
        serialized: &'packet mut [u8],
        key: &Key,
        salt: &Salt,
    ) -> Option<Self> {
        if serialized.len() < RTCP_HEADER_LEN + SRTP_AUTH_TAG_LEN + SRTCP_FOOTER_LEN {
            event!("calling.rtp.invalid.rtcp_too_small");
            debug!("RTCP packet too small: {}", serialized.len());
            return None;
        }
        let sender_ssrc = parse_u32(&serialized[RTCP_SENDER_SSRC_RANGE.clone()]);
        let footer = &serialized[(serialized.len() - SRTCP_FOOTER_LEN)..];
        let encrypted = (footer[0] & 0b1000_0000) > 0;
        let srtcp_index = parse_u32(footer) & 0x7FFF_FFFF;

        if encrypted {
            let (cipher, nonce, aad, ciphertext, tag) =
                Self::prepare_for_crypto(serialized, sender_ssrc, srtcp_index, key, salt)?;
            let nonce = GenericArray::from_slice(&nonce);
            let tag = GenericArray::from_slice(tag);
            cipher
                .decrypt_in_place_detached(nonce, &aad, ciphertext, tag)
                .ok()?;
        } else {
            // Allow processing unencrypted packets when fuzzing;
            // otherwise we'd have to encrypt all fuzz inputs.
            #[cfg(not(fuzzing))]
            {
                event!("calling.rtp.unencrypted");
                return None;
            }
        }

        let mut incoming = Self::default();

        let len_without_tag_and_footer = serialized.len() - SRTP_AUTH_TAG_LEN - SRTCP_FOOTER_LEN;
        let mut compound_packets = &serialized[..len_without_tag_and_footer];
        while compound_packets.len() >= RTCP_HEADER_LEN {
            let (header, after_header) = compound_packets.checked_split_at(RTCP_HEADER_LEN)?;
            let count_or_format = header[0] & 0b11111;
            let pt = header[1];
            // Spec says "minus 1" including 2-word header, which is really "plus 1" excluding the header.
            let payload_len_in_words_plus_1 = parse_u16(&header[RTCP_PAYLOAD_LEN_RANGE.clone()]);
            let _sender_ssrc = parse_u32(&header[RTCP_SENDER_SSRC_RANGE.clone()]);

            if payload_len_in_words_plus_1 == 0 {
                // This could only happen if we received an RTCP packet without a sender_ssrc, which should never happen.
                warn!("Ignoring RTCP packet with expressed len of 0");
                return None;
            }
            let payload_len = (payload_len_in_words_plus_1 as usize - 1) * 4;

            let (payload, after_payload) = after_header.checked_split_at(payload_len)?;
            compound_packets = after_payload;
            match (pt, count_or_format) {
                (RTCP_TYPE_SENDER_REPORT, _) => {}
                (RTCP_TYPE_RECEIVER_REPORT, _) => {}
                (RTCP_TYPE_EXTENDED_REPORT, _) => {}
                (RTCP_TYPE_SDES, _) => {}
                (RTCP_TYPE_BYE, _) => {}
                (RTCP_TYPE_SPECIFIC_FEEDBACK, RTCP_FORMAT_LOSS_NOTIFICATION) => {}
                (RTCP_TYPE_GENERIC_FEEDBACK, RTCP_FORMAT_NACK) => match parse_nack(payload) {
                    Ok(nack) => incoming.nacks.push(nack),
                    Err(err) => warn!("Failed to parse RTCP nack: {}", err),
                },
                (RTCP_TYPE_GENERIC_FEEDBACK, RTCP_FORMAT_TRANSPORT_CC) => {
                    // We use the unparsed payload here because parsing of the feedback is stateful
                    // (it requires expanding the seqnums), so we pass it into the tcc::Sender instead.
                    incoming.tcc_feedbacks.push(payload);
                }
                (RTCP_TYPE_SPECIFIC_FEEDBACK, RTCP_FORMAT_PLI) => {
                    // PLI See https://tools.ietf.org/html/rfc4585
                    if payload.len() < 4 {
                        warn!("RTCP PLI is too small.");
                        return None;
                    }
                    let ssrc = parse_u32(&payload[0..4]);
                    incoming.key_frame_requests.push(KeyFrameRequest { ssrc });
                }
                _ => {
                    warn!("Got weird unexpected RTCP: ({}, {})", pt, count_or_format);
                }
            }
        }
        Some(incoming)
    }

    // pub for tests
    pub fn serialize_and_encrypt(
        pt: u8,
        count_or_format: u8,
        sender_ssrc: Ssrc,
        payload_writer: impl Writer,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        let padded_payload_len = round_up_to_multiple_of::<4>(payload_writer.written_len());
        let mut serialized =
            vec![0u8; RTCP_HEADER_LEN + padded_payload_len + SRTP_AUTH_TAG_LEN + SRTCP_FOOTER_LEN];
        // Spec says "minus 1" including 2-word header, which is really "plus 1" excluding the header.
        let padded_payload_len_in_words_plus_1 = ((padded_payload_len / 4) + 1) as u16;

        serialized[0] = (VERSION << 6) | count_or_format;
        serialized[RTCP_PAYLOAD_TYPE_OFFSET] = pt;
        serialized[RTCP_PAYLOAD_LEN_RANGE.clone()]
            .copy_from_slice(&padded_payload_len_in_words_plus_1.to_be_bytes());
        serialized[RTCP_SENDER_SSRC_RANGE.clone()].copy_from_slice(&sender_ssrc.to_be_bytes());
        // TODO: Make this more efficient by copying less.
        serialized[RTCP_HEADER_LEN..][..payload_writer.written_len()]
            .copy_from_slice(&payload_writer.to_vec());
        serialized[RTCP_HEADER_LEN + padded_payload_len + SRTP_AUTH_TAG_LEN..]
            .copy_from_slice(&(srtcp_index | 0x80000000/* "encrypted" */).to_be_bytes());

        let (cipher, nonce, aad, plaintext, tag) =
            Self::prepare_for_crypto(&mut serialized, sender_ssrc, srtcp_index, key, salt)?;
        let nonce = GenericArray::from_slice(&nonce);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce, &aad, plaintext)
            .ok()?;
        tag.copy_from_slice(&computed_tag);
        Some(serialized)
    }

    #[cfg(test)]
    pub fn serialize_and_encrypt_nack(
        sender_ssrc: Ssrc,
        payload_writer: impl Writer,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        ControlPacket::serialize_and_encrypt(
            RTCP_TYPE_GENERIC_FEEDBACK,
            RTCP_FORMAT_NACK,
            sender_ssrc,
            payload_writer,
            srtcp_index,
            key,
            salt,
        )
    }

    #[cfg(test)]
    pub fn serialize_and_encrypt_acks(
        sender_ssrc: Ssrc,
        payload_writer: impl Writer,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        ControlPacket::serialize_and_encrypt(
            RTCP_TYPE_GENERIC_FEEDBACK,
            RTCP_FORMAT_TRANSPORT_CC,
            sender_ssrc,
            payload_writer,
            srtcp_index,
            key,
            salt,
        )
    }

    #[cfg(test)]
    pub fn serialize_and_encrypt_pli(
        sender_ssrc: Ssrc,
        payload_writer: impl Writer,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        ControlPacket::serialize_and_encrypt(
            RTCP_TYPE_SPECIFIC_FEEDBACK,
            RTCP_FORMAT_PLI,
            sender_ssrc,
            payload_writer,
            srtcp_index,
            key,
            salt,
        )
    }
}

impl ControlPacket<'_> {
    #[allow(clippy::type_complexity)]
    fn prepare_for_crypto<'packet>(
        packet: &'packet mut [u8],
        sender_ssrc: Ssrc,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<(
        Aes128Gcm,
        [u8; SRTP_IV_LEN],
        Vec<u8>,
        &'packet mut [u8],
        &'packet mut [u8],
    )> {
        let (header, payload_plus_tag_plus_footer) = packet.split_at_mut(RTCP_HEADER_LEN);
        let (payload_plus_tag, footer) = payload_plus_tag_plus_footer
            .split_at_mut(payload_plus_tag_plus_footer.len() - SRTCP_FOOTER_LEN);
        let (payload, tag) =
            payload_plus_tag.split_at_mut(payload_plus_tag.len() - SRTP_AUTH_TAG_LEN);
        let iv = rtcp_iv(sender_ssrc, srtcp_index, salt)?;

        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key[..]));
        let aad = [header, footer].concat();
        Some((cipher, iv, aad, payload, tag))
    }
}

#[allow(clippy::identity_op)]
fn rtcp_iv(sender_ssrc: Ssrc, index: u32, salt: &Salt) -> Option<Iv> {
    if index >= (1 << 31) {
        return None;
    }
    let ssrc = sender_ssrc.to_be_bytes();
    let index = index.to_be_bytes();
    Some([
        0 ^ salt[0],
        0 ^ salt[1],
        ssrc[0] ^ salt[2],
        ssrc[1] ^ salt[3],
        ssrc[2] ^ salt[4],
        ssrc[3] ^ salt[5],
        0 ^ salt[6],
        0 ^ salt[7],
        index[0] ^ salt[8],
        index[1] ^ salt[9],
        index[2] ^ salt[10],
        index[3] ^ salt[11],
    ])
}

// This is almost the same as ControlPacket.
// But it processes the transport-cc feedback into Acks based on previously sent packets.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcessedControlPacket {
    pub key_frame_requests: Vec<KeyFrameRequest>,
    pub acks: Vec<tcc::Ack>,
    pub nacks: Vec<Nack>,
}

pub(super) struct ReceiverReportSender {
    max_seqnum: Option<u32>,
    max_seqnum_in_last: Option<u32>,
    cumulative_loss: u32,
    cumulative_loss_in_last: u32,
    last_receive_time: Instant,
    last_rtp_timestamp: u32,
    jitter_q4: u32,
}

impl ReceiverReportSender {
    pub(super) fn new() -> Self {
        Self {
            max_seqnum: None,
            max_seqnum_in_last: None,
            cumulative_loss: 0,
            cumulative_loss_in_last: 0,
            last_receive_time: Instant::now(),
            last_rtp_timestamp: 0,
            jitter_q4: 0,
        }
    }

    pub(super) fn remember_received(
        &mut self,
        seqnum: FullSequenceNumber,
        payload_type: PayloadType,
        rtp_timestamp: u32,
        receive_time: Instant,
    ) {
        let seqnum = seqnum as u32;
        if let Some(max_seqnum) = self.max_seqnum {
            if seqnum.abs_diff(max_seqnum) > SEQNUM_GAP_THRESHOLD {
                // Large seqnum gaps are caused by stream restarts. When this happens, reset the
                // state since the values for the old stream may not be relevant anymore.
                self.cumulative_loss = 0;
                self.cumulative_loss_in_last = 0;
                self.max_seqnum = Some(seqnum);
                self.max_seqnum_in_last = Some(seqnum.saturating_sub(1));

                self.last_receive_time = receive_time;
                self.last_rtp_timestamp = rtp_timestamp;
                self.jitter_q4 = 0;
                return;
            }

            if seqnum > max_seqnum {
                let seqnums_in_gap = seqnum - max_seqnum - 1;
                self.cumulative_loss = self.cumulative_loss.saturating_add(seqnums_in_gap);
                self.max_seqnum = Some(seqnum);

                self.update_jitter(payload_type, rtp_timestamp, receive_time);

                self.last_receive_time = receive_time;
                self.last_rtp_timestamp = rtp_timestamp;
            } else {
                self.cumulative_loss = self.cumulative_loss.saturating_sub(1);
            }
        } else {
            self.max_seqnum = Some(seqnum);
            // When we get the first seqnum, make it so we've expected 1 seqnum since "last"
            // even though there hasn't been a last yet.
            self.max_seqnum_in_last = Some(seqnum.saturating_sub(1));

            self.last_receive_time = receive_time;
            self.last_rtp_timestamp = rtp_timestamp;
        }
    }

    fn update_jitter(
        &mut self,
        payload_type: PayloadType,
        rtp_timestamp: u32,
        receive_time: Instant,
    ) {
        let receive_diff = receive_time.saturating_duration_since(self.last_receive_time);

        let payload_freq_hz = if payload_type == OPUS_PAYLOAD_TYPE {
            48000
        } else if payload_type == VP8_PAYLOAD_TYPE {
            90000
        } else {
            warn!(
                "unexpected payload type {}, using payload frequency of 90000",
                payload_type
            );
            90000
        };

        // The difference in receive time (interarrival time) converted to the units of the RTP
        // timestamps.
        let receive_diff_rtp =
            (receive_diff.as_millis() as u32).saturating_mul(payload_freq_hz) / 1000;

        // The difference in transmission time represented in the units of RTP timestamps.
        let tx_diff_rtp = (receive_diff_rtp as i64)
            .saturating_sub(rtp_timestamp.saturating_sub(self.last_rtp_timestamp) as i64)
            .unsigned_abs() as u32;

        // If the jump in timestamp is large, ignore the value to avoid skewing the jitter.
        if tx_diff_rtp < 10 * payload_freq_hz {
            let jitter_diff_q4 = (tx_diff_rtp << 4) as i32 - self.jitter_q4 as i32;
            self.jitter_q4 = self
                .jitter_q4
                .saturating_add_signed((jitter_diff_q4 + 8) >> 4);
        }
    }

    pub(super) fn write_receiver_report_block(&mut self, ssrc: Ssrc) -> Option<Vec<u8>> {
        if let (Some(max_seqnum), Some(max_seqnum_in_last)) =
            (self.max_seqnum, self.max_seqnum_in_last)
        {
            let expected_since_last = max_seqnum.saturating_sub(max_seqnum_in_last);
            let lost_since_last = self
                .cumulative_loss
                .saturating_sub(self.cumulative_loss_in_last);
            let fraction_lost_since_last = if expected_since_last == 0 {
                0
            } else {
                (256 * lost_since_last / expected_since_last) as u8
            };

            // Negative cumulative loss isn't supported because it can cause problems with WebRTC
            // https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/modules/rtp_rtcp/source/receive_statistics_impl.h;l=91-94;drc=18649971ab02d2f3fc8f360aee2e3c573652b7bd
            const MAX_I24: u32 = (1 << 23) - 1;
            let cumulative_loss_i24 =
                U24::try_from(std::cmp::min(self.cumulative_loss, MAX_I24)).unwrap();

            self.max_seqnum_in_last = self.max_seqnum;
            // cumulative_loss_in_last is used to figure out how many packets have been lost since
            // the last report. We can't update it based off lost_since_last since cumulative_loss
            // can decrease (given duplicate packets), and lost_since_last wouldn't account for
            // that.
            self.cumulative_loss_in_last = self.cumulative_loss;

            let interarrival_jitter: u32 = self.jitter_q4 >> 4;

            // Not used yet.
            let last_sender_report_timestamp: u32 = 0;
            let delay_since_last_sender_report: u32 = 0;

            Some(
                (
                    ssrc,
                    [fraction_lost_since_last],
                    cumulative_loss_i24,
                    max_seqnum,
                    interarrival_jitter,
                    last_sender_report_timestamp,
                    delay_since_last_sender_report,
                )
                    .to_vec(),
            )
        } else {
            // We haven't received a packet yet, so we can't send a receiver report.
            None
        }
    }
}

#[cfg(test)]
mod test {
    use calling_common::{Duration, Writer};

    use super::*;

    #[test]
    fn test_receiver_report_sender_packet_loss() {
        let mut receiver_report_sender = ReceiverReportSender::new();

        fn expected_bytes(
            ssrc: Ssrc,
            fraction_lost_since_last: u8,
            cumulative_loss: u32,
            max_seqnum: u32,
        ) -> Vec<u8> {
            let interarrival_jitter: u32 = 0;
            let last_sender_report_timestamp: u32 = 0;
            let delay_since_last_sender_report: u32 = 0;

            (
                ssrc,
                [fraction_lost_since_last],
                U24::try_from(cumulative_loss).unwrap(),
                max_seqnum,
                (
                    interarrival_jitter,
                    last_sender_report_timestamp,
                    delay_since_last_sender_report,
                ),
            )
                .to_vec()
        }

        let ssrc = 123456;

        // We don't send a report before receiving anything.
        assert_eq!(
            None,
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Receiving all packets in order means no loss.
        for seqnum in 1000..=1004 {
            receiver_report_sender.remember_received(seqnum, OPUS_PAYLOAD_TYPE, 0, Instant::now());
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1004)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Even if packets are received out of order, if there are no gaps, then there's no loss.
        for seqnum in &[1009, 1005, 1007, 1008, 1010, 1006] {
            receiver_report_sender.remember_received(*seqnum, OPUS_PAYLOAD_TYPE, 0, Instant::now());
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1010)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Now we lose 1011..=1019
        receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, Instant::now());

        // ... which means that we lost 9 packets (230 / 256).
        assert_eq!(
            Some(expected_bytes(ssrc, 230, 9, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Receiving duplicate packets reduces the cumulative loss
        for _ in 0..4 {
            receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, Instant::now());
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 5, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        for _ in 0..10 {
            receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, Instant::now());
        }

        // ... but we don't support negative loss.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Increase loss again
        receiver_report_sender.remember_received(1050, OPUS_PAYLOAD_TYPE, 0, Instant::now());

        assert_eq!(
            Some(expected_bytes(ssrc, 247, 29, 1050)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        receiver_report_sender.remember_received(3050, OPUS_PAYLOAD_TYPE, 0, Instant::now());

        // ... to show that a large increase in seqnums causes the statistics to be reset.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 3050)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Increase loss again
        receiver_report_sender.remember_received(3060, OPUS_PAYLOAD_TYPE, 0, Instant::now());

        assert_eq!(
            Some(expected_bytes(ssrc, 230, 9, 3060)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        receiver_report_sender.remember_received(0, OPUS_PAYLOAD_TYPE, 0, Instant::now());

        // ... to show that a large decrease in seqnums causes the statistics to be reset.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 0)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );
    }

    #[test]
    fn test_receiver_report_sender_jitter() {
        let mut receiver_report_sender = ReceiverReportSender::new();

        fn expected_bytes(ssrc: Ssrc, interarrival_jitter: u32, max_seqnum: u32) -> Vec<u8> {
            let last_sender_report_timestamp: u32 = 0;
            let delay_since_last_sender_report: u32 = 0;

            (
                ssrc,
                [0u8],
                U24::from(0),
                max_seqnum,
                (
                    interarrival_jitter,
                    last_sender_report_timestamp,
                    delay_since_last_sender_report,
                ),
            )
                .to_vec()
        }

        let ssrc = 123456;

        // Given a 20 ms ptime (50 packets / second) and a sample rate of 48000, RTP timestamps
        // would increment by this amount assuming no other delays.
        let rtp_interval = 48000 / 50;

        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        // Receiving all packets at a constant rate means that there's no jitter
        receiver_report_sender.remember_received(10, OPUS_PAYLOAD_TYPE, rtp_interval, at(20));
        receiver_report_sender.remember_received(11, OPUS_PAYLOAD_TYPE, 2 * rtp_interval, at(40));
        receiver_report_sender.remember_received(12, OPUS_PAYLOAD_TYPE, 3 * rtp_interval, at(60));

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Receiving older packets doesn't update jitter
        receiver_report_sender.remember_received(9, OPUS_PAYLOAD_TYPE, 0, at(85));

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // We were previously expecting packets to be received every 20 ms, but this is received 40
        // ms after the previous one, so there is jitter now.
        receiver_report_sender.remember_received(13, OPUS_PAYLOAD_TYPE, 4 * rtp_interval, at(100));

        // An interarrival jitter of 60 is 1.25 ms in this case. Although WebRTC stores jitter
        // stats with millisecond precision, so shows up as 1 ms. The conversion factor from RTP
        // timestamps to real time is 1 / (48000 / 50 / 20). Sample rate=48000, packets / second =
        // 50, ptime = 20.
        assert_eq!(
            Some(expected_bytes(ssrc, 60, 13)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // A large increase in sequence numbers is treated as a stream reset, and the jitter is
        // also reset.
        receiver_report_sender.remember_received(
            1000,
            OPUS_PAYLOAD_TYPE,
            5 * rtp_interval,
            at(120),
        );

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 1000)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );
    }

    #[test]
    fn test_receiver_report_sender_jitter_recovery() {
        let mut receiver_report_sender = ReceiverReportSender::new();

        fn expected_bytes(ssrc: Ssrc, interarrival_jitter: u32, max_seqnum: u32) -> Vec<u8> {
            let last_sender_report_timestamp: u32 = 0;
            let delay_since_last_sender_report: u32 = 0;

            (
                ssrc,
                [0u8],
                U24::from(0),
                max_seqnum,
                (
                    interarrival_jitter,
                    last_sender_report_timestamp,
                    delay_since_last_sender_report,
                ),
            )
                .to_vec()
        }

        let ssrc = 123456;

        // Given a 20 ms ptime (50 packets / second) and a sample rate of 48000, RTP timestamps
        // would increment by this amount assuming no other delays.
        let rtp_interval = 48000 / 50;

        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        let mut seqnum = 10;
        receiver_report_sender.remember_received(seqnum, OPUS_PAYLOAD_TYPE, rtp_interval, at(20));

        seqnum += 1;
        receiver_report_sender.remember_received(
            seqnum,
            OPUS_PAYLOAD_TYPE,
            2 * rtp_interval,
            at(40),
        );

        seqnum += 1;
        receiver_report_sender.remember_received(
            seqnum,
            OPUS_PAYLOAD_TYPE,
            3 * rtp_interval,
            at(60),
        );

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12)),
            receiver_report_sender.write_receiver_report_block(ssrc)
        );

        // Now interarrival time increases to 21 ms and jitter increases.
        let expected_jitter_values = [
            3, 5, 8, 10, 13, 15, 17, 19, 21, 22, 24, 26, 27, 28, 29, 31, 32, 33, 34, 34, 35, 36,
            37, 37, 38, 39, 39, 40, 40, 41, 41, 41, 42, 42, 43, 43, 43, 43, 44, 44, 44, 44, 45, 45,
            45, 45, 45, 45, 45, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 47, 47, 47, 47, 47, 47,
            47, 47, 47, 47, 47,
        ];
        let mut time = 60;
        for (i, expected_jitter) in expected_jitter_values.iter().enumerate() {
            time += 21;

            seqnum += 1;

            receiver_report_sender.remember_received(
                seqnum,
                OPUS_PAYLOAD_TYPE,
                (4 + (i as u32)) * rtp_interval,
                at(time),
            );

            assert_eq!(
                Some(expected_bytes(ssrc, *expected_jitter, seqnum as u32)),
                receiver_report_sender.write_receiver_report_block(ssrc)
            );
        }

        // Then goes back to 20 ms and jitter gradually recovers (trends to 0).
        let i_offset = expected_jitter_values.len();
        let expected_jitter_values = [
            44, 41, 39, 36, 34, 32, 30, 28, 26, 24, 23, 21, 20, 19, 18, 16, 15, 14, 13, 13, 12, 11,
            10, 10, 9, 8, 8, 7, 7, 6, 6, 6, 5, 5, 5, 4, 4,
        ];
        for (i, expected_jitter) in expected_jitter_values.iter().enumerate() {
            time += 20;
            let i = i + i_offset;

            seqnum += 1;

            receiver_report_sender.remember_received(
                seqnum,
                OPUS_PAYLOAD_TYPE,
                (4 + (i as u32)) * rtp_interval,
                at(time),
            );

            assert_eq!(
                Some(expected_bytes(ssrc, *expected_jitter, seqnum as u32)),
                receiver_report_sender.write_receiver_report_block(ssrc)
            );
        }
    }
}
