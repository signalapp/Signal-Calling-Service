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
    parse_u16, parse_u24, parse_u32, parse_u64, round_up_to_multiple_of, CheckedSplitAt, Instant,
    Writer, U24,
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
    pub sender_reports: Vec<SenderReport>,
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
        while compound_packets.len() >= RtcpHeader::LENGTH {
            let header = RtcpHeader::from_bytes(compound_packets);
            if header.length_in_words == 0 {
                // This could only happen if we received an RTCP packet without a sender_ssrc, which should never happen.
                warn!("Ignoring RTCP packet with expressed len of 0");
                return None;
            }

            let (packet, after_packet) =
                compound_packets.checked_split_at(header.packet_length_in_bytes())?;
            // used by SR, RR, and SDES
            let payload = &packet[RtcpHeader::LENGTH..];
            // used by feedback packets
            let ignore_sender_ssrc_payload = &payload[4..];
            compound_packets = after_packet;
            match (header.payload_type, header.count_or_format) {
                (RTCP_TYPE_SENDER_REPORT, _) => {
                    match SenderReport::from_bytes_after_header(payload, header) {
                        Ok(sr) => incoming.sender_reports.push(sr),
                        Err(err) => warn!("Failed to parse RTCP sender report: {}", err),
                    }
                }
                (RTCP_TYPE_RECEIVER_REPORT, _) => {}
                (RTCP_TYPE_EXTENDED_REPORT, _) => {}
                (RTCP_TYPE_SDES, _) => {}
                (RTCP_TYPE_BYE, _) => {}
                (RTCP_TYPE_SPECIFIC_FEEDBACK, RTCP_FORMAT_LOSS_NOTIFICATION) => {}
                (RTCP_TYPE_GENERIC_FEEDBACK, RTCP_FORMAT_NACK) => {
                    match parse_nack(ignore_sender_ssrc_payload) {
                        Ok(nack) => incoming.nacks.push(nack),
                        Err(err) => warn!("Failed to parse RTCP nack: {}", err),
                    }
                }
                (RTCP_TYPE_GENERIC_FEEDBACK, RTCP_FORMAT_TRANSPORT_CC) => {
                    // We use the unparsed payload here because parsing of the feedback is stateful
                    // (it requires expanding the seqnums), so we pass it into the tcc::Sender instead.
                    incoming.tcc_feedbacks.push(ignore_sender_ssrc_payload);
                }
                (RTCP_TYPE_SPECIFIC_FEEDBACK, RTCP_FORMAT_PLI) => {
                    // PLI See https://tools.ietf.org/html/rfc4585
                    if ignore_sender_ssrc_payload.len() < 4 {
                        warn!("RTCP PLI is too small.");
                        return None;
                    }
                    let ssrc = parse_u32(&ignore_sender_ssrc_payload[0..4]);
                    incoming.key_frame_requests.push(KeyFrameRequest { ssrc });
                }
                _ => {
                    warn!(
                        "Got unexpected RTCP: ({}, {})",
                        header.payload_type, header.count_or_format
                    );
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

pub(super) struct RtcpReportSender {
    // receiver report stats
    max_seqnum: Option<u32>,
    max_seqnum_in_last: Option<u32>,
    cumulative_loss: u32,
    cumulative_loss_in_last: u32,
    last_receive_time: Instant,
    last_rtp_timestamp: u32,
    jitter_q4: u32,
    last_sender_report_received_ntp_timestamp: u64,
    last_sender_report_received_time: Instant,
}

impl RtcpReportSender {
    pub(super) fn new() -> Self {
        Self {
            max_seqnum: None,
            max_seqnum_in_last: None,
            cumulative_loss: 0,
            cumulative_loss_in_last: 0,
            last_receive_time: Instant::now(),
            last_rtp_timestamp: 0,
            jitter_q4: 0,
            last_sender_report_received_ntp_timestamp: 0,
            last_sender_report_received_time: Instant::now(),
        }
    }

    pub(super) fn remember_received_sender_report(
        &mut self,
        sender_report: SenderReport,
        receive_time: Instant,
    ) {
        // ignore older sender reports
        if sender_report.sender_info.ntp_ts <= self.last_sender_report_received_ntp_timestamp {
            return;
        }

        self.last_sender_report_received_time = receive_time;
        self.last_sender_report_received_ntp_timestamp = sender_report.sender_info.ntp_ts;
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

    pub(super) fn write_receiver_report_block(
        &mut self,
        ssrc: Ssrc,
        now: Instant,
    ) -> Option<Vec<u8>> {
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

            let (last_sender_report_timestamp, delay_since_last_sender_report) =
                if self.last_sender_report_received_ntp_timestamp != 0 {
                    (
                        get_lsr(self.last_sender_report_received_ntp_timestamp),
                        calculate_delay_since_sr(self.last_sender_report_received_time, now),
                    )
                } else {
                    (0, 0)
                };

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

// The middle 32 bits in the NTP timestamp from the most recent RTCP sender report (SR) packet
// from source SSRC_n. If no SR has been received yet, the field is set to zero.
fn get_lsr(last_ntp_timestamp: u64) -> u32 {
    const LSR_MASK: u64 = 0x0000_FFFF_FFFF_0000;
    ((last_ntp_timestamp & LSR_MASK) >> 16) as u32
}

// The delay, expressed in units of 1/2^16 seconds, between receiving the last SR packet from
// source SSRC_n and sending this reception report block.
// If no SR packet has been received yet from SSRC_n, the DLSR field is set to zero.
fn calculate_delay_since_sr(sr_last_received_time: Instant, now: Instant) -> u32 {
    // Max delay representable is 2^16 seconds (a bit over 18 hours). After that, we start
    // to return 0's. 1/2^16 is roughly 0.000015259, which requires nanosecond precision
    // To avoid underflow calculate from duration.as_nanos()/15259
    const NANOS_TO_DELAY_UNIT: u128 = 15259;
    (now.saturating_duration_since(sr_last_received_time)
        .as_nanos()
        / NANOS_TO_DELAY_UNIT)
        .try_into()
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq)]
pub struct RtcpHeader {
    has_padding: bool,
    count_or_format: u8,
    payload_type: u8,
    /// length of the RTCP packet in words, minus the 1-word header
    length_in_words: u16,
}

impl RtcpHeader {
    pub const LENGTH: usize = 4;
    const PADDING_MASK: u8 = 0b00100000;
    const RC_MASK: u8 = 0b00011111;
    const PACKET_LENGTH_RANGE: Range<usize> = 2..4;

    // Parses the following binary format into a RtcpHeader. Note that this is
    // is the common header - the one used by SR, RR, and SDES. SSRCs will be contained
    // in the payload type.
    // See https://datatracker.ietf.org/doc/html/rfc1889#section-6.3.1
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |V=2|P|    RC   |   PT=SR=200   |             length            | header
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn from_bytes(value: &[u8]) -> Self {
        let has_padding = value[0] & Self::PADDING_MASK > 0;
        let count_or_format = value[0] & Self::RC_MASK;
        let payload_type = value[1];
        let length_in_words = parse_u16(&value[Self::PACKET_LENGTH_RANGE]);

        Self {
            has_padding,
            count_or_format,
            payload_type,
            length_in_words,
        }
    }

    /// Number of bytes in the packet, header & padding included
    pub fn packet_length_in_bytes(&self) -> usize {
        (self.length_in_words as usize + 1) * 4
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ReportBlock {
    ssrc: Ssrc,
    fraction_loss: u8,
    cumulative_loss_count: U24,
    highest_sequence_num: u32,
    jitter: u32,
    last_sender_report: u32,
    delay_last_sender_report: u32,
}

impl ReportBlock {
    const BLOCK_LENGTH: usize = 24;
    const SSRC_RANGE: Range<usize> = 0..4;
    const FRACTION_LOSS_RANGE: usize = 4;
    const CUMULATIVE_LOSS_RANGE: Range<usize> = 5..8;
    const HIGHEST_SEQUENCE_NUMBER_RANGE: Range<usize> = 8..12;
    const INTERARRIVAL_JITTER_RANGE: Range<usize> = 12..16;
    const LAST_SENDER_REPORT_RANGE: Range<usize> = 16..20;
    const DELAY_LAST_SENDER_REPORT_RANGE: Range<usize> = 20..24;

    fn from_bytes(value: &[u8]) -> Result<Self, String> {
        if value.len() < Self::BLOCK_LENGTH {
            return Err("Malformed Report Block: too few bytes".to_owned());
        }

        Ok(Self {
            ssrc: parse_u32(&value[Self::SSRC_RANGE]),
            fraction_loss: value[ReportBlock::FRACTION_LOSS_RANGE],
            cumulative_loss_count: parse_u24(&value[Self::CUMULATIVE_LOSS_RANGE]),
            highest_sequence_num: parse_u32(&value[Self::HIGHEST_SEQUENCE_NUMBER_RANGE]),
            jitter: parse_u32(&value[Self::INTERARRIVAL_JITTER_RANGE]),
            last_sender_report: parse_u32(&value[Self::LAST_SENDER_REPORT_RANGE]),
            delay_last_sender_report: parse_u32(&value[Self::DELAY_LAST_SENDER_REPORT_RANGE]),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SenderInfo {
    ssrc: Ssrc,
    ntp_ts: u64,
    rtp_ts: TruncatedTimestamp,
    packet_count: u32,
    octet_count: u32,
}

impl SenderInfo {
    const SENDER_INFO_LENGTH: usize = 24;
    const SSRC_RANGE: Range<usize> = 0..4;
    const NTS_RANGE: Range<usize> = 4..12;
    const RTS_RANGE: Range<usize> = 12..16;
    const SPC_RANGE: Range<usize> = 16..20;
    const SOC_RANGE: Range<usize> = 20..24;

    fn from_bytes(b: &[u8]) -> Self {
        Self {
            ssrc: parse_u32(&b[Self::SSRC_RANGE]),
            ntp_ts: parse_u64(&b[Self::NTS_RANGE]),
            rtp_ts: parse_u32(&b[Self::RTS_RANGE]),
            packet_count: parse_u32(&b[Self::SPC_RANGE]),
            octet_count: parse_u32(&b[Self::SOC_RANGE]),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SenderReport {
    header: RtcpHeader,
    sender_info: SenderInfo,
    report_blocks: Vec<ReportBlock>,
}

impl SenderReport {
    // Parses the following binary format into a sender report.
    // See https://datatracker.ietf.org/doc/html/rfc1889#section-6.3.1
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |V=2|P|    RC   |   PT=SR=200   |             length            | header
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                         SSRC of sender                        | sender info
    //    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    //    |              NTP timestamp, most significant word             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             NTP timestamp, least significant word             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                         RTP timestamp                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                     sender's packet count                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      sender's octet count                     |
    //    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    //    |                 SSRC_1 (SSRC of first source)                 | report
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
    //    | fraction lost |       cumulative number of packets lost       |   1
    //    -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |           extended highest sequence number received           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      interarrival jitter                      |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                         last SR (LSR)                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                   delay since last SR (DLSR)                  |
    //    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    //    |                 SSRC_2 (SSRC of second source)                | report
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
    //    :                               ...                             :   2
    //    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    //    |                  profile-specific extensions                  |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #[cfg(test)]
    pub fn from_bytes(value: &[u8]) -> Result<Self, String> {
        if value.len() < RtcpHeader::LENGTH + SenderInfo::SENDER_INFO_LENGTH {
            return Err("Malformed Sender Report: too few bytes".to_owned());
        }
        let header = RtcpHeader::from_bytes(value);
        Self::from_bytes_after_header(&value[RtcpHeader::LENGTH..], header)
    }

    fn from_bytes_after_header(value: &[u8], header: RtcpHeader) -> Result<Self, String> {
        let header_length = header.length_in_words as usize * 4;
        let minimum_expected_length = SenderInfo::SENDER_INFO_LENGTH
            + header.count_or_format as usize * ReportBlock::BLOCK_LENGTH;
        if header_length < minimum_expected_length || value.len() < header_length {
            return Err(format!(
                "Malformed Sender Report: header_size={}, report_count={}, actual_size={}",
                header_length,
                header.count_or_format,
                value.len()
            ));
        }

        let sender_info = SenderInfo::from_bytes(value);
        let report_count = header.count_or_format.into();
        let mut report_blocks = Vec::with_capacity(report_count);
        let mut bytes_left = &value[SenderInfo::SENDER_INFO_LENGTH..];

        while report_blocks.len() < report_count {
            report_blocks.push(ReportBlock::from_bytes(bytes_left)?);
            bytes_left = &bytes_left[ReportBlock::BLOCK_LENGTH..];
        }

        Ok(Self {
            header,
            sender_info,
            report_blocks,
        })
    }

    pub fn ssrc(&self) -> Ssrc {
        self.sender_info.ssrc
    }
}

#[cfg(test)]
mod test {
    use calling_common::{Duration, Writer};

    use super::*;

    #[test]
    fn test_parse_sender_report() {
        let report_count: u8 = 2;
        let pt = RTCP_TYPE_SENDER_REPORT;
        let length: u16 = (SenderInfo::SENDER_INFO_LENGTH
            + report_count as usize * ReportBlock::BLOCK_LENGTH)
            .try_into()
            .unwrap();
        let length_in_words = length / 4;
        let raw_header: Vec<u8> = ([0b1000_0000 | report_count, pt], length_in_words).to_vec();
        let parsed_header = RtcpHeader::from_bytes(&raw_header);
        assert_eq!(report_count, parsed_header.count_or_format);
        assert_eq!(pt, parsed_header.payload_type);
        assert_eq!(length_in_words, parsed_header.length_in_words);

        let ssrc: u32 = 10000;
        let ntp: u64 = 1234567898765432;
        let rtp_ts: u32 = 1234567876;
        let packet_count: u32 = 155;
        let octet_count: u32 = 155 * 1500;
        let raw_sender_info: Vec<u8> = (ssrc, ntp, rtp_ts, packet_count, octet_count).to_vec();
        let parsed_sender_info = SenderInfo::from_bytes(&raw_sender_info);
        assert_eq!(ssrc, parsed_sender_info.ssrc);
        assert_eq!(ntp, parsed_sender_info.ntp_ts);
        assert_eq!(rtp_ts, parsed_sender_info.rtp_ts);
        assert_eq!(packet_count, parsed_sender_info.packet_count);
        assert_eq!(octet_count, parsed_sender_info.octet_count);

        let fraction_loss = 0u8;
        let num_lost = U24::from(0);
        let ehsn = 1493824u32;
        let jitter = 10u32;
        let lsr = 123784329u32;
        let dlsr = 6000u32;
        let raw_report: Vec<u8> =
            (ssrc, [fraction_loss], num_lost, ehsn, jitter, lsr, dlsr).to_vec();
        let parsed_report_block = ReportBlock::from_bytes(&raw_report).unwrap();
        assert_eq!(fraction_loss, parsed_report_block.fraction_loss);
        assert_eq!(num_lost, parsed_report_block.cumulative_loss_count);
        assert_eq!(ehsn, parsed_report_block.highest_sequence_num);
        assert_eq!(jitter, parsed_report_block.jitter);
        assert_eq!(lsr, parsed_report_block.last_sender_report);
        assert_eq!(dlsr, parsed_report_block.delay_last_sender_report);

        let raw_sender_report =
            (raw_header, raw_sender_info, raw_report.clone(), raw_report).to_vec();
        let parsed_sender_report = SenderReport::from_bytes(&raw_sender_report).unwrap();
        assert_eq!(parsed_header, parsed_sender_report.header);
        assert_eq!(parsed_sender_info, parsed_sender_report.sender_info);
        assert_eq!(
            report_count as usize,
            parsed_sender_report.report_blocks.len()
        );
        assert_eq!(parsed_report_block, parsed_sender_report.report_blocks[0]);
        assert_eq!(parsed_report_block, parsed_sender_report.report_blocks[1]);

        let parsed_sender_report_2 = SenderReport::from_bytes_after_header(
            &raw_sender_report[RtcpHeader::LENGTH..],
            parsed_header,
        )
        .unwrap();
        assert_eq!(parsed_sender_report, parsed_sender_report_2);
    }

    #[test]
    fn test_receiver_report_sender_packet_loss() {
        let mut receiver_report_sender = RtcpReportSender::new();

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
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        // We don't send a report before receiving anything.
        assert_eq!(
            None,
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Receiving all packets in order means no loss.
        // We receive all packets at(0) so there is no jitter
        // We write out all report blocks at(5) so the receptions are counted
        for seqnum in 1000..=1004 {
            receiver_report_sender.remember_received(seqnum, OPUS_PAYLOAD_TYPE, 0, at(0));
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1004)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Even if packets are received out of order, if there are no gaps, then there's no loss.
        for seqnum in &[1009, 1005, 1007, 1008, 1010, 1006] {
            receiver_report_sender.remember_received(*seqnum, OPUS_PAYLOAD_TYPE, 0, at(0));
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1010)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Now we lose 1011..=1019
        receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, at(0));

        // ... which means that we lost 9 packets (230 / 256).
        assert_eq!(
            Some(expected_bytes(ssrc, 230, 9, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Receiving duplicate packets reduces the cumulative loss
        for _ in 0..4 {
            receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, at(0));
        }

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 5, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        for _ in 0..10 {
            receiver_report_sender.remember_received(1020, OPUS_PAYLOAD_TYPE, 0, at(0));
        }

        // ... but we don't support negative loss.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 1020)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Increase loss again
        receiver_report_sender.remember_received(1050, OPUS_PAYLOAD_TYPE, 0, at(0));

        assert_eq!(
            Some(expected_bytes(ssrc, 247, 29, 1050)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        receiver_report_sender.remember_received(3050, OPUS_PAYLOAD_TYPE, 0, at(0));

        // ... to show that a large increase in seqnums causes the statistics to be reset.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 3050)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        // Increase loss again
        receiver_report_sender.remember_received(3060, OPUS_PAYLOAD_TYPE, 0, at(0));

        assert_eq!(
            Some(expected_bytes(ssrc, 230, 9, 3060)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );

        receiver_report_sender.remember_received(0, OPUS_PAYLOAD_TYPE, 0, at(0));

        // ... to show that a large decrease in seqnums causes the statistics to be reset.
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 0, 0)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(5))
        );
    }

    #[test]
    fn test_receiver_report_sender_jitter() {
        let mut receiver_report_sender = RtcpReportSender::new();

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
            receiver_report_sender.write_receiver_report_block(ssrc, at(65))
        );

        // Receiving older packets doesn't update jitter
        receiver_report_sender.remember_received(9, OPUS_PAYLOAD_TYPE, 0, at(85));

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(90))
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
            receiver_report_sender.write_receiver_report_block(ssrc, at(105))
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
            receiver_report_sender.write_receiver_report_block(ssrc, at(125))
        );
    }

    #[test]
    fn test_receiver_report_sender_jitter_recovery() {
        let mut receiver_report_sender = RtcpReportSender::new();

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
            receiver_report_sender.write_receiver_report_block(ssrc, at(65))
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
                receiver_report_sender.write_receiver_report_block(ssrc, at(time))
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
                receiver_report_sender.write_receiver_report_block(ssrc, at(time))
            );
        }
    }

    #[test]
    fn test_receiver_report_after_sender_report() {
        let mut receiver_report_sender = RtcpReportSender::new();
        let mut sent = 1;

        fn expected_bytes(
            ssrc: Ssrc,
            interarrival_jitter: u32,
            max_seqnum: u32,
            last_sender_report_timestamp: u32,
            delay_since_last_sender_report: u32,
        ) -> Vec<u8> {
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
        let mut receive_opus = |ts: Instant| {
            receiver_report_sender.remember_received(
                seqnum,
                OPUS_PAYLOAD_TYPE,
                sent * rtp_interval,
                ts,
            );
            seqnum += 1;
            sent += 1;
        };

        receive_opus(at(20));
        receive_opus(at(40));
        receive_opus(at(60));

        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12, 0, 0)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(65))
        );

        // make it so only the middle 32 bits match the mask
        let ntp_ts = 0xFFFF_FFFF_FFF0_FFFF;
        let rtp_ts = 10000000;
        let mut sender_report = SenderReport {
            header: RtcpHeader {
                has_padding: false,
                count_or_format: 0,
                payload_type: RTCP_TYPE_SENDER_REPORT,
                length_in_words: 6,
            },
            sender_info: SenderInfo {
                ssrc,
                ntp_ts,
                rtp_ts,
                packet_count: 2,
                octet_count: 100,
            },
            report_blocks: vec![],
        };
        receiver_report_sender.remember_received_sender_report(sender_report.clone(), at(80));

        // 5 millis duration to nanos
        let delay = 5_000_000 / 15259;
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12, 0xFFFFFFF0, delay)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(85))
        );

        // earlier sender report is ignored
        sender_report.sender_info.ntp_ts = 0xFFFF_FFFF_FF00_FFFF;
        receiver_report_sender.remember_received_sender_report(sender_report.clone(), at(90));
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12, 0xFFFFFFF0, delay)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(85))
        );

        // newer reports are remembered
        sender_report.sender_info.ntp_ts = 0xFFFF_FFFF_FFFF_FFFF;
        receiver_report_sender.remember_received_sender_report(sender_report, at(125));

        let delay = 10_000_000 / 15259;
        assert_eq!(
            Some(expected_bytes(ssrc, 0, 12, 0xFFFFFFFF, delay)),
            receiver_report_sender.write_receiver_report_block(ssrc, at(135))
        );
    }

    #[test]
    fn test_delay_from_last_sr() {
        let now = Instant::now();
        let last_sr_time = now - Duration::from_secs(5);

        // check if close to expected value (within 150 microseconds)
        assert!((5 * 2_u32.pow(16)).abs_diff(calculate_delay_since_sr(last_sr_time, now)) < 10);

        // within 15ms after 15mins.
        let last_sr_time = now - Duration::from_secs(60 * 15);
        assert!(
            (60 * 15 * 2_u32.pow(16)).abs_diff(calculate_delay_since_sr(last_sr_time, now)) < 1000
        );

        let too_old_to_matter = now - Duration::from_secs(2_u64.pow(16) + 1);
        assert_eq!(0, calculate_delay_since_sr(too_old_to_matter, now));
    }
}
