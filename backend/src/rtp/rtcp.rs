//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::{Packet, OPUS_PAYLOAD_TYPE, VP8_PAYLOAD_TYPE};

use std::{
    convert::TryFrom,
    ops::{Range, RangeInclusive},
};

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes_gcm::{AeadInPlace, Aes128Gcm};
use calling_common::{
    parse_u16, parse_u24, parse_u32, parse_u64, round_up_to_multiple_of, CheckedSplitAt, Duration,
    Instant, SystemTime, Writable, Writer, U24,
};
use log::*;
use once_cell::sync::Lazy;

use crate::transportcc as tcc;

use super::{
    nack::{parse_nack, Nack},
    srtp::{Iv, Key, Salt, SRTP_AUTH_TAG_LEN, SRTP_IV_LEN},
    types::*,
    VERSION,
};

const RTCP_HEADER_LEN: usize = 8;
const RTCP_RECEIVER_REPORT_BLOCK_LEN: usize = 28;
pub const RTCP_PAYLOAD_TYPE_OFFSET: usize = 1;
const RTCP_PAYLOAD_LEN_RANGE: Range<usize> = 2..4;
const RTCP_SENDER_SSRC_RANGE: Range<usize> = 4..8;
pub const SRTCP_FOOTER_LEN: usize = 4;
pub const RTCP_TYPE_SENDER_REPORT: u8 = 200;
pub const RTCP_TYPE_RECEIVER_REPORT: u8 = 201;
const RTCP_TYPE_EXTENDED_REPORT: u8 = 207;
const RTCP_TYPE_SDES: u8 = 202;
pub const RTCP_TYPE_BYE: u8 = 203;
const SEQNUM_GAP_THRESHOLD: u32 = 500;
const FULL_SEQNUM_GAP_THRESHOLD: u64 = 500;
const FULL_SEQNUM_ROLLOVER_THRESHOLD: u64 = 150;
const RTCP_FORMAT_LOSS_NOTIFICATION: u8 = 15;
pub const RTCP_PAYLOAD_TYPES: RangeInclusive<u8> = 64..=95;
pub const RTCP_TYPE_GENERIC_FEEDBACK: u8 = 205;
pub const RTCP_FORMAT_NACK: u8 = 1;
pub const RTCP_FORMAT_TRANSPORT_CC: u8 = 15;
pub const RTCP_TYPE_SPECIFIC_FEEDBACK: u8 = 206;
pub const RTCP_FORMAT_PLI: u8 = 1;
pub const RTT_ESTIMATE_AGE_LIMIT: Duration = Duration::from_secs(15);
const RTT_ESTIMATE_AGE_LIMIT_SECS_F64: f64 = 15.0;
// 1900 Jan 1st 00:00:00 UTC, RTP's chosen EPOCH
static NTP_EPOCH: Lazy<SystemTime> =
    Lazy::new(|| (std::time::UNIX_EPOCH - std::time::Duration::from_secs(2_208_988_800)).into());

#[derive(Default, Debug)]
pub struct ControlPacket<'packet> {
    // pub for tests
    pub key_frame_requests: Vec<KeyFrameRequest>,
    // pub for tests
    pub tcc_feedbacks: Vec<&'packet [u8]>,
    pub nacks: Vec<Nack>,
    pub sender_reports: Vec<SenderReport>,
    pub receiver_reports: Vec<ReceiverReport>,
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
                        Ok(report) => incoming.sender_reports.push(report),
                        Err(err) => warn!("Failed to parse RTCP sender report: {}", err),
                    }
                }
                (RTCP_TYPE_RECEIVER_REPORT, _) => {
                    match ReceiverReport::from_bytes_after_header(payload, header) {
                        Ok(report) => incoming.receiver_reports.push(report),
                        Err(err) => warn!("Failed to parse RTCP receiver report: {}", err),
                    }
                }
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
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_and_encrypt(
        pt: u8,
        count_or_format: u8,
        is_padded: bool,
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

        serialized[0] = (VERSION << 6) | is_padded_mask(is_padded) | count_or_format;
        serialized[RTCP_PAYLOAD_TYPE_OFFSET] = pt;
        serialized[RTCP_PAYLOAD_LEN_RANGE.clone()]
            .copy_from_slice(&padded_payload_len_in_words_plus_1.to_be_bytes());
        serialized[RTCP_SENDER_SSRC_RANGE.clone()].copy_from_slice(&sender_ssrc.to_be_bytes());
        // TODO: Make this more efficient by copying less.
        serialized[RTCP_HEADER_LEN..][..payload_writer.written_len()]
            .copy_from_slice(&payload_writer.to_vec());

        Self::encrypt(serialized, sender_ssrc, srtcp_index, key, salt)
    }

    // Encrypts an SRTP packet. Packet should have space for SRTP tag and footer already
    pub fn encrypt(
        mut packet: Vec<u8>,
        sender_ssrc: Ssrc,
        srtcp_index: u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        let packet_len = packet.len();
        packet[packet_len - SRTCP_FOOTER_LEN..]
            .copy_from_slice(&(srtcp_index | 0x80000000/* "encrypted" */).to_be_bytes());
        let (cipher, nonce, aad, plaintext, tag) =
            Self::prepare_for_crypto(&mut packet, sender_ssrc, srtcp_index, key, salt)?;
        let nonce = GenericArray::from_slice(&nonce);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce, &aad, plaintext)
            .ok()?;
        tag.copy_from_slice(&computed_tag);
        Some(packet)
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
            false,
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
            false,
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
            false,
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

fn is_padded_mask(is_padded: bool) -> u8 {
    if is_padded {
        0b00100000
    } else {
        0b0
    }
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
    // sender report stats
    sent_since_last_report: bool,
    packets_sent: u32,
    total_payload_bytes_sent: u32,
    max_sent_seqnum: Option<u64>,
    last_sent_time: Instant,
    last_sent_rtp_timestamp: u32,
    sent_sample_freq: u64,
    // additional stats state
    last_sender_report_sent_time: Instant,
    last_sender_report_sent_time_ntp: u64,
    last_receiver_report_received_time: Instant,
    last_receiver_report_dlsr: u32,
    rtt_estimate: Option<Duration>,
    rtt_estimate_last_updated: Option<Instant>,
}

impl RtcpReportSender {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        Self {
            max_seqnum: None,
            max_seqnum_in_last: None,
            cumulative_loss: 0,
            cumulative_loss_in_last: 0,
            last_receive_time: now,
            last_rtp_timestamp: 0,
            jitter_q4: 0,
            last_sender_report_received_ntp_timestamp: 0,
            last_sender_report_received_time: now,

            sent_since_last_report: false,
            packets_sent: 0,
            total_payload_bytes_sent: 0,
            max_sent_seqnum: None,
            last_sent_time: now,
            last_sent_rtp_timestamp: 0,
            sent_sample_freq: 90000,

            last_sender_report_sent_time: now,
            last_sender_report_sent_time_ntp: 0,
            last_receiver_report_received_time: now,
            last_receiver_report_dlsr: 0,
            rtt_estimate: None,
            rtt_estimate_last_updated: None,
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

    pub(super) fn remember_report_block(&mut self, report_block: ReportBlock, now: Instant) {
        if report_block.delay_last_sender_report == 0 || report_block.last_sender_report == 0 {
            return;
        }
        // Ignore reports for old SenderReports. In pathological cases, we may always ignore reports
        // if we always receive them too late. Remembering the last few sender reports would reduce
        // this issue, but shouldn't be an issue given reporting rates
        if report_block.last_sender_report != get_lsr(self.last_sender_report_sent_time_ntp) {
            return;
        }

        // When our reporting interval is longer than the clients RR interval, the SFU will receive
        // multiple RR's with the same LSR referencing the same SR. These RR's may arrive out of
        // order - we prioritize the newest RR. We differentiate age of RR's based on their DLSR
        if report_block.delay_last_sender_report < self.last_receiver_report_dlsr {
            return;
        }

        let delay = dlsr_to_duration(report_block.delay_last_sender_report);
        let new_rtt_estimate = now
            .saturating_duration_since(self.last_sender_report_sent_time)
            .saturating_sub(delay);

        self.update_rtt_estimate(new_rtt_estimate, now);
        self.last_receiver_report_received_time = now;
        self.last_receiver_report_dlsr = report_block.delay_last_sender_report;
    }

    /// Update the rtt_estimate. Smoothes the changing of RTT estimates. Ages out estimates older than 15 seconds.
    fn update_rtt_estimate(&mut self, new_rtt_estimate: Duration, now: Instant) {
        if let Some(old_rtt_estimate) = self.rtt_estimate {
            let estimate_age =
                now.saturating_duration_since(self.last_receiver_report_received_time);
            let weight = RTT_ESTIMATE_AGE_LIMIT
                .saturating_sub(estimate_age)
                .as_secs_f64()
                / RTT_ESTIMATE_AGE_LIMIT_SECS_F64;
            self.rtt_estimate = Some(Duration::from_secs_f64(
                weight * old_rtt_estimate.as_secs_f64()
                    + ((1.0 - weight) * new_rtt_estimate.as_secs_f64()),
            ))
        } else {
            self.rtt_estimate = Some(new_rtt_estimate);
        }
        self.rtt_estimate_last_updated = Some(now);
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
            if maybe_receive_stream_restart(seqnum, max_seqnum) {
                // Reset state since the values for the old stream may not be relevant anymore.
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

    pub(super) fn remember_sent(&mut self, outgoing: &Packet<Vec<u8>>, now: Instant) {
        if outgoing.is_rtx() || outgoing.is_data() {
            return;
        }

        // we want to remember the rtp timestamp so we use it to interpolate a timestamp for an SR
        // even though we may forward out of order, the max_sent_seqnum has the closest timestamp
        let seqnum = outgoing.seqnum();
        if let Some(max_seqnum) = self.max_sent_seqnum {
            // if we think the stream rolled over, keep the stats. In pathological cases, max_seqnum
            // will change between high and low values, but still preserve the stats.
            // In the unfortunate case that we get a high seqnum very delayed, we may
            // trigger the stream restart condition.
            let restarted = maybe_send_stream_restart(seqnum, max_seqnum);
            let rolledover = maybe_stream_rollover(seqnum, max_seqnum);
            if seqnum > max_seqnum || rolledover || restarted {
                self.max_sent_seqnum = Some(seqnum);
                self.last_sent_rtp_timestamp = outgoing.timestamp;
                self.last_sent_time = now;
            }
            if restarted && !rolledover {
                self.packets_sent = 0;
                self.total_payload_bytes_sent = 0;
            }
        } else {
            self.max_sent_seqnum = Some(seqnum);
            self.last_sent_rtp_timestamp = outgoing.timestamp;
            self.last_sent_time = now;
        }

        self.sent_since_last_report = true;
        // the spec is to wrap around these counts
        // must ignore padding bytes (though not padding packets)
        self.packets_sent = self.packets_sent.wrapping_add(1);
        let net_bytes = (outgoing.payload_size_bytes() as u32)
            .saturating_sub(outgoing.padding_byte_count as u32);
        self.total_payload_bytes_sent = self.total_payload_bytes_sent.wrapping_add(net_bytes);

        if outgoing.is_audio() || outgoing.is_video() {
            self.sent_sample_freq = Self::estimate_sample_freq(outgoing.payload_type()) as u64;
        }
    }

    fn estimate_sample_freq(payload_type: PayloadType) -> u32 {
        if payload_type == OPUS_PAYLOAD_TYPE {
            48000
        } else if payload_type == VP8_PAYLOAD_TYPE {
            90000
        } else {
            warn!(
                "unexpected payload type {}, using payload frequency of 90000",
                payload_type
            );
            90000
        }
    }

    // converts duration to units of RTP timestamp
    fn duration_to_rtp_duration(duration: Duration, sample_freq: u32) -> u32 {
        (duration.as_millis() as u32).saturating_mul(sample_freq) / 1000
    }

    fn update_jitter(
        &mut self,
        payload_type: PayloadType,
        rtp_timestamp: u32,
        receive_time: Instant,
    ) {
        let receive_diff = receive_time.saturating_duration_since(self.last_receive_time);
        let payload_freq_hz = Self::estimate_sample_freq(payload_type);

        // The difference in receive time (interarrival time) converted to the units of the RTP
        // timestamps.
        let receive_diff_rtp = Self::duration_to_rtp_duration(receive_diff, payload_freq_hz);

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

    /// Appends a sender report or receiver report to buffer depending on whether
    /// any packets have been forwarded for that SSRC on this endpoint.
    ///
    /// SenderReports will never have a reception block since we never forward media
    /// back to the original sender
    ///
    /// returns (payload type, report count, and num bytes appended to buffer)
    pub(super) fn write_report_block_in_place(
        &mut self,
        ssrc: Ssrc,
        now: Instant,
        sys_now: SystemTime,
        buffer: &mut dyn Writable,
    ) -> Option<(u8, u8, usize)> {
        match self.rtcp_report_payload_type()? {
            RTCP_TYPE_SENDER_REPORT => {
                self.write_sender_report_block_in_place(ssrc, now, sys_now, buffer);
                Some((RTCP_TYPE_SENDER_REPORT, 0u8, SenderInfo::SENDER_INFO_LENGTH))
            }
            RTCP_TYPE_RECEIVER_REPORT => {
                self.write_receiver_report_block_in_place(ssrc, now, buffer);
                Some((
                    RTCP_TYPE_RECEIVER_REPORT,
                    1u8,
                    RTCP_RECEIVER_REPORT_BLOCK_LEN,
                ))
            }
            unknown => {
                warn!("Unexpected report type `{}` when writing report", unknown);
                None
            }
        }
    }

    /// returns the next report's payload type
    pub(super) fn rtcp_report_payload_type(&self) -> Option<u8> {
        if self.sent_since_last_report {
            Some(RTCP_TYPE_SENDER_REPORT)
        } else if self.max_seqnum.is_some() && self.max_seqnum_in_last.is_some() {
            Some(RTCP_TYPE_RECEIVER_REPORT)
        } else {
            None
        }
    }

    #[cfg(test)]
    fn write_receiver_report_block(&mut self, ssrc: Ssrc, now: Instant) -> Option<Vec<u8>> {
        let mut buffer = Vec::with_capacity(RTCP_RECEIVER_REPORT_BLOCK_LEN);
        match self.rtcp_report_payload_type() {
            Some(RTCP_TYPE_RECEIVER_REPORT) => {
                self.write_receiver_report_block_in_place(ssrc, now, &mut buffer);
                Some(buffer)
            }
            _ => None,
        }
    }

    fn write_receiver_report_block_in_place(
        &mut self,
        ssrc: Ssrc,
        now: Instant,
        out: &mut dyn Writable,
    ) {
        let (Some(max_seqnum), Some(max_seqnum_in_last)) =
            (self.max_seqnum, self.max_seqnum_in_last)
        else {
            return;
        };
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
                    calculate_dlsr(self.last_sender_report_received_time, now),
                )
            } else {
                (0, 0)
            };

        (
            ssrc, // sender_ssrc - matches source ssrc since we send a separate report for every SSRC
            ssrc, // source_ssrc
            [fraction_lost_since_last],
            cumulative_loss_i24,
            max_seqnum,
            interarrival_jitter,
            last_sender_report_timestamp,
            delay_since_last_sender_report,
        )
            .write(out);
    }

    /// Creates a SenderReport. Since we never forward media back to the original sender,
    /// there are no reception report blocks.
    fn write_sender_report_block_in_place(
        &mut self,
        ssrc: Ssrc,
        now: Instant,
        sys_now: SystemTime,
        buffer: &mut dyn Writable,
    ) {
        let ntp_ts = convert_to_ntp(sys_now);
        self.last_sender_report_sent_time_ntp = ntp_ts;
        // we use sys time as our wall clock timestamp, Instants can only measure elapsed times
        // interpolate based off last sent rtp timestamp, elapsed time, and sample freq
        let rtp_ts_elapsed: u32 = (now
            .saturating_duration_since(self.last_sent_time)
            .as_micros() as u64
            * self.sent_sample_freq
            / 1_000_000)
            .try_into()
            .unwrap_or(0);
        let rtp_ts = self.last_sent_rtp_timestamp.wrapping_add(rtp_ts_elapsed);
        let packet_count = self.packets_sent;
        let octet_count = self.total_payload_bytes_sent;

        self.sent_since_last_report = false;
        self.last_receiver_report_dlsr = 0;
        self.last_sender_report_sent_time = now;

        SenderInfo {
            ssrc,
            ntp_ts,
            rtp_ts,
            packet_count,
            octet_count,
        }
        .write(buffer);
    }

    /// returns the rtt estimate and when the estimate was last updated
    pub(super) fn rtt_estimate(&self) -> Option<(Duration, Instant)> {
        Some((self.rtt_estimate?, self.rtt_estimate_last_updated?))
    }
}

/// Large seqnum gaps are caused by stream restarts. Use seqnums to guess if there was a
/// stream restart
fn maybe_receive_stream_restart(seqnum: u32, max_seqnum: u32) -> bool {
    seqnum.abs_diff(max_seqnum) > SEQNUM_GAP_THRESHOLD
}

/// Large seqnum gaps are caused by stream restarts. Use seqnums to guess if there was a
/// stream restart
fn maybe_send_stream_restart(seqnum: FullSequenceNumber, max_seqnum: FullSequenceNumber) -> bool {
    seqnum.abs_diff(max_seqnum) > FULL_SEQNUM_GAP_THRESHOLD
}

// stream rollovers happen when the seqnum wraps around. We check for wrap around
// less than a certain gap. Note, there is a VERY small chance that the stream
// has restarted instead of rolledover.
fn maybe_stream_rollover(seqnum: FullSequenceNumber, max_seqnum: FullSequenceNumber) -> bool {
    let delta = seqnum.abs_diff(max_seqnum);
    seqnum < max_seqnum
        && max_seqnum > u64::MAX - delta
        && seqnum < FULL_SEQNUM_ROLLOVER_THRESHOLD
        && u64::MAX - max_seqnum < FULL_SEQNUM_ROLLOVER_THRESHOLD
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
fn calculate_dlsr(sr_last_received_time: Instant, now: Instant) -> u32 {
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

fn dlsr_to_duration(delay_since_sr: u32) -> Duration {
    const NANOS_TO_DELAY_UNIT: u64 = 15259;
    Duration::from_nanos(delay_since_sr as u64 * NANOS_TO_DELAY_UNIT)
}

/// Converts to NTP TS in seconds. Returns 0 if the SystemTime is before NTP epoch (Jan 01, 1900)
/// Full length NTP timestamp is 32 bits for seconds since epoch, and 32 bits for fractions of a second
/// Seconds roll over every u32::MAX seconds after NTP Epoch
pub fn convert_to_ntp(ts: SystemTime) -> u64 {
    const ROLLOVER_LIMIT: u64 = u32::MAX as u64 + 1;
    let elapsed = ts.saturating_duration_since(*NTP_EPOCH);
    ((elapsed.as_secs() % ROLLOVER_LIMIT) << 32) + elapsed.subsec_nanos() as u64
}

#[derive(Debug, Clone, PartialEq)]
pub struct RtcpHeader {
    has_padding: bool,
    pub count_or_format: u8,
    pub payload_type: u8,
    /// length of the RTCP packet in words, minus the 1-word header
    pub length_in_words: u16,
}

impl RtcpHeader {
    pub const LENGTH: usize = 4;
    const PADDING_MASK: u8 = 0b00100000;
    const RC_MASK: u8 = 0b00011111;
    const PACKET_LENGTH_RANGE: Range<usize> = 2..4;

    pub fn new(
        has_padding: bool,
        count_or_format: u8,
        payload_type: u8,
        length_in_words: u16,
    ) -> Self {
        Self {
            has_padding,
            count_or_format,
            payload_type,
            length_in_words,
        }
    }

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

impl Writer for RtcpHeader {
    fn written_len(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, out: &mut dyn calling_common::Writable) {
        let first_two_bytes = [
            (VERSION << 6) | is_padded_mask(self.has_padding) | self.count_or_format,
            self.payload_type,
        ];
        first_two_bytes.write(out);
        self.length_in_words.write(out);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportBlock {
    pub ssrc: Ssrc,
    fraction_loss: u8,
    cumulative_loss_count: U24,
    highest_sequence_num: u32,
    jitter: u32,
    // middle 32 bits of last receiver sender reports 64bit NTP TS
    last_sender_report: u32,
    delay_last_sender_report: u32,
}

impl ReportBlock {
    pub const LENGTH: usize = 24;
    const SSRC_RANGE: Range<usize> = 0..4;
    const FRACTION_LOSS_RANGE: usize = 4;
    const CUMULATIVE_LOSS_RANGE: Range<usize> = 5..8;
    const HIGHEST_SEQUENCE_NUMBER_RANGE: Range<usize> = 8..12;
    const INTERARRIVAL_JITTER_RANGE: Range<usize> = 12..16;
    const LAST_SENDER_REPORT_RANGE: Range<usize> = 16..20;
    const DELAY_LAST_SENDER_REPORT_RANGE: Range<usize> = 20..24;

    fn from_bytes(value: &[u8]) -> Result<Self, String> {
        if value.len() < Self::LENGTH {
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

impl Writer for ReportBlock {
    fn written_len(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, out: &mut dyn calling_common::Writable) {
        self.ssrc.write(out);
        [self.fraction_loss].write(out);
        self.cumulative_loss_count.write(out);
        self.highest_sequence_num.write(out);
        self.jitter.write(out);
        self.last_sender_report.write(out);
        self.delay_last_sender_report.write(out);
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

impl Writer for SenderInfo {
    fn written_len(&self) -> usize {
        Self::SENDER_INFO_LENGTH
    }

    fn write(&self, out: &mut dyn calling_common::Writable) {
        self.ssrc.write(out);
        self.ntp_ts.write(out);
        self.rtp_ts.write(out);
        self.packet_count.write(out);
        self.octet_count.write(out);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SenderReport {
    header: RtcpHeader,
    sender_info: SenderInfo,
    report_blocks: Vec<ReportBlock>,
}

impl SenderReport {
    pub const MIN_LENGTH: usize = RtcpHeader::LENGTH + SenderInfo::SENDER_INFO_LENGTH;
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
        if header.payload_type != RTCP_TYPE_SENDER_REPORT {
            return Err(format!(
                "Malformed Sender Report: expected payload type {}, found {}",
                RTCP_TYPE_RECEIVER_REPORT, header.payload_type
            ));
        }
        let header_length = header.length_in_words as usize * 4;
        let minimum_expected_length =
            SenderInfo::SENDER_INFO_LENGTH + header.count_or_format as usize * ReportBlock::LENGTH;
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
            bytes_left = &bytes_left[ReportBlock::LENGTH..];
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

impl Writer for SenderReport {
    fn written_len(&self) -> usize {
        self.header.packet_length_in_bytes()
    }

    fn write(&self, out: &mut dyn calling_common::Writable) {
        self.header.write(out);
        self.sender_info.write(out);
        for report in &self.report_blocks {
            report.write(out);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceiverReport {
    header: RtcpHeader,
    sender_ssrc: Ssrc,
    pub report_blocks: Vec<ReportBlock>,
}

impl ReceiverReport {
    const SSRC_LENGTH: usize = 4;
    const SENDER_SSRC_RANGE: Range<usize> = 0..Self::SSRC_LENGTH;
    pub const MIN_LENGTH: usize = RtcpHeader::LENGTH + Self::SSRC_LENGTH;

    /// Parses binary into ReceiverReport. Format is similar to SenderReport without
    /// the sender info
    #[cfg(test)]
    fn from_bytes(value: &[u8]) -> Result<Self, String> {
        if value.len() < Self::MIN_LENGTH {
            return Err("Malformed Receiver Report: too few bytes".to_owned());
        }
        let header = RtcpHeader::from_bytes(value);
        Self::from_bytes_after_header(&value[RtcpHeader::LENGTH..], header)
    }

    fn from_bytes_after_header(value: &[u8], header: RtcpHeader) -> Result<Self, String> {
        if header.payload_type != RTCP_TYPE_RECEIVER_REPORT {
            return Err(format!(
                "Malformed Receiver Report: expected payload type {}, found {}",
                RTCP_TYPE_RECEIVER_REPORT, header.payload_type
            ));
        }
        let header_length = header.length_in_words as usize * 4;
        let report_count = header.count_or_format.into();
        let minimum_expected_length = Self::SSRC_LENGTH + report_count * ReportBlock::LENGTH;
        if header_length < minimum_expected_length || value.len() < header_length {
            return Err(format!(
                "Malformed Receiver Report: header_size={}, report_count={}, actual_size={}",
                header_length,
                header.count_or_format,
                value.len()
            ));
        }

        let sender_ssrc = parse_u32(&value[Self::SENDER_SSRC_RANGE]);
        let mut report_blocks = Vec::with_capacity(report_count);
        let mut bytes_left = &value[Self::SENDER_SSRC_RANGE.end..];

        while report_blocks.len() < report_count {
            report_blocks.push(ReportBlock::from_bytes(bytes_left)?);
            bytes_left = &bytes_left[ReportBlock::LENGTH..];
        }

        Ok(Self {
            header,
            sender_ssrc,
            report_blocks,
        })
    }

    pub fn ssrc(&self) -> Ssrc {
        self.sender_ssrc
    }
}

#[cfg(test)]
mod test {
    use calling_common::{Duration, Writer};

    use crate::{call::CLIENT_SERVER_DATA_PAYLOAD_TYPE, rtp::new_srtp_keys};

    use super::*;

    #[test]
    fn test_parse_rtcp_reports() {
        let report_count: u8 = 2;
        let pt = RTCP_TYPE_SENDER_REPORT;
        let length: u16 = (SenderInfo::SENDER_INFO_LENGTH
            + report_count as usize * ReportBlock::LENGTH)
            .try_into()
            .unwrap();
        let length_in_words = length / 4;
        let raw_header: Vec<u8> = ([0b1000_0000 | report_count, pt], length_in_words).to_vec();
        let parsed_header = RtcpHeader::from_bytes(&raw_header);
        assert_eq!(report_count, parsed_header.count_or_format);
        assert_eq!(pt, parsed_header.payload_type);
        assert_eq!(length_in_words, parsed_header.length_in_words);
        let mut buf = vec![];
        parsed_header.write(&mut buf);
        assert_eq!(buf, raw_header);

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

        let raw_sender_report = (
            raw_header.clone(),
            raw_sender_info,
            raw_report.clone(),
            raw_report.clone(),
        )
            .to_vec();
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
            parsed_header.clone(),
        )
        .unwrap();
        assert_eq!(parsed_sender_report, parsed_sender_report_2);

        let report_count: u8 = 2;
        let pt = RTCP_TYPE_RECEIVER_REPORT;
        let length: u16 = (ReceiverReport::MIN_LENGTH - RtcpHeader::LENGTH
            + report_count as usize * ReportBlock::LENGTH)
            .try_into()
            .unwrap();
        let length_in_words = length / 4;
        let rr_header = RtcpHeader {
            payload_type: pt,
            has_padding: false,
            count_or_format: report_count,
            length_in_words,
        };
        let raw_receiver_report =
            (rr_header.clone(), ssrc, raw_report.clone(), raw_report).to_vec();
        let parsed_receiver_report = ReceiverReport::from_bytes(&raw_receiver_report).unwrap();
        assert_eq!(rr_header, parsed_receiver_report.header);
        assert_eq!(ssrc, parsed_receiver_report.ssrc());
        assert_eq!(
            report_count as usize,
            parsed_receiver_report.report_blocks.len()
        );
        assert_eq!(parsed_report_block, parsed_receiver_report.report_blocks[0]);
        assert_eq!(parsed_report_block, parsed_receiver_report.report_blocks[1]);

        let parsed_receiver_report_2 = ReceiverReport::from_bytes_after_header(
            &raw_receiver_report[RtcpHeader::LENGTH..],
            rr_header,
        )
        .unwrap();
        assert_eq!(parsed_receiver_report, parsed_receiver_report_2);
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
        assert!((5 * 2_u32.pow(16)).abs_diff(calculate_dlsr(last_sr_time, now)) < 10);

        // within 15ms after 15mins.
        let last_sr_time = now - Duration::from_secs(60 * 15);
        assert!((60 * 15 * 2_u32.pow(16)).abs_diff(calculate_dlsr(last_sr_time, now)) < 1000);

        let too_old_to_matter = now - Duration::from_secs(2_u64.pow(16) + 1);
        assert_eq!(0, calculate_dlsr(too_old_to_matter, now));
    }

    #[test]
    fn test_convert_to_ntp() {
        // NTP Epoch is Jan 01, 1900 00:00:00 UTC
        // Unix Epoch is Jan 01, 1970 00:00:00 UTC
        let unix_epoch = std::time::UNIX_EPOCH.into();
        assert_eq!(
            ((70 * 365 * 24 * 60 * 60) + (17 * 24 * 60 * 60)) << 32,
            convert_to_ntp(unix_epoch),
        );

        assert_eq!(
            (((70 * 365 * 24 * 60 * 60) + (17 * 24 * 60 * 60)) << 32) + 550_500,
            convert_to_ntp(unix_epoch + Duration::from_nanos(550_500)),
        );
    }

    #[test]
    fn test_sender_report_basic() {
        let mut report_sender = RtcpReportSender::new();

        let ssrc = 123456;
        // Given a 20 ms ptime (50 packets / second) and a sample rate of 48000, RTP timestamps
        // would increment by this amount assuming no other delays.
        let sample_rate = 48000;
        let packet_rate = 50;
        let rtp_interval = sample_rate / packet_rate;
        // rtp duration for 5 milliseconds
        let rtp_elapsed = 5 * sample_rate / 1000;
        let now = Instant::now();
        let sys_now = SystemTime::now();
        let at = |millis| now + Duration::from_millis(millis);
        let sys_at = |millis| sys_now + Duration::from_millis(millis);
        let mut seqnum: FullSequenceNumber = 1;
        let mut sent = 0;
        let mut next_packet = |pt, packet_size| {
            let packet = Packet::with_empty_tag(
                pt,
                seqnum,
                sent * rtp_interval,
                ssrc,
                None,
                None,
                &vec![1u8; packet_size],
            );
            seqnum += 1;
            sent += 1;
            packet
        };

        assert_eq!(
            None,
            report_sender.rtcp_report_payload_type(),
            "Nothing received or sent, should have no report"
        );
        assert_eq!(
            None,
            report_sender.write_report_block_in_place(ssrc, now, sys_now, &mut vec![]),
            "Nothing received or sent, should have no report"
        );

        let mut buffer = vec![];
        report_sender.remember_sent(&next_packet(OPUS_PAYLOAD_TYPE, 5), at(20));
        assert_eq!(
            Some(RTCP_TYPE_SENDER_REPORT),
            report_sender.rtcp_report_payload_type()
        );
        report_sender.write_report_block_in_place(ssrc, at(25), sys_at(25), &mut buffer);
        assert_eq!(
            SenderInfo {
                ssrc,
                ntp_ts: convert_to_ntp(sys_at(25)),
                rtp_ts: rtp_elapsed,
                packet_count: 1,
                octet_count: 5
            },
            SenderInfo::from_bytes(&buffer),
        );

        assert_eq!(
            None,
            report_sender.rtcp_report_payload_type(),
            "Report status cleared, should be none pending"
        );

        let mut buffer = vec![];
        report_sender.remember_sent(&next_packet(OPUS_PAYLOAD_TYPE, 100), at(40));
        report_sender.write_report_block_in_place(ssrc, at(45), sys_at(45), &mut buffer);
        assert_eq!(
            SenderInfo {
                ssrc,
                ntp_ts: convert_to_ntp(sys_at(45)),
                rtp_ts: rtp_interval + rtp_elapsed,
                packet_count: 2,
                octet_count: 105
            },
            SenderInfo::from_bytes(&buffer),
            "SenderReport correctly updates"
        );
        assert_eq!(
            None,
            report_sender.rtcp_report_payload_type(),
            "Report status cleared, should be none pending"
        );

        report_sender.remember_sent(&next_packet(CLIENT_SERVER_DATA_PAYLOAD_TYPE, 100), at(40));
        assert_eq!(
            None,
            report_sender.rtcp_report_payload_type(),
            "Should ignore data packets"
        );
        let mut rtx_packet = next_packet(OPUS_PAYLOAD_TYPE, 100);
        rtx_packet.set_seqnum_in_payload(123545);
        report_sender.remember_sent(&rtx_packet, at(40));
        assert_eq!(
            None,
            report_sender.rtcp_report_payload_type(),
            "Should ignore RTX packets"
        );
    }

    #[test]
    fn test_encrypt() {
        let (_, encrypt) = new_srtp_keys(0);
        let report = SenderReport {
            header: RtcpHeader {
                length_in_words: 6,
                has_padding: false,
                count_or_format: 0,
                payload_type: 200,
            },
            sender_info: SenderInfo {
                ssrc: 100,
                ntp_ts: 8888888,
                rtp_ts: 8888888,
                packet_count: 32,
                octet_count: 64,
            },
            report_blocks: vec![],
        };
        let mut packet = report.to_vec();
        packet.extend_from_slice(&[0u8; 20]);

        let mut encrypted =
            ControlPacket::encrypt(packet, 100, 1, &encrypt.rtcp.key, &encrypt.rtcp.salt).unwrap();
        let decrypted = ControlPacket::parse_and_decrypt_in_place(
            &mut encrypted,
            &encrypt.rtcp.key,
            &encrypt.rtcp.salt,
        )
        .unwrap();
        assert_eq!(decrypted.sender_reports[0], report)
    }
}
