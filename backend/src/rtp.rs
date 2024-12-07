//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of RTP/SRTP. See https://tools.ietf.org/html/rfc3550 and
//! https://tools.ietf.org/html/rfc7714. Assumes AES-GCM 128.

mod nack;
mod packet;
mod rtcp;
mod rtx;
mod srtp;
mod types;

use std::{collections::HashMap, convert::TryInto};

use calling_common::{expand_truncated_counter, read_u16, Bits, Duration, Instant, Writer};
use log::*;
use metrics::*;
use nack::*;
pub use nack::{write_nack, Nack};
use packet::*;
pub use packet::{DependencyDescriptor, Header, Packet};
use rtcp::*;
pub use rtcp::{ControlPacket, KeyFrameRequest};
pub use rtx::to_rtx_ssrc;
use rtx::*;
use srtp::*;
#[cfg(test)]
pub use srtp::{key_from, new_srtp_keys, salt_from};
pub use srtp::{new_master_key_material, KeyAndSalt, KeysAndSalts, MasterKeyMaterial};
pub use types::*;

use crate::transportcc as tcc;

const VERSION: u8 = 2;
const PADDING_PAYLOAD_TYPE: PayloadType = 99;
const CLIENT_SERVER_DATA_PAYLOAD_TYPE: PayloadType = 101;
const OPUS_PAYLOAD_TYPE: PayloadType = 102;
const VP8_PAYLOAD_TYPE: PayloadType = 108;

// Discard outgoing packets after this time.
// 3 second lifetime matches WebRTC's RTX history
const PACKET_LIFETIME: Duration = Duration::from_secs(3);

pub fn looks_like_rtp(packet: &[u8]) -> bool {
    packet.len() > RTP_PAYLOAD_TYPE_OFFSET
        && (packet[0] >> 6) == VERSION
        && !RTCP_PAYLOAD_TYPES.contains(&(packet[RTP_PAYLOAD_TYPE_OFFSET] & 0b01111111))
}

pub fn looks_like_rtcp(packet: &[u8]) -> bool {
    packet.len() > RTCP_PAYLOAD_TYPE_OFFSET
        && (packet[0] >> 6) == VERSION
        && RTCP_PAYLOAD_TYPES.contains(&(packet[RTCP_PAYLOAD_TYPE_OFFSET] & 0b01111111))
}

/// The rotation specified by the sender to apply to a video frame
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VideoRotation {
    None = 0,
    Clockwise90 = 90,
    Clockwise180 = 180,
    Clockwise270 = 270,
}

impl From<u8> for VideoRotation {
    fn from(b: u8) -> Self {
        // Parse the 2 bit granularity rotation (the lowest two bits) from the
        // Coordination of Video Orientation information according to
        // https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1404
        //
        //    0 1 2 3 4 5 6 7
        //   +-+-+-+-+-+-+-+-+
        //   |0 0 0 0 C F R R|
        //   +-+-+-+-+-+-+-+-+
        match b & 0x3 {
            0b00 => VideoRotation::None,
            0b01 => VideoRotation::Clockwise90,
            0b10 => VideoRotation::Clockwise180,
            0b11 => VideoRotation::Clockwise270,
            _ => unreachable!("Two bit value is in 0..3"),
        }
    }
}

pub fn expand_seqnum(
    seqnum: TruncatedSequenceNumber,
    max_seqnum: &mut FullSequenceNumber,
) -> FullSequenceNumber {
    expand_truncated_counter(seqnum, max_seqnum, 16)
}

pub fn expand_timestamp(
    timestamp: TruncatedTimestamp,
    max_timestamp: &mut FullTimestamp,
) -> FullTimestamp {
    expand_truncated_counter(timestamp, max_timestamp, 32)
}

pub fn expand_frame_number(
    frame_number: TruncatedFrameNumber,
    max_frame_number: &mut FullFrameNumber,
) -> FullFrameNumber {
    expand_truncated_counter(frame_number, max_frame_number, 16)
}

fn is_media_payload_type(pt: PayloadType) -> bool {
    pt == OPUS_PAYLOAD_TYPE || pt == VP8_PAYLOAD_TYPE
}

fn is_audio_payload_type(pt: PayloadType) -> bool {
    pt == OPUS_PAYLOAD_TYPE
}

fn is_video_payload_type(pt: PayloadType) -> bool {
    pt == VP8_PAYLOAD_TYPE
}

fn is_padding_payload_type(pt: PayloadType) -> bool {
    pt == PADDING_PAYLOAD_TYPE
}

fn is_rtx_payload_type(pt: PayloadType) -> bool {
    is_rtxable_payload_type(from_rtx_payload_type(pt))
}

fn is_rtxable_payload_type(pt: PayloadType) -> bool {
    pt == VP8_PAYLOAD_TYPE
}

// Keeps some state to make it easier to process incoming packets.
// In particular, it:
// 1. Holds and uses the SRTP keys to encrypt/decrypt.
// 2. Parses the SRTP/SRTCP packets.
// 3. Keeps track of incoming SRTP ROCs (and expands seqnums).
// 4. Keeps track of outgoing SRTCP indices.
// 5. Keeps track of outgoing transport-cc seqnums and correlates incoming feedback.
// 6. Keeps track of incoming transport-cc seqnums and sends outgoing feedback.
// 7. Keeps a cache of recently sent packets that can be used to resend packst as RTX.
pub struct Endpoint {
    // For SRTP/SRTCP
    decrypt: KeysAndSalts,
    encrypt: KeysAndSalts,

    // For sending RTCP
    rtcp_sender_ssrc: Ssrc,
    next_outgoing_srtcp_index: u32,

    // For seqnum expanasion of incoming packets
    // and for SRTP replay attack protection
    state_by_incoming_ssrc: HashMap<Ssrc, IncomingSsrcState>,

    // For transport-cc
    tcc_receiver: tcc::Receiver,
    tcc_sender: tcc::Sender,
    max_received_tcc_seqnum: tcc::FullSequenceNumber,

    // For RTX
    rtx_sender: RtxSender,

    // For Endpoint stats
    last_stats_calculated_time: Instant,
    last_stats: Option<EndpointStats>,
}

struct IncomingSsrcState {
    max_seqnum: FullSequenceNumber,
    seqnum_reuse_detector: SequenceNumberReuseDetector,
    nack_sender: NackSender,
    rtcp_report_sender: RtcpReportSender,
}

#[derive(Debug)]
pub struct EndpointStats {
    pub remembered_packet_count: usize,
    pub remembered_packet_bytes: usize,

    /// Average RTT across all SSRCs based on last 15 seconds
    /// returns None if stat is not currently available or recent
    pub rtt_estimate: Option<Duration>,
}

impl AsRef<EndpointStats> for EndpointStats {
    fn as_ref(&self) -> &EndpointStats {
        self
    }
}

impl AsRef<Endpoint> for Endpoint {
    fn as_ref(&self) -> &Endpoint {
        self
    }
}

impl Endpoint {
    pub fn new(
        decrypt: KeysAndSalts,
        encrypt: KeysAndSalts,
        now: Instant,
        rtcp_sender_ssrc: Ssrc,
        ack_sender_ssrc: Ssrc,
    ) -> Self {
        Self {
            decrypt,
            encrypt,

            rtcp_sender_ssrc,
            next_outgoing_srtcp_index: 1,

            state_by_incoming_ssrc: HashMap::new(),

            tcc_sender: tcc::Sender::new(now),
            tcc_receiver: tcc::Receiver::new(ack_sender_ssrc, now),
            max_received_tcc_seqnum: 0,

            rtx_sender: RtxSender::new(PACKET_LIFETIME),

            last_stats: None,
            last_stats_calculated_time: now,
        }
    }

    // Returns a Packet and an optional transport-cc feedback RTCP packet that should be sent.
    // The packet's payload is also decrypted in place.
    // TODO: Use Result instead of Option.
    #[allow(clippy::type_complexity)]
    pub fn receive_rtp<'packet>(
        &mut self,
        encrypted: &'packet mut [u8],
        now: Instant,
    ) -> Option<Packet<&'packet mut [u8]>> {
        // Header::parse will log a warning for every place where it fails to parse.
        let header = Header::parse(encrypted)?;

        let tcc_seqnum = header
            .tcc_seqnum
            .map(|tcc_seqnum| tcc::expand_seqnum(tcc_seqnum, &mut self.max_received_tcc_seqnum));
        let ssrc_state = self.get_incoming_ssrc_state(header.ssrc);
        let mut max_seqnum = ssrc_state.max_seqnum;
        let seqnum_in_header = expand_seqnum(header.seqnum, &mut max_seqnum);
        let mut seqnum_reuse_detector = ssrc_state.seqnum_reuse_detector.clone();
        match seqnum_reuse_detector.remember_used(seqnum_in_header) {
            SequenceNumberReuse::UsedBefore => {
                trace!("Dropping SRTP packet because we've already seen this seqnum ({}) from this ssrc ({})", seqnum_in_header, header.ssrc);
                event!("calling.srtp.seqnum_drop.reused");
                return None;
            }
            SequenceNumberReuse::TooOldToKnow { delta } => {
                trace!(
                    "Dropping SRTP packet because it's such an old seqnum ({}) from this ssrc ({}), delta: {}",
                    seqnum_in_header,
                    header.ssrc,
                    delta
                );
                sampling_histogram!("calling.srtp.seqnum_drop.old", || delta.try_into().unwrap());
                return None;
            }
            SequenceNumberReuse::NotUsedBefore => {
                // Continue decrypting
            }
        }

        let mut incoming = Packet::new(
            &header,
            seqnum_in_header,
            None,
            false,
            tcc_seqnum,
            true,
            Some(now + PACKET_LIFETIME),
            0,
            max_seqnum == seqnum_in_header,
            encrypted,
        );

        let decrypt_failed = incoming
            .decrypt_in_place(&self.decrypt.rtp.key, &self.decrypt.rtp.salt)
            .is_none();
        if decrypt_failed {
            event!("calling.rtp.decryption_failed");
            debug!(
                "Invalid RTP: decryption failed; ssrc: {}, seqnum: {}, pt: {}, payload_range: {:?}",
                incoming.ssrc(),
                incoming.seqnum(),
                incoming.payload_type(),
                incoming.payload_range(),
            );
            return None;
        }

        // Commit state changes
        let ssrc_state = self.get_incoming_ssrc_state_mut(header.ssrc);
        ssrc_state.max_seqnum = max_seqnum;
        ssrc_state.seqnum_reuse_detector = seqnum_reuse_detector;

        if header.has_padding {
            incoming.padding_byte_count = incoming.payload()[incoming.payload().len() - 1];
        }

        // We have to do this after decrypting to get the seqnum in the payload.
        if is_rtx_payload_type(header.payload_type)
            // Padding packets don't have a seqnum in their payload.
            && (incoming.padding_byte_count as usize) < incoming.payload().len()
        {
            let original_ssrc = from_rtx_ssrc(header.ssrc);
            let original_seqnum = if let Some((seqnum_in_payload, _)) = read_u16(incoming.payload())
            {
                seqnum_in_payload
            } else {
                warn!(
                    "Invalid RTP: no seqnum in payload of RTX packet; payload len: {}",
                    incoming.payload_range_in_header.len()
                );
                return None;
            };
            let original_ssrc_state = self.get_incoming_ssrc_state_mut(original_ssrc);
            let original_seqnum =
                expand_seqnum(original_seqnum, &mut original_ssrc_state.max_seqnum);
            // This makes the Packet appear to be an RTX packet for the rest of the processing.
            incoming.seqnum_in_payload = Some(original_seqnum);
            incoming.is_max_seqnum = original_seqnum == original_ssrc_state.max_seqnum;

            let drop = match original_ssrc_state
                .seqnum_reuse_detector
                .remember_used(original_seqnum)
            {
                SequenceNumberReuse::UsedBefore => {
                    trace!("Dropping SRTP packet because we've already seen this seqnum ({}) from this ssrc ({}) RTXed as {} {}", original_seqnum, original_ssrc, seqnum_in_header, header.ssrc);
                    event!("calling.srtp.seqnum_drop.reused_rtx");
                    true
                }
                SequenceNumberReuse::TooOldToKnow { delta } => {
                    trace!(
                        "Dropping SRTP packet because it's such an old seqnum ({}) from this ssrc ({}), delta: {} RTXed as {} {}",
                        original_seqnum,
                        original_ssrc,
                        delta,
                        seqnum_in_header,
                        header.ssrc,
                    );
                    sampling_histogram!("calling.srtp.seqnum_drop.old_rtx", || delta
                        .try_into()
                        .unwrap());
                    true
                }
                SequenceNumberReuse::NotUsedBefore => false,
            };

            if drop {
                if let Some(tcc_seqnum) = incoming.tcc_seqnum {
                    self.tcc_receiver.remember_received(tcc_seqnum, now);
                }
                return None;
            }
        }

        // We have to do this after "unwrapping" the RTX packet
        // otherwise, we'll not remember we received RTX packets and we'll
        // keep NACKing.
        if is_rtxable_payload_type(incoming.payload_type()) {
            let ssrc_state = self.get_incoming_ssrc_state_mut(incoming.ssrc());
            // NACKs are delayed by a bit and sent in tick() to avoid
            // sending too many when there is a small amount of jitter.
            // And it makes it easy to resend them.
            ssrc_state.nack_sender.remember_received(incoming.seqnum());
        }

        if is_media_payload_type(incoming.payload_type()) {
            let ssrc_state = self.get_incoming_ssrc_state_mut(incoming.ssrc());

            ssrc_state.rtcp_report_sender.remember_received(
                incoming.seqnum(),
                incoming.payload_type(),
                incoming.timestamp,
                now,
            );
        }

        if let Some(tcc_seqnum) = incoming.tcc_seqnum {
            self.tcc_receiver.remember_received(tcc_seqnum, now);
        }

        Some(incoming)
    }

    fn get_incoming_ssrc_state_mut(&mut self, ssrc: Ssrc) -> &mut IncomingSsrcState {
        self.state_by_incoming_ssrc
            .entry(ssrc)
            .or_insert(IncomingSsrcState {
                max_seqnum: 0,
                seqnum_reuse_detector: SequenceNumberReuseDetector::default(),
                // A 1KB RTCP payload with 4 bytes each would allow only 250
                // in the worst case scenario.
                nack_sender: NackSender::new(250),
                rtcp_report_sender: RtcpReportSender::new(),
            })
    }

    fn get_incoming_ssrc_state(&mut self, ssrc: Ssrc) -> &IncomingSsrcState {
        self.get_incoming_ssrc_state_mut(ssrc)
    }

    // Returns parsed and decrypted RTCP, and also processes transport-cc feedback based on
    // previously sent packets (if they had transport-cc seqnums).
    // Also decrypts the packet in place.
    // TODO: Use Result instead of Option.
    pub fn receive_rtcp(
        &mut self,
        encrypted: &mut [u8],
        now: Instant,
    ) -> Option<ProcessedControlPacket> {
        let incoming = ControlPacket::parse_and_decrypt_in_place(
            encrypted,
            &self.decrypt.rtcp.key,
            &self.decrypt.rtcp.salt,
        )?;

        let mut acks = vec![];
        if !incoming.tcc_feedbacks.is_empty() {
            acks = self
                .tcc_sender
                .process_feedback_and_correlate_acks(incoming.tcc_feedbacks.into_iter(), now);
        }
        for sender_report in incoming.sender_reports {
            self.get_incoming_ssrc_state_mut(sender_report.ssrc())
                .rtcp_report_sender
                .remember_received_sender_report(sender_report, now);
        }
        self.remember_receiver_reports(incoming.receiver_reports, now);

        Some(ProcessedControlPacket {
            key_frame_requests: incoming.key_frame_requests,
            acks,
            nacks: incoming.nacks,
        })
    }

    // Mutates the seqnum and transport-cc seqnum and encrypts the packet in place.
    // Also remembers the transport-cc seqnum for receiving and processing packets later.
    // TODO: Use Result instead of Option.
    pub fn send_rtp(&mut self, incoming: Packet<Vec<u8>>, now: Instant) -> Option<Packet<Vec<u8>>> {
        let mut outgoing = incoming;
        if outgoing.is_rtx() {
            outgoing.set_seqnum_in_header(self.rtx_sender.increment_seqnum(outgoing.ssrc_in_header))
        }
        outgoing.set_tcc_seqnum_in_header_if_present(|| self.tcc_sender.increment_seqnum());
        self.encrypt_and_send_rtp(outgoing, now)
    }

    pub fn resend_rtp(
        &mut self,
        ssrc: Ssrc,
        seqnum: TruncatedSequenceNumber,
        now: Instant,
    ) -> Option<Packet<Vec<u8>>> {
        let tcc_sender = &mut self.tcc_sender;
        let rtx_sender = &mut self.rtx_sender;
        let rtx = rtx_sender.resend_as_rtx(ssrc, seqnum, now, || tcc_sender.increment_seqnum())?;
        self.encrypt_and_send_rtp(rtx, now)
    }

    pub fn mark_as_sent(&mut self, ssrc: Ssrc, seqnum: TruncatedSequenceNumber) {
        self.rtx_sender.mark_as_sent(ssrc, seqnum);
    }

    pub fn send_padding(&mut self, rtx_ssrc: Ssrc, now: Instant) -> Option<Packet<Vec<u8>>> {
        let tcc_seqnum = self.tcc_sender.increment_seqnum();
        let padding = self.rtx_sender.send_padding(rtx_ssrc, tcc_seqnum);
        self.encrypt_and_send_rtp(padding, now)
    }

    fn encrypt_and_send_rtp(
        &mut self,
        mut outgoing: Packet<Vec<u8>>,
        now: Instant,
    ) -> Option<Packet<Vec<u8>>> {
        // Remember the packet sent for RTX before we encrypt it.
        if is_rtxable_payload_type(outgoing.payload_type()) {
            self.rtx_sender.remember_sent(outgoing.to_owned(), now);
        }
        // Don't remember the packet sent for TCC until after we actually send it.
        // (see remember_sent_for_tcc)
        outgoing.encrypt_in_place(&self.encrypt.rtp.key, &self.encrypt.rtp.salt)?;
        Some(outgoing)
    }

    pub fn remember_sent(&mut self, outgoing: &Packet<Vec<u8>>, now: Instant) {
        self.remember_sent_for_tcc(outgoing, now);
        self.remember_sent_for_reports(outgoing, now);
    }

    fn remember_sent_for_tcc(&mut self, outgoing: &Packet<Vec<u8>>, now: Instant) {
        if let Some(tcc_seqnum) = outgoing.tcc_seqnum {
            self.tcc_sender
                .remember_sent(tcc_seqnum, outgoing.size(), now);
        }
    }

    // counts packets/bytes and remembers timestamps for sender reports
    // does not consider RTX packets or Client <-> SFU data packets
    pub fn remember_sent_for_reports(&mut self, outgoing: &Packet<Vec<u8>>, now: Instant) {
        if outgoing.is_rtx() || outgoing.is_data() {
            return;
        }

        self.get_incoming_ssrc_state_mut(outgoing.ssrc())
            .rtcp_report_sender
            .remember_sent(outgoing, now);
    }

    fn remember_receiver_reports(&mut self, reports: Vec<ReceiverReport>, now: Instant) {
        for rr in reports {
            if !self.state_by_incoming_ssrc.contains_key(&rr.ssrc()) {
                continue;
            }

            for block in rr.report_blocks {
                if !self.state_by_incoming_ssrc.contains_key(&block.ssrc) {
                    continue;
                }

                self.get_incoming_ssrc_state_mut(block.ssrc)
                    .rtcp_report_sender
                    .remember_report_block(block, now);
            }
        }
    }

    // Returns serialized RTCP packets containing ACKs, not just ACK payloads.
    // The SSRC can be any SSRC the sender uses to send TCC seqnums
    #[allow(clippy::needless_lifetimes)]
    pub fn send_acks<'endpoint>(&'endpoint mut self) -> impl Iterator<Item = Vec<u8>> + 'endpoint {
        time_scope_us!("calling.rtp.send_acks");

        let rtcp_sender_ssrc = self.rtcp_sender_ssrc;
        let next_outgoing_srtcp_index = &mut self.next_outgoing_srtcp_index;
        let key = &self.encrypt.rtcp.key;
        let salt = &self.encrypt.rtcp.salt;
        self.tcc_receiver.send_acks().filter_map(move |payload| {
            Self::send_rtcp_and_increment_index(
                RTCP_TYPE_GENERIC_FEEDBACK,
                RTCP_FORMAT_TRANSPORT_CC,
                false,
                rtcp_sender_ssrc,
                payload,
                next_outgoing_srtcp_index,
                key,
                salt,
            )
        })
    }

    // Returns full nack packets
    #[allow(clippy::needless_lifetimes)]
    pub fn send_nacks<'endpoint>(
        &'endpoint mut self,
        now: Instant,
        rtt: Duration,
    ) -> impl Iterator<Item = Vec<u8>> + 'endpoint {
        time_scope_us!("calling.rtp.send_nacks");

        // We have to get all of these refs up front to avoid lifetime issues.
        let state_by_incoming_ssrc = &mut self.state_by_incoming_ssrc;
        let rtcp_sender_ssrc = self.rtcp_sender_ssrc;
        let next_outgoing_srtcp_index = &mut self.next_outgoing_srtcp_index;
        let key = &self.encrypt.rtcp.key;
        let salt = &self.encrypt.rtcp.salt;

        state_by_incoming_ssrc
            .iter_mut()
            .filter_map(move |(ssrc, state)| {
                let seqnums = state.nack_sender.send_nacks(now, rtt)?;
                let payload = write_nack(*ssrc, seqnums);
                Self::send_rtcp_and_increment_index(
                    RTCP_TYPE_GENERIC_FEEDBACK,
                    RTCP_FORMAT_NACK,
                    false,
                    rtcp_sender_ssrc,
                    payload,
                    next_outgoing_srtcp_index,
                    key,
                    salt,
                )
            })
    }

    // Returns a new, encrypted RTCP packet for a PLI (keyframe request).
    // TODO: Use Result instead of Option.
    pub fn send_pli(&mut self, pli_ssrc: Ssrc) -> Option<Vec<u8>> {
        self.send_rtcp(
            RTCP_TYPE_SPECIFIC_FEEDBACK,
            RTCP_FORMAT_PLI,
            false,
            pli_ssrc,
        )
    }

    /// WebRTC deviates from RFC 3550's definition of a compound packet.
    /// According to spec, a compound packet should consist of a 4 byte header, an SR or RR,
    /// an SDES, and report blocks.
    /// However, WebRTC treats compound packets like concantenated RTCP packets. For example, we can
    /// send (Header-1, SR-1, Header-2, RR-1, Header-3, SR-2) as a valid RTCP packet.
    /// https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/modules/rtp_rtcp/source/rtcp_receiver.cc;l=380;drc=2017cd8a8925f180257662f78eaf9eb93e8e394d
    /// Since this can only include SR and RRs, there is no padding.
    pub fn send_rtcp_report(&mut self, now: Instant) -> Option<Vec<u8>> {
        let mut report_buffer = self.create_buffer_for_rtcp_reports()?;
        let mut is_first = true;
        let mut first_ssrc = 0u32;
        let mut block_buffer = Vec::with_capacity(ReceiverReport::MIN_LENGTH + ReportBlock::LENGTH);
        for (ssrc, state) in &mut self.state_by_incoming_ssrc {
            block_buffer.clear();
            let Some((payload_type, block_count, report_length)) = state
                .rtcp_report_sender
                .write_report_block_in_place(*ssrc, now, &mut block_buffer)
            else {
                continue;
            };

            let header = RtcpHeader::new(
                false,
                block_count,
                payload_type,
                (report_length >> 2) as u16,
            );

            if is_first {
                first_ssrc = *ssrc;
                is_first = false;
            }

            header.write(&mut report_buffer);
            block_buffer[..report_length].write(&mut report_buffer);
        }

        report_buffer.resize(report_buffer.capacity(), 0);
        self.encrypt_rtcp_packet_and_increment_index(first_ssrc, report_buffer)
    }

    // Returns a new, encrypted RTCP packet.
    // TODO: Use Result instead of Option.
    fn send_rtcp(
        &mut self,
        pt: u8,
        count_or_format: u8,
        is_padded: bool,
        payload: impl Writer,
    ) -> Option<Vec<u8>> {
        Self::send_rtcp_and_increment_index(
            pt,
            count_or_format,
            is_padded,
            self.rtcp_sender_ssrc,
            payload,
            &mut self.next_outgoing_srtcp_index,
            &self.encrypt.rtcp.key,
            &self.encrypt.rtcp.salt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send_rtcp_and_increment_index(
        pt: u8,
        count_or_format: u8,
        is_padded: bool,
        sender_ssrc: Ssrc,
        payload: impl Writer,
        next_outgoing_srtcp_index: &mut u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        let serialized = ControlPacket::serialize_and_encrypt(
            pt,
            count_or_format,
            is_padded,
            sender_ssrc,
            payload,
            *next_outgoing_srtcp_index,
            key,
            salt,
        )?;
        *next_outgoing_srtcp_index += 1;
        Some(serialized)
    }

    fn encrypt_rtcp_packet_and_increment_index(
        &mut self,
        sender_ssrc: Ssrc,
        packet: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let encrypted = ControlPacket::encrypt(
            packet,
            sender_ssrc,
            self.next_outgoing_srtcp_index,
            &self.encrypt.rtcp.key,
            &self.encrypt.rtcp.salt,
        )?;
        self.next_outgoing_srtcp_index += 1;
        Some(encrypted)
    }

    pub fn get_or_update_stats(&mut self, now: Instant) -> &EndpointStats {
        // destructuring here causes wrong lifetimes (https://github.com/rust-lang/rust/issues/54663)
        if self.last_stats.is_some()
            && now.saturating_duration_since(self.last_stats_calculated_time)
                < RTT_ESTIMATE_AGE_LIMIT
        {
            return self.last_stats.as_ref().unwrap();
        }

        self.update_stats(now)
    }

    pub fn update_stats(&mut self, now: Instant) -> &EndpointStats {
        let (remembered_packet_count, remembered_packet_bytes) =
            self.rtx_sender.remembered_packet_stats();

        self.last_stats = Some(EndpointStats {
            remembered_packet_count,
            remembered_packet_bytes,
            rtt_estimate: self.calculate_rtt(now),
        });
        self.last_stats_calculated_time = now;

        self.last_stats.as_ref().unwrap()
    }

    /// Average RTT estimates across all SSRCS that are not too old.
    /// If all the estimates are old, then return None.
    fn calculate_rtt(&self, now: Instant) -> Option<Duration> {
        let mut count = 0;
        let mut sum = Duration::from_secs(0);

        for ssrc_state in self.state_by_incoming_ssrc.values() {
            if let Some((estimate, last_updated)) = ssrc_state.rtcp_report_sender.rtt_estimate() {
                if now.saturating_duration_since(last_updated) >= RTT_ESTIMATE_AGE_LIMIT {
                    continue;
                }

                sum += estimate;
                count += 1;
            }
        }

        if count != 0 {
            Some(sum / count)
        } else {
            None
        }
    }

    /// returns
    /// - a buffer that can hold all the reports that are ready, SRTP Tag, and SRTP Footer.
    ///     There is NO possibility of padding since the sizes are all multiples of four.
    /// - the number of reports to serialize
    fn create_buffer_for_rtcp_reports(&self) -> Option<Vec<u8>> {
        const RECEIVER_REPORT_MIN_LENGTH: usize = ReceiverReport::MIN_LENGTH + ReportBlock::LENGTH;
        let expected_report_size = self.state_by_incoming_ssrc.iter().fold(
            0usize,
            |total_bytes, (ssrc, state)| match state.rtcp_report_sender.rtcp_report_payload_type() {
                Some(RTCP_TYPE_SENDER_REPORT) => total_bytes + SenderReport::MIN_LENGTH,
                Some(RTCP_TYPE_RECEIVER_REPORT) => total_bytes + RECEIVER_REPORT_MIN_LENGTH,
                Some(unknown) => {
                    warn!("Unexpected report type `{}` returned by {}", unknown, ssrc);
                    total_bytes
                }
                None => total_bytes,
            },
        );

        if expected_report_size == 0 {
            None
        } else {
            Some(Vec::with_capacity(
                expected_report_size + SRTP_AUTH_TAG_LEN + SRTCP_FOOTER_LEN,
            ))
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum SequenceNumberReuse {
    UsedBefore,
    NotUsedBefore,
    TooOldToKnow { delta: u64 },
}

/// Keeps track of a sliding window of history of whether
/// or not we've seen a particular sequence number yet.
// We keep a history of 128 sequence numbers.
// That's what libsrtp/WebRTC uses, which means it's probably
// enough.
#[derive(Clone, Default, Debug)]
struct SequenceNumberReuseDetector {
    /// Everything before this seqnuence number is too old to
    /// know whether or not we have seen it.
    // We increase this as sequence numbers increase.
    first: FullSequenceNumber,
    /// MSB = first/oldest; LSB = last/newest
    // We shift this to the left as sequence numbers increase.
    mask: u128,
}

impl SequenceNumberReuseDetector {
    // Because we're using a u128.
    const MASK_SIZE: u8 = 128;
    // It's common to want to reference the last bit in the mask, so we make this
    // convenient constant.
    const LAST_RELATIVE_TO_FIRST: u8 = Self::MASK_SIZE - 1;

    /// Update the history and return whether or not the sequence number is already
    /// used.  It's possible it's too old to know.
    fn remember_used(&mut self, seqnum: FullSequenceNumber) -> SequenceNumberReuse {
        if seqnum < self.first {
            // seqnum is before the first in the history, so we can't know if it's been used before.
            return SequenceNumberReuse::TooOldToKnow {
                delta: self.first - seqnum,
            };
        }
        let last = self
            .first
            .saturating_add(Self::LAST_RELATIVE_TO_FIRST as u64);

        if seqnum > last {
            // seqnum is after the last, so shift the history left
            // (losing the first/oldest values) such that
            // seqnum becomes the last/newest.
            let seqnum_relative_to_last = seqnum - last;
            self.first += seqnum_relative_to_last;
            // Basically a saturating shl
            let shifted_mask = if seqnum_relative_to_last > (Self::LAST_RELATIVE_TO_FIRST as u64) {
                0
            } else {
                self.mask << seqnum_relative_to_last
            };
            self.mask = shifted_mask.set_ms_bit(Self::LAST_RELATIVE_TO_FIRST);
            return SequenceNumberReuse::NotUsedBefore;
        }

        // seqnum is neither before the first nor after the last,
        // so we can just flip a bit to record that it's used.
        let seqnum_relative_to_first = (seqnum - self.first) as u8;
        let previously_used = self.mask.ms_bit(seqnum_relative_to_first);
        self.mask = self.mask.set_ms_bit(seqnum_relative_to_first);
        if previously_used {
            SequenceNumberReuse::UsedBefore
        } else {
            SequenceNumberReuse::NotUsedBefore
        }
    }
}

#[cfg(fuzzing)]
pub mod fuzz {
    use super::*;

    fn fuzzing_key() -> Key {
        [0u8; SRTP_KEY_LEN].into()
    }

    pub fn parse_and_forward_rtp_for_fuzzing(data: Vec<u8>) -> Option<Vec<u8>> {
        let header = Header::parse(&data)?;

        let mut incoming = Packet::new(
            &header,
            Default::default(),
            None,
            false,
            Default::default(),
            true,
            None,
            0,
            false,
            data,
        );

        if header.has_padding {
            incoming.padding_byte_count = incoming.payload()[incoming.payload().len() - 1];
        }

        let _ = incoming.decrypt_in_place(&fuzzing_key(), &Default::default());
        incoming.encrypted = false;

        if is_rtx_payload_type(header.payload_type) {
            let original_seqnum = if let Some((seqnum_in_payload, _)) = read_u16(incoming.payload())
            {
                seqnum_in_payload
            } else {
                return None;
            };
            // This makes the Packet appear to be an RTX packet for the rest of the processing.
            incoming.seqnum_in_payload = Some(original_seqnum.into());
        }

        let mut outgoing = incoming;
        if outgoing.is_rtx() {
            outgoing.set_seqnum_in_payload(Default::default());
        }
        outgoing.set_ssrc_in_header(Default::default());
        outgoing.set_seqnum_in_header(Default::default());
        outgoing.set_timestamp_in_header(Default::default());
        outgoing.set_tcc_seqnum_in_header_if_present(Default::default);
        outgoing.encrypt_in_place(&fuzzing_key(), &Default::default());
        Some(outgoing.into_serialized())
    }

    pub fn parse_rtcp(buffer: &mut [u8]) {
        ControlPacket::parse_and_decrypt_in_place(buffer, &fuzzing_key(), &Default::default());
    }
}

#[cfg(test)]
mod test {
    use std::borrow::BorrowMut;

    use calling_common::DataSize;

    use super::*;

    const VP8_RTX_PAYLOAD_TYPE: PayloadType = 118;

    #[test]
    fn test_endpoint_nack_rtx() {
        let srtp_master_key_material = zeroize::Zeroizing::new([0u8; 56]);
        let (sender_key, receiver_key) =
            KeysAndSalts::derive_client_and_server_from_master_key_material(
                &srtp_master_key_material,
            );
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let mut sender = Endpoint::new(receiver_key.clone(), sender_key.clone(), now, 1, 2);
        let mut receiver = Endpoint::new(sender_key.clone(), receiver_key, now, 1, 2);

        let mut sent1 = sender
            .send_rtp(
                Packet::with_empty_tag(
                    VP8_PAYLOAD_TYPE,
                    1,
                    2,
                    3,
                    Some(0),
                    Some(at(10)),
                    &[4, 5, 6],
                ),
                at(10),
            )
            .unwrap();
        let received1 = receiver
            .receive_rtp(sent1.serialized.borrow_mut(), at(10))
            .unwrap();
        sent1.encrypted = false; // Got decrypted by the above
        let received1 = received1.to_owned();
        assert_eq!(sent1, received1);
        let empty: Vec<Vec<u8>> = vec![];
        assert_eq!(
            empty,
            receiver
                .send_nacks(at(20), Duration::from_millis(200))
                .collect::<Vec<_>>()
        );
        assert_eq!(Some(1), sent1.tcc_seqnum);

        let mut sent2 = sender
            .send_rtp(
                Packet::with_empty_tag(
                    VP8_PAYLOAD_TYPE,
                    2,
                    4,
                    3,
                    Some(0),
                    Some(at(20)),
                    &[5, 6, 7],
                ),
                at(20),
            )
            .unwrap();
        // Simulate never received
        sent2.decrypt_in_place(&sender_key.rtp.key, &sender_key.rtp.salt);
        assert_eq!(&[5, 6, 7], sent2.payload());
        assert_eq!(Some(2), sent2.tcc_seqnum);

        let mut sent3 = sender
            .send_rtp(
                Packet::with_empty_tag(
                    VP8_PAYLOAD_TYPE,
                    3,
                    6,
                    3,
                    Some(0),
                    Some(at(20)),
                    &[6, 7, 8],
                ),
                at(30),
            )
            .unwrap();
        let received3 = receiver
            .receive_rtp(sent3.serialized.borrow_mut(), at(20))
            .unwrap();
        sent3.encrypted = false; // Got decrypted by the above
        let received3 = received3.to_owned();
        assert_eq!(sent3, received3);
        assert_eq!(Some(3), sent3.tcc_seqnum);
        let mut nacks: Vec<Vec<u8>> = receiver
            .send_nacks(at(40), Duration::from_millis(200))
            .collect();
        assert_eq!(1, nacks.len());
        assert_eq!(
            Some(ProcessedControlPacket {
                key_frame_requests: vec![],
                acks: vec![],
                nacks: vec![Nack {
                    ssrc: 3,
                    seqnums: vec![2],
                }],
            }),
            sender.receive_rtcp(&mut nacks[0], at(50))
        );

        let mut resent2 = sender.resend_rtp(3, 2, at(50)).unwrap();
        let received2 = receiver
            .receive_rtp(resent2.serialized.borrow_mut(), at(60))
            .unwrap();
        resent2.encrypted = false; // Got decrypted by the above
        let mut received2 = received2.to_owned();
        received2.deadline = resent2.deadline; // tweak deadline to match
        received2.pending_retransmission = true; // tweak to match
        assert_eq!(resent2, received2);
        assert_eq!(sent2.payload_type(), resent2.payload_type());
        assert_eq!(VP8_RTX_PAYLOAD_TYPE, resent2.payload_type_in_header);
        assert_eq!(sent2.ssrc(), resent2.ssrc());
        assert_eq!(4, resent2.ssrc_in_header);
        assert_eq!(sent2.seqnum(), resent2.seqnum());
        assert_eq!(1, resent2.seqnum_in_header);
        assert_eq!(sent2.timestamp, resent2.timestamp);
        assert_eq!(sent2.payload(), resent2.payload());
        assert_eq!(Some(4), resent2.tcc_seqnum);
        // Give enough time to retransmit a NACK but make sure we don't retransmit
        // because we've now received it.
        assert_eq!(
            empty,
            receiver
                .send_nacks(at(440), Duration::from_millis(200))
                .collect::<Vec<_>>()
        );

        let mut forwarded2 = receiver
            .send_rtp(sent2.rewrite(33, 22, 44), at(70))
            .unwrap();
        let forwarded2 = sender
            .receive_rtp(forwarded2.serialized.borrow_mut(), at(80))
            .unwrap();
        let forwarded2 = forwarded2.to_owned();
        assert_eq!(sent2.payload_type(), forwarded2.payload_type());
        assert_eq!(33, forwarded2.ssrc());
        assert_eq!(22, forwarded2.seqnum());
        assert_eq!(44, forwarded2.timestamp);
        assert_eq!(sent2.payload(), forwarded2.payload());
        assert_eq!(Some(1), forwarded2.tcc_seqnum);

        // RTX to RTX
        let mut reforwarded2 = receiver
            .send_rtp(resent2.rewrite(33, 22, 44), at(70))
            .unwrap();
        assert_eq!(1, reforwarded2.seqnum_in_header);
        assert_eq!(Some(22), reforwarded2.seqnum_in_payload);
        let reforwarded2 = sender.receive_rtp(reforwarded2.serialized.borrow_mut(), at(90));
        assert_eq!(reforwarded2, None);

        // Padding
        let mut padding = sender.send_padding(4, at(100)).unwrap();
        let received_padding = receiver
            .receive_rtp(padding.serialized.borrow_mut(), at(110))
            .unwrap();
        assert_eq!(99, received_padding.payload_type());
        assert_eq!(99, received_padding.payload_type_in_header);
        assert_eq!(4, received_padding.ssrc());
        assert_eq!(4, received_padding.ssrc_in_header);
        assert_eq!(2, received_padding.seqnum_in_header);
        assert_eq!(2, received_padding.seqnum());
        assert_eq!(DataSize::from_bytes(1172), received_padding.size());
    }

    #[test]
    fn test_seqnum_reuse_detector() {
        use SequenceNumberReuse::*;

        let mut detector = SequenceNumberReuseDetector::default();

        assert_eq!(NotUsedBefore, detector.remember_used(1));
        assert_eq!(UsedBefore, detector.remember_used(1));

        assert_eq!(NotUsedBefore, detector.remember_used(3));
        assert_eq!(UsedBefore, detector.remember_used(1));
        assert_eq!(UsedBefore, detector.remember_used(3));

        assert_eq!(NotUsedBefore, detector.remember_used(2));
        assert_eq!(UsedBefore, detector.remember_used(1));
        assert_eq!(UsedBefore, detector.remember_used(2));
        assert_eq!(UsedBefore, detector.remember_used(3));

        assert_eq!(NotUsedBefore, detector.remember_used(132));
        assert_eq!(UsedBefore, detector.remember_used(132));
        let expected_first = 132 - 127;
        assert_eq!(
            TooOldToKnow {
                delta: expected_first - 1
            },
            detector.remember_used(1)
        );
        assert_eq!(
            TooOldToKnow {
                delta: expected_first - 2
            },
            detector.remember_used(2)
        );
        assert_eq!(
            TooOldToKnow {
                delta: expected_first - 3
            },
            detector.remember_used(3)
        );
        assert_eq!(
            TooOldToKnow {
                delta: expected_first - 4
            },
            detector.remember_used(4)
        );

        assert_eq!(NotUsedBefore, detector.remember_used(5));
        assert_eq!(UsedBefore, detector.remember_used(5));
        assert_eq!(UsedBefore, detector.remember_used(132));

        assert_eq!(NotUsedBefore, detector.remember_used(100001));
        assert_eq!(NotUsedBefore, detector.remember_used(100000));
        assert_eq!(UsedBefore, detector.remember_used(100001));
        assert_eq!(UsedBefore, detector.remember_used(100000));
        let expected_first = 100001 - 127;
        assert_eq!(
            TooOldToKnow {
                delta: expected_first - 132
            },
            detector.remember_used(132)
        );
    }

    #[test]
    fn test_drop_incoming_rtp_when_seqnum_reused() {
        let srtp_master_key_material = zeroize::Zeroizing::new([0u8; 56]);
        let (sender_key, receiver_key) =
            KeysAndSalts::derive_client_and_server_from_master_key_material(
                &srtp_master_key_material,
            );
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let mut sender = Endpoint::new(receiver_key.clone(), sender_key.clone(), now, 1, 2);
        let mut receiver = Endpoint::new(sender_key, receiver_key, now, 1, 2);

        let mut sent1a = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 1, 2, 3, Some(0), None, &[4, 5, 6]),
                at(10),
            )
            .unwrap();
        let mut sent1b = sent1a.clone();
        let mut sent1c = sent1a.clone();
        let mut sent2a = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 2, 2, 3, Some(0), None, &[4, 5, 6]),
                at(10),
            )
            .unwrap();
        let mut sent2b = sent2a.clone();
        let mut sent2c = sent2a.clone();
        let mut sent200a = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 200, 2, 3, Some(0), None, &[4, 5, 6]),
                at(10),
            )
            .unwrap();
        let mut sent200b = sent200a.clone();

        let received1a = receiver.receive_rtp(sent1a.serialized.borrow_mut(), at(10));
        let received1b = receiver.receive_rtp(sent1b.serialized.borrow_mut(), at(10));
        let received2a = receiver.receive_rtp(sent2a.serialized.borrow_mut(), at(10));
        let received2b = receiver.receive_rtp(sent2b.serialized.borrow_mut(), at(10));
        let received200a = receiver.receive_rtp(sent200a.serialized.borrow_mut(), at(10));
        let received200b = receiver.receive_rtp(sent200b.serialized.borrow_mut(), at(10));
        let received1c = receiver.receive_rtp(sent1c.serialized.borrow_mut(), at(10));
        let received2c = receiver.receive_rtp(sent2c.serialized.borrow_mut(), at(10));

        assert!(received1a.is_some());
        assert!(received1b.is_none());
        assert!(received2a.is_some());
        assert!(received2b.is_none());
        assert!(received200a.is_some());
        assert!(received200b.is_none());
        assert!(received1c.is_none());
        assert!(received2c.is_none());
    }
}
