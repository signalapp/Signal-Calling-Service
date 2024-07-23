//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{anyhow, bail, Result};
use calling_common::PixelSize;
use std::{
    borrow::{Borrow, BorrowMut},
    convert::TryFrom,
    ops::Range,
};

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes_gcm::{AeadInPlace, Aes128Gcm};
use calling_common::{
    parse_u16, parse_u32, round_up_to_multiple_of, CheckedSplitAt, DataSize, Instant, Writer,
};
use log::*;

use crate::audio;
use crate::rtp::tcc;

use super::{
    from_rtx_payload_type, from_rtx_ssrc, is_audio_payload_type, is_padding_payload_type,
    is_video_payload_type, srtp::*, to_rtx_payload_type, to_rtx_ssrc, types::*, VideoRotation,
    PACKET_LIFETIME, VERSION, VP8_PAYLOAD_TYPE,
};

const RTP_MIN_HEADER_LEN: usize = 12;
pub const RTP_PAYLOAD_TYPE_OFFSET: usize = 1;
const RTP_SEQNUM_RANGE: Range<usize> = 2..4;
const RTP_TIMESTAMP_RANGE: Range<usize> = 4..8;
const RTP_SSRC_RANGE: Range<usize> = 8..12;
const RTP_EXTENSIONS_HEADER_LEN: usize = 4;
const RTP_ONE_BYTE_EXTENSIONS_PROFILE: u16 = 0xBEDE;
const RTP_TWO_BYTE_EXTENSIONS_PROFILE: u16 = 0x1000;
const RTP_EXT_ID_TCC_SEQNUM: u8 = 1; // Really u4
const RTP_EXT_ID_VIDEO_ORIENTATION: u8 = 4; // Really u4
const RTP_EXT_ID_AUDIO_LEVEL: u8 = 5; // Really u4
const RTP_EXT_ID_DEPENDENCY_DESCRIPTOR: u8 = 6;
const RTP_DEPENDENCY_DESCRIPTOR_MIN_LEN: usize = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HeaderExtensionsProfile {
    /// https://www.rfc-editor.org/rfc/rfc8285#section-4.2
    OneByte,
    /// https://www.rfc-editor.org/rfc/rfc8285#section-4.3
    TwoByte,
}

impl TryFrom<u16> for HeaderExtensionsProfile {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value == RTP_ONE_BYTE_EXTENSIONS_PROFILE {
            Ok(Self::OneByte)
        } else if value & 0xFFF0 == RTP_TWO_BYTE_EXTENSIONS_PROFILE {
            Ok(Self::TwoByte)
        } else {
            Err(anyhow!(
                "not using 1-byte or 2-byte extensions; profile = 0x{:x}",
                value
            ))
        }
    }
}

impl HeaderExtensionsProfile {
    fn len(&self) -> usize {
        match self {
            HeaderExtensionsProfile::OneByte => 1,
            HeaderExtensionsProfile::TwoByte => 2,
        }
    }
}

// pub for tests
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    marker: bool,
    pub has_padding: bool,
    pub payload_type: PayloadType,
    pub(super) seqnum: TruncatedSequenceNumber,
    timestamp: TruncatedTimestamp,
    pub ssrc: Ssrc,
    video_rotation: Option<VideoRotation>,
    audio_level: Option<audio::Level>,
    pub(super) tcc_seqnum: Option<TruncatedSequenceNumber>,
    // We parse the range as well in order to replace it easily.
    tcc_seqnum_range: Option<Range<usize>>,
    // The payload start is the same as the header len.
    // The payload end isn't technically part of the "Header",
    // but it's convenient to parse at the same time.
    pub payload_range: Range<usize>,
    // We store the range as well in order to replace the frame number easily.
    dependency_descriptor: Option<(DependencyDescriptor, Range<usize>)>,
}

impl Header {
    // pub for tests
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let (main_header, csrcs_extensions_payload_tag) =
            packet.checked_split_at(RTP_MIN_HEADER_LEN)?;

        let has_padding = (main_header[0] & 0b0010_0000) > 0;
        let has_extensions = ((main_header[0] & 0b0001_0000) >> 4) > 0;
        let csrc_count = main_header[0] & 0b0000_1111;
        let payload_type = main_header[RTP_PAYLOAD_TYPE_OFFSET] & 0b01111111;
        let marker = ((main_header[RTP_PAYLOAD_TYPE_OFFSET] & 0b1000_0000) >> 7) != 0;
        let seqnum = parse_u16(&main_header[RTP_SEQNUM_RANGE.clone()]);
        let timestamp = parse_u32(&main_header[RTP_TIMESTAMP_RANGE.clone()]);
        let ssrc = parse_u32(&main_header[RTP_SSRC_RANGE.clone()]);

        let csrcs_len = 4 * csrc_count as usize;
        let (_csrcs, extension_payload_tag) =
            csrcs_extensions_payload_tag.checked_split_at(csrcs_len)?;

        let mut tcc_seqnum = None;
        let mut tcc_seqnum_range = None;
        let mut video_rotation = None;
        let mut audio_level = None;
        let mut dependency_descriptor = None;

        let extensions_start = RTP_MIN_HEADER_LEN + csrcs_len;
        let mut payload_start = extensions_start;
        if has_extensions {
            let (extensions_header, extension_payload_tag) =
                extension_payload_tag.checked_split_at(RTP_EXTENSIONS_HEADER_LEN)?;
            let extensions_profile = parse_u16(&extensions_header[0..2]);
            let extensions_len = (parse_u16(&extensions_header[2..4]) as usize) * 4;

            let extensions_profile = match HeaderExtensionsProfile::try_from(extensions_profile) {
                Ok(extensions_profile) => extensions_profile,
                Err(err) => {
                    event!("calling.rtp.invalid.extensions_profile");
                    debug!("Invalid RTP: {err}");
                    debug!("{}", hex::encode(&packet[..packet.len().min(100)]));
                    return None;
                }
            };

            let (extensions, _payload_tag) =
                extension_payload_tag.checked_split_at(extensions_len)?;

            // extension_start is relative to extensions (relative to extensions_start + RTP_EXTENSIONS_HEADER_LEN)
            let mut extension_start = 0;
            while extensions.len() > extension_start {
                let (extension_header, extension_val) =
                    extensions[extension_start..].checked_split_at(extensions_profile.len())?;
                let extension_id = match extensions_profile {
                    HeaderExtensionsProfile::OneByte => extension_header[0] >> 4,
                    HeaderExtensionsProfile::TwoByte => extension_header[0],
                };
                if extension_id == 0 {
                    // Tail padding
                    break;
                }
                let extension_len = match extensions_profile {
                    HeaderExtensionsProfile::OneByte => ((extension_header[0] & 0x0F) as usize) + 1,
                    HeaderExtensionsProfile::TwoByte => extension_header[1] as usize,
                };
                if extension_val.len() < extension_len {
                    event!("calling.rtp.invalid.extension_too_short");
                    debug!(
                        "Invalid RTP: extension too short: {} < {}.  ID = {}",
                        extension_val.len(),
                        extension_len,
                        extension_id,
                    );
                    debug!("{}", hex::encode(&packet[..packet.len().min(100)]));
                    return None;
                }
                let extension_val = &extension_val[..extension_len];
                let extension_val_start = extensions_start
                    + RTP_EXTENSIONS_HEADER_LEN
                    + extension_start
                    + extensions_profile.len();
                let extension_val_end = extension_val_start + extension_len;
                let extension_val_range = extension_val_start..extension_val_end;

                match (extension_id, extension_val) {
                    (RTP_EXT_ID_TCC_SEQNUM, &[b0, b1]) => {
                        tcc_seqnum = Some(u16::from_be_bytes([b0, b1]));
                        tcc_seqnum_range = Some(extension_val_range);
                    }
                    (RTP_EXT_ID_VIDEO_ORIENTATION, &[b0]) => {
                        video_rotation = Some(VideoRotation::from(b0))
                    }
                    (RTP_EXT_ID_AUDIO_LEVEL, [negative_audio_level_with_voice_activity]) => {
                        audio_level =
                            // The spec says to use 127 here, but the clients are all decimating their values
                            // by a factor of 10, so this ends up being 120 as the lowest value (muted).
                            Some(120u8.saturating_sub(negative_audio_level_with_voice_activity & 0b0111_1111));
                    }
                    (RTP_EXT_ID_DEPENDENCY_DESCRIPTOR, val) => {
                        if val.len() < RTP_DEPENDENCY_DESCRIPTOR_MIN_LEN {
                            event!("calling.rtp.invalid.dependency_descriptor_too_short");
                            debug!(
                                "Invalid RTP: dependency descriptor value only {} bytes long",
                                val.len()
                            );
                            return None;
                        }

                        dependency_descriptor = DependencyDescriptorReader::new(val)
                            .read()
                            .ok()
                            .or(Some(DependencyDescriptor {
                                is_key_frame: false,
                                resolution: None,
                                truncated_frame_number: None,
                            }))
                            .map(|descriptor| (descriptor, extension_val_range));
                    }
                    _ => {}
                }
                extension_start += extensions_profile.len() + extension_len;
            }
            payload_start = extensions_start + RTP_EXTENSIONS_HEADER_LEN + extensions_len;
        };

        if packet.len() < (payload_start + SRTP_AUTH_TAG_LEN) {
            event!("calling.rtp.invalid.too_small_for_srtp_auth_tag");
            debug!(
                "Invalid RTP: too small for SRTP auth tag; payload_start = {}; packet len = {}",
                payload_start,
                packet.len()
            );
            debug!("{}", hex::encode(&packet[..packet.len().min(100)]));
            return None;
        }
        let payload_end = packet.len() - SRTP_AUTH_TAG_LEN;
        let payload_range = payload_start..payload_end;

        if has_padding && payload_range.is_empty() {
            event!("calling.rtp.invalid.missing_padding_count");
            debug!(
                "Invalid RTP: has padding, but padding byte count is missing; payload_range={:?}; packet len = {}",
                payload_range,
                packet.len()
            );
            return None;
        }

        Some(Self {
            marker,
            has_padding,
            payload_type,
            seqnum,
            timestamp,
            ssrc,
            video_rotation,
            audio_level,
            tcc_seqnum,
            tcc_seqnum_range,
            payload_range,
            dependency_descriptor,
        })
    }
}

/// https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DependencyDescriptor {
    pub is_key_frame: bool,
    pub resolution: Option<PixelSize>,
    pub truncated_frame_number: Option<u16>,
}

/// Parser for DependencyDescriptor
#[derive(Debug)]
pub(super) struct DependencyDescriptorReader<'a> {
    bytes: &'a [u8],
    /// The index into `bytes` of the next byte to read.
    byte_index: usize,
    /// The offset into `bytes[byte_index]` of the next bit to read. In the range 0..=7.
    bit_offset: u8,
}

impl<'a> DependencyDescriptorReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_index: 0,
            bit_offset: 0,
        }
    }

    /// An implementation of the pseudocode from the following section of the spec:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax
    ///
    /// The meaning of each parsed field is here:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a83-semantics
    pub fn read(mut self) -> Result<DependencyDescriptor> {
        // Ignore start_of_frame, end_of_frame, and frame_dependency_template_id.
        self.byte_index = 1;

        let truncated_frame_number = self.read_u16().ok();
        if self.bytes.len() == 3 {
            return Ok(DependencyDescriptor {
                is_key_frame: false,
                resolution: None,
                truncated_frame_number,
            });
        }

        let template_dependency_structure_present_flag = self.read_u8(1)? == 1;
        let _active_decode_targets_present_flag = self.read_u8(1)?;
        let _custom_dtis_flag = self.read_u8(1)?;
        let _custom_fdiffs_flag = self.read_u8(1)?;
        let _custom_chains_flag = self.read_u8(1)?;

        if !template_dependency_structure_present_flag {
            return Ok(DependencyDescriptor {
                is_key_frame: false,
                resolution: None,
                truncated_frame_number,
            });
        }

        let _template_id_offset = self.read_u8(6)?;
        let dt_cnt = self.read_u8(5)? + 1;

        // template_layers
        let mut template_cnt = 1;
        while self.read_u8(2)? != 3 {
            template_cnt += 1;
        }

        // template_dtis
        for _ in 0..template_cnt {
            for _ in 0..dt_cnt {
                let _template_dti = self.read_u8(2)?;
            }
        }

        // template_fdiffs
        for _ in 0..template_cnt {
            while self.read_u8(1)? == 1 {
                let _fdiff_minus_one = self.read_u8(4)?;
            }
        }

        // Skip over template_chains since we don't use SVC, so num_chains is 0.
        self.skip_non_symmetric(dt_cnt + 1)?;

        let mut resolution = None;
        let resolutions_present_flag = self.read_u8(1)?;
        if resolutions_present_flag == 1 {
            let width = self.read_u16()?.saturating_add(1);
            let height = self.read_u16()?.saturating_add(1);
            resolution = Some(PixelSize { width, height });
        }

        Ok(DependencyDescriptor {
            is_key_frame: true,
            resolution,
            truncated_frame_number,
        })
    }

    /// An implementation of the `f(n)` function in the spec, where 0 < n <= 8:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax
    fn read_u8(&mut self, bits: u8) -> Result<u8> {
        assert!(bits > 0 && bits <= 8);

        let last_byte = self.bytes.len() - 1;
        if self.byte_index > last_byte
            || (self.byte_index == last_byte && self.bit_offset + bits > 8)
        {
            bail!(
                "out of bounds access: byte_index={}, bit_offset={}, bits={bits}, bytes_len={}",
                self.byte_index,
                self.bit_offset,
                self.bytes.len(),
            );
        }

        let mut byte: u8;
        if self.bit_offset + bits >= 8 {
            // Need to read the remainder of the current byte, and potentially some of the
            // following byte.
            byte = self.bytes[self.byte_index];

            let num_bits_in_current_byte = 8 - self.bit_offset;
            if num_bits_in_current_byte < 8 {
                byte &= (1 << num_bits_in_current_byte) - 1;
            }
            let num_bits_in_next_byte = bits - num_bits_in_current_byte;
            byte <<= num_bits_in_next_byte;

            if num_bits_in_next_byte > 0 {
                let next_byte = self.bytes[self.byte_index + 1];
                let mask = ((1 << num_bits_in_next_byte) - 1) << (8 - num_bits_in_next_byte);
                byte |= (next_byte & mask) >> (8 - num_bits_in_next_byte);
            }

            self.byte_index += 1;
            self.bit_offset = (self.bit_offset + bits) % 8;
        } else {
            // Only need to look at the current byte.
            byte = self.bytes[self.byte_index];
            byte &= ((1 << bits) - 1) << (8 - self.bit_offset - bits);
            byte >>= 8 - self.bit_offset - bits;

            self.bit_offset += bits;
        }

        Ok(byte)
    }

    /// A special case of the `f(n)` function where n = 16:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax
    fn read_u16(&mut self) -> Result<u16> {
        match (self.read_u8(8), self.read_u8(8)) {
            (Ok(upper), Ok(lower)) => Ok(u16::from_be_bytes([upper, lower])),
            (Err(err), _) => Err(err),
            (_, Err(err)) => Err(err),
        }
    }

    /// A variant of the `ns(n)` function in the spec which doesn't return the result:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax
    fn skip_non_symmetric(&mut self, n: u8) -> Result<()> {
        let mut w = 0;
        let mut x = n;
        while x != 0 {
            x >>= 1;
            w += 1;
        }

        let m = (1 << w) - n;
        let v = self.read_u8(w - 1)?;
        if v < m {
            return Ok(());
        }

        let _extra_bit = self.read_u8(1)?;
        Ok(())
    }
}

// A combination of the parsed values of an RTP packet (mostly from the header)
// along with the entire serialized packet.
// The packet can be can be either:
// - Borrow or BorrowMut
// - Owned or borrowed
// - Encrypted or Decrypted
// - RTX or non-RTX.
// If it's RTX, many logical values are not what appear in the header
// and the logical seqnum is stored in the first part of the payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet<T> {
    pub(super) marker: bool,
    // We use these _in_header values because of how the logical values
    // and the header values differ when the packet is RTX.
    pub(super) payload_type_in_header: PayloadType,
    pub(super) ssrc_in_header: Ssrc,
    pub(super) seqnum_in_header: FullSequenceNumber,
    // Set if and only if the Packet is RTX.
    pub(super) seqnum_in_payload: Option<FullSequenceNumber>,
    // True when this packet is RTX and is in the pacer queue.
    pub(super) pending_retransmission: bool,
    pub timestamp: TruncatedTimestamp,
    pub video_rotation: Option<VideoRotation>,
    pub audio_level: Option<audio::Level>,
    // The range is relative to self.serialized.
    pub dependency_descriptor: Option<(DependencyDescriptor, Range<usize>)>,
    pub(super) tcc_seqnum: Option<tcc::FullSequenceNumber>,

    // These are relative to self.serialized.
    pub(super) tcc_seqnum_range: Option<Range<usize>>,
    pub(super) payload_range_in_header: Range<usize>,

    // If encrypted, that means the payload is ciphertext
    // and can't be written to, and that the SRTP auth tag is filled in.
    // Technically the header can be written to, but that invalidates
    // the auth tag, so that is also disallowed.
    // If not encrypted, that means the payload is plaintext and both
    // the payload and header can be written to.
    pub(super) encrypted: bool,

    // If the packet isn't sent by the deadline, discard it
    pub(super) deadline: Option<Instant>,

    pub padding_byte_count: u8,

    pub(super) serialized: T,
}

impl<T> Packet<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: &Header,
        seqnum_in_header: FullSequenceNumber,
        seqnum_in_payload: Option<FullSequenceNumber>,
        pending_retransmission: bool,
        tcc_seqnum: Option<FullSequenceNumber>,
        encrypted: bool,
        deadline: Option<Instant>,
        padding_byte_count: u8,
        serialized: T,
    ) -> Self {
        Self {
            marker: header.marker,
            payload_type_in_header: header.payload_type,
            ssrc_in_header: header.ssrc,
            seqnum_in_header,
            seqnum_in_payload,
            pending_retransmission,
            timestamp: header.timestamp,
            video_rotation: header.video_rotation,
            audio_level: header.audio_level,
            dependency_descriptor: header.dependency_descriptor.clone(),
            tcc_seqnum,
            tcc_seqnum_range: header.tcc_seqnum_range.clone(),
            payload_range_in_header: header.payload_range.clone(),
            encrypted,
            deadline,
            padding_byte_count,
            serialized,
        }
    }

    pub fn is_rtx(&self) -> bool {
        self.seqnum_in_payload.is_some()
    }

    pub fn payload_type(&self) -> PayloadType {
        if self.is_rtx() {
            from_rtx_payload_type(self.payload_type_in_header)
        } else {
            self.payload_type_in_header
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        if self.is_rtx() {
            from_rtx_ssrc(self.ssrc_in_header)
        } else {
            self.ssrc_in_header
        }
    }

    pub fn seqnum(&self) -> FullSequenceNumber {
        self.seqnum_in_payload.unwrap_or(self.seqnum_in_header)
    }

    pub fn tcc_seqnum(&self) -> Option<tcc::FullSequenceNumber> {
        self.tcc_seqnum
    }

    pub(super) fn payload_range(&self) -> Range<usize> {
        if self.is_rtx() {
            (self.payload_range_in_header.start + 2)..self.payload_range_in_header.end
        } else {
            self.payload_range_in_header.clone()
        }
    }

    pub fn into_serialized(self) -> T {
        self.serialized
    }

    pub fn is_audio(&self) -> bool {
        is_audio_payload_type(self.payload_type())
    }

    pub fn is_padding(&self) -> bool {
        is_padding_payload_type(self.payload_type())
    }

    pub fn is_video(&self) -> bool {
        is_video_payload_type(self.payload_type())
    }

    pub fn is_vp8(&self) -> bool {
        self.payload_type() == VP8_PAYLOAD_TYPE
    }

    pub fn is_past_deadline(&self, now: Instant) -> bool {
        match self.deadline {
            None => true,
            Some(deadline) => now > deadline,
        }
    }

    pub fn entry_time(&self) -> Option<Instant> {
        self.deadline.map(|deadline| deadline - PACKET_LIFETIME)
    }
}

impl<T: Borrow<[u8]>> Packet<T> {
    pub(super) fn serialized(&self) -> &[u8] {
        self.serialized.borrow()
    }

    fn header(&self) -> &[u8] {
        &self.serialized()[..self.payload_range().start]
    }

    pub fn payload(&self) -> &[u8] {
        &self.serialized()[self.payload_range()]
    }

    pub fn size(&self) -> DataSize {
        DataSize::from_bytes(self.serialized().len() as u64)
    }

    pub fn borrow(&self) -> Packet<&[u8]> {
        Packet {
            marker: self.marker,
            payload_type_in_header: self.payload_type_in_header,
            ssrc_in_header: self.ssrc_in_header,
            seqnum_in_header: self.seqnum_in_header,
            seqnum_in_payload: self.seqnum_in_payload,
            pending_retransmission: self.pending_retransmission,
            timestamp: self.timestamp,
            video_rotation: self.video_rotation,
            audio_level: self.audio_level,
            dependency_descriptor: self.dependency_descriptor.clone(),
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,
            deadline: self.deadline,
            padding_byte_count: self.padding_byte_count,

            serialized: self.serialized.borrow(),
        }
    }

    pub fn to_owned(&self) -> Packet<Vec<u8>> {
        Packet {
            marker: self.marker,
            payload_type_in_header: self.payload_type_in_header,
            ssrc_in_header: self.ssrc_in_header,
            seqnum_in_header: self.seqnum_in_header,
            seqnum_in_payload: self.seqnum_in_payload,
            pending_retransmission: self.pending_retransmission,
            timestamp: self.timestamp,
            video_rotation: self.video_rotation,
            audio_level: self.audio_level,
            dependency_descriptor: self.dependency_descriptor.clone(),
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,
            deadline: self.deadline,
            padding_byte_count: self.padding_byte_count,

            serialized: self.serialized.borrow().to_vec(),
        }
    }

    pub fn rewrite(
        &self,
        new_ssrc: Ssrc,
        new_seqnum: FullSequenceNumber,
        new_timestamp: TruncatedTimestamp,
    ) -> Packet<Vec<u8>> {
        let mut outgoing = self.to_owned();
        if outgoing.is_rtx() {
            // When forwarding RTX, we have to be careful to use
            // the RTX SSRC, the RTX seqnum, and to
            // put the non-RTX seqnum in the payload.
            // Note: outgoing.set_seqnum_in_header(rtx_seqnum) will be called
            // by Endpoint::forward_rtp because it requires updating the state.
            // Another way to think about it is that the tcc seqnum and then
            // seqnum in the header (for RTX packets) are transport-level
            // values, not logic/media-level values, and so will not be set
            // until a packet is about to be sent.
            outgoing.set_ssrc_in_header(to_rtx_ssrc(new_ssrc));
            outgoing.set_seqnum_in_payload(new_seqnum);
        } else {
            outgoing.set_ssrc_in_header(new_ssrc);
            outgoing.set_seqnum_in_header(new_seqnum);
        }
        outgoing.set_timestamp_in_header(new_timestamp);
        outgoing
    }
}

impl<T: BorrowMut<[u8]>> Packet<T> {
    pub fn serialized_mut(&mut self) -> &mut [u8] {
        assert!(
            !self.encrypted,
            "Can't modify the packet while it's encrypted"
        );
        self.serialized.borrow_mut()
    }

    fn header_mut(&mut self) -> &mut [u8] {
        assert!(
            !self.encrypted,
            "Can't modify the packet header while it's encrypted"
        );
        let header_end = self.payload_range().start;
        &mut self.serialized_mut()[..header_end]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        assert!(
            !self.encrypted,
            "Can't modify the packet payload while it's encrypted"
        );
        let payload_range = self.payload_range();
        &mut self.serialized_mut()[payload_range]
    }

    // TODO: Return a Result instead
    // pub for tests
    pub fn decrypt_in_place(&mut self, key: &Key, salt: &Salt) -> Option<()> {
        assert!(self.encrypted, "Can't decrypt an unencrypted packet");
        let (cipher, nonce, aad, ciphertext, tag) = self.prepare_for_crypto(key, salt);
        let nonce = GenericArray::from_slice(&nonce);
        let tag = GenericArray::from_slice(tag);
        cipher
            .decrypt_in_place_detached(nonce, aad, ciphertext, tag)
            .ok()?;
        self.encrypted = false;
        Some(())
    }

    // TODO: Return a Result instead
    // public for tests
    pub fn encrypt_in_place(&mut self, key: &Key, salt: &Salt) -> Option<()> {
        assert!(!self.encrypted, "Can't encrypt an already encrypted packet");
        let (cipher, nonce, aad, plaintext, tag) = self.prepare_for_crypto(key, salt);
        let nonce = GenericArray::from_slice(&nonce);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce, aad, plaintext)
            .ok()?;
        tag.copy_from_slice(&computed_tag);
        self.encrypted = true;
        Some(())
    }

    fn prepare_for_crypto(
        &mut self,
        key: &Key,
        salt: &Salt,
    ) -> (Aes128Gcm, [u8; SRTP_IV_LEN], &[u8], &mut [u8], &mut [u8]) {
        let ssrc = self.ssrc_in_header;
        let seqnum = self.seqnum_in_header;
        let header_len = self.payload_range_in_header.start;
        let payload_len = self.payload_range_in_header.len();

        let (header, payload_plus_tag) = self.serialized.borrow_mut().split_at_mut(header_len);
        let (payload, tag) = payload_plus_tag.split_at_mut(payload_len);
        let iv = rtp_iv(ssrc, seqnum, salt);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key[..]));
        (cipher, iv, header, payload, tag)
    }

    fn set_payload_type_in_header(&mut self, pt: PayloadType) {
        self.payload_type_in_header = pt;
        self.header_mut()[RTP_PAYLOAD_TYPE_OFFSET] = ((self.marker as u8) << 7) | pt;
    }

    pub(super) fn set_ssrc_in_header(&mut self, ssrc: Ssrc) {
        self.ssrc_in_header = ssrc;
        self.write_in_header(RTP_SSRC_RANGE.clone(), &ssrc.to_be_bytes());
    }

    // pub for Call tests
    pub fn set_seqnum_in_header(&mut self, seqnum: FullSequenceNumber) {
        self.seqnum_in_header = seqnum;
        self.write_in_header(RTP_SEQNUM_RANGE.clone(), &(seqnum as u16).to_be_bytes());
    }

    // pub for Call tests
    pub fn set_timestamp_in_header(&mut self, timestamp: TruncatedTimestamp) {
        self.timestamp = timestamp;
        self.write_in_header(RTP_TIMESTAMP_RANGE.clone(), &timestamp.to_be_bytes());
    }

    pub fn set_tcc_seqnum_in_header_if_present(
        &mut self,
        get_tcc_seqnum: impl FnOnce() -> tcc::FullSequenceNumber,
    ) {
        if let Some(tcc_seqnum_range) = self.tcc_seqnum_range.clone() {
            let tcc_seqnum = get_tcc_seqnum();

            self.tcc_seqnum = Some(tcc_seqnum);
            self.write_in_header(
                tcc_seqnum_range,
                &(tcc_seqnum as tcc::TruncatedSequenceNumber).to_be_bytes(),
            );
        }
    }

    pub fn set_frame_number_in_header(&mut self, frame_number: FullFrameNumber) {
        let Some((_, range)) = &self.dependency_descriptor else {
            return;
        };

        // Refer to https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax for dependency
        // descriptor format.
        let frame_number_start = range.start + 1;
        self.write_in_header(
            frame_number_start..(frame_number_start + std::mem::size_of::<TruncatedFrameNumber>()),
            &(frame_number as TruncatedFrameNumber).to_be_bytes(),
        );
    }

    pub(super) fn set_seqnum_in_payload(&mut self, seqnum: FullSequenceNumber) {
        // Clearing the seqnum in the payload makes us be non-RTX temporarily
        // which is a quick and dirty way to write to the non-RTX payload.
        self.seqnum_in_payload = None;
        self.write_in_payload(0..2, &(seqnum as u16).to_be_bytes());
        self.seqnum_in_payload = Some(seqnum);
    }

    fn write_in_header(&mut self, range: Range<usize>, bytes: &[u8]) {
        self.header_mut()[range].copy_from_slice(bytes);
    }

    fn write_in_payload(&mut self, range: Range<usize>, bytes: &[u8]) {
        self.payload_mut()[range].copy_from_slice(bytes);
    }

    pub fn borrow_mut(&mut self) -> Packet<&mut [u8]> {
        Packet {
            marker: self.marker,
            payload_type_in_header: self.payload_type_in_header,
            ssrc_in_header: self.ssrc_in_header,
            seqnum_in_header: self.seqnum_in_header,
            seqnum_in_payload: self.seqnum_in_payload,
            pending_retransmission: self.pending_retransmission,
            timestamp: self.timestamp,
            video_rotation: self.video_rotation,
            audio_level: self.audio_level,
            dependency_descriptor: self.dependency_descriptor.clone(),
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,
            deadline: self.deadline,
            padding_byte_count: self.padding_byte_count,

            serialized: self.serialized.borrow_mut(),
        }
    }
}

/// Encodes a one-byte RTP extension.
pub fn write_extension(id: u8, value: impl Writer) -> impl Writer {
    assert!(id & 0xF == id, "id must fit in 4 bits");
    let length = value.written_len();
    assert!(
        length > 0,
        "one-byte extensions do not support empty values"
    );
    assert!(length <= 16, "length must fit in 4 bits");
    let header = (id << 4) | (length as u8 - 1);
    ([header], value)
}

impl Packet<Vec<u8>> {
    /// Writes a valid RTP packet with the given parameters.
    ///
    /// The packet will not have extra padding, and the CSRC count will be zero.
    ///
    /// Returns `(serialized, payload_range_in_serialized)`.
    /// The returned Vec includes an empty (zeroed) SRTP authentication tag at the end.
    #[allow(clippy::too_many_arguments)]
    fn write_serialized(
        marker: bool,
        pt: PayloadType,
        seqnum: FullSequenceNumber,
        timestamp: TruncatedTimestamp,
        ssrc: Ssrc,
        extensions: impl Writer,
        extensions_profile: HeaderExtensionsProfile,
        payload: &[u8],
    ) -> (Vec<u8>, Range<usize>) {
        let has_padding = 0u8;
        let extensions_len = extensions.written_len();
        let has_extensions = extensions_len != 0;
        let csrc_count = 0u8;
        let header = (
            [(VERSION << 6)
                | (has_padding << 5)
                | ((has_extensions as u8) << 4)
                | (csrc_count & 0b1111)],
            [((marker as u8) << 7) | (pt & 0b1111111)],
            seqnum as TruncatedSequenceNumber,
            timestamp,
            ssrc,
        );
        let extensions = if has_extensions {
            let profile = match extensions_profile {
                HeaderExtensionsProfile::OneByte => RTP_ONE_BYTE_EXTENSIONS_PROFILE,
                HeaderExtensionsProfile::TwoByte => RTP_TWO_BYTE_EXTENSIONS_PROFILE,
            };
            let padded_len = round_up_to_multiple_of::<4>(extensions_len);
            let padding_len = padded_len - extensions_len;
            let extension_padding = &[0u8, 0, 0][..padding_len];
            Some((
                profile,
                u16::try_from(padded_len / 4).expect("too many extensions"),
                extensions,
                extension_padding,
            ))
        } else {
            None
        };

        let header = (header, extensions);
        let mut serialized =
            Vec::with_capacity(header.written_len() + payload.len() + SRTP_AUTH_TAG_LEN);
        header.write(&mut serialized);
        let payload_start = serialized.len();
        serialized.extend_from_slice(payload);
        let payload_end = serialized.len();
        serialized.resize(serialized.capacity(), 0u8); // Fill in empty tag.
        (serialized, payload_start..payload_end)
    }

    pub fn with_empty_tag(
        pt: PayloadType,
        seqnum: FullSequenceNumber,
        timestamp: TruncatedTimestamp,
        ssrc: Ssrc,
        tcc_seqnum: Option<FullSequenceNumber>,
        deadline_start: Option<Instant>,
        payload: &[u8],
    ) -> Self {
        let marker = false;
        let extensions = tcc_seqnum.map(|tcc_seqnum| {
            let tcc_seqnum = tcc_seqnum as tcc::TruncatedSequenceNumber;
            write_extension(RTP_EXT_ID_TCC_SEQNUM, tcc_seqnum)
        });
        let (serialized, payload_range) = Self::write_serialized(
            marker,
            pt,
            seqnum,
            timestamp,
            ssrc,
            extensions,
            HeaderExtensionsProfile::OneByte,
            payload,
        );
        Self {
            marker,
            payload_type_in_header: pt,
            ssrc_in_header: ssrc,
            seqnum_in_header: seqnum,
            seqnum_in_payload: None,
            pending_retransmission: false,
            timestamp,
            video_rotation: None,
            audio_level: None,
            dependency_descriptor: None,
            tcc_seqnum,
            // This only matters for tests.
            tcc_seqnum_range: if tcc_seqnum.is_some() {
                Some(17..19)
            } else {
                None
            },
            payload_range_in_header: payload_range,
            encrypted: false,
            deadline: deadline_start.map(|deadline_start| deadline_start + PACKET_LIFETIME),
            padding_byte_count: 0,
            serialized,
        }
    }

    // pub for tests
    pub fn to_rtx(&self, rtx_seqnum: FullSequenceNumber) -> Self {
        if self.is_rtx() {
            let mut rtx = self.to_owned();
            rtx.set_seqnum_in_header(rtx_seqnum);
            rtx
        } else {
            let serialized: Vec<u8> = (
                self.header(),
                self.seqnum_in_header as u16,
                self.payload(),
                &[0u8; SRTP_AUTH_TAG_LEN][..],
            )
                .to_vec();
            let mut rtx = Packet {
                payload_type_in_header: to_rtx_payload_type(self.payload_type_in_header),
                ssrc_in_header: to_rtx_ssrc(self.ssrc_in_header),
                seqnum_in_header: rtx_seqnum,
                seqnum_in_payload: Some(self.seqnum_in_header),
                dependency_descriptor: self.dependency_descriptor.clone(),
                tcc_seqnum_range: self.tcc_seqnum_range.clone(),
                payload_range_in_header: self.payload_range_in_header.start
                    ..(self.payload_range_in_header.end + 2),
                serialized,

                ..*self
            };
            // This writes the values in the serialized header, which the
            // above does not do.
            rtx.set_payload_type_in_header(rtx.payload_type_in_header);
            rtx.set_ssrc_in_header(rtx.ssrc_in_header);
            rtx.set_seqnum_in_header(rtx.seqnum_in_header);
            rtx
        }
    }
}

#[cfg(test)]
mod dependency_descriptor_tests {
    use super::*;

    #[test]
    fn read_u8() -> Result<()> {
        let bytes = [0b0000_0010, 0b1010_0000];
        let mut rdr = DependencyDescriptorReader::new(&bytes);

        assert_eq!(rdr.read_u8(1)?, 0);

        rdr.bit_offset = 1;
        assert_eq!(rdr.read_u8(1)?, 0);

        rdr.bit_offset = 6;
        assert_eq!(rdr.read_u8(1)?, 1);

        rdr.bit_offset = 3;
        assert_eq!(rdr.read_u8(5)?, 0b10);

        rdr.byte_index = 0;
        rdr.bit_offset = 6;
        assert_eq!(rdr.read_u8(3)?, 0b101);

        Ok(())
    }

    #[test]
    fn read_u8_two_bytes() -> Result<()> {
        let bytes = [0b0000_0010, 0b1010_0011];
        let mut rdr = DependencyDescriptorReader::new(&bytes);

        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(5)?, 0b1);
        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(4)?, 0b1010);
        assert_eq!(rdr.read_u8(2)?, 0b0);
        assert_eq!(rdr.read_u8(1)?, 0b1);
        assert_eq!(rdr.read_u8(1)?, 0b1);

        assert!(rdr.read_u8(1).is_err());

        Ok(())
    }

    #[test]
    fn read_u8_one_byte() -> Result<()> {
        let bytes = [0b0001_1011];
        let mut rdr = DependencyDescriptorReader::new(&bytes);

        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(1)?, 1);
        assert_eq!(rdr.read_u8(1)?, 1);
        assert_eq!(rdr.read_u8(1)?, 0);
        assert_eq!(rdr.read_u8(1)?, 1);
        assert_eq!(rdr.read_u8(1)?, 1);

        rdr.byte_index = 0;
        rdr.bit_offset = 0;
        assert_eq!(rdr.read_u8(2)?, 0b0);
        assert_eq!(rdr.read_u8(2)?, 0b1);
        assert_eq!(rdr.read_u8(2)?, 0b10);
        assert_eq!(rdr.read_u8(2)?, 0b11);

        rdr.byte_index = 0;
        rdr.bit_offset = 0;
        assert_eq!(rdr.read_u8(4)?, 0b1);
        assert_eq!(rdr.read_u8(4)?, 0b1011);

        rdr.byte_index = 0;
        rdr.bit_offset = 0;
        assert_eq!(rdr.read_u8(5)?, 0b11);
        assert_eq!(rdr.read_u8(3)?, 0b11);

        rdr.byte_index = 0;
        rdr.bit_offset = 0;
        assert_eq!(rdr.read_u8(8)?, 0b0001_1011);

        Ok(())
    }

    #[test]
    fn read_camera_layer_0() -> Result<()> {
        let bytes = [
            0b11000000,
            0b00000000,
            0b00000001,
            0b10000000, // The first bit in this byte indicates that this is for a key frame.
            0b00000010,
            0b00000100,
            0b01001110,
            0b10101010,
            0b10101111,
            0b00101000,
            0b01100000,
            0b01000001,
            0b01001101,
            0b00110100,
            0b01010011,
            0b10001010,
            0b00001001,
            0b01000000,
            // The resolution is 160x120, but the value on the wire is one pixel smaller than the
            // real resolution. 159x119 in binary is 0b1001_1111 x 0b0111_0111 and each value is
            // stored as 2 bytes.
            //
            // The second bit in the following byte indicates that a resolution is included.
            // The third bit is where the width starts.
            0b01_000000,
            0b00_100111,
            // The third bit in the following byte is where the height starts.
            0b11_000000,
            0b00_011101,
            0b11_000000,
        ];
        let rdr = DependencyDescriptorReader::new(&bytes);

        let descriptor = rdr.read()?;

        assert!(descriptor.is_key_frame);
        assert_eq!(
            descriptor.resolution,
            Some(PixelSize {
                width: 160,
                height: 120
            })
        );

        Ok(())
    }

    #[test]
    fn read_screenshare() -> Result<()> {
        let bytes = [
            0b10000000,
            0b00001011,
            0b00001011,
            0b10000000, // The first bit in this byte indicates that this is for a key frame.
            0b00000001,
            0b00000100,
            0b11101010,
            0b10101100,
            0b10000101,
            0b00010100,
            0b01010000,
            0b01000110,
            0b0000_0100, // width - 1 is 2879 / 0b0000_1011_0011_1111 (starting on the 7th bit)
            0b0010_1100,
            0b1111_1100, // height - 1 is 1619 / 0b0000_0110_0101_0011 (from the 7th bit)
            0b0001_1001,
            0b0100_1100,
        ];
        let rdr = DependencyDescriptorReader::new(&bytes);

        let descriptor = rdr.read()?;

        assert!(descriptor.is_key_frame);
        assert_eq!(
            descriptor.resolution,
            Some(PixelSize {
                width: 2880,
                height: 1620
            })
        );

        Ok(())
    }

    #[test]
    fn read_no_dependency_structure() -> Result<()> {
        let bytes = [0b10000011, 0b00000001, 0b01100101];
        let rdr = DependencyDescriptorReader::new(&bytes);

        let descriptor = rdr.read()?;

        assert!(!descriptor.is_key_frame);
        assert_eq!(descriptor.resolution, None);

        Ok(())
    }

    #[test]
    fn read_ignore_custom_fdiffs() -> Result<()> {
        let bytes = [
            0b10000010,
            0b00001011,
            0b00101100,
            // The first bit in the following byte indicates that this isn't a keyframe. The fourth
            // bit indicates that there are custom fdiffs.
            0b0001_0010,
            0b01000000,
        ];
        let rdr = DependencyDescriptorReader::new(&bytes);

        let descriptor = rdr.read()?;

        assert!(!descriptor.is_key_frame);
        assert_eq!(descriptor.resolution, None);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::rtp::{looks_like_rtcp, looks_like_rtp, RTCP_PAYLOAD_TYPE_OFFSET, RTCP_TYPE_BYE};

    use super::*;

    #[test]
    fn test_packet_classification_rtp() {
        fn run_tests(packet: &mut [u8], is_rtcp: bool) {
            assert_eq!(!is_rtcp, looks_like_rtp(packet));
            assert_eq!(is_rtcp, looks_like_rtcp(packet));

            assert!(!looks_like_rtp(&packet[..RTP_PAYLOAD_TYPE_OFFSET]));
            assert!(!looks_like_rtcp(&packet[..RTCP_PAYLOAD_TYPE_OFFSET]));

            // Note that we *do* accept packets that are too short if they have an appropriate *prefix.*
            // This saves time checking other packet types in the top-level packet handler.
            assert_eq!(
                !is_rtcp,
                looks_like_rtp(&packet[..=RTP_PAYLOAD_TYPE_OFFSET])
            );
            assert_eq!(
                is_rtcp,
                looks_like_rtcp(&packet[..=RTCP_PAYLOAD_TYPE_OFFSET])
            );

            let version = std::mem::replace(&mut packet[0], 0);
            assert!(!looks_like_rtp(packet));
            assert!(!looks_like_rtcp(packet));
            packet[0] = version;

            // Bottom six bits are ignored.
            packet[0] ^= 0b11_1111;
            assert_eq!(!is_rtcp, looks_like_rtp(packet));
            assert_eq!(is_rtcp, looks_like_rtcp(packet));
            packet[0] ^= 0b11_1111;

            // Top bit of payload type is ignored.
            packet[RTP_PAYLOAD_TYPE_OFFSET] ^= 0b1000_0000;
            assert_eq!(!is_rtcp, looks_like_rtp(packet));
            assert_eq!(is_rtcp, looks_like_rtcp(packet));
            packet[RTP_PAYLOAD_TYPE_OFFSET] ^= 0b1000_0000;
        }

        let mut packet = Packet::with_empty_tag(1, 2, 3, 4, None, None, &[]).into_serialized();
        run_tests(&mut packet, false);

        // Packet types only matter in that they can't be claimed by RTCP.
        let packet_type = std::mem::replace(&mut packet[RTP_PAYLOAD_TYPE_OFFSET], 0);
        run_tests(&mut packet, false);
        packet[RTP_PAYLOAD_TYPE_OFFSET] = packet_type;

        // Rather than make a valid RTCP packet, we'll just take the RTP packet and change the type.
        // Our classification is deliberately fuzzy, just enough to decide which parser to use.
        let packet_type = std::mem::replace(&mut packet[RTP_PAYLOAD_TYPE_OFFSET], RTCP_TYPE_BYE);
        run_tests(&mut packet, true);
        packet[RTP_PAYLOAD_TYPE_OFFSET] = packet_type;
    }

    #[test]
    fn test_parse_rtp_header() {
        assert_eq!(None, Header::parse(&[]));
        let mut packet = Packet::with_empty_tag(1, 2, 3, 4, None, None, &[]).into_serialized();
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: None,
                dependency_descriptor: None,
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range: RTP_MIN_HEADER_LEN..RTP_MIN_HEADER_LEN,
            }),
            Header::parse(&packet)
        );
        assert_eq!(None, Header::parse(&packet[..RTP_MIN_HEADER_LEN]));
        assert_eq!(None, Header::parse(&packet[..SRTP_AUTH_TAG_LEN]));
        assert_eq!(None, Header::parse(&packet[..SRTP_AUTH_TAG_LEN + 5]));
        assert_eq!(
            None,
            Header::parse(&packet[..packet.len() - SRTP_AUTH_TAG_LEN])
        );

        // Make it look like there are many CSRCS
        // (an evil packet)
        packet[0] |= 0b1111;
        assert_eq!(None, Header::parse(&packet));
    }

    #[test]
    fn test_parse_rtp_header_with_seqnum() {
        let mut packet =
            Packet::with_empty_tag(1, 2, 3, 4, Some(0x12345678), None, &[]).into_serialized();
        let expected_payload_start = RTP_MIN_HEADER_LEN + RTP_EXTENSIONS_HEADER_LEN + 4;
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: None,
                dependency_descriptor: None,
                tcc_seqnum: Some(0x5678),
                tcc_seqnum_range: Some(17..19),
                payload_range: expected_payload_start..expected_payload_start,
            }),
            Header::parse(&packet)
        );
        assert_eq!(None, Header::parse(&packet[..RTP_MIN_HEADER_LEN]));
        assert_eq!(None, Header::parse(&packet[..SRTP_AUTH_TAG_LEN]));
        assert_eq!(None, Header::parse(&packet[..SRTP_AUTH_TAG_LEN + 5]));
        assert_eq!(
            None,
            Header::parse(&packet[..packet.len() - SRTP_AUTH_TAG_LEN])
        );

        // Make it look like there are many CSRCS
        // (an evil packet)
        packet[0] |= 0b1111;
        assert_eq!(None, Header::parse(&packet));
    }

    #[test]
    fn test_parse_rtp_header_with_audio() {
        fn parse_audio_level_from_packet(raw_level: u8) -> u8 {
            let extensions = write_extension(RTP_EXT_ID_AUDIO_LEVEL, [raw_level]);
            let (packet, _) = Packet::write_serialized(
                false,
                1,
                2,
                3,
                4,
                extensions,
                HeaderExtensionsProfile::OneByte,
                &[],
            );
            let parsed = Header::parse(&packet).unwrap();
            parsed.audio_level.unwrap()
        }

        // Our limit is -120dB, rather than the spec's -127dB.
        assert_eq!(0, parse_audio_level_from_packet(127));
        assert_eq!(0, parse_audio_level_from_packet(120));
        assert_eq!(1, parse_audio_level_from_packet(119));
        assert_eq!(119, parse_audio_level_from_packet(1));
        assert_eq!(120, parse_audio_level_from_packet(0));

        // The top bit is ignored.
        assert_eq!(0, parse_audio_level_from_packet(127 | 0x80));
        assert_eq!(0, parse_audio_level_from_packet(120 | 0x80));
        assert_eq!(1, parse_audio_level_from_packet(119 | 0x80));
        assert_eq!(119, parse_audio_level_from_packet(1 | 0x80));
        assert_eq!(120, parse_audio_level_from_packet(0x80));
    }

    #[test]
    fn test_parse_rtp_header_with_seqnum_and_audio() {
        let extensions = (
            write_extension(RTP_EXT_ID_TCC_SEQNUM, 0x5678u16),
            write_extension(RTP_EXT_ID_AUDIO_LEVEL, [0x21u8]),
        );
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: Some(87),
                dependency_descriptor: None,
                tcc_seqnum: Some(0x5678),
                tcc_seqnum_range: Some(17..19),
                payload_range,
            }),
            Header::parse(&packet)
        );

        let extensions = (
            write_extension(RTP_EXT_ID_AUDIO_LEVEL, [0x21u8]),
            write_extension(RTP_EXT_ID_TCC_SEQNUM, 0x5678u16),
        );
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: Some(87),
                dependency_descriptor: None,
                tcc_seqnum: Some(0x5678),
                tcc_seqnum_range: Some(19..21),
                payload_range,
            }),
            Header::parse(&packet)
        );

        // Try once more with extra tail padding.
        let extensions = (
            write_extension(RTP_EXT_ID_AUDIO_LEVEL, [0x21u8]),
            write_extension(RTP_EXT_ID_TCC_SEQNUM, 0x5678u16),
            [0u8, 0u8, 0u8, 0u8],
        );
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: Some(87),
                dependency_descriptor: None,
                tcc_seqnum: Some(0x5678),
                tcc_seqnum_range: Some(19..21),
                payload_range,
            }),
            Header::parse(&packet)
        );
    }

    #[test]
    fn test_parse_rtp_header_with_orientation() {
        let extensions = write_extension(RTP_EXT_ID_VIDEO_ORIENTATION, [0x1u8]);
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: Some(VideoRotation::Clockwise90),
                audio_level: None,
                dependency_descriptor: None,
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range,
            }),
            Header::parse(&packet)
        );

        let extensions = write_extension(RTP_EXT_ID_VIDEO_ORIENTATION, [0x2u8]);
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: Some(VideoRotation::Clockwise180),
                audio_level: None,
                dependency_descriptor: None,
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range,
            }),
            Header::parse(&packet)
        );

        // Try once more with extra tail padding.
        let extensions = (
            write_extension(RTP_EXT_ID_VIDEO_ORIENTATION, [0x3u8]),
            [0u8, 0u8, 0u8, 0u8],
        );
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: Some(VideoRotation::Clockwise270),
                audio_level: None,
                dependency_descriptor: None,
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range,
            }),
            Header::parse(&packet)
        );
    }

    #[test]
    fn test_parse_rtp_header_with_dependency_descriptor() {
        let extensions = write_extension(
            RTP_EXT_ID_DEPENDENCY_DESCRIPTOR,
            [0b10000011u8, 0b00000001, 0b01100101],
        );
        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::OneByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: None,
                audio_level: None,
                dependency_descriptor: Some((
                    DependencyDescriptor {
                        is_key_frame: false,
                        resolution: None,
                        truncated_frame_number: Some(357),
                    },
                    17..20
                )),
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range,
            }),
            Header::parse(&packet)
        );
    }

    #[test]
    fn test_parse_rtp_header_two_byte_extensions() {
        fn write_two_byte_extension(id: u8, value: impl Writer) -> impl Writer {
            assert_ne!(id, 0, "id must not be 0");
            let length = value.written_len();
            let header = [id, length.try_into().expect("length must fit in 8 bits")];
            (header, value)
        }

        let extensions = (
            write_two_byte_extension(RTP_EXT_ID_VIDEO_ORIENTATION, [0x3u8]),
            write_two_byte_extension(
                RTP_EXT_ID_DEPENDENCY_DESCRIPTOR,
                [
                    0b10000000u8,
                    0b00001000,
                    0b01010111,
                    0b10000000, // The first bit in this byte indicates that this is for a key frame.
                    0b00000010,
                    0b00000100,
                    0b01001110,
                    0b10101010,
                    0b10101111,
                    0b00101000,
                    0b01100000,
                    0b01000001,
                    0b01001101,
                    0b00110100,
                    0b01010011,
                    0b10001010,
                    0b00001001,
                    0b01000000,
                    0b0100_0000, // width - 1 is 639 / 0b0000_0010_0111_1111 (starting on the 3rd bit)
                    0b1001_1111,
                    0b1100_0000, // height - 1 is 479 / 0b0000_0001_1101_1111 (from the 3rd bit)
                    0b0111_0111,
                    0b1100_0000,
                ],
            ),
        );

        let (packet, payload_range) = Packet::write_serialized(
            false,
            1,
            2,
            3,
            4,
            extensions,
            HeaderExtensionsProfile::TwoByte,
            &[],
        );
        assert_eq!(
            Some(Header {
                marker: false,
                has_padding: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                video_rotation: Some(VideoRotation::Clockwise270),
                audio_level: None,
                dependency_descriptor: Some((
                    DependencyDescriptor {
                        is_key_frame: true,
                        resolution: Some(PixelSize {
                            width: 640,
                            height: 480,
                        }),
                        truncated_frame_number: Some(2135),
                    },
                    21..44
                )),
                tcc_seqnum: None,
                tcc_seqnum_range: None,
                payload_range,
            }),
            Header::parse(&packet)
        );
    }
}
