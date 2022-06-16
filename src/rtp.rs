//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of RTP/SRTP. See https://tools.ietf.org/html/rfc3550 and
//! https://tools.ietf.org/html/rfc7714. Assumes AES-GCM 128.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ops::{Range, RangeInclusive},
};

use aes::{cipher::generic_array::GenericArray, Aes128, BlockEncrypt, NewBlockCipher};
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use byteorder::{ReadBytesExt, BE};
use log::*;
use zeroize::Zeroizing;

use crate::{
    audio,
    common::{
        expand_truncated_counter, parse_u16, parse_u32, read_u16, round_up_to_multiple_of, Bits,
        CheckedSplitAt, DataSize, Duration, Instant, KeySortedCache, TwoGenerationCache, Writer,
    },
    transportcc as tcc,
};

const VERSION: u8 = 2;
const RTP_MIN_HEADER_LEN: usize = 12;
const RTP_PAYLOAD_TYPE_OFFSET: usize = 1;
const RTP_SEQNUM_RANGE: Range<usize> = 2..4;
const RTP_TIMESTAMP_RANGE: Range<usize> = 4..8;
const RTP_SSRC_RANGE: Range<usize> = 8..12;
const RTP_EXTENSIONS_HEADER_LEN: usize = 4;
const RTP_ONE_BYTE_EXTENSIONS_PROFILE: u16 = 0xBEDE;
const RTP_EXT_ID_TCC_SEQNUM: u8 = 1; // Really u4
const RTP_EXT_ID_AUDIO_LEVEL: u8 = 5; // Really u4
const RTCP_PAYLOAD_TYPES: RangeInclusive<u8> = 64..=95;
const RTCP_HEADER_LEN: usize = 8;
const RTCP_PAYLOAD_TYPE_OFFSET: usize = 1;
const RTCP_PAYLOAD_LEN_RANGE: Range<usize> = 2..4;
const RTCP_SENDER_SSRC_RANGE: Range<usize> = 4..8;
pub const SRTP_KEY_LEN: usize = 16;
pub const SRTP_SALT_LEN: usize = 12;
const SRTP_IV_LEN: usize = 12;
const SRTP_AUTH_TAG_LEN: usize = 16;
const SRTCP_FOOTER_LEN: usize = 4;
const RTCP_TYPE_SENDER_REPORT: u8 = 200;
const RTCP_TYPE_RECEIVER_REPORT: u8 = 201;
const RTCP_TYPE_EXTENDED_REPORT: u8 = 207;
const RTCP_TYPE_SDES: u8 = 202;
const RTCP_TYPE_BYE: u8 = 203;
pub const RTCP_TYPE_GENERIC_FEEDBACK: u8 = 205;
pub const RTCP_FORMAT_NACK: u8 = 1;
pub const RTCP_FORMAT_TRANSPORT_CC: u8 = 15;
pub const RTCP_TYPE_SPECIFIC_FEEDBACK: u8 = 206;
pub const RTCP_FORMAT_PLI: u8 = 1;
const RTCP_FORMAT_LOSS_NOTIFICATION: u8 = 15;
pub const VP8_PAYLOAD_TYPE: PayloadType = 108;
const RTX_PAYLOAD_TYPE_OFFSET: PayloadType = 10;
const RTX_SSRC_OFFSET: Ssrc = 1;

pub type Key = Zeroizing<[u8; SRTP_KEY_LEN]>;
pub type Salt = [u8; SRTP_SALT_LEN];
pub type Iv = [u8; SRTP_IV_LEN];
// In the order [client_key, client_salt, server_key, server_salt]
pub const MASTER_KEY_MATERIAL_LEN: usize =
    SRTP_KEY_LEN + SRTP_SALT_LEN + SRTP_KEY_LEN + SRTP_SALT_LEN;
pub type MasterKeyMaterial = Zeroizing<[u8; MASTER_KEY_MATERIAL_LEN]>;

#[derive(Debug, Clone)]
pub struct KeyAndSalt {
    pub key: Key,
    pub salt: Salt,
}

#[derive(Debug, Clone)]
pub struct KeysAndSalts {
    pub rtp: KeyAndSalt,
    pub rtcp: KeyAndSalt,
}

impl KeysAndSalts {
    // Returns (client, server)
    pub fn derive_client_and_server_from_master_key_material(
        master_key_material: &MasterKeyMaterial,
    ) -> (KeysAndSalts, KeysAndSalts) {
        let client_key: Key =
            Zeroizing::new(master_key_material[..SRTP_KEY_LEN].try_into().unwrap());
        let client_salt: Salt = master_key_material[SRTP_KEY_LEN..][..SRTP_SALT_LEN]
            .try_into()
            .unwrap();
        let server_key: Key = Zeroizing::new(
            master_key_material[SRTP_KEY_LEN..][SRTP_SALT_LEN..][..SRTP_KEY_LEN]
                .try_into()
                .unwrap(),
        );
        let server_salt: Salt = master_key_material[SRTP_KEY_LEN..][SRTP_SALT_LEN..]
            [SRTP_KEY_LEN..][..SRTP_SALT_LEN]
            .try_into()
            .unwrap();
        let client = Self::derive_from_master(&KeyAndSalt {
            key: client_key,
            salt: client_salt,
        });
        let server = Self::derive_from_master(&KeyAndSalt {
            key: server_key,
            salt: server_salt,
        });
        (client, server)
    }

    // See https://github.com/cisco/libsrtp/blob/master/crypto/cipher/aes_icm_ossl.c#L278
    // and https://github.com/cisco/libsrtp/blob/master/srtp/srtp.c#L632
    // and https://tools.ietf.org/html/rfc3711#section-4.3.2 for label constants.
    pub fn derive_from_master(master: &KeyAndSalt) -> Self {
        Self {
            rtp: KeyAndSalt {
                key: Self::derive_key_from_master(master, 0),
                salt: Self::derive_salt_from_master(master, 2),
            },
            rtcp: KeyAndSalt {
                key: Self::derive_key_from_master(master, 3),
                salt: Self::derive_salt_from_master(master, 5),
            },
        }
    }

    fn derive_key_from_master(master: &KeyAndSalt, label: u8) -> Key {
        let cipher = Aes128::new(GenericArray::from_slice(&master.key[..]));
        let mut derived = Zeroizing::new([0; SRTP_KEY_LEN]);
        derived[..SRTP_SALT_LEN].copy_from_slice(&master.salt);
        derived[7] ^= label;
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut derived[..]));
        derived
    }

    fn derive_salt_from_master(master: &KeyAndSalt, label: u8) -> Salt {
        Self::derive_key_from_master(master, label)[..SRTP_SALT_LEN]
            .try_into()
            .unwrap()
    }
}

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

pub type PayloadType = u8;
pub type FullSequenceNumber = u64; // Really u48 due to limitations of SRTP
pub type TruncatedSequenceNumber = u16; // What actually goes in the packet
pub type FullTimestamp = u64;
pub type TruncatedTimestamp = u32;
pub type Ssrc = u32;

// pub for tests
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    marker: bool,
    pub payload_type: PayloadType,
    seqnum: TruncatedSequenceNumber,
    timestamp: TruncatedTimestamp,
    pub ssrc: Ssrc,
    audio_level: Option<audio::Level>,
    tcc_seqnum: Option<TruncatedSequenceNumber>,
    // We parse the range as well in order to replace it easily.
    tcc_seqnum_range: Option<Range<usize>>,
    // The payload start is the same as the header len.
    // The payload end isn't technically part of the "Header",
    // but it's convenient to parse at the same time.
    pub payload_range: Range<usize>,
}

impl Header {
    // pub for tests
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let (main_header, csrcs_extensions_payload_tag) =
            packet.checked_split_at(RTP_MIN_HEADER_LEN)?;

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
        let mut audio_level = None;

        let extensions_start = RTP_MIN_HEADER_LEN + csrcs_len;
        let mut payload_start = extensions_start;
        if has_extensions {
            let (extensions_header, extension_payload_tag) =
                extension_payload_tag.checked_split_at(RTP_EXTENSIONS_HEADER_LEN)?;
            let extensions_profile = parse_u16(&extensions_header[0..2]);
            let extensions_len = (parse_u16(&extensions_header[2..4]) as usize) * 4;

            if extensions_profile != RTP_ONE_BYTE_EXTENSIONS_PROFILE {
                // 2-byte header extension is only needed for extensions of size = 0
                // size > 16, and we don't use any such extensions.
                warn!(
                    "Invalid RTP: not using 1-byte extensions; profile = 0x{:x}",
                    extensions_profile
                );
                warn!("{}", hex::encode(&packet[..packet.len().min(100)]));
                return None;
            }

            let (extensions, _payload_tag) =
                extension_payload_tag.checked_split_at(extensions_len)?;

            // extension_start is relative to extensions (relative to extensions_start + RTP_EXTENSIONS_HEADER_LEN)
            let mut extension_start = 0;
            while extensions.len() > extension_start {
                let (extension_header, extension_val) =
                    (&extensions[extension_start..]).checked_split_at(1)?;
                let extension_id = extension_header[0] >> 4;
                if extension_id == 0 {
                    // Tail padding
                    break;
                }
                let extension_len = ((extension_header[0] & 0x0F) as usize) + 1;
                if extension_val.len() < extension_len {
                    warn!(
                        "Invalid RTP: extension too short: {} < {}.  ID = {}",
                        extension_len,
                        extension_val.len(),
                        extension_id,
                    );
                    warn!("{}", hex::encode(&packet[..packet.len().min(100)]));
                    return None;
                }
                let extension_val = &extension_val[..extension_len];
                // TODO: Dedup this with the above code.
                let extension_val_start =
                    extensions_start + RTP_EXTENSIONS_HEADER_LEN + extension_start + 1;
                let extension_val_end = extension_val_start + extension_len;
                let extension_val_range = extension_val_start..extension_val_end;

                match (extension_id, extension_val) {
                    (RTP_EXT_ID_TCC_SEQNUM, &[b0, b1]) => {
                        tcc_seqnum = Some(u16::from_be_bytes([b0, b1]));
                        tcc_seqnum_range = Some(extension_val_range);
                    }
                    (RTP_EXT_ID_AUDIO_LEVEL, [negative_audio_level_with_voice_activity]) => {
                        audio_level =
                            // The spec says to use 127 here, but the clients are all decimating their values
                            // by a factor of 10, so this ends up being 120 as the lowest value (muted).
                            Some(120u8.saturating_sub(negative_audio_level_with_voice_activity & 0b0111_1111));
                    }
                    _ => {}
                }
                extension_start += 1 + extension_len;
            }
            payload_start = extensions_start + RTP_EXTENSIONS_HEADER_LEN + extensions_len;
        };

        if packet.len() < (payload_start + SRTP_AUTH_TAG_LEN) {
            warn!(
                "Invalid RTP: too small for SRTP auth tag; payload_start = {}; packet len = {}",
                payload_start,
                packet.len()
            );
            warn!("{}", hex::encode(&packet[..packet.len().min(100)]));
            return None;
        }
        let payload_end = packet.len() - SRTP_AUTH_TAG_LEN;
        let payload_range = payload_start..payload_end;

        Some(Self {
            marker,
            payload_type,
            seqnum,
            timestamp,
            ssrc,
            audio_level,
            tcc_seqnum,
            tcc_seqnum_range,
            payload_range,
        })
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
) -> FullSequenceNumber {
    expand_truncated_counter(timestamp, max_timestamp, 32)
}

fn is_rtx_payload_type(pt: PayloadType) -> bool {
    is_rtxable_payload_type(from_rtx_payload_type(pt))
}

fn is_rtxable_payload_type(pt: PayloadType) -> bool {
    pt == VP8_PAYLOAD_TYPE
}

fn to_rtx_payload_type(pt: PayloadType) -> PayloadType {
    pt.wrapping_add(RTX_PAYLOAD_TYPE_OFFSET)
}

pub fn to_rtx_ssrc(ssrc: Ssrc) -> Ssrc {
    ssrc.wrapping_add(RTX_SSRC_OFFSET)
}

fn from_rtx_payload_type(rtx_pt: PayloadType) -> PayloadType {
    rtx_pt.wrapping_sub(RTX_PAYLOAD_TYPE_OFFSET)
}

fn from_rtx_ssrc(rtx_ssrc: Ssrc) -> Ssrc {
    rtx_ssrc.wrapping_sub(RTX_SSRC_OFFSET)
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
    marker: bool,
    // We use these _in_header values because of how the logical values
    // and the header values differ when the packet is RTX.
    payload_type_in_header: PayloadType,
    ssrc_in_header: Ssrc,
    seqnum_in_header: FullSequenceNumber,
    // Set if and only if the Packet is RTX.
    seqnum_in_payload: Option<FullSequenceNumber>,
    pub timestamp: TruncatedTimestamp,
    pub audio_level: Option<audio::Level>,
    tcc_seqnum: Option<tcc::FullSequenceNumber>,

    // These are relative to self.serialized.
    tcc_seqnum_range: Option<Range<usize>>,
    payload_range_in_header: Range<usize>,

    // If encrypted, that means the payload is ciphertext
    // and can't be written to, and that the SRTP auth tag is filled in.
    // Technically the header can be written to, but that invalidates
    // the auth tag, so that is also disallowed.
    // If not encrypted, that means the payload is plaintext and both
    // the payload and header can be written to.
    encrypted: bool,

    serialized: T,
}

impl<T> Packet<T> {
    fn is_rtx(&self) -> bool {
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

    fn payload_range(&self) -> Range<usize> {
        if self.is_rtx() {
            (self.payload_range_in_header.start + 2)..self.payload_range_in_header.end
        } else {
            self.payload_range_in_header.clone()
        }
    }

    pub fn into_serialized(self) -> T {
        self.serialized
    }
}

impl<T: Borrow<[u8]>> Packet<T> {
    fn serialized(&self) -> &[u8] {
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
            timestamp: self.timestamp,
            audio_level: self.audio_level,
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,

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
            timestamp: self.timestamp,
            audio_level: self.audio_level,
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,

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
    fn serialized_mut(&mut self) -> &mut [u8] {
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

    fn set_ssrc_in_header(&mut self, ssrc: Ssrc) {
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

    fn set_tcc_seqnum_in_header_if_present(
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

    fn set_seqnum_in_payload(&mut self, seqnum: FullSequenceNumber) {
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
            timestamp: self.timestamp,
            audio_level: self.audio_level,
            tcc_seqnum: self.tcc_seqnum,
            tcc_seqnum_range: self.tcc_seqnum_range.clone(),
            payload_range_in_header: self.payload_range_in_header.clone(),
            encrypted: self.encrypted,

            serialized: self.serialized.borrow_mut(),
        }
    }
}

/// Encodes a one-byte RTP extension.
fn write_extension(id: u8, value: impl Writer) -> impl Writer {
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
    fn write_serialized(
        marker: bool,
        pt: PayloadType,
        seqnum: FullSequenceNumber,
        timestamp: TruncatedTimestamp,
        ssrc: Ssrc,
        extensions: impl Writer,
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
            let padded_len = round_up_to_multiple_of::<4>(extensions_len);
            let padding_len = padded_len - extensions_len;
            let extension_padding = &[0u8, 0, 0][..padding_len];
            Some((
                RTP_ONE_BYTE_EXTENSIONS_PROFILE,
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
        payload: &[u8],
    ) -> Self {
        let marker = false;
        let extensions = tcc_seqnum.map(|tcc_seqnum| {
            let tcc_seqnum = tcc_seqnum as tcc::TruncatedSequenceNumber;
            write_extension(RTP_EXT_ID_TCC_SEQNUM, tcc_seqnum)
        });
        let (serialized, payload_range) =
            Self::write_serialized(marker, pt, seqnum, timestamp, ssrc, extensions, payload);
        Self {
            marker,
            payload_type_in_header: pt,
            ssrc_in_header: ssrc,
            seqnum_in_header: seqnum,
            seqnum_in_payload: None,
            timestamp,
            audio_level: None,
            tcc_seqnum,
            // This only matters for tests.
            tcc_seqnum_range: if tcc_seqnum.is_some() {
                Some(17..19)
            } else {
                None
            },
            payload_range_in_header: payload_range,
            encrypted: false,
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

#[cfg(fuzzing)]
fn fuzzing_key() -> Key {
    [0u8; SRTP_KEY_LEN].into()
}

#[cfg(fuzzing)]
pub fn parse_and_forward_rtp_for_fuzzing(data: Vec<u8>) -> Option<Vec<u8>> {
    let header = Header::parse(&data)?;

    let mut incoming = Packet {
        marker: header.marker,
        payload_type_in_header: header.payload_type,
        ssrc_in_header: header.ssrc,
        seqnum_in_header: Default::default(),
        seqnum_in_payload: None,
        timestamp: header.timestamp,
        audio_level: header.audio_level,
        tcc_seqnum: Default::default(),
        tcc_seqnum_range: header.tcc_seqnum_range,
        payload_range_in_header: header.payload_range,
        encrypted: true,
        serialized: data,
    };

    let _ = incoming.decrypt_in_place(&fuzzing_key(), &Default::default());
    incoming.encrypted = false;

    if is_rtx_payload_type(header.payload_type) {
        let original_seqnum = if let Some((seqnum_in_payload, _)) = read_u16(incoming.payload()) {
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

#[allow(clippy::identity_op)]
fn rtp_iv(ssrc: Ssrc, seqnum: FullSequenceNumber, salt: &Salt) -> Iv {
    let ssrc = ssrc.to_be_bytes();
    let seqnum = seqnum.to_be_bytes();
    [
        0 ^ salt[0],
        0 ^ salt[1],
        ssrc[0] ^ salt[2],
        ssrc[1] ^ salt[3],
        ssrc[2] ^ salt[4],
        ssrc[3] ^ salt[5],
        // Treat as a u48.  In other words, the ROC then the truncated seqnum
        seqnum[2] ^ salt[6],
        seqnum[3] ^ salt[7],
        seqnum[4] ^ salt[8],
        seqnum[5] ^ salt[9],
        seqnum[6] ^ salt[10],
        seqnum[7] ^ salt[11],
    ]
}

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
            warn!("RTCP packet too small: {}", serialized.len());
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
            let _ = cipher
                .decrypt_in_place_detached(nonce, &aad, ciphertext, tag)
                .ok()?;
        } else {
            // Allow processing unencrypted packets when fuzzing;
            // otherwise we'd have to encrypt all fuzz inputs.
            #[cfg(not(fuzzing))]
            {
                warn!("Receiving unencrypted RTCP is not supported!");
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
}

#[cfg(fuzzing)]
pub fn parse_rtcp(buffer: &mut [u8]) {
    ControlPacket::parse_and_decrypt_in_place(buffer, &fuzzing_key(), &Default::default());
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

fn parse_nack(rtcp_payload: &[u8]) -> std::io::Result<Nack> {
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
struct NackSender {
    limit: usize,
    sent_by_seqnum: KeySortedCache<FullSequenceNumber, Option<(Instant, Instant)>>,
    max_received: Option<FullSequenceNumber>,
}

impl NackSender {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            sent_by_seqnum: KeySortedCache::new(limit),
            max_received: None,
        }
    }

    // If there are any new unreceived seqnums (the need to send nacks), returns the necessary seqnums to nack.
    fn remember_received(&mut self, seqnum: FullSequenceNumber) {
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
    fn send_nacks<'sender>(
        &'sender mut self,
        now: Instant,
    ) -> Option<impl Iterator<Item = FullSequenceNumber> + 'sender> {
        let mut send_any = false;
        self.sent_by_seqnum.retain(|_seqnum, sent| {
            if let Some((first_sent, last_sent)) = sent {
                if now.saturating_duration_since(*first_sent) >= Duration::from_secs(2) {
                    // Expire it.
                    false
                } else if now.saturating_duration_since(*last_sent) >= Duration::from_millis(200) {
                    // It has already been sent, but should be sent again.
                    send_any = true;
                    *last_sent = now;
                    true
                } else {
                    // It has already been sent and does not need to be sent again yet.
                    true
                }
            } else {
                // It hasn't been sent yet but should be.
                send_any = true;
                *sent = Some((now, now));
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

// Keeps a cache of previously sent packets over a limited time window
// and can be asked to create an RTX packet from one of those packets
// based on SSRC and seqnum.  The cache is across SSRCs, not per SSRC.
struct RtxSender {
    // The key includes an SSRC because we send packets with many SSRCs
    // and a truncated seqnum because we need to look them up by
    // seqnums in NACKs which are truncated.
    previously_sent_by_seqnum: TwoGenerationCache<(Ssrc, TruncatedSequenceNumber), Packet<Vec<u8>>>,
    next_outgoing_seqnum_by_ssrc: HashMap<Ssrc, FullSequenceNumber>,
}

impl RtxSender {
    fn new(limit: Duration) -> Self {
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

    fn increment_seqnum(&mut self, rtx_ssrc: Ssrc) -> FullSequenceNumber {
        let next_seqnum = self.get_next_seqnum_mut(rtx_ssrc);
        let seqnum = *next_seqnum;
        *next_seqnum += 1;
        seqnum
    }

    fn remember_sent(&mut self, outgoing: Packet<Vec<u8>>, departed: Instant) {
        self.previously_sent_by_seqnum.insert(
            (
                outgoing.ssrc(),
                outgoing.seqnum() as TruncatedSequenceNumber,
            ),
            outgoing,
            departed,
        );
    }

    fn resend_as_rtx(
        &mut self,
        ssrc: Ssrc,
        seqnum: TruncatedSequenceNumber,
        get_tcc_seqnum: impl FnOnce() -> tcc::FullSequenceNumber,
    ) -> Option<Packet<Vec<u8>>> {
        let rtx_ssrc = to_rtx_ssrc(ssrc);
        let rtx_seqnum = *self.get_next_seqnum_mut(rtx_ssrc);

        let previously_sent = self.previously_sent_by_seqnum.get(&(ssrc, seqnum))?;
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

    fn send_padding(
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
            &PADDING_PAYLOAD[..],
        )
    }
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
}

struct IncomingSsrcState {
    max_seqnum: FullSequenceNumber,
    seqnum_reuse_detector: SequenceNumberReuseDetector,
    nack_sender: NackSender,
}

// This is almost the same as ControlPacket.
// But it processes the transport-cc feedback into Acks based on previously sent packets.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcessedControlPacket {
    pub key_frame_requests: Vec<KeyFrameRequest>,
    pub acks: Vec<tcc::Ack>,
    pub nacks: Vec<Nack>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nack {
    pub ssrc: Ssrc,
    pub seqnums: Vec<TruncatedSequenceNumber>,
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

            // 10 seconds of RTX history should be enough for anyone
            rtx_sender: RtxSender::new(Duration::from_secs(10)),
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
        let ssrc_state = self.get_incoming_ssrc_state_mut(header.ssrc);
        let seqnum_in_header = expand_seqnum(header.seqnum, &mut ssrc_state.max_seqnum);
        match ssrc_state
            .seqnum_reuse_detector
            .remember_used(seqnum_in_header)
        {
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

        let mut incoming = Packet {
            marker: header.marker,
            payload_type_in_header: header.payload_type,
            ssrc_in_header: header.ssrc,
            seqnum_in_header,
            seqnum_in_payload: None,
            timestamp: header.timestamp,
            audio_level: header.audio_level,
            tcc_seqnum,
            tcc_seqnum_range: header.tcc_seqnum_range,
            payload_range_in_header: header.payload_range,
            encrypted: true,
            serialized: encrypted,
        };

        let decrypt_failed = incoming
            .decrypt_in_place(&self.decrypt.rtp.key, &self.decrypt.rtp.salt)
            .is_none();
        if decrypt_failed {
            debug!(
                "Invalid RTP: decryption failed; ssrc: {}, seqnum: {}, pt: {}, payload_range: {:?}",
                incoming.ssrc(),
                incoming.seqnum(),
                incoming.payload_type(),
                incoming.payload_range(),
            );
            return None;
        }

        // We have to do this after decrypting to get the seqnum in the payload.
        if is_rtx_payload_type(header.payload_type) {
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
            })
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
        let rtx = rtx_sender.resend_as_rtx(ssrc, seqnum, || tcc_sender.increment_seqnum())?;
        self.encrypt_and_send_rtp(rtx, now)
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
        if let Some(tcc_seqnum) = outgoing.tcc_seqnum {
            self.tcc_sender
                .remember_sent(tcc_seqnum, outgoing.size(), now);
        }
        // Remember the packet sent before we encrypt it.
        if is_rtxable_payload_type(outgoing.payload_type()) {
            self.rtx_sender.remember_sent(outgoing.to_owned(), now);
        }
        outgoing.encrypt_in_place(&self.encrypt.rtp.key, &self.encrypt.rtp.salt)?;
        Some(outgoing)
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
                let seqnums = state.nack_sender.send_nacks(now)?;
                let payload = write_nack(*ssrc, seqnums);
                Self::send_rtcp_and_increment_index(
                    RTCP_TYPE_GENERIC_FEEDBACK,
                    RTCP_FORMAT_NACK,
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
        self.send_rtcp(RTCP_TYPE_SPECIFIC_FEEDBACK, RTCP_FORMAT_PLI, pli_ssrc)
    }

    // Returns a new, encrypted RTCP packet.
    // TODO: Use Result instead of Option.
    fn send_rtcp(&mut self, pt: u8, format: u8, payload: impl Writer) -> Option<Vec<u8>> {
        Self::send_rtcp_and_increment_index(
            pt,
            format,
            self.rtcp_sender_ssrc,
            payload,
            &mut self.next_outgoing_srtcp_index,
            &self.encrypt.rtcp.key,
            &self.encrypt.rtcp.salt,
        )
    }

    fn send_rtcp_and_increment_index(
        pt: u8,
        format: u8,
        sender_ssrc: Ssrc,
        payload: impl Writer,
        next_outgoing_srtcp_index: &mut u32,
        key: &Key,
        salt: &Salt,
    ) -> Option<Vec<u8>> {
        let serialized = ControlPacket::serialize_and_encrypt(
            pt,
            format,
            sender_ssrc,
            payload,
            *next_outgoing_srtcp_index,
            key,
            salt,
        )?;
        *next_outgoing_srtcp_index += 1;
        Some(serialized)
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
#[derive(Default, Debug)]
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

#[cfg(test)]
mod test {
    use super::*;

    const VP8_RTX_PAYLOAD_TYPE: PayloadType = 118;

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

        let mut packet = Packet::with_empty_tag(1, 2, 3, 4, None, &[]).into_serialized();
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
        let mut packet = Packet::with_empty_tag(1, 2, 3, 4, None, &[]).into_serialized();
        assert_eq!(
            Some(Header {
                marker: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                audio_level: None,
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
            Packet::with_empty_tag(1, 2, 3, 4, Some(0x12345678), &[]).into_serialized();
        let expected_payload_start = RTP_MIN_HEADER_LEN + RTP_EXTENSIONS_HEADER_LEN + 4;
        assert_eq!(
            Some(Header {
                marker: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                audio_level: None,
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
            let (packet, _) = Packet::write_serialized(false, 1, 2, 3, 4, extensions, &[]);
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
        let (packet, payload_range) = Packet::write_serialized(false, 1, 2, 3, 4, extensions, &[]);
        assert_eq!(
            Some(Header {
                marker: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                audio_level: Some(87),
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
        let (packet, payload_range) = Packet::write_serialized(false, 1, 2, 3, 4, extensions, &[]);
        assert_eq!(
            Some(Header {
                marker: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                audio_level: Some(87),
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
        let (packet, payload_range) = Packet::write_serialized(false, 1, 2, 3, 4, extensions, &[]);
        assert_eq!(
            Some(Header {
                marker: false,
                payload_type: 1,
                seqnum: 2,
                timestamp: 3,
                ssrc: 4,
                audio_level: Some(87),
                tcc_seqnum: Some(0x5678),
                tcc_seqnum_range: Some(19..21),
                payload_range,
            }),
            Header::parse(&packet)
        );
    }

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

        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(0))));

        nack_sender.remember_received(3);
        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(30))));

        nack_sender.remember_received(4);
        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(40))));

        // 5 went missing
        nack_sender.remember_received(6);
        assert_eq!(
            Some(vec![5]),
            collect_seqnums(nack_sender.send_nacks(at(60)))
        );

        // Not long enough for a resend
        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(70))));
        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(80))));

        nack_sender.remember_received(9);
        assert_eq!(
            Some(vec![7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(90)))
        );

        // Long enough for a resend of 5 but not 7 or 8
        assert_eq!(
            Some(vec![5]),
            collect_seqnums(nack_sender.send_nacks(at(260)))
        );

        // Resending all of them
        assert_eq!(
            Some(vec![5, 7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(460)))
        );
        assert_eq!(
            Some(vec![5, 7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(1860)))
        );

        // 5 has timed out but not 7 or 8
        assert_eq!(
            Some(vec![7, 8]),
            collect_seqnums(nack_sender.send_nacks(at(2070)))
        );

        // Now they have all timed out
        assert_eq!(None, collect_seqnums(nack_sender.send_nacks(at(2090))));

        // And there's a limited history window
        nack_sender.remember_received(208);
        assert_eq!(
            Some(vec![203, 204, 205, 206, 207]),
            collect_seqnums(nack_sender.send_nacks(at(2080)))
        );

        nack_sender.remember_received(60000);
        assert_eq!(
            Some(vec![59995, 59996, 59997, 59998, 59999]),
            collect_seqnums(nack_sender.send_nacks(at(3000)))
        );
    }

    #[test]
    fn test_rtx_sender() {
        let history_limit = Duration::from_millis(10000);
        let mut rtx_sender = RtxSender::new(history_limit);

        fn sent_packet(ssrc: Ssrc, seqnum: FullSequenceNumber) -> Packet<Vec<u8>> {
            let timestamp = seqnum as TruncatedTimestamp;
            let tcc_seqnum = seqnum;
            let payload = &[];
            Packet::with_empty_tag(
                VP8_PAYLOAD_TYPE,
                seqnum,
                timestamp,
                ssrc,
                Some(tcc_seqnum),
                payload,
            )
        }

        fn rtx_packet(
            ssrc: Ssrc,
            seqnum: FullSequenceNumber,
            rtx_seqnum: FullSequenceNumber,
            tcc_seqnum: tcc::FullSequenceNumber,
        ) -> Packet<Vec<u8>> {
            let timestamp = seqnum as TruncatedTimestamp;
            let payload = &(seqnum as u16).to_be_bytes();
            let mut rtx = Packet::with_empty_tag(
                VP8_RTX_PAYLOAD_TYPE,
                rtx_seqnum,
                timestamp,
                ssrc + 1,
                Some(tcc_seqnum),
                payload,
            );
            rtx.seqnum_in_payload = Some(seqnum);
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
                &PAYLOAD[..],
            )
        }

        let now = Instant::now();
        rtx_sender.remember_sent(sent_packet(2, 11), now);
        rtx_sender.remember_sent(sent_packet(4, 21), now + Duration::from_millis(2000));
        assert_eq!(
            Some(rtx_packet(2, 11, 1, 101)),
            rtx_sender.resend_as_rtx(2, 11, || 101)
        );
        // Make sure we can send more than once.
        assert_eq!(
            Some(rtx_packet(2, 11, 2, 102)),
            rtx_sender.resend_as_rtx(2, 11, || 102)
        );
        // Make sure wrong SSRC or seqnum is ignored.
        assert_eq!(None, rtx_sender.resend_as_rtx(0, 11, || 101));
        assert_eq!(None, rtx_sender.resend_as_rtx(2, 12, || 101));

        // Push some things out of the history
        rtx_sender.remember_sent(sent_packet(2, 12), now + Duration::from_millis(14000));
        rtx_sender.remember_sent(sent_packet(4, 22), now + Duration::from_millis(16000));
        rtx_sender.remember_sent(sent_packet(2, 13), now + Duration::from_millis(18000));
        rtx_sender.remember_sent(sent_packet(4, 23), now + Duration::from_millis(20000));
        rtx_sender.remember_sent(sent_packet(2, 14), now + Duration::from_millis(22000));
        rtx_sender.remember_sent(sent_packet(4, 24), now + Duration::from_millis(24000));

        assert_eq!(None, rtx_sender.resend_as_rtx(2, 11, || 103));
        assert_eq!(None, rtx_sender.resend_as_rtx(4, 21, || 103));
        assert_eq!(
            Some(rtx_packet(2, 12, 3, 103)),
            rtx_sender.resend_as_rtx(2, 12, || 103)
        );
        assert_eq!(
            Some(rtx_packet(4, 22, 1, 104)),
            rtx_sender.resend_as_rtx(4, 22, || 104)
        );
        assert_eq!(
            Some(rtx_packet(4, 24, 2, 105)),
            rtx_sender.resend_as_rtx(4, 24, || 105)
        );

        // Make sure the marker bit survives the process
        let mut sent = sent_packet(2, 15);
        sent.marker = true;
        sent.serialized_mut()[1] = (1 << 7) | VP8_PAYLOAD_TYPE;
        let mut rtx = rtx_packet(2, 15, 4, 106);
        rtx.marker = true;
        rtx.serialized_mut()[1] = (1 << 7) | VP8_RTX_PAYLOAD_TYPE;
        rtx_sender.remember_sent(sent, now + Duration::from_millis(16000));
        assert_eq!(Some(rtx), rtx_sender.resend_as_rtx(2, 15, || 106));

        // Make sure the padding RTX seqnums are not reused
        assert_eq!(padding_packet(3, 5, 107), rtx_sender.send_padding(3, 107));
        assert_eq!(padding_packet(5, 3, 108), rtx_sender.send_padding(5, 108));
        assert_eq!(padding_packet(7, 1, 109), rtx_sender.send_padding(7, 109));

        // Try resending an RTX packet.
        rtx_sender.remember_sent(
            rtx_packet(2, 16, 37, 40),
            now + Duration::from_millis(17_000),
        );
        assert_eq!(
            Some(rtx_packet(2, 16, 6, 107)),
            rtx_sender.resend_as_rtx(2, 16, || 107)
        );
    }

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
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 1, 2, 3, Some(0), &[4, 5, 6]),
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
        assert_eq!(empty, receiver.send_nacks(at(20)).collect::<Vec<_>>());
        assert_eq!(Some(1), sent1.tcc_seqnum);

        let mut sent2 = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 2, 4, 3, Some(0), &[5, 6, 7]),
                at(20),
            )
            .unwrap();
        // Simulate never received
        sent2.decrypt_in_place(&sender_key.rtp.key, &sender_key.rtp.salt);
        assert_eq!(&[5, 6, 7], sent2.payload());
        assert_eq!(Some(2), sent2.tcc_seqnum);

        let mut sent3 = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 3, 6, 3, Some(0), &[6, 7, 8]),
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
        let mut nacks: Vec<Vec<u8>> = receiver.send_nacks(at(40)).collect();
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
        let received2 = received2.to_owned();
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
        assert_eq!(empty, receiver.send_nacks(at(440)).collect::<Vec<_>>());

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
        let reforwarded2 = sender
            .receive_rtp(reforwarded2.serialized.borrow_mut(), at(90))
            .unwrap();
        let reforwarded2 = reforwarded2.to_owned();
        assert_eq!(resent2.payload_type(), reforwarded2.payload_type());
        assert_eq!(VP8_RTX_PAYLOAD_TYPE, reforwarded2.payload_type_in_header);
        assert_eq!(33, reforwarded2.ssrc());
        assert_eq!(34, reforwarded2.ssrc_in_header);
        assert_eq!(1, reforwarded2.seqnum_in_header);
        assert_eq!(Some(22), reforwarded2.seqnum_in_payload);
        assert_eq!(22, reforwarded2.seqnum());
        assert_eq!(44, reforwarded2.timestamp);
        assert_eq!(resent2.payload(), reforwarded2.payload());
        assert_eq!(Some(2), reforwarded2.tcc_seqnum);

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
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 1, 2, 3, Some(0), &[4, 5, 6]),
                at(10),
            )
            .unwrap();
        let mut sent1b = sent1a.clone();
        let mut sent1c = sent1a.clone();
        let mut sent2a = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 2, 2, 3, Some(0), &[4, 5, 6]),
                at(10),
            )
            .unwrap();
        let mut sent2b = sent2a.clone();
        let mut sent2c = sent2a.clone();
        let mut sent200a = sender
            .send_rtp(
                Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 200, 2, 3, Some(0), &[4, 5, 6]),
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
