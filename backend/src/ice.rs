//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of ICE lite. See https://tools.ietf.org/html/rfc5389

use std::{
    convert::TryFrom,
    ops::{Deref, Range},
};

use calling_common::{
    parse_u16, random_base64_string_of_length_32, random_base64_string_of_length_4,
    round_up_to_multiple_of, Empty, Writer,
};
use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{digest::MacError, Hmac, Mac};
use log::*;
use sha1::Sha1;
use thiserror::Error;

const HEADER_LEN: usize = 20;
const HMAC_LEN: usize = 20;
const FINGERPRINT_LEN: usize = 4;
const ATTR_HEADER_LEN: usize = 4;
const BINDING_REQUEST_ID: [u8; 2] = [0x00, 0x01];
const BINDING_RESPONSE_ID: [u8; 2] = [0x01, 0x01];
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

struct AttributeId {}

impl AttributeId {
    const USERNAME: u16 = 0x0006;
    const MESSAGE_INTEGRITY: u16 = 0x0008;
    const FINGERPRINT: u16 = 0x8028;
    /// AKA USE-CANDIDATE
    const NOMINATION: u16 = 0x0025;
}

const FINGERPRINT_XOR_VALUE: u32 = 0x5354554E;

struct BindingRequestRanges {
    username: Range<usize>,
    hmac: Range<usize>,
    fingerprint: Range<usize>,
}

pub fn join_username(sender_ufrag: &[u8], receiver_ufrag: &[u8]) -> Vec<u8> {
    [receiver_ufrag, sender_ufrag].join(b":".as_ref())
}

pub struct BindingRequest<'a> {
    packet: &'a [u8],
    is_nominated: bool,
    ranges: BindingRequestRanges,
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum ParseError {
    #[error("ICE binding request has no complete header, packet length {0}.")]
    IncompleteHeader(usize),
    #[error("ICE binding request has no username.")]
    MissingUsernameAttribute,
    #[error("ICE binding request has no hmac.")]
    MissingHMacAttribute,
    #[error("ICE binding request has no fingerprint.")]
    MissingFingerprintAttribute,
    #[error("ICE binding request message length was declared as {0:#06x} but was {1:#06x}.")]
    DeclaredMessageLengthMismatch(usize, usize),
    #[error("ICE binding request hmac length was {0} but expected {1}.")]
    WrongHMacLength(u16, u16),
    #[error("ICE binding request fingerprint length was {0} but expected {1}.")]
    WrongFingerprintLength(u16, u16),
    #[error("ICE binding request fingerprint seen before hmac")]
    FingerprintBeforeHMac,
    #[error("ICE binding request saw attribute {0:#06x} but expected fingerprint.")]
    ExpectedFingerprint(u16),
    #[error("ICE binding request saw attribute {0:#06x} after the fingerprint.")]
    AttributeAfterFingerprint(u16),
    #[error("ICE binding request attribute {0:#06x} is {1} bytes past packet end.")]
    AttributeRangePastPacketEnd(u16, usize),
}

impl<'a> BindingRequest<'a> {
    pub fn looks_like_header(packet: &[u8]) -> bool {
        packet.len() >= 8 && packet[0..2] == BINDING_REQUEST_ID && packet[4..8] == MAGIC_COOKIE
    }

    pub fn parse(packet: &'a [u8]) -> Result<BindingRequest<'a>, ParseError> {
        if packet.len() < HEADER_LEN {
            return Err(ParseError::IncompleteHeader(packet.len()));
        }

        let declared_message_length = parse_u16(&packet[2..4]) as usize;
        let actual_message_length = packet.len() - HEADER_LEN;
        if declared_message_length != actual_message_length {
            return Err(ParseError::DeclaredMessageLengthMismatch(
                declared_message_length,
                actual_message_length,
            ));
        }

        /// State machine states for parsing, to help ensure mac and fingerprint are last.
        enum ParseState {
            ReadingAttributes,
            ExpectFingerprint,
            Done,
        }

        let mut parse_mode = ParseState::ReadingAttributes;
        let mut username: Option<Range<usize>> = None;
        let mut hmac: Option<Range<usize>> = None;
        let mut fingerprint: Option<Range<usize>> = None;
        let mut nomination: Option<Range<usize>> = None;

        let mut attr_start = HEADER_LEN;
        while packet.len() >= attr_start + ATTR_HEADER_LEN {
            let attr_header = &packet[attr_start..][..ATTR_HEADER_LEN];
            let attr_id = parse_u16(&attr_header[0..2]);
            let attr_len = parse_u16(&attr_header[2..4]);
            let attr_val_start = attr_start + ATTR_HEADER_LEN;
            let attr_val_end = attr_val_start + attr_len as usize;
            let attr_range = attr_val_start..attr_val_end;
            if attr_range.end > packet.len() {
                return Err(ParseError::AttributeRangePastPacketEnd(
                    attr_id,
                    attr_range.end - packet.len(),
                ));
            }
            match parse_mode {
                ParseState::ReadingAttributes => match attr_id {
                    AttributeId::USERNAME => username = Some(attr_range.clone()),
                    AttributeId::NOMINATION => nomination = Some(attr_range.clone()),
                    AttributeId::MESSAGE_INTEGRITY => {
                        if attr_range.len() != HMAC_LEN {
                            return Err(ParseError::WrongHMacLength(attr_len, HMAC_LEN as u16));
                        }
                        hmac = Some(attr_range.clone());
                        parse_mode = ParseState::ExpectFingerprint;
                    }
                    AttributeId::FINGERPRINT => {
                        return Err(ParseError::FingerprintBeforeHMac);
                    }
                    _ => {}
                },
                ParseState::ExpectFingerprint => {
                    if attr_id != AttributeId::FINGERPRINT {
                        return Err(ParseError::ExpectedFingerprint(attr_id));
                    }
                    if attr_range.len() != FINGERPRINT_LEN {
                        return Err(ParseError::WrongFingerprintLength(
                            attr_len,
                            FINGERPRINT_LEN as u16,
                        ));
                    }
                    fingerprint = Some(attr_range.clone());
                    parse_mode = ParseState::Done;
                }
                ParseState::Done => {
                    return Err(ParseError::AttributeAfterFingerprint(attr_id));
                }
            }
            attr_start = round_up_to_multiple_of::<4>(attr_range.end);
        }

        let username = username.ok_or(ParseError::MissingUsernameAttribute)?;
        let hmac = hmac.ok_or(ParseError::MissingHMacAttribute)?;
        let fingerprint = fingerprint.ok_or(ParseError::MissingFingerprintAttribute)?;

        if log_enabled!(Level::Trace) {
            trace!("ICE binding request:");
            trace!("  username: {:?}", username.clone().collect::<Vec<_>>());
            trace!("  hmac: {:?}", hmac.clone().collect::<Vec<_>>());
            trace!(
                "  fingerprint: {:?}",
                fingerprint.clone().collect::<Vec<_>>()
            );
        }

        Ok(BindingRequest {
            packet,
            is_nominated: nomination.is_some(),
            ranges: BindingRequestRanges {
                username,
                hmac,
                fingerprint,
            },
        })
    }

    pub fn nominated(&self) -> bool {
        self.is_nominated
    }

    pub fn hmac(&self) -> &[u8] {
        &self.packet[self.ranges.hmac.clone()]
    }

    pub fn fingerprint(&self) -> &[u8] {
        &self.packet[self.ranges.fingerprint.clone()]
    }

    pub fn username(&self) -> &[u8] {
        &self.packet[self.ranges.username.clone()]
    }

    pub fn verify_hmac(&self, pwd: &[u8]) -> Result<VerifiedBindingRequest, MacError> {
        Self::calculate_hmac(self.packet, &self.ranges, pwd)
            .verify_slice(self.hmac())
            .map(|_| VerifiedBindingRequest::new(self))
    }

    fn calculate_hmac(packet: &[u8], ranges: &BindingRequestRanges, pwd: &[u8]) -> Hmac<Sha1> {
        // ICE HMACs are strange in that they are computed without the HMAC attribute,
        // but are computed with a length that includes the HMAC attribute.
        let mut mac = Hmac::<Sha1>::new_from_slice(pwd).expect("All key lengths are valid");
        mac.update(&packet[0..2]);
        // The length in the header excludes the header itself, but includes the HMAC attribute.
        mac.update(&((ranges.hmac.end - HEADER_LEN) as u16).to_be_bytes());
        mac.update(&packet[4..(ranges.hmac.start - ATTR_HEADER_LEN)]);
        mac
    }
}

pub struct VerifiedBindingRequest<'a> {
    request: &'a BindingRequest<'a>,
}

impl<'a> Deref for VerifiedBindingRequest<'a> {
    type Target = BindingRequest<'a>;

    fn deref(&self) -> &Self::Target {
        self.request
    }
}

impl<'a> VerifiedBindingRequest<'a> {
    fn new(request: &'a BindingRequest<'a>) -> VerifiedBindingRequest<'a> {
        VerifiedBindingRequest { request }
    }

    /// Public constructor for fuzzing only, which allows creation of a verified binding request
    /// even though it's not possible for the fuzzer to get past the hmac verification.  
    #[cfg(fuzzing)]
    pub fn new_for_fuzzing(request: &'a BindingRequest<'a>) -> VerifiedBindingRequest<'a> {
        VerifiedBindingRequest { request }
    }

    pub fn to_binding_response(&self, username: &[u8], pwd: &[u8]) -> Vec<u8> {
        let mut packet: Vec<u8> = self.packet.to_vec();
        packet[0..2].copy_from_slice(&BINDING_RESPONSE_ID);
        packet[self.ranges.username.clone()].copy_from_slice(username);
        Self::recalculate_hmac_and_fingerprint_of_packet(&mut packet, &self.ranges, pwd);
        packet
    }

    fn recalculate_hmac_and_fingerprint_of_packet(
        packet: &mut [u8],
        ranges: &BindingRequestRanges,
        pwd: &[u8],
    ) {
        let hmac = BindingRequest::calculate_hmac(packet, ranges, pwd)
            .finalize()
            .into_bytes();
        packet[ranges.hmac.clone()].copy_from_slice(&hmac);
        let fingerprint = FINGERPRINT_XOR_VALUE
            ^ CRC32.checksum(&packet[..(ranges.fingerprint.start - ATTR_HEADER_LEN)]);
        packet[ranges.fingerprint.clone()].copy_from_slice(&fingerprint.to_be_bytes());
    }
}

pub fn random_ufrag() -> String {
    random_base64_string_of_length_4()
}

pub fn random_pwd() -> String {
    random_base64_string_of_length_32()
}

type TransactionId = [u8; 16];

pub fn create_binding_request_packet(
    transaction_id: &TransactionId,
    username: &[u8],
    pwd: &[u8],
    nominated: bool,
) -> Vec<u8> {
    create_packet(BINDING_REQUEST_ID, transaction_id, username, pwd, nominated)
}

// Responses don't need a nomination bit, but for now we include it because it's easier for writing tests.
pub fn create_binding_response_packet(
    transaction_id: &TransactionId,
    username: &[u8],
    pwd: &[u8],
    nominated: bool,
) -> Vec<u8> {
    create_packet(
        BINDING_RESPONSE_ID,
        transaction_id,
        username,
        pwd,
        nominated,
    )
}

fn create_packet(
    message_type: [u8; 2],
    transaction_id: &TransactionId,
    username: &[u8],
    pwd: &[u8],
    nominated: bool,
) -> Vec<u8> {
    let username = write_stun_attribute(AttributeId::USERNAME, username);
    let nomination = if nominated {
        Some(write_stun_attribute(AttributeId::NOMINATION, Empty {}))
    } else {
        None
    };
    let hmaced_attrs = (username, nomination);
    let hmaced_attrs_len = hmaced_attrs.written_len();
    let dummy_hmac = write_stun_attribute(AttributeId::MESSAGE_INTEGRITY, [0u8; HMAC_LEN]);
    let fingerprinted_attrs = (hmaced_attrs, dummy_hmac);
    let fingerprinted_attrs_len = fingerprinted_attrs.written_len();
    let dummy_fingerprint = write_stun_attribute(AttributeId::FINGERPRINT, 0u32);
    let attrs = (fingerprinted_attrs, dummy_fingerprint);
    let attrs_len = attrs.written_len();
    let header = (message_type, attrs_len as u16, transaction_id);
    let header_len = header.written_len();
    let mut packet = (header, attrs).to_vec();

    let write_len_in_header = |packet: &mut [u8], len: usize| {
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    };

    let write_value_in_attr =
        |packet: &mut [u8], attr_start_relative_to_body: usize, value: &[u8]| {
            packet[header_len + attr_start_relative_to_body + ATTR_HEADER_LEN..][..value.len()]
                .copy_from_slice(value);
        };

    // ICE HMACs are strange in that they are computed without the HMAC attribute,
    // but are computed with a length that includes the HMAC attribute.
    write_len_in_header(&mut packet, fingerprinted_attrs_len);
    let hmac_value = {
        let mut hmac = Hmac::<Sha1>::new_from_slice(pwd).expect("All key lengths are valid");
        hmac.update(&packet[..header_len + hmaced_attrs_len]);
        hmac.finalize().into_bytes()
    };
    write_value_in_attr(&mut packet, hmaced_attrs_len, &hmac_value);

    write_len_in_header(&mut packet, attrs_len);
    let fingerprint_value =
        FINGERPRINT_XOR_VALUE ^ CRC32.checksum(&packet[..header_len + fingerprinted_attrs_len]);
    write_value_in_attr(
        &mut packet,
        fingerprinted_attrs_len,
        &fingerprint_value.to_be_bytes(),
    );

    packet
}

fn write_stun_attribute(attribute_id: u16, value: impl Writer) -> impl Writer {
    let value_len = value.written_len();
    let padded_len = round_up_to_multiple_of::<4>(value_len);
    let padding_len = padded_len - value_len;

    let value_len =
        u16::try_from(value.written_len()).expect("STUN attribute is less than u16::MAX in len.");
    let padding = vec![0u8; padding_len];
    (attribute_id, value_len, value, padding)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn check_crc32() {
        let packet = hex!("3e21c9b1b27f576e3a4b516b8298451f");

        // Make sure the crc algorithm is the same as the legacy checksum_ieee().
        assert_eq!(CRC32.checksum(&packet[..]), 4010254265);
    }

    #[test]
    fn test_join_username() {
        assert_eq!(b"B:A".to_vec(), join_username(b"A", b"B"));
        assert_eq!(b"DEF:ABC".to_vec(), join_username(b"ABC", b"DEF"));
    }

    #[test]
    fn test_create_ice_packets() {
        let transaction_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let request_username = b"server:client";
        let response_username = b"client:server";
        let pwd = b"this should be a long pwd";
        let nominated = true;
        let expected_request: &[u8] = &hex!(
            "
     /* header */ 0001 0038 0102030405060708090a0b0c0d0e0f10
   /* username */ 0006 000D 7365727665723a636c69656e74000000
 /* nomination */ 0025 0000
       /* hmac */ 0008 0014 73df552e08ec7ceef7f2056411ec82115ba1198e
/* fingerprint */ 8028 0004 f2273ea4
             "
        );
        assert_eq!(
            expected_request,
            create_binding_request_packet(&transaction_id, request_username, pwd, nominated)
        );

        let nominated = false;
        let expected_response: &[u8] = &hex!(
            "
     /* header */ 0101 0034 0102030405060708090a0b0c0d0e0f10
   /* username */ 0006 000D 636c69656e743a736572766572000000
       /* hmac */ 0008 0014 b7e18a20e28e82c1f0168c223b6e8c2cab599e2e
/* fingerprint */ 8028 0004 dedaa207
            "
        );

        assert_eq!(
            expected_response,
            create_binding_response_packet(&transaction_id, response_username, pwd, nominated)
        );
    }

    mod header_identification_tests {
        use hex_literal::hex;

        use super::BindingRequest;

        #[test]
        fn looks_like_binding_request_header() {
            assert!(BindingRequest::looks_like_header(&hex!(
                "0001 0000 2112A442"
            )));
            assert!(BindingRequest::looks_like_header(&hex!(
                "0001 FFFF 2112A442"
            )));
            assert!(BindingRequest::looks_like_header(&hex!(
                "0001 0000 2112A442 01"
            )));
            assert!(BindingRequest::looks_like_header(&hex!(
                "0001 FFFF 2112A442 0102"
            )));
        }

        #[test]
        fn does_not_look_like_binding_request_header() {
            assert!(
                !BindingRequest::looks_like_header(&hex!("0001 0000 2112A4")),
                "Too short"
            );
            assert!(
                !BindingRequest::looks_like_header(&hex!("0101 0000 2112A442")),
                "Wrong first byte"
            );
            assert!(
                !BindingRequest::looks_like_header(&hex!("0002 0000 2112A442")),
                "Wrong second byte"
            );
            assert!(
                !BindingRequest::looks_like_header(&hex!("0001 0000 FF12A442")),
                "Wrong first byte of magic"
            );
            assert!(
                !BindingRequest::looks_like_header(&hex!("0001 0000 2112A4FF")),
                "Wrong last byte of magic"
            );
        }
    }

    mod parse_binding_requests_failure_tests {
        use hex_literal::hex;

        use super::{BindingRequest, ParseError};

        #[test]
        fn prevent_empty_packet() {
            assert_eq!(
                Some(ParseError::IncompleteHeader(0)),
                BindingRequest::parse(&[]).err()
            );
        }

        #[test]
        fn prevent_incomplete_header() {
            let packet: &[u8] = &hex!("0001 004c 2112a4422b6a714565766478326f5a");
            assert_eq!(
                Some(ParseError::IncompleteHeader(19)),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_header_only() {
            let packet: &[u8] = &hex!("0001 0000 2112a44271536e422b33695952394469");
            assert_eq!(
                Some(ParseError::MissingUsernameAttribute),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_missing_username() {
            let packet: &[u8] = &hex!(
                "
                  0001 0040 2112a44271536e422b33695952394469
   /* username */ // 0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014749225e1798cdcf19c72a48d36b8de0da89effb6
                  8028 000456d8838f
                "
            );
            assert_eq!(
                Some(ParseError::MissingUsernameAttribute),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_missing_hmac() {
            let packet: &[u8] = &hex!(
                "
                  0001 004c 2112a4422b6a714565766478326f5a55
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ // 0008 0014749225e1798cdcf19c72a48d36b8de0da89effb6
/* fingerprint */ // 8028 000456d8838f
                "
            );
            assert_eq!(
                Some(ParseError::MissingHMacAttribute),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_missing_fingerprint() {
            let packet: &[u8] = &hex!(
                "
                  0001 0064 2112a442535a6370696c496c46696d33
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 4ac4f93cd6809b35be287203a673b3033b2769da
/* fingerprint */ // 8028 000456d8838f
                "
            );
            assert_eq!(
                Some(ParseError::MissingFingerprintAttribute),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_fingerprint_before_hmac() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a44238656d797950694b78506e6e
                  0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
/* fingerprint */ 8028 0004 d48fbba0
       /* hmac */ 0008 0014 5be1331d09c86d8cbfaf48f64687669096d32d3b
                "
            );
            assert_eq!(
                Some(ParseError::FingerprintBeforeHMac),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_wrong_hmac_length() {
            let packet: &[u8] = &hex!(
                "
                  0001 0068 2112a442516b77624e657155454a4635
                  0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0010 4de1e857695f0804f5f8e9fcf3150977
                  8028 0004 b7b01d0b
                "
            );
            assert_eq!(
                Some(ParseError::WrongHMacLength(16, 20)),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_something_between_hmac_and_fingerprint() {
            let packet: &[u8] = &hex!(
                "
                  0001 0070 2112a442656b72774b55515041495476
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 d385d7f2f2222979333c405cea0b291444592aca
                  abcd 0000
/* fingerprint */ 8028 000429560496
                "
            );
            assert_eq!(
                Some(ParseError::ExpectedFingerprint(0xabcd)),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_appending_1_byte_to_packet() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442665175732f33426771346c7a
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92
/* fingerprint */ 8028 0004 1698f47f
                  00 // appended 1 bytes past declared message length
                "
            );
            assert_eq!(
                Some(ParseError::DeclaredMessageLengthMismatch(
                    0x006c,
                    0x006c + 1
                )),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_appending_whole_attribute_to_packet() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442665175732f33426771346c7a
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92
/* fingerprint */ 8028 0004 1698f47f
                  abcd 0000 // appended 4 bytes past declared message length
                "
            );
            assert_eq!(
                Some(ParseError::DeclaredMessageLengthMismatch(
                    0x006c,
                    0x006c + 4
                )),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_attribute_after_fingerprint_within_declared_message_length() {
            let packet: &[u8] = &hex!(
                "
                  0001 0070 2112a442665175732f33426771346c7a
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92
/* fingerprint */ 8028 0004 1698f47f
                  abcd 0000
                "
            );
            assert_eq!(
                Some(ParseError::AttributeAfterFingerprint(0xabcd)),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_attribute_past_end_of_packet() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442665175732f33426771346c7a
   /* Too long */ 0006 0069 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92
                  8028 0004 1698f47f
                "
            );
            assert_eq!(
                Some(ParseError::AttributeRangePastPacketEnd(0x0006, 1)),
                BindingRequest::parse(packet).err()
            );
        }

        #[test]
        fn prevent_wrong_length_fingerprint() {
            let packet: &[u8] = &hex!(
                "
                  0001 006b 2112a442665175732f33426771346c7a
                  0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
                  0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92
/* fingerprint */ 8028 0003 1698f4
                "
            );
            assert_eq!(
                Some(ParseError::WrongFingerprintLength(3, 4)),
                BindingRequest::parse(packet).err()
            );
        }
    }

    mod parse_binding_request_tests {
        use hex_literal::hex;

        use super::*;

        #[test]
        fn parse_with_nomination() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a44238656d797950694b78506e6e
   /* username */ 0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
  /* nominated */ 0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 5be1331d09c86d8cbfaf48f64687669096d32d3b
/* fingerprint */ 8028 0004 d48fbba0
                "
            );
            let packet = BindingRequest::parse(packet).expect("Parsed");
            assert!(packet.nominated());
            assert_eq!(
                hex!("63636431623031363037303065383364616232386435303135636563346362653a31315453"),
                packet.username()
            );
            assert_eq!(
                hex!("5be1331d09c86d8cbfaf48f64687669096d32d3b"),
                packet.hmac()
            );
            assert_eq!(hex!("d48fbba0"), packet.fingerprint());
        }

        #[test]
        fn parse_without_nomination() {
            let packet: &[u8] = &hex!(
                "
                  0001 0068 2112a44271536e422b33695952394469
   /* username */ 0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 749225e1798cdcf19c72a48d36b8de0da89effb6
/* fingerprint */ 8028 0004 56d8838f
                "
            );
            let packet = BindingRequest::parse(packet).expect("Parsed");
            assert!(!packet.nominated());
            assert_eq!(
                hex!("63636431623031363037303065383364616232386435303135636563346362653a31315453"),
                packet.username()
            );
            assert_eq!(
                hex!("749225e1798cdcf19c72a48d36b8de0da89effb6"),
                packet.hmac()
            );
            assert_eq!(hex!("56d8838f"), packet.fingerprint());
        }
    }

    mod hmac_verification_tests {
        use hex_literal::hex;

        use super::BindingRequest;

        #[test]
        fn hmac_verify() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442716e517877595a6c5853332f
                  0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 f2929850b442ffc08489031630696a4473534113
/* fingerprint */ 8028 0004 4654be07
                "
            );

            let ice_packet = BindingRequest::parse(packet).expect("Parsed");

            assert!(ice_packet
                .verify_hmac(b"000102030405060708090a0b0c0d0e0f")
                .is_ok());

            assert!(
                ice_packet
                    .verify_hmac(b"0102030405060708090a0b0c0d0e0f10")
                    .is_err(),
                "Should not verify with another password"
            );
        }

        #[test]
        fn hmac_does_not_verify_if_packet_manipulated() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442716e517877595a6c5853332f
                  0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010033
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 f2929850b442ffc08489031630696a4473534113
/* fingerprint */ 8028 0004 4654be07
                "
            );

            let ice_packet = BindingRequest::parse(packet).expect("Parsed");

            assert!(ice_packet
                .verify_hmac(b"000102030405060708090a0b0c0d0e0f")
                .is_err());
        }

        #[test]
        fn hmac_does_not_verify_if_hmac_modified_in_packet() {
            let packet: &[u8] = &hex!(
                "
                  0001 006c 2112a442716e517877595a6c5853332f
                  0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 f66e672cbb22165d
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 f2929850b442ffc08489031630696a4473534114
/* fingerprint */ 8028 0004 4654be07
                "
            );

            let ice_packet = BindingRequest::parse(packet).expect("Parsed");

            assert!(ice_packet
                .verify_hmac(b"000102030405060708090a0b0c0d0e0f")
                .is_err());
        }
    }

    #[test]
    fn create_a_verified_binding_response_from_a_binding_request() {
        let packet = &hex!(
            "
     /* header */ 0001 006c 2112a442656b72774b55515041495476
   /* username */ 0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 4dc36c18cad0520147769290da6ec1c8996355b0
/* fingerprint */ 8028 0004 8eff8489
            "
        );

        let response_packet = BindingRequest::parse(packet)
            .expect("Parsed")
            .verify_hmac(b"000102030405060708090a0b0c0d0e0f")
            .expect("Verified")
            .to_binding_response(
                &hex!("63636431623031363037303065383364616232386435303135636563346362653a31315453"),
                b"0102030405060708090a0b0c0d0e0f10",
            );

        let expected_response: &[u8] = &hex!(
            "
     /* header */ 0101 006c 2112a442656b72774b55515041495476
   /* username */ 0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000
                  c057 0004 00010032
                  802a 0008 eef8294dc5f11c9c
                  0025 0000
                  0024 0004 6e7f1eff
       /* hmac */ 0008 0014 b615c21d9e81e3786dbf40a5ad3825d2f39fbb37
/* fingerprint */ 8028 0004 137e0acf
            "
        );
        assert_eq!(expected_response, &response_packet);
    }
}
