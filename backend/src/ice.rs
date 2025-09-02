//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    array::TryFromSliceError,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, Range},
};

use calling_common::{
    parse_u16, parse_u32, random_base64_string_of_length_32, random_base64_string_of_length_4,
    round_up_to_multiple_of,
};
use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{Hmac, Mac};
use log::*;
use sha1::Sha1;
use thiserror::Error;

const HEADER_LEN: usize = 20;
const HMAC_LEN: usize = 20;
const FINGERPRINT_LEN: usize = 4;
const PRIORITY_LEN: usize = 4;
const NOMINATION_LEN: usize = 0;
const ICE_CONTROLLING_LEN: usize = 8;
const ICE_CONTROLLED_LEN: usize = 8;
const ATTR_HEADER_LEN: usize = 4;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub struct AttributeId;

impl AttributeId {
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLED: u16 = 0x8029;
    pub const ICE_CONTROLLING: u16 = 0x802A;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const PRIORITY: u16 = 0x0024;
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const ERROR_CODE: u16 = 0x0009;
}

fn attr_name(attr_id: u16) -> &'static str {
    match attr_id {
        AttributeId::USERNAME => "USERNAME",
        AttributeId::MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY",
        AttributeId::SOFTWARE => "SOFTWARE",
        AttributeId::FINGERPRINT => "FINGERPRINT",
        AttributeId::ICE_CONTROLLED => "ICE-CONTROLLED",
        AttributeId::ICE_CONTROLLING => "ICE-CONTROLLING",
        AttributeId::USE_CANDIDATE => "USE-CANDIDATE",
        AttributeId::PRIORITY => "PRIORITY",
        AttributeId::MAPPED_ADDRESS => "MAPPED-ADDRESS",
        AttributeId::XOR_MAPPED_ADDRESS => "XOR-MAPPED-ADDRESS",
        AttributeId::ERROR_CODE => "ERROR-CODE",
        _ => "(unknown attribute)",
    }
}

const FINGERPRINT_XOR_VALUE: u32 = 0x5354554E;

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
    #[error("ICE binding request has no priority.")]
    MissingPriorityAttribute,
    #[error("ICE binding request message length was declared as {0:#06x} but was {1:#06x}.")]
    DeclaredMessageLengthMismatch(usize, usize),
    #[error("ICE binding request hmac length was {0} but expected {1}.")]
    WrongHMacLength(u16, u16),
    #[error("ICE binding request fingerprint length was {0} but expected {1}.")]
    WrongFingerprintLength(u16, u16),
    #[error("ICE binding request fingerprint seen before hmac")]
    FingerprintBeforeHMac,
    #[error("ICE binding request priority length was {0} but expected {1}.")]
    WrongPriorityLength(u16, u16),
    #[error("ICE binding request saw attribute {0:#06x} but expected fingerprint.")]
    ExpectedFingerprint(u16),
    #[error("ICE binding request saw attribute {0:#06x} after the fingerprint.")]
    AttributeAfterFingerprint(u16),
    #[error("ICE binding request attribute {0:#06x} is {1} bytes past packet end.")]
    AttributeRangePastPacketEnd(u16, usize),
    #[error("Unknown STUN attribute {0:#06x}")]
    UnknownAttribute(u16),
    #[error("Attribute {0:#06x} not present in packet")]
    FailedToParseAttribute(u16),
    #[error("HMAC validation failure")]
    HmacValidationFailure,
    #[error("Attribute {0:#06x} length is invalid. Expected {1} but got {2}")]
    InvalidAttributeLength(u16, u16, u16),
    #[error("ICE packet has no attributes")]
    PacketHasNoAttributes,
    #[error("Contradicting ICE role attributes")]
    ContradictingICERoleAttributes,
    #[error("Type mismatch")]
    TypeMismatch,
}

pub fn random_ufrag() -> String {
    random_base64_string_of_length_4()
}

pub fn random_pwd() -> String {
    random_base64_string_of_length_32()
}

pub fn join_username(sender_ufrag: &[u8], receiver_ufrag: &[u8]) -> Vec<u8> {
    [receiver_ufrag, sender_ufrag].join(b":".as_ref())
}

/// STUN transaction identifier.
///
/// The transaction ID MUST be uniformly and randomly distributed between 0 and 2**96 - 1.
/// The large range is needed because the transaction ID serves as a form  of randomization,
/// helping to prevent replays of previously signed responses from the server.
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    pub fn new() -> Self {
        rand::random::<u128>().into()
    }
}

impl Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for TransactionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for TransactionId {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

#[cfg(not(test))]
impl From<u128> for TransactionId {
    fn from(value: u128) -> Self {
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(&value.to_ne_bytes()[4..]);
        Self(bytes)
    }
}

// u128 is used to generate sequential transaction IDs during testing. These numbers are almost
// always small. Since we'll be converting from a 128-bit number to a 96-bit number we'll have
// to ensure that we strip off the most significant bits.
#[cfg(test)]
impl From<u128> for TransactionId {
    #[cfg(target_endian = "big")]
    fn from(value: u128) -> Self {
        value.to_le_bytes().into()
    }

    #[cfg(target_endian = "little")]
    fn from(value: u128) -> Self {
        let x = value.to_be_bytes();
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(&x[4..]);
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct PacketType([u8; 2]);

impl PacketType {
    const BINDING_REQUEST: PacketType = PacketType([0x00, 0x01]);
    const BINDING_RESPONSE: PacketType = PacketType([0x01, 0x01]);
}

impl Deref for PacketType {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 2]> for PacketType {
    fn from(value: [u8; 2]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 2]> for PacketType {
    fn from(value: &[u8; 2]) -> Self {
        Self(*value)
    }
}

impl TryFrom<&[u8]> for PacketType {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

// Internal STUN attribute iterator.
struct StunAttributeIterator<'a> {
    packet: &'a [u8],
    pos: usize,
}

impl<'a> StunAttributeIterator<'a> {
    pub fn new(packet: &'a [u8]) -> Result<Self, ParseError> {
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

        Ok(Self {
            packet,
            pos: HEADER_LEN,
        })
    }
}

impl Iterator for StunAttributeIterator<'_> {
    type Item = Result<(u16, Range<usize>), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + ATTR_HEADER_LEN <= self.packet.len() {
            let header = &self.packet[self.pos..][..ATTR_HEADER_LEN];
            let id = parse_u16(&header[0..2]);
            let len = parse_u16(&header[2..4]);
            let val_start = self.pos + ATTR_HEADER_LEN;
            let val_end = val_start + len as usize;
            let range = val_start..val_end;
            if range.end > self.packet.len() {
                Some(Err(ParseError::AttributeRangePastPacketEnd(
                    id,
                    range.end - self.packet.len(),
                )))
            } else {
                self.pos += ATTR_HEADER_LEN + round_up_to_multiple_of::<4>(len.into());
                Some(Ok((id, range)))
            }
        } else {
            None
        }
    }
}

// Internal STUN attribute iterator. Does not perform any consistency checks.
// Make sure that the entire packet is sane before using this iterator.
struct UnsafeStunAttributeIterator<'a> {
    packet: &'a [u8],
    pos: usize,
}

impl<'a> UnsafeStunAttributeIterator<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        Self {
            packet,
            pos: HEADER_LEN,
        }
    }
}

impl Iterator for UnsafeStunAttributeIterator<'_> {
    type Item = (u16, Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + ATTR_HEADER_LEN <= self.packet.len() {
            let header = &self.packet[self.pos..][..ATTR_HEADER_LEN];
            let id = parse_u16(&header[0..2]);
            let len = parse_u16(&header[2..4]);
            let val_start = self.pos + ATTR_HEADER_LEN;
            let val_end = val_start + len as usize;
            let range = val_start..val_end;
            self.pos += ATTR_HEADER_LEN + round_up_to_multiple_of::<4>(len.into());
            Some((id, range))
        } else {
            None
        }
    }
}

/// Simple STUN packet builder. Currently, this builder does not prevent the user from
/// creating meaningless packets. In other words, it will let you add fields that are
/// or may be inappropriate for the packet type that is being built.
pub struct StunPacketBuilder {
    buffer: Vec<u8>,
}

impl StunPacketBuilder {
    // Start out with a 1k buffer. Probably overkill.
    const INITIAL_BUFFER_SIZE: usize = 1024;

    fn new(transaction_id: &TransactionId, packet_type: &PacketType) -> Self {
        let mut buffer = Vec::with_capacity(Self::INITIAL_BUFFER_SIZE);
        buffer.extend_from_slice(packet_type);
        buffer.extend_from_slice(&[0u8, 0u8]);
        buffer.extend_from_slice(&MAGIC_COOKIE);
        buffer.extend_from_slice(transaction_id);
        Self { buffer }
    }

    pub fn new_binding_request(transaction_id: &TransactionId) -> Self {
        Self::new(transaction_id, &PacketType::BINDING_REQUEST)
    }

    pub fn new_binding_response(transaction_id: &TransactionId) -> Self {
        Self::new(transaction_id, &PacketType::BINDING_RESPONSE)
    }

    fn transaction_id(&self) -> &[u8] {
        &self.buffer[8..20]
    }

    /// Appends a MAPPED-ADDRESS attribute.
    pub fn set_mapped_address(mut self, addr: &SocketAddr) -> Self {
        // [ RFC 8489 ]
        //
        // The MAPPED-ADDRESS attribute indicates a reflexive transport address
        // of the client.  It consists of an 8-bit address family and a 16-bit
        // port, followed by a fixed-length value representing the IP address.
        // If the address family is IPv4, the address MUST be 32 bits.  If the
        // address family is IPv6, the address MUST be 128 bits.  All fields
        // must be in network byte order.
        //
        // The format of the MAPPED-ADDRESS attribute is:
        //
        //    0                   1                   2                   3
        //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   |0 0 0 0 0 0 0 0|    Family     |           Port                |
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   |                                                               |
        //   |                 Address (32 bits or 128 bits)                 |
        //   |                                                               |
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //
        // The address family can take on the following values:
        //
        // 0x01:IPv4
        // 0x02:IPv6
        //
        // The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
        // ignored by receivers.  These bits are present for aligning parameters
        // on natural 32-bit boundaries.

        let (buffer, rng) = match addr {
            SocketAddr::V4(addr) => {
                let mut buffer: [u8; 20] = [0; 20];
                buffer[4..8].copy_from_slice(&addr.ip().to_bits().to_be_bytes());
                buffer[2..4].copy_from_slice(&addr.port().to_be_bytes());
                buffer[1] = 1;
                (buffer, 0..8)
            }
            SocketAddr::V6(addr) => {
                let mut buffer: [u8; 20] = [0; 20];
                buffer[4..20].copy_from_slice(&addr.ip().to_bits().to_be_bytes());
                buffer[2..4].copy_from_slice(&addr.port().to_be_bytes());
                buffer[1] = 2;
                (buffer, 0..20)
            }
        };

        self.append_attribute(AttributeId::MAPPED_ADDRESS, &buffer[rng]);
        self
    }

    /// Appends a XOR-MAPPED-ADDRESS attribute.
    pub fn set_xor_mapped_address(mut self, addr: &SocketAddr) -> Self {
        // [ RFC 8489 ]
        //
        // The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
        // attribute, except that the reflexive transport address is obfuscated
        // through the XOR function.
        //
        // The format of the XOR-MAPPED-ADDRESS is:
        //
        //    0                   1                   2                   3
        //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   |0 0 0 0 0 0 0 0|    Family     |         X-Port                |
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //   |                X-Address (Variable)
        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //
        // The Family field represents the IP address family and is encoded
        // identically to the Family field in MAPPED-ADDRESS.
        //
        // X-Port is computed by XOR'ing the mapped port with the most
        // significant 16 bits of the magic cookie.  If the IP address family is
        // IPv4, X-Address is computed by XOR'ing the mapped IP address with the
        // magic cookie.  If the IP address family is IPv6, X-Address is
        // computed by XOR'ing the mapped IP address with the concatenation of
        // the magic cookie and the 96-bit transaction ID.  In all cases, the
        // XOR operation works on its inputs in network byte order (that is, the
        // order they will be encoded in the message).
        const XOR_IPV4: u32 = u32::from_ne_bytes(MAGIC_COOKIE);
        const XOR_PORT: u16 = u16::from_ne_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);

        let port = u16::to_be(addr.port()) ^ XOR_PORT;

        let (buffer, rng) = match addr {
            SocketAddr::V4(addr) => {
                let mut buffer: [u8; 20] = [0; 20];
                let ip = u32::to_be(addr.ip().to_bits()) ^ XOR_IPV4;
                buffer[4..8].copy_from_slice(&ip.to_ne_bytes());
                buffer[2..4].copy_from_slice(&port.to_ne_bytes());
                buffer[1] = 1;
                (buffer, 0..8)
            }
            SocketAddr::V6(addr) => {
                let mut buffer: [u8; 20] = [0; 20];
                let mut xor_bytes = [0u8; 16];
                xor_bytes[..4].copy_from_slice(&MAGIC_COOKIE);
                xor_bytes[4..].copy_from_slice(self.transaction_id());
                let ip = u128::to_be(addr.ip().to_bits()) ^ u128::from_ne_bytes(xor_bytes);
                buffer[4..20].copy_from_slice(&ip.to_ne_bytes());
                buffer[2..4].copy_from_slice(&port.to_ne_bytes());
                buffer[1] = 2;
                (buffer, 0..20)
            }
        };

        self.append_attribute(AttributeId::XOR_MAPPED_ADDRESS, &buffer[rng]);
        self
    }

    /// Appends the ERROR-CODE attribute.
    pub fn set_error_code(mut self, error_code: u16) -> Self {
        // [ RFC 8489 ]
        //
        // The ERROR-CODE attribute is used in error response messages.  It
        // contains a numeric error code value in the range of 300 to 699 plus a
        // textual reason phrase encoded in UTF-8 [RFC3629], and is consistent
        // in its code assignments and semantics with SIP [RFC3261] and HTTP
        // [RFC2616].  The reason phrase is meant for user consumption, and can
        // be anything appropriate for the error code.  Recommended reason
        // phrases for the defined error codes are included in the IANA registry
        // for error codes.  The reason phrase MUST be a UTF-8 [RFC3629] encoded
        // sequence of less than 128 characters (which can be as long as 763
        // bytes).
        //
        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |           Reserved, should be 0         |Class|     Number    |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |      Reason Phrase (variable)                                ..
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        let class = error_code / 100;
        let number = error_code - (class * 100);
        self.append_attribute(
            AttributeId::ERROR_CODE,
            &(class << 8 | number).to_be_bytes(),
        );
        self
    }

    pub fn set_nomination(mut self) -> Self {
        // [ RFC 8445 ]
        //
        // The controlling agent MUST include the USE-CANDIDATE attribute in
        // order to nominate a candidate pair (Section 8.1.1).  The controlled
        // agent MUST NOT include the USE-CANDIDATE attribute in a Binding
        // request.
        self.append_attribute(AttributeId::USE_CANDIDATE, &[]);
        self
    }

    pub fn set_priority(mut self, priority: u32) -> Self {
        // [ RFC 8445 ]
        //
        // The PRIORITY attribute MUST be included in a Binding request and be
        // set to the value computed by the algorithm in Section 5.1.2 for the
        // local candidate, but with the candidate type preference of peer-
        // reflexive candidates.
        self.append_attribute(AttributeId::PRIORITY, &priority.to_be_bytes());
        self
    }

    pub fn set_username(mut self, username: &[u8]) -> Self {
        self.append_attribute(AttributeId::USERNAME, username);
        self
    }

    pub fn append_attribute(&mut self, id: u16, value: &[u8]) {
        let len = value.len();
        self.buffer.extend_from_slice(&id.to_be_bytes());
        self.buffer.extend_from_slice(&(len as u16).to_be_bytes());
        self.buffer.extend_from_slice(value);
        self.buffer.resize(
            self.buffer.len() + round_up_to_multiple_of::<4>(len) - len,
            0,
        );
    }

    /// Builds the STUN packet and returns a vector with the packet's on-wire representation. This
    /// method will generate the MESSAGE-INTEGRITY and FINGERPRINT attributes and add them to
    /// the packet.
    pub fn build(mut self, pwd: &[u8]) -> Vec<u8> {
        // [ RFC 8489 ]
        //
        // The text used as input to HMAC is the STUN message, up to and
        // including the attribute preceding the MESSAGE-INTEGRITY attribute.
        // The Length field of the STUN message header is adjusted to point to
        // the end of the MESSAGE-INTEGRITY attribute.  The value of the
        // MESSAGE-INTEGRITY attribute is set to a dummy value.
        let hmac_calc_len = self.buffer.len() + HMAC_LEN + ATTR_HEADER_LEN - HEADER_LEN;
        let mut hmac = Hmac::<Sha1>::new_from_slice(pwd).expect("All key lengths are valid");
        hmac.update(&self.buffer[0..2]);
        hmac.update(&(hmac_calc_len as u16).to_be_bytes());
        hmac.update(&self.buffer[4..]);
        let attr_val = &hmac.finalize().into_bytes();
        self.append_attribute(AttributeId::MESSAGE_INTEGRITY, attr_val);

        // Calculate and append the fingerprint
        //
        // [ RFC 8489 ]
        //
        // The value of the attribute is computed as the CRC-32 of the STUN
        // message up to (but excluding) the FINGERPRINT attribute itself,
        // XOR'ed with the 32-bit value 0x5354554e.  (The XOR operation ensures
        // that the FINGERPRINT test will not report a false positive on a
        // packet containing a CRC-32 generated by an application protocol.)
        // The 32-bit CRC is the one defined in ITU V.42 [ITU.V42.2002], which
        // has a generator polynomial of x^32 + x^26 + x^23 + x^22 + x^16 + x^12
        // + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.  See the sample
        // code for the CRC-32 in Section 8 of [RFC1952].
        //
        // When present, the FINGERPRINT attribute MUST be the last attribute in
        // the message and thus will appear after MESSAGE-INTEGRITY and MESSAGE-
        // INTEGRITY-SHA256.
        //
        // ...
        //
        // As with MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256, the CRC used
        // in the FINGERPRINT attribute covers the Length field from the STUN
        // message header.  Therefore, prior to computation of the CRC, this
        // value must be correct and include the CRC attribute as part of the
        // message length.
        let len = (self.buffer.len() + FINGERPRINT_LEN + ATTR_HEADER_LEN - HEADER_LEN) as u16;
        self.buffer[2..4].copy_from_slice(&len.to_be_bytes());
        self.append_attribute(
            AttributeId::FINGERPRINT,
            &(FINGERPRINT_XOR_VALUE ^ CRC32.checksum(&self.buffer)).to_be_bytes(),
        );

        // Finally, set the packet length.
        let len = (self.buffer.len() - HEADER_LEN) as u16;
        self.buffer[2..4].copy_from_slice(&len.to_be_bytes());

        self.buffer
    }
}

fn check_attr_len(attr_id: u16, len: usize, rng: Range<usize>) -> Result<(), ParseError> {
    if len == rng.len() {
        Ok(())
    } else {
        Err(ParseError::InvalidAttributeLength(
            attr_id,
            len as u16,
            rng.len() as u16,
        ))
    }
}

// Determines the header length of an address field (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, ...).
fn get_address_header_len(attr_id: u16, attr_val: &[u8]) -> Result<usize, ParseError> {
    if attr_val.len() < 8 {
        Err(ParseError::InvalidAttributeLength(
            attr_id,
            8,
            attr_val.len() as u16,
        ))
    } else {
        // 1 ---> IPv4 (1 res + 1 type + 2 port +  4 ip)
        // 2 ---> IPv6 (1 res + 1 type + 2 port + 16 ip)
        match attr_val[1] {
            1 => Ok(8),
            2 => Ok(20),
            _ => Err(ParseError::FailedToParseAttribute(attr_id)),
        }
    }
}

/// Simple STUN packet buffer wrapper that provides methods for querying and extracting
/// values from a STUN packet. See [`BindingRequest`] and [`BindingResponse`] for more
/// specialized access to STUN packets.
#[derive(Debug)]
pub struct StunPacket<'a> {
    packet: &'a [u8],
}

impl<'a> StunPacket<'a> {
    /// Wraps the given packet into a StunPacket instance.
    ///
    /// This function will perform basic sanity checks on all STUN attributes in the packet and it will
    /// ensure that the MESSAGE-INTEGRITY and FINGERPRINT attributes appear in the correct order,
    /// if they are present.
    ///
    /// For the attributes for which accessors are provided (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS,
    /// PRIORITY, USE-CANDIDATE, FINGERPRINT, ICE-CONTROLLING, ICE-CONTROLLED, and MESSAGE-INTEGRITY)
    /// additional length checks are performed  (i.e. they are not dynamic and have predefined lengths.)
    pub fn from_buffer(packet: &'a [u8]) -> Result<Self, ParseError> {
        Self::sanity_check(packet)?;
        Ok(Self { packet })
    }

    #[cfg(test)]
    pub fn from_buffer_without_sanity_check(packet: &'a [u8]) -> Self {
        Self { packet }
    }

    /// This function will perform basic sanity checks on all STUN attributes in the packet and it will
    /// ensure that the MESSAGE-INTEGRITY and FINGERPRINT attributes appear in the correct order,
    /// if they are present.
    ///
    /// For the attributes for which accessors are provided (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS,
    /// PRIORITY, USE-CANDIDATE, FINGERPRINT, ICE-CONTROLLING, ICE-CONTROLLED, and MESSAGE-INTEGRITY)
    /// additional length checks are performed  (i.e. they are not dynamic and have predefined lengths.)
    pub fn sanity_check(packet: &'a [u8]) -> Result<(), ParseError> {
        let mut iter = StunAttributeIterator::new(packet)?;
        let mut attr_cnt = 0;
        let mut ice_controlling = false;
        let mut ice_controlled = false;

        for v in iter.by_ref() {
            attr_cnt += 1;
            match v {
                Ok((attr_id, attr_rng)) => match attr_id {
                    AttributeId::FINGERPRINT => return Err(ParseError::FingerprintBeforeHMac),
                    AttributeId::MESSAGE_INTEGRITY => {
                        check_attr_len(attr_id, HMAC_LEN, attr_rng)?;
                        break;
                    }
                    AttributeId::PRIORITY => {
                        check_attr_len(attr_id, PRIORITY_LEN, attr_rng)?;
                    }
                    AttributeId::USE_CANDIDATE => {
                        check_attr_len(attr_id, NOMINATION_LEN, attr_rng)?;
                    }
                    AttributeId::ICE_CONTROLLING => {
                        check_attr_len(attr_id, ICE_CONTROLLING_LEN, attr_rng)?;
                        ice_controlling = true;
                    }
                    AttributeId::ICE_CONTROLLED => {
                        check_attr_len(attr_id, ICE_CONTROLLED_LEN, attr_rng)?;
                        ice_controlled = true;
                    }
                    AttributeId::XOR_MAPPED_ADDRESS | AttributeId::MAPPED_ADDRESS => {
                        let len = get_address_header_len(attr_id, &packet[attr_rng.clone()])?;
                        check_attr_len(attr_id, len, attr_rng)?;
                    }
                    _ => {
                        // Any other attribute type we accept as-is.
                    }
                },
                Err(e) => return Err(e),
            }
        }

        if attr_cnt == 0 {
            return Err(ParseError::PacketHasNoAttributes);
        }
        if ice_controlling && ice_controlled {
            return Err(ParseError::ContradictingICERoleAttributes);
        }

        // If this is not a malformed STUN packet then either there is no next attribute or the
        // next attribute is a FINGERPRINT attribute, not followed by any more attributes.
        match iter.next() {
            Some(Ok((attr_id, attr_rng))) if attr_id == AttributeId::FINGERPRINT => {
                check_attr_len(attr_id, FINGERPRINT_LEN, attr_rng)?;
                // There should be nothing following this attribute.
                match iter.next() {
                    Some(Ok((attr_id, _))) => Err(ParseError::AttributeAfterFingerprint(attr_id)),
                    Some(Err(e)) => Err(e),
                    None => Ok(()),
                }
            }
            Some(Ok((attr_id, _))) => Err(ParseError::ExpectedFingerprint(attr_id)),
            Some(Err(e)) => Err(e),
            None => Ok(()),
        }
    }

    pub fn verify_integrity(&self, pwd: &[u8]) -> Result<(), ParseError> {
        self.find_attr_range(AttributeId::MESSAGE_INTEGRITY).map_or(
            Err(ParseError::MissingHMacAttribute),
            |range| {
                let mut mac = Hmac::<Sha1>::new_from_slice(pwd).expect("all key lengths are valid");
                mac.update(&self.packet[0..2]);
                mac.update(&((range.end - HEADER_LEN) as u16).to_be_bytes());
                mac.update(&self.packet[4..range.start - ATTR_HEADER_LEN]);
                mac.verify_slice(&self.packet[range.clone()])
                    .map_err(|_| ParseError::HmacValidationFailure)
            },
        )
    }

    pub fn is_stun_packet(packet: &[u8]) -> bool {
        packet.len() >= 8 && packet[4..8] == MAGIC_COOKIE
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.packet.len()
    }

    pub fn transaction_id(&self) -> TransactionId {
        // The constructor ensured that the packet is valid.
        self.packet[8..20].try_into().unwrap()
    }

    pub fn packet_type(&self) -> PacketType {
        // The constructor ensured that the packet is valid.
        self.packet[0..2].try_into().unwrap()
    }

    /// Always returns the "unsafe" variant of the iterator because the sanity of the packet header
    /// and all of the attributes has been established at construction time [`Self::from_buffer`].
    fn iter(&self) -> UnsafeStunAttributeIterator<'a> {
        UnsafeStunAttributeIterator::new(self.packet)
    }

    fn find_attr_range(&self, attr_id: u16) -> Option<Range<usize>> {
        self.iter()
            .find(|(id, _)| *id == attr_id)
            .map(|(_, range)| range)
    }

    fn get_attr_value(&self, attr_id: u16) -> Option<&[u8]> {
        self.find_attr_range(attr_id)
            .map(|range| &self.packet[range])
    }

    fn has_attr(&self, attr_id: u16) -> bool {
        self.find_attr_range(attr_id).is_some()
    }

    pub fn ice_controlled(&self) -> Option<u64> {
        self.get_attr_value(AttributeId::ICE_CONTROLLED)
            .map(|value| u64::from_be_bytes(value.try_into().unwrap()))
    }

    pub fn ice_controlling(&self) -> Option<u64> {
        self.get_attr_value(AttributeId::ICE_CONTROLLING)
            .map(|value| u64::from_be_bytes(value.try_into().unwrap()))
    }

    /// Retrieves the USERNAME attribute value, if available.
    pub fn username(&self) -> Option<&[u8]> {
        self.get_attr_value(AttributeId::USERNAME)
    }

    /// Retrieves the MESSAGE-INTEGRITY attribute value, if available.
    pub fn hmac(&self) -> Option<&[u8]> {
        self.get_attr_value(AttributeId::MESSAGE_INTEGRITY)
    }

    /// Retrieves the FINGERPRINT attribute value, if available.
    pub fn fingerprint(&self) -> Option<&[u8]> {
        self.get_attr_value(AttributeId::FINGERPRINT)
    }
}

impl<'a> TryFrom<StunPacket<'a>> for BindingResponse<'a> {
    type Error = ParseError;

    fn try_from(packet: StunPacket<'a>) -> Result<Self, Self::Error> {
        match packet.packet_type() {
            PacketType::BINDING_RESPONSE => Ok(BindingResponse { packet }),
            _ => Err(ParseError::TypeMismatch),
        }
    }
}

impl<'a> TryFrom<StunPacket<'a>> for BindingRequest<'a> {
    type Error = ParseError;

    fn try_from(packet: StunPacket<'a>) -> Result<Self, Self::Error> {
        match packet.packet_type() {
            PacketType::BINDING_REQUEST => Ok(BindingRequest { packet }),
            _ => Err(ParseError::TypeMismatch),
        }
    }
}

impl Display for StunPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TRANSACTION-ID=[{:x?}], PACKET-TYPE=[{:x?}]",
            self.transaction_id(),
            self.packet_type()
        )?;
        write!(f, " attrs: [ ")?;
        for (attr_id, attr_rng) in self.iter() {
            write!(f, "{}={:x?} ", attr_name(attr_id), &self.packet[attr_rng])?;
        }
        write!(f, "]")
    }
}

fn looks_like_header(packet: &[u8], packet_type: PacketType) -> bool {
    StunPacket::is_stun_packet(packet)
        && PacketType::try_from(&packet[..2]).is_ok_and(|pt| pt == packet_type)
}

/// Provides all of the functionality of [`StunPacket`] with accessors that are relevant
/// in the context of processing a STUN binding response.
#[derive(Debug)]
pub struct BindingResponse<'a> {
    packet: StunPacket<'a>,
}

impl<'a> BindingResponse<'a> {
    pub fn looks_like_header(packet: &[u8]) -> bool {
        looks_like_header(packet, PacketType::BINDING_RESPONSE)
    }

    /// Attempts to create a [BindingResponse] instance out of the given packet buffer. If the
    /// packet is determined to be a STUN packet with the message type of binding response, and if
    /// the packet sanity check succeeds, a new [BindingResponse] will be created and returned.
    pub fn try_from_buffer(packet: &'a [u8]) -> Result<Option<BindingResponse<'a>>, ParseError> {
        if Self::looks_like_header(packet) {
            Ok(Some(StunPacket::from_buffer(packet)?.try_into()?))
        } else {
            Ok(None)
        }
    }

    // During testing, it is frequently necessary to build a raw packet and then immediately
    // convert it to a BindingResponse. In those cases, we generally don't want to perform a sanity
    // check on a raw packet that we just generated.
    #[cfg(test)]
    pub fn from_buffer_without_sanity_check(packet: &'a [u8]) -> Self {
        Self {
            packet: StunPacket::from_buffer_without_sanity_check(packet),
        }
    }

    /// Retrieves the ERROR-CODE attribute value, if available. The text message portion
    /// of the attribute is ignored.
    pub fn error_code(&self) -> Option<u16> {
        self.packet
            .get_attr_value(AttributeId::ERROR_CODE)
            .map(|code| {
                let x = parse_u16(code);
                let class = (x & 0xf00) >> 8;
                let number = x & 0x0ff;
                100 * class + number
            })
    }

    /// Retrieves the MAPPED-ADDRESS attribute value, if available.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.packet
            .get_attr_value(AttributeId::MAPPED_ADDRESS)
            .map(|buffer| {
                let port = u16::from_be_bytes(buffer[2..4].try_into().unwrap());
                match buffer[1] {
                    1 => {
                        let v = u32::from_be_bytes(buffer[4..].try_into().unwrap());
                        let ipv4 = Ipv4Addr::from_bits(v);
                        SocketAddr::new(IpAddr::V4(ipv4), port)
                    }
                    2 => {
                        let v = u128::from_be_bytes(buffer[4..].try_into().unwrap());
                        let ipv6 = Ipv6Addr::from_bits(v);
                        SocketAddr::new(IpAddr::V6(ipv6), port)
                    }
                    _ => {
                        // We have already ensured that only 1 and 2 are possible here during
                        // the sanity check.
                        unreachable!();
                    }
                }
            })
    }

    /// Retrieves the XOR-MAPPED-ADDRESS value, if available.
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        const XOR_IPV4: u32 = u32::from_ne_bytes(MAGIC_COOKIE);
        const XOR_PORT: u16 = u16::from_ne_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);

        self.packet
            .get_attr_value(AttributeId::XOR_MAPPED_ADDRESS)
            .map(|buffer| {
                let port =
                    u16::from_be(u16::from_ne_bytes(buffer[2..4].try_into().unwrap()) ^ XOR_PORT);
                match buffer[1] {
                    1 => {
                        let v = u32::from_ne_bytes(buffer[4..].try_into().unwrap()) ^ XOR_IPV4;
                        let ipv4 = Ipv4Addr::from(v.to_ne_bytes());
                        SocketAddr::new(IpAddr::V4(ipv4), port)
                    }
                    2 => {
                        let mut xor_bytes = [0u8; 16];
                        xor_bytes[..4].copy_from_slice(&MAGIC_COOKIE);
                        xor_bytes[4..].copy_from_slice(&self.transaction_id());
                        let xor_val = u128::from_ne_bytes(xor_bytes);
                        let v = u128::from_ne_bytes(buffer[4..].try_into().unwrap()) ^ xor_val;
                        let ipv6 = Ipv6Addr::from(v.to_ne_bytes());
                        SocketAddr::new(IpAddr::V6(ipv6), port)
                    }
                    _ => {
                        // We have already ensured that only 1 and 2 are possible here during
                        // the sanity check.
                        unreachable!();
                    }
                }
            })
    }
}

impl<'a> Deref for BindingResponse<'a> {
    type Target = StunPacket<'a>;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl Display for BindingResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingResponse {}", self.packet)
    }
}

/// Provides all of the functionality of [`StunPacket`] with accessors that are relevant
/// in the context of processing a STUN binding request.
#[derive(Debug)]
pub struct BindingRequest<'a> {
    packet: StunPacket<'a>,
}

impl<'a> BindingRequest<'a> {
    pub fn looks_like_header(packet: &[u8]) -> bool {
        looks_like_header(packet, PacketType::BINDING_REQUEST)
    }

    /// Attempts to create a [BindingRequest] instance out of the given packet buffer. If the
    /// packet is determined to be a STUN packet with the message type of binding request, and if
    /// the packet sanity check succeeds, a new [BindingRequest] will be created and returned.
    pub fn try_from_buffer(packet: &'a [u8]) -> Result<Option<BindingRequest<'a>>, ParseError> {
        if Self::looks_like_header(packet) {
            Ok(Some(StunPacket::from_buffer(packet)?.try_into()?))
        } else {
            Ok(None)
        }
    }

    // During testing, it is frequently necessary to build a raw packet and then immediately
    // convert it to a BindingRequest. In those cases, we generally don't want to perform a sanity
    // check on a raw packet that we just generated.
    #[cfg(test)]
    pub fn from_buffer_without_sanity_check(packet: &'a [u8]) -> Self {
        Self {
            packet: StunPacket::from_buffer_without_sanity_check(packet),
        }
    }

    /// Returns `true` if the USE-CANDIDATE attribute is present.
    pub fn nominated(&self) -> bool {
        self.packet.has_attr(AttributeId::USE_CANDIDATE)
    }

    /// Retrieves the value of the PRIORITY attribute, if available.
    pub fn priority(&self) -> Option<u32> {
        self.packet
            .get_attr_value(AttributeId::PRIORITY)
            .map(parse_u32)
    }
}

impl<'a> Deref for BindingRequest<'a> {
    type Target = StunPacket<'a>;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl Display for BindingRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingRequest {}", self.packet)
    }
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
    fn test_with_rfc5769_vectors() {
        let packet = hex!(
            "00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
            "80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74"
            "00 24 00 04 6e 00 01 ff 80 29 00 08 93 2f f9 b1 51 26 3b 36"
            "00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20 00 08 00 14"
            "9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2"
            "80 28 00 04 e5 7a 3b cf");
        let request = BindingRequest::try_from_buffer(&packet)
            .expect("recognized")
            .expect("sane");
        request
            .verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt")
            .expect("integrity verified");
        let username = request.username().expect("username");
        assert_eq!(username, b"evtj:h6vY");
        let software = request
            .get_attr_value(AttributeId::SOFTWARE)
            .expect("software");
        assert_eq!(software, b"STUN test client");

        let packet = hex!(
            "01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
            "80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20 00 20 00 08"
            "00 01 a1 47 e1 12 a6 43 00 08 00 14 2b 91 f5 99 fd 9e 90 c3"
            "8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7 80 28 00 04 c0 7d 4c 96");
        let response = BindingResponse::try_from_buffer(&packet)
            .expect("recognized")
            .expect("sane");
        response
            .verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt")
            .expect("integrity verified");
        let xor_mapped_addr = response.xor_mapped_address().expect("xor mapped address");
        assert_eq!(
            xor_mapped_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853)
        );
        let software = response
            .get_attr_value(AttributeId::SOFTWARE)
            .expect("software");
        assert_eq!(software, b"test vector");

        let packet = hex!(
            "01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
            "80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20 00 20 00 14"
            "00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9"
            "00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75"
            "bf e3 ed 41 80 28 00 04 c8 fb 0b 4c");
        let response = BindingResponse::try_from_buffer(&packet)
            .expect("recognized")
            .expect("sane");
        response
            .verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt")
            .expect("integrity verified");
        let xor_mapped_addr = response.xor_mapped_address().expect("xor mapped address");
        assert_eq!(
            xor_mapped_addr,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x1234, 0x5678, 0x11, 0x2233, 0x4455, 0x6677
                )),
                32853
            )
        );
        let software = response
            .get_attr_value(AttributeId::SOFTWARE)
            .expect("software");
        assert_eq!(software, b"test vector");
    }

    #[test]
    fn test_request_creation_and_parsing() {
        let username = b"some interesting username";
        let pwd = b"some interesting password";
        let request = StunPacketBuilder::new_binding_request(&TransactionId::new())
            .set_username(username)
            .set_nomination()
            .set_priority(0xc350c000)
            .build(pwd);
        let parsed_request = BindingRequest::try_from_buffer(&request)
            .expect("recognized")
            .expect("sane");
        parsed_request
            .verify_integrity(pwd)
            .expect("integrity validated");
        assert!(parsed_request.nominated());
        assert_eq!(parsed_request.username().expect("username"), username);
        assert_eq!(parsed_request.priority(), Some(0xc350c000));
        assert!(parsed_request.fingerprint().is_some());
    }

    #[test]
    fn test_response_creation_and_parsing() {
        let pwd = b"some interesting password";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = StunPacketBuilder::new_binding_response(&TransactionId::new())
            .set_xor_mapped_address(&addr)
            .set_mapped_address(&addr)
            .set_error_code(400)
            .build(pwd);
        let parsed_response = BindingResponse::try_from_buffer(&response)
            .expect("recognized")
            .expect("sane");
        parsed_response
            .verify_integrity(pwd)
            .expect("integrity validated");
        assert!(parsed_response.fingerprint().is_some());
        assert_eq!(
            addr,
            parsed_response.mapped_address().expect("mapped address")
        );
        assert_eq!(
            addr,
            parsed_response
                .xor_mapped_address()
                .expect("xor mapped address")
        );
        assert_eq!(400, parsed_response.error_code().expect("error code"));
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

        use super::ParseError;
        use crate::ice::{AttributeId, StunPacket};

        #[test]
        fn prevent_empty_packet() {
            assert_eq!(
                Some(ParseError::IncompleteHeader(0)),
                StunPacket::from_buffer(&[]).err()
            );
        }

        #[test]
        fn prevent_incomplete_header() {
            let packet: &[u8] = &hex!("0001 004c 2112a4422b6a714565766478326f5a");
            assert_eq!(
                Some(ParseError::IncompleteHeader(19)),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_header_only() {
            let packet: &[u8] = &hex!("0001 0000 2112a44271536e422b33695952394469");
            assert_eq!(
                Some(ParseError::PacketHasNoAttributes),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_fingerprint_before_hmac() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a44238656d797950694b78506e6e"
                              "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                              "c057 0004 00010032"
                              "802a 0008 f66e672cbb22165d"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
            /* fingerprint */ "8028 0004 d48fbba0"
                   /* hmac */ "0008 0014 5be1331d09c86d8cbfaf48f64687669096d32d3b"
            );
            assert_eq!(
                Some(ParseError::FingerprintBeforeHMac),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_wrong_hmac_length() {
            let packet: &[u8] = &hex!(
                       "0001 0068 2112a442516b77624e657155454a4635"
                       "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                       "c057 0004 00010032"
                       "802a 0008 f66e672cbb22165d"
                       "0025 0000"
                       "0024 0004 6e7f1eff"
            /* hmac */ "0008 0010 4de1e857695f0804f5f8e9fcf3150977"
                       "8028 0004 b7b01d0b"
            );
            assert_eq!(
                Some(ParseError::InvalidAttributeLength(
                    AttributeId::MESSAGE_INTEGRITY,
                    20,
                    16
                )),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_something_between_hmac_and_fingerprint() {
            let packet: &[u8] = &hex!(
                              "0001 0070 2112a442656b72774b55515041495476"
                              "0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                              "c057 0004 00010032"
                              "802a 0008 eef8294dc5f11c9c"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 d385d7f2f2222979333c405cea0b291444592aca"
                              "abcd 0000"
            /* fingerprint */ "8028 000429560496"
            );
            assert_eq!(
                Some(ParseError::ExpectedFingerprint(0xabcd)),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_appending_1_byte_to_packet() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a442665175732f33426771346c7a"
                              "0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                              "c057 0004 00010032"
                              "802a 0008 eef8294dc5f11c9c"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                              "0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92"
            /* fingerprint */ "8028 0004 1698f47f"
                              "00" // appended 1 bytes past declared message length
            );
            assert_eq!(
                Some(ParseError::DeclaredMessageLengthMismatch(
                    0x006c,
                    0x006c + 1
                )),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_appending_whole_attribute_to_packet() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a442665175732f33426771346c7a"
                              "0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                              "c057 0004 00010032"
                              "802a 0008 eef8294dc5f11c9c"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                              "0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92"
            /* fingerprint */ "8028 0004 1698f47f"
                              "abcd 0000" // appended 4 bytes past declared message length
            );
            assert_eq!(
                Some(ParseError::DeclaredMessageLengthMismatch(
                    0x006c,
                    0x006c + 4
                )),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_attribute_after_fingerprint_within_declared_message_length() {
            let packet: &[u8] = &hex!(
                              "0001 0070 2112a442665175732f33426771346c7a"
                              "0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                              "c057 0004 00010032"
                              "802a 0008 eef8294dc5f11c9c"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                              "0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92"
            /* fingerprint */ "8028 0004 1698f47f"
                              "abcd 0000"
            );
            assert_eq!(
                Some(ParseError::AttributeAfterFingerprint(0xabcd)),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_attribute_past_end_of_packet() {
            let packet: &[u8] = &hex!(
                           "0001 006c 2112a442665175732f33426771346c7a"
            /* Too long */ "0006 0069 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                           "c057 0004 00010032"
                           "802a 0008 eef8294dc5f11c9c"
                           "0025 0000"
                           "0024 0004 6e7f1eff"
                           "0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92"
                           "8028 0004 1698f47f"
            );
            assert_eq!(
                Some(ParseError::AttributeRangePastPacketEnd(0x0006, 1)),
                StunPacket::from_buffer(packet).err()
            );
        }

        #[test]
        fn prevent_wrong_length_fingerprint() {
            let packet: &[u8] = &hex!(
                              "0001 006b 2112a442665175732f33426771346c7a"
                              "0006 0025 33643462313062303033306363646638353762393063663962373032353939383a416d3356000000"
                              "c057 0004 00010032"
                              "802a 0008 eef8294dc5f11c9c"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                              "0008 0014 62d3395bf9d117fa6b915cccd60d4dc141d39c92"
            /* fingerprint */ "8028 0003 1698f4"
            );
            assert_eq!(
                Some(ParseError::InvalidAttributeLength(
                    AttributeId::FINGERPRINT,
                    4,
                    3
                )),
                StunPacket::from_buffer(packet).err()
            );
        }
    }

    mod parse_binding_request_tests {
        use hex_literal::hex;

        use super::*;

        #[test]
        fn parse_with_nomination() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a44238656d797950694b78506e6e"
               /* username */ "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                              "c057 0004 00010032"
                              "802a 0008 f66e672cbb22165d"
              /* nominated */ "0025 0000"
                              "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 5be1331d09c86d8cbfaf48f64687669096d32d3b"
            /* fingerprint */ "8028 0004 d48fbba0"
            );
            let packet = BindingRequest::try_from_buffer(packet)
                .expect("recognized")
                .expect("sane");
            assert!(packet.nominated());
            assert_eq!(
                hex!("63636431623031363037303065383364616232386435303135636563346362653a31315453"),
                packet.username().expect("username is present")
            );
            assert_eq!(
                hex!("5be1331d09c86d8cbfaf48f64687669096d32d3b"),
                packet.hmac().expect("hmac is present")
            );
            assert_eq!(
                hex!("d48fbba0"),
                packet.fingerprint().expect("fingerprint is present")
            )
        }

        #[test]
        fn parse_without_nomination() {
            let packet: &[u8] = &hex!(
                              "0001 0068 2112a44271536e422b33695952394469"
               /* username */ "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                              "c057 0004 00010032"
                              "802a 0008 f66e672cbb22165d"
                              "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 749225e1798cdcf19c72a48d36b8de0da89effb6"
            /* fingerprint */ "8028 0004 56d8838f"
            );
            let packet = BindingRequest::try_from_buffer(packet)
                .expect("recognized")
                .expect("sane");
            assert!(!packet.nominated());
            assert_eq!(
                hex!("63636431623031363037303065383364616232386435303135636563346362653a31315453"),
                packet.username().expect("username is present")
            );
            assert_eq!(
                hex!("749225e1798cdcf19c72a48d36b8de0da89effb6"),
                packet.hmac().expect("hmac is present")
            );
            assert_eq!(
                hex!("56d8838f"),
                packet.fingerprint().expect("fingerprint is present")
            );
        }
    }

    mod hmac_verification_tests {
        use hex_literal::hex;

        use super::BindingRequest;

        #[test]
        fn hmac_verify() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a442716e517877595a6c5853332f"
                              "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                              "c057 0004 00010032"
                              "802a 0008 f66e672cbb22165d"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 f2929850b442ffc08489031630696a4473534113"
            /* fingerprint */ "8028 0004 4654be07"
            );

            let ice_packet = BindingRequest::try_from_buffer(packet)
                .expect("recognized")
                .expect("sane");

            assert!(ice_packet
                .verify_integrity(b"000102030405060708090a0b0c0d0e0f")
                .is_ok());

            assert!(
                ice_packet
                    .verify_integrity(b"0102030405060708090a0b0c0d0e0f10")
                    .is_err(),
                "Should not verify with another password"
            );
        }

        #[test]
        fn hmac_does_not_verify_if_packet_manipulated() {
            let packet: &[u8] = &hex!(
                              "0001 006c 2112a442716e517877595a6c5853332f"
                              "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                              "c057 0004 00010033"
                              "802a 0008 f66e672cbb22165d"
                              "0025 0000"
                              "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 f2929850b442ffc08489031630696a4473534113"
            /* fingerprint */ "8028 0004 4654be07"
            );

            let ice_packet = BindingRequest::try_from_buffer(packet)
                .expect("recognized")
                .expect("sane");

            assert!(ice_packet
                .verify_integrity(b"000102030405060708090a0b0c0d0e0f")
                .is_err());
        }

        #[test]
        fn hmac_does_not_verify_if_hmac_modified_in_packet() {
            let packet: &[u8] = &hex!(
                  "0001 006c 2112a442716e517877595a6c5853332f"
                  "0006 0025 63636431623031363037303065383364616232386435303135636563346362653a31315453000000"
                  "c057 0004 00010032"
                  "802a 0008 f66e672cbb22165d"
                  "0025 0000"
                  "0024 0004 6e7f1eff"
                   /* hmac */ "0008 0014 f2929850b442ffc08489031630696a4473534114"
            /* fingerprint */ "8028 0004 4654be07"
            );

            let ice_packet = BindingRequest::try_from_buffer(packet)
                .expect("recognized")
                .expect("sane");

            assert!(ice_packet
                .verify_integrity(b"000102030405060708090a0b0c0d0e0f")
                .is_err());
        }
    }
}
