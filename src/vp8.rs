//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Result;
use byteorder::{ReadBytesExt, BE, LE};
use thiserror::Error;

use crate::common::{expand_truncated_counter, Bits, PixelSize, ReadSliceExt};

pub type TruncatedPictureId = u16;
pub type FullPictureId = u64;
pub type TruncatedTl0PicIdx = u8;
pub type FullTl0PicIdx = u64;

/// See https://tools.ietf.org/html/rfc7741 for the format.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ParsedHeader {
    /// Incremented with each video frame. Really a u15.
    /// Used to provide indicate frame order and gaps.
    /// Must be rewritten or cleared when forwarding simulcast.
    pub picture_id: Option<TruncatedPictureId>,

    // /// If false, the frame can be discarded without disrupting future frames.
    // /// There doesn't seem to be any use for this field
    // /// because we don't support dropping frames in the SFU.
    //  referenced: bool,
    //
    /// Incremented with each frame with TemporalLayerId == 0.
    /// Used to indicate temporal layer dependencies.
    /// Frames with TemporalLayerId > 0 refer to frames with TemporalLayerId == 0
    /// either directly or through a frame with one less TemoralLayerId.
    /// Must be rewritten or cleared when forwarding simulcast.
    pub tl0_pic_idx: Option<TruncatedTl0PicIdx>,

    // /// 0 = temporal base layer. Really a u4.
    // /// There doesn't seem to be any use for this field
    // /// because we don't support dropping frames in the SFU.
    //  temporal_layer_id: Option<u8>,

    // /// AKA "layer sync". If true, this frame references temporal layer 0
    // /// even if this frame's temporal_layer_id > 1. If false, this frame
    // /// references a frame with temporal_layer_id-1.
    // /// But there doesn't seem to be any use for this field
    // /// because we don't support dropping frames in the SFU.
    //  references_temporal_layer0_directly: Option<bool>,
    //
    /// Incremented with each key frame. Really a u5.
    /// There doesn't seem to be any use for this field.
    /// key_frame_index: Option<u8>,
    pub is_key_frame: bool,

    /// (width, height). Only included in the header if is_key_frame.
    /// Subsequent frames must have the same resolution.
    /// Really u14s.
    pub resolution: Option<PixelSize>,
}

#[derive(Debug, Eq, PartialEq)]
struct Byte0 {
    has_extensions: bool,
    starts_partition: bool,
    zero_partition_idx: bool,
}

impl Byte0 {
    fn parse(byte0: u8) -> Self {
        Self {
            has_extensions: byte0.ms_bit(0), //   X bit
            //_reserved1: byte0.ms_bit(1),     // R bit
            //_non_ref_frame: byte0.ms_bit(2), // N bit
            starts_partition: byte0.ms_bit(3), // S bit,
            //_reserved2: byte0.ms_bit(4),     // R bit
            zero_partition_idx: byte0 & 0b111 == 0,
        }
    }

    /// Note that the payload header is present only in packets that have the S bit equal to one
    /// and the PID equal to zero in the payload descriptor.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc7741#section-4.3
    fn has_payload_header(&self) -> bool {
        self.starts_partition && self.zero_partition_idx
    }
}

#[derive(Debug, Eq, PartialEq)]
struct XByte {
    has_picture_id: bool,
    has_tl0_pic_idx: bool,
    has_tid: bool,
    has_key_idx: bool,
}

impl XByte {
    fn parse(x_byte: u8) -> Self {
        Self {
            has_picture_id: x_byte.ms_bit(0),  // I bit
            has_tl0_pic_idx: x_byte.ms_bit(1), // L bit
            has_tid: x_byte.ms_bit(2),         // T bit
            has_key_idx: x_byte.ms_bit(3),     // K bit
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PayloadHeader {
    key_frame: bool,
}

impl PayloadHeader {
    fn parse(byte: u8) -> Self {
        Self {
            key_frame: !byte.ms_bit(7), // P bit: Inverse key frame flag.
        }
    }
}

#[derive(Error, Eq, PartialEq, Debug, Copy, Clone)]
pub enum Vp8Error {
    #[error("Got a 7-bit VP8 picture ID. Expecting only 15-bit picture IDs.")]
    SevenBitPictureId,
}

impl ParsedHeader {
    /// This reads both the "descriptor" and the "header"
    /// See https://datatracker.ietf.org/doc/html/rfc7741#section-4.2
    pub fn read(mut payload: &[u8]) -> Result<Self> {
        let mut header = Self::default();

        let byte0 = Byte0::parse(payload.read_u8()?);

        if byte0.has_extensions {
            let x_byte = XByte::parse(payload.read_u8()?);

            if x_byte.has_picture_id {
                let mut peek = payload;
                if !peek.read_u8()?.ms_bit(0) {
                    // The spec says it could be 7-bit, but WebRTC only sends 15-bit
                    return Err(Vp8Error::SevenBitPictureId.into());
                }
                let picture_id_with_leading_bit = payload.read_u16::<BE>()?;
                header.picture_id = Some(picture_id_with_leading_bit & 0b0111_1111_1111_1111);
            }

            if x_byte.has_tl0_pic_idx {
                let tl0_pic_idx = payload.read_u8()?;
                header.tl0_pic_idx = Some(tl0_pic_idx);
            };

            if x_byte.has_tid || x_byte.has_key_idx {
                let _tk_byte = payload.read_u8()?;
                // If in the future we want the TID or key frame index, here is how to get it:
                // if has_tid {
                //     header.temporal_layer_id = Some(tk_byte >> 6);
                //     header.references_temporal_layer0_directly = Some(tk_byte.ms_bit(2));
                // }
                // if has_key_idx {
                //     header.key_frame_index = Some(tk_byte & 0b0001_1111);
                // }
            };
        }

        if byte0.has_payload_header() {
            // The codec bitstream format specifies two different variants of the uncompressed data
            // chunk: a 3-octet version for interframes and a 10-octet version for key frames.
            // The first 3 octets are common to both variants.
            let mut common_header = payload.read_slice(3)?;
            let payload0 = PayloadHeader::parse(common_header.read_u8()?);
            header.is_key_frame = payload0.key_frame;
            if header.is_key_frame {
                // In the case of a key frame, the remaining 7 octets are considered to be part
                // of the remaining payload in this RTP format.
                let mut additional_key_frame_header = payload.read_slice(7)?;
                header.resolution = Some(ParsedHeader::size_from_additional_key_frame_header(
                    &mut additional_key_frame_header,
                )?);
            }
        }

        Ok(header)
    }

    /// see https://datatracker.ietf.org/doc/html/rfc6386#section-9.1
    fn size_from_additional_key_frame_header(
        additional_key_frame_header: &mut &[u8],
    ) -> std::io::Result<PixelSize> {
        let _skipped = additional_key_frame_header.read_slice(3)?;
        let width_with_scale = additional_key_frame_header.read_u16::<LE>()?;
        let height_with_scale = additional_key_frame_header.read_u16::<LE>()?;
        let width = width_with_scale & 0b11_1111_1111_1111;
        let height = height_with_scale & 0b11_1111_1111_1111;
        Ok(PixelSize { width, height })
    }
}

// This assumes that the picture ID and TL0 PIC IDX are present in the packet
// and that the picture ID is of the 15-bit variety.
// If they aren't, the payload will be corrupted
pub fn modify_header(
    rtp_payload: &mut [u8],
    picture_id: TruncatedPictureId,
    tl0_pic_idx: TruncatedTl0PicIdx,
) {
    rtp_payload[2..4].copy_from_slice(&((picture_id | 0b1000_0000_0000_0000).to_be_bytes()));
    rtp_payload[4] = tl0_pic_idx;
}

pub fn expand_picture_id(truncated: TruncatedPictureId, max: &mut FullPictureId) -> FullPictureId {
    expand_truncated_counter(truncated, max, 15)
}

pub fn expand_tl0_pic_idx(truncated: TruncatedTl0PicIdx, max: &mut FullTl0PicIdx) -> FullTl0PicIdx {
    expand_truncated_counter(truncated, max, 8)
}

#[cfg(test)]
mod byte_0_tests {
    use super::*;

    #[test]
    fn zero() {
        assert_eq!(
            Byte0::parse(0b00000000),
            Byte0 {
                has_extensions: false,
                starts_partition: false,
                zero_partition_idx: true
            }
        );
    }

    #[test]
    fn all_ones() {
        assert_eq!(
            Byte0::parse(0b11111111),
            Byte0 {
                has_extensions: true,
                starts_partition: true,
                zero_partition_idx: false
            }
        );
    }

    #[test]
    fn reserved_ignored() {
        assert_eq!(
            Byte0::parse(0b01001000),
            Byte0 {
                has_extensions: false,
                starts_partition: false,
                zero_partition_idx: true
            }
        );
    }

    #[test]
    fn has_extensions() {
        assert_eq!(
            Byte0::parse(0b10000000),
            Byte0 {
                has_extensions: true,
                starts_partition: false,
                zero_partition_idx: true
            }
        );
    }

    #[test]
    fn begins_partition() {
        assert_eq!(
            Byte0::parse(0b00010000),
            Byte0 {
                has_extensions: false,
                starts_partition: true,
                zero_partition_idx: true
            }
        );
    }

    #[test]
    fn non_zero_partitions() {
        assert_eq!(
            Byte0::parse(0b00000001),
            Byte0 {
                has_extensions: false,
                starts_partition: false,
                zero_partition_idx: false
            }
        );
        assert_eq!(
            Byte0::parse(0b00000010),
            Byte0 {
                has_extensions: false,
                starts_partition: false,
                zero_partition_idx: false
            }
        );
        assert_eq!(
            Byte0::parse(0b00000100),
            Byte0 {
                has_extensions: false,
                starts_partition: false,
                zero_partition_idx: false
            }
        );
    }
}

#[cfg(test)]
mod x_byte_tests {
    use super::*;

    #[test]
    fn zero() {
        assert_eq!(
            XByte::parse(0b00000000),
            XByte {
                has_picture_id: false,
                has_tl0_pic_idx: false,
                has_tid: false,
                has_key_idx: false
            }
        );
    }

    #[test]
    fn all_ones() {
        assert_eq!(
            XByte::parse(0b11111111),
            XByte {
                has_picture_id: true,
                has_tl0_pic_idx: true,
                has_tid: true,
                has_key_idx: true
            }
        );
    }

    #[test]
    fn reserved_ignored() {
        assert_eq!(
            XByte::parse(0b00001111),
            XByte {
                has_picture_id: false,
                has_tl0_pic_idx: false,
                has_tid: false,
                has_key_idx: false
            }
        );
    }

    #[test]
    fn has_picture_id() {
        assert_eq!(
            XByte::parse(0b10000000),
            XByte {
                has_picture_id: true,
                has_tl0_pic_idx: false,
                has_tid: false,
                has_key_idx: false
            }
        );
    }

    #[test]
    fn has_t10_pic_index() {
        assert_eq!(
            XByte::parse(0b01000000),
            XByte {
                has_picture_id: false,
                has_tl0_pic_idx: true,
                has_tid: false,
                has_key_idx: false
            }
        );
    }

    #[test]
    fn has_tid() {
        assert_eq!(
            XByte::parse(0b00100000),
            XByte {
                has_picture_id: false,
                has_tl0_pic_idx: false,
                has_tid: true,
                has_key_idx: false
            }
        );
    }

    #[test]
    fn has_key_index() {
        assert_eq!(
            XByte::parse(0b00010000),
            XByte {
                has_picture_id: false,
                has_tl0_pic_idx: false,
                has_tid: false,
                has_key_idx: true
            }
        );
    }
}

#[cfg(test)]
mod payload_header_tests {
    use super::*;

    #[test]
    fn non_key_frame() {
        assert_eq!(
            PayloadHeader::parse(0b00000001),
            PayloadHeader { key_frame: false }
        );
    }

    #[test]
    fn key_frame() {
        assert_eq!(
            PayloadHeader::parse(0b00000000),
            PayloadHeader { key_frame: true }
        );
    }
}

#[cfg(test)]
mod read_header_tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn read_header() {
        let data = &hex!(
            "
           /* byte0 */ 90
           /* xbyte */ c0
      /* picture_id */ 9267  // (with leading bit)
     /* tl0_pic_idx */ dc
        /* payload0 */ 00
         /* skipped */ 0000000000
 /* width and scale */ 8002
/* height and scale */ 6801
            "
        );
        assert_eq!(
            ParsedHeader::read(data).unwrap(),
            ParsedHeader {
                picture_id: Some(4711),
                tl0_pic_idx: Some(220),
                is_key_frame: true,
                resolution: Some(PixelSize {
                    width: 640,
                    height: 360
                })
            }
        );
    }

    #[test]
    fn read_header_alternative_values() {
        let data = &hex!(
            "
           /* byte0 */ 90
           /* xbyte */ c0
      /* picture_id */ 81d4  // (with leading bit)
     /* tl0_pic_idx */ d4
        /* payload0 */ 00
         /* skipped */ 0000000000
 /* width and scale */ 8007
/* height and scale */ 38C4
            "
        );
        assert_eq!(
            ParsedHeader::read(data).unwrap(),
            ParsedHeader {
                picture_id: Some(468),
                tl0_pic_idx: Some(212),
                is_key_frame: true,
                resolution: Some(PixelSize {
                    width: 1920,
                    height: 1080
                })
            }
        );
    }

    #[test]
    fn no_extensions() {
        let data = &hex!(
            "
          /* byte0 */ 10
       /* payload0 */ 00
        /* skipped */ 0000000000
 /* width and scale */ 8002
/* height and scale */ 6801
        "
        );
        assert_eq!(
            ParsedHeader::read(data).unwrap(),
            ParsedHeader {
                picture_id: None,
                tl0_pic_idx: None,
                is_key_frame: true,
                resolution: Some(PixelSize {
                    width: 640,
                    height: 360
                })
            }
        );
    }

    #[test]
    fn seven_bit_picture_id() {
        let data = &hex!(
            "
           /* byte0 */ 90
           /* xbyte */ c0
      /* picture_id */ 12 // seven bits due to no leading bit set
     /* tl0_pic_idx */ dc
        /* payload0 */ 00
         /* skipped */ 0000000000
 /* width and scale */ 8002
/* height and scale */ 6801
            "
        );
        assert_eq!(
            ParsedHeader::read(data)
                .unwrap_err()
                .downcast::<Vp8Error>()
                .unwrap(),
            Vp8Error::SevenBitPictureId
        );
    }
}
