//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::bail;
use smallvec::SmallVec;

#[derive(Debug)]
pub struct BitstreamReader<'a> {
    bytes: &'a [u8],
    /// The index into `bytes` of the next byte to read.
    byte_index: usize,
    /// The offset into `bytes[byte_index]` of the next bit to read. In the range 0..=7.
    bit_offset: u8,
}

impl<'a> BitstreamReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_index: 0,
            bit_offset: 0,
        }
    }

    pub fn read_u64(&mut self, bits: usize) -> anyhow::Result<u64> {
        assert!(bits <= 64);
        let mut result = 0;
        if bits > 0 {
            let byte_count = bits / 8;
            if byte_count > 0 {
                result |= u64::from(self.read_u8(8)?);
                for _ in 0..byte_count - 1 {
                    result <<= 8;
                    result |= u64::from(self.read_u8(8)?);
                }
            }
            let bits_left = bits - (byte_count * 8);
            result <<= bits_left;
            result |= u64::from(self.read_u8(bits_left as u8)?);
        }
        Ok(result)
    }

    pub fn read_u32(&mut self, bits: usize) -> anyhow::Result<u32> {
        assert!(bits <= 32);
        self.read_u64(bits).map(|v| v as u32)
    }

    pub fn read_u16(&mut self, bits: usize) -> anyhow::Result<u16> {
        assert!(bits <= 16);
        self.read_u64(bits).map(|v| v as u16)
    }

    /// An implementation of the `f(n)` function in the spec, where 0 < n <= 8:
    /// https://aomediacodec.github.io/av1-rtp-spec/#a82-syntax
    pub fn read_u8(&mut self, bits: u8) -> anyhow::Result<u8> {
        if bits == 0 {
            return Ok(0);
        }

        assert!(bits <= 8);

        let bytes_len = self.bytes.len();
        if self.byte_index >= bytes_len
            || (self.bit_offset + bits > 8 && self.byte_index + 1 == bytes_len)
        {
            bail!(
                "out of bounds access: byte_index={}, bit_offset={}, bits={bits}, bytes_len={}",
                self.byte_index,
                self.bit_offset,
                bytes_len,
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

    pub fn read_non_symmetric(&mut self, n: u8) -> anyhow::Result<u8> {
        let mut w = 0;
        let mut x = n;
        while x != 0 {
            x >>= 1;
            w += 1;
        }

        let m = (1 << w) - n;
        let v = self.read_u8(w - 1)?;
        if v < m {
            return Ok(v);
        }

        let extra_bit = self.read_u8(1)?;
        Ok((v << 1) - m + extra_bit)
    }

    pub fn has_more(&mut self) -> bool {
        self.byte_index < self.bytes.len()
    }

    pub fn zero_pad(&mut self) {
        if self.bit_offset > 0 {
            self.bit_offset = 0;
            self.byte_index += 1;
        }
    }

    /// An implementation of https://aomediacodec.github.io/av1-spec/#leb128
    pub fn read_leb128(&mut self) -> anyhow::Result<u128> {
        let mut value = 0;
        for i in 0..8 {
            let byte = self.read_u8(8)? as u128;
            value |= (byte & 0x7f) << (i * 7);
            if byte & 0x80 == 0 {
                break;
            }
        }
        Ok(value)
    }
}

macro_rules! impl_bit_writer_for_type {
    ($type:ty, $func_name:ident) => {
        pub fn $func_name(&mut self, value: $type, bits: usize) {
            if bits > 0 {
                let len = std::mem::size_of::<$type>();
                assert!(bits <= len * 8);
                let bytes = value.to_be_bytes();
                let index = (len * 8 - bits) / 8;
                let topmost_bits = bits - (len - index - 1) * 8;
                self.write_u8(bytes[index], topmost_bits);
                for i in index + 1..len {
                    self.write_u8(bytes[i], 8);
                }
            }
        }
    };
}

#[derive(Debug, Default)]
pub struct BitstreamWriter<const N: usize> {
    storage: SmallVec<[u8; N]>,
    free_bits: usize,
}

impl<const N: usize> BitstreamWriter<N> {
    impl_bit_writer_for_type!(u16, write_u16);
    impl_bit_writer_for_type!(u32, write_u32);
    impl_bit_writer_for_type!(u64, write_u64);

    fn push_bits(&mut self, value: u8, bits: usize) {
        let i = self.storage.len() - 1;
        self.free_bits -= bits;
        self.storage[i] |= value << self.free_bits;
    }

    fn extend(&mut self) {
        self.storage.push(0);
        self.free_bits = 8;
    }

    pub fn write_u8(&mut self, value: u8, bits: usize) {
        if bits > 0 {
            if self.free_bits == 0 {
                self.extend();
                self.push_bits(value, bits);
            } else if bits <= self.free_bits {
                self.push_bits(value, bits);
            } else {
                let overflow = bits - self.free_bits;
                self.push_bits(value >> overflow, self.free_bits);
                self.extend();
                self.push_bits(value & ((1 << overflow) - 1), overflow);
            }
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u8(*byte, 8);
        }
    }

    pub fn write_padding(&mut self) {
        self.write_u8(0, self.free_bits);
    }

    pub fn write_non_symmetric(&mut self, n: usize, v: u8) {
        if n == 1 {
            return;
        }
        let mut w = 0;
        let mut x = n;
        while x != 0 {
            x >>= 1;
            w += 1;
        }
        let m = (1 << w) - n as u8;
        if v < m {
            self.write_u8(v, w - 1);
        } else {
            self.write_u8(v + m, w);
        }
    }

    pub fn len(&self) -> usize {
        8 * self.storage.len() + 8 - self.free_bits
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.free_bits == 8
    }

    pub fn as_slice(&self) -> &[u8] {
        self.storage.as_slice()
    }
}

#[cfg(test)]
mod bitstream_reader_tests {
    use super::*;

    #[test]
    fn read_u8() -> anyhow::Result<()> {
        let bytes = [0b0000_0010, 0b1010_0000];
        let mut rdr = BitstreamReader::new(&bytes);

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
    fn read_u8_error() -> anyhow::Result<()> {
        let bytes = [];
        let mut rdr = BitstreamReader::new(&bytes);
        assert!(!rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(1).is_err());

        let bytes = [0b1000_0000];
        let mut rdr = BitstreamReader::new(&bytes);
        assert!(rdr.has_more());
        assert_eq!(rdr.read_u8(1)?, 1);

        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());
        assert!(rdr.read_u8(5).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());
        assert!(rdr.read_u8(5).is_err());
        assert!(rdr.read_u8(4).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());
        assert!(rdr.read_u8(5).is_err());
        assert!(rdr.read_u8(4).is_err());
        assert!(rdr.read_u8(3).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());
        assert!(rdr.read_u8(5).is_err());
        assert!(rdr.read_u8(4).is_err());
        assert!(rdr.read_u8(3).is_err());
        assert!(rdr.read_u8(2).is_err());

        assert_eq!(rdr.read_u8(1)?, 0);
        assert!(!rdr.has_more());
        assert!(rdr.read_u8(8).is_err());
        assert!(rdr.read_u8(7).is_err());
        assert!(rdr.read_u8(6).is_err());
        assert!(rdr.read_u8(5).is_err());
        assert!(rdr.read_u8(4).is_err());
        assert!(rdr.read_u8(3).is_err());
        assert!(rdr.read_u8(2).is_err());
        assert!(rdr.read_u8(1).is_err());

        Ok(())
    }

    #[test]
    fn read_u8_two_bytes() -> anyhow::Result<()> {
        let bytes = [0b0000_0010, 0b1010_0011];
        let mut rdr = BitstreamReader::new(&bytes);

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
    fn read_u8_one_byte() -> anyhow::Result<()> {
        let bytes = [0b0001_1011];
        let mut rdr = BitstreamReader::new(&bytes);

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
}

#[cfg(test)]
mod bitstream_writer_tests {
    use crate::bitstream::BitstreamWriter;

    #[test]
    fn test_bitwriter_u8_write() {
        let mut writer = BitstreamWriter::<32>::default();
        writer.write_u8(0b00000011, 2);
        assert_eq!(writer.as_slice()[0], 0b11000000);
        writer.write_u8(0b00000101, 3);
        assert_eq!(writer.as_slice()[0], 0b11101000);
        writer.write_u8(0b00001111, 4);
        assert_eq!(writer.as_slice()[0], 0b11101111);
        assert_eq!(writer.as_slice()[1], 0b10000000);
    }
}
