//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{convert::TryInto, fmt::Debug};

use thiserror::Error;

use crate::common::{U24, U48};

#[derive(Clone)]
pub struct BytesReader<'a> {
    data: &'a [u8],
}

impl<'a> BytesReader<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { data: slice }
    }

    pub fn read_u8(&mut self) -> ReadResult<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Gets the next `n` bytes from the stream.
    ///
    /// If there are not at least `n` bytes remaining it reads them all and returns the Error `End`.
    pub fn read_bytes(&mut self, n: usize) -> ReadResult<&'a [u8]> {
        if self.data.len() < n {
            self.data = &self.data[self.data.len()..];
            return Err(ReadError::End);
        }
        let result = &self.data[..n];
        self.data = &self.data[n..];
        Ok(result)
    }

    /// Reads the next `n` bytes as an independent `BytesReader`.
    ///
    /// If there are not at least `n` bytes remaining it reads them all and returns the Error `End`.
    pub fn read(&mut self, n: usize) -> ReadResult<BytesReader<'a>> {
        Ok(Self::from_slice(self.read_bytes(n)?))
    }

    /// Reads all remaining bytes.
    pub fn read_all(&mut self) -> &[u8] {
        let result = self.data;
        self.data = &self.data[self.data.len()..];
        result
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a `T` using the supplied function.
    ///
    /// This will only stop reading when the stream end is hit, this means that once read_one starts,
    /// it must complete a whole read.
    ///
    /// Panics if `read_one` reads nothing.
    pub fn read_until_end_exactly<T>(
        &mut self,
        read_one: impl Fn(&mut Self) -> ReadResult<T>,
    ) -> ReadResult<Vec<T>> {
        let mut values = vec![];
        while !self.is_empty() {
            let data_length = self.data.len();
            values.push(
                read_one(self)
                    .map_err(|_| ReadError::EndReachedInLoop(values.len(), data_length))?,
            );
            assert!(
                data_length > self.data.len(),
                "The function did not read anything"
            );
        }
        Ok(values)
    }
}

macro_rules! read_implementation {
    ($T:ty, $be_fn_name:ident, $le_fn_name:ident) => {
        impl<'a> BytesReader<'a> {
            pub fn $be_fn_name(&mut self) -> ReadResult<$T> {
                let size = <$T>::BITS as usize / 8;
                let bytes = self.read_bytes(size)?;
                Ok(<$T>::from_be_bytes(bytes[0..size].try_into().unwrap()))
            }

            pub fn $le_fn_name(&mut self) -> ReadResult<$T> {
                let size = <$T>::BITS as usize / 8;
                let bytes = self.read_bytes(size)?;
                Ok(<$T>::from_le_bytes(bytes[0..size].try_into().unwrap()))
            }
        }
    };
}

read_implementation! { u16, read_u16_be, read_u16_le }
read_implementation! { i16, read_i16_be, read_i16_le }
read_implementation! { U24, read_u24_be, read_u24_le }
read_implementation! { u32, read_u32_be, read_u32_le }
read_implementation! { i32, read_i32_be, read_i32_le }
read_implementation! { U48, read_u48_be, read_u48_le }

pub type ReadResult<T> = Result<T, ReadError>;

#[derive(Error, Eq, PartialEq, Debug, Copy, Clone)]
pub enum ReadError {
    #[error("Reached end of stream")]
    End,
    #[error("Reached end of stream in loop. After {0} successful loops, there were only {1} bytes available at the next loop start.")]
    EndReachedInLoop(usize, usize),
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn read_u8() {
        let data = &hex!("01 02 03");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(1), reader.read_u8());
        assert_eq!(Ok(2), reader.read_u8());
        assert_eq!(Ok(3), reader.read_u8());
        assert_eq!(Err(ReadError::End), reader.read_u8());
    }

    #[test]
    fn read_u16_be() {
        let data = &hex!("0102 0304");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(0x0102), reader.read_u16_be());
        assert_eq!(Ok(0x0304), reader.read_u16_be());
        assert_eq!(Err(ReadError::End), reader.read_u16_be());
    }

    #[test]
    fn read_u16_le() {
        let data = &hex!("0102 0304");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(0x0201), reader.read_u16_le());
        assert_eq!(Ok(0x0403), reader.read_u16_le());
        assert_eq!(Err(ReadError::End), reader.read_u16_le());
    }

    #[test]
    fn read_i16_be() {
        let data = &hex!("0102 ffff fffe 7fff 8000");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(0x0102), reader.read_i16_be());
        assert_eq!(Ok(-1), reader.read_i16_be());
        assert_eq!(Ok(-2), reader.read_i16_be());
        assert_eq!(Ok(i16::MAX), reader.read_i16_be());
        assert_eq!(Ok(i16::MIN), reader.read_i16_be());
        assert_eq!(Err(ReadError::End), reader.read_u16_be());
    }

    #[test]
    fn read_u8_after_u16_fail_to_get_all_bytes() {
        let data = &hex!("0102 0304 05");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(0x0102), reader.read_u16_be());
        assert_eq!(Ok(0x0304), reader.read_u16_be());
        assert_eq!(Err(ReadError::End), reader.read_u16_be());
        assert_eq!(Err(ReadError::End), reader.read_u8());
    }

    #[test]
    fn read_u32_be() {
        let data = &hex!("01020304 05060708");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(0x01020304), reader.read_u32_be());
        assert_eq!(Ok(0x05060708), reader.read_u32_be());
        assert_eq!(Err(ReadError::End), reader.read_u32_be());
    }

    #[test]
    fn read_u24_be() {
        let data = &hex!("010203 040506");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(U24::truncate(0x010203)), reader.read_u24_be());
        assert_eq!(Ok(U24::truncate(0x040506)), reader.read_u24_be());
        assert_eq!(Err(ReadError::End), reader.read_u24_be());
    }

    #[test]
    fn read_u48_be() {
        let data = &hex!("010203040506 0708090a0b0c");
        let mut reader = BytesReader::from_slice(data);
        assert_eq!(Ok(U48::truncate(0x010203040506u64)), reader.read_u48_be());
        assert_eq!(Ok(U48::truncate(0x0708090a0b0cu64)), reader.read_u48_be());
        assert_eq!(Err(ReadError::End), reader.read_u48_be());
    }

    #[test]
    fn read_as_many_as_possible() {
        let data = &hex!("010203 040506");
        let mut reader = BytesReader::from_slice(data);
        let result = reader.read_until_end_exactly(|s| Ok((s.read_u8()?, s.read_u16_be()?)));
        assert_eq!(Ok(vec![(1u8, 0x0203u16), (4u8, 0x0506u16)]), result);
    }

    #[test]
    fn read_as_many_as_possible_but_empty() {
        let data = &hex!("");
        let mut reader = BytesReader::from_slice(data);
        let result = reader.read_until_end_exactly(|s| Ok((s.read_u8()?, s.read_u16_be()?)));
        assert_eq!(Ok(vec![]), result);
    }

    #[test]
    fn read_as_many_as_possible_length_mismatch_two_loops_one_byte_remains() {
        let data = &hex!("010203 040506 07");
        let mut reader = BytesReader::from_slice(data);
        let result = reader.read_until_end_exactly(|s| Ok((s.read_u8()?, s.read_u16_be()?)));
        assert_eq!(Err(ReadError::EndReachedInLoop(2, 1)), result);
        assert!(reader.is_empty());
    }

    #[test]
    fn read_as_many_as_possible_length_mismatch_three_loops_two_bytes_remain() {
        let data = &hex!("010203 040506 070809 0a0b");
        let mut reader = BytesReader::from_slice(data);
        let result = reader.read_until_end_exactly(|s| Ok((s.read_u8()?, s.read_u16_be()?)));
        assert_eq!(Err(ReadError::EndReachedInLoop(3, 2)), result);
        assert!(reader.is_empty());
    }

    #[test]
    #[should_panic(expected = "The function did not read anything")]
    fn read_as_many_as_possible_no_movement() {
        let data = &hex!("010203");
        let mut reader = BytesReader::from_slice(data);
        let _result = reader.read_until_end_exactly(|_| Ok(()));
    }

    #[test]
    fn read_as_many_as_possible_no_movement_but_empty_anyway() {
        let data = &hex!("");
        let mut reader = BytesReader::from_slice(data);
        let result = reader.read_until_end_exactly(|_| Ok(()));
        assert_eq!(Ok(vec![]), result);
    }

    #[test]
    fn clone() {
        let data = &hex!("010203");
        let mut reader1 = BytesReader::from_slice(data);
        assert_eq!(Ok(1), reader1.read_u8());
        let mut reader2 = BytesReader::clone(&reader1);
        assert_eq!(Ok(2), reader2.read_u8());
        assert_eq!(Ok(2), reader1.read_u8());
    }

    #[test]
    fn read_all() {
        let data = &hex!("010203");
        let mut byte_array = BytesReader::from_slice(data);
        let read = byte_array.read_all();
        assert_eq!(data, read);
        let read = byte_array.read_all();
        assert_eq!(vec![0u8; 0], read);
    }

    #[test]
    fn read_all_via_read() {
        let data = &hex!("0102 03");
        let mut byte_array = BytesReader::from_slice(data);
        let mut sub_reader = byte_array.read(2).unwrap();
        let read = sub_reader.read_all();
        assert_eq!(&hex!("0102"), read);
        let read = sub_reader.read_all();
        assert_eq!(vec![0u8; 0], read);
        let read = byte_array.read_all();
        assert_eq!(&hex!("03"), read);
        let read = byte_array.read_all();
        assert_eq!(vec![0u8; 0], read);
    }
}
