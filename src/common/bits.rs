//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::{BitAnd, BitOr, Shl, Shr};

pub trait Bits: Sized + Copy {
    const BIT_WIDTH: u8 = (std::mem::size_of::<Self>() * 8) as u8;

    /// Returns true iff the bit at the index is one.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0 based index starting at the most significant bit.  
    fn ms_bit(self, index: u8) -> bool;

    /// Sets the bit to one at the index.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0 based index starting at the most significant bit.  
    fn set_ms_bit(self, index: u8) -> Self;

    /// Returns true iff the bit at the index is one.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0 based index starting at the least significant bit.  
    fn ls_bit(self, index: u8) -> bool;

    /// Sets the bit to one at the index.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0 based index starting at the least significant bit.  
    fn set_ls_bit(self, index: u8) -> Self;
}

impl<T> Bits for T
where
    T: Copy
        + Shr<u8, Output = T>
        + Shl<u8, Output = T>
        + BitAnd<T, Output = T>
        + BitOr<T, Output = T>
        + From<u8>
        + Eq,
{
    fn ms_bit(self, index: u8) -> bool {
        assert!(index < Self::BIT_WIDTH);

        self >> (Self::BIT_WIDTH - index - 1) & T::from(1) == T::from(1)
    }

    fn set_ms_bit(self, index: u8) -> Self {
        assert!(index < Self::BIT_WIDTH);

        self | T::from(1) << (Self::BIT_WIDTH - index - 1)
    }

    fn ls_bit(self, index: u8) -> bool {
        assert!(index < Self::BIT_WIDTH);

        self >> index & T::from(1) == T::from(1)
    }

    fn set_ls_bit(self, index: u8) -> Self {
        assert!(index < Self::BIT_WIDTH);

        self | T::from(1) << index
    }
}

#[cfg(test)]
mod msb_tests {
    use super::*;

    #[test]
    fn is_set_leading_ms_bit_u8() {
        assert!(0b1111_1111u8.ms_bit(0));
        assert!(!0b0111_1111u8.ms_bit(0));
    }

    #[test]
    fn is_set_trailing_ms_bit_u8() {
        assert!(0b1111_1111u8.ms_bit(7));
        assert!(!0b1111_1110u8.ms_bit(7));
    }

    #[test]
    #[should_panic]
    fn get_panics_when_over_bit_length_u8() {
        0u8.ms_bit(8);
    }

    #[test]
    #[should_panic]
    fn set_panics_when_over_bit_length_u8() {
        0u8.set_ms_bit(8);
    }

    #[test]
    #[should_panic]
    fn get_panics_when_over_bit_length_u32() {
        0u32.ms_bit(32);
    }

    #[test]
    fn is_set_leading_ms_bit_u32() {
        assert!(0b1111_1111_1111_1111_1111_1111_1111_1111u32.ms_bit(0));
        assert!(!0b0111_1111_1111_1111_1111_1111_1111_1111u32.ms_bit(0));
    }

    #[test]
    fn is_set_trailing_ms_bit_u32() {
        assert!(0b1111_1111_1111_1111_1111_1111_1111_1111u32.ms_bit(31));
        assert!(!0b1111_1111_1111_1111_1111_1111_1111_1110u32.ms_bit(31));
    }

    #[test]
    fn set_same_bit_twice() {
        let byte = 0b0000_0000u8.set_ms_bit(0);
        assert_eq!(0b1000_0000, byte);
        let byte = byte.set_ms_bit(0);
        assert_eq!(0b1000_0000, byte);
    }

    #[test]
    fn set_bits_u8() {
        let byte = 0b0000_0000u8.set_ms_bit(0);
        assert_eq!(0b1000_0000, byte);
        let byte = byte.set_ms_bit(2);
        assert_eq!(0b1010_0000, byte);
        let byte = byte.set_ms_bit(4);
        assert_eq!(0b1010_1000, byte);
        let byte = byte.set_ms_bit(6);
        assert_eq!(0b1010_1010, byte);
        let byte = byte.set_ms_bit(7);
        assert_eq!(0b1010_1011, byte);
        let byte = byte.set_ms_bit(5);
        assert_eq!(0b1010_1111, byte);
        let byte = byte.set_ms_bit(3);
        assert_eq!(0b1011_1111, byte);
        let byte = byte.set_ms_bit(1);
        assert_eq!(0b1111_1111, byte);
    }

    #[test]
    fn set_bits_u16() {
        let byte = 0b0000_0000_0000_0000u16.set_ms_bit(0);
        assert_eq!(0b1000_0000_0000_0000, byte);
        let byte = byte.set_ms_bit(15);
        assert_eq!(0b1000_0000_0000_0001, byte);
    }
}

#[cfg(test)]
mod lsb_tests {
    use super::*;

    #[test]
    fn is_set_trailing_ls_bit_u8() {
        assert!(0b1111_1111u8.ls_bit(0));
        assert!(!0b1111_1110u8.ls_bit(0));
    }

    #[test]
    fn is_set_leading_ls_bit_u8() {
        assert!(0b1111_1111u8.ls_bit(7));
        assert!(!0b0111_1111u8.ls_bit(7));
    }

    #[test]
    #[should_panic]
    fn get_panics_when_over_bit_length_u8() {
        0u8.ls_bit(8);
    }

    #[test]
    #[should_panic]
    fn set_panics_when_over_bit_length_u8() {
        0u8.set_ls_bit(8);
    }

    #[test]
    #[should_panic]
    fn get_panics_when_over_bit_length_u32() {
        0u32.ls_bit(32);
    }

    #[test]
    fn is_set_trailing_ls_bit_u32() {
        assert!(0b1111_1111_1111_1111_1111_1111_1111_1111u32.ls_bit(0));
        assert!(!0b1111_1111_1111_1111_1111_1111_1111_1110u32.ls_bit(0));
    }

    #[test]
    fn is_set_leading_ls_bit_u32() {
        assert!(0b1111_1111_1111_1111_1111_1111_1111_1111u32.ls_bit(31));
        assert!(!0b0111_1111_1111_1111_1111_1111_1111_1111u32.ls_bit(31));
    }

    #[test]
    fn set_same_bit_twice() {
        let byte = 0b0000_0000u8.set_ls_bit(0);
        assert_eq!(0b0000_0001, byte);
        let byte = byte.set_ls_bit(0);
        assert_eq!(0b0000_0001, byte);
    }

    #[test]
    fn set_bits_u8() {
        let byte = 0b0000_0000u8.set_ls_bit(0);
        assert_eq!(0b0000_0001, byte);
        let byte = byte.set_ls_bit(2);
        assert_eq!(0b0000_0101, byte);
        let byte = byte.set_ls_bit(4);
        assert_eq!(0b0001_0101, byte);
        let byte = byte.set_ls_bit(6);
        assert_eq!(0b0101_0101, byte);
        let byte = byte.set_ls_bit(7);
        assert_eq!(0b1101_0101, byte);
        let byte = byte.set_ls_bit(5);
        assert_eq!(0b1111_0101, byte);
        let byte = byte.set_ls_bit(3);
        assert_eq!(0b1111_1101, byte);
        let byte = byte.set_ls_bit(1);
        assert_eq!(0b1111_1111, byte);
    }

    #[test]
    fn set_bits_u16() {
        let byte = 0b0000_0000_0000_0000u16.set_ls_bit(0);
        assert_eq!(0b0000_0000_0000_0001, byte);
        let byte = byte.set_ls_bit(15);
        assert_eq!(0b1000_0000_0000_0001, byte);
    }
}
