//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Contains non-standard integer lengths.

use std::{
    convert::TryFrom,
    fmt,
    fmt::{Debug, Display, Formatter},
};

use thiserror::Error;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[error("out of range integral type conversion attempted")]
pub struct TryFromIntError(());

macro_rules! non_standard_unsigned_int {
    (pub struct $T:ident($UNDERLYING_TYPE:ty) { bytes = $BYTE_WIDTH:literal }) => {
        #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
        pub struct $T($UNDERLYING_TYPE);

        impl $T {
            #[doc = "Number of bytes the type uses"]
            pub const SIZE: usize = $BYTE_WIDTH;

            #[doc = "Number of bits the type uses"]
            pub const BITS: u32 = $BYTE_WIDTH * 8;

            pub const MAX: $T = $T((1 << ($BYTE_WIDTH * 8)) - 1);
            pub const MIN: $T = $T(0);
            pub const ZERO: $T = $T(0);

            pub fn truncate(value: $UNDERLYING_TYPE) -> Self {
                Self(value & Self::MAX.0)
            }

            pub fn wrapping_add(self, other: Self) -> Self {
                Self::truncate(self.0 + other.0)
            }

            pub fn from_be_bytes(bytes: [u8; Self::SIZE]) -> Self {
                let mut r: $UNDERLYING_TYPE = 0;
                for b in bytes.iter() {
                    r = r << 8 | *b as $UNDERLYING_TYPE;
                }
                Self(r)
            }

            pub fn from_le_bytes(bytes: [u8; Self::SIZE]) -> Self {
                let mut r: $UNDERLYING_TYPE = 0;
                for b in bytes.iter().rev() {
                    r = r << 8 | *b as $UNDERLYING_TYPE;
                }
                Self(r)
            }
        }

        impl Debug for $T {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat![stringify!($T), "({:#0width$x})"],
                    self.0,
                    width = $BYTE_WIDTH * 2 + 2
                )
            }
        }

        impl Display for $T {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<$T> for $UNDERLYING_TYPE {
            fn from(value: $T) -> Self {
                value.0
            }
        }
    };
}

non_standard_unsigned_int! {
    pub struct U48(u64) { bytes = 6 }
}

impl TryFrom<u64> for U48 {
    type Error = TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > Self::MAX.0 {
            Err(TryFromIntError(()))
        } else {
            Ok(U48(value))
        }
    }
}

impl From<u16> for U48 {
    fn from(value: u16) -> Self {
        U48(value as u64)
    }
}

impl From<u32> for U48 {
    fn from(value: u32) -> Self {
        U48(value as u64)
    }
}

#[cfg(target_pointer_width = "64")]
impl From<U48> for usize {
    fn from(value: U48) -> Self {
        value.0 as usize
    }
}

#[cfg(test)]
mod u48_tests {
    use std::convert::{TryFrom, TryInto};

    use hex_literal::hex;

    use super::U48;

    #[test]
    fn zero() {
        assert_eq!(Ok(U48(0)), 0u16.try_into());
        assert_eq!(U48(0), 0u16.into());
        assert_eq!(U48::ZERO, 0u16.into());
        assert_eq!(U48::MIN, 0u16.into());
    }

    #[test]
    fn one() {
        assert_eq!(Ok(U48(1)), 1u16.try_into());
        assert_eq!(U48(1), 1u16.into());
    }

    #[test]
    fn largest_value() {
        assert_eq!(Ok(U48(0xffffffffffff)), 0xffffffffffffu64.try_into());
        assert_eq!(Ok(U48::MAX), 0xffffffffffffu64.try_into());
    }

    #[test]
    fn too_large() {
        assert!(U48::try_from(0x1000000000000u64).is_err());
    }

    #[test]
    fn to_u64() {
        let u48: U48 = 0x101112131415u64.try_into().unwrap();
        assert_eq!(0x101112131415u64, u64::from(u48));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn to_usize() {
        let u48: U48 = 0x101112131415u64.try_into().unwrap();
        assert_eq!(0x101112131415usize, usize::from(u48));
    }

    #[test]
    fn debug_print() {
        assert_eq!("U48(0x000000000064)", format!("{:?}", U48::from(100u16)))
    }

    #[test]
    fn print() {
        assert_eq!("100", format!("{}", U48::from(100u16)))
    }

    #[test]
    fn from_u16() {
        assert_eq!(U48(0xffff), 0xffffu16.into());
    }

    #[test]
    fn from_u32() {
        assert_eq!(U48(0xffff0102), 0xffff0102u32.into());
    }

    #[test]
    fn truncate() {
        assert_eq!(U48(0xf7123456789a), U48::truncate(0xffeef7123456789au64));
    }

    #[test]
    fn wrapping_add() {
        assert_eq!(U48::from(1u16), U48::ZERO.wrapping_add(U48::from(1u16)));
        assert_eq!(
            U48::from(3u16),
            U48::from(2u32).wrapping_add(U48::from(1u32))
        );
        assert_eq!(U48::from(9u16), U48::MAX.wrapping_add(U48::from(10u32)));
    }

    #[test]
    fn compare() {
        assert!(U48(1) > U48::ZERO);
        assert!(U48(2) > U48(1));
    }

    #[test]
    fn from_be_bytes() {
        assert_eq!(
            U48(0x111213141516),
            U48::from_be_bytes(hex!("11 12 13 14 15 16"))
        );
    }

    #[test]
    fn from_le_bytes() {
        assert_eq!(
            U48(0x161514131211),
            U48::from_le_bytes(hex!("11 12 13 14 15 16"))
        );
    }
}

non_standard_unsigned_int! {
    pub struct U24(u32) { bytes = 3 }
}

impl TryFrom<u32> for U24 {
    type Error = TryFromIntError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::MAX.0 {
            Err(TryFromIntError(()))
        } else {
            Ok(U24(value))
        }
    }
}

impl From<u16> for U24 {
    fn from(value: u16) -> Self {
        U24(value as u32)
    }
}

impl From<U24> for u64 {
    fn from(value: U24) -> Self {
        value.0 as u64
    }
}

impl From<U24> for usize {
    fn from(value: U24) -> Self {
        value.0 as usize
    }
}

#[cfg(test)]
mod u24_tests {
    use std::convert::{TryFrom, TryInto};

    use hex_literal::hex;

    use super::U24;

    #[test]
    fn zero() {
        assert_eq!(Ok(U24(0)), 0u16.try_into());
        assert_eq!(U24(0), 0.into());
        assert_eq!(U24::ZERO, 0.into());
        assert_eq!(U24::MIN, 0.into());
    }

    #[test]
    fn one() {
        assert_eq!(Ok(U24(1)), 1u16.try_into());
        assert_eq!(U24(1), 1.into());
    }

    #[test]
    fn largest_value() {
        assert_eq!(Ok(U24(0xffffff)), 0xffffffu32.try_into());
        assert_eq!(Ok(U24::MAX), 0xffffffu32.try_into());
    }

    #[test]
    fn too_large() {
        assert!(U24::try_from(0x1000000u32).is_err());
    }

    #[test]
    fn to_u32() {
        let u24: U24 = 0x121314u32.try_into().unwrap();
        assert_eq!(0x121314u32, u32::from(u24));
    }

    #[test]
    fn to_u64() {
        let u24: U24 = 0x121314u32.try_into().unwrap();
        assert_eq!(0x121314u64, u64::from(u24));
    }

    #[test]
    fn to_usize() {
        let u24: U24 = 0x121314u32.try_into().unwrap();
        assert_eq!(0x121314usize, usize::from(u24));
    }

    #[test]
    fn debug_print() {
        assert_eq!("U24(0x000064)", format!("{:?}", U24::from(100)))
    }

    #[test]
    fn print() {
        assert_eq!("100", format!("{}", U24::from(100)))
    }

    #[test]
    fn from_u16() {
        assert_eq!(U24(0xffff), 0xffff.into());
    }

    #[test]
    fn truncate() {
        assert_eq!(U24(0xf71234), U24::truncate(0xfef71234u32));
    }

    #[test]
    fn wrapping_add() {
        assert_eq!(U24::from(1u16), U24::ZERO.wrapping_add(U24::from(1u16)));
        assert_eq!(
            U24::from(3u16),
            U24::from(2u16).wrapping_add(U24::from(1u16))
        );
        assert_eq!(U24::from(9u16), U24::MAX.wrapping_add(U24::from(10u16)));
    }

    #[test]
    fn compare() {
        assert!(U24(1) > U24::ZERO);
        assert!(U24(2) > U24(1));
    }

    #[test]
    fn from_be_bytes() {
        assert_eq!(U24(0x141516), U24::from_be_bytes(hex!("14 15 16")));
    }

    #[test]
    fn from_le_bytes() {
        assert_eq!(U24(0x161514), U24::from_le_bytes(hex!("14 15 16")));
    }
}
