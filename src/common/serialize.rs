//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Allows the serialization of datastructures to Vec<u8>.

use sha2::{Digest, Sha256};

use crate::common::integers::{U24, U48};

pub trait Writer {
    fn written_len(&self) -> usize;
    fn write(&self, out: &mut dyn Writable);
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.written_len());
        self.write(&mut vec);
        vec
    }
    fn to_sha256(&self) -> Sha256 {
        let mut digest = Sha256::new();
        self.write(&mut digest);
        digest
    }
}

// Like std::io::Write but can't fail or only do partial writes.
pub trait Writable {
    fn write(&mut self, input: &[u8]);
}

impl Writable for Vec<u8> {
    fn write(&mut self, input: &[u8]) {
        self.extend_from_slice(input);
    }
}

impl Writable for Sha256 {
    fn write(&mut self, input: &[u8]) {
        sha2::Digest::update(self, input);
    }
}

pub struct Empty {}

impl Writer for Empty {
    fn written_len(&self) -> usize {
        0
    }
    fn write(&self, _out: &mut dyn Writable) {}
}

impl<T: Writer> Writer for Option<T> {
    fn written_len(&self) -> usize {
        match self {
            None => 0,
            Some(writer) => writer.written_len(),
        }
    }
    fn write(&self, out: &mut dyn Writable) {
        match self {
            None => {}
            Some(writer) => writer.write(out),
        }
    }
}

// We don't impl u8 directly so as to avoid a conflict between [u8] and [T: Writer]
impl<const N: usize> Writer for [u8; N] {
    fn written_len(&self) -> usize {
        self.len()
    }
    fn write(&self, out: &mut dyn Writable) {
        out.write(&self[..]);
    }
}

impl Writer for [u8] {
    fn written_len(&self) -> usize {
        self.len()
    }
    fn write(&self, out: &mut dyn Writable) {
        out.write(self);
    }
}

impl Writer for Vec<u8> {
    fn written_len(&self) -> usize {
        self.len()
    }
    fn write(&self, out: &mut dyn Writable) {
        out.write(&self[..]);
    }
}

impl Writer for u16 {
    fn written_len(&self) -> usize {
        2
    }
    fn write(&self, out: &mut dyn Writable) {
        self.to_be_bytes().write(out)
    }
}

impl Writer for U24 {
    fn written_len(&self) -> usize {
        3
    }
    fn write(&self, out: &mut dyn Writable) {
        (&(u32::from(*self)).to_be_bytes()[1..4]).write(out);
    }
}

impl Writer for u32 {
    fn written_len(&self) -> usize {
        4
    }
    fn write(&self, out: &mut dyn Writable) {
        self.to_be_bytes().write(out)
    }
}

impl Writer for U48 {
    fn written_len(&self) -> usize {
        6
    }
    fn write(&self, out: &mut dyn Writable) {
        (&u64::from(*self).to_be_bytes()[2..8]).write(out);
    }
}

impl Writer for Box<dyn Writer> {
    fn written_len(&self) -> usize {
        (**self).written_len()
    }
    fn write(&self, out: &mut dyn Writable) {
        (**self).write(out)
    }
}

macro_rules! impl_writer_tuple {
    ($($name:ident)+) => (
    impl<$($name: Writer),+> Writer for ($($name,)+) {
        #[allow(non_snake_case)]
        fn written_len(&self) -> usize {
            let ($(ref $name,)+) = *self;
            let mut len = 0;
            $(len += $name.written_len();)+
            len
        }
        #[allow(non_snake_case)]
        fn write(&self, out: &mut dyn Writable) {
            let ($(ref $name,)+) = *self;
            $($name.write(out);)+
        }
    });
}

impl_writer_tuple! { A }
impl_writer_tuple! { A B }
impl_writer_tuple! { A B C }
impl_writer_tuple! { A B C D }
impl_writer_tuple! { A B C D E }

impl<T: Writer, const N: usize> Writer for [T; N] {
    fn written_len(&self) -> usize {
        self.iter().map(|writable| writable.written_len()).sum()
    }
    fn write(&self, out: &mut dyn Writable) {
        for writable in self {
            writable.write(out);
        }
    }
}

impl<T: Writer> Writer for [T] {
    fn written_len(&self) -> usize {
        self.iter().map(|writable| writable.written_len()).sum()
    }
    fn write(&self, out: &mut dyn Writable) {
        for writable in self {
            writable.write(out);
        }
    }
}

impl<T: Writer> Writer for Vec<T> {
    fn written_len(&self) -> usize {
        self.iter().map(|writable| writable.written_len()).sum()
    }
    fn write(&self, out: &mut dyn Writable) {
        for writable in self {
            writable.write(out);
        }
    }
}

// Necessary for composition with other impls (such as tuples).
impl<T: Writer + ?Sized> Writer for &T {
    fn written_len(&self) -> usize {
        T::written_len(self)
    }

    fn write(&self, out: &mut dyn Writable) {
        T::write(self, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn u16() {
        assert_eq!("0064", hex::encode(100u16.to_vec()));
        assert_eq!("2778", hex::encode(10104u16.to_vec()));
        assert_eq!(2, 100u16.written_len());
        assert_eq!(
            "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
            hex::encode(1u16.to_sha256().finalize())
        );
    }

    #[test]
    fn u32() {
        assert_eq!("00000064", hex::encode(100u32.to_vec()));
        assert_eq!("00002778", hex::encode(10104u32.to_vec()));
        assert_eq!("7e8a6925", hex::encode(2_123_000_101u32.to_vec()));
        assert_eq!(4, 100u32.written_len());
        assert_eq!(
            "b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d",
            hex::encode(1u32.to_sha256().finalize())
        );
    }

    #[test]
    fn u24() {
        assert_eq!("000064", hex::encode(U24::from(100u16).to_vec()));
        assert_eq!("002778", hex::encode(U24::from(10104u16).to_vec()));
        assert_eq!(
            "800000",
            hex::encode(U24::try_from(1u32 << 23).unwrap().to_vec())
        );
        assert_eq!(
            "8a6925",
            hex::encode(U24::try_from(0x8a6925u32).unwrap().to_vec())
        );
        assert_eq!(3, U24::from(100u16).written_len());
        assert_eq!(
            "cf7605ed1bc735f6c825554154627467e1cac9df54cee8699218ed434603c568",
            hex::encode(U24::from(1u16).to_sha256().finalize())
        );
    }

    #[test]
    fn u48() {
        assert_eq!("000000000064", hex::encode(U48::from(100u16).to_vec()));
        assert_eq!("000000002778", hex::encode(U48::from(10104u32).to_vec()));
        assert_eq!(
            "800000000000",
            hex::encode(U48::try_from(1u64 << 47).unwrap().to_vec())
        );
        assert_eq!(6, U48::from(100u16).written_len());
        assert_eq!(
            "186128bf8a4d60eb4b51102ae2a2cb6a0b80011977582480395a454454bec7e1",
            hex::encode(U48::from(1u16).to_sha256().finalize())
        );
    }

    #[test]
    fn single_element_slice_of_writable() {
        let element = U48::from(100u16);
        let slice_of_1 = [element];
        assert_eq!(element.written_len(), slice_of_1.written_len());
        assert_eq!(element.to_vec(), slice_of_1.to_vec());
        assert_eq!(
            element.to_sha256().finalize(),
            slice_of_1.to_sha256().finalize()
        );
    }

    #[test]
    fn double_element_slice_of_writable() {
        let element_1 = U48::from(100u16);
        let element_2 = U48::from(203u16);
        let slice_of_2 = [element_1, element_2];
        assert_eq!(
            element_1.written_len() + element_2.written_len(),
            slice_of_2.written_len()
        );
        let mut vec = element_1.to_vec();
        vec.append(&mut element_2.to_vec());
        assert_eq!(vec, slice_of_2.to_vec());
    }

    #[test]
    fn single_element_slice_of_u8() {
        let element = 100u8;
        let slice_of_1 = [element];
        assert_eq!(1, slice_of_1.written_len());
        assert_eq!(vec![element], slice_of_1.to_vec());
    }

    #[test]
    fn double_element_slice_of_u8() {
        let element_1 = 100u8;
        let element_2 = 234u8;
        let slice_of_2 = [element_1, element_2];
        assert_eq!(2, slice_of_2.written_len());
        assert_eq!(vec![element_1, element_2], slice_of_2.to_vec());
    }

    #[test]
    fn vec_of_u8() {
        let vec = vec![1u8, 2u8, 255u8];
        assert_eq!("0102ff", hex::encode(vec.to_vec()));
        assert_eq!(
            "0526d0e18ea19dfaad9d79166bec1e18d6221ef6b1830385fe9bf67022ed5f96",
            hex::encode(vec.to_sha256().finalize())
        );
    }

    #[test]
    fn tuple2() {
        let tuple = (100u16, 2_123_000_101u32);
        assert_eq!("00647e8a6925", hex::encode(tuple.to_vec()));
        assert_eq!(
            "dffc18faa457d5aa0a27c5bc8cd065d837cf997bb37940abcf5cef505b31b725",
            hex::encode(tuple.to_sha256().finalize())
        );
    }

    #[test]
    fn tuple3() {
        let tuple = ([255u8], 100u16, 2_123_000_101u32);
        assert_eq!("ff00647e8a6925", hex::encode(tuple.to_vec()));
        assert_eq!(
            "52ab2cba6473730d0e6a0f7feba988e59b9cc83ca04e0343cd34e0f27a924ee0",
            hex::encode(tuple.to_sha256().finalize())
        );
    }

    #[test]
    fn tuple4() {
        let tuple = ([255u8], 100u16, [127u8], 2_123_000_101u32);
        assert_eq!("ff00647f7e8a6925", hex::encode(tuple.to_vec()));
        assert_eq!(
            "8ec96a4f46c07b2d92a9009278fa6675ff89dec47985dcb7e76acc30b621a685",
            hex::encode(tuple.to_sha256().finalize())
        );
    }

    #[test]
    fn tuple5() {
        let tuple = (
            [127u8],
            65535u16,
            [1u8],
            1_000_000_000u32,
            U24::try_from(1u32 << 23).unwrap(),
        );
        assert_eq!("7fffff013b9aca00800000", hex::encode(tuple.to_vec()));
        assert_eq!(
            "521e73b5adde4db9a2ddf9c8cc263a327dfecf9e54f78114deb286ed65574a21",
            hex::encode(tuple.to_sha256().finalize())
        );
    }

    #[test]
    fn static_vec() {
        let vec = vec![1u32, 1 << 31];
        assert_eq!("0000000180000000", hex::encode(vec.to_vec()));
        assert_eq!(
            "3c258dec7ff9182db1c9ceac940453011fcc3ce440309a310f2a2c8475509c8a",
            hex::encode(vec.to_sha256().finalize())
        );
    }

    #[test]
    fn tuple_and_vec_u8() {
        let vec1 = vec![1u8, 1 << 7];
        let tuple = (1u16, vec1);
        assert_eq!("00010180", hex::encode(tuple.to_vec()));
        assert_eq!(
            "ba57af15c8d49bc2d673bdbcc15b9761dddf25386be00890bb7cf56cc02b0dba",
            hex::encode(tuple.to_sha256().finalize())
        );
    }

    #[test]
    fn dynamic_vec() {
        let mut vec: Vec<&dyn Writer> = vec![&[127u8]];
        vec.push(&65535u16);
        vec.push(&[1u8]);
        vec.push(&1_000_000_000u32);
        let u24 = U24::try_from(1u32 << 23).unwrap();
        vec.push(&u24);
        assert_eq!("7fffff013b9aca00800000", hex::encode(vec.to_vec()));
        assert_eq!(
            "521e73b5adde4db9a2ddf9c8cc263a327dfecf9e54f78114deb286ed65574a21",
            hex::encode(vec.to_sha256().finalize())
        );
    }
}
