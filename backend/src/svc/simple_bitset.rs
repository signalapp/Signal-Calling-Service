//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::{BitAndAssign, BitOrAssign, Shl, ShlAssign};

use num_traits::{ConstOne, ConstZero, PrimInt, Unsigned};

#[derive(Debug, PartialEq)]
pub enum SimpleBitsetError {
    OutOfBounds,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SimpleBitset<const N: usize, T> {
    words: [T; N],
    topmost: Option<usize>,
}

impl<const N: usize, T> SimpleBitset<N, T>
where
    T: Unsigned
        + ConstOne
        + ConstZero
        + PrimInt
        + ShlAssign<usize>
        + BitOrAssign
        + BitAndAssign
        + Copy,
{
    const BITS_PER_WORD: usize = size_of::<T>() * 8;

    const fn position(bit: usize) -> (usize, usize) {
        (bit / Self::BITS_PER_WORD, bit % Self::BITS_PER_WORD)
    }

    fn make_bitmask(index: usize) -> T {
        let v = T::ONE << index;
        v | (v - T::ONE)
    }

    pub const fn new() -> Self {
        Self {
            words: [T::ZERO; N],
            topmost: None,
        }
    }

    pub const fn reset(&mut self) {
        self.words = [T::ZERO; N];
        self.topmost = None;
    }

    fn find_topmost_set_bit(&mut self) {
        for i in (0..N).rev() {
            let leading_zeros = self.words[i].leading_zeros() as usize;
            if leading_zeros < Self::BITS_PER_WORD {
                self.topmost = Some((i + 1) * Self::BITS_PER_WORD - leading_zeros - 1);
                return;
            }
        }
        self.topmost = None;
    }

    #[allow(unused)]
    pub fn clear(&mut self, bit: usize) -> Result<(), SimpleBitsetError> {
        let (w, b) = Self::position(bit);
        if w >= N {
            Err(SimpleBitsetError::OutOfBounds)
        } else {
            self.words[w] &= !(T::ONE << b);
            if self.topmost.is_some_and(|v| v == bit) {
                self.find_topmost_set_bit();
            }
            Ok(())
        }
    }

    pub fn set(&mut self, bit: usize) -> Result<(), SimpleBitsetError> {
        let (w, b) = Self::position(bit);
        if w >= N {
            Err(SimpleBitsetError::OutOfBounds)
        } else {
            if self.topmost.is_none_or(|v| v < bit) {
                self.topmost = Some(bit);
            }
            self.words[w] |= T::ONE << b;
            Ok(())
        }
    }

    #[allow(unused)]
    pub fn get(&self, bit: usize) -> Result<bool, SimpleBitsetError> {
        let (w, b) = Self::position(bit);
        if w >= N {
            Err(SimpleBitsetError::OutOfBounds)
        } else {
            Ok(self.words[w] & (T::ONE << b) != T::ZERO)
        }
    }

    pub fn all_bits_in_subset_set(&self, topmost_bit: usize) -> Result<bool, SimpleBitsetError> {
        let (w, b) = Self::position(topmost_bit);
        if w >= N {
            Err(SimpleBitsetError::OutOfBounds)
        } else {
            let result = self.words.into_iter().take(w).all(|word| word == !T::ZERO) && {
                let v = Self::make_bitmask(b);
                (self.words[w] & v) == v
            };
            Ok(result)
        }
    }

    #[allow(unused)]
    pub fn all_bits_set(&self) -> bool {
        self.words.into_iter().all(|word| word == !T::ZERO)
    }

    pub fn shift_left_limited_to_word_size(&mut self, count: usize) -> T {
        debug_assert!(count < Self::BITS_PER_WORD);
        let mut carry_bits = T::ZERO;
        if count > 0 {
            let shift = Self::BITS_PER_WORD - count;
            let mask = Self::make_bitmask(count - 1) << shift;

            for i in 0..N {
                let mut v = self.words[i];
                let bits = (v & mask) >> shift;
                v <<= count;
                self.words[i] = v | carry_bits;
                carry_bits = bits;
            }
        }
        carry_bits
    }

    pub fn shift_left(&mut self, count: usize) -> bool {
        let will_lose_bits = self.topmost.is_some_and(|v| {
            count >= Self::BITS_PER_WORD * N || v + count >= Self::BITS_PER_WORD * N
        });
        if count < Self::BITS_PER_WORD {
            self.shift_left_limited_to_word_size(count);
        } else {
            let (n, shift) = Self::position(count);
            if n < N {
                for i in (n..N).rev() {
                    self.words[i] = self.words[i - n];
                }
                for i in 0..n {
                    self.words[i] = T::ZERO;
                }
                self.shift_left_limited_to_word_size(shift);
            } else {
                self.reset();
            }
        }
        self.find_topmost_set_bit();
        will_lose_bits
    }
}

impl<const N: usize, T> Shl<usize> for SimpleBitset<N, T>
where
    T: Unsigned
        + ConstOne
        + ConstZero
        + PrimInt
        + ShlAssign<usize>
        + BitOrAssign
        + BitAndAssign
        + Copy,
{
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        let mut v = self;
        v.shift_left(rhs);
        v
    }
}

impl<const N: usize, T> ShlAssign<usize> for SimpleBitset<N, T>
where
    T: Unsigned
        + ConstOne
        + ConstZero
        + PrimInt
        + ShlAssign<usize>
        + BitOrAssign
        + BitAndAssign
        + Copy,
{
    fn shl_assign(&mut self, rhs: usize) {
        self.shift_left(rhs);
    }
}

#[cfg(test)]
mod tests {
    use crate::svc::simple_bitset::{SimpleBitset, SimpleBitsetError};

    #[test]
    fn test_bitmap() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<2, u128> = SimpleBitset::new();

        bitset.set(0)?;
        assert_eq!(bitset.words[0], 1);
        assert!(bitset.get(0)?);

        bitset.set(255)?;
        assert_eq!(bitset.words[1], 1 << 127);
        assert!(bitset.get(255)?);

        bitset.clear(255)?;
        assert_eq!(bitset.words[1], 0);

        assert_eq!(bitset.set(1024), Err(SimpleBitsetError::OutOfBounds));
        assert_eq!(bitset.get(1024), Err(SimpleBitsetError::OutOfBounds));
        assert_eq!(bitset.clear(1024), Err(SimpleBitsetError::OutOfBounds));

        Ok(())
    }

    #[test]
    fn test_all_bits_in_subset_set() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<4, u64> = SimpleBitset::new();

        for i in 0..125 {
            bitset.set(i)?;
        }
        assert!(bitset.all_bits_in_subset_set(124)?);

        for i in 0..255 {
            bitset.set(i)?;
        }
        assert!(bitset.all_bits_in_subset_set(254)?);

        Ok(())
    }

    #[test]
    fn test_all_bits_in_subset_set_false() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<4, u64> = SimpleBitset::new();

        // Set bits 0..124 but not bit 124 itself — topmost bit missing.
        for i in 0..124 {
            bitset.set(i)?;
        }
        assert!(!bitset.all_bits_in_subset_set(124)?);

        // Set bit 124 but clear a bit in a prior word — gap in the middle.
        bitset.set(124)?;
        bitset.clear(50)?;
        assert!(!bitset.all_bits_in_subset_set(124)?);

        // Out-of-bounds index must return an error.
        assert_eq!(
            bitset.all_bits_in_subset_set(1024),
            Err(SimpleBitsetError::OutOfBounds)
        );

        Ok(())
    }

    #[test]
    fn test_all_bits_set() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<2, u64> = SimpleBitset::new();
        assert!(!bitset.all_bits_set());

        for i in 0..64 {
            bitset.set(i)?;
        }
        assert!(!bitset.all_bits_set());

        for i in 64..128 {
            bitset.set(i)?;
        }
        assert!(bitset.all_bits_set());

        bitset.clear(50)?;
        assert!(!bitset.all_bits_set());

        Ok(())
    }

    // Exercises the b == 0 path through make_bitmask (topmost_bit is word-aligned).
    #[test]
    fn test_all_bits_in_subset_set_word_boundary() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<4, u64> = SimpleBitset::new();

        for i in 0..=64 {
            bitset.set(i)?;
        }
        assert!(bitset.all_bits_in_subset_set(64)?);

        // Missing bit 64 itself.
        bitset.clear(64)?;
        assert!(!bitset.all_bits_in_subset_set(64)?);

        // Gap in the prior word.
        bitset.set(64)?;
        bitset.clear(32)?;
        assert!(!bitset.all_bits_in_subset_set(64)?);

        Ok(())
    }

    #[test]
    fn test_all_bits_in_subset_set_zero() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<4, u64> = SimpleBitset::new();
        assert!(!bitset.all_bits_in_subset_set(0)?);

        bitset.set(0)?;
        assert!(bitset.all_bits_in_subset_set(0)?);

        Ok(())
    }

    #[test]
    fn test_out_of_bounds_exact() -> Result<(), SimpleBitsetError> {
        let mut bitset: SimpleBitset<4, u64> = SimpleBitset::new();

        bitset.set(255)?;
        assert!(bitset.get(255)?);

        assert_eq!(bitset.set(256), Err(SimpleBitsetError::OutOfBounds));
        assert_eq!(bitset.get(256), Err(SimpleBitsetError::OutOfBounds));
        assert_eq!(bitset.clear(256), Err(SimpleBitsetError::OutOfBounds));
        assert_eq!(
            bitset.all_bits_in_subset_set(256),
            Err(SimpleBitsetError::OutOfBounds)
        );

        Ok(())
    }

    // --- shift_left overflow detection (bool return) ---

    #[test]
    fn test_shift_left_no_overflow() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(10).unwrap();
        assert!(!b.shift_left(5)); // 10 + 5 = 15 < 256
    }

    #[test]
    fn test_shift_left_overflow_exact_boundary() {
        // topmost + count == N * BPW: bit lands exactly out of range.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(255).unwrap();
        assert!(b.shift_left(1)); // 255 + 1 = 256 >= 256
    }

    #[test]
    fn test_shift_left_no_overflow_one_below_boundary() {
        // topmost + count == N * BPW - 1: last valid position.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(254).unwrap();
        assert!(!b.shift_left(1)); // 254 + 1 = 255 < 256
    }

    #[test]
    fn test_shift_left_overflow_large_count_with_bits() {
        // count >= capacity: true even though count is huge.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(0).unwrap();
        assert!(b.shift_left(256));
        assert_eq!(b.words, [0u64; 4]);
    }

    #[test]
    fn test_shift_left_overflow_large_count_empty_bitmap() {
        // No bits set: nothing to lose regardless of count.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        assert!(!b.shift_left(256));
    }

    #[test]
    fn test_shift_left_overflow_multi_word_shift() {
        // Overflow via word-copy path (BITS_PER_WORD <= count < N*BPW).
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(200).unwrap();
        assert!(b.shift_left(60)); // 200 + 60 = 260 >= 256
    }

    // --- shift_left word content ---

    #[test]
    fn test_shift_left_zero_is_noop() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(42).unwrap();
        assert!(!b.shift_left(0));
        assert!(b.get(42).unwrap());
        assert_eq!(b.topmost, Some(42));
    }

    #[test]
    fn test_shift_left_intra_word() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[0] = 0b0101;
        b.shift_left(1);
        assert_eq!(b.words[0], 0b1010);
        assert_eq!(b.words[1], 0);
    }

    #[test]
    fn test_shift_left_word_copy_exact() {
        // Shift of exactly one word width: no intra-word shift.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[0] = 0xF;
        b.shift_left(64);
        assert_eq!(b.words[0], 0);
        assert_eq!(b.words[1], 0xF);
        assert_eq!(b.words[2], 0);
        assert_eq!(b.words[3], 0);
    }

    #[test]
    fn test_shift_left_word_copy_plus_intra() {
        // Shift of one word + one extra bit.
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[0] = 0xF;
        b.words[1] = 0xA;
        b.shift_left(65);
        assert_eq!(b.words[0], 0);
        assert_eq!(b.words[1], 0x1E); // 0xF << 1
        assert_eq!(b.words[2], 0x14); // 0xA << 1
        assert_eq!(b.words[3], 0);
    }

    #[test]
    fn test_shift_left_full_reset_clears_words() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[0] = 0xFF;
        b.words[2] = 0xAB;
        b.shift_left(1000);
        assert_eq!(b.words, [0u64; 4]);
    }

    // --- topmost consistency through shifts ---

    #[test]
    fn test_shift_left_updates_topmost() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(3).unwrap();
        b.shift_left(10);
        assert_eq!(b.topmost, Some(13));
    }

    #[test]
    fn test_shift_left_topmost_none_after_full_shift() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.set(0).unwrap();
        b.shift_left(256);
        assert_eq!(b.topmost, None);
    }

    // --- shift_left_limited_to_word_size carry ---

    #[test]
    fn test_shift_left_limited_carry_single_bit() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[3] = 1u64 << 63;
        let carry = b.shift_left_limited_to_word_size(1);
        assert_eq!(carry, 1);
        assert_eq!(b.words[3], 0);
    }

    #[test]
    fn test_shift_left_limited_carry_multi_bit() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[3] = 0xF << 60;
        let carry = b.shift_left_limited_to_word_size(4);
        assert_eq!(carry, 0xF);
        assert_eq!(b.words[3], 0);
    }

    #[test]
    fn test_shift_left_limited_zero_count() {
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[0] = 0xDEADBEEF;
        let carry = b.shift_left_limited_to_word_size(0);
        assert_eq!(carry, 0);
        assert_eq!(b.words[0], 0xDEADBEEF);
    }

    #[test]
    fn test_shift_left_limited_carry_propagates_across_words() {
        // MSB of words[2] carries into words[3].
        let mut b: SimpleBitset<4, u64> = SimpleBitset::new();
        b.words[2] = 1u64 << 63;
        let carry = b.shift_left_limited_to_word_size(1);
        assert_eq!(carry, 0);
        assert_eq!(b.words[3], 1);
        assert_eq!(b.words[2], 0);
    }
}
