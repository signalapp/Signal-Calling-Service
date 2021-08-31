//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    convert::{TryFrom, TryInto},
    ops::Sub,
};

/// Expands a truncated counter value to the full length by using the previous largest value as
/// guide to rollover/rollunder. Updates this maximum.
///
/// # Arguments
///
/// * `truncated` - The truncated counter value.
/// * `max` - The previously return value from this function.
/// * `width` - The bit width the supplied value has been truncated to.  
pub fn expand_truncated_counter<Truncated>(truncated: Truncated, max: &mut u64, width: usize) -> u64
where
    Truncated: TryFrom<u64> + Into<u64> + Sub<Truncated, Output = Truncated> + Ord + Copy,
    <Truncated as TryFrom<u64>>::Error: std::fmt::Debug,
{
    let mask: u64 = (1 << width) - 1;
    let really_big: Truncated = (1 << (width - 1)).try_into().unwrap();

    let truncated_max = (*max & mask).try_into().unwrap();
    let max_roc = *max >> width;
    let roc: u64 = if truncated_max > truncated && truncated_max - truncated > really_big {
        // Truncated is a lot smaller than the max;  It's likely a rollover.
        max_roc + 1
    } else if max_roc > 0 && truncated > truncated_max && truncated - truncated_max > really_big {
        // Truncated is a lot bigger than the max;  It's likely a rollunder.
        max_roc - 1
    } else {
        // Truncated is close to the max, so it's neither rollover nor rollunder.
        max_roc
    };
    let full = (roc << width) | (truncated.into() & mask);
    if full > *max {
        *max = full;
    }
    full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_max() {
        let mut max = 0u64;
        let expanded = expand_truncated_counter(0x3u16, &mut max, 16);
        assert_eq!(0x3u64, expanded);
        assert_eq!(0x3u64, max);
    }

    #[test]
    fn roll_over() {
        let mut max = 0xffffu64;
        let expanded = expand_truncated_counter(0x0001u16, &mut max, 16);
        assert_eq!(0x10001u64, expanded);
        assert_eq!(0x10001u64, max);
    }

    #[test]
    fn roll_over_larger_roc() {
        let mut max = 0x3ffffu64;
        let expanded = expand_truncated_counter(0x0001u16, &mut max, 16);
        assert_eq!(0x40001u64, expanded);
        assert_eq!(0x40001u64, max);
    }

    #[test]
    fn roll_under() {
        let mut max = 0x10001u64;
        let expanded = expand_truncated_counter(0xffffu16, &mut max, 16);
        assert_eq!(0xffffu64, expanded);
        assert_eq!(0x10001u64, max);
    }

    #[test]
    fn roll_under_larger_roc() {
        let mut max = 0x30001u64;
        let expanded = expand_truncated_counter(0xffffu16, &mut max, 16);
        assert_eq!(0x2ffffu64, expanded);
        assert_eq!(0x30001u64, max);
    }

    #[test]
    fn non_8_multiple_bits() {
        let mut max = 0b0011_1111;
        let expanded = expand_truncated_counter(0b0000u8, &mut max, 4);
        assert_eq!(0b0100_0000u64, expanded);
        assert_eq!(0b0100_0000u64, max);
        let expanded = expand_truncated_counter(0b1000u8, &mut max, 4);
        assert_eq!(0b0100_1000u64, expanded);
        assert_eq!(0b0100_1000u64, max);
        let expanded = expand_truncated_counter(0b0100u8, &mut max, 4);
        assert_eq!(0b0100_0100u64, expanded);
        assert_eq!(0b0100_1000u64, max);
        let expanded = expand_truncated_counter(0b1101u8, &mut max, 4);
        assert_eq!(0b0100_1101u64, expanded);
        assert_eq!(0b0100_1101u64, max);
        let expanded = expand_truncated_counter(0b0001u8, &mut max, 4);
        assert_eq!(0b0101_0001u64, expanded);
        assert_eq!(0b0101_0001u64, max);
        let expanded = expand_truncated_counter(0b1101u8, &mut max, 4);
        assert_eq!(0b0100_1101u64, expanded);
        assert_eq!(0b0101_0001u64, max);
    }
}
