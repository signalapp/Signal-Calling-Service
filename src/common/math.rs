//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::{Add, Mul, Sub};

pub fn round_up_to_multiple_of<const M: usize>(n: usize) -> usize {
    (n + (M - 1)) / M * M
}

#[cfg(test)]
mod round_up_multiple_of_n_tests {
    use super::round_up_to_multiple_of;

    #[test]
    fn round_up_multiple_4() {
        assert_eq!(0, round_up_to_multiple_of::<4>(0));
        assert_eq!(4, round_up_to_multiple_of::<4>(1));
        assert_eq!(4, round_up_to_multiple_of::<4>(2));
        assert_eq!(4, round_up_to_multiple_of::<4>(3));
        assert_eq!(4, round_up_to_multiple_of::<4>(4));
        assert_eq!(8, round_up_to_multiple_of::<4>(5));
        assert_eq!(8, round_up_to_multiple_of::<4>(6));
        assert_eq!(8, round_up_to_multiple_of::<4>(7));
        assert_eq!(8, round_up_to_multiple_of::<4>(8));
        assert_eq!(12, round_up_to_multiple_of::<4>(9));
    }

    #[test]
    fn round_up_multiple_5() {
        assert_eq!(0, round_up_to_multiple_of::<5>(0));
        assert_eq!(5, round_up_to_multiple_of::<5>(1));
        assert_eq!(5, round_up_to_multiple_of::<5>(2));
        assert_eq!(5, round_up_to_multiple_of::<5>(3));
        assert_eq!(5, round_up_to_multiple_of::<5>(4));
        assert_eq!(5, round_up_to_multiple_of::<5>(5));
        assert_eq!(10, round_up_to_multiple_of::<5>(6));
        assert_eq!(10, round_up_to_multiple_of::<5>(10));
        assert_eq!(15, round_up_to_multiple_of::<5>(11));
    }
}

pub trait Square: Copy + Mul + Sized {
    fn square(self) -> Self::Output {
        self * self
    }
}

impl<T: Copy + Mul + Sized> Square for T {}

#[cfg(test)]
mod square_tests {
    use super::Square;

    #[test]
    #[allow(clippy::float_cmp)]
    fn simple() {
        assert_eq!(0, 0.square());
        assert_eq!(4, 2.square());
        assert_eq!(4, (-2).square());

        assert_eq!(0.25, 0.5.square());
    }
}

pub trait AbsDiff: PartialOrd + Sub + Sized {
    fn abs_diff(self, other: Self) -> Self::Output {
        if self > other {
            self - other
        } else {
            other - self
        }
    }
}

impl<T: PartialOrd + Sub + Sized> AbsDiff for T {}

#[cfg(test)]
mod abs_diff_tests {
    use super::AbsDiff;

    #[test]
    #[allow(clippy::float_cmp)]
    fn positive() {
        assert_eq!(0, 1.abs_diff(1));
        assert_eq!(5, 10.abs_diff(15));
        assert_eq!(5, 15.abs_diff(10));

        assert_eq!(5.0, 15.0.abs_diff(10.0));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn negative() {
        assert_eq!(0, (-1).abs_diff(-1));
        assert_eq!(5, (-10).abs_diff(-15));
        assert_eq!(5, (-15).abs_diff(-10));

        assert_eq!(5.0, (-15.0).abs_diff(-10.0));
    }

    #[test]
    fn non_numeric() {
        // Use the std Instant because ours deliberately doesn't implement Sub.
        let now = std::time::Instant::now();
        let interval = std::time::Duration::from_millis(25);

        assert_eq!(interval, now.abs_diff(now + interval));
        assert_eq!(interval, (now + interval).abs_diff(now));
    }
}

pub fn exponential_moving_average<T: Mul<f64, Output = T> + Add<T, Output = T>>(
    average: T,
    alpha: f64,
    update: T,
) -> T {
    (update * alpha) + (average * (1.0 - alpha))
}

#[cfg(test)]
mod exponential_moving_average_tests {
    use crate::common::exponential_moving_average;

    #[test]
    #[allow(clippy::float_cmp)]
    fn interpolation() {
        assert_eq!(10.0, exponential_moving_average(10.0, 0.0, 20.0));
        assert_eq!(15.0, exponential_moving_average(10.0, 0.5, 20.0));
        assert_eq!(20.0, exponential_moving_average(10.0, 1.0, 20.0));
    }
}
