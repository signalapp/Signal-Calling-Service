//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign},
};

/// A wrapper around [`std::time::Instant`] that does not expose panicking `duration_since` operations.
///
/// Instead of subtraction, use `checked_duration_since` or `saturating_duration_since`.
///
/// Note that addition and subtraction of durations that would result in distant-future or
/// distant-past Instants may still panic. Only operations that might result in a negative
/// duration have been forbidden.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(std::time::Instant);

impl Instant {
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0).map(Duration)
    }

    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_duration_since(earlier.0))
    }

    pub fn now() -> Instant {
        Instant(std::time::Instant::now())
    }
}

impl From<std::time::Instant> for Instant {
    fn from(instant: std::time::Instant) -> Self {
        Self(instant)
    }
}

impl From<Instant> for std::time::Instant {
    fn from(instant: Instant) -> Self {
        instant.0
    }
}

impl Debug for Instant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        self.0 -= rhs.0
    }
}

/// A wrapper around [`std::time::SystemTime`] that does not expose errors in the `duration_since` operations.
///
/// Instead of subtraction, use `checked_duration_since` or `saturating_duration_since`.
///
/// Note that addition and subtraction of durations that would result in distant-future or
/// distant-past SystemTime may still panic. Only operations that might result in a negative
/// duration have been forbidden.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime(std::time::SystemTime);

impl SystemTime {
    pub fn checked_duration_since(&self, earlier: SystemTime) -> Option<Duration> {
        self.0.duration_since(earlier.0).ok().map(Duration)
    }

    pub fn saturating_duration_since(&self, earlier: SystemTime) -> Duration {
        self.0
            .duration_since(earlier.0)
            .map_or(Duration::ZERO, Duration)
    }

    pub fn now() -> SystemTime {
        SystemTime(std::time::SystemTime::now())
    }
}

impl From<std::time::SystemTime> for SystemTime {
    fn from(value: std::time::SystemTime) -> Self {
        Self(value)
    }
}

impl From<SystemTime> for std::time::SystemTime {
    fn from(value: SystemTime) -> Self {
        value.0
    }
}

impl Debug for SystemTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign<Duration> for SystemTime {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0
    }
}

impl Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign<Duration> for SystemTime {
    fn sub_assign(&mut self, rhs: Duration) {
        self.0 -= rhs.0
    }
}

/// A wrapper around [`std::time::Duration`] that does not expose panicking difference operations.
///
/// Instead of subtraction, use `checked_sub` or `saturating_sub`.
///
/// Note that addition or multiplication of durations that would result in an overly large duration
/// may still panic. Only operations that could result in a negative duration have been forbidden.
///
/// Only methods of `std::time::Duration` that are used in the project are exposed here.
/// If you need another method of `std::time::Duration`,
/// add a wrapper here rather than converting to the underlying value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(std::time::Duration);

impl Duration {
    pub const ZERO: Duration = Duration::from_secs(0);
    pub const MILLISECOND: Duration = Duration::from_millis(1);
    pub const SECOND: Duration = Duration::from_secs(1);

    pub const fn from_secs(secs: u64) -> Duration {
        Duration(std::time::Duration::from_secs(secs))
    }

    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub fn from_secs_f64(secs: f64) -> Duration {
        Duration(std::time::Duration::from_secs_f64(secs))
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.0.as_secs_f64()
    }

    pub const fn from_millis(millis: u64) -> Duration {
        Duration(std::time::Duration::from_millis(millis))
    }

    pub const fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    pub const fn from_micros(micros: u64) -> Duration {
        Duration(std::time::Duration::from_micros(micros))
    }

    pub const fn as_micros(&self) -> u128 {
        self.0.as_micros()
    }

    pub const fn from_nanos(nanos: u64) -> Duration {
        Duration(std::time::Duration::from_nanos(nanos))
    }

    pub const fn as_nanos(&self) -> u128 {
        self.0.as_nanos()
    }

    pub fn mul_f64(&self, rhs: f64) -> Duration {
        self.0.mul_f64(rhs).into()
    }

    pub fn abs_diff(&self, other: Duration) -> Duration {
        self.0.abs_diff(other.0).into()
    }

    pub const fn subsec_nanos(&self) -> u32 {
        self.0.subsec_nanos()
    }

    pub fn checked_sub(&self, rhs: Duration) -> Option<Duration> {
        self.0.checked_sub(rhs.0).map(Duration)
    }

    pub fn saturating_sub(&self, rhs: Duration) -> Duration {
        // TODO: use std::time::Duration::saturating_sub when stabilized
        self.checked_sub(rhs).unwrap_or_default()
    }

    pub fn truncated_to(&self, unit: Duration) -> Duration {
        assert!(
            unit.0.subsec_nanos() == 0,
            "only works on granularities of 1 second or larger"
        );
        let remainder = self.0.as_secs() % unit.0.as_secs();
        self.saturating_sub(Duration::from_secs(remainder))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<std::time::Duration> for Duration {
    fn from(duration: std::time::Duration) -> Self {
        Self(duration)
    }
}

impl From<Duration> for std::time::Duration {
    fn from(duration: Duration) -> Self {
        duration.0
    }
}

impl Debug for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<Duration> for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Self::Output {
        Duration(self.0 + rhs.0)
    }
}

impl AddAssign<Duration> for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0
    }
}

impl Mul<u32> for Duration {
    type Output = Duration;

    fn mul(self, rhs: u32) -> Self::Output {
        Duration(self.0 * rhs)
    }
}

impl Mul<Duration> for u32 {
    type Output = Duration;

    fn mul(self, rhs: Duration) -> Self::Output {
        rhs * self
    }
}

impl MulAssign<u32> for Duration {
    fn mul_assign(&mut self, rhs: u32) {
        self.0 *= rhs
    }
}

impl Div<u32> for Duration {
    type Output = Duration;

    fn div(self, rhs: u32) -> Self::Output {
        Duration(self.0 / rhs)
    }
}

impl DivAssign<u32> for Duration {
    fn div_assign(&mut self, rhs: u32) {
        self.0 /= rhs
    }
}

impl Sum for Duration {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Duration(iter.map(|x| x.0).sum())
    }
}

impl<'a> Sum<&'a Duration> for Duration {
    fn sum<I: Iterator<Item = &'a Duration>>(iter: I) -> Self {
        Duration(iter.map(|x| x.0).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap() {
        let now = std::time::Instant::now();
        assert_eq!(now, Instant::from(now).into());

        let duration = std::time::Duration::new(5, 10);
        assert_eq!(duration, Duration::from(duration).into());
    }

    #[test]
    fn transparent_debug() {
        let now = std::time::Instant::now();
        assert_eq!(format!("{:?}", now), format!("{:?}", Instant::from(now)));

        let duration = std::time::Duration::new(5, 10);
        assert_eq!(
            format!("{:?}", duration),
            format!("{:?}", Duration::from(duration))
        );
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn duration_from_as() {
        assert_eq!(2.5, Duration::from_secs_f64(2.5).as_secs_f64());
        assert_eq!(2, Duration::from_millis(2).as_millis());
        assert_eq!(2, Duration::from_micros(2).as_micros());
        assert_eq!(2, Duration::from_nanos(2).as_nanos());

        assert_eq!(2.0, Duration::from_secs(2).as_secs_f64());
    }

    #[test]
    fn duration_default() {
        assert_eq!(Duration::from_secs(0), Duration::default());
    }

    #[test]
    fn duration_arithmetic() {
        let short = Duration::from_millis(2);
        let long = Duration::from_secs(5);
        let sum = Duration::from_millis(5002);

        assert_eq!(sum, short + long);
        assert_eq!(Some(long), sum.checked_sub(short));
        assert_eq!(None, short.checked_sub(sum));
        assert_eq!(long, sum.saturating_sub(short));
        assert_eq!(Duration::ZERO, short.saturating_sub(sum));
        assert_eq!(sum, [short, long].iter().sum());
        assert_eq!(sum, vec![short, long].into_iter().sum());

        let mut manual_sum = short;
        manual_sum += long;
        assert_eq!(sum, manual_sum);

        assert_eq!(long, short * 2500);
        let mut manual_product = short;
        manual_product *= 2500;
        assert_eq!(long, manual_product);

        assert_eq!(short, long / 2500);
        let mut manual_quotient = long;
        manual_quotient /= 2500;
        assert_eq!(short, manual_quotient);
    }

    #[test]
    fn instant_arithmetic() {
        let now = Instant::now();
        let duration = Duration::from_millis(2);
        let soon = now + duration;

        assert_eq!(now, soon - duration);
        assert_eq!(Some(duration), soon.checked_duration_since(now));
        assert_eq!(None, now.checked_duration_since(soon));
        assert_eq!(duration, soon.saturating_duration_since(now));
        assert_eq!(Duration::ZERO, now.saturating_duration_since(soon));

        let mut manual_sum = now;
        manual_sum += duration;
        assert_eq!(soon, manual_sum);

        let mut manual_difference = soon;
        manual_difference -= duration;
        assert_eq!(now, manual_difference);
    }
}
