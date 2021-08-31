//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::{Add, Mul, Sub};

use crate::common::{Duration, Instant};

/// Like [Duration], but can be negative, and may not have the same precision.
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct TimeDelta {
    secs: f64,
}

impl TimeDelta {
    pub fn from_secs(secs: f64) -> Self {
        Self { secs }
    }

    pub fn from_millis(millis: f64) -> Self {
        Self::from_secs(millis / 1000.0)
    }

    pub fn as_secs(self) -> f64 {
        self.secs
    }
}

impl Add<TimeDelta> for TimeDelta {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self::from_secs(self.as_secs() + other.as_secs())
    }
}

impl Add<Duration> for TimeDelta {
    type Output = Self;

    fn add(self, other: Duration) -> Self {
        Self::from_secs(self.as_secs() + other.as_secs_f64())
    }
}

impl Sub<TimeDelta> for TimeDelta {
    type Output = Self;

    fn sub(self, other: TimeDelta) -> Self {
        Self::from_secs(self.as_secs() - other.as_secs())
    }
}

impl Sub<Duration> for TimeDelta {
    type Output = Self;

    fn sub(self, other: Duration) -> Self {
        Self::from_secs(self.as_secs() - other.as_secs_f64())
    }
}

impl Mul<f64> for TimeDelta {
    type Output = Self;

    fn mul(self, other: f64) -> Self {
        Self::from_secs(self.as_secs() * other)
    }
}

pub trait TimeDeltaSince {
    fn time_delta_since(self, other: Self) -> TimeDelta;
}

impl TimeDeltaSince for Instant {
    fn time_delta_since(self, other: Self) -> TimeDelta {
        if self > other {
            TimeDelta::from_secs(self.checked_duration_since(other).unwrap().as_secs_f64())
        } else {
            TimeDelta::from_secs(-other.checked_duration_since(self).unwrap().as_secs_f64())
        }
    }
}

impl TimeDeltaSince for crate::transportcc::RemoteInstant {
    fn time_delta_since(self, other: Self) -> TimeDelta {
        if self > other {
            TimeDelta::from_secs(self.saturating_duration_since(other).as_secs_f64())
        } else {
            TimeDelta::from_secs(-other.saturating_duration_since(self).as_secs_f64())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transportcc::RemoteInstant;

    #[test]
    #[allow(clippy::float_cmp)]
    fn from_and_as() {
        assert_eq!(TimeDelta::from_secs(2.5).as_secs(), 2.5);
        assert_eq!(TimeDelta::from_millis(2.5).as_secs(), 0.0025);
        assert_eq!(TimeDelta::from_secs(-2.5).as_secs(), -2.5);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn time_delta_since() {
        assert_eq!(
            RemoteInstant::from_millis(2500)
                .time_delta_since(RemoteInstant::from_millis(250))
                .as_secs(),
            2.25
        );
        assert_eq!(
            RemoteInstant::from_millis(250)
                .time_delta_since(RemoteInstant::from_millis(2500))
                .as_secs(),
            -2.25
        );

        let now = Instant::now();
        let duration = Duration::from_millis(2500);
        assert_eq!((now + duration).time_delta_since(now).as_secs(), 2.5);
        assert_eq!(now.time_delta_since(now + duration).as_secs(), -2.5);
    }

    #[test]
    fn add_and_sub() {
        assert_eq!(
            TimeDelta::from_secs(2.5) + TimeDelta::from_secs(5.25),
            TimeDelta::from_secs(7.75)
        );
        assert_eq!(
            TimeDelta::from_secs(2.5) + Duration::from_millis(5250),
            TimeDelta::from_secs(7.75)
        );
        assert_eq!(
            TimeDelta::from_secs(2.25) - TimeDelta::from_secs(2.5),
            TimeDelta::from_secs(-0.25)
        );
        assert_eq!(
            TimeDelta::from_secs(2.25) - Duration::from_millis(2500),
            TimeDelta::from_secs(-0.25)
        );
    }

    #[test]
    fn mul() {
        assert_eq!(TimeDelta::from_secs(2.5) * 3.0, TimeDelta::from_secs(7.5));
    }
}
