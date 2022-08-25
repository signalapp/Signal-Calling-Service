//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug)]
pub struct TimingOptions {
    /// How many samples you want to take in the reporting period.
    ///
    /// The timer will adjust automatically to take this many from the second reporting period onwards.
    pub target_sample_rate: usize,

    /// The precision the durations will be recorded at on the histogram.
    pub sample_precision: Precision,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Precision {
    Centisecond,
    Millisecond,
    Microsecond,
    Nanosecond,
}

impl TimingOptions {
    const DEFAULT: TimingOptions = TimingOptions {
        target_sample_rate: 1_000,
        sample_precision: Precision::Millisecond,
    };

    pub fn microsecond_1000_per_minute() -> TimingOptions {
        TimingOptions {
            target_sample_rate: 1_000,
            sample_precision: Precision::Microsecond,
        }
    }

    pub fn nanosecond_1000_per_minute() -> TimingOptions {
        TimingOptions {
            target_sample_rate: 1_000,
            sample_precision: Precision::Nanosecond,
        }
    }
}

impl Default for TimingOptions {
    fn default() -> Self {
        TimingOptions::DEFAULT
    }
}
