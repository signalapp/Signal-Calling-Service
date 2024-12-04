//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::macros::Metrics;
use once_cell::sync::Lazy;

pub static __METRICS: Lazy<Metrics> = Lazy::new(Metrics::new_enabled);

pub mod metric_config {
    pub use crate::datadog_statsd::*;
    pub use crate::histogram::*;
    pub use crate::reporter::*;
    pub use crate::timing_options::*;
}

#[macro_use]
mod macros;
mod datadog_statsd;
mod histogram;
mod reporter;
mod test_utils;
mod timing_options;
