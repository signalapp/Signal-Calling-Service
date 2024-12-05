//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::macros::Metrics;
use log::{error, info};
use once_cell::sync::Lazy;
use std::thread::JoinHandle;
use std::time::Duration;

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
pub mod tags;
mod test_utils;
mod timing_options;

pub fn monitor_deadlocks(
    monitor_interval: Duration,
    ender_rx: std::sync::mpsc::Receiver<()>,
) -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        if ender_rx.try_recv().is_ok() {
            info!("Signal received, exiting monitor_deadlocks");
            return;
        }

        let deadlocks = parking_lot::deadlock::check_deadlock();
        if !deadlocks.is_empty() {
            let deadlock_debug_string = deadlocks
                .iter()
                .enumerate()
                .map(|(i, threads)| {
                    let thread_traces = threads
                        .iter()
                        .map(|t| format!("Thread Id {:#?}: {:?}", t.thread_id(), t.backtrace()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("Deadlock #{i}\n{}", thread_traces)
                })
                .collect::<Vec<_>>()
                .join("\n");
            error!(
                "Detected {} deadlocks:\n{deadlock_debug_string}",
                deadlocks.len()
            );
            event!("calling.operations.deadlock")
        }

        std::thread::sleep(monitor_interval);
    })
}
