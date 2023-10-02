//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use datadog_statsd::*;
pub use histogram::*;
pub use macros::*;
pub use reporter::*;
pub use timing_options::*;

#[macro_use]
mod macros;

mod datadog_statsd;
pub mod histogram;
mod reporter;
mod test_utils;
mod timing_options;

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use log::*;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use psutil::process::Process;
use tokio::sync::oneshot::Receiver;

use crate::{
    config::Config,
    frontend::Frontend,
    metrics::{Client as DatadogClient, Histogram},
};

pub async fn start(frontend: Arc<Frontend>, shutdown_signal_rx: Receiver<()>) -> Result<()> {
    match Datadog::new(frontend.config) {
        None => {
            metrics!().disable();

            let tick_handle = tokio::spawn(async move {
                let mut tick_interval = tokio::time::interval(Duration::from_secs(30));

                loop {
                    tick_interval.tick().await;

                    // For testing, just get the api_metrics lock and clear out and reset any
                    // accumulated metrics.
                    let mut api_metrics = frontend.api_metrics.lock();

                    for histogram in api_metrics.latencies.values_mut() {
                        histogram.clear();
                    }

                    for value in api_metrics.counts.values_mut() {
                        *value = 0;
                    }
                }
            });

            info!("metrics ready (for testing)");

            tokio::select!(
                _ = tick_handle => {},
                _ = shutdown_signal_rx => {},
            );

            info!("metrics shutdown");
            Ok(())
        }
        Some(mut datadog) => {
            let tick_handle = tokio::spawn(async move {
                let mut tick_interval = tokio::time::interval(Duration::from_secs(30));

                loop {
                    tick_interval.tick().await;

                    let mut datadog = datadog.open_pipeline();

                    for (metric_name, value) in get_value_metrics() {
                        datadog.gauge(metric_name, value as f64, &None);
                    }

                    let report = metrics!().report();
                    for report in report.histograms {
                        datadog.send_timer_histogram(&report, &None);
                    }
                    for report in report.events {
                        datadog.count(report.name(), report.event_count() as f64, &None);
                    }

                    let mut api_metrics = frontend.api_metrics.lock();

                    for (name, histogram) in &mut api_metrics.latencies {
                        datadog.send_latency_histogram(name, histogram, &None);
                        histogram.clear();
                    }

                    for (name, value) in &mut api_metrics.counts {
                        datadog.count(name, *value as f64, &None);
                        *value = 0;
                    }
                }
            });

            info!("metrics ready");

            tokio::select!(
                _ = tick_handle => {},
                _ = shutdown_signal_rx => {},
            );

            info!("metrics shutdown");
            Ok(())
        }
    }
}

struct Datadog {
    client: DatadogClient<UdpEventSink>,
}

struct DatadogPipeline<'a>(DatadogClient<PipelineSink<'a, UdpEventSink>>);

impl Datadog {
    fn new(config: &'static Config) -> Option<Self> {
        let host = config.metrics_datadog_host.as_ref()?;

        let sink = UdpEventSink::new(host).unwrap();

        let point_tags = vec![
            ("region", config.region.to_string()),
            ("version", config.version.to_string()),
            ("source", config.server_ip.to_string()),
        ];

        let constant_tags: Vec<_> = point_tags
            .iter()
            .map(|(a, b)| format!("{}:{}", a, b))
            .collect();

        let constant_tags: Vec<_> = constant_tags.iter().map(|a| a.as_ref()).collect();

        let client = DatadogClient::new(sink, "", Some(constant_tags));

        Some(Self { client })
    }

    fn open_pipeline(&mut self) -> DatadogPipeline<'_> {
        DatadogPipeline(self.client.pipeline())
    }
}

impl<'a> Deref for DatadogPipeline<'a> {
    type Target = DatadogClient<PipelineSink<'a, UdpEventSink>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for DatadogPipeline<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> DatadogPipeline<'a> {
    fn send_timer_histogram(
        &mut self,
        histogram_report: &HistogramReport,
        tags: &Option<Vec<&str>>,
    ) {
        let name = histogram_report.name();

        let precision = histogram_report.sample_precision();

        let factor = match precision {
            Precision::Centisecond => 10f64,
            Precision::Millisecond => 1f64,
            Precision::Microsecond => 0.001f64,
            Precision::Nanosecond => 0.000_001f64,
        };

        for (value, frequency) in histogram_report.histogram.iter() {
            self.timer_at_rate(
                name,
                *value as f64 * factor,
                1f64 / (*frequency as f64),
                tags,
            );
            self.distribution_at_rate(
                name,
                *value as f64 * factor,
                1f64 / (*frequency as f64),
                tags,
            );
        }
    }

    fn send_latency_histogram(
        &mut self,
        metric_name: &str,
        histogram: &Histogram<u64>,
        tags: &Option<Vec<&str>>,
    ) {
        for (value, frequency) in histogram.iter() {
            let value_seconds = *value as f64 / 1000000.0;
            self.histogram_at_rate(metric_name, value_seconds, 1f64 / (*frequency as f64), tags);
            self.distribution_at_rate(metric_name, value_seconds, 1f64 / (*frequency as f64), tags);
        }
    }
}

/// Gets a vector of (metric_names, values)
fn get_value_metrics() -> Vec<(&'static str, f32)> {
    let mut value_metrics = Vec::new();

    value_metrics.extend(get_process_metrics());

    value_metrics
}

/// Gets a vector of (metric_names, values) for current process metrics
fn get_process_metrics() -> Vec<(&'static str, f32)> {
    let mut value_metrics = Vec::new();

    static CURRENT_PROCESS: Lazy<Mutex<Process>> =
        Lazy::new(|| Mutex::new(Process::current().expect("Can't get current process")));

    let mut current_process = CURRENT_PROCESS.lock();

    match current_process.memory_percent() {
        Ok(memory_percentage) => {
            value_metrics.push(("calling.frontend.system.memory.pc", memory_percentage));
        }
        Err(e) => {
            warn!("Error getting memory percentage {:?}", e)
        }
    }

    #[cfg(target_os = "linux")]
    match current_process.open_files() {
        Ok(open_files) => {
            value_metrics.push((
                "calling.frontend.system.memory.fd.count",
                open_files.len() as f32,
            ));
        }
        Err(psutil::process::ProcessError::NoSuchProcess { .. }) => {
            // This is really "no such *file*", which can happen if a file descriptor is closed
            // while open_files() runs. See https://github.com/rust-psutil/rust-psutil/issues/106.
            // We could retry, but it's fine to just skip the metric until next time.
        }
        Err(e) => {
            warn!("Error getting fd count {:?}", e)
        }
    }

    match current_process.cpu_percent() {
        Ok(cpu_percentage) => {
            value_metrics.push(("calling.frontend.system.cpu.pc", cpu_percentage));
        }
        Err(e) => {
            warn!("Error getting cpu percentage {:?}", e)
        }
    }

    value_metrics
}
