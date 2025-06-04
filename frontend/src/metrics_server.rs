//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use log::*;
use metrics::{
    metric_config::{Client as DatadogClient, *},
    *,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use psutil::process::Process;
use tokio::sync::oneshot::Receiver;

use crate::{config::Config, frontend::Frontend};

pub async fn start(
    frontend: Arc<Frontend>,
    shutdown_signal_rx: Receiver<()>,
    fd_limit: usize,
) -> Result<()> {
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

                    for histogram_map in api_metrics.latencies.values_mut() {
                        histogram_map.clear();
                    }

                    for value_map in api_metrics.counts.values_mut() {
                        value_map.clear();
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

                    for (metric_name, value) in get_value_metrics(fd_limit) {
                        datadog.gauge(metric_name, value as f64);
                    }

                    let report = metrics!().report();
                    for report in report.sampling_histograms {
                        datadog.send_timer_histogram(&report, &None);
                    }
                    for report in report.events {
                        datadog.count_with_tags(
                            report.name(),
                            report.event_count() as f64,
                            report.tags(),
                        );
                    }

                    let mut api_metrics = frontend.api_metrics.lock();

                    for (name, histogram_map) in &mut api_metrics.latencies {
                        for (tags, histogram) in histogram_map {
                            datadog.send_latency_histogram(name, histogram, tags.as_ref());
                            histogram.clear();
                        }
                    }

                    for (name, value_map) in &mut api_metrics.counts {
                        for (tags, value) in value_map {
                            datadog.count_with_tags(name, *value as f64, tags.as_ref());
                            *value = 0;
                        }
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

        let point_tags = [
            ("region", &config.region),
            ("version", &config.version),
            ("source", &config.server_ip.to_string()),
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

impl DerefMut for DatadogPipeline<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DatadogPipeline<'_> {
    fn send_timer_histogram(
        &mut self,
        histogram_report: &SamplingHistogramReport,
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
            self.timer_at_rate_with_tags(
                name,
                *value as f64 * factor,
                1f64 / (*frequency as f64),
                tags.as_ref(),
            );
            self.distribution_at_rate(
                name,
                *value as f64 * factor,
                1f64 / (*frequency as f64),
                tags.as_ref(),
            );
        }
    }

    fn send_latency_histogram<T: AsRef<str>>(
        &mut self,
        metric_name: &str,
        histogram: &Histogram<u64>,
        tags: TagsRef<T>,
    ) {
        for (value, frequency) in histogram.iter() {
            let value_seconds = *value as f64 / 1000000.0;
            self.distribution_at_rate(metric_name, value_seconds, 1f64 / (*frequency as f64), tags);
        }
    }
}

/// Gets a vector of (metric_names, values)
fn get_value_metrics(fd_limit: usize) -> Vec<(&'static str, f32)> {
    let mut value_metrics = Vec::new();

    value_metrics.extend(get_process_metrics(fd_limit));

    value_metrics
}

/// Gets a vector of (metric_names, values) for current process metrics
fn get_process_metrics(fd_limit: usize) -> Vec<(&'static str, f32)> {
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match current_process.open_files() {
        Ok(open_files) => {
            let fd_count = open_files.len();
            value_metrics.push(("calling.frontend.system.memory.fd.count", fd_count as f32));
            value_metrics.push((
                "calling.frontend.system.memory.fd.avail",
                (fd_limit - fd_count) as f32,
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
