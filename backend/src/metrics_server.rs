//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

#[cfg(target_os = "linux")]
use accounting_allocator::AccountingAlloc;
use anyhow::Result;
use log::*;
use metrics::{
    metric_config::{
        Client as DatadogClient, Histogram, HistogramReport, PipelineSink, Precision, TagsRef,
        UdpEventSink,
    },
    metrics, time_scope_us,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use psutil::process::Process;
use tokio::sync::oneshot::Receiver;

use crate::{
    config::{self, Config},
    sfu::Sfu,
};

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL_ALLOCATOR: AccountingAlloc = AccountingAlloc::new();

static CURRENT_PROCESS: Lazy<Mutex<Process>> =
    Lazy::new(|| Mutex::new(Process::current().expect("Can't get current process")));

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    shutdown_signal_rx: Receiver<()>,
) -> Result<()> {
    match Datadog::new(config) {
        None => {
            metrics!().disable();
            info!("metrics server not started because not configured, metrics disabled");

            tokio::select!(
                _ = shutdown_signal_rx => {},
            );

            Ok(())
        }
        Some(mut datadog) => {
            let tick_handle = tokio::spawn(async move {
                let mut tick_interval = tokio::time::interval(Duration::from_secs(60));

                #[cfg(target_os = "linux")]
                let mut last_alloc = 0;

                loop {
                    tick_interval.tick().await;
                    let mut datadog = datadog.open_pipeline();

                    for (metric_name, value) in get_value_metrics() {
                        datadog.gauge(metric_name, value as f64);
                    }

                    {
                        time_scope_us!("calling.sfu.get_stats");
                        // Note that we are including the time waiting for the lock in this stat.

                        let stats = sfu.lock().get_stats();
                        for (name, histogram_map) in stats.histograms {
                            for (tags, histogram) in histogram_map {
                                datadog.send_count_histogram(name, &histogram, tags);
                            }
                        }
                        for (name, value) in stats.values {
                            datadog.gauge(name, value as f64);
                        }
                    }

                    let report = metrics!().report();
                    for report in report.histograms {
                        datadog.send_timer_histogram(&report);
                    }
                    for report in report.events {
                        datadog.count_with_tags(
                            report.name(),
                            report.event_count() as f64,
                            report.tags(),
                        );
                    }

                    #[cfg(target_os = "linux")]
                    {
                        let stats = GLOBAL_ALLOCATOR.count();
                        let alloc = stats.all_time.alloc;
                        let dealloc = stats.all_time.dealloc;

                        datadog.count(
                            "calling.system.memory.new_alloc_bytes",
                            (alloc - last_alloc) as f64,
                        );
                        datadog.gauge(
                            "calling.system.memory.net_alloc_bytes",
                            (alloc - dealloc) as f64,
                        );
                        last_alloc = alloc;
                    }
                }
            });

            tokio::select!(
                _ = tick_handle => {},
                _ = shutdown_signal_rx => {},
            );

            info!("metrics server shutdown");

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
        let host = config.metrics.datadog.as_ref()?;

        let sink = UdpEventSink::new(host).unwrap();
        let media_server = config::ServerMediaAddress::from(config);
        let source = media_server.ip();

        let mut point_tags = vec![
            ("region", config.metrics.region.clone()),
            ("source", source.to_string()),
        ];

        if let Some(version) = &config.metrics.version {
            point_tags.push(("version", version.to_string()));
        }

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
    fn send_timer_histogram(&mut self, histogram_report: &HistogramReport) {
        self.send_timer_histogram_with_tags::<&str>(histogram_report, None);
    }

    fn send_timer_histogram_with_tags<T: AsRef<str>>(
        &mut self,
        histogram_report: &HistogramReport,
        tags: TagsRef<T>,
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

    fn send_count_histogram<T: AsRef<str>>(
        &mut self,
        metric_name: &str,
        histogram: &Histogram<usize>,
        tags: TagsRef<T>,
    ) {
        for (value, frequency) in histogram.iter() {
            self.histogram_at_rate(metric_name, *value as f64, 1f64 / (*frequency as f64), tags);
            self.distribution_at_rate(metric_name, *value as f64, 1f64 / (*frequency as f64), tags);
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

    let mut current_process = CURRENT_PROCESS.lock();

    match current_process.memory_percent() {
        Ok(memory_percentage) => {
            value_metrics.push(("calling.system.memory.pc", memory_percentage));
        }
        Err(e) => {
            warn!("Error getting memory percentage {:?}", e)
        }
    }

    #[cfg(target_os = "linux")] // open_files is not yet implemented for macos
    match current_process.open_files() {
        Ok(open_files) => {
            value_metrics.push(("calling.system.memory.fd.count", open_files.len() as f32));
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
            value_metrics.push(("calling.system.cpu.pc", cpu_percentage));
        }
        Err(e) => {
            warn!("Error getting cpu percentage {:?}", e)
        }
    }

    value_metrics
}
