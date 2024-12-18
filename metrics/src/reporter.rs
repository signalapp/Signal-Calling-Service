//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(not(test))]
use std::time::Instant;
use std::{
    collections::HashMap,
    mem,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

#[cfg(test)]
use mock_instant::Instant;
use parking_lot::Mutex;

use crate::{
    histogram::Histogram,
    metric_config::StaticStrTagsRef,
    timing_options::{Precision, TimingOptions},
};

/// Represents a sampler for collecting histograms of values of any unit.
/// e.g. they might be times, or packets sizes.
pub struct NumericValueReporter {
    name: &'static str,
    measurements_since_last_report: Mutex<SinceLastReport>,
    event_counter: AtomicUsize,
    /// 1 in every sample_interval will be actually be measured.
    sample_interval: AtomicUsize,
    options: TimingOptions,
}

/// The internally mutable component of the performance measuring system.
struct SinceLastReport {
    histogram: Histogram<usize>,
    initial_event_counter: usize,
    sample_count: usize,
}

impl NumericValueReporter {
    pub fn new(name: &'static str, options: TimingOptions) -> NumericValueReporter {
        NumericValueReporter {
            name,
            measurements_since_last_report: Mutex::new(SinceLastReport::new(0)),
            event_counter: AtomicUsize::new(0),
            sample_interval: AtomicUsize::new(1),
            options,
        }
    }

    fn sample_interval_is_enabled(sample_interval: usize) -> bool {
        sample_interval != usize::MAX
    }

    pub fn disable(&self) {
        self.sample_interval.store(usize::MAX, Ordering::Relaxed);
    }

    #[must_use = "If you don't want to assign to a local and drop manually, then use time_scope! macro"]
    pub fn start_timer(&self) -> impl Timer + '_ {
        self.sample(|sample_interval| RunningTimer::start(self, Instant::now(), sample_interval))
    }

    /// This will use the sampling interval and only invoke the sampler periodically to push an
    /// arbitrary unit value to the histogram.
    pub fn push(&self, sampler: impl FnOnce() -> usize) {
        self.sample(|sample_interval| self.push_sample(sampler(), sample_interval));
    }

    /// Executes the supplied sampler according to the sample interval.
    fn sample<T>(&self, sampler: impl FnOnce(usize) -> T) -> Option<T> {
        let sample_interval = self.sample_interval.load(Ordering::Relaxed);
        if Self::sample_interval_is_enabled(sample_interval) {
            let previous_counter = self.event_counter.fetch_add(1, Ordering::AcqRel);
            if previous_counter % sample_interval == (sample_interval - 1) {
                return Some(sampler(sample_interval));
            }
        };
        None
    }

    fn push_time_sample(&self, sample: Duration, sample_interval: usize) {
        let value = match self.options.sample_precision {
            Precision::Centisecond => sample.as_millis() as usize / 10,
            Precision::Millisecond => sample.as_millis() as usize,
            Precision::Microsecond => sample.as_micros() as usize,
            Precision::Nanosecond => sample.as_nanos() as usize,
        };
        self.push_sample(value, sample_interval);
    }

    fn push_sample(&self, sample: usize, sample_interval: usize) {
        self.measurements_since_last_report
            .lock()
            .push_sample(sample, sample_interval);
    }

    /// Creates a report of timings and resets the reporter.
    pub fn report(&self) -> SamplingHistogramReport {
        let event_count = self.event_counter.load(Ordering::Relaxed);
        let last_sample_interval = self.sample_interval.load(Ordering::Relaxed);

        let since_last_report = {
            let mut times_since_last_report = self.measurements_since_last_report.lock();

            mem::replace(
                &mut *times_since_last_report,
                SinceLastReport::new(event_count),
            )
        };

        let events_since_last_report = event_count - since_last_report.initial_event_counter;

        if Self::sample_interval_is_enabled(last_sample_interval) {
            self.sample_interval.store(
                Self::calculate_sample_rate(
                    events_since_last_report,
                    self.options.target_sample_rate,
                ),
                Ordering::Relaxed,
            );
        }

        SamplingHistogramReport {
            name: self.name,
            sample_interval: last_sample_interval,
            histogram: since_last_report.histogram,
            event_count: events_since_last_report,
            sample_count: since_last_report.sample_count,
            sample_precision: self.options.sample_precision,
        }
    }

    fn calculate_sample_rate(actual_count: usize, target_rate: usize) -> usize {
        (actual_count / target_rate).max(1)
    }
}

#[derive(Debug)]
pub struct ValueHistogramReport {
    pub name: &'static str,
    pub histogram: Histogram<usize>,
    pub tags: StaticStrTagsRef,
}

pub struct ValueHistogramReporter {
    name: &'static str,
    histograms: parking_lot::RwLock<HashMap<StaticStrTagsRef, Mutex<Histogram<usize>>>>,
}

impl ValueHistogramReporter {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            histograms: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// This will count n events.
    pub fn push(&self, value: usize) {
        self.push_tagged(value, None)
    }

    pub fn push_tagged(&self, value: usize, tags: StaticStrTagsRef) {
        if let Some(histogram) = self.histograms.read().get(&tags) {
            histogram.lock().push(value);
            return;
        }

        // Must recheck entry in case it was made while waiting for write lock
        self.histograms
            .write()
            .entry(tags.to_owned())
            .or_insert_with(|| Mutex::new(Histogram::default()))
            .lock()
            .push(value);
    }

    pub fn report(&self) -> Vec<ValueHistogramReport> {
        self.histograms
            .read()
            .iter()
            .map(|(tags, histogram)| {
                let mut histogram = histogram.lock();
                let report = ValueHistogramReport {
                    name: self.name,
                    histogram: histogram.clone(),
                    tags: tags.to_owned(),
                };
                histogram.clear();
                report
            })
            .collect()
    }
}

pub struct EventCountReporter {
    name: &'static str,
    event_counters: parking_lot::RwLock<HashMap<StaticStrTagsRef, AtomicUsize>>,
}

impl EventCountReporter {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            event_counters: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// This will count n events.
    pub fn count_n(&self, n: usize) {
        self.count_n_tagged(n, None)
    }

    pub fn count_n_tagged(&self, n: usize, tags: StaticStrTagsRef) {
        if let Some(counter) = self.event_counters.read().get(&tags) {
            counter.fetch_add(n, Ordering::Relaxed);
            return;
        }

        // Must recheck entry in case it was made while waiting for write lock
        self.event_counters
            .write()
            .entry(tags.to_owned())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// This will count an event.
    pub fn count(&self) {
        self.count_n_tagged(1, None);
    }

    /// Grab the event count and reset to zero.
    pub fn report(&self) -> Vec<EventReport> {
        self.event_counters
            .read()
            .iter()
            .map(|(tags, counter)| EventReport {
                name: self.name,
                event_count: counter.swap(0, Ordering::Relaxed),
                tags: tags.to_owned(),
            })
            .collect()
    }
}

struct RunningTimer<'a> {
    reporter: &'a NumericValueReporter,
    start_time: Instant,
    sample_interval: usize,
}

pub trait Timer {
    fn stop(self);
}

impl<'a> RunningTimer<'a> {
    fn start(
        reporter: &'a NumericValueReporter,
        start_time: Instant,
        sample_interval: usize,
    ) -> RunningTimer<'a> {
        RunningTimer {
            reporter,
            start_time,
            sample_interval,
        }
    }

    fn stop(&mut self) {
        self.reporter
            .push_time_sample(self.start_time.elapsed(), self.sample_interval);
    }
}

impl<'a> Drop for RunningTimer<'a> {
    fn drop(&mut self) {
        self.stop();
    }
}

impl<'a> Timer for RunningTimer<'a> {
    fn stop(self) {}
}

impl<T: Timer> Timer for Option<T> {
    fn stop(self) {
        if let Some(stoppable) = self {
            stoppable.stop();
        }
    }
}

#[derive(Debug)]
pub struct SamplingHistogramReport {
    name: &'static str,
    sample_interval: usize,
    event_count: usize,
    sample_count: usize,
    pub histogram: Histogram<usize>,
    sample_precision: Precision,
}

impl SamplingHistogramReport {
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Actual number of times this event started in this reporting period.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Number of times this event was sampled in the time period.
    pub fn sample_count(&self) -> usize {
        self.sample_count
    }

    /// 1 in sample_intervals were actually recorded.
    pub fn sample_interval(&self) -> usize {
        self.sample_interval
    }

    pub fn sample_precision(&self) -> Precision {
        self.sample_precision
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct EventReport {
    name: &'static str,
    event_count: usize,
    tags: StaticStrTagsRef,
}

impl EventReport {
    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn event_count(&self) -> usize {
        self.event_count
    }

    pub fn tags(&self) -> StaticStrTagsRef {
        self.tags
    }
}

impl SinceLastReport {
    /// # Arguments
    ///
    /// * `event_counter` - The reporter's event counter at the time of creation.
    fn new(event_counter: usize) -> SinceLastReport {
        SinceLastReport {
            histogram: Histogram::default(),
            initial_event_counter: event_counter,
            sample_count: 0,
        }
    }

    fn push_sample(&mut self, sample: usize, n: usize) {
        self.histogram.push_n(sample, n);
        self.sample_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use mock_instant::MockClock;
    use once_cell::sync::Lazy;

    use super::*;
    use crate::{test_utils::assert_histogram_eq, timing_options::Precision};

    #[test]
    fn push_a_value_sample() {
        let name = "test";
        let reporter = NumericValueReporter::new(name, Default::default());

        reporter.push(|| 100);

        let report = reporter.report();
        assert_eq!(1, report.event_count());

        assert_histogram_eq(&report.histogram, vec![(100, 1)]);
    }

    #[test]
    fn once_report_is_taken_a_new_report_starts() {
        let name = "test";
        let reporter = NumericValueReporter::new(name, Default::default());

        reporter.start_timer().stop();

        let report = reporter.report();
        assert_eq!(1, report.event_count());

        let report = reporter.report();
        assert_eq!(0, report.event_count());
    }

    #[test]
    fn report_contains_name_of_perf() {
        let name = "test";
        let reporter = NumericValueReporter::new(name, Default::default());
        let report = reporter.report();
        assert_eq!("test", report.name());
    }

    #[test]
    fn timer_added_to_report_when_dropped() {
        let name = "test";
        let reporter = NumericValueReporter::new(name, Default::default());

        let timer = reporter.start_timer();

        let report = reporter.report();
        assert_eq!(1, report.event_count(), "Expect to be counted when start");
        assert_eq!(
            0,
            report.sample_count(),
            "Expect to be absent from report before drop"
        );

        drop(timer);

        let report = reporter.report();
        assert_eq!(
            0,
            report.event_count(),
            "Event didn't start in this reporting period"
        );
        assert_eq!(
            1,
            report.sample_count(),
            "Expect to be present in report after drop"
        );
    }

    #[test]
    fn accurate_timers_at_millisecond_precision() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                sample_precision: Precision::Millisecond,
                ..Default::default()
            },
        );

        {
            let _timer = reporter.start_timer();

            for _ in 0..2 {
                let _timer = reporter.start_timer();

                MockClock::advance(Duration::from_secs(2));
            }

            MockClock::advance(Duration::from_secs(1));
        }

        let report = reporter.report();

        assert_eq!("Mocked Time", report.name);
        assert_histogram_eq(&report.histogram, vec![(2000, 2), (5000, 1)]);
        assert_eq!(Precision::Millisecond, report.sample_precision());
    }

    #[test]
    fn accurate_timers_at_centisecond_precision() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                sample_precision: Precision::Centisecond,
                ..Default::default()
            },
        );

        {
            let _timer = reporter.start_timer();
            MockClock::advance(Duration::from_secs(5));
        }

        let report = reporter.report();

        assert_eq!("Mocked Time", report.name);
        assert_histogram_eq(&report.histogram, vec![(500, 1)]);
        assert_eq!(Precision::Centisecond, report.sample_precision());
    }

    #[test]
    fn accurate_timers_at_microsecond_precision() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                sample_precision: Precision::Microsecond,
                ..Default::default()
            },
        );

        {
            let _timer = reporter.start_timer();
            MockClock::advance(Duration::from_micros(3621));
        }

        let report = reporter.report();

        assert_eq!("Mocked Time", report.name);
        assert_histogram_eq(&report.histogram, vec![(3621, 1)]);
        assert_eq!(Precision::Microsecond, report.sample_precision());
    }

    #[test]
    fn accurate_timers_at_nanosecond_precision() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                sample_precision: Precision::Nanosecond,
                ..Default::default()
            },
        );

        {
            let _timer = reporter.start_timer();
            MockClock::advance(Duration::from_nanos(123));
        }

        let report = reporter.report();

        assert_eq!("Mocked Time", report.name);
        assert_histogram_eq(&report.histogram, vec![(123, 1)]);
        assert_eq!(Precision::Nanosecond, report.sample_precision());
    }

    #[test]
    fn early_stop() {
        let name = "Mocked Time";
        let reporter = NumericValueReporter::new(name, Default::default());

        {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();

            MockClock::advance(Duration::from_secs(2));
        }

        let report = reporter.report();

        assert_histogram_eq(&report.histogram, vec![(1000, 1)]);
    }

    #[test]
    fn early_stop_twice_doesnt_count_twice() {
        let name = "Mocked Time";
        let reporter = NumericValueReporter::new(name, Default::default());

        {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();

            MockClock::advance(Duration::from_secs(2));
        }

        let report = reporter.report();

        assert_histogram_eq(&report.histogram, vec![(1000, 1)]);
    }

    #[test]
    fn auto_sampling_with_timers() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                target_sample_rate: 1_000,
                sample_precision: Precision::Millisecond,
            },
        );
        assert_eq!(0, reporter.event_counter.fetch_add(0, Ordering::Acquire));

        for _ in 0..10_000 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        assert_eq!(
            10_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(1, report.sample_interval);
        assert_eq!(10_000, report.sample_count);
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);

        // because 10K were sampled in the report, the actual sample rate should be adjusted to 10

        for _ in 0..10_000 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        assert_eq!(
            20_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(10, report.sample_interval);
        assert_eq!(1_000, report.sample_count);
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);

        // because we got exactly as many as expected, no further change should happen
        for _ in 0..10_000 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        assert_eq!(
            30_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(10, report.sample_interval);
        assert_eq!(1_000, report.sample_count);
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);
    }

    #[test]
    fn auto_sampling_using_push() {
        let invocations = AtomicUsize::new(0);
        let count_invocations_return_1000 = || {
            invocations.fetch_add(1, Ordering::Relaxed);
            1000
        };
        let reporter = NumericValueReporter::new(
            "Mocked",
            TimingOptions {
                target_sample_rate: 1_000,
                sample_precision: Precision::Millisecond,
            },
        );
        assert_eq!(0, reporter.event_counter.fetch_add(0, Ordering::Acquire));

        for _ in 0..10_000 {
            reporter.push(count_invocations_return_1000);
        }

        assert_eq!(
            10_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(1, report.sample_interval);
        assert_eq!(10_000, report.sample_count);
        assert_eq!(report.sample_count, invocations.load(Ordering::Relaxed));
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);
        invocations.store(0, Ordering::Relaxed);

        // because 10K were sampled in the report, the actual sample rate should be adjusted to 10

        for _ in 0..10_000 {
            reporter.push(count_invocations_return_1000);
        }

        assert_eq!(
            20_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(10, report.sample_interval);
        assert_eq!(1_000, report.sample_count);
        assert_eq!(report.sample_count, invocations.load(Ordering::Relaxed));
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);
        invocations.store(0, Ordering::Relaxed);

        // because we got exactly as many as expected, no further change should happen
        for _ in 0..10_000 {
            reporter.push(count_invocations_return_1000);
        }

        assert_eq!(
            30_000,
            reporter.event_counter.fetch_add(0, Ordering::Acquire)
        );

        let report = reporter.report();
        assert_eq!(10, report.sample_interval);
        assert_eq!(1_000, report.sample_count);
        assert_eq!(report.sample_count, invocations.load(Ordering::Relaxed));
        assert_eq!(10_000, report.event_count);
        assert_histogram_eq(&report.histogram, vec![(1000, 10_000)]);
    }

    #[test]
    fn only_the_nth_sample_is_taken() {
        let reporter = NumericValueReporter::new(
            "Mocked Time",
            TimingOptions {
                target_sample_rate: 1_000,
                sample_precision: Precision::Millisecond,
            },
        );
        assert_eq!(0, reporter.event_counter.fetch_add(0, Ordering::Acquire));

        for _ in 0..10_000 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        let report = reporter.report();
        assert_eq!(1, report.sample_interval);

        // because 10K were sampled in the report, the actual sample rate should be adjusted to 10
        for _ in 0..10_000 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        let report = reporter.report();
        assert_eq!(10, report.sample_interval);

        for _ in 0..9 {
            let timer = reporter.start_timer();

            MockClock::advance(Duration::from_secs(1));

            timer.stop();
        }

        let timer = reporter.start_timer();

        MockClock::advance(Duration::from_secs(3));

        timer.stop();

        let report = reporter.report();
        assert_eq!(1, report.sample_count);

        // Because there were 9x1 second, followed by 1x3second, this shows the 10th value exactly is being sampled.
        assert_histogram_eq(&report.histogram, vec![(3000, 10)])
    }

    #[test]
    fn target_sample_rate_calculations() {
        assert_eq!(
            10,
            NumericValueReporter::calculate_sample_rate(10_000, 1_000)
        );
        assert_eq!(
            20,
            NumericValueReporter::calculate_sample_rate(20_000, 1_000)
        );
        assert_eq!(1, NumericValueReporter::calculate_sample_rate(0, 1_000));
        assert_eq!(
            123,
            NumericValueReporter::calculate_sample_rate(12_314, 100)
        );
    }

    #[test]
    fn disable_timer() {
        let timing_reporter = NumericValueReporter::new("c", Default::default());

        timing_reporter.disable();

        timing_reporter.start_timer().stop();
        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count);

        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count);
    }

    #[test]
    fn event_counting() {
        let event_reporter = EventCountReporter::new("event");

        event_reporter.count();

        let reports = event_reporter.report();
        assert_eq!(1, reports.len());

        let report = reports.first().unwrap();
        assert_eq!("event", report.name());
        assert_eq!(1, report.event_count());

        event_reporter.count();
        event_reporter.count_n(3);

        let reports = event_reporter.report();
        assert_eq!(1, reports.len());
        let report = reports.first().unwrap();
        assert_eq!("event", report.name());
        assert_eq!(4, report.event_count());

        static TAGS_SET: Lazy<Vec<Vec<&'static str>>> = Lazy::new(|| {
            vec![
                vec!["size:big", "color:red"],
                vec!["size:medium", "color:blue"],
                vec!["size:small", "color:green"],
            ]
        });

        event_reporter.count_n_tagged(1, TAGS_SET.first());
        let reports = event_reporter.report();
        assert_eq!(2, reports.len(), "expect 1 tagged and 1 no-tag report");
        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 1,
            tags: TAGS_SET.first(),
        }));

        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 0,
            tags: None,
        }));

        event_reporter.count_n_tagged(1, TAGS_SET.first());
        event_reporter.count_n_tagged(1, TAGS_SET.get(1));
        event_reporter.count_n_tagged(1, TAGS_SET.get(2));
        event_reporter.count_n_tagged(1, None);
        event_reporter.count_n_tagged(1, TAGS_SET.first());
        event_reporter.count_n_tagged(2, TAGS_SET.get(1));
        event_reporter.count_n_tagged(3, TAGS_SET.get(2));
        event_reporter.count_n(4);

        let reports = event_reporter.report();
        assert_eq!(4, reports.len(), "expect 3 tagged and 1 no-tag report");
        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 2,
            tags: TAGS_SET.first(),
        }));
        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 3,
            tags: TAGS_SET.get(1),
        }));
        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 4,
            tags: TAGS_SET.get(2),
        }));
        assert!(reports.contains(&EventReport {
            name: "event",
            event_count: 5,
            tags: None,
        }));
    }
}
