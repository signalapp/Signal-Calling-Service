//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use parking_lot::Mutex;

use crate::{
    reporter::{EventCountReporter, EventReport, HistogramReport, NumericValueReporter},
    timing_options::TimingOptions,
};

/// A global structure that contains a map to each of the registered Timing Reporters.
///
/// The mutex lock is only used once to register a new reporter, and then once by the report
/// generation.
pub struct Metrics {
    enabled: AtomicBool,
    registry: Mutex<Registry>,
}

#[derive(Default)]
struct Registry {
    registered_names: HashSet<&'static str>,
    numeric_reporters: Vec<Arc<NumericValueReporter>>,
    event_reporters: Vec<Arc<EventCountReporter>>,
}

#[derive(Debug)]
pub struct Report {
    pub histograms: Vec<HistogramReport>,
    pub events: Vec<EventReport>,
}

impl Metrics {
    pub(crate) fn new_enabled() -> Metrics {
        Metrics {
            enabled: AtomicBool::new(true),
            registry: Default::default(),
        }
    }

    #[cfg(test)]
    pub fn clear(&self) {
        let mut registry = self.registry.lock();
        *registry = Default::default();
    }

    /// Locks the internal structure and adds a new timer.
    pub fn create_and_register_timer(
        &self,
        name: &'static str,
        options: TimingOptions,
    ) -> Arc<NumericValueReporter> {
        let numeric_reporter = Arc::new(NumericValueReporter::new(name, options));

        if !self.enabled() {
            numeric_reporter.disable();
        }

        let mut registry = self.registry.lock();

        if !registry.registered_names.insert(name) {
            panic!("The metric name \"{}\" has been used elsewhere.", name);
        }

        registry
            .numeric_reporters
            .push(Arc::clone(&numeric_reporter));
        numeric_reporter
    }

    /// Locks the internal structure and adds a new event.
    pub fn create_and_register_event(&self, name: &'static str) -> Arc<EventCountReporter> {
        let event_reporter = Arc::new(EventCountReporter::new(name));

        let mut registry = self.registry.lock();

        if !registry.registered_names.insert(name) {
            panic!("The metric name \"{}\" has been used elsewhere.", name);
        }

        registry.event_reporters.push(Arc::clone(&event_reporter));
        event_reporter
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Returns reports and resets timer reporters sorted by name.
    ///
    /// The lock is open this whole time, but the only other use of the lock is registering new timers.
    pub fn report(&self) -> Report {
        let registry = self.registry.lock();

        let mut histograms = registry
            .numeric_reporters
            .iter()
            .map(|reporter| reporter.report())
            .collect::<Vec<_>>();
        histograms.sort_unstable_by_key(|report| report.name());

        let mut events = registry
            .event_reporters
            .iter()
            .flat_map(|reporter| reporter.report())
            .collect::<Vec<_>>();
        events.sort_unstable_by_key(|report| report.name());

        Report { histograms, events }
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.registry
            .lock()
            .numeric_reporters
            .iter()
            .for_each(|reporter| reporter.disable());
    }
}

#[macro_export]
macro_rules! reporter {
    ($name:expr, $options:expr) => {{
        static __REPORTER: once_cell::sync::Lazy<
            std::sync::Arc<$crate::metric_config::NumericValueReporter>,
        > = once_cell::sync::Lazy::new(|| {
            $crate::__METRICS.create_and_register_timer($name, $options)
        });

        &__REPORTER
    }};
}

#[macro_export]
macro_rules! event_reporter {
    ($name:expr) => {{
        static __REPORTER: once_cell::sync::Lazy<
            std::sync::Arc<$crate::metric_config::EventCountReporter>,
        > = once_cell::sync::Lazy::new(|| $crate::__METRICS.create_and_register_event($name));

        &__REPORTER
    }};
}

/// Start a timer, and manually choose when to stop the timer.
#[macro_export]
macro_rules! start_timer {
    ($name:expr) => {
        $crate::reporter!($name, Default::default()).start_timer()
    };
    ($name:expr, $options:expr) => {
        $crate::reporter!($name, $options).start_timer()
    };
}

/// Start a timer that automatically stops when it falls out of scope.
#[macro_export]
macro_rules! time_scope {
    ($name:expr) => {
        let _t = $crate::reporter!($name, Default::default()).start_timer();
    };
    ($name:expr, $options:expr) => {
        let _t = $crate::reporter!($name, $options).start_timer();
    };
}

/// Time the scope in microseconds, 1000 samples per reporting minute
#[macro_export]
macro_rules! time_scope_us {
    ($name:expr) => {
        $crate::time_scope!(
            $name,
            $crate::metric_config::TimingOptions::microsecond_1000_per_minute()
        );
    };
}

/// Start timer in microseconds, 1000 samples per reporting minute
#[macro_export]
macro_rules! start_timer_us {
    ($name:expr) => {{
        $crate::start_timer!(
            $name,
            $crate::metric_config::TimingOptions::microsecond_1000_per_minute()
        )
    }};
}

#[macro_export]
macro_rules! event {
    ($name:expr) => {
        $crate::event_reporter!($name).count()
    };
    ($name:expr, $count:expr) => {
        $crate::event_reporter!($name).count_n($count)
    };
    ($name:expr, $count:expr, $tags:expr) => {
        $crate::event_reporter!($name).count_n_tagged($count, $tags)
    };
}

#[macro_export]
macro_rules! metrics {
    () => {{
        &$crate::__METRICS
    }};
}

/// Sample the value produced by the supplied function and produce a histogram.
#[macro_export]
macro_rules! sampling_histogram {
    ($name:expr, $sampler:expr) => {
        $crate::reporter!($name, Default::default()).push($sampler)
    };
    ($name:expr, $options:expr, $sampler:expr) => {
        $crate::reporter!($name, $options).push($sampler)
    };
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        ops::AddAssign,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, LazyLock,
        },
        time::{Duration, Instant},
    };

    use mock_instant::MockClock;
    use rand::Rng;

    use crate::{
        metric_config::StaticStrTagsRef, reporter::Timer, test_utils::assert_histogram_eq, *,
    };

    #[test]
    #[should_panic(expected = "The metric name \"A\" has been used elsewhere.")]
    fn cant_register_same_timer_twice() {
        let metrics = Metrics::new_enabled();

        metrics.create_and_register_timer("A", Default::default());
        metrics.create_and_register_timer("A", Default::default());
    }

    #[test]
    #[should_panic(expected = "The metric name \"A\" has been used elsewhere.")]
    fn cant_register_same_event_twice() {
        let metrics = Metrics::new_enabled();

        metrics.create_and_register_event("A");
        metrics.create_and_register_event("A");
    }

    #[test]
    #[should_panic(expected = "The metric name \"A\" has been used elsewhere.")]
    fn cant_register_same_name_for_an_event_and_timer() {
        let metrics = Metrics::new_enabled();

        metrics.create_and_register_timer("A", Default::default());
        metrics.create_and_register_event("A");
    }

    #[test]
    fn registrations_are_enabled() {
        let metrics = Metrics::new_enabled();

        let timing_reporter = metrics.create_and_register_timer("A", Default::default());

        timing_reporter.start_timer().stop();
        timing_reporter.start_timer().stop();

        assert_eq!(2, timing_reporter.report().sample_count());

        timing_reporter.start_timer().stop();

        assert_eq!(1, timing_reporter.report().sample_count());
    }

    #[test]
    fn registrations_after_disabled_are_not_enabled() {
        let metrics = Metrics::new_enabled();

        metrics.disable();

        let timing_reporter = metrics.create_and_register_timer("A", Default::default());

        timing_reporter.start_timer().stop();
        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count());

        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count());
    }

    #[test]
    fn registrations_before_disabled_are_later_disabled() {
        let metrics = Metrics::new_enabled();

        let timing_reporter = metrics.create_and_register_timer("A", Default::default());

        metrics.disable();

        timing_reporter.start_timer().stop();
        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count());

        timing_reporter.start_timer().stop();

        assert_eq!(0, timing_reporter.report().sample_count());
    }

    #[test]
    fn accurate_timers_using_macros() {
        // Other tests that trigger reports will cause this test to fail unless we clear it first.
        metrics!().clear();

        {
            time_scope!("outer");
            {
                time_scope_us!("inner");

                MockClock::advance(Duration::from_secs(2));
            }

            let timer = start_timer_us!("manual");
            MockClock::advance(Duration::from_millis(600));
            timer.stop();
            MockClock::advance(Duration::from_millis(400));
        }

        for _ in 0..2 {
            sampling_histogram!("event1", || 100);
        }

        sampling_histogram!("event2", || 50);

        event!("event3");
        event!("event4", 10);
        static TAGS: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec!["tag_name:tag_value"]);
        event!("event5", 10, Some(&TAGS));

        let reports = metrics!().report();
        let histograms = reports.histograms;

        let mut iter = histograms.iter();
        let report1 = iter.next().unwrap();
        let report2 = iter.next().unwrap();
        let report3 = iter.next().unwrap();
        let report4 = iter.next().unwrap();
        let report5 = iter.next().unwrap();

        assert_eq!("event1", report1.name());
        assert_eq!("event2", report2.name());
        assert_eq!("inner", report3.name());
        assert_eq!("manual", report4.name());
        assert_eq!("outer", report5.name());

        assert_histogram_eq(&report1.histogram, vec![(100, 2)]);
        assert_histogram_eq(&report2.histogram, vec![(50, 1)]);
        assert_histogram_eq(&report3.histogram, vec![(2_000_000, 1)]);
        assert_histogram_eq(&report4.histogram, vec![(600_000, 1)]);
        assert_histogram_eq(&report5.histogram, vec![(3_000, 1)]);

        let events = reports.events;
        let mut iter = events.iter();
        let event3 = iter.next().unwrap();
        let event4 = iter.next().unwrap();

        assert_eq!("event3", event3.name());
        assert_eq!("event4", event4.name());
        assert_eq!(1, event3.event_count());
        assert_eq!(10, event4.event_count());
    }

    #[test]
    fn correctly_clear_counters() {
        static TAG_SET: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(|| {
            vec![
                vec!["tag_name:0"],
                vec!["tag_name:1"],
                vec!["tag_name:2"],
                vec!["tag_name:3"],
                vec!["tag_name:4"],
            ]
        });

        fn random_tags() -> StaticStrTagsRef {
            TAG_SET.get(rand::thread_rng().gen_range(0..(TAG_SET.len() + 1)))
        }

        let expected_count = 10_000_000usize;
        let parallelism = std::thread::available_parallelism().unwrap().into();
        let finished = Arc::new(AtomicUsize::new(0));
        let handles = (0..parallelism)
            .map(|i| {
                let finished = finished.clone();
                std::thread::spawn(move || {
                    for _ in (i..expected_count).step_by(parallelism) {
                        event!("event", 1, random_tags());
                    }
                    finished.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect::<Vec<_>>();

        let start = Instant::now();
        let interval_millis = 1000;
        // save reports so it's easier to debug!
        let mut reports = vec![];
        while finished.load(Ordering::Relaxed) < parallelism {
            std::thread::sleep(Duration::from_millis(interval_millis));
            reports.push(__METRICS.report());
        }

        // get any leftover values
        for handle in handles {
            handle.join().unwrap();
        }
        reports.push(__METRICS.report());
        println!(
            "Finished emitting metrics in {} seconds",
            start.elapsed().as_secs()
        );
        println!("Total reports: {}\n{:?}", reports.len(), reports);
        let sum_by_tag = reports.iter().fold(HashMap::new(), |mut acc, report| {
            for event_report in &report.events {
                acc.entry(event_report.tags())
                    .or_insert(0)
                    .add_assign(event_report.event_count());
            }
            acc
        });

        println!("Sum by tag:");
        sum_by_tag.iter().for_each(|(tags, count)| {
            println!("\t{:?}={count}", tags);
        });
        let total_events = sum_by_tag.iter().fold(0, |acc, (_, count)| acc + count);
        println!("Total Events={:?}", total_events);

        assert_eq!(expected_count, total_events);
        let last_report = __METRICS.report();
        for event_report in &last_report.events {
            assert_eq!(0, event_report.event_count());
        }
    }
}
