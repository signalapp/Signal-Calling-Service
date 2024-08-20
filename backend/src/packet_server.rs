//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the packet server.

use std::{
    collections::binary_heap::BinaryHeap,
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Result;
use log::*;
use parking_lot::Mutex;
use tokio::sync::oneshot::Receiver;

#[cfg(all(feature = "epoll", target_os = "linux"))]
use nix::sys::{time::TimeSpec, timer::Expiration::OneShot, timerfd::*};
#[cfg(all(feature = "epoll", target_os = "linux"))]
mod epoll;
#[cfg(all(feature = "epoll", target_os = "linux"))]
pub use epoll::PacketServerState;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
mod generic;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
pub use generic::PacketServerState;

use calling_common::{Duration, Instant};

use crate::{
    config,
    sfu::{HandleOutput, Sfu, SfuError},
};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SocketLocator {
    Udp(SocketAddr),
    Tcp { id: i64, is_ipv6: bool },
}

impl fmt::Display for SocketLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketLocator::Udp(a) => write!(f, "U{}", a),
            SocketLocator::Tcp { id, is_ipv6 } => write!(f, "T{}-{}", id, is_ipv6),
        }
    }
}

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    packet_ender_rx: Receiver<()>,
    is_healthy: Arc<AtomicBool>,
) -> Result<()> {
    let num_threads = num_cpus::get();

    let tick_interval = Duration::from_millis(config.tick_interval_ms);

    let local_addr_udp = SocketAddr::new(config.binding_ip, config.ice_candidate_port);
    let local_addr_tcp = SocketAddr::new(config.binding_ip, config.ice_candidate_port_tcp);

    let packet_handler_state =
        PacketServerState::new(local_addr_udp, local_addr_tcp, num_threads, tick_interval)?;
    let packet_handler_state_for_tick = packet_handler_state.clone();
    let packet_handler_state_for_stats = packet_handler_state.clone();

    let sfu_for_tick = sfu.clone();
    let sfu_for_cleanup = sfu.clone();

    info!(
        "packet_server ready: udp {:?}, tcp {:?}; starting {} threads",
        local_addr_udp, local_addr_tcp, num_threads
    );

    sfu.lock()
        .set_packet_server(Some(packet_handler_state_for_stats));

    // Spawn (blocking) threads for the packet server.
    let packet_handles = packet_handler_state.start_threads(&sfu);

    // Spawn a normal (cooperative) task to run some regular maintenance on an interval.
    let tick_handle = tokio::spawn(async move {
        loop {
            time_scope_us!("calling.udp_server.tick");
            // Use sleep() instead of interval() so that we never wait *less* than one interval
            // to do the next tick.
            tokio::time::sleep(tick_interval.into()).await;
            time_scope_us!("calling.udp_server.tick.processing");

            let tick_output = {
                sfu_for_tick
                    .lock()
                    .tick(Instant::now(), calling_common::SystemTime::now())
            };

            // Process outside the scope of the lock on the sfu.
            match packet_handler_state_for_tick.tick(tick_output) {
                Ok(()) => {}
                Err(err) => {
                    error!("{}", err);
                    is_healthy.store(false, Ordering::Relaxed);
                }
            }
        }
    });

    // Wait for any task to complete and cancel the rest.
    tokio::select!(
        _ = packet_handles => {},
        _ = tick_handle => {},
        _ = packet_ender_rx => {},
    );

    sfu_for_cleanup.lock().set_packet_server(None);
    info!("packet_server shutdown");
    Ok(())
}

fn handle_packet(
    sfu: &Arc<Mutex<Sfu>>,
    sender_address: SocketLocator,
    incoming_packet: &mut [u8],
) -> HandleOutput {
    time_scope_us!("calling.udp_server.handle_packet"); // metric names use udp_server for historic continuity

    trace!(
        "received packet of {} bytes from {}",
        incoming_packet.len(),
        sender_address
    );

    sampling_histogram!("calling.udp_server.incoming_packet.size_bytes", || {
        incoming_packet.len()
    });

    Sfu::handle_packet(sfu, sender_address, incoming_packet).unwrap_or_else(|err| {
        // Check for certain errors that can arise in normal conditions
        // (say, because UDP packets arrive out of order).
        // Note that we still use ".sfu" prefixes for these error events.
        match &err {
            SfuError::UnknownPacketType(_) => {
                event!("calling.sfu.error.expected.unhandled");
                trace!("handle_packet() failed: {}", err);
            }
            SfuError::IceBindingRequestUnknownUsername(_) => {
                event!("calling.sfu.error.expected.ice_binding_request_unknown_username");
                trace!("handle_packet() failed: {}", err);
            }
            _ => {
                event!("calling.sfu.error.unexpected");
                debug!("handle_packet() failed: {}", err);
            }
        }
        Default::default()
    })
}

struct ScheduledValue<T> {
    time: Instant,
    value: T,
}

impl<T> PartialOrd for ScheduledValue<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for ScheduledValue<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.time.cmp(&self.time)
    }
}

impl<T> PartialEq for ScheduledValue<T> {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl<T> Eq for ScheduledValue<T> {}

struct TimerHeap<T> {
    tasks: BinaryHeap<ScheduledValue<T>>,
    /// Which Instant, if any, is scheduled on a timerfd.
    active_timer: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
enum TimerHeapNextResult<T> {
    Value(T),
    Wait(Duration),
    WaitForever,
}

impl<T> TimerHeap<T> {
    fn new() -> Self {
        let tasks = BinaryHeap::new();
        let active_timer = None;
        Self {
            tasks,
            active_timer,
        }
    }

    pub fn schedule(&mut self, time: Instant, value: T) {
        self.tasks.push(ScheduledValue { time, value });
    }

    pub fn next(&mut self, now: Instant) -> TimerHeapNextResult<T> {
        match self.tasks.peek() {
            None => TimerHeapNextResult::WaitForever,
            Some(ScheduledValue { time, .. }) => {
                if time <= &now {
                    let task = self.tasks.pop().expect("task was just there");
                    if Some(task.time) == self.active_timer {
                        self.active_timer = None;
                    }
                    TimerHeapNextResult::Value(task.value)
                } else {
                    TimerHeapNextResult::Wait(time.saturating_duration_since(now))
                }
            }
        }
    }

    #[cfg(all(feature = "epoll", target_os = "linux"))]
    pub fn set_timer(&mut self, timer: &TimerFd, now: Instant) {
        match (self.tasks.peek(), self.active_timer) {
            (None, _) => {}
            (Some(task), None) => {
                self.set_timer_impl(timer, now, task.time);
            }
            (Some(task), Some(active_timer)) => {
                if task.time < active_timer {
                    self.set_timer_impl(timer, now, task.time);
                }
            }
        }
    }

    #[cfg(all(feature = "epoll", target_os = "linux"))]
    fn set_timer_impl(&mut self, timer: &TimerFd, now: Instant, active_timer: Instant) {
        match active_timer.checked_duration_since(now) {
            Some(duration) => {
                let _ = timer.set(
                    OneShot(TimeSpec::from_duration(duration.into())),
                    TimerSetTimeFlags::empty(),
                );
            }
            None => {
                // Setting the timer to 1 ns in the future so it activates
                // as soon as possible. Setting to zero would clear the
                // timer instead.
                let _ = timer.set(OneShot(TimeSpec::new(0, 1)), TimerSetTimeFlags::empty());
            }
        }
        self.active_timer = Some(active_timer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calling_common::{Duration, Instant};

    #[test]
    fn test_basics() {
        // test basic ordering
        let epoch = Instant::now();
        let mut heap = TimerHeap::new();

        for i in 0..2000 {
            heap.schedule(epoch + Duration::from_millis(i), i);
        }

        for i in 0..2000 {
            assert_eq!(
                heap.next(epoch + Duration::from_millis(i)),
                TimerHeapNextResult::Value(i)
            );
            if i < 1999 {
                assert_eq!(
                    heap.next(epoch + Duration::from_millis(i)),
                    TimerHeapNextResult::Wait(Duration::from_millis(1))
                );
            } else {
                assert_eq!(
                    heap.next(epoch + Duration::from_millis(i)),
                    TimerHeapNextResult::WaitForever
                );
            }
        }
    }

    #[test]
    fn test_heap_ref_movement() {
        let epoch = Instant::now();
        let mut heap = TimerHeap::new();

        heap.schedule(epoch + Duration::from_millis(500), 500);
        assert_eq!(
            heap.next(epoch + Duration::from_millis(500)),
            TimerHeapNextResult::Value(500)
        );

        heap.schedule(epoch + Duration::from_millis(1200), 1200);
        heap.schedule(epoch + Duration::from_millis(1000), 1000);

        assert_eq!(
            heap.next(epoch + Duration::from_millis(1500)),
            TimerHeapNextResult::Value(1000)
        );

        assert_eq!(
            heap.next(epoch + Duration::from_millis(1500)),
            TimerHeapNextResult::Value(1200)
        );
    }

    #[test]
    fn test_heap_big_jump() {
        let epoch = Instant::now();
        let mut heap = TimerHeap::new();

        heap.schedule(epoch + Duration::from_millis(50_000), 50_000);
        heap.schedule(epoch + Duration::from_millis(25_000), 25_000);

        assert_eq!(
            heap.next(epoch + Duration::from_millis(1_000)),
            TimerHeapNextResult::Wait(Duration::from_secs(24))
        );

        assert_eq!(
            heap.next(epoch + Duration::from_millis(25_000)),
            TimerHeapNextResult::Value(25_000)
        );
        assert_eq!(
            heap.next(epoch + Duration::from_millis(50_000)),
            TimerHeapNextResult::Value(50_000)
        );

        // advance far forward, and verify events are scheduled properly
        assert_eq!(
            heap.next(epoch + Duration::from_millis(150_000)),
            TimerHeapNextResult::WaitForever
        );

        heap.schedule(epoch + Duration::from_millis(150_120), 150_120);
        heap.schedule(epoch + Duration::from_millis(150_100), 150_100);

        assert_eq!(
            heap.next(epoch + Duration::from_millis(150_500)),
            TimerHeapNextResult::Value(150_100)
        );

        assert_eq!(
            heap.next(epoch + Duration::from_millis(150_500)),
            TimerHeapNextResult::Value(150_120)
        );
    }
}
