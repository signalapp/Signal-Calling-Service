//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the packet server.

use std::{
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
mod epoll;
#[cfg(all(feature = "epoll", target_os = "linux"))]
pub use epoll::PacketServerState;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
mod generic;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
pub use generic::PacketServerState;

use calling_common::{Duration, Instant, ThreadPool};

use crate::{
    config,
    sfu::{Sfu, SfuError},
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
    let packet_handler_state_for_dequeue = packet_handler_state.clone();
    let packet_handler_state_for_stats = packet_handler_state.clone();

    let sfu_for_tick = sfu.clone();
    let sfu_for_cleanup = sfu.clone();

    info!(
        "packet_server ready: udp {:?}, tcp {:?}; starting {} threads",
        local_addr_udp, local_addr_tcp, num_threads
    );

    sfu.lock()
        .set_packet_server(Some(packet_handler_state_for_stats));

    let thread_pool = ThreadPool::new(num_threads);

    sfu.lock()
        .set_new_connection_handler(Box::new(move |connection| {
            let thread_pool_for_dequeue = thread_pool.clone();
            let connection_for_dequeue = connection.clone();
            let packet_handler_state_for_dequeue = packet_handler_state_for_dequeue.clone();
            connection
                .lock()
                // Note: this creates a reference cycle, but that cycle is broken
                // by the SFU when it removes the connection from its tables
                // by calling .set_dequeue_scheduler(None).
                .set_dequeue_scheduler(Some(Box::new(move |time_to_dequeue| {
                    let connection_for_dequeue = connection_for_dequeue.clone();
                    let packet_handler_state_for_dequeue = packet_handler_state_for_dequeue.clone();
                    thread_pool_for_dequeue.spawn_blocking_at(
                        time_to_dequeue,
                        Box::new(move || {
                            if let Some((buf, addr)) = connection_for_dequeue
                                .lock()
                                .dequeue_outgoing_rtp(Instant::now())
                            {
                                packet_handler_state_for_dequeue.send_packet(&buf, addr);
                            }
                        }),
                    );
                })));
        }));

    // Spawn (blocking) threads for the packet server.
    let packet_packet_handles = packet_handler_state.start_threads(move |sender_addr, data| {
        time_scope_us!("calling.udp_server.handle_packet"); // metric names use udp_server for historic continuity

        trace!(
            "received packet of {} bytes from {}",
            data.len(),
            sender_addr
        );

        sampling_histogram!("calling.udp_server.incoming_packet.size_bytes", || data
            .len());

        Sfu::handle_packet(&sfu, sender_addr, data).unwrap_or_else(|err| {
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
            Vec::new()
        })
    });

    // Spawn a normal (cooperative) task to run some regular maintenance on an interval.
    let tick_handle = tokio::spawn(async move {
        loop {
            time_scope_us!("calling.udp_server.tick");
            // Use sleep() instead of interval() so that we never wait *less* than one interval
            // to do the next tick.
            tokio::time::sleep(tick_interval.into()).await;
            time_scope_us!("calling.udp_server.tick.processing");

            let tick_output = { sfu_for_tick.lock().tick(Instant::now()) };

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
        _ = packet_packet_handles => {},
        _ = tick_handle => {},
        _ = packet_ender_rx => {},
    );

    sfu_for_cleanup.lock().set_packet_server(None);
    info!("packet_server shutdown");
    Ok(())
}
