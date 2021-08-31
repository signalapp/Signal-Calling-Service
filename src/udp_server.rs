//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the udp server.

use std::{
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
use epoll::*;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
mod generic;
#[cfg(not(all(feature = "epoll", target_os = "linux")))]
use generic::*;

use crate::{
    common::{Duration, Instant},
    config,
    sfu::{Sfu, SfuError},
};

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    udp_ender_rx: Receiver<()>,
    is_healthy: Arc<AtomicBool>,
) -> Result<()> {
    let num_udp_threads = config.udp_threads.unwrap_or_else(|| {
        // Default to N - 1 CPUs, keeping one clear for the HTTP server.
        // But clamp to 15 so we don't run out of memory or another contended resource.
        num_cpus::get().clamp(2, 16) - 1
    });

    let tick_interval = Duration::from_millis(config.tick_interval_ms);

    let local_addr = SocketAddr::new(config.binding_ip.parse()?, config.ice_candidate_port);

    let udp_handler_state = UdpServerState::new(local_addr, num_udp_threads, tick_interval)?;
    let udp_handler_state_for_tick = udp_handler_state.clone();

    let sfu_for_tick = sfu.clone();

    info!(
        "udp_server ready: {:?}; starting {} threads",
        local_addr, num_udp_threads
    );

    // Spawn (blocking) threads for the UDP server.
    let udp_packet_handles = udp_handler_state.start_threads(move |sender_addr, data| {
        time_scope_us!("calling.udp_server.handle_packet");

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
        let mut tick_state = Default::default();
        loop {
            time_scope_us!("calling.udp_server.tick");
            // Use sleep() instead of interval() so that we never wait *less* than one interval
            // to do the next tick.
            tokio::time::sleep(tick_interval.into()).await;
            time_scope_us!("calling.udp_server.tick.processing");

            let tick_output = { sfu_for_tick.lock().tick(Instant::now()) };

            // Process outside the scope of the lock on the sfu.
            match udp_handler_state_for_tick.tick(tick_output, &mut tick_state) {
                Ok(()) => {}
                Err(err) => {
                    error!("{}", err);
                    is_healthy.store(false, Ordering::Relaxed);
                }
            }
        }
    });

    // Wait for any task to complete and cancel the rest.
    let _ = tokio::select!(
        _ = udp_packet_handles => {},
        _ = tick_handle => {},
        _ = udp_ender_rx => {},
    );

    info!("udp_server shutdown");
    Ok(())
}
