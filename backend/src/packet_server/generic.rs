//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    collections::HashMap,
    future::Future,
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use anyhow::Result;
use calling_common::{Duration, Instant};
use log::*;
use parking_lot::Mutex;
use rustls::ServerConfig;

use crate::{
    metrics::TimingOptions,
    packet_server::{self, SocketLocator, TimerHeap, TimerHeapNextResult},
    sfu::{self, HandleOutput, Sfu, SfuStats},
};

/// The shared state for a generic packet server, only UDP is supported.
///
/// This server is implemented with a single socket for all sends and receives. Multiple threads can
/// use the socket, but this only helps if packet processing takes a long time. Otherwise they'll
/// just block in the kernel trying to send.
pub struct PacketServerState {
    socket: UdpSocket,
    num_threads: usize,
    timer_heap: Mutex<TimerHeap<SocketLocator>>,
}

impl PacketServerState {
    /// Sets up the server state by binding a socket to `local_addr`.
    pub fn new(
        local_addr_udp: SocketAddr,
        _local_addr_tcp: SocketAddr,
        _local_addr_tls: Option<SocketAddr>,
        _tls_config: Option<Arc<ServerConfig>>,
        num_threads: usize,
        _tick_interval: Duration,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            socket: UdpSocket::bind(local_addr_udp)?,
            num_threads,
            timer_heap: Mutex::new(TimerHeap::new()),
        }))
    }

    /// Launches the configured number of threads for the server using Tokio's blocking thread pool
    /// ([`tokio::task::spawn_blocking`]).
    ///
    /// `handle_packet` should take a single incoming packet's source address and data and produce a
    /// (possibly empty) set of outgoing packets.
    ///
    /// This should only be called once.
    pub fn start_threads(self: Arc<Self>, sfu: &Arc<Mutex<Sfu>>) -> impl Future {
        let all_handles = (0..self.num_threads).map(|_| {
            let self_for_thread = self.clone();
            let sfu_for_thread = sfu.clone();
            tokio::task::spawn_blocking(move || self_for_thread.run(&sfu_for_thread))
        });
        futures::future::select_all(all_handles)
    }

    fn sample(length: usize) {
        sampling_histogram!("calling.generic.send_packet.size_bytes", || length);
    }

    /// Runs a single listener on the current thread.
    ///
    /// See [`PacketServerState::start_threads`].
    fn run(self: Arc<Self>, sfu: &Arc<Mutex<Sfu>>) {
        let mut buf = [0u8; 1500];

        loop {
            let received_packet = match self.socket.recv_from(&mut buf) {
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock => None,
                    ErrorKind::TimedOut => None,
                    _ => {
                        warn!("recv_from() failed: {}", err);
                        None
                    }
                },
                Ok((size, sender_addr)) => Some((size, sender_addr)),
            };
            if let Some((size, sender_addr)) = received_packet {
                let HandleOutput {
                    packets_to_send,
                    dequeues_to_schedule,
                } = packet_server::handle_packet(
                    sfu,
                    SocketLocator::Udp(sender_addr),
                    &mut buf[..size],
                );

                for (buf, addr) in packets_to_send {
                    time_scope!(
                        "calling.udp.generic.send_packet",
                        TimingOptions::nanosecond_1000_per_minute()
                    );
                    Self::sample(buf.len());
                    self.send_packet(&buf, addr);
                }

                if !dequeues_to_schedule.is_empty() {
                    let mut timer_heap = self.timer_heap.lock();
                    for (time, addr) in dequeues_to_schedule {
                        timer_heap.schedule(time, addr);
                    }
                }
            }
            let mut heap = self.timer_heap.lock();
            loop {
                let now = Instant::now();
                match heap.next(now) {
                    TimerHeapNextResult::Value(addr) => {
                        if let Some((addr, buf, time)) = Sfu::handle_dequeue(sfu, addr, now) {
                            if let Some(buf) = buf {
                                time_scope!(
                                    "calling.udp.generic.send_packet_from_timer_heap",
                                    TimingOptions::nanosecond_1000_per_minute()
                                );
                                Self::sample(buf.len());
                                self.send_packet(&buf, addr);
                            }
                            if let Some(time) = time {
                                heap.schedule(time, addr);
                            }
                        }
                    }
                    TimerHeapNextResult::Wait(timeout) => {
                        let _ = self.socket.set_read_timeout(Some(timeout.into()));
                        break;
                    }
                    TimerHeapNextResult::WaitForever => {
                        let _ = self.socket.set_read_timeout(None);
                        break;
                    }
                }
            }
        }
    }

    pub fn send_packet(&self, buf: &[u8], addr: SocketLocator) {
        match addr {
            SocketLocator::Udp(addr) => {
                trace!("sending packet of {} bytes to {}", buf.len(), addr);
                if let Err(err) = self.socket.send_to(buf, addr) {
                    warn!("send_to failed: {}", err);
                }
            }
            _ => warn!("unable to send packet to {}", addr),
        }
    }

    /// Process the results of [`sfu::Sfu::tick`].
    pub fn tick(&self, tick_update: sfu::TickOutput) -> Result<()> {
        for (buf, addr) in tick_update.packets_to_send {
            self.send_packet(&buf, addr);
        }
        if !tick_update.dequeues_to_schedule.is_empty() {
            let mut timer_heap = self.timer_heap.lock();
            for (time, addr) in tick_update.dequeues_to_schedule {
                timer_heap.schedule(time, addr);
            }
        }

        Ok(())
    }

    pub fn get_stats(&self) -> SfuStats {
        let histograms = HashMap::new();
        let values = HashMap::new();
        SfuStats { histograms, values }
    }
}
