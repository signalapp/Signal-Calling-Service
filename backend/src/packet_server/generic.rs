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
use core_affinity::CoreId;
use log::*;
use metrics::{metric_config::TimingOptions, *};
use parking_lot::{Mutex, RwLock};
use rustls::ServerConfig;

use crate::{
    connection::Connection,
    packet_server::{self, SocketLocator, TimerHeap, TimerHeapNextResult},
    sfu::{self, HandleOutput, HandleUnconnectedOutput, Sfu, SfuError, SfuStats},
};

/// The shared state for a generic packet server, only UDP is supported.
///
/// This server is implemented with a single socket for all sends and receives. Multiple threads can
/// use the socket, but this only helps if packet processing takes a long time. Otherwise they'll
/// just block in the kernel trying to send.
pub struct PacketServerState {
    socket: UdpSocket,
    num_threads: usize,
    timer_heap: Mutex<TimerHeap<Arc<Connection>>>,
    connection_map: RwLock<HashMap<SocketLocator, Arc<Connection>>>,
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
            timer_heap: Default::default(),
            connection_map: Default::default(),
        }))
    }

    /// Launches the configured number of threads for the server using Tokio's blocking thread pool
    /// ([`tokio::task::spawn_blocking`]).
    ///
    /// `handle_packet` should take a single incoming packet's source address and data and produce a
    /// (possibly empty) set of outgoing packets.
    ///
    /// This should only be called once.
    pub fn start_threads(self: Arc<Self>, sfu: &Arc<Sfu>, _core_ids: Vec<CoreId>) -> impl Future {
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
    fn run(self: Arc<Self>, sfu: &Arc<Sfu>) {
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
                Ok((size, sender_addr)) => Some((size, SocketLocator::Udp(sender_addr))),
            };

            if let Some((size, sender_addr)) = received_packet {
                let (packets_to_send, dequeues_to_schedule) = {
                    let read_lock = self.connection_map.read();
                    if let Some(connection) = read_lock.get(&sender_addr) {
                        match packet_server::handle_packet_connected(
                            sfu,
                            connection,
                            sender_addr,
                            &mut buf[..size],
                        ) {
                            Ok(HandleOutput {
                                packets_to_send,
                                dequeues_to_schedule,
                            }) => (packets_to_send, dequeues_to_schedule),
                            Err(SfuError::Leave) => {
                                let connection = connection.clone();
                                drop(read_lock);
                                self.remove_connection(&connection, Instant::now());
                                (vec![], vec![])
                            }
                            Err(_) => (vec![], vec![]),
                        }
                    } else {
                        drop(read_lock);
                        if let Some(HandleUnconnectedOutput {
                            packets_to_send,
                            connection,
                        }) = packet_server::handle_packet_unconnected(
                            sfu,
                            sender_addr,
                            &mut buf[..size],
                        ) {
                            trace!(
                                "adding {} -> {} to connection_map",
                                sender_addr,
                                connection.id()
                            );
                            self.connection_map.write().insert(sender_addr, connection);
                            (packets_to_send, vec![])
                        } else {
                            (vec![], vec![])
                        }
                    }
                };

                for (buf, addr) in packets_to_send {
                    time_scope!(
                        "calling.udp.generic.send_packet",
                        TimingOptions::nanosecond_1000_per_minute()
                    );
                    Self::sample(buf.len());
                    self.send_packet(&buf, addr);
                }

                for (time, addr) in dequeues_to_schedule {
                    self.timer_heap.lock().schedule(time, addr);
                }
            }
            let mut packets_to_send = vec![];
            let mut dequeues_to_schedule = vec![];
            {
                let mut heap = self.timer_heap.lock();
                loop {
                    let now = Instant::now();
                    match heap.next(now) {
                        TimerHeapNextResult::Value(connection) => {
                            let (_, dequeue_time) =
                                Sfu::handle_dequeue(sfu, &connection, now, &mut packets_to_send);
                            if let Some(dequeue_time) = dequeue_time {
                                dequeues_to_schedule.push((dequeue_time, connection));
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

            for (buf, addr) in packets_to_send {
                time_scope!(
                    "calling.udp.generic.send_packet_from_timer_heap",
                    TimingOptions::nanosecond_1000_per_minute()
                );
                Self::sample(buf.len());
                self.send_packet(&buf, addr);
            }

            for (time, addr) in dequeues_to_schedule {
                self.timer_heap.lock().schedule(time, addr);
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
            for (time, connection) in tick_update.dequeues_to_schedule {
                timer_heap.schedule(time, connection);
            }
        }
        Ok(())
    }

    pub fn remove_connection(&self, connection: &Arc<Connection>, now: Instant) {
        for locator in connection.all_addrs().iter() {
            self.remove_candidate(connection, locator, now);
        }
    }

    pub fn remove_candidate(
        &self,
        connection: &Arc<Connection>,
        locator: &SocketLocator,
        _now: Instant,
    ) {
        let mut write_lock = self.connection_map.write();
        if connection.has_candidate(*locator) {
            warn!("candidate came back during tick processing");
        } else if write_lock.get(locator) == Some(connection) {
            write_lock.remove(locator);
        }
    }

    pub fn get_stats(&self) -> SfuStats {
        let histograms = HashMap::new();
        let values = HashMap::new();
        SfuStats { histograms, values }
    }
}
