//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    cmp::Ordering,
    collections::{hash_map, HashMap, VecDeque},
    ffi::c_int,
    future::Future,
    io::{self, IoSlice, Read, Write},
    net::{
        IpAddr::{V4, V6},
        SocketAddr, TcpListener, TcpStream, UdpSocket,
    },
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::io::{AsRawFd, RawFd},
    },
    sync::{
        atomic::{AtomicU64, Ordering as AtomicOrdering},
        Arc,
    },
    thread,
};

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use calling_common::{try_scoped, Duration, Instant};
use core_affinity::CoreId;
use log::*;
use metrics::{metric_config::TimingOptions, *};
use nix::{
    errno::Errno,
    libc,
    sys::{epoll::*, timerfd::*},
};
use parking_lot::{Mutex, RwLock};
use rustls::{ServerConfig, ServerConnection};
use unique_id::{sequence::SequenceGenerator, Generator};

use crate::{
    connection::Connection,
    packet_server::{self, SocketLocator, TimerHeap, TimerHeapNextResult},
    sfu::{self, HandleOutput, HandleUnconnectedOutput, Sfu, SfuError, SfuStats},
};

/// Controls number of sockets a particular thread will handle without going back to epoll.
///
/// A higher number saves calls into the kernel, but claims more events for a single thread to
/// process.
const MAX_EPOLL_EVENTS: usize = 16;

/// How long to keep the TCP connection in a connected state without any data.
const TCP_INACTIVE_CONNECTION_TTL_TICKS: u64 = 100;

/// How many pending connections to allow on the TCP listen connection.
const TCP_BACKLOG: usize = 128;

/// Maximum RTP packet size (WebRTC has kVideoMtu = 1200).
const MAX_RTP_LENGTH: usize = 1500;

/// Tcp socket sendbuffer size, enough for 10 Mbps with a 1 second round trip time.
const TCP_SEND_BUFFER_BYTES: usize = 10_000_000 / 8;

/// epoll_wait timeout in ms.
///
/// Timers set from tick() don't have a wakeup mechanism; a lower value
/// limits the maximum delay for those timers. A larger value reduces CPU load.
const EPOLL_WAIT_TIMEOUT_MS: isize = 25;

/// Time between logging errors when receiving packets to the unpinned socket.
///
/// This indicates a singificant setup error, but if it happens at all, it
/// will likely happen often, so don't overwelm the logs.
const UNPINNED_LOG_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// The shared state for an epoll-based packet server.
///
/// This server is implemented with a "new client" socket that receives new connections, plus a map
/// of dedicated sockets for each connected client. Processing these sockets is handled by [epoll],
/// with each thread of the packet server getting its own epoll descriptor to block on. This allows
/// events to be level-triggered (as in, threads will be repeatedly woken up if a socket with data
/// is not immediately read from) while still only waking one thread for a particular event.
///
/// The implementation uses two-phase cleanup for clients that have left the call (either gracefully
/// or through timeout). This avoids opening a new connection immediately after the old one was
/// closed.
///
/// [epoll]: https://man7.org/linux/man-pages/man7/epoll.7.html
pub struct PacketServerState {
    local_addr_udp: SocketAddr,
    local_addr_tcp: SocketAddr,
    local_addr_tls: Option<SocketAddr>,
    tls_config: Option<Arc<ServerConfig>>,
    all_connections: RwLock<ConnectionMap<ConnectedSocket>>,
    tick_number: AtomicU64, // u64 will never rollover
    tcp_id_generator: Arc<SequenceGenerator>,
    timer_heaps: Vec<Mutex<TimerHeap<Arc<Connection>>>>,
    num_threads: usize,
}

impl PacketServerState {
    /// Sets up the server state by binding an initial socket to `local_addr`.
    ///
    /// Also creates a separate epoll file descriptor for each thread we plan to use.
    pub fn new(
        local_addr_udp: SocketAddr,
        local_addr_tcp: SocketAddr,
        local_addr_tls: Option<SocketAddr>,
        tls_config: Option<Arc<ServerConfig>>,
        num_threads: usize,
    ) -> Result<Arc<Self>> {
        let tcp_id_generator = Arc::new(SequenceGenerator);

        let mut timer_heaps = Vec::with_capacity(num_threads);
        timer_heaps.resize_with(num_threads, Default::default);

        let result = Self {
            local_addr_udp,
            local_addr_tcp,
            local_addr_tls,
            tls_config,
            all_connections: RwLock::new(ConnectionMap::new()),
            tick_number: 0.into(),
            tcp_id_generator,
            timer_heaps,
            num_threads,
        };
        Ok(Arc::new(result))
    }

    /// Opens a socket and binds it to `local_addr` after setting the `SO_REUSEPORT` sockopt.
    ///
    /// This allows multiple sockets to bind to the same address.
    fn open_socket_with_reusable_port(
        local_addr: &SocketAddr,
        core: Option<&CoreId>,
    ) -> Result<(ConnectedSocket, RawFd)> {
        let socket = Self::open_socket_impl(local_addr, core)?;
        let raw_fd = socket.as_raw_fd();
        Ok((ConnectedSocket::unconnected(Socket::Udp(socket)), raw_fd))
    }

    fn connect_udp_socket(
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        connection: Arc<Connection>,
    ) -> Result<(ConnectedSocket, RawFd)> {
        let socket = Self::open_socket_impl(local_addr, None)?;
        socket.connect(remote_addr)?;
        let raw_fd = socket.as_raw_fd();
        Ok((
            ConnectedSocket {
                socket: Socket::Udp(socket),
                connection: Some(connection),
            },
            raw_fd,
        ))
    }

    fn open_socket_impl(local_addr: &SocketAddr, core: Option<&CoreId>) -> Result<UdpSocket> {
        use nix::sys::socket::*;

        // Open a UDP socket in blocking mode.
        let socket_fd = socket(
            if local_addr.is_ipv4() {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            },
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        // Allow later sockets to handle connections.
        setsockopt(&socket_fd, sockopt::ReusePort, &true)?;
        if let Some(core) = core {
            Self::set_sockopt_incoming_cpu(&socket_fd, core)?;
        }

        // Bind the socket to the given local address.
        bind(socket_fd.as_raw_fd(), &SockaddrStorage::from(*local_addr))?;
        let result = UdpSocket::from(socket_fd);
        // set socket to non-blocking, in case more than one thread polls the socket while it's ready
        result
            .set_nonblocking(true)
            .expect("Cannot set non-blocking");
        Ok(result)
    }

    fn open_listen_socket(
        local_addr: &SocketAddr,
        core: Option<&CoreId>,
    ) -> Result<(TcpListener, RawFd)> {
        use nix::sys::socket::*;

        // Open a TCP socket in blocking mode.
        let socket_fd = socket(
            if local_addr.is_ipv4() {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            },
            SockType::Stream,
            SockFlag::empty(),
            SockProtocol::Tcp,
        )?;

        setsockopt(&socket_fd, sockopt::SndBuf, &TCP_SEND_BUFFER_BYTES)?;

        // Allow later sockets to handle connections.
        setsockopt(&socket_fd, sockopt::ReusePort, &true)?;
        if let Some(core) = core {
            Self::set_sockopt_incoming_cpu(&socket_fd, core)?;
        }
        // Bind the socket to the given local address.
        bind(socket_fd.as_raw_fd(), &SockaddrStorage::from(*local_addr))?;

        listen(&socket_fd, TCP_BACKLOG)?;

        let result = TcpListener::from(socket_fd);
        // set listen socket to non-blocking, in case more than one thread polls the socket while it's ready
        result
            .set_nonblocking(true)
            .expect("Cannot set non-blocking");
        let raw_fd = result.as_raw_fd();
        Ok((result, raw_fd))
    }

    /// nix::sys::socket doesn't have a sockopt for SO_INCOMING_CPU, so do it ourselves...
    fn set_sockopt_incoming_cpu(socket: &OwnedFd, core: &CoreId) -> Result<()> {
        let core: c_int = core.id.try_into()?;
        unsafe {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_INCOMING_CPU,
                &core as *const _ as *const libc::c_void,
                size_of_val(&core).try_into()?,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Launches the configured number of threads for the server using Tokio's blocking thread pool
    /// ([`tokio::task::spawn_blocking`]).
    ///
    /// This should only be called once.
    pub fn start_threads(self: Arc<Self>, sfu: &Arc<Sfu>, core_ids: Vec<CoreId>) -> impl Future {
        assert!(
            self.num_threads == core_ids.len(),
            "Number of threads must be equal to number of cores to pin to"
        );
        let all_handles = core_ids.iter().enumerate().map(|(thread_num, core_id)| {
            let self_for_thread = self.clone();
            let sfu_for_thread = sfu.clone();
            let core_id = *core_id;
            tokio::task::spawn_blocking(move || {
                let builder =
                    thread::Builder::new().name(format!("epoll{:3}/{:3}", thread_num, core_id.id));
                builder
                    .spawn(move || self_for_thread.run(&sfu_for_thread, thread_num, core_id))
                    .unwrap()
                    .join()
            })
        });
        futures::future::select_all(all_handles)
    }

    /// Runs on the current thread, polling `epoll_fd`.
    ///
    /// See [`PacketServerState::start_threads`].
    fn run(&self, sfu: &Arc<Sfu>, thread_num: usize, core: CoreId) -> Result<()> {
        let timer_heap = &self.timer_heaps[thread_num];

        if !core_affinity::set_for_current(core) {
            error!("Could not cpu pin to core {}", core.id);
        }
        let (new_client_socket, new_client_socket_fd) =
            Self::open_socket_with_reusable_port(&self.local_addr_udp, None)?;

        let (new_pinned_client_socket, new_pinned_client_socket_fd) =
            Self::open_socket_with_reusable_port(&self.local_addr_udp, Some(&core))?;

        let (new_tcp_socket, new_tcp_socket_fd) =
            Self::open_listen_socket(&self.local_addr_tcp, None)?;
        let (new_pinned_tcp_socket, new_pinned_tcp_socket_fd) =
            Self::open_listen_socket(&self.local_addr_tcp, Some(&core))?;

        let (new_tls_socket, new_tls_socket_fd, new_pinned_tls_socket, new_pinned_tls_socket_fd) =
            if let Some(local_addr_tls) = self.local_addr_tls {
                let (tls_socket, tls_fd) = Self::open_listen_socket(&local_addr_tls, None)?;
                let (pinned_socket, pinned_fd) =
                    Self::open_listen_socket(&local_addr_tls, Some(&core))?;
                (Some(tls_socket), tls_fd, Some(pinned_socket), pinned_fd)
            } else {
                (None, -1, None, -1)
            };

        let epoll = Epoll::new(EpollCreateFlags::empty())?;
        epoll.add(
            &new_client_socket,
            EpollEvent::new(EpollFlags::EPOLLIN, new_client_socket_fd as u64),
        )?;
        epoll.add(
            &new_pinned_client_socket,
            EpollEvent::new(EpollFlags::EPOLLIN, new_pinned_client_socket_fd as u64),
        )?;
        epoll.add(
            &new_tcp_socket,
            EpollEvent::new(EpollFlags::EPOLLIN, new_tcp_socket_fd as u64),
        )?;
        epoll.add(
            &new_pinned_tcp_socket,
            EpollEvent::new(EpollFlags::EPOLLIN, new_pinned_tcp_socket_fd as u64),
        )?;

        if let Some(listen_socket) = &new_tls_socket {
            epoll.add(
                listen_socket,
                EpollEvent::new(EpollFlags::EPOLLIN, new_tls_socket_fd as u64),
            )?;
        }
        if let Some(listen_socket) = &new_pinned_tls_socket {
            epoll.add(
                listen_socket,
                EpollEvent::new(EpollFlags::EPOLLIN, new_pinned_tls_socket_fd as u64),
            )?;
        }

        let mut bufs = vec![PacketBuffer::new()];
        let mut poll_timeout_ms = EPOLL_WAIT_TIMEOUT_MS;

        let (timer, timer_fd) = match TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::empty()) {
            Ok(timer) => {
                let timer_fd = timer.as_fd().as_raw_fd();
                match epoll.add(
                    &timer,
                    EpollEvent::new(EpollFlags::EPOLLIN, timer_fd as u64),
                ) {
                    Ok(()) => (Some(timer), timer_fd),
                    Err(e) => {
                        error!("timerfd couldn't be added to epoll, {}, coercing timer waits to milliseconds", e);
                        (None, -1)
                    }
                }
            }
            Err(e) => {
                error!(
                    "timerfd creation failed, {}, coercing timer waits to milliseconds",
                    e
                );
                (None, -1)
            }
        };

        let mut unpinned_recv = None;

        loop {
            let mut current_events = [EpollEvent::empty(); MAX_EPOLL_EVENTS];
            let num_events = epoll
                .wait(&mut current_events, poll_timeout_ms)
                .unwrap_or_else(|err| {
                    warn!("epoll_wait() failed: {}", err);
                    0
                });
            for event in &current_events[..num_events] {
                let socket_fd = event.data() as i32;
                if socket_fd == new_client_socket_fd {
                    warn_unpinned(&mut unpinned_recv, "UDP");
                    self.read_unconnected(&mut bufs[0], sfu, &epoll, &new_client_socket);
                } else if socket_fd == new_pinned_client_socket_fd {
                    self.read_unconnected(&mut bufs[0], sfu, &epoll, &new_pinned_client_socket);
                } else if socket_fd == new_tcp_socket_fd {
                    warn_unpinned(&mut unpinned_recv, "TCP");
                    self.accept_tcp(&new_tcp_socket, &epoll, false);
                } else if socket_fd == new_pinned_tcp_socket_fd {
                    self.accept_tcp(&new_pinned_tcp_socket, &epoll, false);
                } else if socket_fd == new_tls_socket_fd {
                    warn_unpinned(&mut unpinned_recv, "TLS");
                    let socket = new_tls_socket.as_ref().expect("socket must exist");
                    self.accept_tcp(socket, &epoll, true);
                } else if socket_fd == new_pinned_tls_socket_fd {
                    let socket = new_pinned_tls_socket.as_ref().expect("socket must exist");
                    self.accept_tcp(socket, &epoll, true);
                } else if socket_fd == timer_fd {
                    let _ = timer.as_ref().expect("timer must exist").wait();
                } else {
                    // Not a special fd, must be a client fd
                    let is_error = event.events().contains(EpollFlags::EPOLLERR);
                    let input_ready = event.events().contains(EpollFlags::EPOLLIN);

                    self.read_connected(
                        &mut bufs,
                        timer_heap,
                        sfu,
                        socket_fd,
                        is_error,
                        input_ready,
                    );
                }
            }

            poll_timeout_ms = self.process_timer(timer_heap, &timer, sfu);
        }
    }

    fn read_unconnected(
        &self,
        buf: &mut PacketBuffer,
        sfu: &Arc<Sfu>,
        epoll: &Epoll,
        socket: &ConnectedSocket,
    ) {
        let sender_addr = match buf.recv_from(socket) {
            Err(err) => {
                Self::socket_error(&err);
                return;
            }
            Ok(sender_addr) => sender_addr,
        };

        let HandleUnconnectedOutput {
            packets_to_send,
            connection,
        } = match packet_server::handle_packet_unconnected(sfu, sender_addr, buf.as_mut()) {
            Some(output) => output,
            None => return,
        };

        {
            let mut write_lock = self.all_connections.write();
            match write_lock.get_by_addr(&sender_addr) {
                ConnectionState::New(_) => {
                    write_lock.mark_as_active(&sender_addr, |s| s.connection = Some(connection));
                }
                ConnectionState::Connected(socket) => {
                    if let Some(socket_connection) = &socket.connection {
                        if socket_connection.id() != connection.id() {
                            error!(
                                "connection changed! addr {} id {} -> id {}",
                                sender_addr,
                                socket_connection.id(),
                                connection.id()
                            );
                        }
                    } else {
                        error!(
                            "sender_addr marked connected without Connection {}",
                            sender_addr
                        );
                    }
                }
                ConnectionState::NotYetConnected => {
                    trace!("connecting to {:?}", sender_addr);
                    match sender_addr {
                        SocketLocator::Udp(udp_addr) => {
                            match try_scoped(|| {
                                // TODO: socket.local address?
                                let (client_socket, client_socket_fd) = Self::connect_udp_socket(
                                    &self.local_addr_udp,
                                    &udp_addr,
                                    connection,
                                )?;
                                epoll.add(
                                    &client_socket,
                                    EpollEvent::new(EpollFlags::EPOLLIN, client_socket_fd as u64),
                                )?;
                                write_lock.get_or_insert_connected(
                                    client_socket,
                                    sender_addr,
                                    None,
                                );
                                Ok(())
                            }) {
                                Ok(()) => {}
                                Err(e) => {
                                    error!("failed to connect to peer: {}", e);
                                }
                            }
                        }
                        SocketLocator::Tcp { .. } => {
                            error!("should not handle tcp connections in read_unconnected");
                        }
                    }
                }
            }
        }

        for (buf, addr) in packets_to_send {
            self.send_packet(&buf, addr)
        }
    }

    fn read_connected(
        &self,
        bufs: &mut Vec<PacketBuffer>,
        timer_heap: &Mutex<TimerHeap<Arc<Connection>>>,
        sfu: &Arc<Sfu>,
        socket_fd: i32,
        is_error: bool,
        input_ready: bool,
    ) {
        let connections_lock = self.all_connections.read();

        let socket = match connections_lock.get_by_fd(socket_fd) {
            Some(socket) => socket,
            // By the time we got to this event the socket was closed.
            None => {
                return;
            }
        };

        if is_error {
            match socket.take_error() {
                Err(err) => {
                    warn!("take_error() failed: {}", err);
                    event!("calling.udp.epoll.take_error_failure");
                    // Hopefully this is a transient failure. Just skip this socket for now.
                    return;
                }
                Ok(None) => {
                    // Assume another thread got here first.
                    return;
                }
                Ok(Some(err)) => {
                    match err.kind() {
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::BrokenPipe => {
                            // This can happen when someone leaves a call
                            // because e.g. their router stops forwarding packets.
                            // This is normal with UDP; technically this error happened
                            // with the *previous* packet and we're just finding out now.
                            trace!("socket error: {}", err);

                            match socket.peer_addr() {
                                Err(err) => {
                                    warn!("peer_addr() failed while handling an error: {}", err);
                                }
                                Ok(addr) => {
                                    let connection = socket.connection.clone();
                                    // Drop the read lock...
                                    drop(connections_lock);
                                    // ...and connect with a write lock...
                                    let mut write_lock = self.all_connections.write();
                                    // ...and mark the connection as closed.
                                    // If we changed state (such as already going to Closed)
                                    // in between the locks, mark_closed is still safe to call:
                                    // - If the connection is still open, we want to close it.
                                    // - If the connection is closed, closing it again doesn't hurt.
                                    // - If the connection has been removed entirely, closing it does nothing.
                                    // - If the connection has been removed and the address gets reused,
                                    // we'll close a connection that doesn't belong here anymore.
                                    // That's very unlikely because it means we've had at least two ticks,
                                    // and it'll (hopefully) heal itself in another two.
                                    if write_lock.mark_closed(&addr).is_some() {
                                        event!("calling.epoll.socket_error.had_error_mark_closed");
                                    }
                                    if let Some(connection) = connection {
                                        connection.remove_candidate(addr);
                                    }
                                    // No need to read more from this socket.
                                    return;
                                }
                            }
                        }
                        _ => {
                            Self::socket_error(&err);
                        }
                    }
                }
            }
        }

        // We ignore all other events but EPOLLIN; hangups will be handled by tick()
        // expiring the connection.
        if !input_ready {
            return;
        }

        // We only read one packet for each socket that's ready. This isn't as efficient
        // as it could be; if one socket has many packets ready, we have to go back into
        // the epoll loop to find that out. On the other hand, this does ensure that we
        // don't get stuck reading from one socket and ignore all others.
        //
        // Note that this relies on using epoll in level-triggered mode rather than
        // edge-triggered.
        //
        // We loop here, to allow reading multiple RTP packets from TLS connections;
        // it's possible that the TLS layer will have read all data from the socket and
        // there are multiple RTP packets within that data. If we only read one RTP
        // packet, the next packet will remain buffered in the TLS layer, but epoll will
        // not find the socket ready for read, until a future packet arrives.

        let mut index = 0;
        let mut sender_addr = None;
        let mut connection = None;
        loop {
            match bufs[index].recv_from(socket) {
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted => {}
                        io::ErrorKind::ConnectionRefused => {
                            // This can happen when someone leaves a call
                            // because e.g. their router stops forwarding packets.
                            // This is normal with UDP; technically this error happened
                            // with the previous *sent* packet and we're just finding out now.
                            trace!("recv_from() failed: {}", err);
                        }
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData => {
                            // got invalid data, so drop the connection
                            if let Ok(peer_addr) = socket.peer_addr() {
                                let connection = socket.connection.clone();
                                // Drop the read lock...
                                drop(connections_lock);
                                // ...and connect with a write lock...
                                let mut write_lock = self.all_connections.write();
                                if write_lock.mark_closed(&peer_addr).is_some() {
                                    event!("calling.epoll.socket_error.read_error_mark_closed");
                                }
                                if let Some(connection) = connection {
                                    connection.remove_candidate(peer_addr);
                                }
                                break;
                            }
                        }
                        _ => {
                            Self::socket_error(&err);
                        }
                    };
                    drop(connections_lock);
                    break;
                }
                Ok(s_a) => {
                    sender_addr = Some(s_a);
                    connection = socket.connection.clone();
                }
            };
            index += 1;
            if socket.has_pending_data() {
                if bufs.len() <= index {
                    bufs.push(PacketBuffer::new());
                }
            } else {
                drop(connections_lock);
                break;
            }
        }

        let sender_addr = match sender_addr {
            Some(sender_addr) => sender_addr,
            None => return,
        };

        for inbuf in bufs.iter_mut().take(index) {
            let (packets_to_send, dequeues_to_schedule) = if let Some(connection) = &connection {
                match packet_server::handle_packet_connected(
                    sfu,
                    connection,
                    sender_addr,
                    inbuf.as_mut(),
                ) {
                    Ok(HandleOutput {
                        packets_to_send,
                        dequeues_to_schedule,
                    }) => (packets_to_send, dequeues_to_schedule),
                    Err(SfuError::Leave) => {
                        self.remove_connection(connection);
                        // end processing after a Leave
                        return;
                    }
                    Err(_) => (vec![], vec![]),
                }
            } else if let Some(HandleUnconnectedOutput {
                packets_to_send,
                connection: new_connection,
            }) =
                packet_server::handle_packet_unconnected(sfu, sender_addr, inbuf.as_mut())
            {
                connection = Some(new_connection.clone());
                self.all_connections
                    .write()
                    .mark_as_active(&sender_addr, |s| s.connection = Some(new_connection));
                (packets_to_send, vec![])
            } else {
                self.all_connections.write().mark_closed(&sender_addr);
                return;
            };

            for (buf, addr) in packets_to_send {
                self.send_packet(&buf, addr)
            }

            if !dequeues_to_schedule.is_empty() {
                let mut timer_heap = timer_heap.lock();
                for (time, connection) in dequeues_to_schedule {
                    timer_heap.schedule(time, connection);
                }
            }
        }
    }

    fn accept_tcp(&self, socket: &TcpListener, epoll: &Epoll, use_tls: bool) {
        let accepted = socket.accept();
        let tls_config = if use_tls {
            Some(
                self.tls_config
                    .as_ref()
                    .expect("tls config must exist if we got a tls accept")
                    .clone(),
            )
        } else {
            None
        };

        match accepted {
            Ok((client_socket, addr)) => {
                let _ = client_socket.set_nodelay(true); // fail quietly
                client_socket
                    .set_nonblocking(true)
                    .expect("Cannot set non-blocking");

                let is_ipv6 = match addr.ip() {
                    V4(_) => false,
                    V6(addr) => addr.to_ipv4_mapped().is_none(),
                };
                let id = self.tcp_id_generator.next_id();
                let is_tls = tls_config.is_some();
                if let Ok(client_socket) =
                    ConnectedSocket::new_tcp(client_socket, id, is_ipv6, tls_config)
                {
                    let mut write_lock = self.all_connections.write();
                    if epoll
                        .add(
                            &client_socket,
                            EpollEvent::new(EpollFlags::EPOLLIN, client_socket.as_raw_fd() as u64),
                        )
                        .is_ok()
                    {
                        write_lock.get_or_insert_connected(
                            client_socket,
                            SocketLocator::Tcp {
                                id,
                                is_ipv6,
                                is_tls,
                            },
                            Some(self.tick_number.load(AtomicOrdering::Relaxed)),
                        );
                    }
                }
            }
            Err(err) => match err.kind() {
                io::ErrorKind::WouldBlock => {}
                err => {
                    event!("calling.udp.epoll.accept_error");
                    warn!("accept error: {}", err);
                }
            },
        }
    }

    fn process_timer(
        &self,
        timer_heap: &Mutex<TimerHeap<Arc<Connection>>>,
        timer: &Option<TimerFd>,
        sfu: &Arc<Sfu>,
    ) -> isize {
        let mut dequeues_left = MAX_EPOLL_EVENTS;
        let mut packets_to_send = vec![];
        let mut dequeues_to_schedule = vec![];
        while dequeues_left > 0 {
            let now = Instant::now();
            let mut timer_heap = timer_heap.lock();
            match timer_heap.next(now) {
                TimerHeapNextResult::Value(connection) => {
                    let (did_dequeue, dequeue_time) =
                        Sfu::handle_dequeue(sfu, &connection, now, &mut packets_to_send);

                    if did_dequeue {
                        dequeues_left -= 1;
                    }
                    if let Some(dequeue_time) = dequeue_time {
                        dequeues_to_schedule.push((dequeue_time, connection));
                    }
                }
                TimerHeapNextResult::Wait(_timeout) => {
                    if !dequeues_to_schedule.is_empty() {
                        for (time, connection) in dequeues_to_schedule.drain(..) {
                            timer_heap.schedule(time, connection);
                        }
                    } else {
                        if let Some(timer) = &timer {
                            timer_heap.set_timer(timer, now);
                        }
                        break;
                    }
                }
                TimerHeapNextResult::WaitForever => {
                    break;
                }
            }
        }

        for (buf, addr) in packets_to_send {
            self.send_packet(&buf, addr)
        }

        if !dequeues_to_schedule.is_empty() {
            let mut timer_heap = timer_heap.lock();
            for (time, connection) in dequeues_to_schedule {
                timer_heap.schedule(time, connection);
            }
        }

        if dequeues_left == 0 {
            0 // busy loop
        } else {
            EPOLL_WAIT_TIMEOUT_MS
        }
    }

    /// Counts socket errors; unexpected errors are logged.
    #[track_caller]
    fn socket_error(err: &io::Error) {
        match err.kind() {
            io::ErrorKind::PermissionDenied => {
                event!("calling.udp.epoll.socket_error.permission_denied");
            }
            io::ErrorKind::ConnectionReset => {
                event!("calling.udp.epoll.socket_error.reset_by_peer");
            }
            _ => {
                let errno = err.raw_os_error();
                // io::ErrorKind doesn't have all the kinds we want to match (or they're unstable)
                // so also look at the raw OS error.
                if errno == Some(Errno::EHOSTUNREACH as i32) {
                    // io::ErrorKind::HostUnreachable pending io_error_more #86442
                    event!("calling.udp.epoll.socket_error.host_unreachable");
                } else if errno == Some(Errno::EMSGSIZE as i32) {
                    event!("calling.udp.epoll.socket_error.packet_too_big");
                } else {
                    event!("calling.udp.epoll.socket_error");
                    // Work around missing https://github.com/rust-lang/log/pull/410. Once that's
                    // supported, the `#[track_caller]` on this function will be sufficient for
                    // plain `warn!` to work.
                    let location = std::panic::Location::caller();
                    log::logger().log(
                        &log::Record::builder()
                            .args(format_args!("socket_error: {err}"))
                            .level(log::Level::Warn)
                            .target(std::module_path!())
                            .file(Some(location.file()))
                            .line(Some(location.line()))
                            .build(),
                    );
                }
            }
        }
    }

    /// Sends socket and returns true if socket is still good, or false if
    /// it should be closed.
    fn send_and_keep(socket: &ConnectedSocket, buf: &[u8]) -> bool {
        if let Err(err) = socket.send(buf) {
            match err.kind() {
                io::ErrorKind::ConnectionRefused | io::ErrorKind::BrokenPipe => {
                    // This can happen when someone leaves a call
                    // because e.g. their router stops forwarding packets.
                    // This is normal with UDP; technically this error happened
                    // with the *previous* packet and we're just finding out now.
                    trace!("send() failed: {}, closing", err);
                    return false;
                }
                io::ErrorKind::WouldBlock => {}
                _ => {
                    Self::socket_error(&err);
                }
            }
        }
        true
    }

    pub fn send_packet(&self, buf: &[u8], addr: SocketLocator) {
        trace!("sending packet of {} bytes to {}", buf.len(), addr);
        time_scope!(
            "calling.udp.epoll.send_packet",
            TimingOptions::nanosecond_1000_per_minute()
        );
        sampling_histogram!("calling.epoll.send_packet.size_bytes", || buf.len());

        let connections_lock = self.all_connections.read();
        match connections_lock.get_by_addr(&addr) {
            ConnectionState::Connected(socket) => {
                if !Self::send_and_keep(socket, buf) {
                    let connection = socket.connection.clone();
                    // Drop the read lock...
                    drop(connections_lock);
                    // ...and connect with a write lock...
                    let mut write_lock = self.all_connections.write();
                    // ...and mark the connection as closed.
                    // If we changed state (such as already going to Closed)
                    // in between the locks, mark_closed is still safe to call:
                    // - If the connection is still open, we want to close it.
                    // - If the connection is closed, closing it again doesn't hurt.
                    // - If the connection has been removed entirely, closing it does nothing.
                    // - If the connection has been removed and the address gets reused,
                    // we'll close a connection that doesn't belong here anymore.
                    // That's very unlikely because it means we've had at least two ticks,
                    // and it'll (hopefully) heal itself in another two.
                    if write_lock.mark_closed(&addr).is_some() {
                        event!("calling.epoll.socket_error.write_error_mark_closed");
                    }
                    if let Some(connection) = connection {
                        connection.remove_candidate(addr);
                    }
                }
            }
            ConnectionState::New(_) => {
                error!("connection state new in send_packet, addr {:?}", addr);
            }
            ConnectionState::NotYetConnected => {
                event!("calling.epoll.socket_error.write_to_unknown_addr");
            }
        }
    }

    /// Process the results of [`sfu::SfuServer::tick`].
    ///
    /// This includes cleaning up connections for clients that have left or the quiet ones that
    /// reached ttl without having passed any data.
    pub fn tick(&self, tick_update: sfu::TickOutput) -> Result<()> {
        let tick_number = self.tick_number.fetch_add(1, AtomicOrdering::Relaxed);
        time_scope_us!("calling.packet_server.tick");

        {
            time_scope_us!("calling.packet_server.tick.sending");
            for (buf, addr) in tick_update.packets_to_send {
                trace!("sending tick packet of {} bytes to {}", buf.len(), addr);

                let connections_lock = self.all_connections.read();
                match connections_lock.get_by_addr(&addr) {
                    ConnectionState::New(_) => {
                        warn!("shouldn't find new TCP socket in tick");
                    }
                    ConnectionState::Connected(socket) => {
                        if !Self::send_and_keep(socket, &buf) {
                            let connection = socket.connection.clone();
                            drop(connections_lock);
                            // ...and connect with a write lock...
                            let mut write_lock = self.all_connections.write();
                            if write_lock.mark_closed(&addr).is_some() {
                                event!("calling.epoll.socket_error.tick_write_error_mark_closed");
                            }
                            if let Some(connection) = connection {
                                connection.remove_candidate(addr);
                            }
                        }
                    }
                    ConnectionState::NotYetConnected => {
                        trace!("dropping packet (not yet connected)")
                    }
                }
            }
        }

        {
            time_scope_us!("calling.packet_server.tick.dequeue_scheduling");
            // Round robin through the timer heaps
            let mut counter = self.timer_heaps.len() - 1;
            for (time, connection) in tick_update.dequeues_to_schedule {
                self.timer_heaps[counter].lock().schedule(time, connection);
                if counter > 0 {
                    counter -= 1;
                } else {
                    counter = self.timer_heaps.len() - 1;
                }
            }
        }

        {
            time_scope_us!("calling.packet_server.tick.inactive_tcp");
            let read_lock = self.all_connections.read();
            let inactive_tcp_connections = read_lock.inactive_tcp(tick_number);
            drop(read_lock);

            for locator in inactive_tcp_connections {
                self.all_connections.write().mark_closed(&locator);
            }
        }

        Ok(())
    }

    pub fn remove_connection(&self, connection: &Arc<Connection>) {
        for locator in connection.all_addrs().iter() {
            self.remove_candidate(connection, locator);
        }
    }

    pub fn remove_candidate(&self, connection: &Arc<Connection>, locator: &SocketLocator) {
        let mut write_lock = self.all_connections.write();
        if connection.has_candidate(*locator) {
            warn!("candidate came back during tick processing");
        } else {
            write_lock.mark_closed_if(locator, |s| s.connection.as_ref() == Some(connection));
        }
    }

    pub fn get_stats(&self) -> SfuStats {
        let histograms = HashMap::new();
        let mut values = HashMap::new();
        {
            let connections_lock = self.all_connections.read();
            values.insert(
                "calling.packet_server.connection_map.by_fd.count",
                HashMap::from([(None, connections_lock.by_fd.len() as f32)]),
            );
            values.insert(
                "calling.packet_server.connection_map.by_peer_addr.count",
                HashMap::from([(None, connections_lock.by_peer_addr.len() as f32)]),
            );
            values.insert(
                "calling.packet_server.connection_map.inactive_ttls.count",
                HashMap::from([(None, connections_lock.inactive_ttls.len() as f32)]),
            );
        }
        SfuStats { histograms, values }
    }
}

fn warn_unpinned(unpinned_recv: &mut Option<Instant>, message: &str) {
    if unpinned_recv.is_none_or(|instant| {
        Instant::now().saturating_duration_since(instant) > UNPINNED_LOG_INTERVAL
    }) {
        error!(
            "packet delivered to unpinned {} socket; check cpu pinning",
            message
        );
        *unpinned_recv = Some(Instant::now());
    }
}

struct PacketBuffer {
    buf: [u8; MAX_RTP_LENGTH],
    size: usize,
}

impl PacketBuffer {
    fn new() -> Self {
        Self {
            buf: [0; MAX_RTP_LENGTH],
            size: 0,
        }
    }

    fn recv_from(&mut self, socket: &ConnectedSocket) -> io::Result<SocketLocator> {
        self.size = 0;
        socket.recv_from(&mut self.buf).map(|(size, sender_addr)| {
            self.size = size;
            sender_addr
        })
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[0..self.size]
    }
}

struct TcpState {
    stream: SocketStream,
    size: usize,
    pos: usize,
    buf: [u8; MAX_RTP_LENGTH],
    outq: VecDeque<u8>,
    id: i64,
    is_ipv6: bool,
    is_tls: bool,
}

impl TcpState {
    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketLocator)> {
        if self.size > MAX_RTP_LENGTH {
            // this has already been logged
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if self.size == 0 {
            match self.stream.read(&mut self.buf[self.pos..2]) {
                Ok(read) => {
                    if read == 0 {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    self.pos += read;
                    match self.pos.cmp(&2) {
                        Ordering::Less => (),
                        Ordering::Equal => {
                            self.size = BigEndian::read_u16(&self.buf[0..2]) as usize;
                            self.pos = 0;
                        }
                        Ordering::Greater => {
                            error!(
                                "read more than asked for, self.pos {}, read {}",
                                self.pos, read
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                }
                Err(err) => return Err(err),
            }
        }
        if self.size > MAX_RTP_LENGTH {
            debug!(
                "tcp encoded RTP length too large: {} (0x{:04x})",
                self.size, self.size
            );
            event!("calling.udp.epoll.tcp_too_large");
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.size != 0 {
            match self.stream.read(&mut self.buf[self.pos..self.size]) {
                Ok(read) => {
                    if read == 0 {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    self.pos += read;
                    if self.pos == self.size {
                        let size = self.size;
                        buf[0..self.pos].copy_from_slice(&self.buf[0..self.pos]);
                        self.size = 0;
                        self.pos = 0;
                        return Ok((
                            size,
                            SocketLocator::Tcp {
                                id: self.id,
                                is_ipv6: self.is_ipv6,
                                is_tls: self.is_tls,
                            },
                        ));
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            error!("sending tcp encoded zero length RTP");
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if buf.len() > MAX_RTP_LENGTH {
            error!("sending too large tcp encoded packet: {}", buf.len());
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let size = (buf.len() as u16).to_be_bytes();
        let mut dropped = false;
        if self.outq.is_empty() {
            let sent = match self
                .stream
                .write_vectored(&[IoSlice::new(&size), IoSlice::new(buf)])
            {
                Ok(sent) => sent,
                Err(err) => match err.kind() {
                    io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted => 0,
                    _ => return Err(err),
                },
            };
            if sent == 0 {
                dropped = true;
            } else if sent == 1 {
                self.outq.push_back(size[1]);
                self.outq.extend(buf.iter());
            } else {
                let sent = sent - 2;
                if sent < buf.len() {
                    self.outq.extend(buf[sent..].iter());
                } else {
                    return Ok(());
                }
            }
        } else {
            let (a, b) = self.outq.as_slices();
            let mut sent = match self.stream.write_vectored(&[
                IoSlice::new(a),
                IoSlice::new(b),
                IoSlice::new(&size),
                IoSlice::new(buf),
            ]) {
                Ok(sent) => sent,
                Err(err) => match err.kind() {
                    io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted => 0,
                    _ => return Err(err),
                },
            };

            // drop outgoing message when the socket is blocked
            if sent == 0 {
                dropped = true;
            } else if sent < self.outq.len() {
                self.outq.drain(0..sent);
                dropped = true;
            } else {
                sent -= self.outq.len();
                self.outq.clear();
                if sent == 0 {
                    dropped = true;
                } else if sent == 1 {
                    self.outq.push_back(size[1]);
                    self.outq.extend(buf.iter());
                } else {
                    let sent = sent - 2;
                    if sent < buf.len() {
                        self.outq.extend(buf[sent..].iter());
                    } else {
                        return Ok(());
                    }
                }
            }
        }
        if dropped {
            event!("calling.udp.epoll.tcp_dropped_outgoing_packet");
        }

        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }
}

enum SocketStream {
    Tcp(TcpStream),
    Tls(Box<(ServerConnection, TcpStream)>),
}

impl AsFd for SocketStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            SocketStream::Tcp(s) => s.as_fd(),
            SocketStream::Tls(b) => {
                let (_c, s) = b.as_ref();
                s.as_fd()
            }
        }
    }
}

impl SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            SocketStream::Tcp(s) => s.read(buf),
            SocketStream::Tls(b) => {
                let (c, s) = b.as_mut();
                let was_handshaking = c.is_handshaking();
                if c.wants_read() {
                    c.read_tls(s)?;
                }
                if let Err(e) = c.process_new_packets() {
                    // try to write any alerts generated
                    if c.wants_write() {
                        _ = c.write_tls(s);
                    }
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
                if was_handshaking && c.wants_write() {
                    // ignore any write errors during handshaking
                    _ = c.write_tls(s);
                }
                c.reader().read(buf)
            }
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice]) -> io::Result<usize> {
        match self {
            SocketStream::Tcp(s) => s.write_vectored(bufs),
            SocketStream::Tls(b) => {
                let (c, s) = b.as_mut();
                let result = c.writer().write_vectored(bufs);
                // ignore result from socket write
                _ = c.write_tls(s);
                result
            }
        }
    }

    fn as_raw_fd(&self) -> RawFd {
        match self {
            SocketStream::Tcp(s) => s.as_raw_fd(),
            SocketStream::Tls(b) => b.1.as_raw_fd(),
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            SocketStream::Tcp(s) => s.take_error(),
            SocketStream::Tls(b) => b.1.take_error(),
        }
    }

    fn has_pending_data(&self) -> bool {
        match self {
            SocketStream::Tcp(_) => false,
            // If the ServerConnection wants_read, it doesn't have any data for us to read
            SocketStream::Tls(b) => !b.0.wants_read(),
        }
    }
}

enum Socket {
    Udp(UdpSocket),
    Tcp(Box<Mutex<TcpState>>),
}

struct ConnectedSocket {
    connection: Option<Arc<Connection>>,
    socket: Socket,
}

impl AsRawFd for ConnectedSocket {
    fn as_raw_fd(&self) -> RawFd {
        match &self.socket {
            Socket::Udp(s) => s.as_raw_fd(),
            Socket::Tcp(m) => m.lock().stream.as_raw_fd(),
        }
    }
}

impl AsFd for ConnectedSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.socket {
            Socket::Udp(s) => s.as_fd(),
            Socket::Tcp(m) => {
                let lock = m.lock();
                let fd = lock.stream.as_fd();
                // SAFETY: we're using this value immediately with nix::sys::epoll::Epoll::add.
                // epoll gracefully handles closed FDs
                unsafe {
                    let laundered_fd = BorrowedFd::borrow_raw(fd.as_raw_fd());
                    laundered_fd
                }
            }
        }
    }
}

impl ConnectedSocket {
    fn new_tcp(
        s: TcpStream,
        id: i64,
        is_ipv6: bool,
        tls_config: Option<Arc<ServerConfig>>,
    ) -> Result<Self> {
        let (stream, is_tls) = if let Some(tls_config) = tls_config {
            let connection = rustls::ServerConnection::new(tls_config)?;
            (SocketStream::Tls(Box::new((connection, s))), true)
        } else {
            (SocketStream::Tcp(s), false)
        };
        Ok(Self {
            connection: None,
            socket: Socket::Tcp(Box::new(Mutex::new(TcpState {
                stream,
                size: 0,
                pos: 0,
                buf: [0u8; MAX_RTP_LENGTH],
                outq: VecDeque::new(),
                id,
                is_ipv6,
                is_tls,
            }))),
        })
    }

    fn unconnected(s: Socket) -> Self {
        Self {
            connection: None,
            socket: s,
        }
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        match &self.socket {
            Socket::Udp(s) => {
                let ret = s.send(buf).map(|_| ());
                if let Err(ref err) = ret {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        event!("calling.udp.epoll.udp_send.would_block");
                    }
                }
                ret
            }
            Socket::Tcp(m) => m.lock().send(buf),
        }
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketLocator)> {
        match &self.socket {
            Socket::Udp(s) => s
                .recv_from(buf)
                .map(|(size, addr)| (size, SocketLocator::Udp(addr))),
            Socket::Tcp(m) => m.lock().recv_from(buf),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketLocator> {
        match &self.socket {
            Socket::Udp(s) => s.peer_addr().map(SocketLocator::Udp),
            Socket::Tcp(m) => {
                let state = m.lock();
                Ok(SocketLocator::Tcp {
                    id: state.id,
                    is_ipv6: state.is_ipv6,
                    is_tls: state.is_tls,
                })
            }
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match &self.socket {
            Socket::Udp(s) => s.take_error(),
            Socket::Tcp(m) => m.lock().stream.take_error(),
        }
    }

    fn has_pending_data(&self) -> bool {
        match &self.socket {
            Socket::Udp(_) => false,
            Socket::Tcp(m) => m.lock().stream.has_pending_data(),
        }
    }
}

/// A doubly-keyed map that allows looking up a socket by raw file descriptor (for epoll) or by peer
/// address.
///
/// The map owns the socket, so removal from the map will close the socket as well.
///
/// The map is generic to support unit testing, but isn't intended for storing anything else.
struct ConnectionMap<T> {
    /// The primary map from file descriptors to sockets.
    ///
    /// The use of file descriptors is largely arbitrary; it's a value *already* uniquely associated
    /// with a socket.
    by_fd: HashMap<RawFd, T>,

    /// The secondary map from peer addresses to file descriptors, or the timestamp when the
    /// connection to that socket was closed.
    by_peer_addr: HashMap<SocketLocator, ConnectionState<RawFd>>,

    /// Mapping of connections in Connected state to the number of the tick after which they expire.
    inactive_ttls: HashMap<SocketLocator, u64>,
}

/// Represents the state of a connection in a [ConnectionMap].
#[derive(Debug)]
enum ConnectionState<T> {
    /// The peer address was not found, so there must be no existing connection.
    NotYetConnected,
    /// The socket is a TCP socket that hasn't yet been acknowledged by the SFU.
    New(T),
    /// The given socket is connected to the peer in question.
    Connected(T),
}

impl<T: AsRawFd> ConnectionMap<T> {
    fn new() -> Self {
        Self {
            by_fd: HashMap::new(),
            by_peer_addr: HashMap::new(),
            inactive_ttls: HashMap::new(),
        }
    }

    /// Gets the socket for `peer_addr` or inserts `socket` if there isn't one.
    ///
    /// If there is already a socket for `peer_addr`, the argument `socket` will be dropped (and the
    /// underlying socket closed).
    /// New non-UDP sockets are tracked as inactive, because the SFU only
    /// manages their lifetime once they send a valid ICE binding.
    fn get_or_insert_connected(
        &mut self,
        socket: T,
        peer_addr: SocketLocator,
        current_tick: Option<u64>,
    ) -> &T {
        let fd = socket.as_raw_fd();
        let is_udp = matches!(peer_addr, SocketLocator::Udp(_));

        match self.by_peer_addr.entry(peer_addr) {
            hash_map::Entry::Occupied(entry) => {
                match entry.get() {
                    ConnectionState::NotYetConnected => {
                        unreachable!("should not be in the table at all")
                    }
                    ConnectionState::Connected(existing_fd) | ConnectionState::New(existing_fd) => {
                        // This address is already connected to a different socket.
                        return &self.by_fd[existing_fd];
                    }
                }
            }
            hash_map::Entry::Vacant(entry) => {
                if is_udp {
                    entry.insert(ConnectionState::Connected(fd));
                } else {
                    entry.insert(ConnectionState::New(fd));
                }
            }
        }
        let inserted_socket = match self.by_fd.entry(fd) {
            hash_map::Entry::Occupied(_) => {
                unreachable!("file descriptor reused before socket closed");
            }
            hash_map::Entry::Vacant(entry) => entry.insert(socket),
        };
        if !is_udp {
            if let hash_map::Entry::Vacant(entry) = self.inactive_ttls.entry(peer_addr) {
                if let Some(current_tick) = current_tick {
                    entry.insert(TCP_INACTIVE_CONNECTION_TTL_TICKS + current_tick);
                } else {
                    error!("current_tick was not provided to get_or_insert_connected when adding new tcp socket")
                }
            }
        }
        inserted_socket
    }

    /// Gets the connection for `peer_addr`, which can be in any of the states represented by
    /// [ConnectionState].
    fn get_by_addr(&self, peer_addr: &SocketLocator) -> ConnectionState<&T> {
        match self
            .by_peer_addr
            .get(peer_addr)
            .unwrap_or(&ConnectionState::NotYetConnected)
        {
            ConnectionState::NotYetConnected => ConnectionState::NotYetConnected,
            ConnectionState::Connected(fd) => ConnectionState::Connected(&self.by_fd[fd]),
            ConnectionState::New(fd) => ConnectionState::New(&self.by_fd[fd]),
        }
    }

    /// Looks up a socket by file descriptor.
    fn get_by_fd(&self, fd: RawFd) -> Option<&T> {
        self.by_fd.get(&fd)
    }

    /// Marks the connection for `peer_addr` as closed.
    ///
    /// The socket associated with that connection will be removed from the map. If there was no
    /// connection for the given peer, or if it was already closed, returns `None`.
    fn mark_closed(&mut self, peer_addr: &SocketLocator) -> Option<T> {
        let entry = self.by_peer_addr.remove(peer_addr)?;
        match &entry {
            ConnectionState::NotYetConnected => {
                unreachable!("should not be in the table at all")
            }
            ConnectionState::Connected(fd) => self.by_fd.remove(fd),
            ConnectionState::New(fd) => {
                self.inactive_ttls.remove(peer_addr);
                self.by_fd.remove(fd)
            }
        }
    }

    /// Marks the connection for `peer_addr` as closed, if it matches the connection id passed.
    fn mark_closed_if(&mut self, peer_addr: &SocketLocator, f: impl FnOnce(&T) -> bool) {
        if let Some(ConnectionState::Connected(fd)) = self.by_peer_addr.get(peer_addr) {
            let socket = &self.by_fd[fd];
            if f(socket) {
                self.by_fd.remove(fd);
                self.by_peer_addr.remove(peer_addr);
            }
        }
    }

    /// Removes the connection information from inactive_ttls effectively marking it as active and
    /// healthy
    fn mark_as_active(&mut self, peer_addr: &SocketLocator, f: impl FnOnce(&mut T)) {
        self.inactive_ttls.remove(peer_addr);
        if let Some(entry) = self.by_peer_addr.get_mut(peer_addr) {
            if let ConnectionState::New(fd) = entry {
                f(self
                    .by_fd
                    .get_mut(fd)
                    .expect("fd in by_peer_addr should be in by_fd"));
                *entry = ConnectionState::Connected(*fd);
            }
        }
    }

    /// Decrements the TTL for each of the inactive candidates, invoking a callback
    /// for all connections that reached end of life and removing them
    fn inactive_tcp(&self, current_tick: u64) -> Vec<SocketLocator> {
        self.inactive_ttls
            .iter()
            .filter_map(move |(locator, ttl)| {
                if current_tick >= *ttl {
                    Some(*locator)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug)]
    struct FakeSocket {
        fd: RawFd,
        id: i32,
    }
    impl AsRawFd for FakeSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    #[test]
    fn connection_map_absent() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Udp("127.0.0.1:80".parse().expect("valid SocketAddr"));

        assert!(map.get_by_fd(0).is_none());
        assert!(matches!(
            map.get_by_addr(&addr),
            ConnectionState::NotYetConnected
        ));
        assert!(map.mark_closed(&addr).is_none());
    }

    #[test]
    fn connection_map_lifecycle() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Udp("127.0.0.1:80".parse().expect("valid SocketAddr"));

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr, None);
        assert_eq!(socket_ref.id, id);

        assert_eq!(map.get_by_fd(fd).expect("present").id, id);
        match map.get_by_addr(&addr) {
            ConnectionState::Connected(socket) => {
                assert_eq!(socket.id, id);
            }
            state => {
                panic!("unexpected state: {:?}", state)
            }
        }

        // Mark closed.
        let socket = map.mark_closed(&addr).expect("present");
        assert_eq!(socket.id, id);

        assert!(map.get_by_fd(fd).is_none());
        assert!(matches!(
            map.get_by_addr(&addr),
            ConnectionState::NotYetConnected
        ));
    }

    #[test]
    fn connection_map_first_insert_wins() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Udp("127.0.0.1:80".parse().expect("valid SocketAddr"));

        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr, None);
        assert_eq!(socket_ref.id, id);

        // Check that we don't replace an existing connection.
        let new_socket = FakeSocket { fd, id: id + 1 };
        let socket_ref = map.get_or_insert_connected(new_socket, addr, None);
        assert_eq!(socket_ref.id, id);

        assert_eq!(map.get_by_fd(fd).expect("present").id, id);
        match map.get_by_addr(&addr) {
            ConnectionState::Connected(socket) => {
                assert_eq!(socket.id, id);
            }
            state => {
                panic!("unexpected state: {:?}", state)
            }
        }
    }

    #[test]
    fn connection_map_can_insert_over_closed() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Udp("127.0.0.1:80".parse().expect("valid SocketAddr"));

        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr, None);
        assert_eq!(socket_ref.id, id);

        map.mark_closed(&addr);

        let new_socket = FakeSocket { fd, id: id + 1 };
        let socket_ref = map.get_or_insert_connected(new_socket, addr, None);
        assert_eq!(socket_ref.id, id + 1);
    }

    #[test]
    fn connection_map_remove_open() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Udp("127.0.0.1:80".parse().expect("valid SocketAddr"));

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr, None);
        assert_eq!(socket_ref.id, id);

        map.mark_closed_if(&addr, |s| s.id == (id + 1));

        assert_eq!(map.get_by_fd(fd).expect("present").id, id);
        match map.get_by_addr(&addr) {
            ConnectionState::Connected(socket) => {
                assert_eq!(socket.id, id);
            }
            state => {
                panic!("unexpected state: {:?}", state)
            }
        }
    }

    #[test]
    fn inactive_connection_tracking() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Tcp {
            id: 1,
            is_ipv6: false,
            is_tls: false,
        };

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let _ = map.get_or_insert_connected(socket, addr, Some(0));

        assert_eq!(
            map.inactive_ttls,
            HashMap::from([(addr, TCP_INACTIVE_CONNECTION_TTL_TICKS)])
        );

        // Simulate getting close to reaching TTL
        *map.inactive_ttls
            .get_mut(&addr)
            .expect("entry should exist") = 1;
        assert!(
            !map.inactive_tcp(TCP_INACTIVE_CONNECTION_TTL_TICKS)
                .is_empty(),
            "There should be some inactive tcp connections"
        );
    }

    #[test]
    fn mark_sender_as_active() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr = SocketLocator::Tcp {
            id: 2,
            is_ipv6: false,
            is_tls: false,
        };

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let _ = map.get_or_insert_connected(socket, addr, Some(0));

        assert_eq!(
            map.inactive_ttls,
            HashMap::from([(addr, TCP_INACTIVE_CONNECTION_TTL_TICKS)])
        );

        map.mark_as_active(&addr, |_| {});
        assert!(
            map.inactive_ttls.is_empty(),
            "The only connections should have been removed"
        );
    }
}
