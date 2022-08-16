//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    collections::{hash_map, HashMap},
    future::Future,
    io,
    net::{SocketAddr, UdpSocket},
    os::unix::io::{AsRawFd, FromRawFd, RawFd},
    sync::Arc,
};

use anyhow::Result;
use log::*;
use nix::sys::epoll::*;
use parking_lot::RwLock;
use scopeguard::ScopeGuard;

use crate::{
    common::{try_scoped, Duration, Instant},
    metrics::TimingOptions,
    sfu,
};

/// Controls number of sockets a particular thread will handle without going back to epoll.
///
/// A higher number saves calls into the kernel, but claims more events for a single thread to
/// process.
const MAX_EPOLL_EVENTS: usize = 16;

/// How long before an IP address can be reused, if it was previously used by a now-closed
/// connection.
///
/// A higher number prevents delayed sends from "reviving" a closed connection for longer,
/// but could result in the server ignoring someone who reconnected.
const CLOSED_SOCKET_EXPIRATION_IN_TICKS: u32 = 10;

/// The shared state for an epoll-based UDP server.
///
/// This server is implemented with a "new client" socket that receives new connections, plus a map
/// of dedicated sockets for each connected client. Processing these sockets is handled by [epoll],
/// with each thread of the UDP server getting its own epoll descriptor to block on. This allows
/// events to be level-triggered (as in, threads will be repeatedly woken up if a socket with data
/// is not immediately read from) while still only waking one thread for a particular event.
///
/// The implementation uses two-phase cleanup for clients that have left the call (either gracefully
/// or through timeout). This avoids opening a new connection immediately after the old one was
/// closed.
///
/// [epoll]: https://man7.org/linux/man-pages/man7/epoll.7.html
pub(super) struct UdpServerState {
    local_addr: SocketAddr,
    new_client_socket: UdpSocket,
    all_epoll_fds: Vec<RawFd>,
    all_connections: RwLock<ConnectionMap>,
    tick_interval: Duration,
}

impl UdpServerState {
    /// Sets up the server state by binding an initial socket to `local_addr`.
    ///
    /// Also creates a separate epoll file descriptor for each thread we plan to use.
    pub fn new(
        local_addr: SocketAddr,
        num_threads: usize,
        tick_interval: Duration,
    ) -> Result<Arc<Self>> {
        let new_client_socket = Self::open_socket_with_reusable_port(&local_addr)?;
        let all_epoll_fds = (0..num_threads)
            .map(|_| epoll_create1(EpollCreateFlags::empty()))
            .collect::<nix::Result<_>>()?;
        let result = Self {
            local_addr,
            new_client_socket,
            all_epoll_fds,
            all_connections: RwLock::new(ConnectionMap::new()),
            tick_interval,
        };
        result.add_socket_to_poll_for_reads(&result.new_client_socket)?;
        Ok(Arc::new(result))
    }

    /// Opens a socket and binds it to `local_addr` after setting the `SO_REUSEPORT` sockopt.
    ///
    /// This allows multiple sockets to bind to the same address.
    fn open_socket_with_reusable_port(local_addr: &SocketAddr) -> Result<UdpSocket> {
        use nix::sys::socket::*;

        // Open an IPv4 UDP socket in blocking mode.
        let socket_fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        // Don't pass ownership into a std::net::UdpSocket just yet;
        // it's not clear whether it's correct to do that before binding.
        // Instead, use an ad-hoc ScopeGuard.
        let socket_fd = scopeguard::guard(socket_fd, |fd| match nix::unistd::close(fd) {
            Ok(()) => {}
            Err(e) => warn!("error closing failed socket: {}", e),
        });
        // Allow later sockets to handle connections.
        setsockopt(*socket_fd, sockopt::ReusePort, &true)?;
        // Bind the socket to the given local address.
        bind(*socket_fd, &SockaddrStorage::from(*local_addr))?;
        // Pass ownership from ScopeGuard into a proper Rust UdpSocket.
        // std::net::UdpSocket can only be created and bound in one step, which
        // doesn't allow us to set SO_REUSEPORT.
        // Safety: we have just created this socket FD, so we know it's valid.
        let result = unsafe { UdpSocket::from_raw_fd(ScopeGuard::into_inner(socket_fd)) };
        // Set a read timeout for a "pseudo-nonblocking" interface.
        // Why? Because epoll might wake up more than one thread to read from a single socket.
        result.set_read_timeout(Some(Duration::from_millis(10).into()))?;
        Ok(result)
    }

    /// Adds `socket` to be polled by each of the descriptors in `self.all_epoll_fds`.
    ///
    /// Specifically, this is only polling for read events with "exclusive" wakeups. That is,
    /// "out-of-band" data will be ignored, and only one epoll FD will receive an event for any
    /// particular socket being ready.
    fn add_socket_to_poll_for_reads(&self, socket: &UdpSocket) -> Result<()> {
        let socket_fd = socket.as_raw_fd();
        let mut event_read_only = EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLEXCLUSIVE,
            socket_fd as u64,
        );
        for &epoll_fd in &self.all_epoll_fds {
            epoll_ctl(
                epoll_fd,
                EpollOp::EpollCtlAdd,
                socket_fd,
                &mut event_read_only,
            )?;
        }
        Ok(())
    }

    /// Launches the configured number of threads for the server using Tokio's blocking thread pool
    /// ([`tokio::task::spawn_blocking`]).
    ///
    /// `handle_packet` should take a single incoming packet's source address and data and produce a
    /// (possibly empty) set of outgoing packets.
    ///
    /// This should only be called once.
    pub fn start_threads(
        self: Arc<Self>,
        handle_packet: impl FnMut(SocketAddr, &mut [u8]) -> Vec<(Vec<u8>, SocketAddr)>
            + Clone
            + Send
            + 'static,
    ) -> impl Future {
        let all_handles = self.all_epoll_fds.iter().map(|&epoll_fd| {
            let self_for_thread = self.clone();
            let handle_packet_for_thread = handle_packet.clone();
            tokio::task::spawn_blocking(move || {
                self_for_thread.run(epoll_fd, handle_packet_for_thread)
            })
        });
        futures::future::select_all(all_handles)
    }

    /// Runs a single listener on the current thread, polling `epoll_fd`.
    ///
    /// See [`UdpServerState::start_threads`].
    fn run(
        self: Arc<Self>,
        epoll_fd: RawFd,
        mut handle_packet: impl FnMut(SocketAddr, &mut [u8]) -> Vec<(Vec<u8>, SocketAddr)>,
    ) {
        let new_client_socket_fd = self.new_client_socket.as_raw_fd();
        let mut buf = [0u8; 1500];

        loop {
            let mut current_events = [EpollEvent::empty(); MAX_EPOLL_EVENTS];
            let num_events = epoll_wait(epoll_fd, &mut current_events, -1).unwrap_or_else(|err| {
                warn!("epoll_wait() failed: {}", err);
                0
            });
            for event in &current_events[..num_events] {
                let socket_fd = event.data() as i32;
                let connections_lock = self.all_connections.read();
                let socket = if socket_fd == new_client_socket_fd {
                    &self.new_client_socket
                } else {
                    match connections_lock.get_by_fd(socket_fd) {
                        Some(socket) => socket,
                        None => {
                            // By the time we got to this event the socket was closed.
                            continue;
                        }
                    }
                };

                if event.events().contains(EpollFlags::EPOLLERR) {
                    match socket.take_error() {
                        Err(err) => {
                            warn!("take_error() failed: {}", err);
                            event!("calling.udp.epoll.take_error_failure");
                            // Hopefully this is a transient failure. Just skip this socket for now.
                            continue;
                        }
                        Ok(None) => {
                            // Assume another thread got here first.
                            continue;
                        }
                        Ok(Some(err)) => {
                            if err.kind() == io::ErrorKind::ConnectionRefused {
                                // This can happen when someone leaves a call
                                // because e.g. their router stops forwarding packets.
                                // This is normal with UDP; technically this error happened
                                // with the *previous* packet and we're just finding out now.
                                trace!("socket error: {}", err);

                                match socket.peer_addr() {
                                    Err(err) => {
                                        warn!(
                                            "peer_addr() failed while handling an error: {}",
                                            err
                                        );
                                    }
                                    Ok(addr) => {
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
                                        write_lock.mark_closed(&addr, Instant::now());
                                        // No need to read more from this socket.
                                        continue;
                                    }
                                }
                            } else {
                                event!("calling.udp.epoll.socket_error");
                                warn!("socket error: {}", err);
                            }
                        }
                    }
                }

                // We ignore all other events but EPOLLIN; hangups will be handled by tick()
                // expiring the connection.
                if !event.events().contains(EpollFlags::EPOLLIN) {
                    continue;
                }

                // We only read one packet for each socket that's ready. This isn't as efficient
                // as it could be; if one socket has many packets ready, we have to go back into
                // the epoll loop to find that out. On the other hand, this does ensure that we
                // don't get stuck reading from one socket and ignore all others.
                //
                // Note that this relies on using epoll in level-triggered mode rather than
                // edge-triggered.
                let (size, sender_addr) = match socket.recv_from(&mut buf) {
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
                            _ => {
                                warn!("recv_from() failed: {}", err);
                            }
                        }
                        continue;
                    }
                    Ok((size, sender_addr)) => (size, sender_addr),
                };
                drop(connections_lock);

                let packets_to_send = handle_packet(sender_addr, &mut buf[..size]);
                for (buf, addr) in packets_to_send {
                    self.send_packet(&buf, addr)
                }
            }
        }
    }

    pub fn send_packet(&self, buf: &[u8], addr: SocketAddr) {
        trace!("sending packet of {} bytes to {}", buf.len(), addr);
        time_scope!(
            "calling.udp.epoll.send_packet",
            TimingOptions::nanosecond_1000_per_minute()
        );
        sampling_histogram!("calling.epoll.send_packet.size_bytes", || buf.len());

        let connections_lock = self.all_connections.read();
        match connections_lock.get_by_addr(&addr) {
            ConnectionState::Connected(socket) => {
                if let Err(err) = socket.send(buf) {
                    if err.kind() == io::ErrorKind::ConnectionRefused {
                        // This can happen when someone leaves a call
                        // because e.g. their router stops forwarding packets.
                        // This is normal with UDP; technically this error happened
                        // with the *previous* packet and we're just finding out now.
                        trace!("send() failed: {}", err);

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
                        write_lock.mark_closed(&addr, Instant::now());
                    } else {
                        warn!("send() failed: {}", err);
                    }
                }
            }
            ConnectionState::Closed(_) => {
                trace!("dropping packet (connection already closed)")
            }
            ConnectionState::NotYetConnected => {
                // Drop the read lock...
                drop(connections_lock);
                // ...and connect with a write lock...
                let mut write_lock = self.all_connections.write();

                // ...and check if another thread beat us to it.
                match write_lock.get_by_addr(&addr) {
                    ConnectionState::Connected(socket) => {
                        if let Err(err) = socket.send(buf) {
                            if err.kind() == io::ErrorKind::ConnectionRefused {
                                // This can happen when someone leaves a call
                                // because e.g. their router stops forwarding packets.
                                // This is normal with UDP; technically this error happened
                                // with the *previous* packet and we're just finding out now.
                                trace!("send() failed: {}", err);

                                // ...and mark the connection as closed.
                                write_lock.mark_closed(&addr, Instant::now());
                            } else {
                                warn!("send() failed: {}", err);
                            }
                        }
                    }
                    ConnectionState::Closed(_) => {
                        trace!("dropping packet (connection already closed)")
                    }
                    ConnectionState::NotYetConnected => {
                        trace!("connecting to {:?}", addr);
                        match try_scoped(|| {
                            let client_socket =
                                Self::open_socket_with_reusable_port(&self.local_addr)?;
                            client_socket.connect(addr)?;
                            self.add_socket_to_poll_for_reads(&client_socket)?;
                            Ok(client_socket)
                        }) {
                            Ok(client_socket) => {
                                let client_socket =
                                    write_lock.get_or_insert_connected(client_socket, addr);
                                if let Err(err) = client_socket.send(buf) {
                                    warn!("send() failed: {}", err);
                                }
                            }
                            Err(e) => {
                                error!("failed to connect to peer: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Process the results of [`sfu::SfuServer::tick`].
    ///
    /// This includes cleaning up connections for clients that have left.
    pub fn tick(&self, mut tick_update: sfu::TickOutput) -> Result<()> {
        for (buf, addr) in tick_update.packets_to_send {
            trace!("sending tick packet of {} bytes to {}", buf.len(), addr);

            let connections_lock = self.all_connections.read();
            match connections_lock.get_by_addr(&addr) {
                ConnectionState::Connected(socket) => {
                    if let Err(err) = socket.send(&buf) {
                        if err.kind() == io::ErrorKind::ConnectionRefused {
                            // This can happen when someone leaves a call
                            // because e.g. their router stops forwarding packets.
                            // This is normal with UDP; technically this error happened
                            // with the *previous* packet and we're just finding out now.
                            trace!("send() failed: {}", err);

                            // This will call mark_closed below
                            tick_update.expired_client_addrs.push(addr)
                        } else {
                            warn!("send() failed: {}", err);
                        }
                    }
                }
                ConnectionState::Closed(_) => {
                    trace!("dropping packet (connection already closed)")
                }
                ConnectionState::NotYetConnected => {
                    trace!("dropping packet (not yet connected)")
                }
            }
        }

        // Collect the addresses of any sockets that have been closed for several ticks.
        // We can now free up those table entries.
        // (We scan ahead of time to avoid taking the write lock if there aren't any.)
        let now = Instant::now();
        let expiration = now - (CLOSED_SOCKET_EXPIRATION_IN_TICKS * self.tick_interval);
        let mut expired_socket_addrs = vec![];
        {
            let connections_lock = self.all_connections.read();
            for (addr, close_timestamp) in connections_lock.closed_connection_iter() {
                if close_timestamp <= &expiration {
                    expired_socket_addrs.push(*addr);
                }
            }
        }

        // Clean up any clients that have already left.
        if !tick_update.expired_client_addrs.is_empty() || !expired_socket_addrs.is_empty() {
            match self
                .all_connections
                .try_write_for(self.tick_interval.into())
            {
                None => {
                    anyhow::bail!(
                        "could not acquire connection lock after {:?}; one of the epoll handler threads is likely deadlocked",
                        self.tick_interval
                    );
                }
                Some(mut socket_lock) => {
                    // Clean up sockets closed on previous ticks.
                    // This two-phase cleanup makes the following scenario unlikely:
                    // 1. UDP handler produces packets for socket X.
                    // 2. The UDP handler is pre-empted.
                    // 3. The tick handler runs and removes socket X.
                    // 4. The UDP handler resumes and tries to send to socket X.
                    // 5. The UDP handler thinks it needs to make a new connection.
                    for addr in expired_socket_addrs.iter() {
                        socket_lock.remove_closed(addr);
                    }

                    // Mark clients to be cleaned up next tick.
                    for addr in tick_update.expired_client_addrs.iter() {
                        socket_lock.mark_closed(addr, now);
                    }
                }
            }
        }
        Ok(())
    }
}

/// A doubly-keyed map that allows looking up a socket by raw file descriptor (for epoll) or by peer
/// address.
///
/// The map owns the socket, so removal from the map will close the socket as well. However, when a
/// socket is removed, the peer address stays in the map to distinguish "recently closed" from "not
/// yet connected". [`ConnectionMap::mark_closed`] and [`ConnectionMap::remove_closed`] implement
/// the two parts of this two-phase cleanup.
///
/// The map is generic to support unit testing, but isn't intended for storing anything else.
struct ConnectionMap<T = UdpSocket> {
    /// The primary map from file descriptors to sockets.
    ///
    /// The use of file descriptors is largely arbitrary; it's a value *already* uniquely associated
    /// with a socket.
    by_fd: HashMap<RawFd, T>,

    /// The secondary map from peer addresses to file descriptors, or the timestamp when the
    /// connection to that socket was closed.
    by_peer_addr: HashMap<SocketAddr, ConnectionState<RawFd>>,
}

/// Represents the state of a connection in a [ConnectionMap].
#[derive(Debug)]
enum ConnectionState<T> {
    /// The peer address was not found, so there must be no existing connection.
    NotYetConnected,
    /// The given socket is connected to the peer in question.
    Connected(T),
    /// There was a connection to this peer but that connection has been closed.
    Closed(Instant),
}

impl<T: AsRawFd> ConnectionMap<T> {
    fn new() -> Self {
        Self {
            by_fd: HashMap::new(),
            by_peer_addr: HashMap::new(),
        }
    }

    /// Gets the socket for `peer_addr` or inserts `socket` if there isn't one.
    ///
    /// If there is already a socket for `peer_addr`, the argument `socket` will be dropped (and the
    /// underlying socket closed).
    fn get_or_insert_connected(&mut self, socket: T, peer_addr: SocketAddr) -> &T {
        let fd = socket.as_raw_fd();
        match self.by_peer_addr.entry(peer_addr) {
            hash_map::Entry::Occupied(mut entry) => {
                match entry.get() {
                    ConnectionState::NotYetConnected => {
                        unreachable!("should not be in the table at all")
                    }
                    ConnectionState::Connected(existing_fd) => {
                        // This address is already connected to a different socket.
                        return &self.by_fd[existing_fd];
                    }
                    ConnectionState::Closed(_) => {
                        entry.insert(ConnectionState::Connected(fd));
                    }
                }
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(ConnectionState::Connected(fd));
            }
        }
        let inserted_socket = match self.by_fd.entry(fd) {
            hash_map::Entry::Occupied(_) => {
                unreachable!("file descriptor reused before socket closed");
            }
            hash_map::Entry::Vacant(entry) => entry.insert(socket),
        };
        inserted_socket
    }

    /// Gets the connection for `peer_addr`, which can be in any of the states represented by
    /// [ConnectionState].
    fn get_by_addr(&self, peer_addr: &SocketAddr) -> ConnectionState<&T> {
        match self
            .by_peer_addr
            .get(peer_addr)
            .unwrap_or(&ConnectionState::NotYetConnected)
        {
            ConnectionState::NotYetConnected => ConnectionState::NotYetConnected,
            ConnectionState::Connected(fd) => ConnectionState::Connected(&self.by_fd[fd]),
            ConnectionState::Closed(instant) => ConnectionState::Closed(*instant),
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
    fn mark_closed(&mut self, peer_addr: &SocketAddr, now: Instant) -> Option<T> {
        let entry = self.by_peer_addr.get_mut(peer_addr)?;
        match entry {
            ConnectionState::NotYetConnected => {
                unreachable!("should not be in the table at all")
            }
            ConnectionState::Connected(fd) => {
                let socket = self.by_fd.remove(fd);
                *entry = ConnectionState::Closed(now);
                socket
            }
            ConnectionState::Closed(_) => None,
        }
    }

    /// Returns an iterator over the closed connections only.
    fn closed_connection_iter(&self) -> impl Iterator<Item = (&SocketAddr, &Instant)> {
        self.by_peer_addr
            .iter()
            .filter_map(|(addr, entry)| match entry {
                ConnectionState::NotYetConnected => {
                    unreachable!("should not be in the table at all")
                }
                ConnectionState::Connected(_fd) => None,
                ConnectionState::Closed(instant) => Some((addr, instant)),
            })
    }

    /// Removes the entry for `peer_addr` from the map, which must have previously been marked
    /// closed.
    ///
    /// This allows a peer address to be reused (perhaps reconnecting to the server). It also keeps
    /// the peer map from growing indefinitely.
    ///
    /// See [`ConnectionMap::mark_closed`].
    fn remove_closed(&mut self, peer_addr: &SocketAddr) {
        match self.by_peer_addr.remove_entry(peer_addr) {
            None => {
                warn!("no connection record to remove for this address");
            }
            Some((_, ConnectionState::NotYetConnected)) => {
                unreachable!("should not be in the table at all");
            }
            Some((addr, ConnectionState::Connected(fd))) => {
                // There's already a new connection to this address. Put the entry back.
                self.by_peer_addr
                    .insert(addr, ConnectionState::Connected(fd));
            }
            Some((_, ConnectionState::Closed(_))) => {}
        }
    }
}

#[cfg(test)]
mod tests {
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
        let addr = "127.0.0.1:80".parse().expect("valid SocketAddr");

        assert!(map.get_by_fd(0).is_none());
        assert!(matches!(
            map.get_by_addr(&addr),
            ConnectionState::NotYetConnected
        ));
        assert!(map.mark_closed(&addr, Instant::now()).is_none());
        map.remove_closed(&addr); // just don't panic
    }

    #[test]
    fn connection_map_lifecycle() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr: SocketAddr = "127.0.0.1:80".parse().expect("valid SocketAddr");

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr);
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
        let now = Instant::now();
        let socket = map.mark_closed(&addr, now).expect("present");
        assert_eq!(socket.id, id);

        assert!(map.get_by_fd(fd).is_none());
        assert!(
            matches!(map.get_by_addr(&addr), ConnectionState::Closed(instant) if instant == now)
        );

        // Remove closed.
        map.remove_closed(&addr);

        assert!(map.get_by_fd(fd).is_none());
        assert!(matches!(
            map.get_by_addr(&addr),
            ConnectionState::NotYetConnected
        ));
    }

    #[test]
    fn connection_map_first_insert_wins() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr: SocketAddr = "127.0.0.1:80".parse().expect("valid SocketAddr");

        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr);
        assert_eq!(socket_ref.id, id);

        // Check that we don't replace an existing connection.
        let new_socket = FakeSocket { fd, id: id + 1 };
        let socket_ref = map.get_or_insert_connected(new_socket, addr);
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
        let addr: SocketAddr = "127.0.0.1:80".parse().expect("valid SocketAddr");

        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr);
        assert_eq!(socket_ref.id, id);

        map.mark_closed(&addr, Instant::now());
        // But don't remove it!

        let new_socket = FakeSocket { fd, id: id + 1 };
        let socket_ref = map.get_or_insert_connected(new_socket, addr);
        assert_eq!(socket_ref.id, id + 1);
    }

    #[test]
    fn connection_map_remove_open() {
        let mut map: ConnectionMap<FakeSocket> = ConnectionMap::new();
        let addr: SocketAddr = "127.0.0.1:80".parse().expect("valid SocketAddr");

        // Insert
        let fd = 5;
        let id = 55;
        let socket = FakeSocket { fd, id };
        let socket_ref = map.get_or_insert_connected(socket, addr);
        assert_eq!(socket_ref.id, id);

        // Try to remove.
        map.remove_closed(&addr);

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
}
