//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The model for the SFU's shared state.

use core::ops::DerefMut;
use std::{
    collections::HashMap, convert::TryInto, fmt::Write, net::SocketAddr, sync::Arc,
    time::SystemTime,
};

use anyhow::Result;
use hkdf::Hkdf;
use log::*;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    call::{self, Call, LoggableCallId},
    common::{DataRate, Duration, Instant, TwoGenerationCacheWithManualRemoveOld},
    config,
    connection::{self, Connection, HandleRtcpResult, PacketToSend, SrtpMasterSource},
    dtls, googcc, ice,
    ice::BindingRequest,
    metrics::{Histogram, Timer},
    rtp,
};
pub use crate::{
    call::{CallId, DemuxId, UserId},
    connection::{SrtpMasterSourceClientPublic, SrtpMasterSourceServerPublic},
};

#[derive(Error, Eq, PartialEq)]
pub enum SfuError {
    #[error("DemuxId is already in use for the call")]
    DuplicateDemuxIdDetected,
    #[error("non-ICE packet from unknown address: {0}")]
    UnknownAddress(SocketAddr),
    #[error("packet with unknown type from {0}")]
    UnknownPacketType(SocketAddr),
    #[error(
        "connection with (CallId={:?} DemuxId={:?}) went missing",
        LoggableCallId::from(.0),
        .1
    )]
    MissingConnection(CallId, DemuxId),
    #[error("call {:?} went missing", LoggableCallId::from(.0))]
    MissingCall(CallId),
    #[error("parsing ICE binding request failed: {0}")]
    ParseIceBindingRequest(ice::ParseError),
    #[error("ICE binding request with unknown username: {0:?}")]
    IceBindingRequestUnknownUsername(Vec<u8>),
    #[error("connection error: {0}")]
    ConnectionError(connection::Error),
    #[error("call error: {0}")]
    CallError(call::Error),
}

impl std::fmt::Debug for SfuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rely on the Display synthesized by thiserror.
        write!(f, "SfuError({})", self)
    }
}

/// Uniquely identifies a Connection across calls using a combination
/// of CallId and DemuxId.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnectionId {
    call_id: CallId,
    demux_id: DemuxId,
}

impl ConnectionId {
    fn from_call_id_and_demux_id(call_id: CallId, demux_id: DemuxId) -> ConnectionId {
        Self { call_id, demux_id }
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "call_id: {}, demux_id: {}",
            &LoggableCallId::from(&self.call_id),
            &self.demux_id.as_u32()
        )
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionId")
            .field("call_id", &LoggableCallId::from(&self.call_id))
            .field("demux_id", &self.demux_id)
            .finish()
    }
}

pub struct Sfu {
    /// Configuration structure originally from the command line or environment.
    pub config: &'static config::Config,
    /// DTLS fingerprint of the server, from sha256(certificate der).
    server_dtls_fingerprint: [u8; 32],
    /// Mapping of Calls by their unique CallId. Set by configuration/signaling.
    call_by_call_id: HashMap<CallId, Arc<Mutex<Call>>>,
    /// Mapping of Connection by their unique ConnectionId, which is really (CallId, DemuxId)
    // The value needs to be an Arc so we can have a lock on the Connection while outside
    // the lock of the SFU.
    connection_by_id: HashMap<ConnectionId, Arc<Mutex<Connection>>>,
    /// Packets are demuxed by either the incoming socket address or the ICE binding request username.
    connection_id_by_ice_request_username: HashMap<Vec<u8>, ConnectionId>,
    connection_id_by_address: TwoGenerationCacheWithManualRemoveOld<SocketAddr, ConnectionId>,

    /// The last time activity was checked.
    activity_checked: Instant,
    /// The last time diagnostics were logged.
    diagnostics_logged: Instant,
}

/// The state that results from the SFU receiving a tick event, to be processed by the UDP server.
///
/// See [Sfu::tick].
pub struct TickOutput {
    pub packets_to_send: Vec<(PacketToSend, SocketAddr)>,
    pub expired_client_addrs: Vec<SocketAddr>,
}

pub struct SfuStats {
    pub histograms: HashMap<&'static str, Histogram<usize>>,
    pub values: HashMap<&'static str, f32>,
}

impl Sfu {
    pub fn new(now: Instant, config: &'static config::Config) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(&config.server_certificate_der);
        let server_dtls_fingerprint: [u8; 32] = hasher.finalize()[..]
            .try_into()
            .expect("Sha256 result should be 32 bytes");

        trace!("new sfu with:");
        trace!("  server_dtls_fingerprint: {:?}", server_dtls_fingerprint);

        Ok(Self {
            config,
            server_dtls_fingerprint,
            call_by_call_id: HashMap::new(),
            connection_by_id: HashMap::new(),
            connection_id_by_ice_request_username: HashMap::new(),
            connection_id_by_address: TwoGenerationCacheWithManualRemoveOld::new(
                Duration::from_secs(30),
                now,
            ),
            activity_checked: now,
            diagnostics_logged: now,
        })
    }

    /// Return a snapshot of all calls tracked by the Sfu.
    pub fn get_calls_snapshot(&self) -> Vec<Arc<Mutex<Call>>> {
        self.call_by_call_id.values().map(Arc::clone).collect()
    }

    /// Get info about a call that is relevant to call signaling.
    pub fn get_call_signaling_info(&self, call_id: CallId) -> Option<CallSignalingInfo> {
        let call = self.call_by_call_id.get(&Arc::new(call_id))?;
        let call = call.lock();
        Some(CallSignalingInfo {
            size: call.size(),
            created: call.created(),
            creator_id: call.creator_id().clone(),
            client_ids: call.get_client_ids(),
        })
    }

    /// Gives a snapshot of current metrics, such as call size.
    pub fn get_stats(&self) -> SfuStats {
        let mut histograms = HashMap::new();
        let mut values = HashMap::new();
        let mut all_clients = 0;
        let mut calls_above_one = 0;
        let mut clients_in_calls_above_one = 0;
        let mut call_size = Histogram::default();
        let mut call_size_squared = Histogram::default();
        let mut call_age_minutes = Histogram::default();
        let mut call_size_above_one = Histogram::default();
        let mut call_size_squared_above_one = Histogram::default();
        let mut call_age_minutes_above_one = Histogram::default();
        for call in self.call_by_call_id.values() {
            let call = call.lock();
            let clients = call.size();
            let clients_squared = clients * clients;
            let call_duration =
                (call.created().elapsed().unwrap_or_default().as_secs() / 60) as usize;

            all_clients += clients;
            call_size.push(clients);
            call_size_squared.push(clients_squared);
            call_age_minutes.push(call_duration);
            if clients > 1 {
                call_size_above_one.push(clients);
                call_size_squared_above_one.push(clients_squared);
                call_age_minutes_above_one.push(call_duration);
                calls_above_one += 1;
                clients_in_calls_above_one += clients;
            }
        }
        histograms.insert("calling.sfu.call_size", call_size);
        histograms.insert("calling.sfu.call_size.squared", call_size_squared);
        histograms.insert("calling.sfu.call_age_minutes", call_age_minutes);
        histograms.insert("calling.sfu.call_size.above_one", call_size_above_one);
        histograms.insert(
            "calling.sfu.call_size.squared.above_one",
            call_size_squared_above_one,
        );
        histograms.insert(
            "calling.sfu.call_age_minutes.above_one",
            call_age_minutes_above_one,
        );
        values.insert("calling.sfu.calls.count", self.call_by_call_id.len() as f32);
        values.insert("calling.sfu.calls.clients.count", all_clients as f32);
        values.insert("calling.sfu.calls.above_one.count", calls_above_one as f32);
        values.insert(
            "calling.sfu.calls.above_one.clients.count",
            clients_in_calls_above_one as f32,
        );

        SfuStats { histograms, values }
    }

    /// Adds the given client, creating a call if it doesn't exist.
    #[allow(clippy::too_many_arguments)]
    pub fn get_or_create_call_and_add_client(
        &mut self,
        call_id: CallId,
        user_id: &UserId,
        resolution_request_id: u64,
        active_speaker_id: String,
        demux_id: DemuxId,
        server_ice_ufrag: String,
        server_ice_pwd: String,
        client_ice_ufrag: String,
        client_public: SrtpMasterSourceClientPublic,
    ) -> Result<SrtpMasterSourceServerPublic, SfuError> {
        let loggable_call_id = LoggableCallId::from(&call_id);
        trace!("get_or_create_call_and_add_client():");

        trace!("  {:25}{}", "call_id:", loggable_call_id);
        trace!("  {:25}{}", "user_id:", hex::encode(user_id.as_slice()));
        trace!("  {:25}{}", "client_ice_ufrag:", client_ice_ufrag);
        trace!("  {:25}{:?}", "client_public:", client_public,);
        trace!("  {:25}{:?}", "demux_id:", demux_id);
        trace!("  {:25}{}", "resolution_request_id:", resolution_request_id);
        trace!("  {:25}{}", "active_speaker_id:", active_speaker_id);

        let initial_target_send_rate =
            DataRate::from_kbps(self.config.initial_target_send_rate_kbps);
        let min_target_send_rate = DataRate::from_kbps(self.config.min_target_send_rate_kbps);
        let max_target_send_rate = DataRate::from_kbps(self.config.max_target_send_rate_kbps);
        let default_requested_max_send_rate =
            DataRate::from_kbps(self.config.default_requested_max_send_rate_kbps);

        trace!("  {:25}{}", "server_ice_ufrag:", server_ice_ufrag);
        trace!("  {:25}{}", "server_ice_pwd:", server_ice_pwd);

        let ice_pwd = server_ice_pwd.as_bytes().to_vec();

        let ice_request_username =
            ice::join_username(client_ice_ufrag.as_bytes(), server_ice_ufrag.as_bytes());
        let ice_response_username =
            ice::join_username(server_ice_ufrag.as_bytes(), client_ice_ufrag.as_bytes());

        let now = Instant::now();

        let connection_id = ConnectionId::from_call_id_and_demux_id(call_id.clone(), demux_id);

        let active_speaker_message_interval_ms = self.config.active_speaker_message_interval_ms;
        let call = self
            .call_by_call_id
            .entry(call_id.clone())
            .or_insert_with(|| {
                Arc::new(Mutex::new(Call::new(
                    LoggableCallId::from(&call_id),
                    user_id.clone(),
                    Duration::from_millis(active_speaker_message_interval_ms),
                    initial_target_send_rate,
                    default_requested_max_send_rate,
                    now,
                    SystemTime::now(),
                )))
            });
        {
            let mut call = call.lock();
            if call.has_client(demux_id) {
                return Err(SfuError::DuplicateDemuxIdDetected);
            }

            info!(
                "call_id: {} adding demux_id: {}",
                loggable_call_id,
                demux_id.as_u32()
            );

            call.add_client(
                demux_id,
                user_id.clone(),
                active_speaker_id,
                resolution_request_id,
                Instant::now(), // Now after taking the lock
            );
        }

        // ACKs can be sent from any SSRC that the client is configured to send with, which includes the
        // video base layer, so use that.
        let ack_ssrc = call::LayerId::Video0.to_ssrc(demux_id);

        let (srtp_master_source, server_public) = match client_public {
            SrtpMasterSourceClientPublic::DtlsFingerprint(client_fingerprint) => (
                SrtpMasterSource::DtlsHandshake {
                    client_fingerprint,
                    server_certificate_der: &self.config.server_certificate_der[..],
                    server_private_key_der: &self.config.server_private_key_der[..],
                },
                SrtpMasterSourceServerPublic::DtlsFingerprint(self.server_dtls_fingerprint),
            ),
            SrtpMasterSourceClientPublic::Dhe {
                public_key,
                hkdf_extra_info,
            } => {
                let server_secret = EphemeralSecret::new(OsRngCompatibleWithDalek);
                let server_public_key = PublicKey::from(&server_secret).to_bytes();
                let shared_secret = server_secret.diffie_hellman(&PublicKey::from(public_key));
                let mut master_key_material =
                    zeroize::Zeroizing::new([0u8; rtp::MASTER_KEY_MATERIAL_LEN]);
                Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
                    .expand_multi_info(
                        &[
                            b"Signal_Group_Call_20211105_SignallingDH_SRTPKey_KDF",
                            &hkdf_extra_info[..],
                        ],
                        master_key_material.deref_mut(),
                    )
                    .expect("Expand SRTP master key material");
                (
                    SrtpMasterSource::Value(master_key_material),
                    SrtpMasterSourceServerPublic::Dhe {
                        public_key: server_public_key,
                    },
                )
            }
        };

        let inactivity_timeout = Duration::from_secs(self.config.inactivity_timeout_secs);
        self.connection_by_id.insert(
            connection_id.clone(),
            Arc::new(Mutex::new(Connection::new(
                ice_request_username.clone(),
                ice_response_username,
                ice_pwd,
                srtp_master_source,
                ack_ssrc,
                googcc::Config {
                    initial_target_send_rate,
                    min_target_send_rate,
                    max_target_send_rate,
                },
                inactivity_timeout,
                now,
            ))),
        );
        self.connection_id_by_ice_request_username
            .insert(ice_request_username, connection_id);
        // Entries are inserted into self.connection_id_by_address as we received ICE binding

        Ok(server_public)
    }

    /// Remove a client from a call.
    pub fn remove_client_from_call(&mut self, now: Instant, call_id: CallId, demux_id: DemuxId) {
        let loggable_call_id = LoggableCallId::from(&call_id);
        let connection_id = ConnectionId::from_call_id_and_demux_id(call_id, demux_id);

        trace!("remove_client_from_call():");
        trace!("  call_id: {}", loggable_call_id);
        trace!("  demux_id: {:?}", demux_id);

        if let Some(call) = self.call_by_call_id.get(&connection_id.call_id) {
            info!(
                "call_id: {} removing demux_id: {}",
                loggable_call_id,
                demux_id.as_u32()
            );

            let mut call = call.lock();
            call.remove_client(demux_id, now);
        }

        if let Some(connection) = self.connection_by_id.remove(&connection_id) {
            let connection = connection.lock();
            self.connection_id_by_ice_request_username
                .remove(connection.ice_request_username());
            // Entries are removed from self.connection_id_by_address over time in tick().
        }
    }

    fn get_connection_from_id(
        &self,
        connection_id: &ConnectionId,
    ) -> Option<Arc<Mutex<Connection>>> {
        let connection = self.connection_by_id.get(connection_id)?;
        Some(Arc::clone(connection))
    }

    fn get_connection_from_address(
        &self,
        address: &SocketAddr,
    ) -> Result<(ConnectionId, Arc<Mutex<Connection>>), SfuError> {
        let connection_id = self
            .connection_id_by_address
            .get(address)
            .ok_or(SfuError::UnknownAddress(*address))?;
        let connection = self.connection_by_id.get(connection_id).ok_or_else(|| {
            SfuError::MissingConnection(connection_id.call_id.clone(), connection_id.demux_id)
        })?;
        Ok((connection_id.clone(), Arc::clone(connection)))
    }

    fn get_connection_from_ice_request_username(
        &self,
        ice_request_username: &[u8],
    ) -> Result<(ConnectionId, Arc<Mutex<Connection>>), SfuError> {
        let connection_id = self
            .connection_id_by_ice_request_username
            .get(ice_request_username)
            .ok_or_else(|| {
                SfuError::IceBindingRequestUnknownUsername(ice_request_username.to_vec())
            })?;
        let connection = self.connection_by_id.get(connection_id).ok_or_else(|| {
            SfuError::MissingConnection(connection_id.call_id.clone(), connection_id.demux_id)
        })?;
        Ok((connection_id.clone(), Arc::clone(connection)))
    }

    fn get_call_from_id(&self, call_id: &CallId) -> Result<Arc<Mutex<Call>>, SfuError> {
        let call = self
            .call_by_call_id
            .get(call_id)
            .ok_or_else(|| SfuError::MissingCall(call_id.clone()))?;
        Ok(Arc::clone(call))
    }

    pub fn handle_packet(
        sfu: &Mutex<Self>,
        sender_addr: SocketAddr,
        incoming_packet: &mut [u8],
    ) -> Result<Vec<(PacketToSend, SocketAddr)>, SfuError> {
        trace!("handle_packet():");

        // RTP should go first because it's by far the most common.
        if rtp::looks_like_rtp(incoming_packet) {
            trace!("looks like rtp");
            time_scope_us!("calling.sfu.handle_packet.rtp");

            let (incoming_connection_id, incoming_rtp) = {
                let (incoming_connection_id, incoming_connection) =
                    sfu.lock().get_connection_from_address(&sender_addr)?;
                let mut incoming_connection = incoming_connection.lock();
                time_scope_us!("calling.sfu.handle_packet.rtp.in_incoming_connection_lock");
                let incoming_rtp = incoming_connection
                    .handle_rtp_packet(incoming_packet, Instant::now())
                    .map_err(SfuError::ConnectionError)?;
                (incoming_connection_id, incoming_rtp)
            };

            trace!("rtp packet:");
            trace!("  sender_addr: {}", sender_addr);
            trace!("  sender demux ID: {:?}", incoming_connection_id.demux_id);
            trace!("  ssrc: {}", incoming_rtp.ssrc());
            trace!("  seqnum: {}", incoming_rtp.seqnum());

            let outgoing_rtp = {
                let call = sfu
                    .lock()
                    .get_call_from_id(&incoming_connection_id.call_id)?;
                let mut call = call.lock();
                time_scope_us!("calling.sfu.handle_packet.rtp.in_call_lock");
                call.handle_rtp(
                    incoming_connection_id.demux_id,
                    incoming_rtp,
                    Instant::now(),
                )
                .map_err(SfuError::CallError)?
            };

            let mut packets_to_send = vec![];
            // We use one mutable outgoing ConnectionId to avoid cloning the CallId many times.
            let mut outgoing_connection_id = incoming_connection_id;
            for (demux_id, outgoing_rtp) in outgoing_rtp {
                outgoing_connection_id.demux_id = demux_id;
                if let Some(outgoing_connection) =
                    sfu.lock().get_connection_from_id(&outgoing_connection_id)
                {
                    let mut outgoing_connection = outgoing_connection.lock();
                    time_scope_us!("calling.sfu.handle_packet.rtp.in_outgoing_connection_lock");
                    outgoing_connection.send_rtp(
                        outgoing_rtp,
                        &mut packets_to_send,
                        Instant::now(),
                    );
                }
            }

            return Ok(packets_to_send);
        }

        if rtp::looks_like_rtcp(incoming_packet) {
            trace!("looks like rtcp");
            time_scope_us!("calling.sfu.handle_packet.rtcp");

            let (
                incoming_connection_id,
                HandleRtcpResult {
                    incoming_key_frame_requests,
                    outgoing_rtx,
                    new_target_send_rate,
                },
            ) = {
                let (incoming_connection_id, incoming_connection) =
                    sfu.lock().get_connection_from_address(&sender_addr)?;
                let mut incoming_connection = incoming_connection.lock();

                time_scope_us!("calling.sfu.handle_packet.rtcp.in_incomin_connection_lock");
                let result = incoming_connection
                    .handle_rtcp_packet(incoming_packet, Instant::now())
                    .map_err(SfuError::ConnectionError)?;
                (incoming_connection_id, result)
            };

            let outgoing_key_frame_requests = {
                let call = sfu
                    .lock()
                    .get_call_from_id(&incoming_connection_id.call_id)?;
                let mut call = call.lock();
                time_scope_us!("calling.sfu.handle_packet.rtcp.in_call_lock");

                if let Some(new_target_send_rate) = new_target_send_rate {
                    if let Err(err) = call
                        .set_target_send_rate(incoming_connection_id.demux_id, new_target_send_rate)
                    {
                        debug!("Failed to set target send rate: {:?}", err);
                    }
                }
                call.handle_key_frame_requests(
                    incoming_connection_id.demux_id,
                    &incoming_key_frame_requests,
                    Instant::now(),
                )
            };

            let mut outgoing_packets = outgoing_rtx;
            // We use one mutable outgoing ConnectionId to avoid cloning the CallId many times.
            let mut outgoing_connection_id = incoming_connection_id;

            for (demux_id, key_frame_request) in outgoing_key_frame_requests {
                outgoing_connection_id.demux_id = demux_id;
                if let Some(outgoing_connection) =
                    sfu.lock().get_connection_from_id(&outgoing_connection_id)
                {
                    let mut outgoing_connection = outgoing_connection.lock();

                    time_scope_us!("calling.sfu.handle_packet.rtcp.in_outgoing_connection_lock");

                    if let Some(key_frame_request) =
                        outgoing_connection.send_key_frame_request(key_frame_request)
                    {
                        outgoing_packets.push(key_frame_request);
                    };
                }
            }

            return Ok(outgoing_packets);
        }

        // When we get a valid ICE check, send back a check response and update the
        // outgoing address for the client.
        if BindingRequest::looks_like_header(incoming_packet) {
            trace!("looks like ice binding request");
            time_scope_us!("calling.sfu.handle_packet.ice");

            let ice_binding_request =
                BindingRequest::parse(incoming_packet).map_err(SfuError::ParseIceBindingRequest)?;

            let (incoming_connection_id, outgoing_response) = {
                let (incoming_connection_id, incoming_connection) = sfu
                    .lock()
                    .get_connection_from_ice_request_username(ice_binding_request.username())?;
                let mut incoming_connection = incoming_connection.lock();
                time_scope_us!("calling.sfu.handle_packet.ice.in_locks");
                let outgoing_response = incoming_connection
                    .handle_ice_binding_request(sender_addr, ice_binding_request, Instant::now())
                    .map_err(SfuError::ConnectionError)?;
                (incoming_connection_id, outgoing_response)
            };

            // Removal of old addresses is done in tick().
            sfu.lock()
                .connection_id_by_address
                .insert_without_removing_old(sender_addr, incoming_connection_id);

            return Ok(vec![(outgoing_response, sender_addr)]);
        }

        // When we get a DTLS packet, process it as part of the DTLS handshake.
        // Once the handshake completes, use the DTLS-SRTP master key.
        if dtls::looks_like_packet(incoming_packet) {
            trace!("looks like dtls");
            time_scope_us!("calling.sfu.handle_packet.dtls");

            let outgoing_response = {
                let (_incoming_connection_id, incoming_connection) =
                    sfu.lock().get_connection_from_address(&sender_addr)?;
                let mut incoming_connection = incoming_connection.lock();

                time_scope_us!("calling.sfu.handle_packet.dtls.in_locks");

                incoming_connection.handle_dtls_packet(
                    incoming_packet,
                    Instant::now(),
                    SystemTime::now(),
                    &mut OsRng,
                )
            };

            if let Some(outgoing_response) = outgoing_response {
                trace!("  pushing dtls response to send");
                return Ok(vec![(outgoing_response, sender_addr)]);
            } else {
                return Ok(vec![]);
            }
        }

        Err(SfuError::UnknownPacketType(sender_addr))
    }

    /// Handle the periodic tick, which could be fired every 100ms in production.
    /// For every tick, we need to iterate all calls, with the goal of iterating
    /// only once. Since we need to sometimes remove clients or calls, we will
    /// generally iterate with retain().
    pub fn tick(&mut self, now: Instant) -> TickOutput {
        time_scope_us!("calling.sfu.tick");
        let config = self.config;
        let mut packets_to_send: Vec<(PacketToSend, SocketAddr)> = vec![];

        // Post diagnostics to the log if needed.
        if let Some(diagnostics_interval_secs) = config.diagnostics_interval_secs {
            if now >= self.diagnostics_logged + Duration::from_secs(diagnostics_interval_secs) {
                time_scope_us!("calling.sfu.tick.diagnostics");
                self.diagnostics_logged = now;

                // Keep a string buffer we can reuse for posting diagnostic logs.
                let mut diagnostic_string: String = String::with_capacity(3072);

                for call in self.call_by_call_id.values() {
                    let call = call.lock();
                    let stats = call.get_stats();
                    if !stats.clients.is_empty() {
                        diagnostic_string.clear();
                        let _ = write!(diagnostic_string, "call_id: {}", stats.loggable_call_id);

                        for client in stats.clients {
                            let _ = write!(diagnostic_string, " {{ demux_id: {}, incoming_heights: ({}, {}, {}), incoming_rates: ({}, {}, {}), target: {}, requested_base: {}, ideal: {}, allocated: {}, padding: {}, max_requested_height: {} }}",
                                  client.demux_id.as_u32(),
                                  client.video0_incoming_height.unwrap_or_default().as_u16(),
                                  client.video1_incoming_height.unwrap_or_default().as_u16(),
                                  client.video2_incoming_height.unwrap_or_default().as_u16(),
                                  client.video0_incoming_rate.unwrap_or_default().as_kbps(),
                                  client.video1_incoming_rate.unwrap_or_default().as_kbps(),
                                  client.video2_incoming_rate.unwrap_or_default().as_kbps(),
                                  client.requested_base_rate.as_kbps(),
                                  client.target_send_rate.as_kbps(),
                                  client.ideal_send_rate.as_kbps(),
                                  client.allocated_send_rate.as_kbps(),
                                  client.padding_send_rate.as_kbps(),
                                  client.max_requested_height.unwrap_or_default().as_u16(),
                            );
                        }

                        info!("{}", diagnostic_string);
                    }
                }
            }
        }

        // Set a flag if we need to check for inactivity while we iterate.
        let check_for_inactivity = if now
            >= self.activity_checked + Duration::from_secs(config.inactivity_check_interval_secs)
        {
            trace!("tick: checking for inactivity");
            self.activity_checked = now;
            true
        } else {
            false
        };

        // Borrow this explicitly so that we can modify it at the same time as self.call_by_call_id.
        let connection_id_by_ice_request_username = &mut self.connection_id_by_ice_request_username;

        let remove_inactive_calls_timer = start_timer_us!("calling.sfu.tick.remove_inactive_calls");

        let mut expired_demux_ids_by_call_id: HashMap<CallId, Vec<DemuxId>> = HashMap::new();
        self.connection_by_id.retain(|connection_id, connection| {
            let mut connection = connection.lock();
            if check_for_inactivity && connection.inactive(now) {
                info!("dropping connection: {}", connection_id);

                connection_id_by_ice_request_username
                    .remove_entry(connection.ice_request_username());

                // Addresses in sfu.client_by_address will get aged out
                // by self.client_by_address.remove_old() below.
                // and don't need to be removed here.

                expired_demux_ids_by_call_id
                    .entry(connection_id.call_id.clone())
                    .or_default()
                    .push(connection_id.demux_id);
                false
            } else {
                // Don't remove the connection; it's still active!
                connection.tick(&mut packets_to_send, now);
                true
            }
        });

        let mut call_tick_results = vec![];
        // Iterate all calls, maybe dropping some that are inactive.
        self.call_by_call_id.retain(|call_id, call| {
            let mut call = call.lock();

            if let Some(expired_demux_ids) = expired_demux_ids_by_call_id.get(call_id) {
                for expired_demux_id in expired_demux_ids {
                    call.remove_client(*expired_demux_id, now);
                }
            }

            if call.is_empty() {
                // If the call is empty there is nothing to send out.
                if now
                    >= call.client_added_or_removed()
                        + Duration::from_secs(config.inactivity_timeout_secs)
                {
                    // If the call hasn't had any activity recently, remove it.
                    info!("call_id: {} removed", call.loggable_call_id());
                    false
                } else {
                    // Keep the call around for a while longer.
                    true
                }
            } else {
                // Don't remove the call; there are still clients!
                let (outgoing_rtp, outgoing_key_frame_requests) = call.tick(now);
                let send_rate_allocation_infos =
                    call.get_send_rate_allocation_info().collect::<Vec<_>>();

                call_tick_results.push((
                    call_id.clone(),
                    outgoing_rtp,
                    outgoing_key_frame_requests,
                    send_rate_allocation_infos,
                ));
                true
            }
        });
        remove_inactive_calls_timer.stop();

        for (call_id, outgoing_rtp, outgoing_key_frame_requests, send_rate_allocation_infos) in
            call_tick_results
        {
            // We make one mutable outgoing ConnectionId to avoid cloning the CallId many times.
            let mut outgoing_connection_id = ConnectionId::from_call_id_and_demux_id(
                call_id.clone(),
                0u32.try_into().expect("0 is a valid demux ID"),
            );

            // Change the padding send rate and maybe reset the congestion controller of each connection
            // based on info after the Call.tick().
            for send_rate_allocation_info in send_rate_allocation_infos {
                outgoing_connection_id.demux_id = send_rate_allocation_info.demux_id;
                if let Some(connection) = self.connection_by_id.get_mut(&outgoing_connection_id) {
                    let mut connection = connection.lock();
                    connection.set_padding_send_rate(
                        send_rate_allocation_info.padding_send_rate,
                        send_rate_allocation_info.padding_ssrc,
                    );
                    connection.send_request_to_congestion_controller(googcc::Request {
                        base: send_rate_allocation_info.requested_base_rate,
                        ideal: send_rate_allocation_info.ideal_send_rate,
                    });
                }
            }

            // Send key frame requests calculated by Call.tick().
            for (demux_id, key_frame_request) in outgoing_key_frame_requests {
                outgoing_connection_id.demux_id = demux_id;
                if let Some(outgoing_connection) =
                    self.connection_by_id.get_mut(&outgoing_connection_id)
                {
                    let mut outgoing_connection = outgoing_connection.lock();
                    if let Some(key_frame_request) =
                        outgoing_connection.send_key_frame_request(key_frame_request)
                    {
                        packets_to_send.push(key_frame_request);
                    };
                }
            }

            // Send server->client messages like active speaker updates calculated by Call.tick().
            for (demux_id, outgoing_rtp) in outgoing_rtp {
                outgoing_connection_id.demux_id = demux_id;
                if let Some(outgoing_connection) =
                    self.connection_by_id.get_mut(&outgoing_connection_id)
                {
                    let mut outgoing_connection = outgoing_connection.lock();
                    outgoing_connection.send_rtp(outgoing_rtp, &mut packets_to_send, now);
                }
            }
        }

        let expired_client_addrs = {
            time_scope_us!("calling.sfu.tick.remove_inactive_client_addresses");
            self.connection_id_by_address.remove_old(now)
        };

        TickOutput {
            packets_to_send,
            expired_client_addrs,
        }
    }
}

/// Info about a call that is relevant to call signaling.
/// See Sfu::get_call_signaling_info()
pub struct CallSignalingInfo {
    pub size: usize,
    pub created: SystemTime,
    pub creator_id: UserId,
    pub client_ids: Vec<(DemuxId, String)>,
}

struct OsRngCompatibleWithDalek;

impl rand_core5::RngCore for OsRngCompatibleWithDalek {
    fn next_u32(&mut self) -> u32 {
        rand_core::RngCore::next_u32(&mut OsRng)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::RngCore::next_u64(&mut OsRng)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(&mut OsRng, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core5::Error> {
        rand_core::RngCore::try_fill_bytes(&mut OsRng, dest).map_err(rand_core5::Error::new)
    }
}

impl rand_core5::CryptoRng for OsRngCompatibleWithDalek {}

#[cfg(test)]
mod sfu_tests {
    use std::{convert::TryFrom, net::IpAddr, ops::Add, str::FromStr, sync::Arc};

    use hex::{FromHex, ToHex};
    use lazy_static::lazy_static;
    use parking_lot::Mutex;
    use rand::{thread_rng, Rng};

    use super::*;

    fn random_byte_vector(n: usize) -> Vec<u8> {
        let mut numbers: Vec<u8> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..n {
            numbers.push(rng.gen());
        }
        numbers
    }

    fn random_byte_id_vector(n: usize, id_size: usize) -> Vec<Vec<u8>> {
        let mut vector: Vec<Vec<u8>> = Vec::new();
        for _ in 0..n {
            vector.push(random_byte_vector(id_size));
        }
        vector
    }

    fn custom_config(tick_period_ms: u64, inactivity_timeout: u64) -> config::Config {
        let mut config = config::default_test_config();

        config.tick_interval_ms = tick_period_ms;
        config.inactivity_timeout_secs = inactivity_timeout;

        config
    }

    lazy_static! {
        static ref DEFAULT_CONFIG: config::Config = config::default_test_config();
    }

    fn new_sfu(now: Instant, config: &'static config::Config) -> Arc<Mutex<Sfu>> {
        Arc::new(Mutex::new(
            Sfu::new(now, config).expect("Sfu::new should be working"),
        ))
    }

    #[allow(clippy::ptr_arg)]
    fn add_test_client<'a>(
        sfu: &'a mut Sfu,
        call_id: &'a CallId,
        user_id: &'a UserId,
        demux_id: DemuxId,
        client_ice_ufrag: String,
        client_dhe_pub_key: [u8; 32],
    ) -> Result<(), SfuError> {
        // Generate ids for the client.
        let resolution_request_id = rand::thread_rng().gen::<u64>();
        let active_speaker_id = format!(
            "{}-{}",
            user_id.as_slice().encode_hex::<String>(),
            resolution_request_id
        );
        let server_ice_ufrag = ice::random_ufrag();
        let server_ice_pwd = ice::random_pwd();

        let _ = sfu.get_or_create_call_and_add_client(
            call_id.clone(),
            user_id,
            resolution_request_id,
            active_speaker_id,
            demux_id,
            server_ice_ufrag,
            server_ice_pwd,
            client_ice_ufrag,
            SrtpMasterSourceClientPublic::Dhe {
                public_key: client_dhe_pub_key,
                hkdf_extra_info: vec![],
            },
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_new_sfu() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        // Make sure elements exist correctly.
        let sfu = sfu.lock();
        assert_eq!("127.0.0.1".to_string(), sfu.config.binding_ip);
        assert_eq!(8080, sfu.config.signaling_port);
        assert_eq!(8, sfu.config.max_clients_per_call);
        assert_eq!(0, sfu.call_by_call_id.len());
    }

    #[tokio::test]
    async fn test_create_call() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        let user_id = UserId::from(random_byte_vector(32));
        let call_id = CallId::from(random_byte_vector(32));
        let demux_id = 123392u32.try_into().unwrap();

        // We add a client but won't do anything with it in this test.
        let mut sfu = sfu.lock();
        let _ = add_test_client(
            &mut sfu,
            &call_id,
            &user_id,
            demux_id,
            "1".to_string(),
            [0; 32],
        );

        assert_eq!(1, sfu.call_by_call_id.len());
        assert_eq!(1, sfu.get_call_signaling_info(call_id).unwrap().size);
    }

    fn random_user_id() -> UserId {
        UserId::from(random_byte_vector(32))
    }

    fn random_call_id() -> CallId {
        CallId::from(random_byte_vector(32))
    }

    fn random_call_ids(count: usize) -> Vec<CallId> {
        random_byte_id_vector(count, 32)
            .into_iter()
            .map(CallId::from)
            .collect()
    }

    fn random_user_ids(count: usize) -> Vec<UserId> {
        random_byte_id_vector(count, 32)
            .into_iter()
            .map(UserId::from)
            .collect()
    }

    #[tokio::test]
    async fn test_create_call_bench() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        // The same user_id can make all the calls.
        let user_id = random_user_id();

        // Create 1000 call_id's to use.
        let count = 1000;
        let call_ids = random_call_ids(count);

        // We aren't measuring lock time in this test.
        let mut sfu = sfu.lock();

        let start = Instant::now();
        for (index, call_id) in call_ids.iter().enumerate() {
            let demux_id = ((index as u32) << 4).try_into().unwrap();
            // We add a client but won't do anything with it in this test.
            let _ = add_test_client(
                &mut sfu,
                call_id,
                &user_id,
                demux_id,
                "1".to_string(),
                [0u8; 32],
            );
        }
        let end = Instant::now();

        // Make sure there were no collisions to skew results.
        assert_eq!(count, sfu.call_by_call_id.len());
        for call_id in call_ids {
            assert_eq!(1, sfu.get_call_signaling_info(call_id).unwrap().size);
        }

        println!(
            "get_or_create_group_call_and_add_client() for {} groups took {}ns",
            count,
            end.saturating_duration_since(start).as_nanos()
        );
    }

    #[tokio::test]
    async fn test_create_call_with_client() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        let user_id = random_user_id();
        let call_id = random_call_id();
        let demux_id = 123392.try_into().unwrap();

        let mut sfu = sfu.lock();
        match add_test_client(
            &mut sfu,
            &call_id,
            &user_id,
            demux_id,
            "1".to_string(),
            [0; 32],
        ) {
            Ok(_) => {
                // Expected results:
                //  - A call should have been created
                //  - A client should have been created
                //  - The client should be in all mappings

                let call_info = sfu.get_call_signaling_info(call_id).unwrap();
                assert_eq!(user_id.as_slice(), call_info.creator_id.as_slice());
                assert_eq!(1, call_info.size);
                assert_eq!(demux_id, call_info.client_ids[0].0);
                assert_eq!(1, sfu.call_by_call_id.len());
            }
            Err(err) => {
                panic!("get_or_create_call_and_add_client() failed with: {}", err);
            }
        }
    }

    #[tokio::test]
    async fn test_create_call_and_add_client_bench() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        // 1000 calls with 8 users each.
        let call_count = 1000;
        let user_count = 8;

        let user_ids = random_user_ids(user_count);
        let call_ids = random_call_ids(call_count);

        // We aren't measuring lock time in this test.
        let mut sfu = sfu.lock();

        let start = Instant::now();
        for call_id in &call_ids {
            for (index, user_id) in user_ids.iter().enumerate() {
                let demux_id = ((index as u32) << 4).try_into().unwrap();
                match add_test_client(
                    &mut sfu,
                    call_id,
                    user_id,
                    demux_id,
                    "1".to_string(),
                    [0; 32],
                ) {
                    Ok(_) => {
                        // Nothing to do here.
                    }
                    Err(err) => {
                        panic!("get_or_create_call_and_add_client() failed with: {}", err);
                    }
                }
            }
        }
        let end = Instant::now();

        // Make sure there were no collisions to skew results.
        assert_eq!(call_count, sfu.call_by_call_id.len());
        for call_id in call_ids {
            assert_eq!(
                user_count,
                sfu.get_call_signaling_info(call_id).unwrap().size
            );
        }

        println!(
            "get_or_create_call_and_add_client() for {} calls with {} users each took {}ns",
            call_count,
            user_count,
            end.saturating_duration_since(start).as_nanos()
        );
    }

    // As we create calls and add clients, keep a verbose record of them so that
    // we can iterate and cleanup as necessary.
    struct GroupRecord {
        // TODO: We'll keep copies, but maybe we should keep references
        // for better performance, but these are just tests... Maybe it
        // it will affect benchmarks if we use this there...
        call_id: CallId,
        demux_id: DemuxId,
        // TODO: Probably add ufrag/pwd so we can remove by those too.
    }

    fn setup_calls_and_clients(
        sfu: Arc<Mutex<Sfu>>,
        call_ids: &[CallId],
        user_ids: &[UserId],
    ) -> Vec<GroupRecord> {
        // Get one write lock to fill the calls and clients.
        let mut sfu = sfu.lock();

        let mut group_record: Vec<GroupRecord> = Vec::new();

        for call_id in call_ids {
            for (index, user_id) in user_ids.iter().enumerate() {
                let demux_id = ((index as u32) << 4).try_into().unwrap();
                match add_test_client(
                    &mut sfu,
                    call_id,
                    user_id,
                    demux_id,
                    "1".to_string(),
                    [0; 32],
                ) {
                    Ok(_) => {
                        group_record.push(GroupRecord {
                            call_id: call_id.clone(),
                            demux_id,
                        });
                    }
                    Err(err) => {
                        panic!("get_or_create_call_and_add_client() failed with: {}", err);
                    }
                }
            }
        }

        group_record
    }

    const TICK_PERIOD_MS: u64 = 100;
    const INACTIVITY_TIMEOUT_SECS: u64 = 30;
    lazy_static! {
        static ref CUSTOM_CONFIG: config::Config =
            custom_config(TICK_PERIOD_MS, INACTIVITY_TIMEOUT_SECS);
    }

    #[tokio::test]
    async fn test_remove_clients() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &CUSTOM_CONFIG);

        // 1000 calls with 8 users each.
        let call_ids = random_call_ids(1000);
        let user_ids = random_user_ids(8);

        let group_record = setup_calls_and_clients(sfu.clone(), &call_ids, &user_ids);

        {
            // Now get read access here and check the numbers.
            let sfu = sfu.lock();

            // Make sure there were no collisions to skew results.
            assert_eq!(call_ids.len(), sfu.call_by_call_id.len());
            for call_id in call_ids {
                assert_eq!(
                    user_ids.len(),
                    sfu.get_call_signaling_info(call_id).unwrap().size,
                );
            }
        }

        {
            // Now get write access and remove all the users.
            let mut sfu = sfu.lock();

            for record in group_record {
                sfu.remove_client_from_call(initial_now, record.call_id, record.demux_id);
            }

            // There should still be calls but no more clients.
            assert_eq!(1000, sfu.call_by_call_id.len());

            // Run the tick for (inactivity_timeout_secs * 1000) / tick_interval_ms times.
            for i in 0..((INACTIVITY_TIMEOUT_SECS * 1000) / TICK_PERIOD_MS) {
                sfu.tick(initial_now.add(Duration::from_millis((i + 1) * TICK_PERIOD_MS)));
            }

            // The calls should now be gone.
            assert_eq!(0, sfu.call_by_call_id.len());
        }
    }

    /// This version obtains a lock for every operation instead for all.
    fn setup_calls_and_clients_parallel(
        sfu: Arc<Mutex<Sfu>>,
        call_ids: &[CallId],
        user_ids: &[UserId],
    ) -> Vec<GroupRecord> {
        let mut group_record: Vec<GroupRecord> = Vec::new();

        for call_id in call_ids {
            for (index, user_id) in user_ids.iter().enumerate() {
                let demux_id = ((index as u32) << 4).try_into().unwrap();
                // Get the write lock to the sfu for this block.
                let mut sfu = sfu.lock();

                match add_test_client(
                    &mut sfu,
                    call_id,
                    user_id,
                    demux_id,
                    "1".to_string(),
                    [0; 32],
                ) {
                    Ok(_) => {
                        group_record.push(GroupRecord {
                            call_id: call_id.clone(),
                            demux_id,
                        });
                    }
                    Err(err) => {
                        panic!("get_or_create_call_and_add_client() failed with: {}", err);
                    }
                }
            }
        }

        group_record
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_parallel_operations() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        let count = 200;

        let client_a = |sfu: Arc<Mutex<Sfu>>, count: usize| async move {
            // N calls with 8 users each.
            let call_ids = random_call_ids(count);
            let user_ids = random_user_ids(8);
            let _ = setup_calls_and_clients_parallel(sfu, &call_ids, &user_ids);
        };

        let client_b = |sfu: Arc<Mutex<Sfu>>, count: usize| async move {
            // N calls with 8 users each.
            let call_ids = random_call_ids(count);
            let user_ids = random_user_ids(8);
            let _ = setup_calls_and_clients_parallel(sfu, &call_ids, &user_ids);
        };

        let _ = tokio::join!(
            tokio::spawn(client_a(sfu.clone(), count / 2)),
            tokio::spawn(client_b(sfu.clone(), count / 2)),
        );

        let sfu = sfu.lock();

        assert_eq!(count, sfu.call_by_call_id.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_parallel_operations_bench() {
        let initial_now = Instant::now();
        let sfu = new_sfu(initial_now, &DEFAULT_CONFIG);

        let count = 1000;

        let client_a = |sfu: Arc<Mutex<Sfu>>, count: usize| async move {
            // N calls with 8 users each.
            let call_ids = random_call_ids(count);
            let user_ids = random_user_ids(8);
            let _ = setup_calls_and_clients_parallel(sfu, &call_ids, &user_ids);
        };

        let client_b = |sfu: Arc<Mutex<Sfu>>, count: usize| async move {
            // N calls with 8 users each.
            let call_ids = random_call_ids(count);
            let user_ids = random_user_ids(8);
            let _ = setup_calls_and_clients_parallel(sfu, &call_ids, &user_ids);
        };

        let start = Instant::now();
        let _ = tokio::join!(
            tokio::spawn(client_a(sfu.clone(), count / 2)),
            tokio::spawn(client_b(sfu.clone(), count / 2)),
        );
        let end = Instant::now();

        let sfu = sfu.lock();

        assert_eq!(count, sfu.call_by_call_id.len());

        println!(
            "test_parallel_operations() for {} calls took {}ns",
            count,
            end.saturating_duration_since(start).as_nanos()
        );
    }

    #[tokio::test]
    async fn test_handle_packet_generic() {
        let sfu = new_sfu(Instant::now(), &DEFAULT_CONFIG);

        let mut buf = [0u8; 1500];
        let sender_addr = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 20000);

        let result = Sfu::handle_packet(&sfu, sender_addr, &mut buf);
        assert_eq!(result, Err(SfuError::UnknownPacketType(sender_addr)));
    }

    #[test]
    fn test_connection_id_logging() {
        let id =
            <Vec<u8>>::from_hex("e43483a50016ce820d362a4c3a43d426b7f48582e864bb39c47fb480e1dce066")
                .unwrap();

        let connection_id = ConnectionId {
            call_id: CallId::from(id),
            demux_id: DemuxId::try_from(123456).unwrap(),
        };

        assert_eq!(
            "call_id: e43483, demux_id: 123456",
            format!("{}", connection_id)
        );
    }
}
