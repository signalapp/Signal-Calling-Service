//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use calling_common::{DataRate, DataRateTracker, DataSize, Duration, Instant, SignalUserAgent};
use log::*;
use metrics::event;
use parking_lot::RwLock;
use thiserror::Error;

#[cfg(test)]
use crate::candidate_selector::IceCredentials;
use crate::{
    call::Call,
    candidate_selector::{self, CandidateSelector},
    config::Config,
    googcc,
    ice::{self},
    pacer::{self, Pacer},
    packet_server::{AddressType, SocketLocator},
    region::RegionRelation,
    rtp::{self, TruncatedSequenceNumber},
    sfu::ConnectionId,
};

// This is a value sent in each RTCP message that isn't used anywhere, but
// we have to pick a value.
pub const RTCP_SENDER_SSRC: rtp::Ssrc = 0;
// This is the amount of time we want to give to batching of NACKs to avoid
// sending too many due to small jitter.  And it helps avoid using too much
// CPU for no value.
// Note: as long as the tick interval is more than this value,
// this interval doesn't matter.  But we leave it anyway in case the
// tick interval ever decreases.
const NACK_CALCULATION_INTERVAL: Duration = Duration::from_millis(20);
// This is the amount of time we want to give to batching of ACKs
// to avoid sending too many packets.
// Note: as long as the tick interval is more than or equal to this value,
// this interval doesn't matter.  But we leave it anyway in case the
// tick interval ever decreases.
const ACK_CALCULATION_INTERVAL: Duration = Duration::from_millis(100);

pub const RTCP_REPORT_INTERVAL: Duration = Duration::from_secs(5);

pub type PacketToSend = Vec<u8>;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("received ICE with invalid hmac")]
    ReceivedIceWithInvalidHmac,
    #[error("received ICE with invalid username: {0:?}")]
    ReceivedIceWithInvalidUsername(Vec<u8>),
    #[error("received invalid ICE packet")]
    ReceivedInvalidIcePacket,
    #[error("received invalid RTP packet")]
    ReceivedInvalidRtp,
    #[error("received invalid RTCP packet")]
    ReceivedInvalidRtcp,
    #[error("received packet after Connection was ended")]
    ReceivedPacketWhileClosed,
    #[error("received ping response with error code")]
    ReceivedResponseWithErrorCode,
    #[error("received ping response without mapped address field")]
    ReceivedResponseWithoutMappedAddress,
    #[error("received ping response from unknown address")]
    ReceivedResponseFromUnknownAddress,
    #[error("received ping response when no transaction was outstanding")]
    ReceivedUnexpectedResponse,
    #[error("received ping response with non-matching transaction id")]
    ReceivedResponseWithInvalidTransactionId,
}

pub enum TickOutput {
    Inactive,
    Active(Vec<SocketLocator>),
}

pub struct Connection {
    inner: RwLock<ConnectionInner>,
    id: ConnectionId,
    call: Arc<Call>,
    ice_username: Vec<u8>,
    region_relation: RegionRelation,
    user_agent: SignalUserAgent,
}

pub struct CreateConnectionArgs<'a> {
    pub config: &'static Config,
    pub connection_id: &'a ConnectionId,
    pub call: Arc<Call>,
    pub ice_server_username: Vec<u8>,
    pub ice_client_username: Vec<u8>,
    pub ice_server_pwd: Vec<u8>,
    pub ice_client_pwd: Vec<u8>,
    pub srtp_master_key_material: rtp::MasterKeyMaterial,
    pub ack_ssrc: rtp::Ssrc,
    pub googcc_config: googcc::Config,
    pub region_relation: RegionRelation,
    pub user_agent: SignalUserAgent,
    pub now: Instant,
}

impl PartialEq for Connection {
    /// Two connections are equal if the inner data pointer is the same.
    fn eq(&self, other: &Self) -> bool {
        self.inner.data_ptr() == other.inner.data_ptr()
    }
}
impl Eq for Connection {}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Connection{:?}", self.id)
    }
}

impl Connection {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_candidate_selector_config(
        id: ConnectionId,
        call: Arc<Call>,
        candidate_selector_config: candidate_selector::Config,
        srtp_master_key_material: rtp::MasterKeyMaterial,
        ack_ssrc: rtp::Ssrc,
        googcc_config: googcc::Config,
        region_relation: RegionRelation,
        user_agent: SignalUserAgent,
        now: Instant,
    ) -> Self {
        let ice_username = candidate_selector_config
            .ice_credentials
            .server_username
            .clone();

        let inner = RwLock::new(ConnectionInner::with_candidate_selector_config(
            candidate_selector_config,
            srtp_master_key_material,
            ack_ssrc,
            googcc_config,
            now,
        ));

        Self {
            id,
            call,
            inner,
            ice_username,
            region_relation,
            user_agent,
        }
    }

    #[cfg(test)]
    pub fn ice_credentials(&self) -> IceCredentials {
        self.inner
            .read()
            .candidate_selector
            .ice_credentials()
            .clone()
    }

    pub fn new(args: CreateConnectionArgs) -> Self {
        let CreateConnectionArgs {
            config,
            connection_id,
            call,
            ice_server_username,
            ice_client_username,
            ice_server_pwd,
            ice_client_pwd,
            srtp_master_key_material,
            ack_ssrc,
            googcc_config,
            region_relation,
            user_agent,
            now,
        } = args;

        let ice_username = ice_server_username.clone();

        let inner = RwLock::new(ConnectionInner::new(
            config,
            ice_server_username,
            ice_client_username,
            ice_server_pwd,
            ice_client_pwd,
            srtp_master_key_material,
            ack_ssrc,
            googcc_config,
            now,
        ));

        let id = connection_id.clone();

        Self {
            inner,
            call,
            id,
            ice_username,
            region_relation,
            user_agent,
        }
    }

    #[inline(always)]
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }

    #[inline(always)]
    pub fn call(&self) -> &Arc<Call> {
        &self.call
    }

    // This is a convenience for the SFU to be able to iterate over Connections
    // and remove them from a table of username => Connection if the Connection is inactive.
    #[inline(always)]
    pub fn ice_request_username(&self) -> &[u8] {
        &self.ice_username
    }

    /// All packets except for ICE binding responses should be sent to this address,
    /// if there is one.
    #[inline(always)]
    pub fn outgoing_addr(&self) -> Option<SocketLocator> {
        self.inner.read().outgoing_addr()
    }

    #[inline(always)]
    pub fn outgoing_addr_type(&self) -> Option<AddressType> {
        self.inner.read().outgoing_addr_type()
    }

    #[inline(always)]
    pub fn all_addrs(&self) -> Vec<SocketLocator> {
        self.inner.read().all_addrs()
    }

    /// Returns true if at least one candidate was ever selected.
    pub fn had_selected_candidate(&self) -> bool {
        self.inner.read().had_selected_candidate()
    }

    #[inline(always)]
    pub fn handle_ice_binding_request(
        &self,
        sender_addr: SocketLocator,
        binding_request: ice::BindingRequest,
        now: Instant,
    ) -> Result<Vec<(PacketToSend, SocketLocator)>, Error> {
        self.inner
            .write()
            .handle_ice_binding_request(sender_addr, binding_request, now)
    }

    #[inline(always)]
    pub fn handle_ice_binding_response(
        &self,
        sender_addr: SocketLocator,
        binding_response: ice::BindingResponse,
        now: Instant,
    ) -> Result<(), Error> {
        self.inner
            .write()
            .handle_ice_binding_response(sender_addr, binding_response, now)
    }

    // This effectively overrides the DHE, which is more convenient for tests.
    #[cfg(test)]
    fn set_srtp_keys(&self, decrypt: rtp::KeysAndSalts, encrypt: rtp::KeysAndSalts, now: Instant) {
        self.inner.write().set_srtp_keys(decrypt, encrypt, now);
    }

    /// Decrypts an incoming RTP packet and returns it.
    /// Also remembers that we may need to send ACKs and NACKs
    /// at the next call to tick().
    #[inline(always)]
    pub fn handle_rtp_packet<'packet>(
        &self,
        incoming_packet: &'packet mut [u8],
        now: Instant,
    ) -> Result<Option<rtp::Packet<&'packet mut [u8]>>, Error> {
        self.inner.write().handle_rtp_packet(incoming_packet, now)
    }

    /// Decrypts an incoming RTCP packet and processes it.
    /// Returns 3 things, all or none of which could happen at once
    /// (because RTCP packets can be "compound"):
    /// 1. Key frame requests contained in the RTCP packet
    /// 2. RTX packets triggered by NACKs in the RTCP packet,
    ///    which should be sent to the Connection::outgoing_addr().
    /// 3. A new target send rate calculated from ACKs in the RTCP packet.
    #[inline(always)]
    pub fn handle_rtcp_packet(
        &self,
        incoming_packet: &mut [u8],
        now: Instant,
    ) -> Result<HandleRtcpResult, Error> {
        self.inner.write().handle_rtcp_packet(incoming_packet, now)
    }

    /// This must be called regularly (at least every 100ms, preferably more often) to
    /// keep ACKs and NACKs being sent to the client.
    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    #[inline(always)]
    pub fn tick(
        &self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> TickOutput {
        self.inner.write().tick(packets_to_send, now)
    }

    /// Encrypts the outgoing RTP.
    /// Sends nothing if there is no outgoing address.
    /// Packets may be queued instead of returned here, so make sure
    /// to call dequeue() frequently.
    #[inline(always)]
    pub fn send_or_enqueue_rtp(
        &self,
        outgoing_rtp: rtp::Packet<Vec<u8>>,
        // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use this vec of (packet, addr) for convenience.
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> Option<Instant> {
        self.inner
            .write()
            .send_or_enqueue_rtp(outgoing_rtp, packets_to_send, now)
    }

    /// Dequeues previously encrypted outgoing RTP (if possible)
    /// or generates padding (if necessary).
    #[inline(always)]
    pub fn dequeue_outgoing_rtp(
        &self,
        now: Instant,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
    ) -> (bool, Option<Instant>) {
        self.inner
            .write()
            .dequeue_outgoing_rtp(now, packets_to_send)
    }

    /// Creates an encrypted key frame request to be sent to
    /// Connection::outgoing_addr().
    /// Will return None if SRTCP encryption fails.
    // TODO: Use Result instead of Option
    #[inline(always)]
    pub fn send_key_frame_request(
        &self,
        key_frame_request: rtp::KeyFrameRequest,
        now: Instant,
        // It would make more sense to return Option<Packet>, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use (packet, addr) for convenience.
    ) -> Option<(PacketToSend, SocketLocator)> {
        self.inner
            .write()
            .send_key_frame_request(key_frame_request, now)
    }

    #[inline(always)]
    pub fn outgoing_queue_size(&self) -> DataSize {
        self.inner.read().outgoing_queue_size()
    }

    #[inline(always)]
    pub fn outgoing_queue_delay(&self, now: Instant) -> Option<Duration> {
        self.inner.read().outgoing_queue_delay(now)
    }

    #[inline(always)]
    pub fn rtp_endpoint_stats(&self, now: Instant) -> rtp::EndpointStats {
        self.inner.write().rtp_endpoint_stats(now)
    }

    #[inline(always)]
    pub fn configure_congestion_control(
        &self,
        googcc_request: googcc::Request,
        pacer_config: pacer::Config,
        now: Instant,
    ) -> Option<Instant> {
        self.inner
            .write()
            .configure_congestion_control(googcc_request, pacer_config, now)
    }

    #[inline(always)]
    pub fn rtt(&self, now: Instant) -> Duration {
        self.inner.write().rtt(now)
    }

    #[inline(always)]
    pub fn stun_rtt(&self) -> Option<Duration> {
        self.inner.read().stun_rtt()
    }

    #[inline(always)]
    pub fn rtts(&self, now: Instant) -> (Duration, Option<Duration>) {
        let mut inner = self.inner.write();
        (inner.rtt(now), inner.stun_rtt())
    }

    #[inline(always)]
    pub fn region_relation(&self) -> RegionRelation {
        self.region_relation
    }

    #[inline(always)]
    pub fn user_agent(&self) -> SignalUserAgent {
        self.user_agent
    }

    #[inline(always)]
    pub fn current_rates(&self, now: Instant) -> ConnectionRates {
        self.inner.write().current_rates(now)
    }

    /// Mark the Connection as closed
    #[inline(always)]
    pub fn close(&self) {
        self.inner.write().close()
    }

    #[inline(always)]
    pub fn remove_candidate(&self, sender_addr: SocketLocator) {
        self.inner.write().remove_candidate(sender_addr)
    }

    #[inline(always)]
    pub fn has_candidate(&self, sender_addr: SocketLocator) -> bool {
        self.inner.write().has_candidate(sender_addr)
    }
}

struct Rtp {
    // Immutable
    /// The SSRC used for sending transport-CC ACKs.
    #[cfg_attr(not(test), allow(dead_code))]
    ack_ssrc: rtp::Ssrc,

    endpoint: rtp::Endpoint,

    /// The last time ACKs were sent.
    acks_sent: Option<Instant>,

    /// The last time NACKs were sent.
    nacks_sent: Option<Instant>,

    /// The last time an RTCP Receiver Report was sent.
    rtcp_report_sent: Option<Instant>,
}

struct CongestionControl {
    controller: googcc::CongestionController,
    pacer: Pacer,
}

pub type DhePublicKey = [u8; 32];

/// The state of a connection to a client.
/// Combines the ICE and SRTP/SRTCP state.
/// Takes care of transport auth, crypto, ACKs, NACKs,
/// retransmissions, congestion control, and IP mobility.
struct ConnectionInner {
    closed: bool,
    rtp: Rtp,
    congestion_control: CongestionControl,
    candidate_selector: CandidateSelector,
    video_rate: DataRateTracker,
    audio_rate: DataRateTracker,
    rtx_rate: DataRateTracker,
    padding_rate: DataRateTracker,
    non_media_rate: DataRateTracker,
    incoming_audio_rate: DataRateTracker,
    incoming_rtx_rate: DataRateTracker,
    incoming_padding_rate: DataRateTracker,
    incoming_non_media_rate: DataRateTracker,
    incoming_discard_rate: DataRateTracker,
}

impl ConnectionInner {
    #[cfg(test)]
    pub fn with_candidate_selector_config(
        candidate_selector_config: candidate_selector::Config,
        srtp_master_key_material: rtp::MasterKeyMaterial,
        ack_ssrc: rtp::Ssrc,
        googcc_config: googcc::Config,
        now: Instant,
    ) -> Self {
        let (decrypt, encrypt) =
            rtp::KeysAndSalts::derive_client_and_server_from_master_key_material(
                &srtp_master_key_material,
            );

        let rtp_endpoint = rtp::Endpoint::new(decrypt, encrypt, now, RTCP_SENDER_SSRC, ack_ssrc);

        Self {
            closed: false,
            rtp: Rtp {
                ack_ssrc,
                endpoint: rtp_endpoint,
                acks_sent: None,
                nacks_sent: None,
                rtcp_report_sent: None,
            },
            congestion_control: CongestionControl {
                pacer: Pacer::new(pacer::Config {
                    media_send_rate: googcc_config.initial_target_send_rate,
                    padding_send_rate: googcc_config.initial_target_send_rate,
                    padding_ssrc: None,
                }),
                controller: googcc::CongestionController::new(googcc_config, now),
            },
            candidate_selector: CandidateSelector::new(now, candidate_selector_config),
            video_rate: DataRateTracker::default(),
            audio_rate: DataRateTracker::default(),
            rtx_rate: DataRateTracker::default(),
            padding_rate: DataRateTracker::default(),
            non_media_rate: DataRateTracker::default(),

            incoming_audio_rate: DataRateTracker::default(),
            incoming_rtx_rate: DataRateTracker::default(),
            incoming_padding_rate: DataRateTracker::default(),
            incoming_non_media_rate: DataRateTracker::default(),
            incoming_discard_rate: DataRateTracker::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &'static Config,
        ice_server_username: Vec<u8>,
        ice_client_username: Vec<u8>,
        ice_server_pwd: Vec<u8>,
        ice_client_pwd: Vec<u8>,
        srtp_master_key_material: rtp::MasterKeyMaterial,
        ack_ssrc: rtp::Ssrc,
        googcc_config: googcc::Config,
        now: Instant,
    ) -> Self {
        let (decrypt, encrypt) =
            rtp::KeysAndSalts::derive_client_and_server_from_master_key_material(
                &srtp_master_key_material,
            );

        let rtp_endpoint = rtp::Endpoint::new(decrypt, encrypt, now, RTCP_SENDER_SSRC, ack_ssrc);

        let candidate_selector = CandidateSelector::new(
            now,
            candidate_selector::Config {
                inactivity_timeout: Duration::from_secs(config.inactivity_timeout_secs),
                ping_period: Duration::from_millis(config.candidate_selector_options.ping_period),
                rtt_sensitivity: config.candidate_selector_options.rtt_sensitivity,
                rtt_max_penalty: config.candidate_selector_options.rtt_max_penalty,
                rtt_limit: config.candidate_selector_options.rtt_limit,
                scoring_values: candidate_selector::ScoringValues {
                    score_nominated: config.candidate_selector_options.score_nominated,
                    score_udpv4: config.candidate_selector_options.score_udpv4,
                    score_udpv6: config.candidate_selector_options.score_udpv6,
                    score_tcpv4: config.candidate_selector_options.score_tcpv4,
                    score_tcpv6: config.candidate_selector_options.score_tcpv6,
                    score_tlsv4: config.candidate_selector_options.score_tlsv4,
                    score_tlsv6: config.candidate_selector_options.score_tlsv6,
                },
                ice_credentials: candidate_selector::IceCredentials {
                    server_username: ice_server_username.clone(),
                    client_username: ice_client_username.clone(),
                    server_pwd: ice_server_pwd.clone(),
                    client_pwd: ice_client_pwd.clone(),
                },
            },
        );

        Self {
            closed: false,
            rtp: Rtp {
                ack_ssrc,
                endpoint: rtp_endpoint,
                acks_sent: None,
                nacks_sent: None,
                rtcp_report_sent: None,
            },
            congestion_control: CongestionControl {
                pacer: Pacer::new(pacer::Config {
                    media_send_rate: googcc_config.initial_target_send_rate,
                    padding_send_rate: googcc_config.initial_target_send_rate,
                    padding_ssrc: None,
                }),
                controller: googcc::CongestionController::new(googcc_config, now),
            },
            candidate_selector,
            video_rate: DataRateTracker::default(),
            audio_rate: DataRateTracker::default(),
            rtx_rate: DataRateTracker::default(),
            padding_rate: DataRateTracker::default(),
            non_media_rate: DataRateTracker::default(),
            incoming_audio_rate: DataRateTracker::default(),
            incoming_rtx_rate: DataRateTracker::default(),
            incoming_padding_rate: DataRateTracker::default(),
            incoming_non_media_rate: DataRateTracker::default(),
            incoming_discard_rate: DataRateTracker::default(),
        }
    }

    fn outgoing_addr(&self) -> Option<SocketLocator> {
        self.candidate_selector.outbound_address()
    }

    fn outgoing_addr_type(&self) -> Option<AddressType> {
        self.candidate_selector.outbound_address_type()
    }

    fn all_addrs(&self) -> Vec<SocketLocator> {
        self.candidate_selector.all_addrs()
    }

    /// Returns true if at least one candidate was ever selected.
    fn had_selected_candidate(&self) -> bool {
        self.candidate_selector.had_selected_candidate()
    }

    fn handle_ice_binding_request(
        &mut self,
        sender_addr: SocketLocator,
        binding_request: ice::BindingRequest,
        now: Instant,
    ) -> Result<Vec<(PacketToSend, SocketLocator)>, Error> {
        if self.closed {
            return Err(Error::ReceivedPacketWhileClosed);
        }

        self.push_incoming_non_media_bytes(binding_request.len(), now);

        let ice_credentials = self.candidate_selector.ice_credentials();

        binding_request
            .verify_integrity(&ice_credentials.server_pwd)
            .map_err(|e| {
                if matches!(e, ice::ParseError::HmacValidationFailure) {
                    Error::ReceivedIceWithInvalidHmac
                } else {
                    Error::ReceivedInvalidIcePacket
                }
            })?;

        // This should never happen because sfu.rs should never call us with an invalid username.
        // But defense in depth is good too.
        let username = binding_request
            .username()
            .ok_or(Error::ReceivedIceWithInvalidUsername(vec![]))?;

        if username != ice_credentials.server_username {
            return Err(Error::ReceivedIceWithInvalidUsername(username.to_vec()));
        }

        let mut packets_to_send = vec![];

        self.candidate_selector.handle_ping_request(
            &mut packets_to_send,
            binding_request,
            sender_addr,
            now,
        );

        for (packet, _) in &packets_to_send {
            self.push_outgoing_non_media_bytes(packet.len(), now);
        }

        Ok(packets_to_send)
    }

    fn handle_ice_binding_response(
        &mut self,
        sender_addr: SocketLocator,
        binding_response: ice::BindingResponse,
        now: Instant,
    ) -> Result<(), Error> {
        if self.closed {
            return Err(Error::ReceivedPacketWhileClosed);
        }

        self.push_incoming_non_media_bytes(binding_response.len(), now);

        let ice_credentials = self.candidate_selector.ice_credentials();

        binding_response
            .verify_integrity(&ice_credentials.client_pwd)
            .map_err(|e| {
                if matches!(e, ice::ParseError::HmacValidationFailure) {
                    Error::ReceivedIceWithInvalidHmac
                } else {
                    Error::ReceivedInvalidIcePacket
                }
            })?;

        self.candidate_selector
            .handle_ping_response(sender_addr, binding_response, now)
    }

    // This effectively overrides the DHE, which is more convenient for tests.
    #[cfg(test)]
    fn set_srtp_keys(
        &mut self,
        decrypt: rtp::KeysAndSalts,
        encrypt: rtp::KeysAndSalts,
        now: Instant,
    ) {
        self.rtp.endpoint =
            rtp::Endpoint::new(decrypt, encrypt, now, RTCP_SENDER_SSRC, self.rtp.ack_ssrc);
    }

    fn handle_rtp_packet<'packet>(
        &mut self,
        incoming_packet: &'packet mut [u8],
        now: Instant,
    ) -> Result<Option<rtp::Packet<&'packet mut [u8]>>, Error> {
        if self.closed {
            return Err(Error::ReceivedPacketWhileClosed);
        }

        let rtp_endpoint = &mut self.rtp.endpoint;
        let size = incoming_packet.len();
        match rtp_endpoint.receive_rtp(incoming_packet, now) {
            Some(packet) => {
                if packet.is_rtx() {
                    event!("calling.bandwidth.incoming.rtx_bytes", size);
                    self.incoming_rtx_rate.push_bytes(size, now);
                } else if packet.is_audio() {
                    event!("calling.bandwidth.incoming.audio_bytes", size);
                    self.incoming_audio_rate.push_bytes(size, now);
                } else if packet.padding_byte_count as usize >= packet.payload().len() {
                    let size = packet.size().as_bytes() as usize;
                    event!("calling.bandwidth.incoming.padding_bytes", size);
                    self.incoming_padding_rate.push_bytes(size, now);
                    return Ok(None);
                } else if !packet.is_video() {
                    self.push_incoming_non_media_bytes(size, now);
                }
                // video packet datarate tracked by layer, in call.rs;
                // includes data from original and retransmitted packets
                Ok(Some(packet))
            }
            None => {
                event!("calling.bandwidth.incoming.discard_bytes", size);
                self.incoming_discard_rate.push_bytes(size, now);
                Err(Error::ReceivedInvalidRtp)
            }
        }
    }

    fn handle_rtcp_packet(
        &mut self,
        incoming_packet: &mut [u8],
        now: Instant,
    ) -> Result<HandleRtcpResult, Error> {
        if self.closed {
            return Err(Error::ReceivedPacketWhileClosed);
        }

        self.push_incoming_non_media_bytes(incoming_packet.len(), now);

        let rtp_endpoint = &mut self.rtp.endpoint;
        let rtcp = rtp_endpoint
            .receive_rtcp(incoming_packet, now)
            .ok_or(Error::ReceivedInvalidRtcp)?;

        let new_target_send_rate = self
            .congestion_control
            .controller
            .recalculate_target_send_rate(rtcp.acks);
        // TODO: Adjust the ACK interval like WebRTC does.  Something like this:
        // ack_interval = (DataSize::from_bytes(68) / (new_target_send_rate * 0.05)).clamp(Duration::from_millis(50), Duration::from_millis(250));
        // WebRTC sends this initially every 100ms
        // and then adjusts it to between 50ms and 250ms based on the target send rate.
        // It tries to hit 5% of the target send rate and assumes an average
        // TCC feedback size of 68 bytes (including IP, UDP, SRTP, and RTCP overhead).

        let mut packets_to_send = vec![];
        let mut dequeue_time = None;
        if let Some(outgoing_addr) = self.candidate_selector.outbound_address() {
            for rtp::Nack { ssrc, seqnums } in rtcp.nacks {
                for seqnum in seqnums {
                    if let Some(rtx) = rtp_endpoint.resend_rtp(ssrc, seqnum, now) {
                        let (outgoing_rtp, new_dequeue_time) =
                            self.congestion_control.pacer.enqueue(rtx, now);
                        if let Some(outgoing_rtp) = outgoing_rtp {
                            rtp_endpoint.remember_sent(&outgoing_rtp, now);
                            let size = outgoing_rtp.size();
                            self.rtx_rate.push(size, now);
                            Self::count_outgoing_rtx(size);
                            packets_to_send.push((outgoing_rtp.into_serialized(), outgoing_addr));
                            rtp_endpoint.mark_as_sent(ssrc, seqnum);
                        }
                        // if more than one packet requests a scheduled dequeue, only the most recent time requested is scheduled
                        if new_dequeue_time.is_some() {
                            dequeue_time = new_dequeue_time;
                        }
                    } else {
                        debug!("Ignoring NACK for (SSRC, seqnum) that is either too old or invalid: ({}, {})", ssrc, seqnum);
                    }
                }
            }
        }

        Ok(HandleRtcpResult {
            incoming_key_frame_requests: rtcp.key_frame_requests,
            packets_to_send,
            dequeue_time,
            new_target_send_rate,
        })
    }

    fn candidate_selector_tick(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> Vec<SocketLocator> {
        let mut outbound_packets = vec![];
        let ret = self.candidate_selector.tick(&mut outbound_packets, now);
        outbound_packets.into_iter().for_each(|packet| {
            self.push_outgoing_non_media_bytes(packet.0.len(), now);
            packets_to_send.push(packet);
        });
        ret
    }

    fn tick(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> TickOutput {
        if self.inactive(now) {
            return TickOutput::Inactive;
        }
        self.send_acks_if_its_been_too_long(packets_to_send, now);
        self.send_nacks_if_its_been_too_long(packets_to_send, now);
        self.send_rtcp_report_if_its_been_too_long(packets_to_send, now);
        TickOutput::Active(self.candidate_selector_tick(packets_to_send, now))
    }

    fn inactive(&self, now: Instant) -> bool {
        self.closed || self.candidate_selector.inactive(now)
    }

    fn send_or_enqueue_rtp(
        &mut self,
        outgoing_rtp: rtp::Packet<Vec<u8>>,
        // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use this vec of (packet, addr) for convenience.
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let mut dequeue_time = None;
        let rtp_endpoint = &mut self.rtp.endpoint;
        if let Some(outgoing_addr) = self.candidate_selector.outbound_address() {
            if let Some(outgoing_rtp) = rtp_endpoint.send_rtp(outgoing_rtp, now) {
                if outgoing_rtp.tcc_seqnum().is_some() {
                    if !outgoing_rtp.is_video() {
                        warn!("forwarding non-video congestion controlled packet");
                    }
                    let new_outgoing_rtp;
                    (new_outgoing_rtp, dequeue_time) =
                        self.congestion_control.pacer.enqueue(outgoing_rtp, now);
                    if let Some(outgoing_rtp) = new_outgoing_rtp {
                        rtp_endpoint.remember_sent(&outgoing_rtp, now);
                        self.push_outgoing_video(outgoing_rtp.size(), now);
                        packets_to_send.push((outgoing_rtp.into_serialized(), outgoing_addr));
                    }
                } else {
                    rtp_endpoint.remember_sent_for_reports(&outgoing_rtp, now);
                    // Skip the pacer for packets that aren't congestion controlled.
                    if outgoing_rtp.is_audio() {
                        let size = outgoing_rtp.size();
                        event!(
                            "calling.bandwidth.outgoing.audio_bytes",
                            size.as_bytes() as usize
                        );
                        self.audio_rate.push(size, now);
                    } else if outgoing_rtp.is_video() {
                        warn!("forwarding video packet without congestion control");
                        self.push_outgoing_video(outgoing_rtp.size(), now);
                    } else {
                        self.push_outgoing_non_media_bytes(
                            outgoing_rtp.size().as_bytes() as usize,
                            now,
                        );
                    }
                    packets_to_send.push((outgoing_rtp.into_serialized(), outgoing_addr));
                }
            }
        } else if outgoing_rtp.tcc_seqnum().is_some() && outgoing_rtp.is_video() {
            // Queue outgoing video packets, even if there's no nominated connection.
            self.congestion_control.pacer.force_enqueue(outgoing_rtp);
        }
        dequeue_time
    }

    fn dequeue_outgoing_rtp(
        &mut self,
        now: Instant,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
    ) -> (bool, Option<Instant>) {
        if self.closed {
            return (false, None);
        }
        let rtp_endpoint = &mut self.rtp.endpoint;
        let generate_padding = |padding_ssrc| rtp_endpoint.send_padding(padding_ssrc, now);
        let outgoing_addr = match self.candidate_selector.outbound_address() {
            Some(addr) => addr,
            None => return (false, None),
        };

        let (outgoing_rtp, dequeue_time) =
            self.congestion_control.pacer.dequeue(generate_padding, now);

        if let Some(outgoing_rtp) = outgoing_rtp {
            rtp_endpoint.remember_sent(&outgoing_rtp, now);
            let size = outgoing_rtp.size();
            if outgoing_rtp.is_padding() {
                event!(
                    "calling.bandwidth.outgoing.padding_bytes",
                    size.as_bytes() as usize
                );
                self.padding_rate.push(size, now);
            } else if outgoing_rtp.is_rtx() {
                rtp_endpoint.mark_as_sent(
                    outgoing_rtp.ssrc(),
                    outgoing_rtp.seqnum() as TruncatedSequenceNumber,
                );
                self.rtx_rate.push(size, now);
                Self::count_outgoing_rtx(size);
            } else {
                if !outgoing_rtp.is_video() {
                    warn!("dequeued non-video packet");
                }
                self.push_outgoing_video(size, now);
            }

            packets_to_send.push((outgoing_rtp.into_serialized(), outgoing_addr));
            (true, dequeue_time)
        } else {
            (false, dequeue_time)
        }
    }

    fn send_key_frame_request(
        &mut self,
        key_frame_request: rtp::KeyFrameRequest,
        now: Instant,
        // It would make more sense to return Option<Packet>, since the outgoing address is fixed,
        // but that actually makes it more difficult for sfu.rs to aggregate the
        // results of calling this across many connections.
        // So we use (packet, addr) for convenience.
    ) -> Option<(PacketToSend, SocketLocator)> {
        let outgoing_addr = self.candidate_selector.outbound_address()?;
        let rtp_endpoint = &mut self.rtp.endpoint;
        let rtcp_packet = rtp_endpoint.send_pli(key_frame_request.ssrc)?;
        self.push_outgoing_non_media_bytes(rtcp_packet.len(), now);
        Some((rtcp_packet, outgoing_addr))
    }

    // TODO: Use Result instead of Option
    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    fn send_acks_if_its_been_too_long(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) {
        if let Some(acks_sent) = self.rtp.acks_sent {
            if now < acks_sent + ACK_CALCULATION_INTERVAL {
                // We sent ACKs recently. Wait to resend/recalculate them.
                return;
            }
        }

        let rtp_endpoint = &mut self.rtp.endpoint;
        if let Some(outgoing_addr) = self.candidate_selector.outbound_address() {
            let mut bytes = 0;
            for ack_packet in rtp_endpoint.send_acks() {
                bytes += ack_packet.len();
                packets_to_send.push((ack_packet, outgoing_addr));
            }
            self.push_outgoing_non_media_bytes(bytes, now);
            self.rtp.acks_sent = Some(now);
        }
    }

    // It would make more sense to return a Vec of packets, since the outgoing address is fixed,
    // but that actually makes it more difficult for sfu.rs to aggregate the
    // results of calling this across many connections.
    // So we use (packet, addr) for convenience.
    fn send_nacks_if_its_been_too_long(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) {
        // allow the client some time to queue/pace the RTX
        const RTT_GRACE_MULTIPLIER: f64 = 1.1;

        if let Some(nacks_sent) = self.rtp.nacks_sent {
            if now < nacks_sent + NACK_CALCULATION_INTERVAL {
                // We sent NACKs recently. Wait to resend/recalculate them.
                return;
            }
        }

        if let Some(outgoing_addr) = self.candidate_selector.outbound_address() {
            let rtt = self.rtt(now).mul_f64(RTT_GRACE_MULTIPLIER);
            let rtp_endpoint = &mut self.rtp.endpoint;

            let mut bytes = 0;
            for nack_packet in rtp_endpoint.send_nacks(now, rtt) {
                bytes += nack_packet.len();
                packets_to_send.push((nack_packet, outgoing_addr));
            }

            self.push_outgoing_non_media_bytes(bytes, now);
            self.rtp.nacks_sent = Some(now);
        }
    }

    fn send_rtcp_report_if_its_been_too_long(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) {
        if let Some(rtcp_report_sent) = self.rtp.rtcp_report_sent {
            if now < rtcp_report_sent + RTCP_REPORT_INTERVAL {
                // We sent a report recently. Wait to resend/recalculate it.
                return;
            }
        }

        if let Some(outgoing_addr) = self.candidate_selector.outbound_address() {
            if let Some(rtcp_report_packet) = self.rtp.endpoint.send_rtcp_report(now) {
                self.push_outgoing_non_media_bytes(rtcp_report_packet.len(), now);
                packets_to_send.push((rtcp_report_packet, outgoing_addr));
            }

            self.rtp.rtcp_report_sent = Some(now);
        }
    }

    fn outgoing_queue_size(&self) -> DataSize {
        self.congestion_control.pacer.queued_size()
    }

    fn outgoing_queue_delay(&self, now: Instant) -> Option<Duration> {
        self.congestion_control.pacer.queue_delay(now)
    }

    fn rtp_endpoint_stats(&mut self, now: Instant) -> rtp::EndpointStats {
        *(self.rtp.endpoint.update_stats(now))
    }

    fn configure_congestion_control(
        &mut self,
        googcc_request: googcc::Request,
        pacer_config: pacer::Config,
        now: Instant,
    ) -> Option<Instant> {
        self.congestion_control.controller.request(googcc_request);
        self.congestion_control.pacer.set_config(pacer_config, now)
    }

    fn rtt(&mut self, now: Instant) -> Duration {
        // Congestion Controller RTT tends to be higher and more reactive, switch when delta is large
        const RTCP_RTT_LAG_THRESHOLD: Duration = Duration::from_millis(250);

        let cc_rtt = self.congestion_control.controller.rtt();
        if let Some(rtcp_rtt) = self.rtp.endpoint.get_or_update_stats(now).rtt_estimate {
            if cc_rtt.abs_diff(rtcp_rtt) < RTCP_RTT_LAG_THRESHOLD {
                return rtcp_rtt;
            }
        }

        cc_rtt
    }

    fn stun_rtt(&self) -> Option<Duration> {
        self.candidate_selector.rtt()
    }

    fn current_rates(&mut self, now: Instant) -> ConnectionRates {
        self.video_rate.update(now);
        self.audio_rate.update(now);
        self.rtx_rate.update(now);
        self.padding_rate.update(now);
        self.non_media_rate.update(now);

        self.incoming_audio_rate.update(now);
        self.incoming_rtx_rate.update(now);
        self.incoming_padding_rate.update(now);
        self.incoming_non_media_rate.update(now);
        self.incoming_discard_rate.update(now);

        ConnectionRates {
            video_rate: self.video_rate.rate().unwrap_or(DataRate::ZERO),
            audio_rate: self.audio_rate.rate().unwrap_or(DataRate::ZERO),
            rtx_rate: self.rtx_rate.rate().unwrap_or(DataRate::ZERO),
            padding_rate: self.padding_rate.rate().unwrap_or(DataRate::ZERO),
            non_media_rate: self.non_media_rate.rate().unwrap_or(DataRate::ZERO),

            incoming_audio_rate: self.incoming_audio_rate.rate().unwrap_or(DataRate::ZERO),
            incoming_rtx_rate: self.incoming_rtx_rate.rate().unwrap_or(DataRate::ZERO),
            incoming_padding_rate: self.incoming_padding_rate.rate().unwrap_or(DataRate::ZERO),
            incoming_non_media_rate: self
                .incoming_non_media_rate
                .rate()
                .unwrap_or(DataRate::ZERO),
            incoming_discard_rate: self.incoming_discard_rate.rate().unwrap_or(DataRate::ZERO),
        }
    }

    fn push_incoming_non_media_bytes(&mut self, size: usize, now: Instant) {
        event!("calling.bandwidth.incoming.non_media_bytes", size);
        self.incoming_non_media_rate.push_bytes(size, now);
    }

    fn push_outgoing_non_media_bytes(&mut self, size: usize, now: Instant) {
        event!("calling.bandwidth.outgoing.non_media_bytes", size);
        self.non_media_rate.push_bytes(size, now);
    }

    fn push_outgoing_video(&mut self, size: DataSize, now: Instant) {
        event!(
            "calling.bandwidth.outgoing.video_bytes",
            size.as_bytes() as usize
        );
        self.video_rate.push(size, now);
    }

    fn count_outgoing_rtx(size: DataSize) {
        event!(
            "calling.bandwidth.outgoing.rtx_bytes",
            size.as_bytes() as usize
        );
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn remove_candidate(&mut self, sender_addr: SocketLocator) {
        self.candidate_selector.remove_candidate(sender_addr)
    }

    fn has_candidate(&mut self, sender_addr: SocketLocator) -> bool {
        !self.closed && self.candidate_selector.has_candidate(sender_addr)
    }
}

/// Result of Connection::handle_rtcp_packet().
/// See Connection::handle_rtcp_packet().
pub struct HandleRtcpResult {
    pub incoming_key_frame_requests: Vec<rtp::KeyFrameRequest>,
    pub packets_to_send: Vec<(PacketToSend, SocketLocator)>,
    pub dequeue_time: Option<Instant>,
    pub new_target_send_rate: Option<DataRate>,
}

#[derive(Clone, Copy, Default)]
pub struct ConnectionRates {
    pub video_rate: DataRate,
    pub audio_rate: DataRate,
    pub rtx_rate: DataRate,
    pub padding_rate: DataRate,
    pub non_media_rate: DataRate,

    pub incoming_audio_rate: DataRate,
    pub incoming_rtx_rate: DataRate,
    pub incoming_padding_rate: DataRate,
    pub incoming_non_media_rate: DataRate,
    pub incoming_discard_rate: DataRate,
}

impl ConnectionRates {
    pub const fn outgoing_rate_bps(&self) -> u64 {
        self.audio_rate.as_bps() + self.video_rate.as_bps() + self.non_media_rate.as_bps()
    }
}

#[cfg(test)]
mod connection_tests {
    use std::borrow::Borrow;

    use calling_common::{CallType, SystemTime, Writer};
    use candidate_selector::ScoringValues;
    use rtp::new_srtp_keys;

    use super::{Error::*, *};
    use crate::{
        call::CreateCallArgs,
        sfu::{CallId, UserId},
        transportcc as tcc,
    };

    fn new_call(
        call_id: &[u8],
        now: Instant,
        created: SystemTime,
        new_clients_require_approval: bool,
    ) -> Call {
        let creator_id = UserId::from("creator_id".to_string());
        let initial_target_send_rate = DataRate::from_kbps(600);
        let default_requested_max_send_rate = DataRate::from_kbps(20000);
        Call::new(CreateCallArgs {
            call_id: CallId::from(call_id.to_vec()),
            room_id: None,
            creator_id,
            new_clients_require_approval,
            call_type: CallType::GroupV2,
            now,
            created,
            approved_users: None,
            approved_users_persistence_url: None,
            initial_target_send_rate,
            default_requested_max_send_rate,
            persist_approval_for_all_users_who_join: false,
            endorsement_issuer: None,
            drop_fragmentable_updates: false,
        })
    }

    fn new_connection(now: Instant) -> Connection {
        let ice_server_username = b"server:client";
        let ice_client_username = b"client:server";
        let ice_server_pwd = b"the_pwd_should_be_long";
        let ice_client_pwd = b"some_client_pwd";
        let ack_ssrc = 0xACC;
        let googcc_config = googcc::Config {
            initial_target_send_rate: DataRate::from_kbps(500),
            ..Default::default()
        };
        let candidate_selector_config = candidate_selector::Config {
            inactivity_timeout: Duration::from_secs(30),
            ping_period: Duration::from_millis(1000),
            rtt_sensitivity: 0.2,
            rtt_max_penalty: 2000.0,
            rtt_limit: 200.0,
            scoring_values: ScoringValues {
                score_nominated: 1000,
                score_udpv4: 500,
                score_udpv6: 600,
                score_tcpv4: 250,
                score_tcpv6: 300,
                score_tlsv4: 200,
                score_tlsv6: 300,
            },
            ice_credentials: candidate_selector::IceCredentials {
                server_username: ice_server_username.to_vec(),
                client_username: ice_client_username.to_vec(),
                server_pwd: ice_server_pwd.to_vec(),
                client_pwd: ice_client_pwd.to_vec(),
            },
        };
        let call = Arc::new(new_call(b"dummy-call-id", now, SystemTime::now(), false));
        Connection::with_candidate_selector_config(
            ConnectionId::null(),
            call,
            candidate_selector_config,
            zeroize::Zeroizing::new([0u8; 56]),
            ack_ssrc,
            googcc_config,
            RegionRelation::Unknown,
            SignalUserAgent::Unknown,
            now,
        )
    }

    fn handle_ice_binding_request(
        connection: &Connection,
        client_addr: SocketLocator,
        transaction_id: u128,
        nominated: bool,
        now: Instant,
    ) -> Vec<(PacketToSend, SocketLocator)> {
        let ice_credentials = connection.ice_credentials();
        let request_packet = {
            if nominated {
                ice::StunPacketBuilder::new_binding_request(&transaction_id.into())
                    .set_username(&ice_credentials.server_username)
                    .set_nomination()
                    .build(&ice_credentials.server_pwd)
            } else {
                ice::StunPacketBuilder::new_binding_request(&transaction_id.into())
                    .set_username(&ice_credentials.server_username)
                    .build(&ice_credentials.server_pwd)
            }
        };
        connection
            .handle_ice_binding_request(
                client_addr,
                ice::BindingRequest::from_buffer_without_sanity_check(&request_packet),
                now,
            )
            .expect("ice binding request handled")
    }

    fn establish_outbound_address(connection: &Connection, addr: SocketLocator, now: Instant) {
        let ice_credentials = connection.ice_credentials();
        let packets = handle_ice_binding_request(connection, addr, 1u128, true, now);
        let mut binding_response_sent = false;
        packets.into_iter().for_each(|(packet, addr)| {
            let packet = &packet;
            if let Some(req) = ice::BindingRequest::try_from_buffer(packet).expect("sane") {
                let buffer = ice::StunPacketBuilder::new_binding_response(&req.transaction_id())
                    .set_xor_mapped_address(&"203.0.113.1:10".parse().unwrap())
                    .build(&ice_credentials.client_pwd);
                let res = ice::BindingResponse::from_buffer_without_sanity_check(&buffer);
                connection
                    .handle_ice_binding_response(addr, res, now)
                    .expect("ice binding response handled");
                binding_response_sent = true;
            }
        });
        assert!(binding_response_sent);
    }

    fn new_encrypted_rtp(
        seqnum: rtp::FullSequenceNumber,
        tcc_seqnum: Option<tcc::FullSequenceNumber>,
        encrypt: &rtp::KeysAndSalts,
        now: Instant,
    ) -> rtp::Packet<Vec<u8>> {
        let ssrc = 10000;
        let timestamp = 1000;
        // Note: for this to work with the RTX/NACK tests, this has to be a "NACKable" PT.
        let pt = 108;
        let payload = b"payload";
        let mut incoming_rtp = rtp::Packet::with_empty_tag(
            pt,
            seqnum,
            timestamp,
            ssrc,
            tcc_seqnum,
            Some(now),
            payload,
        );
        incoming_rtp
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        incoming_rtp
    }

    fn new_encrypted_rtx_rtp(
        rtx_seqnum: rtp::FullSequenceNumber,
        seqnum: rtp::FullSequenceNumber,
        tcc_seqnum: Option<tcc::FullSequenceNumber>,
        encrypt: &rtp::KeysAndSalts,
        now: Instant,
    ) -> rtp::Packet<Vec<u8>> {
        // This gets bumped to 10001 in to_rtx() below.
        let ssrc = 10000;
        let timestamp = 1000;
        // Note: for this to work with the RTX/NACK tests, this has to be a "NACKable" PT.
        // This gets bumped to 118 in to_rtx() below.
        let pt = 108;
        let payload = b"payload";
        let incoming_rtp = rtp::Packet::with_empty_tag(
            pt,
            seqnum,
            timestamp,
            ssrc,
            tcc_seqnum,
            Some(now),
            payload,
        );
        let mut incoming_rtx_rtp = incoming_rtp.to_rtx(rtx_seqnum);
        incoming_rtx_rtp
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        incoming_rtx_rtp
    }

    fn decrypt_rtp<T: Borrow<[u8]>>(
        encrypted_rtp: &rtp::Packet<T>,
        decrypt: &rtp::KeysAndSalts,
    ) -> rtp::Packet<Vec<u8>> {
        let mut decrypted_rtp: rtp::Packet<Vec<u8>> = encrypted_rtp.to_owned();
        decrypted_rtp
            .decrypt_in_place(&decrypt.rtp.key, &decrypt.rtp.salt)
            .unwrap();
        decrypted_rtp
    }

    type TccAck = (tcc::FullSequenceNumber, tcc::RemoteInstant);

    fn decrypt_rtcp(
        encrypted_rtcp: &mut [u8],
        encrypt: &rtp::KeysAndSalts,
    ) -> Option<(Vec<TccAck>, Vec<rtp::Nack>)> {
        let rtcp = rtp::ControlPacket::parse_and_decrypt_in_place(
            encrypted_rtcp,
            &encrypt.rtcp.key,
            &encrypt.rtcp.salt,
        )?;
        let acks = rtcp
            .tcc_feedbacks
            .iter()
            .filter_map(|payload| tcc::read_feedback(payload, &mut 0))
            .flat_map(|(_seqnum, acks)| acks)
            .collect::<Vec<_>>();
        Some((acks, rtcp.nacks))
    }

    #[test]
    fn test_ice_request() {
        let now = Instant::now();

        let connection = new_connection(now);
        let ice_credentials = connection.ice_credentials();

        let request = ice::StunPacketBuilder::new_binding_request(&0u128.into())
            .set_nomination()
            .set_username(&ice_credentials.server_username)
            .build(&ice_credentials.server_pwd);

        let sender_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        assert!(connection
            .handle_ice_binding_request(
                sender_addr,
                ice::BindingRequest::from_buffer_without_sanity_check(&request),
                now,
            )
            .is_ok());
    }

    #[test]
    fn test_ice_request_with_bad_hmac() {
        let now = Instant::now();

        let connection = new_connection(now);
        let ice_credentials = connection.ice_credentials();

        let request = ice::StunPacketBuilder::new_binding_request(&0u128.into())
            .set_nomination()
            .set_username(&ice_credentials.server_username)
            .build(b"bad password");

        let sender_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        assert_eq!(
            connection.handle_ice_binding_request(
                sender_addr,
                ice::BindingRequest::from_buffer_without_sanity_check(&request),
                now,
            ),
            Err(Error::ReceivedIceWithInvalidHmac)
        );
    }

    #[test]
    fn test_ice_request_with_bad_username() {
        let now = Instant::now();

        let connection = new_connection(now);
        let ice_credentials = connection.ice_credentials();

        let request = ice::StunPacketBuilder::new_binding_request(&0u128.into())
            .set_nomination()
            .set_username(b"bad username")
            .build(&ice_credentials.server_pwd);

        let sender_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        assert_eq!(
            connection.handle_ice_binding_request(
                sender_addr,
                ice::BindingRequest::from_buffer_without_sanity_check(&request),
                now,
            ),
            Err(Error::ReceivedIceWithInvalidUsername(
                b"bad username".to_vec()
            ))
        );
    }

    // Solicited ice response tested in establish_outbound_address
    #[test]
    fn test_unsolicited_ice_response() {
        let now = Instant::now();

        let connection = new_connection(now);
        let ice_credentials = connection.ice_credentials();

        let response = ice::StunPacketBuilder::new_binding_response(&0u128.into())
            .set_username(&ice_credentials.server_username)
            .set_xor_mapped_address(&"203.0.113.1:1".parse().unwrap())
            .build(&ice_credentials.client_pwd);

        let sender_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        assert_eq!(
            connection.handle_ice_binding_response(
                sender_addr,
                ice::BindingResponse::from_buffer_without_sanity_check(&response),
                now,
            ),
            Err(ReceivedResponseFromUnknownAddress)
        );
    }

    #[test]
    fn test_ice_response_with_bad_hmac() {
        let now = Instant::now();

        let connection = new_connection(now);
        let ice_credentials = connection.ice_credentials();

        let request = ice::StunPacketBuilder::new_binding_response(&0u128.into())
            .set_username(&ice_credentials.server_username)
            .build(b"bad password");

        let sender_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        assert_eq!(
            connection.handle_ice_binding_response(
                sender_addr,
                ice::BindingResponse::from_buffer_without_sanity_check(&request),
                now,
            ),
            Err(Error::ReceivedIceWithInvalidHmac)
        );
    }

    #[test]
    fn test_receive_srtp() {
        let now = Instant::now();
        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);

        let encrypted_rtp = new_encrypted_rtp(1, None, &decrypt, now);
        let expected_decrypted_rtp = decrypt_rtp(&encrypted_rtp, &decrypt);
        assert_eq!(
            expected_decrypted_rtp.to_owned(),
            connection
                .handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
                .unwrap()
                .unwrap()
                .to_owned()
        );

        let encrypted_rtp = new_encrypted_rtp(2, None, &encrypt, now);
        assert_eq!(
            Err(Error::ReceivedInvalidRtp),
            connection.handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
        );

        let encrypted_rtp = new_encrypted_rtx_rtp(5, 2, None, &decrypt, now);
        let expected_decrypted_rtp = decrypt_rtp(&encrypted_rtp, &decrypt);
        assert_eq!(
            expected_decrypted_rtp.borrow().to_owned(),
            connection
                .handle_rtp_packet(&mut encrypted_rtp.into_serialized(), now)
                .unwrap()
                .unwrap()
                .to_owned()
        );
    }

    #[test]
    fn test_send_srtp() {
        let now = Instant::now();
        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt.clone(), now);

        let set_send_rate = |connection: &Connection, send_rate, now| {
            connection.configure_congestion_control(
                googcc::Request {
                    base: send_rate,
                    ideal: send_rate,
                },
                pacer::Config {
                    media_send_rate: send_rate,
                    padding_send_rate: send_rate,
                    padding_ssrc: None,
                },
                now,
            );
        };

        let encrypted_rtp = new_encrypted_rtp(2, None, &encrypt, now);
        let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);

        let mut packets_to_send = vec![];
        connection.send_or_enqueue_rtp(unencrypted_rtp.clone(), &mut packets_to_send, now);

        // Can't send yet because there is no outgoing address.
        assert_eq!(0, packets_to_send.len());

        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, now);
        // Packets without tcc seqnums skip the pacer queue and still go out even if the rate is 0.
        set_send_rate(&connection, DataRate::from_kbps(0), now);
        connection.send_or_enqueue_rtp(unencrypted_rtp, &mut packets_to_send, now);

        assert_eq!(
            vec![(encrypted_rtp.into_serialized(), client_addr)],
            packets_to_send
        );
    }

    #[test]
    fn test_send_srtp_with_padding() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let mut connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt, now);
        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, now);

        let set_padding_send_rate =
            |connection: &Connection, padding_send_rate, padding_ssrc, now| {
                connection.configure_congestion_control(
                    googcc::Request {
                        base: padding_send_rate,
                        ideal: padding_send_rate,
                    },
                    pacer::Config {
                        media_send_rate: padding_send_rate,
                        padding_send_rate,
                        padding_ssrc,
                    },
                    now,
                );
            };

        let padding_ssrc = 2000u32;
        set_padding_send_rate(
            &mut connection,
            DataRate::from_kbps(500),
            Some(padding_ssrc),
            now,
        );

        // 500kbps * 20ms = 1250 bytes, just enough for a padding packet of around 1200 bytes

        let mut packets_to_send = vec![];

        let (sent, _) = connection.dequeue_outgoing_rtp(at(20), &mut packets_to_send);
        assert!(sent, "sent padding");
        assert_eq!(1, packets_to_send.len(), "has padding");
        let (buf, _addr) = &packets_to_send[0];

        assert_eq!(1172, buf.len());
        let actual_padding_header = rtp::Header::parse(buf).unwrap();
        assert_eq!(padding_ssrc, actual_padding_header.ssrc);
        assert_eq!(99, actual_padding_header.payload_type);
        assert_eq!(1136, actual_padding_header.payload_range.len());

        // Don't send padding if the rate is 0.
        set_padding_send_rate(
            &mut connection,
            DataRate::from_kbps(0),
            Some(padding_ssrc),
            at(40),
        );

        let mut packets_to_send = vec![];
        let (sent, _) = connection.dequeue_outgoing_rtp(at(40), &mut packets_to_send);
        assert!(!sent, "sent nothing");

        assert!(packets_to_send.is_empty());

        // Don't send padding if the SSRC isn't set.
        set_padding_send_rate(&mut connection, DataRate::from_kbps(500), None, at(40));

        let mut packets_to_send = vec![];

        let (sent, _) = connection.dequeue_outgoing_rtp(at(40), &mut packets_to_send);

        assert!(!sent, "sent nothing");
        assert!(packets_to_send.is_empty());

        // Can still send some more
        set_padding_send_rate(
            &mut connection,
            DataRate::from_kbps(500),
            Some(padding_ssrc),
            at(60),
        );

        let mut packets_to_send = vec![];
        let (sent, _) = connection.dequeue_outgoing_rtp(at(60), &mut packets_to_send);

        assert!(sent, "sent padding");
        assert_eq!(1, packets_to_send.len(), "has padding");
        let (buf, _addr) = &packets_to_send[0];

        assert_eq!(1172, buf.len());
        let actual_padding_header = rtp::Header::parse(buf).unwrap();
        assert_eq!(padding_ssrc, actual_padding_header.ssrc);
        assert_eq!(99, actual_padding_header.payload_type);
        assert_eq!(1136, actual_padding_header.payload_range.len());
    }

    #[test]
    fn test_send_rtx() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);
        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, now);

        let encrypted_rtp = new_encrypted_rtp(1, None, &encrypt, at(20));
        let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
        let mut packets_to_send = vec![];
        connection.send_or_enqueue_rtp(unencrypted_rtp.clone(), &mut packets_to_send, at(20));
        assert_eq!(
            vec![(encrypted_rtp.clone().into_serialized(), client_addr)],
            packets_to_send
        );

        let mut nacks = rtp::ControlPacket::serialize_and_encrypt_nack(
            RTCP_SENDER_SSRC,
            rtp::write_nack(
                encrypted_rtp.ssrc(),
                vec![encrypted_rtp.seqnum()].into_iter(),
            ),
            1,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();
        let result = connection.handle_rtcp_packet(&mut nacks, at(30)).unwrap();
        let mut expected_rtx = unencrypted_rtp.to_rtx(1);
        expected_rtx
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        assert_eq!(
            vec![(expected_rtx.into_serialized(), client_addr)],
            result.packets_to_send
        );

        let encrypted_rtp2 = new_encrypted_rtp(2, None, &encrypt, at(40));
        let unencrypted_rtp2 = decrypt_rtp(&encrypted_rtp2, &encrypt);
        let mut packets_to_send = vec![];
        connection.send_or_enqueue_rtp(unencrypted_rtp2.clone(), &mut packets_to_send, at(40));
        assert_eq!(
            vec![(encrypted_rtp2.clone().into_serialized(), client_addr)],
            packets_to_send
        );

        // The first one is resent again, and the second one is sent for the first time.
        let mut nacks2 = rtp::ControlPacket::serialize_and_encrypt_nack(
            RTCP_SENDER_SSRC,
            rtp::write_nack(
                encrypted_rtp.ssrc(),
                vec![encrypted_rtp.seqnum(), encrypted_rtp2.seqnum()].into_iter(),
            ),
            2,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();
        let result = connection.handle_rtcp_packet(&mut nacks2, at(40)).unwrap();
        let mut expected_rtx = unencrypted_rtp.to_rtx(2);
        expected_rtx
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();
        assert_eq!(
            vec![(expected_rtx.into_serialized(), client_addr)],
            result.packets_to_send
        );

        let mut expected_rtx2 = unencrypted_rtp2.to_rtx(3);
        expected_rtx2
            .encrypt_in_place(&encrypt.rtp.key, &encrypt.rtp.salt)
            .unwrap();

        let mut packets_to_send = vec![];
        let (sent, _) = connection.dequeue_outgoing_rtp(at(60), &mut packets_to_send);

        assert!(sent, "sent padding");
        assert_eq!(1, packets_to_send.len(), "has padding");
        let (buf, addr) = &packets_to_send[0];
        assert_eq!(client_addr, *addr);
        assert_eq!(*buf, expected_rtx2.into_serialized());
    }

    #[test]
    fn test_send_acks_and_nacks() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);

        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(1, Some(101), &decrypt, at(1)).into_serialized(),
                at(1),
            )
            .unwrap()
            .unwrap();

        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(3, Some(103), &decrypt, at(3)).into_serialized(),
                at(3),
            )
            .unwrap()
            .unwrap();

        let mut packets_to_send = vec![];

        // Can't send yet because there is no outgoing address.
        connection.tick(&mut packets_to_send, at(4));
        assert_eq!(0, packets_to_send.len());

        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, at(5));
        assert_eq!(Some(client_addr), connection.outgoing_addr());

        // Now we can send ACKs, NACKs, and receiver reports.
        connection.tick(&mut packets_to_send, at(6));
        assert_eq!(3, packets_to_send.len());

        let expected_acks = vec![
            (101u64, tcc::RemoteInstant::from_millis(1)),
            (103u64, tcc::RemoteInstant::from_millis(3)),
        ];
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[0].0, &encrypt).unwrap();
        assert_eq!(client_addr, packets_to_send[0].1);
        assert_eq!(expected_acks, actual_acks);
        assert_eq!(0, actual_nacks.len());

        let expected_nacks = vec![rtp::Nack {
            ssrc: 10000,
            seqnums: vec![2],
        }];
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[1].0, &encrypt).unwrap();
        assert_eq!(client_addr, packets_to_send[1].1);
        assert_eq!(expected_nacks, actual_nacks);
        assert_eq!(0, actual_acks.len());

        // We resend NACKs but not acks or receiver reports.
        connection.tick(&mut packets_to_send, at(1000));
        assert_eq!(4, packets_to_send.len());
        assert_eq!(client_addr, packets_to_send[3].1);
        let (actual_acks, actual_nacks) =
            decrypt_rtcp(&mut packets_to_send[3].0, &encrypt).unwrap();
        assert_eq!(expected_nacks, actual_nacks);
        assert_eq!(0, actual_acks.len());

        // But once the NACKed packet is received, we stop NACKing it
        connection
            .handle_rtp_packet(
                &mut new_encrypted_rtp(2, Some(102), &decrypt, at(10002)).into_serialized(),
                at(10002),
            )
            .unwrap()
            .unwrap();
        connection.tick(&mut packets_to_send, at(1000));
        assert_eq!(4, packets_to_send.len());
    }

    #[test]
    fn test_send_key_frame_requests() {
        let now = Instant::now();

        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt, encrypt.clone(), now);
        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, now);

        let ssrc = 10;
        let (mut encrypted_rtcp, outgoing_addr) = connection
            .send_key_frame_request(rtp::KeyFrameRequest { ssrc }, now)
            .unwrap();
        let rtcp = rtp::ControlPacket::parse_and_decrypt_in_place(
            &mut encrypted_rtcp,
            &encrypt.rtcp.key,
            &encrypt.rtcp.salt,
        )
        .unwrap();

        assert_eq!(client_addr, outgoing_addr);
        assert_eq!(vec![rtp::KeyFrameRequest { ssrc }], rtcp.key_frame_requests);
    }

    #[test]
    fn test_receive_key_frame_requests() {
        let now = Instant::now();

        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt, now);

        let ssrc = 1000u32;
        let mut rtcp = rtp::ControlPacket::serialize_and_encrypt_pli(
            RTCP_SENDER_SSRC,
            ssrc,
            1,
            &decrypt.rtcp.key,
            &decrypt.rtcp.salt,
        )
        .unwrap();

        let result = connection.handle_rtcp_packet(&mut rtcp, now).unwrap();
        assert_eq!(
            vec![rtp::KeyFrameRequest { ssrc }],
            result.incoming_key_frame_requests
        );
    }

    #[test]
    fn test_receive_acks() {
        let now = Instant::now();
        let at = |ms| now + Duration::from_millis(ms);

        let connection = new_connection(now);
        let (decrypt, encrypt) = new_srtp_keys(0);
        connection.set_srtp_keys(decrypt.clone(), encrypt.clone(), now);
        let client_addr = SocketLocator::Udp("192.0.2.4:5".parse().unwrap());
        establish_outbound_address(&connection, client_addr, now);

        for seqnum in 1..=25 {
            let sent = at(10 * seqnum);
            let received = at(10 * (seqnum + 1));

            let encrypted_rtp = new_encrypted_rtp(seqnum, Some(seqnum), &encrypt, sent);
            let unencrypted_rtp = decrypt_rtp(&encrypted_rtp, &encrypt);
            connection.send_or_enqueue_rtp(unencrypted_rtp, &mut vec![], sent);

            let mut acks = rtp::ControlPacket::serialize_and_encrypt_acks(
                RTCP_SENDER_SSRC,
                tcc::write_feedback(10000, &mut 0, now, vec![(seqnum, received)].into_iter())
                    .collect::<Vec<_>>(),
                1,
                &decrypt.rtcp.key,
                &decrypt.rtcp.salt,
            )
            .unwrap();
            let result = connection.handle_rtcp_packet(&mut acks, now).unwrap();

            let expected_new_target_send_rate = match seqnum {
                3 => Some(501),
                22 => Some(502),
                23 => Some(503),
                24 => Some(504),
                25 => Some(505),
                _ => None,
            }
            .map(DataRate::from_kbps);
            assert_eq!(
                expected_new_target_send_rate, result.new_target_send_rate,
                "failed at seqnum {}",
                seqnum
            );
        }
    }
}
