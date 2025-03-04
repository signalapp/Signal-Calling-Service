//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::SocketAddr;

use calling_common::{Duration, Instant};
use log::{info, trace, warn};
use metrics::event;
use partial_default::PartialDefault;

use crate::{
    connection::PacketToSend,
    ice::{BindingRequest, BindingResponse, IceTransactionTable, StunPacketBuilder, TransactionId},
    packet_server::{AddressType, SocketLocator},
    sfu::ConnectionId,
};

// ADJUSTED_PRIORITY_MAXIMUM specifies the upper bound for the adjusted priority.
const ADJUSTED_PRIORITY_MAXIMUM: f32 = 1000.0;
// PRIORITY_ADJUSTMENT_FACTOR is used to map ICE priority values from the [0, u32::MAX]
// range to the [0, ADJUSTED_PRIORITY_MAXIMUM_RANGE].
const PRIORITY_ADJUSTMENT_FACTOR: f32 = ADJUSTED_PRIORITY_MAXIMUM / (u32::MAX as f32);
// PENALTY_LAG describes how long to wait before starting to aggressively punish high
// RTT values. The higher the value, the greater the lag. This value represents
// the highest degree of the polynomial that is used to compute the lag. Currently,
// this polynomial is simply x^L where L is the lag value. The x value is always in
// the [0, 1] range.
const PENALTY_LAG: f32 = 5.0;

// PING_RTO is the default initial RTO for pings going out over all transports. We use
// the currently estimated RTT as RTO if it is available and greater than this value.
// Otherwise, this value is used. The RTO for all subsequent retransmits, if any, is
// calculated from this value.
const PING_RTO: Duration = Duration::from_millis(500);
// The final timeout value is the product of the initial RTO and PING_RTO_RM.
const PING_RTO_RM: u32 = 16;
// Maximum number of ping retransmits before transitioning a candidate into
// the Dead state.
const PING_MAX_RETRANSMITS: u32 = 6;

#[derive(Debug)]
pub struct Config {
    pub ping_period: Duration,
    pub rtt_sensitivity: f32,
    pub rtt_max_penalty: f32,
    pub rtt_limit: f32,
    pub scoring_values: ScoringValues,
    pub ice_credentials: IceCredentials,
    pub connection_id: ConnectionId,
}

#[derive(Clone, Debug, Default)]
pub struct IceCredentials {
    /// Username expected by server in binding requests from clients.
    pub server_username: Vec<u8>,
    /// Username expected by clients in binding responses from server.
    pub client_username: Vec<u8>,
    /// Used to verify the HMAC in requests and generate HMACs in responses.
    pub server_pwd: Vec<u8>,
    /// Used to verify the HMAC in responses and generate HMACs in requests.
    pub client_pwd: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ScoringValues {
    pub score_nominated: u32,
    pub score_udpv4: u32,
    pub score_udpv6: u32,
    pub score_tcpv4: u32,
    pub score_tcpv6: u32,
    pub score_tlsv4: u32,
    pub score_tlsv6: u32,
}

impl ScoringValues {
    pub fn for_address_type(&self, address_type: AddressType) -> u32 {
        match address_type {
            AddressType::UdpV4 => self.score_udpv4,
            AddressType::UdpV6 => self.score_udpv6,
            AddressType::TcpV4 => self.score_tcpv4,
            AddressType::TcpV6 => self.score_tcpv6,
            AddressType::TlsV4 => self.score_tlsv4,
            AddressType::TlsV6 => self.score_tlsv6,
        }
    }

    pub fn for_address(&self, address: SocketLocator) -> u32 {
        self.for_address_type(address.get_address_type())
    }
}

// RTT estimator smoothes out the RTT by calculating the average RTT over a moving window over
// the measured RTT values. The parameter N specifies the maximum number values that the estimator
// can capture. It is possible to increase the sensitivity at construction time via
// the sensitivity parameter, which further limits the number of values that the estimator
// will capture.
#[derive(Debug, Clone)]
struct RttEstimatorBase<const N: usize> {
    buffer: [u32; N],
    pos: usize,
    len: usize,
    capacity: usize,
}

impl<const N: usize> RttEstimatorBase<N> {
    fn with_sensitivity(sensitivity: f32) -> Self {
        Self {
            buffer: [0; N],
            pos: 0,
            len: 0,
            capacity: ((1.0 - sensitivity).max(0.0) * N as f32).ceil() as usize,
        }
    }

    fn reset(&mut self) {
        self.len = 0;
    }

    fn rtt(&self) -> Option<Duration> {
        if self.len > 0 {
            let average = self.buffer.iter().sum::<u32>() / (self.len as u32);
            Some(Duration::from_millis(average.into()))
        } else {
            None
        }
    }

    fn push(&mut self, rtt: Duration) {
        if self.capacity > 0 {
            self.buffer[self.pos] = rtt.as_millis() as u32;
            self.pos = (self.pos + 1) % self.capacity;
            if self.len < self.capacity {
                self.len += 1;
            }
        }
    }
}

// We expect pings to go out in 0.5 to 1.5 second intervals. A value of 10 gives
// us an estimator that can provide RTT estimates over windows that span
// 5 - 15 seconds. More frequent pings may generate too much traffic.
type RttEstimator = RttEstimatorBase<10>;

#[derive(Debug, PartialEq, Clone)]
pub enum State {
    New,
    Active,
    Dead,
}

enum Action {
    SendPing(TransactionId),
    ForgetTransaction(TransactionId),
    None,
}

#[derive(Debug, Clone, PartialDefault)]
#[partial_default(bound = "")]
pub struct Candidate {
    #[partial_default(value = "SocketLocator::Udp(\"0.0.0.0:0\".parse().unwrap())")]
    address: SocketLocator,
    #[partial_default(value = "AddressType::UdpV4")]
    address_type: AddressType,
    remote_priority: u32,
    base_score: f32,
    #[partial_default(value = "Instant::now()")]
    last_update_time: Instant,
    #[partial_default(value = "RttEstimator::with_sensitivity(1.0)")]
    rtt_estimator: RttEstimator,
    #[partial_default(value = "State::New")]
    state: State,
    ping_transaction_id: Option<TransactionId>,
    #[partial_default(value = "Instant::now()")]
    ping_sent_time: Instant,
    ping_retransmit_count: u32,
    #[partial_default(value = "Instant::now()")]
    ping_next_send_time: Instant,
    #[partial_default(value = "Duration::ZERO")]
    ping_period: Duration,
    #[partial_default(value = "Duration::ZERO")]
    ping_rto: Duration,
}

impl Candidate {
    fn new(
        address: SocketLocator,
        base_score: f32,
        rtt_sensitivity: f32,
        ping_period: Duration,
        now: Instant,
    ) -> (Action, Self) {
        trace!("active candidate created: {}", address);

        let mut candidate = Self {
            ping_period,
            address,
            base_score,
            address_type: address.get_address_type(),
            rtt_estimator: RttEstimator::with_sensitivity(rtt_sensitivity),
            ..PartialDefault::partial_default()
        };

        let action = candidate.will_transmit_ping(now);

        (action, candidate)
    }

    fn for_passive_mode(address: SocketLocator) -> Self {
        Self {
            address,
            address_type: address.get_address_type(),
            state: State::Active,
            ..PartialDefault::partial_default()
        }
    }

    fn maybe_update_priority(&mut self, priority: u32) -> bool {
        if self.remote_priority != priority {
            self.remote_priority = priority;
            true
        } else {
            false
        }
    }

    fn score(&self, rtt_max_penalty: f32, rtt_limit: f32) -> f32 {
        let rtt_penalty = self.rtt_estimator.rtt().map_or(0.0, |rtt| {
            let m = (rtt.as_millis() as f32 / rtt_limit).min(1.0);
            rtt_max_penalty * m.powf(PENALTY_LAG)
        });
        let adjusted_remote_priority = (self.remote_priority as f32) * PRIORITY_ADJUSTMENT_FACTOR;
        self.base_score + adjusted_remote_priority - rtt_penalty
    }

    fn maybe_resurrect(&mut self, now: Instant) -> Action {
        match self.state {
            State::Dead => {
                trace!("{}: resurrected", self.address);
                self.state = State::New;
                self.remote_priority = 0;
                self.last_update_time = now;
                self.rtt_estimator.reset();
                self.will_transmit_ping(now)
            }
            _ => Action::None,
        }
    }

    fn will_transmit_ping(&mut self, now: Instant) -> Action {
        trace!("{}: will send ICE ping", self.address);

        let transaction_id = TransactionId::new();
        self.ping_transaction_id = Some(transaction_id.clone());
        self.ping_sent_time = now;
        self.ping_retransmit_count = 0;
        // Determine the RTO. The currently estimated RTT is used as RTO if it is
        // available and greater than the default RTO. Otherwise, the default RTO
        // is used.
        self.ping_rto = {
            if let Some(rtt) = self.rtt_estimator.rtt() {
                Duration::max(rtt, PING_RTO)
            } else {
                PING_RTO
            }
        };
        // Pre-emptively schedule a ping retransmit. If a response arrives the next
        // ping will be scheduled in its place.
        self.ping_next_send_time = now + self.ping_rto;

        Action::SendPing(transaction_id)
    }

    fn will_retransmit_ping(&mut self, now: Instant) -> Action {
        trace!("{}: will retransmit ICE ping", self.address);

        // Pre-emptively schedule a ping retransmit. If a response arrives the next
        // ping will be scheduled in its place.
        let delay = self.ping_rto
            * if self.ping_retransmit_count < PING_MAX_RETRANSMITS - 1 {
                2 << self.ping_retransmit_count
            } else {
                PING_RTO_RM
            };
        self.ping_next_send_time = now + delay;
        self.ping_retransmit_count += 1;

        Action::SendPing(
            self.ping_transaction_id
                .as_ref()
                .expect("must have transaction id")
                .clone(),
        )
    }

    fn tick(&mut self, now: Instant) -> Action {
        if matches!(self.state, State::Dead) || self.ping_next_send_time >= now {
            return Action::None;
        }

        // If there is currently no transaction we'll create a new one by creating
        // a new ping request. Otherwise, we'll either retransmit or trigger
        // a client timeout.
        if self.ping_transaction_id.is_none() {
            self.will_transmit_ping(now)
        } else if self.ping_retransmit_count == PING_MAX_RETRANSMITS {
            info!(
                "{}: timed out after {} retransmits",
                self.address, self.ping_retransmit_count
            );
            self.state = State::Dead;
            Action::ForgetTransaction(
                self.ping_transaction_id
                    .take()
                    .expect("must have transaction id"),
            )
        } else {
            // We haven't received a response yet, but we'll do an RTT update
            // in order to degrade the candidate score.
            let penalty_rtt = now.saturating_duration_since(self.ping_sent_time);
            self.rtt_estimator.push(penalty_rtt);
            self.will_retransmit_ping(now)
        }
    }

    fn maybe_handle_ping_response(&mut self, now: Instant) {
        if matches!(self.state, State::Dead) {
            return;
        }
        // Transition into the Active state if this is a response to the first ping.
        if matches!(self.state, State::New) {
            self.state = State::Active;
        }
        // The transaction is over.
        self.ping_transaction_id = None;
        self.last_update_time = now;

        // It is possible that this response is a response to a retransmit.
        // We update the RTT estimator, even though we don't know to which
        // retransmit the response belongs. In those cases, we end up degrading
        // the candidate score, which is what we want.
        let rtt = now.saturating_duration_since(self.ping_sent_time);
        self.rtt_estimator.push(rtt);
        self.ping_retransmit_count = 0;

        // Schedule the next ping send time. If we're overdue we'll schedule the ping
        // to be sent as soon as possible. By setting this to 'now' we're ensuring
        // that the ping will be sent during the upcoming tick.
        if rtt >= self.ping_period {
            self.ping_next_send_time = now
        } else {
            self.ping_next_send_time = now + self.ping_period - rtt;
        }
    }
}

#[derive(Debug)]
pub struct CandidateSelector {
    candidates: Vec<Candidate>,
    selected_candidate: Option<usize>,
    nominated_candidate: Option<usize>,
    config: Config,
}

impl CandidateSelector {
    pub fn new(config: Config) -> Self {
        let mut candidates = vec![];

        // Backward compatibility: the selector will operate in passive mode
        // if no client ICE password is provided.
        if config.ice_credentials.client_pwd.is_none() {
            event!("calling.sfu.candidate_selector.passive");
            candidates.push(Candidate::partial_default());
        }

        Self {
            candidates,
            config,
            selected_candidate: None,
            nominated_candidate: None,
        }
    }

    pub fn ice_credentials(&self) -> &IceCredentials {
        &self.config.ice_credentials
    }

    pub fn is_passive(&self) -> bool {
        self.config.ice_credentials.client_pwd.is_none()
    }

    /// Selects the most suitable candidate from the list of known candidates.
    /// The selection is based on the score calculated for each candidate,
    /// the "freshness" of candidate's information and whether the candidate is
    /// the currently selected candidate or not.
    ///
    /// Specifically, when comparing two candidates:
    ///
    ///   1. If the scores are not equal, always select the candidate with
    ///      the higher score
    ///   2. If the scores are equal and one of the candidates is
    ///      the currently selected candidate, then select that candidate
    ///   3. If the scores are equal and neither of the candidates is
    ///      the currently selected candidate then select the candidate with
    ///      the most recently updated information
    pub fn make_candidate_selection(&mut self, now: Instant) {
        // Very simple float comparison. This should work decently well for the numbers that
        // we expect to encounter here [-10000, 10000].
        fn float_eq(a: f32, b: f32) -> bool {
            (a - b).abs() < 0.05
        }

        let init_state = (None, f32::MIN, Duration::from_secs(u64::MAX));

        let nominated = self.nominated_candidate;
        let nominated_score = self.config.scoring_values.score_nominated as f32;
        let rtt_max_penalty = self.config.rtt_max_penalty;
        let rtt_limit = self.config.rtt_limit;

        let (selected, score, _) =
            self.candidates
                .iter()
                .enumerate()
                .fold(init_state, |state, (i, candidate)| {
                    if matches!(candidate.state, State::Active) {
                        let time_delta = now.saturating_duration_since(candidate.last_update_time);
                        let (_, sel_score, sel_time_delta) = state;
                        let mut score = candidate.score(rtt_max_penalty, rtt_limit);
                        if Some(i) == nominated {
                            score += nominated_score;
                        }
                        trace!("{}: score={}", candidate.address, score);
                        if score > sel_score
                            || (float_eq(score, sel_score)
                                && (Some(i) == self.selected_candidate
                                    || sel_time_delta > time_delta))
                        {
                            return (Some(i), score, time_delta);
                        }
                    }
                    state
                });

        if self.selected_candidate != selected {
            info!(
                "candidate nominated/selected: {:?}/{:?} (score={}) out of {} candidates",
                nominated.map(|i| self.candidates[i].address),
                selected.map(|i| self.candidates[i].address),
                score,
                self.candidates.len(),
            );
            self.selected_candidate = selected;
            if selected.is_none() {
                event!("calling.sfu.candidate_selector.no_output_address");
            } else {
                event!("calling.sfu.ice.outgoing_addr_switch");
            }
        }
    }

    fn get_candidate_index_from_addr(&self, address: SocketLocator) -> Option<usize> {
        self.candidates.iter().position(|c| c.address == address)
    }

    #[cfg(test)]
    pub fn candidates(&self) -> &Vec<Candidate> {
        &self.candidates
    }

    /// Returns `true` if the candidate selector is currently inactive. A candidate
    /// selector is deemed *inactive* if all of its candidates are in the Dead state.
    ///
    /// A candidate selector with no candidates is considered *active*.
    pub fn inactive(&self, _now: Instant) -> bool {
        !self
            .candidates
            .iter()
            .any(|c| !matches!(c.state, State::Dead))
    }

    fn selected_candidate(&self) -> Option<&Candidate> {
        self.selected_candidate.map(|k| &self.candidates[k])
    }

    /// Returns the address of the currently selected remote candidate, if one is available.
    pub fn outbound_address(&self) -> Option<SocketLocator> {
        self.selected_candidate().map(|c| c.address)
    }

    /// Returns the address type of the currently selected remote candidate,
    /// if one is available.
    pub fn outbound_address_type(&self) -> Option<AddressType> {
        self.selected_candidate().map(|c| c.address_type)
    }

    fn get_or_create_candidate(
        &mut self,
        source_addr: SocketLocator,
        now: Instant,
    ) -> (Action, usize) {
        if let Some(index) = self.get_candidate_index_from_addr(source_addr) {
            let action = self.candidates[index].maybe_resurrect(now);
            (action, index)
        } else {
            trace!("{}: new candidate", source_addr);
            let base_score = self.config.scoring_values.for_address(source_addr) as f32;
            let (action, candidate) = Candidate::new(
                source_addr,
                base_score,
                self.config.rtt_sensitivity,
                self.config.ping_period,
                now,
            );
            self.candidates.push(candidate);
            (action, self.candidates.len() - 1)
        }
    }

    pub fn handle_ping_request(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        request: BindingRequest,
        source_addr: SocketLocator,
        now: Instant,
    ) {
        trace!("received STUN ping from {:?}: {}", source_addr, request);

        self.send_ping_response(packets_to_send, &request, source_addr);

        if self.is_passive() {
            self.handle_ping_request_passive(request, source_addr);
        } else {
            self.handle_ping_request_default(packets_to_send, request, source_addr, now);
        }
    }

    fn handle_ping_request_passive(&mut self, request: BindingRequest, source_addr: SocketLocator) {
        if request.nominated() && self.candidates[0].address != source_addr {
            info!("candidate selected (passive): {}", source_addr);
            self.candidates[0] = Candidate::for_passive_mode(source_addr);
            self.selected_candidate = Some(0);
        }
    }

    fn handle_ping_request_default(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        request: BindingRequest,
        source_addr: SocketLocator,
        now: Instant,
    ) {
        let (action, candidate_index) = self.get_or_create_candidate(source_addr, now);

        let candidate = &mut self.candidates[candidate_index];

        Self::execute_candidate_action(
            action,
            candidate,
            &self.config.connection_id,
            &self.config.ice_credentials,
            packets_to_send,
        );

        if request.nominated() {
            trace!("nominated: {}", source_addr);
            self.nominated_candidate = Some(candidate_index);
        }

        // Perform candidate selection here, but only if candidate nomination was
        // updated or if the candidate priority was updated and the candidate is
        // still active. We don't need to run the selection process if the candidate
        // is not in the Active state as it will not be considered during
        // the selection process anyway.
        let priority = request.priority().unwrap_or_default();
        let priority_updated = candidate.maybe_update_priority(priority);
        if request.nominated() || (priority_updated && matches!(candidate.state, State::Active)) {
            self.make_candidate_selection(now);
        }
    }

    fn send_ping_response(
        &self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        request: &BindingRequest,
        source_addr: SocketLocator,
    ) {
        // TODO(emir): For transport over UDP we have the address readily available
        // to us. As for TCP/TLS, the address is buried in the underlying socket
        // servicing layer and we need to figure out a way to dig it up from there.
        // For the time being, we'll only include XOR-MAPPED-ADDRESS for UDP.
        let response = {
            let transaction_id = &request.transaction_id();
            let username = &self.config.ice_credentials.client_username;
            let password = &self.config.ice_credentials.server_pwd;
            match source_addr {
                SocketLocator::Udp(address) => {
                    let address = SocketAddr::new(address.ip().to_canonical(), address.port());
                    StunPacketBuilder::new_binding_response(transaction_id)
                        .set_username(username)
                        .set_xor_mapped_address(&address)
                        .build(password)
                }
                SocketLocator::Tcp { .. } => {
                    StunPacketBuilder::new_binding_response(transaction_id)
                        .set_username(username)
                        .build(password)
                }
            }
        };

        trace!("sending STUN response ({}): {:x?}", source_addr, response);

        packets_to_send.push((response, source_addr));
    }

    pub fn tick(&mut self, packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>, now: Instant) {
        // Nothing to do if we're in the passive mode.
        if self.is_passive() {
            return;
        }

        for candidate in &mut self.candidates {
            let action = candidate.tick(now);
            Self::execute_candidate_action(
                action,
                candidate,
                &self.config.connection_id,
                &self.config.ice_credentials,
                packets_to_send,
            );
        }

        // If the currently selected candidate transitions into the Dead state then
        // we no longer have a selected candidate.
        if let Some(selected_candidate) = self.selected_candidate() {
            if matches!(selected_candidate.state, State::Dead) {
                self.make_candidate_selection(now);
            }
        }
    }

    pub fn handle_ping_response(
        &mut self,
        source_addr: SocketLocator,
        response: BindingResponse,
        now: Instant,
    ) {
        trace!(
            "received STUN ping response from {}: {}",
            source_addr,
            response
        );

        if let Some(error_code) = response.error_code() {
            warn!("received error {} from {}", source_addr, error_code);
            return;
        }

        if response.xor_mapped_address().is_none() && response.mapped_address().is_none() {
            warn!(
                "no XOR-MAPPED-ADDRESS/MAPPED-ADDRESS in response from {}",
                source_addr
            );
            return;
        }

        if let Some(index) = self.get_candidate_index_from_addr(source_addr) {
            self.candidates[index].maybe_handle_ping_response(now);
            self.make_candidate_selection(now);
        }
    }

    fn execute_candidate_action(
        action: Action,
        candidate: &Candidate,
        connection_id: &ConnectionId,
        ice_credentials: &IceCredentials,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
    ) {
        match action {
            Action::ForgetTransaction(transaction_id) => {
                trace!("forgetting transaction {}", transaction_id);
                IceTransactionTable::remove(candidate.address, &transaction_id);
            }
            Action::SendPing(transaction_id) => {
                trace!("sending STUN ping request to {}", candidate.address);
                IceTransactionTable::put(candidate.address, &transaction_id, connection_id);
                let ice_pwd = ice_credentials
                    .client_pwd
                    .as_ref()
                    .expect("must have client ice pwd in active mode");
                let request = StunPacketBuilder::new_binding_request(&transaction_id)
                    .set_username(&ice_credentials.client_username)
                    .build(ice_pwd);
                packets_to_send.push((request, candidate.address));
            }
            Action::None => {
                // No action
            }
        }
    }
}

// A candidate selector will be dropped whenever its parent connection is dropeed. We must clear
// out any lingering transaction identifiers from the global transaction lookup table.
impl Drop for CandidateSelector {
    fn drop(&mut self) {
        trace!(
            "clearing transaction IDs for connection {}",
            self.config.connection_id
        );
        IceTransactionTable::remove_all_for_connection(&self.config.connection_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        ops::Range,
        rc::Rc,
    };

    use calling_common::{Duration, Instant};
    use rand::Rng;

    use super::{CandidateSelector, Config, RttEstimator, ScoringValues};
    use crate::{
        candidate_selector::{IceCredentials, State},
        connection::PacketToSend,
        ice::{BindingRequest, BindingResponse, StunPacketBuilder, TransactionId},
        packet_server::SocketLocator,
        sfu::ConnectionId,
    };

    fn create_candidate_selector(ping_period: Duration) -> CandidateSelector {
        let config = Config {
            ping_period,
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
            ice_credentials: IceCredentials {
                server_username: b"some ice req username".to_vec(),
                client_username: b"some ice res username".to_vec(),
                server_pwd: b"some server ice pwd".to_vec(),
                client_pwd: Some(b"some client ice pwd".to_vec()),
            },
            connection_id: ConnectionId::null(),
        };
        CandidateSelector::new(config)
    }

    fn create_passive_candidate_selector() -> CandidateSelector {
        let config = Config {
            ping_period: Duration::ZERO,
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
            ice_credentials: IceCredentials {
                server_username: b"some ice req username".to_vec(),
                client_username: b"some ice res username".to_vec(),
                server_pwd: b"some server ice pwd".to_vec(),
                client_pwd: None,
            },
            connection_id: ConnectionId::null(),
        };
        CandidateSelector::new(config)
    }

    #[derive(Debug)]
    struct SimulatedEndpoint {
        selector: Rc<RefCell<CandidateSelector>>,
        address: SocketLocator,
        rtt_range: Range<u64>,
        packet_loss_percentage: f64,
        ping_queue: VecDeque<(PacketToSend, Instant)>,
    }

    impl SimulatedEndpoint {
        fn new(
            selector: Rc<RefCell<CandidateSelector>>,
            address: SocketLocator,
            rtt_range: Range<u64>,
            packet_loss_percentage: f64,
        ) -> Self {
            Self {
                selector,
                address,
                rtt_range,
                packet_loss_percentage,
                ping_queue: VecDeque::new(),
            }
        }

        fn should_drop_packet(&self) -> bool {
            rand::thread_rng().gen_bool(self.packet_loss_percentage)
        }

        fn generate_rtt(&self) -> Duration {
            Duration::from_millis(rand::thread_rng().gen_range(self.rtt_range.clone()))
        }

        fn push(&mut self, packet: PacketToSend, now: Instant) {
            assert!(BindingRequest::looks_like_header(&packet));
            if !self.should_drop_packet() {
                let rtt = self.generate_rtt();
                self.ping_queue.push_back((packet, now + rtt));
            }
        }

        fn send_ping_request(
            &mut self,
            packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
            now: Instant,
            priority: u32,
        ) {
            let mut selector = self.selector.borrow_mut();
            let transaction_id = TransactionId::new();
            let packet = StunPacketBuilder::new_binding_request(&transaction_id)
                .set_priority(priority)
                .set_username(&selector.config.ice_credentials.server_username)
                .build(&selector.config.ice_credentials.server_pwd);
            selector.handle_ping_request(
                packets_to_send,
                BindingRequest::from_buffer_without_sanity_check(&packet),
                self.address,
                now,
            );
        }

        fn send_ping_request_with_nomination(
            &mut self,
            packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
            now: Instant,
            priority: u32,
        ) {
            let mut selector = self.selector.borrow_mut();
            let transaction_id = TransactionId::new();
            let packet = StunPacketBuilder::new_binding_request(&transaction_id)
                .set_nomination()
                .set_priority(priority)
                .set_username(&selector.config.ice_credentials.server_username)
                .build(&selector.config.ice_credentials.server_pwd);
            selector.handle_ping_request(
                packets_to_send,
                BindingRequest::from_buffer_without_sanity_check(&packet),
                self.address,
                now,
            );
        }

        fn tick(&mut self, now: Instant) {
            if let Some((_, send_time)) = self.ping_queue.front() {
                if *send_time < now {
                    let mut selector = self.selector.borrow_mut();
                    let (req, _) = self.ping_queue.pop_front().unwrap();
                    let req = BindingRequest::from_buffer_without_sanity_check(&req);
                    let transaction_id = req.transaction_id();
                    let packet = StunPacketBuilder::new_binding_response(&transaction_id)
                        .set_xor_mapped_address(&"1.1.1.1:10".parse().unwrap())
                        .build(&selector.config.ice_credentials.server_pwd);
                    selector.handle_ping_response(
                        self.address,
                        BindingResponse::from_buffer_without_sanity_check(&packet),
                        now,
                    );
                }
            }
        }
    }

    #[derive(Debug)]
    struct Simulator<'a> {
        selector: Rc<RefCell<CandidateSelector>>,
        endpoints: &'a mut Vec<SimulatedEndpoint>,
        tick_period: Duration,
    }

    impl<'a> Simulator<'a> {
        fn new(
            selector: Rc<RefCell<CandidateSelector>>,
            endpoints: &'a mut Vec<SimulatedEndpoint>,
            tick_period: Duration,
        ) -> Self {
            Self {
                selector,
                endpoints,
                tick_period,
            }
        }

        fn with_endpoint<R, F>(&mut self, address: SocketLocator, func: F) -> Option<R>
        where
            F: FnOnce(&mut SimulatedEndpoint) -> R,
        {
            self.endpoints
                .iter_mut()
                .find(|e| e.address == address)
                .map(func)
        }

        fn update_rtt(&mut self, address: SocketLocator, rtt_range: Range<u64>) {
            self.with_endpoint(address, |e| e.rtt_range = rtt_range);
        }

        fn update_packet_loss_percentage(&mut self, address: SocketLocator, percentage: f64) {
            self.with_endpoint(address, |e| e.packet_loss_percentage = percentage);
        }

        fn send_ping_request(
            &mut self,
            address: SocketLocator,
            now: Instant,
            priority: u32,
            packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        ) {
            self.with_endpoint(address, |e| {
                e.send_ping_request(packets_to_send, now, priority)
            });
        }

        fn send_ping_request_with_nomination(
            &mut self,
            address: SocketLocator,
            now: Instant,
            priority: u32,
            packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        ) {
            self.with_endpoint(address, |e| {
                e.send_ping_request_with_nomination(packets_to_send, now, priority)
            });
        }

        #[must_use]
        fn run(&mut self, how_long: Duration, now: Instant) -> Instant {
            let mut time = now;
            let mut next_selector_tick_time = now;
            let end_time = now + how_long;

            while time < end_time {
                if time >= next_selector_tick_time {
                    let mut packets = vec![];

                    self.selector.borrow_mut().tick(&mut packets, time);

                    packets.into_iter().for_each(|(p, addr)| {
                        self.with_endpoint(addr, |e| e.push(p, time));
                    });

                    next_selector_tick_time += self.tick_period;
                }

                self.endpoints.iter_mut().for_each(|e| e.tick(time));

                time += Duration::from_millis(1);
            }

            time
        }
    }

    #[test]
    fn test_rtt_estimator() {
        // Simple RNG
        fn random_range(range: Range<usize>) -> u32 {
            (range.start as f32 + (range.len() as f32 * rand::random::<f32>())) as u32
        }

        let mut rtt_estimator = RttEstimator::with_sensitivity(0.0);

        // Generate some large number samples. We will push them all into the RTT estimator. The
        // estimator is expected to take into account up to `sample_count` samples when generating
        // the estimate (which is simply an average over those samples).
        let rtts: Vec<u32> = (0..1000).map(|_| random_range(50..550)).collect();

        rtts.iter()
            .for_each(|v| rtt_estimator.push(Duration::from_millis(*v as u64)));

        let average = rtts
            .iter()
            .skip(rtts.len() - rtt_estimator.capacity)
            .sum::<u32>()
            / (rtt_estimator.capacity as u32);

        assert_eq!(
            average,
            rtt_estimator.rtt().expect("has rtt").as_millis() as u32
        );
    }

    #[test]
    fn test_selection() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));
        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send the initial ping with nomination. After this, the candidate should be
        // in the New state, but not yet selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert_eq!(selector.borrow().selected_candidate, None);

        // Run the simulator for 60 seconds.
        let _ = simulator.run(Duration::from_secs(60), time);

        // At this point, the candidate should have transitioned into the Active state.
        assert_eq!(selector.borrow().candidates().len(), 1);
        assert!(selector.borrow().selected_candidate().is_some());
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));
    }

    #[test]
    fn test_rtt_based_switchover() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8000,
        ));

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send a ping for each candidate. This first candidate gets the nomination.
        // After this, both candidates should be in the New state. No candidate
        // should be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        simulator.send_ping_request(client_addr2, time, 32, &mut packets);
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert_eq!(selector.borrow().candidates[1].state, State::New);
        assert_eq!(selector.borrow().selected_candidate, None);

        // Run the simulator for 60 seconds.
        let time = simulator.run(Duration::from_secs(60), time);

        // After this, the first candidate should be the selected candidate.
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Degrade the first candidate's RTT and run the simulator for 60 seconds.
        // The first candidate should incur a significant RTT penalty. As a consequence,
        // the second candidate should be the selected candidate, despite the fact
        // that it was not nominated.
        simulator.update_rtt(client_addr1, 180..220);
        let _ = simulator.run(Duration::from_secs(60), time);
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));
    }

    #[test]
    fn test_two_clients_with_packet_loss() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8000,
        ));

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send the initial pings. After this, both clients should be in the New
        // state, but neither of them should be the selected candidate.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        simulator.send_ping_request(client_addr2, time, 32, &mut packets);
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert_eq!(selector.borrow().candidates[1].state, State::New);
        assert_eq!(selector.borrow().selected_candidate, None);

        // Run the simulator for 60 seconds. Both candidates should transition into
        // the Active state. The first candidate should be selected since it has been
        // nominated.
        let time = simulator.run(Duration::from_secs(60), time);
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Set the packet loss to 40% for the first candidate and run the simulator
        // for another 60 seconds. The second candidate should become the selected
        // candidate, despite the first candidate having been nominated.
        simulator.update_packet_loss_percentage(client_addr1, 0.4);
        let _ = simulator.run(Duration::from_secs(60), time);
        assert_eq!(selector.borrow().candidates.len(), 2);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));
    }

    #[test]
    fn test_resurrection() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send the initial ping with nomination and run the simulator for some time.
        // We expect the candidate to transition from the New into the Active state
        // and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(32), time);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Set the packet loss for the candidate to 100% and run the simulator for 42
        // seconds. With the default parameters, this should result in the candidate
        // not responding to any pings, and therefore, timing out. There should be no
        // selected candidate, and the selector should declare itself as "inactive".
        simulator.update_packet_loss_percentage(client_addr1, 1.0);
        let time = simulator.run(Duration::from_secs(42), time);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::Dead);
        assert!(selector.borrow().selected_candidate().is_none());
        assert!(selector.borrow().inactive(time));

        // Now send another ping from the candidate. The candidate should be resurrected,
        // and, therefore, transition into the New state. No candidates should yet be
        // selected, but the selector should declare itself as "active".
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert!(selector.borrow().selected_candidate.is_none());
        assert!(!selector.borrow().inactive(time));

        // Set packet loss to 0% and run the simulator for some time. The candidate
        // should transition into the Active state and it should be selected.
        simulator.update_packet_loss_percentage(client_addr1, 0.0);
        let _ = simulator.run(Duration::from_secs(32), time);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert!(matches!(selector.borrow().selected_candidate, Some(0)));
    }

    #[test]
    fn test_passive_mode() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8001,
        ));

        let selector = Rc::new(RefCell::new(create_passive_candidate_selector()));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send a ping for the first candidate, but without a nomination. There should
        // be no selected candidate.
        simulator.send_ping_request(client_addr1, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(5), time);
        assert!(selector.borrow().selected_candidate.is_none());

        // Send a ping for the first candidate, but this time with a nomination.
        // The candidate should be in the active state and selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(5), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[0].address, client_addr1);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send another ping without a nomination, but with a different address. The current
        // selection should not change.
        simulator.send_ping_request(client_addr2, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(5), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[0].address, client_addr1);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send a ping with a nomination, but with the second address. The second address
        // should be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32, &mut packets);
        let _ = simulator.run(Duration::from_secs(5), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[0].address, client_addr2);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
    }

    #[test]
    fn test_candidate_list() {
        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8001,
        ));

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Send the initial ping for the first canddiate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second canddiate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32, &mut packets);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));
    }

    #[test]
    fn test_candidate_ordering() {
        let client_addr1 = SocketLocator::Udp("[::1]:8001".parse().unwrap());
        let client_addr2 = SocketLocator::Udp("10.0.0.1:8000".parse().unwrap());
        let client_addr3 = SocketLocator::Tcp {
            id: 0,
            is_ipv6: false,
            is_tls: false,
        };
        let client_addr4 = SocketLocator::Tcp {
            id: 1,
            is_ipv6: true,
            is_tls: false,
        };
        let client_addr5 = SocketLocator::Tcp {
            id: 2,
            is_ipv6: false,
            is_tls: true,
        };
        let client_addr6 = SocketLocator::Tcp {
            id: 3,
            is_ipv6: true,
            is_tls: true,
        };

        let selector = Rc::new(RefCell::new(create_candidate_selector(
            Duration::from_millis(1000),
        )));

        let time = Instant::now();
        let mut packets = vec![];

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr3, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr4, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr5, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr6, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(
            Rc::clone(&selector),
            &mut endpoints,
            Duration::from_millis(100),
        );

        // Register all except UDP IPv6. The selected candidate should be the second
        // candidate, the candidate with an IPv4 address.
        simulator.send_ping_request(client_addr2, time, 32, &mut packets);
        simulator.send_ping_request(client_addr3, time, 32, &mut packets);
        simulator.send_ping_request(client_addr4, time, 32, &mut packets);
        simulator.send_ping_request(client_addr5, time, 32, &mut packets);
        simulator.send_ping_request(client_addr6, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(
            selector.borrow().selected_candidate().unwrap().address,
            client_addr2
        );

        // Now, register UDP IPv6. The selected candidate should be the first candidate,
        // the candidate with an IPv6 address.
        simulator.send_ping_request(client_addr1, time, 32, &mut packets);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(
            selector.borrow().selected_candidate().unwrap().address,
            client_addr1
        );

        // Set packet loss to 100% for the first candidate. This should result in
        // the second candidate being selected.
        simulator.update_packet_loss_percentage(client_addr1, 1.0);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(
            selector.borrow().selected_candidate().unwrap().address,
            client_addr2
        );
    }
}
