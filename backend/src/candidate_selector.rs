//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::SocketAddr;

use calling_common::{Duration, Instant};
use log::{trace, warn};
use metrics::event;

use crate::{
    connection::{Error, PacketToSend},
    ice::{BindingRequest, BindingResponse, StunPacketBuilder, TransactionId},
    packet_server::{AddressType, SocketLocator},
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

// RTO for pings going out over all transports.
const PING_RTO: Duration = Duration::from_millis(500);
// The final timeout value is the product of the initial RTO and PING_RTO_RM.
const PING_RTO_RM: u32 = 16;
// Maximum number of ping retransmits before removing a candidate
const PING_MAX_RETRANSMITS: u32 = 6;

#[derive(Debug)]
pub struct Config {
    pub ping_period: Duration,
    pub rtt_sensitivity: f32,
    pub rtt_max_penalty: f32,
    pub rtt_limit: f32,
    pub inactivity_timeout: Duration,
    pub scoring_values: ScoringValues,
    pub ice_credentials: IceCredentials,
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
    pub client_pwd: Vec<u8>,
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
}

enum Action {
    SendPing(TransactionId),
    None,
    Remove,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    address: SocketLocator,
    address_type: AddressType,
    remote_priority: u32,
    base_score: f32,
    last_update_time: Instant,
    rtt_estimator: RttEstimator,
    state: State,
    ping_transaction_id: Option<TransactionId>,
    ping_sent_time: Instant,
    ping_retransmit_count: u32,
    ping_next_send_time: Instant,
    ping_period: Duration,
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
            last_update_time: now,
            state: State::New,
            remote_priority: 0,
            ping_transaction_id: None,
            ping_sent_time: now,
            ping_retransmit_count: 0,
            ping_next_send_time: now,
        };

        let action = candidate.will_transmit_ping(now);

        (action, candidate)
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

    fn will_transmit_ping(&mut self, now: Instant) -> Action {
        trace!("{}: will send ICE ping", self.address);

        let transaction_id = TransactionId::new();
        self.ping_transaction_id = Some(transaction_id.clone());
        self.ping_sent_time = now;
        self.ping_retransmit_count = 0;
        // Pre-emptively schedule a ping retransmit. If a response arrives the next
        // ping will be scheduled in its place.
        self.ping_next_send_time = now + PING_RTO;

        Action::SendPing(transaction_id)
    }

    fn will_retransmit_ping(&mut self, now: Instant) -> Action {
        trace!("{}: will retransmit ICE ping", self.address);

        // Pre-emptively schedule a ping retransmit. If a response arrives the next
        // ping will be scheduled in its place.
        let delay = PING_RTO
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
        if self.ping_next_send_time > now {
            return Action::None;
        }

        // If there is currently no transaction we'll create a new one by creating
        // a new ping request. Otherwise, we'll either retransmit or trigger
        // a client timeout.
        if self.ping_transaction_id.is_none() {
            self.will_transmit_ping(now)
        } else if self.ping_retransmit_count == PING_MAX_RETRANSMITS {
            trace!("{}: timed out", self.address);
            Action::Remove
        } else {
            // We haven't received a response yet, but we'll do an RTT update
            // in order to degrade the candidate score.
            let penalty_rtt = now.saturating_duration_since(self.ping_sent_time);
            self.rtt_estimator.push(penalty_rtt);
            self.will_retransmit_ping(now)
        }
    }

    fn maybe_handle_ping_response(
        &mut self,
        transaction_id: TransactionId,
        now: Instant,
    ) -> Result<(), Error> {
        match &self.ping_transaction_id {
            None => return Err(Error::ReceivedUnexpectedResponse),
            Some(tid) if *tid != transaction_id => {
                return Err(Error::ReceivedResponseWithInvalidTransactionId)
            }
            _ => (),
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
        Ok(())
    }
}

#[derive(Debug)]
pub struct CandidateSelector {
    inactivity_time: Instant,
    candidates: Vec<Candidate>,
    selected_candidate: Option<usize>,
    nominated_candidate: Option<usize>,
    had_selected_candidate: bool,
    config: Config,
}

impl CandidateSelector {
    pub fn new(now: Instant, config: Config) -> Self {
        Self {
            inactivity_time: now + config.inactivity_timeout,
            candidates: vec![],
            config,
            selected_candidate: None,
            nominated_candidate: None,
            had_selected_candidate: false,
        }
    }

    pub fn ice_credentials(&self) -> &IceCredentials {
        &self.config.ice_credentials
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
            self.selected_candidate = selected;
            trace!(
                "candidate nominated/selected: {:?}/{:?} (score={}) out of {} candidates",
                nominated.map(|i| self.candidates[i].address),
                selected.map(|i| self.candidates[i].address),
                score,
                self.candidates.len(),
            );
            if selected.is_none() {
                event!("calling.sfu.candidate_selector.no_output_address");
            } else if self.had_selected_candidate {
                event!("calling.sfu.ice.outgoing_addr_switch");
            } else {
                self.had_selected_candidate = true;
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

    /// Returns `true` if the candidate selector's inactivity time has passed. The inactive time is reset on every successful ping response.
    pub fn inactive(&self, now: Instant) -> bool {
        self.inactivity_time < now
    }

    fn selected_candidate(&self) -> Option<&Candidate> {
        self.selected_candidate.map(|k| &self.candidates[k])
    }

    /// Returns true if the selector ever had a selected candidate.
    pub fn had_selected_candidate(&self) -> bool {
        self.had_selected_candidate
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

    pub fn all_addrs(&self) -> Vec<SocketLocator> {
        self.candidates.iter().map(|c| c.address).collect()
    }

    /// Returns the estimated rtt of the currently selected remote candidate, if one is available.
    pub fn rtt(&self) -> Option<Duration> {
        self.selected_candidate().map(|c| c.rtt_estimator.rtt())?
    }

    fn get_or_create_candidate(
        &mut self,
        source_addr: SocketLocator,
        now: Instant,
    ) -> (Action, usize) {
        if let Some(index) = self.get_candidate_index_from_addr(source_addr) {
            (Action::None, index)
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

        let (action, candidate_index) = self.get_or_create_candidate(source_addr, now);

        if let Action::SendPing(transaction_id) = action {
            self.send_ping(transaction_id, candidate_index, packets_to_send);
        }

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
        let candidate = &mut self.candidates[candidate_index];
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

    pub fn tick(
        &mut self,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
        now: Instant,
    ) -> Vec<SocketLocator> {
        let had_selection = self.selected_candidate.is_some();
        let mut dead_candidates = vec![];
        let mut index = 0;
        while index < self.candidates.len() {
            let candidate = &mut self.candidates[index];
            match candidate.tick(now) {
                Action::Remove => {
                    dead_candidates.push(candidate.address);
                    self.remove_candidate_by_index(index);
                }
                Action::SendPing(transaction_id) => {
                    self.send_ping(transaction_id, index, packets_to_send);
                    index += 1;
                }
                Action::None => {
                    index += 1;
                }
            }
        }

        // If the selected candidate was removed, select a new one.
        if had_selection && self.selected_candidate.is_none() {
            self.make_candidate_selection(now);
        }

        dead_candidates
    }

    pub fn handle_ping_response(
        &mut self,
        source_addr: SocketLocator,
        response: BindingResponse,
        now: Instant,
    ) -> Result<(), Error> {
        trace!(
            "received STUN ping response from {}: {}",
            source_addr,
            response
        );

        if let Some(error_code) = response.error_code() {
            warn!("received error {} from {}", source_addr, error_code);
            return Err(Error::ReceivedResponseWithErrorCode);
        }

        if response.xor_mapped_address().is_none() && response.mapped_address().is_none() {
            warn!(
                "no XOR-MAPPED-ADDRESS/MAPPED-ADDRESS in response from {}",
                source_addr
            );
            return Err(Error::ReceivedResponseWithoutMappedAddress);
        }

        if let Some(index) = self.get_candidate_index_from_addr(source_addr) {
            self.candidates[index].maybe_handle_ping_response(response.transaction_id(), now)?;
            self.make_candidate_selection(now);
            self.inactivity_time = now + self.config.inactivity_timeout;
            Ok(())
        } else {
            Err(Error::ReceivedResponseFromUnknownAddress)
        }
    }

    fn send_ping(
        &self,
        transaction_id: TransactionId,
        candidate_index: usize,
        packets_to_send: &mut Vec<(PacketToSend, SocketLocator)>,
    ) {
        let ice_credentials = &self.config.ice_credentials;
        let request = StunPacketBuilder::new_binding_request(&transaction_id)
            .set_username(&ice_credentials.client_username)
            .build(&ice_credentials.client_pwd);
        let candidate = &self.candidates[candidate_index];
        trace!("sending STUN ping request to {}", candidate.address);
        packets_to_send.push((request, candidate.address));
    }

    pub fn remove_candidate(&mut self, addr: SocketLocator) {
        trace!("removing candidate {}", addr);
        if let Some(index) = self.get_candidate_index_from_addr(addr) {
            trace!("index {}", index);
            self.remove_candidate_by_index(index);
        }
    }

    fn remove_candidate_by_index(&mut self, index: usize) {
        self.candidates.swap_remove(index);
        let last_index = self.candidates.len();
        if self.nominated_candidate == Some(index) {
            self.nominated_candidate = None;
        } else if self.nominated_candidate == Some(last_index) {
            self.nominated_candidate = Some(index);
        }

        if self.selected_candidate == Some(index) {
            self.selected_candidate = None;
            self.make_candidate_selection(Instant::now());
        } else if self.selected_candidate == Some(last_index) {
            self.selected_candidate = Some(index);
        }
    }

    pub fn has_candidate(&mut self, addr: SocketLocator) -> bool {
        self.get_candidate_index_from_addr(addr).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        ops::Range,
        rc::Rc,
    };

    use calling_common::{Duration, Instant};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::{CandidateSelector, Config, RttEstimator, ScoringValues, PING_MAX_RETRANSMITS};
    use crate::{
        candidate_selector::{IceCredentials, State, PING_RTO, PING_RTO_RM},
        connection::PacketToSend,
        ice::{BindingRequest, BindingResponse, StunPacketBuilder, TransactionId},
        packet_server::SocketLocator,
    };

    fn create_candidate_selector(now: Instant, ping_period: Duration) -> CandidateSelector {
        let config = Config {
            ping_period,
            inactivity_timeout: Duration::from_secs(30),
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
                client_pwd: b"some client ice pwd".to_vec(),
            },
        };
        CandidateSelector::new(now, config)
    }

    fn find_ping_request(packets: Vec<(PacketToSend, SocketLocator)>) -> Option<Vec<u8>> {
        packets
            .into_iter()
            .find(|(p, _)| BindingRequest::looks_like_header(p))
            .map(|(p, _)| p)
    }

    fn create_ping_response(req: BindingRequest, selector: &CandidateSelector) -> Vec<u8> {
        let transaction_id = req.transaction_id();
        StunPacketBuilder::new_binding_response(&transaction_id)
            .set_xor_mapped_address(&"203.0.113.1:10".parse().unwrap())
            .build(&selector.config.ice_credentials.server_pwd)
    }

    #[derive(Debug)]
    struct SimulatedEndpoint {
        selector: Rc<RefCell<CandidateSelector>>,
        address: SocketLocator,
        rtt_range: Range<u64>,
        packet_loss_percentage: f64,
        current_ping: Option<PacketToSend>,
        current_ping_response_time: Option<Instant>,
        rnd: StdRng,
    }

    impl SimulatedEndpoint {
        fn new(
            selector: Rc<RefCell<CandidateSelector>>,
            address: SocketLocator,
            rtt_range: Range<u64>,
            packet_loss_percentage: f64,
        ) -> Self {
            // Keep RTT always smaller than RTO. We don't test responses to retransmits here.
            assert!((rtt_range.end as u128) < PING_RTO.as_millis());

            Self {
                selector,
                address,
                rtt_range,
                packet_loss_percentage,
                current_ping: None,
                current_ping_response_time: None,
                rnd: StdRng::seed_from_u64(42),
            }
        }

        fn should_drop_packet(&mut self) -> bool {
            self.rnd.gen_bool(self.packet_loss_percentage)
        }

        fn generate_rtt(&self) -> Duration {
            Duration::from_millis(rand::thread_rng().gen_range(self.rtt_range.clone()))
        }

        fn push(&mut self, packet: PacketToSend, now: Instant) {
            assert!(BindingRequest::looks_like_header(&packet));
            assert!(self.current_ping.is_none());
            assert!(self.current_ping_response_time.is_none());

            if !self.should_drop_packet() {
                let rtt = self.generate_rtt();
                self.current_ping = Some(packet);
                self.current_ping_response_time = Some(now + rtt);
            }
        }

        fn send_ping_request(&mut self, now: Instant, priority: u32, nominated: bool) {
            assert_eq!(self.current_ping, None);
            assert_eq!(self.current_ping_response_time, None);

            let mut selector = self.selector.borrow_mut();

            let transaction_id = TransactionId::new();
            let packet = if nominated {
                StunPacketBuilder::new_binding_request(&transaction_id)
                    .set_nomination()
                    .set_priority(priority)
                    .set_username(&selector.config.ice_credentials.server_username)
                    .build(&selector.config.ice_credentials.server_pwd)
            } else {
                StunPacketBuilder::new_binding_request(&transaction_id)
                    .set_priority(priority)
                    .set_username(&selector.config.ice_credentials.server_username)
                    .build(&selector.config.ice_credentials.server_pwd)
            };

            let mut packets = vec![];

            selector.handle_ping_request(
                &mut packets,
                BindingRequest::from_buffer_without_sanity_check(&packet),
                self.address,
                now,
            );

            // The selector may have sent a ping. Capture it here. We'll eventually
            // respond to it in tick().
            if let Some(req) = find_ping_request(packets) {
                self.current_ping = Some(req);
                self.current_ping_response_time = Some(now + self.generate_rtt());
            }
        }

        fn tick(&mut self, now: Instant) {
            if let Some(current_ping_response_time) = self.current_ping_response_time {
                if current_ping_response_time < now {
                    self.current_ping_response_time = None;
                    let req = self.current_ping.take().unwrap();
                    let req = BindingRequest::from_buffer_without_sanity_check(&req);
                    let mut selector = self.selector.borrow_mut();
                    let res = create_ping_response(req, &selector);
                    let res = BindingResponse::from_buffer_without_sanity_check(&res);
                    let _ = selector.handle_ping_response(self.address, res, now);
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
            for endpoint in endpoints.iter() {
                assert_eq!(
                    &*endpoint.selector.borrow() as *const CandidateSelector,
                    &*selector.borrow() as *const CandidateSelector
                );
            }
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

        fn send_ping_request(&mut self, address: SocketLocator, now: Instant, priority: u32) {
            self.with_endpoint(address, |e| e.send_ping_request(now, priority, false));
        }

        fn send_ping_request_with_nomination(
            &mut self,
            address: SocketLocator,
            now: Instant,
            priority: u32,
        ) {
            self.with_endpoint(address, |e| e.send_ping_request(now, priority, true));
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

        // Generate some large number of samples and push them into the RTT estimator.
        // The estimator is expected to take into account up to `sample_count` samples
        // when generating the estimate (which is simply an average over those samples).
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
    fn test_retransmits() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut packets = vec![];
        let mut n = 0;
        let mut now = time;
        let mut expected = Duration::ZERO;

        SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0)
            .send_ping_request(time, 32, true);

        while n < PING_MAX_RETRANSMITS {
            packets.clear();
            selector.borrow_mut().tick(&mut packets, now);
            if !packets.is_empty() {
                expected += if n == 0 {
                    PING_RTO
                } else {
                    PING_RTO * (2 << (n - 1))
                };
                assert_eq!(expected, now.saturating_duration_since(time));
                n += 1;
            }
            now += TICK_PERIOD;
        }

        expected += PING_RTO * PING_RTO_RM;
        selector.borrow_mut().tick(&mut packets, time + expected);
        assert!(selector.borrow().inactive(time + expected));
    }

    #[test]
    fn test_pings() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut packets = vec![];
        let mut now = time;
        let mut last_ping_time = now;
        let mut total_delta = Duration::ZERO;
        let mut total_pings = 0;
        let mut endpoint = SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0);

        // Send the first ping to register the endpoint
        endpoint.send_ping_request(time, 32, true);

        let mut selector = selector.borrow_mut();

        // We'll receive the first ping immediately. We must handle that here in order to avoid
        // retransmit, but cannot include it in the delta calculation.
        let req = endpoint.current_ping.take().unwrap();
        let req = BindingRequest::from_buffer_without_sanity_check(&req);
        let res = create_ping_response(req, &selector);
        let res = BindingResponse::from_buffer_without_sanity_check(&res);
        let _ = selector.handle_ping_response(client_addr1, res, now);

        // Perform 1000 ticks, during which we'll receive pings every 1000ms.
        // Since there is only one candidate, the only packet that will ever be
        // deposited in the packet array will be a ping from the selector.
        for _ in 0..=1000 {
            packets.clear();
            selector.tick(&mut packets, now);
            if !packets.is_empty() {
                // We have a ping. Send a response to avoid possible retransmits.
                let req = packets.pop().map(|(p, _)| p).unwrap();
                let req = BindingRequest::from_buffer_without_sanity_check(&req);
                let res = create_ping_response(req, &selector);
                let res = BindingResponse::from_buffer_without_sanity_check(&res);
                let _ = selector.handle_ping_response(client_addr1, res, now);
                // Update stats.
                let delta = now.saturating_duration_since(last_ping_time);
                total_delta += delta;
                total_pings += 1;
                last_ping_time = now;
            }
            now += TICK_PERIOD;
        }

        let avg_delta = total_delta.as_millis() as f32 / total_pings as f32;

        println!("Pings sent: {}", total_pings);

        assert!((avg_delta - 1000.0).abs() <= 0.1);
        assert_eq!(
            total_pings,
            1000 * TICK_PERIOD.as_millis() / PING_PERIOD.as_millis()
        );
    }

    #[test]
    fn test_selection() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping with nomination. After this, the candidate should be
        // in the New state, but not yet selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
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
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send a ping for each candidate. This first candidate gets the nomination.
        // After this, both candidates should be in the New state. No candidate
        // should be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        simulator.send_ping_request(client_addr2, time, 32);
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
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial pings. After this, both clients should be in the New
        // state, but neither of them should be the selected candidate.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        simulator.send_ping_request(client_addr2, time, 32);
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
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping with nomination and run the simulator for some time.
        // We expect the candidate to transition from the New into the Active state
        // and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(32), time);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Set the packet loss for the candidate to 100% and run the simulator for 42
        // seconds. With the default parameters, this should result in the candidate
        // not responding to any pings, and therefore, timing out. There should be no
        // selected candidate and the selector should declare itself as "inactive".
        simulator.update_packet_loss_percentage(client_addr1, 1.0);
        let time = simulator.run(Duration::from_secs(42), time);
        assert_eq!(selector.borrow().candidates.len(), 0);
        assert!(selector.borrow().selected_candidate().is_none());
        assert!(selector.borrow().inactive(time));

        // Now send another ping from the candidate. The candidate should be resurrected,
        // and, therefore, transition into the New state. No candidates should yet be
        // selected and the selector is not yet active, because no ping responses have arrived.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert!(selector.borrow().selected_candidate.is_none());
        assert!(selector.borrow().inactive(time));

        // Set packet loss to 0% and run the simulator for some time. The candidate
        // should transition into the Active state and it should be selected.
        simulator.update_packet_loss_percentage(client_addr1, 0.0);
        let _ = simulator.run(Duration::from_secs(32), time);
        assert_eq!(selector.borrow().candidates.len(), 1);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert!(matches!(selector.borrow().selected_candidate, Some(0)));
        assert!(!selector.borrow().inactive(time));
    }

    #[test]
    fn test_initialization_timeout() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));
        let mut endpoints = vec![];
        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // At this point the selector is not inactive since the intialization
        // timeout has not been reached.
        assert!(!selector.borrow().inactive(time));

        // Run the simulator for 35 seconds. We will never send any pings. Therefore,
        // the initialization timeout will be reached and the selector will become
        // inactive.
        let time = simulator.run(Duration::from_secs(35), time);
        assert!(selector.borrow().inactive(time));
    }

    #[test]
    fn test_candidate_list() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8001,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first canddiate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second canddiate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));
    }

    #[test]
    fn test_candidate_ordering() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

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

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr3, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr4, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr5, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr6, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Register all except UDP IPv6. The selected candidate should be the second
        // candidate, the candidate with an IPv4 address.
        simulator.send_ping_request(client_addr2, time, 32);
        simulator.send_ping_request(client_addr3, time, 32);
        simulator.send_ping_request(client_addr4, time, 32);
        simulator.send_ping_request(client_addr5, time, 32);
        simulator.send_ping_request(client_addr6, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(
            selector.borrow().selected_candidate().unwrap().address,
            client_addr2
        );

        // Now, register UDP IPv6. The selected candidate should be the first candidate,
        // the candidate with an IPv6 address.
        simulator.send_ping_request(client_addr1, time, 32);
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

    #[test]
    fn test_remove_candidate_single_selected() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().nominated_candidate, Some(0));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));

        selector.borrow_mut().remove_candidate(client_addr1);
        assert_eq!(selector.borrow().selected_candidate, None);
        assert_eq!(selector.borrow().nominated_candidate, None);
        assert_eq!(selector.borrow().outbound_address(), None);
    }

    #[test]
    fn test_remove_candidate_single_not_selected() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![SimulatedEndpoint::new(
            Rc::clone(&selector),
            client_addr1,
            50..90,
            0.0,
        )];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 0);
        assert_eq!(selector.borrow().candidates[0].state, State::New);
        assert_eq!(selector.borrow().selected_candidate, None);
        assert_eq!(selector.borrow().nominated_candidate, Some(0));
        assert_eq!(selector.borrow().outbound_address(), None);

        selector.borrow_mut().remove_candidate(client_addr1);
        assert_eq!(selector.borrow().selected_candidate, None);
        assert_eq!(selector.borrow().nominated_candidate, None);
        assert_eq!(selector.borrow().outbound_address(), None);
    }

    #[test]
    fn test_remove_candidate_selected_front() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8001,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));

        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));
        assert_eq!(selector.borrow().nominated_candidate, Some(0));

        selector.borrow_mut().remove_candidate(client_addr1);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr2));
        // Actually, we did nominate client_addr2, but client_addr1 was nominated afterward
        assert_eq!(selector.borrow().nominated_candidate, None);
    }

    #[test]
    fn test_remove_candidate_selected_back() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8001,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr2));
        assert_eq!(selector.borrow().nominated_candidate, Some(1));

        selector.borrow_mut().remove_candidate(client_addr2);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));
        // Actually, we did nominate client_addr1, but client_addr2 was nominated afterward
        assert_eq!(selector.borrow().nominated_candidate, None);
    }

    #[test]
    fn test_remove_candidate_unselected_front() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8001,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));

        assert_eq!(selector.borrow().selected_candidate, Some(1));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr2));
        assert_eq!(selector.borrow().nominated_candidate, Some(1));

        selector.borrow_mut().remove_candidate(client_addr1);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr2));
        assert_eq!(selector.borrow().nominated_candidate, Some(0));
    }

    #[test]
    fn test_remove_candidate_unselected_back() {
        const PING_PERIOD: Duration = Duration::from_secs(1);
        const TICK_PERIOD: Duration = Duration::from_millis(100);

        let client_addr1 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8000,
        ));
        let client_addr2 = SocketLocator::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8001,
        ));

        let time = Instant::now();
        let selector = Rc::new(RefCell::new(create_candidate_selector(time, PING_PERIOD)));

        let mut endpoints = vec![
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr1, 50..90, 0.0),
            SimulatedEndpoint::new(Rc::clone(&selector), client_addr2, 50..90, 0.0),
        ];

        let mut simulator = Simulator::new(Rc::clone(&selector), &mut endpoints, TICK_PERIOD);

        // Send the initial ping for the first candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(0));

        // Send the initial ping for the second candidate. We expect the candidate to
        // transition into the Active state and be selected.
        simulator.send_ping_request_with_nomination(client_addr2, time, 32);
        let time = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().selected_candidate, Some(1));

        simulator.send_ping_request_with_nomination(client_addr1, time, 32);
        let _ = simulator.run(Duration::from_secs(10), time);
        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().candidates[1].state, State::Active);
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));
        assert_eq!(selector.borrow().nominated_candidate, Some(0));

        selector.borrow_mut().remove_candidate(client_addr2);

        assert_eq!(selector.borrow().selected_candidate, Some(0));
        assert_eq!(selector.borrow().candidates[0].state, State::Active);
        assert_eq!(selector.borrow().outbound_address(), Some(client_addr1));
        assert_eq!(selector.borrow().nominated_candidate, Some(0));
    }
}
