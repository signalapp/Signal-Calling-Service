//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Configuration options for the calling backend.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use clap;

/// General configuration options, set by command line arguments or
/// falls back to default or environment variables (in some cases).
#[derive(clap::Parser, Debug, Clone)]
#[command(name = "calling_backend")]
pub struct Config {
    /// The IP address to bind to for all servers.
    #[arg(long, default_value = "::")]
    pub binding_ip: IpAddr,

    /// The IP address to share for for ICE candidates. Clients will
    /// connect to the calling backend using this IP. If unset, binding-ip
    /// is used, if binding-ip is set to 0.0.0.0 or ::, 127.0.0.1 is used
    #[arg(long)]
    pub ice_candidate_ip: Vec<IpAddr>,

    /// The port to use for ICE candidates. Clients will connect to the
    /// calling backend using this port.
    #[arg(long, default_value = "10000")]
    pub ice_candidate_port: u16,

    /// The port to use for ICE candidates when connected over TCP. Clients
    /// will connect to the calling backend using this port.
    #[arg(long, default_value = "10000")]
    pub ice_candidate_port_tcp: u16,

    /// The port to use for ICE candidates when connected over TCP+TLS. Clients
    /// will connect to the calling backend using this port.
    #[arg(long)]
    pub ice_candidate_port_tls: Option<u16>,

    /// The IP address to share for direct access to the signaling_server. If
    /// defined, then the signaling_server will be used, otherwise the
    /// http_server will be used for testing.
    #[arg(long)]
    pub signaling_ip: Option<IpAddr>,

    /// The port to use for the signaling interface.
    #[arg(long, default_value = "8080")]
    pub signaling_port: u16,

    /// Maximum clients per call, if using the http_server for testing.
    #[arg(long, default_value = "8")]
    pub max_clients_per_call: u32,

    /// The initial bitrate target for sending. In a 16-person call with
    /// each base layer at 50kbps you'd need 800kbps to send them all.
    #[arg(long, default_value = "800")]
    pub initial_target_send_rate_kbps: u64,

    /// The min target send rate for sending.
    /// This affects the congestion controller (googcc).
    #[arg(long, default_value = "100")]
    pub min_target_send_rate_kbps: u64,

    /// The max target send rate for sending.
    /// This affects the congestion controller (googcc)
    /// and indirectly the maximum that any client can receive
    /// no matter how much the client requests.
    #[arg(long, default_value = "30000")]
    pub max_target_send_rate_kbps: u64,

    /// If the client doesn't request a max send rate,
    /// use this as the max send rate.
    /// Affects the allocation of the target send rate,
    /// not the calculation of the of the target send rate.
    #[arg(long, default_value = "5000")]
    pub default_requested_max_send_rate_kbps: u64,

    /// Timer tick period for operating on the Sfu state (ms).
    #[arg(long, default_value = "100")]
    pub tick_interval_ms: u64,

    /// How quickly we want to drain each outgoing queue.
    /// This affects the rate we allocate for draining the queue.
    /// It will push out other, lower-priority, streams to prioritize draining.
    /// The lower the value here, the higher the rate and the
    /// higher priority put on draining the outgoing queue.
    #[arg(long, default_value = "500")]
    pub outgoing_queue_drain_ms: u64,

    /// Optional interval used to post diagnostics to the log. If not defined
    /// then no periodic information about calls will be posted to the log.
    #[arg(long)]
    pub diagnostics_interval_secs: Option<u64>,

    /// Amount of time to wait before dropping a call or client due to inactivity (seconds).
    #[arg(long, default_value = "30")]
    pub inactivity_timeout_secs: u64,

    /// Whether new clients require approval. Only used with the testing http_server.
    #[arg(long)]
    pub new_clients_require_approval: bool,

    /// The URL to PUT the list of approved users to.
    #[arg(long)]
    pub approved_users_persistence_url: Option<reqwest::Url>,

    /// The base URL to DELETE individual and batch of call records.
    /// An empty URL disables backend initiated call record removal.
    #[arg(long)]
    pub remove_call_records_base_url: Option<reqwest::Url>,

    /// Amount of time to wait before failing a call to the calling frontend.
    #[arg(long, default_value = "5000")]
    pub frontend_operation_timeout_ms: u64,

    /// Whether to save any users who join to the approved users list.
    ///
    /// ...as opposed to only those who are explicitly approved. Only used for testing.
    #[arg(long)]
    pub persist_approval_for_all_users_who_join: bool,

    /// The path to the certificate file for TLS
    #[arg(long)]
    pub certificate_file_path: Option<String>,

    /// The path to the private key file for TLS
    #[arg(long)]
    pub key_file_path: Option<String>,

    /// The secret used to issue Send Endorsements
    #[arg(long)]
    pub endorsement_secret: Option<String>,

    // The hostname to give the client to validate the certificate used for TLS
    #[arg(long)]
    pub hostname: Option<String>,

    #[clap(flatten)]
    pub metrics: MetricsOptions,

    #[clap(flatten)]
    pub candidate_selector_options: CandidateSelectorOptions,
}

#[derive(clap::Parser, Clone, Debug, Default)]
pub struct MetricsOptions {
    /// Host and port of Datadog StatsD agent. Typically 127.0.0.1:8125.
    #[arg(long)]
    pub datadog: Option<String>,

    /// Region appears as a tag in metrics and logging.
    #[arg(long = "metrics-region", default_value = "unspecified")]
    pub region: String,

    /// Deployment version appears as a tag in metrics and in logging if specified.
    #[arg(long = "metrics-version")]
    pub version: Option<String>,
}

#[derive(clap::Parser, Clone, Debug, Default)]
pub struct CandidateSelectorOptions {
    /// Candidate selector: connection ping period in milliseconds.
    /// This value must be in the [500, 1500] range.
    #[arg(long = "csel-ping-period", default_value = "1000", value_parser = clap::value_parser!(u64).range(500..=1500))]
    pub ping_period: u64,

    // Candidate selector: how many points to award to remotely nominated candidates.
    // This value must be in the [0, 1000] range.
    #[arg(long = "csel-score-nominated", default_value = "1000", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_nominated: u32,

    /// Candidate selector: UDPv4 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-udpv4", default_value = "500", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_udpv4: u32,

    /// Candidate selector: UDPv6 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-udpv6", default_value = "600", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_udpv6: u32,

    /// Candidate selector: TCPv4 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-tcpv4", default_value = "250", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_tcpv4: u32,

    /// Candidate selector: TCPv6 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-tcpv6", default_value = "350", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_tcpv6: u32,

    /// Candidate selector: TLSv4 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-tlsv4", default_value = "100", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_tlsv4: u32,

    /// Candidate selector: TLSv6 connection score.
    /// This value must be in the [0..1000] range.
    #[arg(long = "csel-score-tlsv6", default_value = "150", value_parser = clap::value_parser!(u32).range(0..=1000))]
    pub score_tlsv6: u32,

    /// Candidate selector: maximum ICE ping RTT penalty.
    /// This value must be greater than or equal to 0.
    #[arg(long = "csel-rtt-max-penalty", default_value = "2000")]
    pub rtt_max_penalty: f32,

    /// Candidate selector: any remote candidate whose ICE ping RTT exceeds this value will
    /// receive the maximum penalty. This value must be greater than or equal to 0.
    #[arg(long = "csel-rtt-limit", default_value = "300")]
    pub rtt_limit: f32,

    /// Candidate selector: ICE ping RTT estimator sensitivity.
    /// This value must be in the [0, 1] range where 0 will yield the least sensitive RTT
    /// estimator, and, conversely, 1 will yield the most sensitive RTT estimator.
    #[arg(long = "csel-rtt-sensitivity", default_value = "0.1")]
    pub rtt_sensitivity: f32,
}

#[derive(Debug, Clone)]
pub struct MediaPorts {
    pub udp: u16,
    pub tcp: u16,
    pub tls: Option<u16>,
}

pub struct ServerMediaAddress {
    pub addresses: Vec<IpAddr>,
    pub ports: MediaPorts,
    pub hostname: Option<String>,
}

/// Public address of the server for media/UDP/TCP/TLS derived from the configuration.
impl ServerMediaAddress {
    pub fn from(config: &'static Config) -> Self {
        let addresses = if config.ice_candidate_ip.is_empty() {
            let ip = if config.binding_ip == Ipv4Addr::UNSPECIFIED
                || config.binding_ip == Ipv6Addr::UNSPECIFIED
            {
                Ipv4Addr::LOCALHOST.into()
            } else {
                config.binding_ip
            };
            vec![ip]
        } else {
            config.ice_candidate_ip.clone()
        };
        Self {
            addresses,
            ports: MediaPorts {
                udp: config.ice_candidate_port,
                tcp: config.ice_candidate_port_tcp,
                tls: config.ice_candidate_port_tls,
            },
            hostname: config.hostname.clone(),
        }
    }

    pub fn ip(&self) -> &IpAddr {
        self.addresses
            .first()
            .expect("addresses should be non-empty")
    }
}

#[cfg(test)]
pub(crate) fn default_test_config() -> Config {
    Config {
        binding_ip: Ipv4Addr::LOCALHOST.into(),
        ice_candidate_ip: vec![Ipv4Addr::LOCALHOST.into()],
        signaling_ip: Some(Ipv4Addr::LOCALHOST.into()),
        signaling_port: 8080,
        ice_candidate_port: 10000,
        ice_candidate_port_tcp: 10000,
        max_clients_per_call: 8,
        initial_target_send_rate_kbps: 1500,
        min_target_send_rate_kbps: 100,
        max_target_send_rate_kbps: 30000,
        default_requested_max_send_rate_kbps: 20000,
        tick_interval_ms: 100,
        outgoing_queue_drain_ms: 500,
        diagnostics_interval_secs: None,
        inactivity_timeout_secs: 30,
        new_clients_require_approval: false,
        approved_users_persistence_url: Default::default(),
        remove_call_records_base_url: Default::default(),
        persist_approval_for_all_users_who_join: false,
        metrics: Default::default(),
        frontend_operation_timeout_ms: 1000,
        certificate_file_path: None,
        key_file_path: None,
        hostname: None,
        endorsement_secret: None,
        ice_candidate_port_tls: None,
        candidate_selector_options: Default::default(),
    }
}
