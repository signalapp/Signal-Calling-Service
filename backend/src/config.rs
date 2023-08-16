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
#[clap(name = "calling_backend")]
pub struct Config {
    /// The IP address to bind to for all servers.
    #[clap(long, default_value = "::")]
    pub binding_ip: IpAddr,

    /// The IP address to share for for ICE candidates. Clients will
    /// connect to the calling backend using this IP. If unset, binding-ip
    /// is used, if binding-ip is set to 0.0.0.0 or ::, 127.0.0.1 is used
    #[clap(long)]
    pub ice_candidate_ip: Vec<IpAddr>,

    /// The port to use for ICE candidates. Clients will connect to the
    /// calling backend using this port.
    #[clap(long, default_value = "10000")]
    pub ice_candidate_port: u16,

    /// The port to use for ICE candidates when connected over TCP. Clients
    /// will connect to the calling backend using this port.
    #[clap(long, default_value = "10000")]
    pub ice_candidate_port_tcp: u16,

    /// The IP address to share for direct access to the signaling_server. If
    /// defined, then the signaling_server will be used, otherwise the
    /// http_server will be used for testing.
    #[clap(long)]
    pub signaling_ip: Option<IpAddr>,

    /// The port to use for the signaling interface.
    #[clap(long, default_value = "8080")]
    pub signaling_port: u16,

    /// Maximum clients per call, if using the http_server for testing.
    #[clap(long, default_value = "8")]
    pub max_clients_per_call: u32,

    /// The initial bitrate target for sending. In a 16-person call with
    /// each base layer at 50kbps you'd need 800kbps to send them all.
    #[clap(long, default_value = "800")]
    pub initial_target_send_rate_kbps: u64,

    /// The min target send rate for sending.
    /// This affects the congestion controller (googcc).
    #[clap(long, default_value = "100")]
    pub min_target_send_rate_kbps: u64,

    /// The max target send rate for sending.
    /// This affects the congestion controller (googcc)
    /// and indirectly the maximum that any client can receive
    /// no matter how much the client requests.
    #[clap(long, default_value = "30000")]
    pub max_target_send_rate_kbps: u64,

    /// If the client doesn't request a max send rate,
    /// use this as the max send rate.
    /// Affects the allocation of the target send rate,
    /// not the calculation of the of the target send rate.
    #[clap(long, default_value = "5000")]
    pub default_requested_max_send_rate_kbps: u64,

    /// Timer tick period for operating on the Sfu state (ms).
    #[clap(long, default_value = "100")]
    pub tick_interval_ms: u64,

    /// How quickly we want to drain each outgoing queue.
    /// This affects the rate we allocate for draining the queue.
    /// It will push out other, lower-priority, streams to prioritize draining.
    /// The lower the value here, the higher the rate and the
    /// higher priority put on draining the outgoing queue.
    #[clap(long, default_value = "500")]
    pub outgoing_queue_drain_ms: u64,

    /// Optional interval used to post diagnostics to the log. If not defined
    /// then no periodic information about calls will be posted to the log.
    #[clap(long)]
    pub diagnostics_interval_secs: Option<u64>,

    /// Interval for sending active speaker messages (ms). The amount of time
    /// to wait between sending messages to the clients to remind them of the
    /// current active speaker for the call. Using milliseconds in case sub-
    /// second resolution is needed.
    #[clap(long, default_value = "1000")]
    pub active_speaker_message_interval_ms: u64,

    /// Inactivity check interval (seconds). The amount of time to wait between
    /// iterating structures for inactive calls and clients.
    #[clap(long, default_value = "5")]
    pub inactivity_check_interval_secs: u64,

    /// Amount of time to wait before dropping a call or client due to inactivity (seconds).
    #[clap(long, default_value = "30")]
    pub inactivity_timeout_secs: u64,

    /// Whether new clients require approval. Only used with the testing http_server.
    #[clap(long, action)]
    pub new_clients_require_approval: bool,

    /// The URL to PUT the list of approved users to.
    #[clap(long)]
    pub approved_users_persistence_url: Option<hyper::Uri>,

    /// Whether to save any users who join to the approved users list.
    ///
    /// ...as opposed to only those who are explicitly approved. Only used for testing.
    #[clap(long, action)]
    pub persist_approval_for_all_users_who_join: bool,

    #[clap(flatten)]
    pub metrics: MetricsOptions,
}

#[derive(clap::Parser, Clone, Debug, Default)]
pub struct MetricsOptions {
    /// Host and port of Datadog StatsD agent. Typically 127.0.0.1:8125.
    #[clap(long)]
    pub datadog: Option<String>,

    /// Region appears as a tag in metrics and logging.
    #[clap(long = "metrics-region", default_value = "unspecified")]
    pub region: String,

    /// Deployment version appears as a tag in metrics and in logging if specified.
    #[clap(long = "metrics-version")]
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaPorts {
    pub udp: u16,
    pub tcp: u16,
}

pub struct ServerMediaAddress {
    pub addresses: Vec<IpAddr>,
    pub ports: MediaPorts,
}

/// Public address of the server for media/UDP/TCP derived from the configuration.
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
            },
        }
    }

    pub fn ip(&self) -> &IpAddr {
        self.addresses
            .get(0)
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
        active_speaker_message_interval_ms: 1000,
        inactivity_check_interval_secs: 5,
        inactivity_timeout_secs: 30,
        new_clients_require_approval: false,
        approved_users_persistence_url: Default::default(),
        persist_approval_for_all_users_who_join: false,
        metrics: Default::default(),
    }
}
