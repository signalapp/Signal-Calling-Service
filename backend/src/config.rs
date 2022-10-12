//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Configuration options for the calling backend.

use std::net::SocketAddr;

use clap;

/// General configuration options, set by command line arguments or
/// falls back to default or environment variables (in some cases).
#[derive(Default, clap::Parser, Debug, Clone)]
#[clap(name = "calling_backend")]
pub struct Config {
    /// The IP address to bind to for all servers.
    #[clap(long, default_value = "0.0.0.0")]
    pub binding_ip: String,

    /// The IP address to share for for ICE candidates. Clients will connect
    /// to the calling backend using this IP.
    #[clap(long)]
    pub ice_candidate_ip: Option<String>,

    /// The port to use for ICE candidates. Clients will connect to the
    /// calling backend using this port.
    #[clap(long, default_value = "10000")]
    pub ice_candidate_port: u16,

    /// The IP address to share for direct access to the signaling_server. If
    /// defined, then the signaling_server will be used, otherwise the
    /// http_server will be used for testing.
    #[clap(long)]
    pub signaling_ip: Option<String>,

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

/// Returns the public address of the server for media/UDP as per configuration.
pub fn get_server_media_address(config: &'static Config) -> SocketAddr {
    let ip = config
        .ice_candidate_ip
        .as_deref()
        .unwrap_or_else(|| {
            if config.binding_ip == "0.0.0.0" {
                "127.0.0.1"
            } else {
                &config.binding_ip
            }
        })
        .parse()
        .expect("ice_candidate_ip should parse");
    SocketAddr::new(ip, config.ice_candidate_port)
}

#[cfg(test)]
pub(crate) fn default_test_config() -> Config {
    Config {
        binding_ip: "127.0.0.1".to_string(),
        ice_candidate_ip: Some("127.0.0.1".to_string()),
        signaling_ip: Some("127.0.0.1".to_string()),
        signaling_port: 8080,
        ice_candidate_port: 10000,
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
        metrics: Default::default(),
    }
}
