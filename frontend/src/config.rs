//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, Ipv4Addr};

use clap::ArgGroup;

/// Configuration options from command line arguments.
#[derive(clap::Parser, Debug, Clone)]
#[command(name = "calling_frontend")]
#[command(group(ArgGroup::new("backend").required(true).multiple(true).args(&["calling_server_url", "backend_list_instances_url", "backend_ip"])))]
#[command(group(ArgGroup::new("new_backend").required(false).args(&["backend_list_instances_url", "backend_ip"])))]
pub struct Config {
    /// The IP address to bind to for the server.
    #[arg(long, default_value = "0.0.0.0")]
    pub server_ip: IpAddr,

    /// The port to use to access the server.
    #[arg(long, default_value = "8080")]
    pub server_port: u16,

    /// The IP address to bind to for the backend to frontend API.
    #[arg(long, default_value = "0.0.0.0")]
    pub internal_api_ip: IpAddr,

    /// The port to use for the backend to frontend API. Default is to not run the internal API server.
    #[arg(long)]
    pub internal_api_port: Option<u16>,

    /// GCP region of the frontend. Appears as a tag in metrics and logging.
    #[arg(long)]
    pub region: String,

    /// The authentication key to use when validating group credentials, hex-encoded.
    #[arg(long)]
    pub authentication_key: String,

    /// The authentication key to use when validating zero-knowledge credentials, base64-encoded.
    #[arg(long)]
    pub zkparams: String,

    /// Deployment version of the frontend. Appears as a tag in metrics and in logging.
    #[arg(long)]
    pub version: String,

    /// Maximum clients per call.
    #[arg(long)]
    pub max_clients_per_call: u32,

    /// Interval for removing ended calls from the database.
    #[arg(long)]
    pub cleanup_interval_ms: u64,

    /// A URL template string that provides a region-specific address of the server and
    /// used for redirects.
    /// '<region>' will be substituted with the current region.
    /// Example: "https://sfu.<region>.voip.signal.org"
    #[arg(long)]
    pub regional_url_template: String,

    /// The URL of the calling server to access for the backend.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub calling_server_url: Option<String>,

    /// The URL instance group of calling backends.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new(), requires = "oauth2_token_url")]
    pub backend_list_instances_url: Option<String>,

    /// Where to fetch oauth2 tokens from for fetching backend instance list.
    #[arg(long)]
    pub oauth2_token_url: Option<String>,

    // Static list of calling backend IPs
    #[arg(long)]
    pub backend_ip: Option<Vec<Ipv4Addr>>,

    /// Interval for fetching a new identity token for storage support via DynamodDB.
    #[arg(long, default_value = "600000")]
    pub identity_fetcher_interval_ms: u64,

    /// Where to fetch identity tokens from for storage support via DynamodDB.
    #[arg(long)]
    pub identity_token_url: Option<String>,

    /// The name of the table that tracks information about rooms.
    #[arg(long)]
    pub storage_table: String,

    /// The AWS region in which the DynamoDB server resides.
    #[arg(long)]
    pub storage_region: String,

    /// The storage endpoint used only for testing. Typically something like "http://dynamodb:8000".
    /// Do not specify anything for production.
    #[arg(long)]
    pub storage_endpoint: Option<String>,

    /// IP and port of Datadog StatsD agent. Typically 127.0.0.1:8125. If not
    /// present, metrics will be disabled.
    #[arg(long)]
    pub metrics_datadog_host: Option<String>,

    /// Enables support for call link epochs.
    #[arg(long, default_value = "false")]
    pub enable_call_link_epochs: bool,
}

#[cfg(test)]
pub fn default_test_config() -> Config {
    Config {
        server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_port: 8080,
        internal_api_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        internal_api_port: None,
        max_clients_per_call: 8,
        cleanup_interval_ms: 5000,
        identity_fetcher_interval_ms: 1000 * 60 * 10,
        identity_token_url: None,
        authentication_key: "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b"
            .to_string(),
        zkparams: "AMJqvmQRYwEGlm0MSy6QFPIAvgOVsqRASNX1meQyCOYHJFqxO8lITPkow5kmhPrsNbu9JhVfKFwesVSKhdZaqQko3IZlJZMqP7DDw0DgTWpdnYzSt0XBWT50DM1cw1nCUXXBZUiijdaFs+JRlTKdh54M7sf43pFxyMHlS3URH50LOeR8jVQKaUHi1bDP2GR9ZXp3Ot9Fsp0pM4D/vjL5PwoOUuzNNdpIqUSFhKVrtazwuHNn9ecHMsFsN0QPzByiDA8nhKcGpdzyWUvGjEDBvpKkBtqjo8QuXWjyS3jSl2oJ/Z4Fh3o2N1YfD2aWV/K88o+TN2/j2/k+KbaIZgmiWwppLU+SYGwthxdDfZgnbaaGT/vMYX9P5JlUWSuP3xIxDzPzxBEFho67BP0Pvux+0a5nEOEVEpfRSs61MMvwNXEKZtzkO0QFbOrFYrPntyb7ToqNi66OQNyTfl/J7kqFZg2MTm3CKjHTAIvVMFAGCIamsrT9sWXOtuNeMS94xazxDA==".to_string(),
        region: "us-west1".to_string(),
        version: "1".to_string(),
        regional_url_template: "".to_string(),
        calling_server_url: Some("http://127.0.0.1:8080".to_string()),
        backend_list_instances_url: None,
        oauth2_token_url: None,
        backend_ip: None,
        storage_table: "Rooms".to_string(),
        storage_region: "us-west-1".to_string(),
        storage_endpoint: Some("http://localhost:8000".to_string()),
        metrics_datadog_host: None,
        enable_call_link_epochs: true,
    }
}
