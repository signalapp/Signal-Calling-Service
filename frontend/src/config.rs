//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use clap;

/// Configuration options from command line arguments.
#[derive(Default, clap::Parser, Debug, Clone)]
#[clap(name = "calling_frontend")]
pub struct Config {
    /// The IP address to bind to for the server.
    #[clap(long, default_value = "0.0.0.0")]
    pub server_ip: String,

    /// The port to use to access the server.
    #[clap(long, default_value = "8080")]
    pub server_port: u16,

    /// GCP region of the frontend. Appears as a tag in metrics and logging.
    #[clap(long)]
    pub region: String,

    /// The authentication key to use when validating API requests.
    #[clap(long)]
    pub authentication_key: String,

    /// Deployment version of the frontend. Appears as a tag in metrics and in logging.
    #[clap(long)]
    pub version: String,

    /// Maximum clients per call.
    #[clap(long)]
    pub max_clients_per_call: u32,

    /// Interval for removing ended calls from the database.
    #[clap(long)]
    pub cleanup_interval_ms: u64,

    /// A URL template string that provides a region-specific address of the server and
    /// used for redirects.
    /// '<region>' will be substituted with the current region.
    /// Example: "https://sfu.<region>.voip.signal.org"
    #[clap(long)]
    pub regional_url_template: String,

    /// The URL of the calling server to access for the backend.
    #[clap(long)]
    pub calling_server_url: String,

    /// Interval for fetching a new identity token for storage support via DynamodDB.
    #[clap(long, default_value = "600000")]
    pub identity_fetcher_interval_ms: u64,

    /// Where to fetch identity tokens from for storage support via DynamodDB.
    #[clap(long)]
    pub identity_token_url: Option<String>,

    /// The name of the table that provides the list of calls being tracked.
    #[clap(long)]
    pub storage_table: String,

    /// The AWS region in which the DynamoDB server resides.
    #[clap(long)]
    pub storage_region: String,

    /// The storage endpoint used only for testing. Typically something like "http://dynamodb:8000".
    /// Do not specify anything for production.
    #[clap(long)]
    pub storage_endpoint: Option<String>,

    /// IP and port of Datadog StatsD agent. Typically 127.0.0.1:8125. If not
    /// present, metrics will be disabled.
    #[clap(long)]
    pub metrics_datadog_host: Option<String>,
}

#[cfg(test)]
pub fn default_test_config() -> Config {
    Config {
        server_ip: "127.0.0.1".to_string(),
        server_port: 8080,
        max_clients_per_call: 8,
        cleanup_interval_ms: 5000,
        identity_fetcher_interval_ms: 1000 * 60 * 10,
        identity_token_url: None,
        authentication_key: "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b"
            .to_string(),
        region: "us-west1".to_string(),
        version: "1".to_string(),
        regional_url_template: "".to_string(),
        calling_server_url: "http://127.0.0.1:8080".to_string(),
        storage_table: "CallRecords".to_string(),
        storage_region: "us-east-1".to_string(),
        storage_endpoint: Some("localhost:9010".to_string()),
        metrics_datadog_host: None,
    }
}
