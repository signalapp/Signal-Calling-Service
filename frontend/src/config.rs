//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use clap;
use serde::Deserialize;

/// Configuration options from command line arguments.
#[derive(Default, clap::Parser, Debug, Clone)]
#[clap(name = "calling_frontend")]
pub struct ArgConfig {
    /// The IP address to bind to for the server.
    #[clap(long, default_value = "0.0.0.0")]
    pub server_ip: String,

    /// The port to use to access the server.
    #[clap(long, default_value = "8090")]
    pub server_port: u16,

    /// Region of the frontend. Appears as a tag in metrics and logging.
    #[clap(long)]
    pub region: String,

    /// Deployment version of the frontend. Appears as a tag in metrics and in logging.
    #[clap(long)]
    pub version: String,

    /// A version string suitable to be used in the calling_server_url_template.
    /// Examples: "21", "staging.21"
    #[clap(long)]
    pub calling_server_version: String,

    /// The path to a yaml file with further configuration settings.
    #[clap(long)]
    pub yaml: String,
}

/// Configuration options from a yaml file.
#[derive(Default, Deserialize)]
pub struct YamlConfig {
    /// Maximum clients per call.
    pub max_clients_per_call: u32,

    /// Interval for removing ended calls from the database.
    pub cleanup_interval_ms: u64,

    /// The authentication key to use when validating API requests.
    pub authentication_key: String,

    /// A URL template string that provides a region-specific address of the server and
    /// used for redirects.
    /// '<region>' will be substituted with the current region.
    /// Example: "https://sfu.<region>.voip.signal.org"
    pub regional_url_template: String,

    /// A URL template string that provides a specific address to a calling server.
    /// '<region>' will be substituted with the current region.
    /// '<version>' will be substituted with the current deployment version.
    /// Example: `http://cs.<version>.<region>.voip.signal.org`
    pub calling_server_url_template: String,

    /// The key used for accessing storage, such as the AWS_ACCESS_KEY_ID.
    pub storage_key: String,

    /// The password used for accessing storage, such as the AWS_SECRET_ACCESS_KEY.
    pub storage_password: String,

    /// The name of the table that provides the list of calls being tracked.
    pub storage_table: String,

    /// The region in which the server resides.
    pub storage_region: String,

    /// The storage endpoint used only for testing. Typically something like http://dynamodb:8000.
    /// Do not specify anything for production.
    pub storage_endpoint: Option<String>,

    /// IP and port of Datadog StatsD agent. Typically 127.0.0.1:8125. If not
    /// present, metrics will be disabled.
    pub metrics_datadog_host: Option<String>,
}

pub struct Config {
    pub server_ip: String,
    pub server_port: u16,
    pub region: String,
    pub version: String,
    pub calling_server_version: String,
    pub max_clients_per_call: u32,
    pub cleanup_interval_ms: u64,
    pub authentication_key: String,
    pub regional_url_template: String,
    pub calling_server_url_template: String,
    pub storage_key: String,
    pub storage_password: String,
    pub storage_table: String,
    pub storage_region: String,
    pub storage_endpoint: Option<String>,
    pub metrics_datadog_host: Option<String>,
}

impl Config {
    pub fn merge(arg_config: ArgConfig, yaml_config: YamlConfig) -> Config {
        Config {
            server_ip: arg_config.server_ip,
            server_port: arg_config.server_port,
            region: arg_config.region,
            version: arg_config.version,
            calling_server_version: arg_config.calling_server_version,
            max_clients_per_call: yaml_config.max_clients_per_call,
            cleanup_interval_ms: yaml_config.cleanup_interval_ms,
            authentication_key: yaml_config.authentication_key,
            regional_url_template: yaml_config.regional_url_template,
            calling_server_url_template: yaml_config.calling_server_url_template,
            storage_key: yaml_config.storage_key,
            storage_password: yaml_config.storage_password,
            storage_table: yaml_config.storage_table,
            storage_region: yaml_config.storage_region,
            storage_endpoint: yaml_config.storage_endpoint,
            metrics_datadog_host: yaml_config.metrics_datadog_host,
        }
    }
}

#[cfg(test)]
pub fn default_test_config() -> Config {
    Config {
        server_ip: "127.0.0.1".to_string(),
        server_port: 8080,
        max_clients_per_call: 8,
        cleanup_interval_ms: 5000,
        authentication_key: "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b"
            .to_string(),
        region: "us-west-1".to_string(),
        version: "1".to_string(),
        regional_url_template: "".to_string(),
        calling_server_url_template: "http://127.0.0.1:8080".to_string(),
        calling_server_version: "1".to_string(),
        storage_key: "DUMMYKEY".to_string(),
        storage_password: "DUMMYSECRET".to_string(),
        storage_table: "Conferences".to_string(),
        storage_region: "us-east-2".to_string(),
        storage_endpoint: Some("http://127.0.0.1:8000".to_string()),
        metrics_datadog_host: None,
    }
}
