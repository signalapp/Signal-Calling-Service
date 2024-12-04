//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[macro_use]
extern crate log;

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use calling_common::Duration;
use calling_frontend::{
    api,
    authenticator::Authenticator,
    backend::BackendHttpClient,
    cleaner, config,
    frontend::Frontend,
    frontend::FrontendIdGenerator,
    internal_api, metrics_server,
    storage::{DynamoDb, IdentityFetcher},
};
use clap::Parser;
use env_logger::Env;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{env, sync::Arc};
use tokio::{
    runtime,
    signal::unix::{signal, SignalKind},
    sync::{mpsc, oneshot},
};

// Load the config and treat it as a read-only static value.
static CONFIG: Lazy<config::Config> = Lazy::new(config::Config::parse);

#[rustfmt::skip]
fn print_config(config: &'static config::Config) {
    info!("config:");
    info!("  {:38}{}", "server_ip:", config.server_ip);
    info!("  {:38}{}", "server_port:", config.server_port);
    info!("  {:38}{}", "max_clients_per_call:", config.max_clients_per_call);
    info!("  {:38}{}", "cleanup_interval_ms:", config.cleanup_interval_ms);
    info!("  {:38}{}", "region:", config.region);
    info!("  {:38}{}", "version:", config.version);
    info!("  {:38}{}", "regional_url_template:", config.regional_url_template);
    info!("  {:38}{:?}", "calling_server_url:", config.calling_server_url);
    info!("  {:38}{:?}", "backend_list_instances_url:", config.backend_list_instances_url);
    info!("  {:38}{:?}", "backend_ip:", config.backend_ip);
    info!("  {:38}{}", "storage_table:", config.storage_table);
    info!("  {:38}{:?}", "identity_url:", config.identity_token_url);
    info!("  {:38}{:?}", "oauth2_url:", config.oauth2_token_url);
    info!("  {:38}{:?}", "storage_endpoint:", config.storage_endpoint);
    info!("  {:38}{}", "metrics_datadog:",
          match &config.metrics_datadog_host {
              Some(host) => host,
              None => "Disabled",
          });
}

/// Waits for a SIGINT or SIGTERM signal and returns. Can be cancelled
/// by sending something to the channel.
pub async fn wait_for_signal(mut canceller: mpsc::Receiver<()>) {
    tokio::select!(
        _ = async {
            signal(SignalKind::interrupt()).expect("SIGINT stream is valid").recv().await;
        } => {
            // Handle SIGINT for ctrl+c and debug stop command.
            info!("terminating by signal: SIGINT");
        },
        _ = async {
            signal(SignalKind::terminate()).expect("SIGTERM stream is valid").recv().await;
        } => {
            // Handle SIGTERM for docker stop command.
            info!("terminating by signal: SIGTERM");
        },
        _ = async { canceller.recv().await } => {},
    )
}

fn main() -> Result<()> {
    std::env::set_var("RUST_BACKTRACE", "full");

    // Initialize logging.
    env_logger::Builder::from_env(
        Env::default()
            .default_filter_or("calling_frontend=info")
            .default_write_style_or("never"),
    )
    .format(calling_common::format_log_line)
    .init();

    info!("Signal Calling Frontend starting up...");

    // Log information about the environment we are running in.
    info!(
        "calling_frontend: v{}",
        option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")
    );

    #[cfg(not(debug_assertions))]
    {
        match option_env!("RUSTFLAGS") {
            None => {
                warn!("for optimal performance, build with RUSTFLAGS=\"-C target-cpu=native\" or better");
            }
            Some(rust_flags) => {
                info!("built with: RUSTFLAGS=\"{}\"", rust_flags);
            }
        }
    }

    // Parse the command line arguments.
    let config = &CONFIG;
    print_config(config);

    // Create a threaded tokio runtime. By default, starts a worker thread
    // for each core on the system.
    let threaded_rt = runtime::Runtime::new()?;

    let (api_ender_tx, api_ender_rx) = oneshot::channel();
    let (internal_api_ender_tx, internal_api_ender_rx) = oneshot::channel();
    let (cleaner_ender_tx, cleaner_ender_rx) = oneshot::channel();
    let (metrics_ender_tx, metrics_ender_rx) = oneshot::channel();
    let (identity_fetcher_ender_tx, identity_fetcher_ender_rx) = oneshot::channel();
    let (signal_canceller_tx, signal_canceller_rx) = mpsc::channel(1);

    let signal_canceller_tx_clone_for_internal_api = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_cleaner = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_metrics = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_identity_fetcher = signal_canceller_tx.clone();

    // Create frontend entities that might fail.
    let authenticator = Authenticator::from_hex_key(&config.authentication_key)?;
    let zkparams = bincode::deserialize(&STANDARD.decode(&config.zkparams)?)?;
    let identity_fetcher = if config.storage_endpoint.is_some() {
        // Create an identity fetcher with a dummy token path, which isn't used
        // for testing with a storage endpoint and won't be fetched.
        IdentityFetcher::new(config, "/tmp/token")
    } else {
        // Get the location of the identity token file from the environment variable,
        // the same location that the storage client will try to get it from when
        // searching for credentials.
        let identity_token_path = env::var("AWS_WEB_IDENTITY_TOKEN_FILE")?;
        let identity_fetcher = IdentityFetcher::new(config, &identity_token_path);

        // Fetch an identity token once before connecting for the first time.
        threaded_rt.block_on(identity_fetcher.fetch_token())?;

        identity_fetcher
    };
    let storage = threaded_rt.block_on(DynamoDb::new(config))?;
    let backend = threaded_rt.block_on(BackendHttpClient::from_config(config))?;

    threaded_rt.block_on(async {
        // Create the shared Frontend state.
        let frontend: Arc<Frontend> = Arc::new(Frontend {
            config,
            authenticator,
            zkparams,
            storage: Box::new(storage),
            backend: Box::new(backend),
            id_generator: Box::new(FrontendIdGenerator),
            api_metrics: Mutex::new(Default::default()),
        });

        let frontend_clone_for_metrics = frontend.clone();
        let frontend_clone_for_internal_api = frontend.clone();

        // Start the api server.
        let api_handle = tokio::spawn(async move {
            if let Err(err) = api::start(frontend, api_ender_rx).await {
                error!("api start error: {}", err);
            }
            let _ = signal_canceller_tx.send(()).await;
        });

        // Start the internal api server.
        let internal_api_handle = tokio::spawn(async move {
            if let Err(err) =
                internal_api::start(frontend_clone_for_internal_api, internal_api_ender_rx).await
            {
                error!("api start error: {}", err);
            }
            let _ = signal_canceller_tx_clone_for_internal_api.send(()).await;
        });

        // Start the cleaner server.
        let cleaner_handle = tokio::spawn(async move {
            let _ = cleaner::start(config, cleaner_ender_rx).await;
            let _ = signal_canceller_tx_clone_for_cleaner.send(()).await;
        });

        // Start the metrics server.
        let metrics_handle = tokio::spawn(async move {
            let _ = metrics_server::start(frontend_clone_for_metrics, metrics_ender_rx).await;
            let _ = signal_canceller_tx_clone_for_metrics.send(()).await;
        });

        // Start the identity token fetcher.
        let fetcher_handle = tokio::spawn(async move {
            let _ = identity_fetcher.start(identity_fetcher_ender_rx).await;
            let _ = signal_canceller_tx_clone_for_identity_fetcher
                .send(())
                .await;
        });

        // Wait for any signals to be detected, or cancel due to one of the
        // servers not being able to be started (the channel is buffered).
        wait_for_signal(signal_canceller_rx).await;

        // Gracefully exit the servers if needed.
        let _ = api_ender_tx.send(());
        let _ = internal_api_ender_tx.send(());
        let _ = cleaner_ender_tx.send(());
        let _ = metrics_ender_tx.send(());
        let _ = identity_fetcher_ender_tx.send(());

        // Wait for the servers to exit.
        let _ = tokio::join!(
            api_handle,
            internal_api_handle,
            cleaner_handle,
            metrics_handle,
            fetcher_handle
        );
    });

    info!("shutting down the runtime");
    threaded_rt.shutdown_timeout(Duration::from_millis(500).into());

    Ok(())
}
