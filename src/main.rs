//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;
use calling_server::{
    common::{DataRate, Duration, Instant},
    config, http_server, metrics_server,
    sfu::Sfu,
    signaling_server, udp_server,
};
use env_logger::Env;
use parking_lot::Mutex;
use structopt::StructOpt;
use tokio::{
    runtime,
    signal::unix::{signal, SignalKind},
    sync::{mpsc, oneshot},
};

lazy_static! {
    // Load the config and treat it as a read-only static value.
    static ref CONFIG: config::Config = config::Config::from_args();
}

#[rustfmt::skip]
fn print_config(config: &'static config::Config) {
    info!("config:");
    info!("  {:38}{}", "binding_ip:", config.binding_ip);
    info!("  {:38}{:?}", "ice_candidate_ip:", config.ice_candidate_ip);
    info!("  {:38}{}", "ice_candidate_port:", config.ice_candidate_port);
    info!("  {:38}{:?}", "signaling_ip:", config.signaling_ip);
    info!("  {:38}{}", "signaling_port:", config.signaling_port);
    info!("  {:38}{}", "max_clients_per_call:", config.max_clients_per_call);
    info!("  {:38}{} ({})", "initial_target_send_rate_kbps:", config.initial_target_send_rate_kbps, DataRate::from_kbps(config.initial_target_send_rate_kbps));
    info!("  {:38}{}", "tick_interval_ms:", config.tick_interval_ms);
    info!("  {:38}{:?}", "diagnostics_interval_secs:", config.diagnostics_interval_secs);
    info!("  {:38}{}", "active_speaker_message_interval_ms:", config.active_speaker_message_interval_ms);
    info!("  {:38}{}", "inactivity_check_interval_secs:", config.inactivity_check_interval_secs);
    info!("  {:38}{}", "inactivity_timeout_secs:", config.inactivity_timeout_secs);
    info!("  {:38}{}", "datadog metrics:",
          match &config.metrics.datadog {
              Some(host) => host,
              None => "Off",
          });
}

/// Waits for a SIGINT or SIGTERM signal and returns. Can be cancelled
/// by sending something to the channel.
pub async fn wait_for_signal(mut canceller: mpsc::Receiver<()>) {
    tokio::select!(
        _ = async {
            if let Ok(mut stream) = signal(SignalKind::interrupt()) {
                stream.recv().await;
            }
        } => {
            // Handle SIGINT for ctrl+c and debug stop command.
            info!("terminating by signal: SIGINT");
        },
        _ = async {
            if let Ok(mut stream) = signal(SignalKind::terminate()) {
                stream.recv().await;
            }
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
            .default_filter_or("calling_server=info")
            .default_write_style_or("never"),
    )
    .format_timestamp_millis()
    .init();

    info!("Signal Calling Server starting up...");

    // Log information about the environment we are running in.
    info!(
        "calling_server: v{}",
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

    // Create the shared SFU context.
    let sfu: Arc<Mutex<Sfu>> = Arc::new(Mutex::new(Sfu::new(Instant::now(), config)?));

    // Create a threaded tokio runtime. By default, starts a worker thread
    // for each core on the system.
    let threaded_rt = runtime::Runtime::new()?;

    let (signaling_ender_tx, signaling_ender_rx) = oneshot::channel();
    let (udp_ender_tx, udp_ender_rx) = oneshot::channel();
    let (metrics_ender_tx, metrics_ender_rx) = oneshot::channel();
    let (signal_canceller_tx, signal_canceller_rx) = mpsc::channel(1);
    let is_healthy = Arc::new(AtomicBool::new(true));

    let sfu_clone_for_udp = sfu.clone();
    let sfu_clone_for_metrics = sfu.clone();
    let signal_canceller_tx_clone_for_udp = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_metrics = signal_canceller_tx.clone();
    let is_healthy_clone_for_udp = is_healthy.clone();

    let _ = threaded_rt.block_on(async {
        // Start the signaling server, either the signaling_server for production
        // or the http_server for testing.
        let signaling_server_handle = tokio::spawn(async move {
            if config.signaling_ip.is_some() {
                let _ = signaling_server::start(config, sfu, signaling_ender_rx, is_healthy).await;
            } else {
                let _ = http_server::start(config, sfu, signaling_ender_rx).await;
            }
            let _ = signal_canceller_tx.send(()).await;
        });

        // Start the udp_server.
        let udp_server_handle = tokio::spawn(async move {
            let _ = udp_server::start(
                config,
                sfu_clone_for_udp,
                udp_ender_rx,
                is_healthy_clone_for_udp,
            )
            .await;
            let _ = signal_canceller_tx_clone_for_udp.send(()).await;
        });

        // Start the metrics_server.
        let metrics_server_handle = tokio::spawn(async move {
            let _ = metrics_server::start(config, sfu_clone_for_metrics, metrics_ender_rx).await;
            let _ = signal_canceller_tx_clone_for_metrics.send(()).await;
        });

        // Wait for any signals to be detected, or cancel due to one of the
        // servers not being able to be started (the channel is buffered).
        let _ = wait_for_signal(signal_canceller_rx).await;

        // Gracefully exit the servers if needed.
        let _ = signaling_ender_tx.send(());
        let _ = udp_ender_tx.send(());
        let _ = metrics_ender_tx.send(());

        // Wait for the servers to exit.
        let _ = tokio::join!(
            signaling_server_handle,
            udp_server_handle,
            metrics_server_handle,
        );
    });

    info!("shutting down the runtime");
    threaded_rt.shutdown_timeout(Duration::from_millis(500).into());

    Ok(())
}
