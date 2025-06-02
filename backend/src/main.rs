//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[macro_use]
extern crate log;

use std::{
    fs::File,
    io::BufReader,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::Result;
use calling_backend::{
    call_lifecycle, config, http_server, metrics_server, packet_server, sfu::Sfu, signaling_server,
};
use calling_common::{DataRate, Duration, Instant};
use clap::Parser;
use env_logger::Env;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rlimit::increase_nofile_limit;
use rustls::{server::NoServerSessionStorage, version::TLS13, ServerConfig};
use tokio::{
    runtime,
    signal::unix::{signal, SignalKind},
    sync::{mpsc, oneshot},
};

// Load the config and treat it as a read-only static value.
static CONFIG: Lazy<config::Config> = Lazy::new(config::Config::parse);
const MONITOR_DEADLOCK_INTERVAL: Duration = Duration::from_secs(5);

#[rustfmt::skip]
fn print_config(config: &'static config::Config) {
    info!("config:");
    info!("  {:38}{}", "binding_ip:", config.binding_ip);
    info!("  {:38}{:?}", "ice_candidate_ip:", config.ice_candidate_ip);
    info!("  {:38}{}", "ice_candidate_port:", config.ice_candidate_port);
    info!("  {:38}{}", "ice_candidate_port_tcp:", config.ice_candidate_port_tcp);
    info!("  {:38}{:?}", "signaling_ip:", config.signaling_ip);
    info!("  {:38}{}", "signaling_port:", config.signaling_port);
    info!("  {:38}{}", "max_clients_per_call:", config.max_clients_per_call);
    info!("  {:38}{} ({})", "initial_target_send_rate_kbps:", config.initial_target_send_rate_kbps, DataRate::from_kbps(config.initial_target_send_rate_kbps));
    info!("  {:38}{}", "tick_interval_ms:", config.tick_interval_ms);
    info!("  {:38}{}", "outgoing_queue_drain_ms:", config.outgoing_queue_drain_ms);
    info!("  {:38}{:?}", "diagnostics_interval_secs:", config.diagnostics_interval_secs);
    info!("  {:38}{}", "inactivity_check_interval_secs:", config.inactivity_check_interval_secs);
    info!("  {:38}{}", "inactivity_timeout_secs:", config.inactivity_timeout_secs);
    info!("  {:38}{}", "datadog metrics:",
          match &config.metrics.datadog {
              Some(host) => host,
              None => "Off",
          });
    if config.ice_candidate_port_tls.is_some() {
        info!("  {:38}{:?}", "ice_candidate_port_tls:", config.ice_candidate_port_tls);
        info!("  {:38}{:?}", "hostname:", config.hostname);
        info!("  {:38}{:?}", "certificate_file_path:", config.certificate_file_path);
        info!("  {:38}{:?}", "key_file_path:", config.key_file_path);
    }
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
            .default_filter_or("calling_backend=info")
            .default_write_style_or("never"),
    )
    .format(calling_common::format_log_line)
    .init();

    info!("Signal Calling Backend starting up...");

    // Log information about the environment we are running in.
    info!(
        "calling_backend: v{}",
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

    let fd_limit =
        increase_nofile_limit(rlimit::INFINITY).expect("should be able to set RLIMIT_NOFILE");
    info!("FD limit: {}", fd_limit);

    let tls_config = if config.ice_candidate_port_tls.is_some()
        && config.hostname.is_some()
        && config.certificate_file_path.is_some()
        && config.key_file_path.is_some()
    {
        let certificates = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(
            config
                .certificate_file_path
                .as_ref()
                .expect("must have a certificate file path"),
        )?))
        .collect::<Result<Vec<_>, _>>()?;
        let private_key = rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(
            config
                .key_file_path
                .as_ref()
                .expect("must have a key file path"),
        )?))?;

        let mut tls_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key.expect("must have a private key"))?;
        // Explicitly disable TLS sessions and tickets, WebRTC does not use them, so don't waste bandwidth
        tls_config.session_storage = Arc::new(NoServerSessionStorage {});
        tls_config.max_early_data_size = 0;
        tls_config.send_tls13_tickets = 0;

        Some(Arc::new(tls_config))
    } else {
        if config.ice_candidate_port_tls.is_some()
            || config.hostname.is_some()
            || config.certificate_file_path.is_some()
            || config.key_file_path.is_some()
        {
            panic!("For TLS, all values must be set: ice-candidate-port-tls, hostname, certificate-file-path, key-file-path");
        }
        None
    };

    let csel_opts = &config.candidate_selector_options;
    if csel_opts.rtt_limit < 0.0
        || csel_opts.rtt_max_penalty < 0.0
        || csel_opts.rtt_sensitivity < 0.0
    {
        panic!("rtt-limit, rtt-max-penalty, and rtt-sensitivity must be greater than 0");
    }

    let (deadlock_monitor_ender_tx, deadlock_monitor_ender_rx) = std::sync::mpsc::channel();
    let deadlock_monitor_handle =
        metrics::monitor_deadlocks(MONITOR_DEADLOCK_INTERVAL.into(), deadlock_monitor_ender_rx);

    // Create the shared SFU context.
    let sfu: Arc<RwLock<Sfu>> = Arc::new(RwLock::new(Sfu::new(Instant::now(), config)?));

    // Create a threaded tokio runtime. By default, starts a worker thread
    // for each core on the system.
    let threaded_rt = runtime::Runtime::new()?;

    let (signaling_ender_tx, signaling_ender_rx) = oneshot::channel();
    let (packet_ender_tx, packet_ender_rx) = oneshot::channel();
    let (metrics_ender_tx, metrics_ender_rx) = oneshot::channel();
    let (call_lifecycle_ender_tx, call_lifecycle_ender_rx) = oneshot::channel();
    let (signal_canceller_tx, signal_canceller_rx) = mpsc::channel(1);
    let is_healthy = Arc::new(AtomicBool::new(true));

    let sfu_clone_for_packet = sfu.clone();
    let sfu_clone_for_metrics = sfu.clone();
    let sfu_clone_for_call_lifecycle = sfu.clone();
    let signal_canceller_tx_clone_for_packet = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_metrics = signal_canceller_tx.clone();
    let signal_canceller_tx_clone_for_call_lifecycle = signal_canceller_tx.clone();
    let is_healthy_clone_for_packet = is_healthy.clone();

    threaded_rt.block_on(async {
        // Start the signaling server, either the signaling_server for production
        // or the http_server for testing.
        let signaling_server_handle = tokio::spawn(async move {
            let start_result = if config.signaling_ip.is_some() {
                signaling_server::start(config, sfu, signaling_ender_rx, is_healthy).await
            } else {
                http_server::start(config, sfu, signaling_ender_rx).await
            };
            if let Err(err) = start_result {
                error!("server start error: {}", err);
            }

            let _ = signal_canceller_tx.send(()).await;
        });

        // Start the packet_server.
        let packet_server_handle = tokio::spawn(async move {
            if let Err(err) = packet_server::start(
                config,
                tls_config,
                sfu_clone_for_packet,
                packet_ender_rx,
                is_healthy_clone_for_packet,
            )
            .await
            {
                error!("packet server shutdown {:?}", err);
            }
            let _ = signal_canceller_tx_clone_for_packet.send(()).await;
        });

        // Start the metrics_server.
        let metrics_server_handle = tokio::spawn(async move {
            let _ = metrics_server::start(
                config,
                sfu_clone_for_metrics,
                metrics_ender_rx,
                fd_limit as usize,
            )
            .await;
            let _ = signal_canceller_tx_clone_for_metrics.send(()).await;
        });

        // Start the call lifecycle task that manages call hangups off of sfu tick execution.
        let call_lifecycle_handle = tokio::spawn(async move {
            let _ = call_lifecycle::start(
                config,
                sfu_clone_for_call_lifecycle,
                call_lifecycle_ender_rx,
            )
            .await;
            let _ = signal_canceller_tx_clone_for_call_lifecycle.send(()).await;
        });

        // Wait for any signals to be detected, or cancel due to one of the
        // servers not being able to be started (the channel is buffered).
        wait_for_signal(signal_canceller_rx).await;

        // Gracefully exit the servers if needed.
        let _ = signaling_ender_tx.send(());
        let _ = packet_ender_tx.send(());
        let _ = metrics_ender_tx.send(());
        let _ = call_lifecycle_ender_tx.send(());
        let _ = deadlock_monitor_ender_tx.send(());

        // Wait for the servers to exit.
        let _ = tokio::join!(
            signaling_server_handle,
            packet_server_handle,
            metrics_server_handle,
            call_lifecycle_handle,
        );
        let _ = deadlock_monitor_handle.join();
    });

    info!("shutting down the runtime");
    threaded_rt.shutdown_timeout(Duration::from_millis(500).into());

    Ok(())
}
