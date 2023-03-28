//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Result;
use calling_common::Duration;
use log::*;
use rand::{thread_rng, Rng};
use tokio::sync::oneshot::Receiver;

use crate::{
    backend::{self, Backend, BackendError, BackendHttpClient},
    config,
    metrics::Timer,
    storage::{CallRecord, DynamoDb, Storage},
};

/// Returns true if the call is currently being handled by the associated Calling Backend.
async fn does_call_exist_on_backend(call_record: &CallRecord, backend: &BackendHttpClient) -> bool {
    // Get the direct address to the Calling Backend from the call record.
    match backend::Address::try_from(&call_record.backend_ip) {
        Err(err) => {
            error!("failed to parse backend_ip: {:?}", err);

            // If the ip is badly formatted, the call should not be in the database.
            false
        }
        Ok(backend_address) => {
            if let Err(err) = backend
                .get_clients(&backend_address, &call_record.era_id)
                .await
            {
                match err {
                    BackendError::CallNotFound => {
                        event!("calling.frontend.cleaner.get.clients.call_not_found");
                    }
                    _ => {
                        error!("failed to get clients from backend: {:?}", err);
                        event!("calling.frontend.cleaner.get.clients.backend_error");
                    }
                }

                // The Calling Backend is not handling the call or there was an unexpected error.
                false
            } else {
                // The call exists on the Calling Backend.
                true
            }
        }
    }
}

pub async fn start(config: &'static config::Config, ender_rx: Receiver<()>) -> Result<()> {
    let cleanup_interval = Duration::from_millis(config.cleanup_interval_ms);

    let storage = Box::new(DynamoDb::new(config).await?);
    let backend = Box::new(BackendHttpClient::from_config(config).await?);

    // Spawn a normal (cooperative) task to cleanup calls from storage periodically.
    let cleaner_handle = tokio::spawn(async move {
        loop {
            // Add up to 5% delay on the cleanup interval
            // so that instances started simultaneously don't try to clean simultaneously.
            let jitter = (cleanup_interval / 100) * thread_rng().gen_range(0..=5);

            // Use sleep() instead of interval() so that we never wait *less* than one
            // interval to do the next tick.
            tokio::time::sleep((cleanup_interval + jitter).into()).await;

            let cleaner_timer = start_timer_us!("calling.frontend.cleaner.timed");

            match storage.get_call_records_for_region(&config.region).await {
                Ok(calls) => {
                    for call_record in calls {
                        if !does_call_exist_on_backend(&call_record, &backend).await {
                            info!(
                                "Cleaning up call: {} - {:.6}",
                                call_record.room_id, call_record.era_id
                            );

                            // Remove the call from the database since it doesn't exist anymore
                            // on the Calling Backend (or there is an *error* accessing it).
                            if let Err(err) = storage
                                .remove_call_record(&call_record.room_id, &call_record.era_id)
                                .await
                            {
                                error!("{:?}", err);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("{:?}", err);
                }
            }

            cleaner_timer.stop();
        }
    });

    info!("cleaner ready");

    // Wait for any task to complete and cancel the rest.
    tokio::select!(
        _ = cleaner_handle => {},
        _ = ender_rx => {},
    );

    info!("cleaner shutdown");
    Ok(())
}
