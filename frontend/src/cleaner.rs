//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Result;
use calling_common::Duration;
use futures::future::join_all;
use log::*;
use metrics::{event, metric_config::Timer, start_timer_us};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tokio::sync::{oneshot::Receiver, Semaphore};

use crate::storage::CallRecordKey;
use crate::{
    backend::{self, Backend, BackendError, BackendHttpClient},
    config,
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
                .get_clients(&backend_address, &call_record.era_id, None)
                .await
            {
                if let BackendError::CallNotFound = err {
                    event!("calling.frontend.cleaner.get.clients.call_not_found");
                } else {
                    error!("failed to get clients from backend: {:?}", err);
                    event!("calling.frontend.cleaner.get.clients.backend_error");
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

    let storage = Arc::new(DynamoDb::new(config).await?);
    let backend = Arc::new(BackendHttpClient::from_config(config).await?);

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
                Ok(calls) if !calls.is_empty() => {
                    debug!("Found {} calls in table!", calls.len());

                    let calls_to_remove = Arc::new(Mutex::new(Vec::new()));

                    // Create a list of handles for requests to the backend, limited by semaphore to 10 at a time.
                    let mut join_handles = vec![];
                    let permits = Arc::new(Semaphore::new(10));
                    for call_record in calls {
                        let backend = Arc::clone(&backend);
                        let calls_to_remove = Arc::clone(&calls_to_remove);
                        let permits = permits.clone();

                        join_handles.push(async move {
                            let permit = permits.acquire().await;
                            if permit.is_ok()
                                && !does_call_exist_on_backend(&call_record, &backend).await
                            {
                                calls_to_remove.lock().push(CallRecordKey {
                                    room_id: call_record.room_id,
                                    era_id: call_record.era_id,
                                });
                            }
                        });
                    }
                    join_all(join_handles).await;

                    let calls_to_remove = {
                        let mut guard = calls_to_remove.lock();
                        let calls: &mut Vec<_> = &mut guard;
                        std::mem::take(calls)
                    };
                    debug!("Found {} calls to cleanup!", calls_to_remove.len());

                    for call_record_key in &calls_to_remove {
                        info!(
                            "Cleaning up call: {} - {:.6}",
                            call_record_key.room_id, call_record_key.era_id
                        );
                    }

                    for chunk in calls_to_remove.chunks(100) {
                        info!("attempting to batch delete {} calls", chunk.len());

                        // Remove the calls from the database since they don't exist anymore
                        // on a Calling Backend (or there was an *error* accessing it).
                        if let Err(err) = storage.remove_batch_call_records(chunk.to_vec()).await {
                            error!("failed remove_batch_call_records: {}", err);

                            // There was a problem with the batch removal, try to remove each separately.
                            for call_record_key in chunk {
                                if let Err(err) = storage
                                    .remove_call_record(
                                        &call_record_key.room_id,
                                        &call_record_key.era_id,
                                    )
                                    .await
                                {
                                    error!("{:?}", err);
                                }
                            }
                        }
                    }
                }
                Ok(_) => {
                    debug!("Found 0 calls in table!");
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

#[cfg(test)]
mod tests {
    use calling_common::{random_hex_string, RoomId};

    use crate::config::default_test_config;

    use super::*;

    // Run this test manually to load several call records into local storage.
    // 1. Run the docker compose environment
    // 2. Run this test function
    // 3. Watch for the cleaner results
    #[tokio::test]
    #[ignore]
    async fn test_inject_random_records() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;

        for _ in 0..1000 {
            let call_record = CallRecord {
                room_id: RoomId::from(random_hex_string(32)),
                era_id: random_hex_string(32),
                backend_ip: "192.168.0.126".to_string(),
                backend_region: "us-west1".to_string(),
                creator: random_hex_string(32),
            };

            let _ = storage.get_or_add_call_record(call_record).await?;
        }

        Ok(())
    }
}
