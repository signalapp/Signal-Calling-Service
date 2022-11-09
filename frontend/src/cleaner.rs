//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use anyhow::Result;
use calling_common::Duration;
use log::*;
use rand::{thread_rng, Rng};
use tokio::sync::oneshot::Receiver;

use crate::{
    frontend::{Frontend, FrontendError},
    metrics::Timer,
};

pub async fn start(frontend: Arc<Frontend>, ender_rx: Receiver<()>) -> Result<()> {
    let cleanup_interval = Duration::from_millis(frontend.config.cleanup_interval_ms);

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

            if let Ok(calls) = frontend
                .get_call_records_for_region(&frontend.config.region)
                .await
            {
                for call_record in calls {
                    // For each call record, get the list of clients currently in that call from
                    // the backend. If the backend server is available and reports that the call
                    // is not found, it can be removed from storage. If there is a problem
                    // accessing the backend, we assume the server does not exist anymore or
                    // otherwise isn't working correctly and still remove it from storage.
                    if let Err(err) = frontend.get_client_ids_in_call(&call_record).await {
                        info!(
                            "Cleaning up call: {} - {:.6}",
                            call_record.group_id, call_record.call_id
                        );

                        // Remove the call since it doesn't exist anymore.
                        let _ = frontend
                            .remove_call_record(&call_record.group_id, &call_record.call_id)
                            .await;

                        // Log metrics for either disposition: not found or access error.
                        if err == FrontendError::CallNotFound {
                            event!("calling.frontend.cleaner.get.clients.call_not_found");
                        } else {
                            event!("calling.frontend.cleaner.get.clients.backend_unavailable");
                        }
                    }
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
