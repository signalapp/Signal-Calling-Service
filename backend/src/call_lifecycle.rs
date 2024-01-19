//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//
use log::*;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::{sync::mpsc, sync::oneshot::Receiver};

use crate::{
    call::LoggableCallId,
    config,
    frontend::{CallKey, Frontend, FrontendHttpClient},
    sfu::Sfu,
};

const CALL_REMOVAL_QUEUE_CAPACITY: usize = 2048;

/// Start the lifecycle server. Sets the SFU call_end_handler.
/// If the SFU can no longer interact with the lifecycle server,
/// the lifecycle server will shutdown. We ignore failures in the
/// SFU call_end_handler to avoid blocking the SFU tick thread.
/// We attempt to remove call records in batches.
/// On failure, we issue error metrics and discard the call keys.
pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    shutdown_signal_rx: Receiver<()>,
) -> anyhow::Result<()> {
    let (call_removal_queue_tx, mut call_removal_queue_rx) =
        mpsc::channel(CALL_REMOVAL_QUEUE_CAPACITY);
    let frontend_client = FrontendHttpClient::from_config(config);

    sfu.lock()
        .set_call_ended_handler(Box::new(move |call_id, call| {
            if call.room_id().is_none() {
                event!("hangup with no room_id, leaving for cleaner");
                return Ok(());
            }

            let key = CallKey {
                room_id: call.room_id().unwrap().clone(),
                call_id: call_id.clone(),
            };

            if let Err(err) = call_removal_queue_tx.try_send(key) {
                error!("Failed to send call removal to queue: {}", err);
            }
            info!("call: {} queued for delete", LoggableCallId::from(call_id));
            Ok(())
        }));

    // Yield until there are calls in removal queue. Collect call keys into
    // buffer. Attempt to delete them in batches. On batch failure, issue
    // serial deletes. Log any final errors. Discard keys that fail to delete.
    let tick_handle = tokio::spawn(async move {
        let mut pacing = tokio::time::interval(tokio::time::Duration::from_millis(10));
        let mut delete_buffer: Vec<CallKey> = Vec::with_capacity(CALL_REMOVAL_QUEUE_CAPACITY);
        info!("call_lifecycle started, delete buffer with capacity {}", delete_buffer.capacity());

        loop {
            if let Some(key) = call_removal_queue_rx.recv().await {
                delete_buffer.push(key);
            } else {
                // channel unexpectedly closed, breakout of loop and start shutdown
                break;
            }

            while let Ok(key) = call_removal_queue_rx.try_recv() {
                delete_buffer.push(key);
                if delete_buffer.len() == delete_buffer.capacity() {
                    break;
                }
            }

            for chunk in delete_buffer.chunks(FrontendHttpClient::MAX_BATCH_SIZE) {
                info!("attempting to batch delete {} calls", chunk.len());
                if let Err(err) = frontend_client.remove_batch_call_records(chunk).await {
                    warn!("failed to batch remove calls: {:?}", err);
                    for key in chunk {
                        if let Err(err) = frontend_client.remove_call_record(key).await {
                            error!(
                                "failed to remove call '{}': {:?}'",
                                LoggableCallId::from(&key.call_id),
                                err
                            );
                        }
                        pacing.tick().await;
                    }
                }
            }
            delete_buffer.clear();
        }
    });

    tokio::select!(
        _ = tick_handle => {},
        _ = shutdown_signal_rx => {},
    );

    info!("call_lifecycle shutdown");

    Ok(())
}
