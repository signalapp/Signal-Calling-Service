//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use async_trait::async_trait;
use calling_common::RoomId;
use hex::ToHex;
use log::*;
use reqwest::Url;
use serde::Serialize;

use crate::{config, sfu::CallId};

/// Used to send call key into removal queue
#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CallKey {
    pub room_id: RoomId,
    /// CallId is referred to as EraId in the frontend
    #[serde(rename = "eraId")]
    pub call_id: CallId,
}

#[derive(thiserror::Error, Debug)]
pub enum FrontendError {
    #[error("no frontend URI provided")]
    ClientNotConfigured,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
    #[error("timeout")]
    Timeout,
}

/// Frontend represents the internal API hosted on the frontend
#[async_trait]
pub trait Frontend: Sync + Send {
    const MAX_BATCH_SIZE: usize = 100;

    /// Remove call record. Returns success if record was removed or not found.
    async fn remove_call_record(&self, call_key: &CallKey) -> Result<(), FrontendError>;

    /// All or nothing operation. Fails entire batch if one call fails or is not found.
    /// Call remove_call_record() for each call key in batch after a failure.
    async fn remove_batch_call_records(&self, call_keys: &[CallKey]) -> Result<(), FrontendError>;
}

pub struct FrontendHttpClient {
    http_client: reqwest::Client,
    remove_call_records_base_url: Option<Url>,
}

impl FrontendHttpClient {
    pub fn from_config(config: &'static config::Config) -> Self {
        let operation_timeout = Duration::from_millis(config.frontend_operation_timeout_ms);
        let http_client = reqwest::Client::builder()
            .timeout(operation_timeout)
            .build()
            .unwrap();
        let remove_call_records_base_url = config.remove_call_records_base_url.clone();

        Self {
            http_client,
            remove_call_records_base_url,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveBatchCallRecordsRequest<'a> {
    pub call_keys: &'a [CallKey],
}

#[async_trait]
impl Frontend for FrontendHttpClient {
    async fn remove_call_record(&self, call_key: &CallKey) -> Result<(), FrontendError> {
        let Some(base_url) = self.remove_call_records_base_url.as_ref() else {
            return Err(FrontendError::ClientNotConfigured);
        };
        let url = format!(
            "{}/{}/{}",
            base_url,
            call_key.room_id,
            call_key.call_id.as_slice().encode_hex::<String>()
        );
        let result = self.http_client.delete(url).send().await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    let res_body =
                        String::from_utf8(bytes.into()).expect("Could not parse body as UTF-8");
                    Err(FrontendError::UnexpectedError(anyhow::anyhow!(
                        "Received non-success response. status={:?}, body={:?}",
                        status,
                        res_body
                    )))
                }
            }
            Err(err) if err.is_timeout() => Err(FrontendError::Timeout),
            Err(err) => Err(FrontendError::UnexpectedError(anyhow::Error::from(err))),
        }
    }

    async fn remove_batch_call_records(&self, call_keys: &[CallKey]) -> Result<(), FrontendError> {
        let Some(base_url) = self.remove_call_records_base_url.as_ref() else {
            return Err(FrontendError::ClientNotConfigured);
        };

        let result = self
            .http_client
            .delete(base_url.clone())
            .json(&RemoveBatchCallRecordsRequest { call_keys })
            .send()
            .await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    let res_body =
                        String::from_utf8(bytes.into()).expect("Could not parse body as UTF-8");
                    Err(FrontendError::UnexpectedError(anyhow::anyhow!(
                        "Received non-success response. status={:?}, body={:?}",
                        status,
                        res_body
                    )))
                }
            }
            Err(err) if err.is_timeout() => Err(FrontendError::Timeout),
            Err(err) => Err(FrontendError::UnexpectedError(anyhow::Error::from(err))),
        }
    }
}
