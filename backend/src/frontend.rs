//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{config, sfu::CallId};
use async_trait::async_trait;
use calling_common::RoomId;
use futures::TryFutureExt;
use hex::ToHex;
use hyper::{
    client::HttpConnector,
    header, Method, Request, Uri, {Body, Client as HttpClient},
};
use log::*;
use serde::Serialize;
use std::time::Duration;

/// Used to send call key into removal queue
#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CallKey {
    pub room_id: RoomId,
    /// CallId is referred to as EraId in the frontend
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
    operation_timeout: Duration,
    http_client: HttpClient<HttpConnector>,
    remove_call_records_base_url: Option<Uri>,
}

impl FrontendHttpClient {
    pub fn from_config(config: &'static config::Config) -> Self {
        let operation_timeout = Duration::from_millis(config.frontend_operation_timeout_ms);
        let http_client = HttpClient::builder().build_http();
        let remove_call_records_base_url = config.remove_call_records_base_url.clone();

        Self {
            operation_timeout,
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
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(url)
            .body(Body::empty())
            .unwrap();
        let future = tokio::time::timeout(
            self.operation_timeout,
            self.http_client
                .request(request)
                .map_err(anyhow::Error::from),
        );

        match future.await {
            Ok(response) => match response {
                Ok(_) => Ok(()),
                Err(err) => Err(FrontendError::UnexpectedError(err)),
            },
            _ => Err(FrontendError::Timeout),
        }
    }

    async fn remove_batch_call_records(&self, call_keys: &[CallKey]) -> Result<(), FrontendError> {
        let Some(base_url) = self.remove_call_records_base_url.as_ref() else {
            return Err(FrontendError::ClientNotConfigured);
        };
        let url = format!("{}", base_url);
        let body = serde_json::to_vec(&RemoveBatchCallRecordsRequest { call_keys }).unwrap();
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let future = tokio::time::timeout(
            self.operation_timeout,
            self.http_client
                .request(request)
                .map_err(anyhow::Error::from),
        );

        match future.await {
            Ok(response) => match response {
                Ok(_) => Ok(()),
                Err(err) => Err(FrontendError::UnexpectedError(err)),
            },
            _ => Err(FrontendError::Timeout),
        }
    }
}
