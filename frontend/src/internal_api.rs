//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{collections::HashMap, net::SocketAddr, str, sync::Arc, time::Instant};

use anyhow::Result;
use axum::{
    extract::{MatchedPath, Path, Request, State},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use axum_extra::TypedHeader;
use http::StatusCode;
use log::*;
use metrics::{event, metric_config::Histogram};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Receiver;
use tower::ServiceBuilder;

use crate::{
    api::call_links::RoomId,
    frontend::Frontend,
    storage::{CallLinkUpdateError, CallRecordKey},
};

#[derive(Default)]
pub struct ApiMetrics {
    pub latencies: HashMap<String, Histogram<u64>>,
    pub counts: HashMap<String, u64>,
}

fn get_request_path(req: &Request) -> &str {
    if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str()
    } else {
        req.uri().path()
    }
}

/// Middleware to process metrics after a response is sent.
async fn metrics(
    State(frontend): State<Arc<Frontend>>,
    req: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    trace!("metrics");

    let start = Instant::now();
    // Get the method and path here to avoid cloning the whole
    // request before next.run() consumes it.
    let method = req.method().as_str().to_lowercase();
    let path = get_request_path(&req);

    let tag = if path.starts_with("/v1/call-link-approvals") {
        "call_link_approvals"
    } else if path == "/v2/conference" {
        "conference_batch"
    } else if path.starts_with("/v2/conference/") {
        "conference"
    } else {
        "unknown"
    };

    let response = next.run(req).await;

    let latency = start.elapsed();

    let mut api_metrics = frontend.api_metrics.lock();

    let _ = api_metrics
        .counts
        .entry(format!("calling.frontend.internal_api.{}.{}", tag, method))
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    let _ = api_metrics
        .counts
        .entry(format!(
            "calling.frontend.internal_api.{}.{}.{}",
            tag,
            method,
            response.status().as_str()
        ))
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    let latencies = api_metrics
        .latencies
        .entry(format!(
            "calling.frontend.internal_api.{}.{}.latency",
            tag, method
        ))
        .or_insert_with(Histogram::default);
    latencies.push(latency.as_micros() as u64);

    Ok(response)
}

/// Handler for the GET /health route.
async fn get_health() {
    trace!("get_health():");
}

/// For any unexpected requests, return 503 without any middleware processing.
async fn unknown_request_handler() -> impl IntoResponse {
    event!("calling.frontend.internal_api.unexpected.request");
    StatusCode::SERVICE_UNAVAILABLE
}

fn app(frontend: Arc<Frontend>) -> Router {
    let health_route = Router::new().route("/health", get(get_health));

    let approval_route = Router::new()
        .route("/v1/call-link-approvals", put(update_approval))
        .layer(
            ServiceBuilder::new().layer(middleware::from_fn_with_state(frontend.clone(), metrics)),
        )
        .with_state(frontend.clone());

    let remove_calls_route = Router::new()
        .route("/v2/conference", delete(remove_batch_call_records))
        .route(
            "/v2/conference/:room_id/:era_id",
            delete(remove_call_record),
        )
        .layer(
            ServiceBuilder::new().layer(middleware::from_fn_with_state(frontend.clone(), metrics)),
        )
        .with_state(frontend);

    Router::new()
        .merge(health_route)
        .merge(approval_route)
        .merge(remove_calls_route)
        .fallback(unknown_request_handler)
}

pub async fn start(frontend: Arc<Frontend>, ender_rx: Receiver<()>) -> Result<()> {
    match frontend.config.internal_api_port {
        None => {
            info!("internal api disabled: port not configured");
            let _ = ender_rx.await;
        }
        Some(port) => {
            let addr = SocketAddr::new(frontend.config.internal_api_ip, port);

            let listener = tokio::net::TcpListener::bind(addr).await?;
            let server = axum::serve(listener, app(frontend).into_make_service())
                .with_graceful_shutdown(async {
                    let _ = ender_rx.await;
                });

            info!("internal api ready: {}", addr);
            if let Err(err) = server.await {
                error!("internal api server returned: {}", err);
            }
        }
    }

    info!("internal api shutdown");
    Ok(())
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedUsers {
    pub approved_users: Vec<String>,
}

pub async fn update_approval(
    State(frontend): State<Arc<Frontend>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
    Json(request): Json<ApprovedUsers>,
) -> Result<impl IntoResponse, StatusCode> {
    let room_id = room_id.into();

    match frontend
        .storage
        .update_call_link_approved_users(&room_id, request.approved_users)
        .await
    {
        Ok(_) => Ok(Json("ok")),
        Err(CallLinkUpdateError::RoomDoesNotExist) => {
            error!("update_approval: room does not exist");
            Err(StatusCode::NOT_FOUND)
        }
        Err(err) => {
            error!("update_approval: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RemoveBatchCallRecordsRequest {
    pub call_keys: Vec<CallRecordKey>,
}

/// Removes a call record in the database. If the record does not exist, returns success.
pub async fn remove_call_record(
    State(frontend): State<Arc<Frontend>>,
    Path((room_id, era_id)): Path<(calling_common::RoomId, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    if room_id.as_ref().is_empty() || era_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match frontend.storage.remove_call_record(&room_id, &era_id).await {
        Ok(_) => Ok(Json("ok")),
        Err(err) => {
            error!("remove_call_record: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Attempts to remove a batch of call records in the database. All or nothing operation.
/// Caller should issue serial deletes if the batch fails.
pub async fn remove_batch_call_records(
    State(frontend): State<Arc<Frontend>>,
    Json(request): Json<RemoveBatchCallRecordsRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if request.call_keys.is_empty() {
        return Ok(Json("ok"));
    }

    match frontend
        .storage
        .remove_batch_call_records(request.call_keys)
        .await
    {
        Ok(_) => Ok(Json("ok")),
        Err(err) => {
            error!("failed remove_batch_call_records: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
