//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub mod call_links;
mod v2;

#[cfg(test)]
pub use v2::api_server_v2_tests as v2_tests;

use std::{
    collections::HashMap, fmt::Display, net::SocketAddr, str::FromStr, sync::Arc, time::Instant,
};

use anyhow::Result;
use axum::{
    extract::{MatchedPath, Request, State},
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
    Extension, Router,
};
use axum_extra::TypedHeader;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{header, Method, StatusCode};
use log::*;
use metrics::metric_config::Tags;
use metrics::{event, metric_config::Histogram};
use tokio::sync::oneshot::Receiver;
use tower::ServiceBuilder;
use zkgroup::call_links::CreateCallLinkCredentialPresentation;

use crate::{
    api::call_links::RoomId,
    authenticator::{Authenticator, AuthenticatorError, GroupAuthToken, ParsedHeader::*},
    frontend::{Frontend, FrontendError},
};

#[derive(Default)]
pub struct ApiMetrics {
    pub latencies: HashMap<String, HashMap<Tags<String>, Histogram<u64>>>,
    pub counts: HashMap<String, HashMap<Tags<String>, u64>>,
}

impl From<FrontendError> for StatusCode {
    fn from(err: FrontendError) -> Self {
        match err {
            FrontendError::CallNotFound => StatusCode::NOT_FOUND,
            FrontendError::NoPermissionToCreateCall => StatusCode::FORBIDDEN,
            FrontendError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn get_request_path(req: &Request) -> &str {
    if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str()
    } else {
        req.uri().path()
    }
}

fn get_user_agent(req: &Request) -> Result<&str, StatusCode> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| {
            warn!(
                "get_user_agent: user agent header missing for {}",
                req.method()
            );
            StatusCode::BAD_REQUEST
        })
}

fn user_agent_event_string(user_agent: &str) -> &str {
    if user_agent.starts_with("Signal-iOS") {
        "ios"
    } else if user_agent.starts_with("Signal-Android") {
        "android"
    } else if user_agent.starts_with("Signal-Desktop") {
        if user_agent.contains("macOS") {
            "desktop.mac"
        } else if user_agent.contains("Windows") {
            "desktop.windows"
        } else if user_agent.contains("Linux") {
            "desktop.linux"
        } else {
            "desktop.unknown"
        }
    } else if user_agent.starts_with("Signal-Internal") {
        "internal"
    } else {
        "unknown"
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
    // Get the method, path, user_agent, and frontend here to avoid cloning the whole
    // request before next.run() consumes it.
    let method = req.method().as_str().to_lowercase();
    let path = get_request_path(&req).to_owned();
    let user_agent = get_user_agent(&req)?.to_string();

    let tag = if path == "/v1/call-link" || path.starts_with("/v1/call-link/") {
        "call_links.v1"
    } else if path.starts_with("/v2/") {
        "v2"
    } else {
        "unknown"
    };

    let response = next.run(req).await;

    let latency = start.elapsed();

    let mut api_metrics = frontend.api_metrics.lock();

    let _ = api_metrics
        .counts
        .entry(format!("calling.frontend.api.{}.{}", tag, method))
        .or_default()
        .entry(None)
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    let _ = api_metrics
        .counts
        .entry(format!(
            "calling.frontend.api.{}.{}.{}",
            tag,
            method,
            response.status().as_str()
        ))
        .or_default()
        .entry(None)
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    if method == "put" {
        // We only collect user_agent metrics for PUT (i.e. join).
        let _ = api_metrics
            .counts
            .entry(format!(
                "calling.frontend.api.{}.{}.user_agent.{}",
                tag,
                method,
                user_agent_event_string(&user_agent)
            ))
            .or_default()
            .entry(None)
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
    }

    api_metrics
        .latencies
        .entry(format!("calling.frontend.api.{}.{}.latency", tag, method))
        .or_default()
        .entry(None)
        .or_default()
        .push(latency.as_micros() as u64);

    Ok(response)
}

/// Middleware to handle the authorization header.
async fn authorize(
    State(frontend): State<Arc<Frontend>>,
    room_id: Option<TypedHeader<RoomId>>,
    mut req: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    trace!("authorize");

    let user_agent = get_user_agent(&req)?;

    if let Some(room_id) = room_id {
        if room_id.0.as_ref().contains(":") {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let authorization_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| {
            event!("calling.frontend.api.authorization.header.missing");
            warn!(
                "authorize: authorization header missing for {} from {}",
                req.method(),
                user_agent
            );
            StatusCode::UNAUTHORIZED
        })?;

    let authorization_header = Authenticator::parse_authorization_header(authorization_header)
        .map_err(|err| {
            event!("calling.frontend.api.authorization.header.invalid");
            warn!(
                "authorize: {} for {} from {}",
                err,
                req.method(),
                user_agent
            );
            StatusCode::BAD_REQUEST
        })?;

    match authorization_header {
        Basic(_, password) => {
            let user_authorization = frontend
                .authenticator
                .verify(
                    GroupAuthToken::from_str(&password).map_err(|err| {
                        event!("calling.frontend.api.authorization.malformed");
                        info!(
                            "authorize: malformed credentials for {} from {}: {}",
                            req.method(),
                            user_agent,
                            err
                        );
                        StatusCode::UNAUTHORIZED
                    })?,
                    &password,
                )
                .map_err(|err| {
                    event!("calling.frontend.api.authorization.unauthorized");

                    if err != AuthenticatorError::ExpiredCredentials {
                        info!(
                            "authorize: {} for {} from {}",
                            err,
                            req.method(),
                            user_agent
                        );
                    }

                    StatusCode::UNAUTHORIZED
                })?;
            req.extensions_mut().insert(user_authorization);
            Ok(next.run(req).await)
        }
        Bearer(token) => {
            let method = req.method();
            let fail_malformed = |err: &dyn Display| {
                event!("calling.frontend.api.authorization.malformed.zkcredential");
                info!(
                    "authorize: malformed credentials for {} from {}: {}",
                    method, user_agent, err
                );
                StatusCode::BAD_REQUEST
            };

            // We use '.' as a separator because it matches the "token68" charset expected for Bearer auth.
            match token.split_once('.') {
                Some(("auth", credential_base64)) => {
                    let credential_bytes = STANDARD
                        .decode(credential_base64)
                        .map_err(|e| fail_malformed(&e))?;
                    let credential: zkgroup::call_links::CallLinkAuthCredentialPresentation =
                        bincode::deserialize(&credential_bytes).map_err(|e| fail_malformed(&e))?;

                    // We can't verify the credential without the room info, so wait to see how it's used.
                    // Put the presentation in an Arc to satisfy the Clone requirement on the Extension extractor.
                    req.extensions_mut().insert(Arc::new(credential));
                    Ok(next.run(req).await)
                }
                Some(("create", credential_base64)) if req.method() == Method::PUT => {
                    let credential_bytes = STANDARD
                        .decode(credential_base64)
                        .map_err(|e| fail_malformed(&e))?;
                    let credential: zkgroup::call_links::CreateCallLinkCredentialPresentation =
                        bincode::deserialize(&credential_bytes).map_err(|e| fail_malformed(&e))?;

                    // We can't verify the credential without the room info, so wait to see how it's used.
                    // Put the presentation in an Arc to satisfy the Clone requirement on the Extension extractor.
                    req.extensions_mut().insert(Arc::new(credential));
                    Ok(next.run(req).await)
                }
                _ => {
                    event!("calling.frontend.api.authorization.header.unrecognized");
                    warn!(
                        "authorize: unrecognized token for {} from {}",
                        req.method(),
                        user_agent
                    );
                    Err(StatusCode::BAD_REQUEST)
                }
            }
        }
    }
}

async fn extra_call_link_metrics(
    State(frontend): State<Arc<Frontend>>,
    create_auth: Option<Extension<Arc<CreateCallLinkCredentialPresentation>>>,
    req: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    if create_auth.is_none() || req.method() != Method::PUT {
        return Ok(next.run(req).await);
    }

    trace!("extra_call_link_metrics");

    // Get the method and user_agent here to avoid cloning the whole
    // request before next.run() consumes it.
    let path = get_request_path(&req);
    let user_agent = get_user_agent(&req)?.to_string();

    let tag = if path == "/v1/call-link" || path.starts_with("/v1/call-link/") {
        "call_links.v1"
    } else {
        "unknown"
    };

    let response = next.run(req).await;

    // In addition to the normal metrics, break out attempts to create a new room.
    // This isn't going to match up exactly with the number of new rooms because of retries
    // and failures.
    let mut api_metrics = frontend.api_metrics.lock();

    let _ = api_metrics
        .counts
        .entry(format!(
            "calling.frontend.api.{}.create.{}",
            tag,
            response.status().as_str()
        ))
        .or_default()
        .entry(None)
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);
    let _ = api_metrics
        .counts
        .entry(format!(
            "calling.frontend.api.{}.create.user_agent.{}",
            tag,
            user_agent_event_string(&user_agent)
        ))
        .or_default()
        .entry(None)
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    Ok(response)
}

/// Handler for the GET /health route.
async fn get_health() {
    trace!("get_health():");
}

/// For any unexpected requests, return 503 without any middleware processing.
async fn unknown_request_handler() -> impl IntoResponse {
    event!("calling.frontend.api.unexpected.request");
    StatusCode::SERVICE_UNAVAILABLE
}

fn app(frontend: Arc<Frontend>) -> Router {
    let health_route = Router::new().route("/health", get(get_health));

    let sfu_routes = Router::new()
        .route(
            "/v2/conference/participants",
            get(v2::get_participants).put(v2::join),
        )
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(frontend.clone(), metrics))
                .layer(middleware::from_fn_with_state(frontend.clone(), authorize)),
        )
        .with_state(frontend.clone());

    let call_link_routes = Router::new().route(
        "/v1/call-link",
        get(call_links::read_call_link)
            .put(call_links::update_call_link)
            .delete(call_links::delete_call_link),
    );
    #[cfg(any(debug_assertions, feature = "testing"))]
    let call_link_routes = call_link_routes
        .route(
            "/v1/call-link/reset-expiration",
            axum::routing::post(call_links::reset_call_link_expiration),
        )
        .route(
            "/v1/call-link/approvals",
            axum::routing::delete(call_links::reset_call_link_approvals),
        );
    let call_link_routes = call_link_routes
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(frontend.clone(), metrics))
                .layer(middleware::from_fn_with_state(frontend.clone(), authorize))
                .layer(middleware::from_fn_with_state(
                    frontend.clone(),
                    extra_call_link_metrics,
                )),
        )
        .with_state(frontend);

    Router::new()
        .merge(health_route)
        .merge(sfu_routes)
        .merge(call_link_routes)
        .fallback(unknown_request_handler)
}

pub async fn start(frontend: Arc<Frontend>, ender_rx: Receiver<()>) -> Result<()> {
    let addr = SocketAddr::new(frontend.config.server_ip, frontend.config.server_port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let server =
        axum::serve(listener, app(frontend).into_make_service()).with_graceful_shutdown(async {
            let _ = ender_rx.await;
        });

    info!("api ready: {}", addr);
    if let Err(err) = server.await {
        error!("api server returned: {}", err);
    }

    info!("api shutdown");
    Ok(())
}
