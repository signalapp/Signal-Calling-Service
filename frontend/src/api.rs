//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

mod call_links;
mod v2;

use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use anyhow::Result;
use axum::{
    extract::{MatchedPath, State},
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
    Extension, Router,
};
use http::{header, Method, Request, StatusCode};
use log::*;
use tokio::sync::oneshot::Receiver;
use tower::ServiceBuilder;
use zkgroup::call_links::CreateCallLinkCredentialPresentation;

use crate::{
    authenticator::{Authenticator, AuthenticatorError, GroupAuthToken},
    frontend::{Frontend, FrontendError},
    metrics::histogram::Histogram,
};

#[derive(Default)]
pub struct ApiMetrics {
    pub latencies: HashMap<String, Histogram<u64>>,
    pub counts: HashMap<String, u64>,
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

fn get_request_path<B>(req: &Request<B>) -> &str {
    if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str()
    } else {
        req.uri().path()
    }
}

fn get_user_agent<B>(req: &Request<B>) -> Result<&str, StatusCode> {
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
    } else {
        "unknown"
    }
}

/// Middleware to process metrics after a response is sent.
async fn metrics<B>(
    State(frontend): State<Arc<Frontend>>,
    req: Request<B>,
    next: Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    trace!("metrics");

    let start = Instant::now();
    // Get the method, path, user_agent, and frontend here to avoid cloning the whole
    // request before next.run() consumes it.
    let method = req.method().as_str().to_lowercase();
    let path = get_request_path(&req);
    let user_agent = get_user_agent(&req)?.to_string();

    let tag = if path.starts_with("/v1/call-links/") {
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
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
    }

    let latencies = api_metrics
        .latencies
        .entry(format!("calling.frontend.api.{}.{}.latency", tag, method))
        .or_insert_with(Histogram::default);
    latencies.push(latency.as_micros() as u64);

    Ok(response)
}

/// Middleware to handle the authorization header.
async fn authorize<B>(
    State(frontend): State<Arc<Frontend>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    trace!("authorize");

    let user_agent = get_user_agent(&req)?;

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

    let (_, password) = Authenticator::parse_basic_authorization_header(authorization_header)
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

async fn extra_call_link_metrics<B>(
    State(frontend): State<Arc<Frontend>>,
    create_auth: Option<Extension<Arc<CreateCallLinkCredentialPresentation>>>,
    req: Request<B>,
    next: Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    if create_auth.is_none() || req.method() != Method::PUT {
        return Ok(next.run(req).await);
    }

    trace!("extra_call_link_metrics");

    // Get the method and user_agent here to avoid cloning the whole
    // request before next.run() consumes it.
    let path = get_request_path(&req);
    let user_agent = get_user_agent(&req)?.to_string();

    let tag = if path.starts_with("/v1/call-links/") {
        "call_links.v1"
    } else if path.starts_with("/v2/conference/") {
        // don't add extra metrics for joining with a call link
        return Ok(next.run(req).await);
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
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);
    let _ = api_metrics
        .counts
        .entry(format!(
            "calling.frontend.api.{}.create.user_agent.{}",
            tag,
            user_agent_event_string(&user_agent)
        ))
        .and_modify(|value| *value = value.saturating_add(1))
        .or_insert(1);

    Ok(response)
}

/// Middleware to parse the authorization header for the call link endpoints.
///
/// We can't actually authenticate now because we need to fetch the room info.
async fn authorize_call_link<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    trace!("authorize");

    let user_agent = get_user_agent(&req)?;

    let authorization_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| {
            event!("calling.frontend.api.call_links_authorization.header.missing");
            warn!(
                "authorize: authorization header missing for {} from {}",
                req.method(),
                user_agent
            );
            StatusCode::UNAUTHORIZED
        })?;

    let token =
        Authenticator::parse_bearer_authorization_header(authorization_header).map_err(|err| {
            event!("calling.frontend.api.call_links_authorization.header.invalid");
            warn!(
                "authorize: {} for {} from {}",
                err,
                req.method(),
                user_agent
            );
            StatusCode::BAD_REQUEST
        })?;

    let fail_malformed = |err: &dyn Display| {
        event!("calling.frontend.api.authorization.malformed.zkcredential");
        info!(
            "authorize: malformed credentials for {} from {}: {}",
            req.method(),
            user_agent,
            err
        );
        StatusCode::BAD_REQUEST
    };

    // We use '.' as a separator because it matches the "token68" charset expected for Bearer auth.
    match token.split_once('.') {
        Some(("auth", credential_base64)) => {
            let credential_bytes =
                base64::decode(credential_base64).map_err(|e| fail_malformed(&e))?;
            let credential: zkgroup::call_links::CallLinkAuthCredentialPresentation =
                bincode::deserialize(&credential_bytes).map_err(|e| fail_malformed(&e))?;

            // We can't verify the credential without the room info, so wait to see how it's used.
            // Put the presentation in an Arc to satisfy the Clone requirement on the Extension extractor.
            req.extensions_mut().insert(Arc::new(credential));
            Ok(next.run(req).await)
        }
        Some(("create", credential_base64)) if req.method() == Method::PUT => {
            let credential_bytes =
                base64::decode(credential_base64).map_err(|e| fail_malformed(&e))?;
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

    let call_link_routes = Router::new()
        .route(
            "/v1/call-link/:room_id",
            get(call_links::read_call_link).put(call_links::update_call_link),
        )
        .route(
            "/v2/conference/:room_id/participants",
            get(v2::get_participants_by_room_id).put(v2::join_by_room_id),
        )
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(frontend.clone(), metrics))
                .layer(middleware::from_fn_with_state(
                    frontend.clone(),
                    authorize_call_link,
                ))
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
    let addr = SocketAddr::new(
        IpAddr::from_str(&frontend.config.server_ip)?,
        frontend.config.server_port,
    );

    let server = axum::Server::try_bind(&addr)?
        .serve(app(frontend).into_make_service())
        .with_graceful_shutdown(async {
            let _ = ender_rx.await;
        });

    info!("api ready: {}", addr);
    if let Err(err) = server.await {
        error!("api server returned: {}", err);
    }

    info!("api shutdown");
    Ok(())
}
