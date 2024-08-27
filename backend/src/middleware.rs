//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use calling_common::Instant;
use hyper::header;
use log::*;

pub async fn log_response(req: Request, next: Next) -> Response {
    let started = Instant::now();

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let version = req.version();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    let response = next.run(req).await;

    let elapsed = Instant::now().saturating_duration_since(started);

    info!(
        target: "calling_service",
        r#""{} {} {:?}" {} "{}" {:?}"#,
        method,
        path,
        version,
        response.status().as_u16(),
        user_agent,
        elapsed,
    );

    response
}
