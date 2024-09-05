//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the http server. This version is based on axum.
//! Supported APIs:
//!   GET /metrics
//!   GET /v2/conference/participants
//!   PUT /v2/conference/participants

use std::{net::SocketAddr, str, sync::Arc, time::UNIX_EPOCH};

use anyhow::{anyhow, Result};
use axum::{
    http::StatusCode, middleware, response::IntoResponse, routing::get, Extension, Json, Router,
};
use axum_extra::{
    headers::{self, authorization::Basic, Authorization},
    TypedHeader,
};
use hex::{FromHex, ToHex};
use log::*;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Receiver;
use tower::ServiceBuilder;

use crate::{
    config, ice,
    middleware::log_response,
    region::Region,
    sfu::{self, Sfu},
};

use calling_common::DemuxId;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_user_id: Option<String>,
    pub demux_id: u32,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantsResponse {
    pub conference_id: String,
    pub max_devices: u32,
    pub participants: Vec<Participant>,
    pub creator: String,
    pub pending_clients: Vec<Participant>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub ice_ufrag: String,
    pub dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub demux_id: u32,
    pub port: u16,
    pub port_tcp: u16,
    pub port_tls: Option<u16>,
    pub ip: String,
    pub ips: Vec<String>,
    pub hostname: Option<String>,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub dhe_public_key: String,
    pub conference_id: String,
    pub client_status: String,
}

mod metrics {
    use serde::Serialize;

    #[derive(Serialize, Debug)]
    pub struct Client {
        pub user_id: String,
        pub demux_id: u32,
        pub video0_incoming_bps: u64,
        pub video1_incoming_bps: u64,
        pub video2_incoming_bps: u64,
        pub target_send_bps: u64,
        pub requested_base_bps: u64,
        pub ideal_send_bps: u64,
        pub allocated_send_bps: u64,
        pub outgoing_queue_drain_bps: u64,
        pub video0_incoming_height: u64,
        pub video1_incoming_height: u64,
        pub video2_incoming_height: u64,
        pub max_requested_height: u64,
    }

    #[derive(Serialize, Debug)]
    pub struct Call {
        pub call_id: String,
        pub client_count: usize,
        pub clients: Vec<Client>,
    }

    #[derive(Serialize, Debug)]
    pub struct Response {
        pub call_count: usize,
        pub client_count: usize,
        pub calls: Vec<Call>,
    }
}

pub fn random_demux_id() -> DemuxId {
    let unmasked_id = rand::thread_rng().gen::<u32>();
    DemuxId::try_from(unmasked_id & !0b1111).expect("valid")
}

/// Synthesizes a conference ID from the call start timestamp.
fn conference_id_from_signaling_info(signaling: &sfu::CallSignalingInfo) -> String {
    signaling
        .created
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
        .to_string()
}

/// Authenticate the header and return the (user_id, call_id) tuple or an error.
fn authenticate(
    _config: &'static config::Config,
    password: &str,
) -> Result<(sfu::UserId, sfu::CallId)> {
    let (user_id_str, call_id_hex) = match password.split(':').collect::<Vec<_>>()[..] {
        ["2", user_id_str, call_id_hex, _timestamp, _permission, _mac_hex]
            if !user_id_str.is_empty() && !call_id_hex.is_empty() =>
        {
            Ok((user_id_str, call_id_hex))
        }
        _ => Err(anyhow!("Password not valid")),
    }?;

    let user_id = user_id_str.to_string().into();
    let call_id = Vec::from_hex(call_id_hex)?.into();

    // The http_server is used for testing and therefore will not perform
    // actual GV2 auth, as this is done by the frontend.
    Ok((user_id, call_id))
}

fn parse_and_authenticate(
    config: &'static config::Config,
    authorization_header: &Authorization<Basic>,
) -> Result<(sfu::UserId, sfu::CallId)> {
    let password = authorization_header.password();
    authenticate(config, password)
}

async fn get_metrics(
    Extension(sfu): Extension<Arc<Mutex<Sfu>>>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("get_metrics():");

    let calls = sfu.lock().get_calls_snapshot(); // SFU lock released here.

    let calls = calls
        .iter()
        .map(|call| {
            // We can take this call lock after closing the SFU lock because we are only reading it
            // and do not care if it is removed from the list of active calls around the same time.
            // This is in contrast to if we were updating it with a mut reference and we might revive
            // the call.
            let call = call.lock();
            let clients = call
                .get_stats()
                .clients
                .iter()
                .map(|client| metrics::Client {
                    demux_id: client.demux_id.into(),
                    user_id: client.user_id.as_str().to_string(),
                    target_send_bps: client.target_send_rate.as_bps(),
                    video0_incoming_bps: client.video0_incoming_rate.unwrap_or_default().as_bps(),
                    video1_incoming_bps: client.video1_incoming_rate.unwrap_or_default().as_bps(),
                    video2_incoming_bps: client.video2_incoming_rate.unwrap_or_default().as_bps(),
                    requested_base_bps: client.requested_base_rate.as_bps(),
                    ideal_send_bps: client.ideal_send_rate.as_bps(),
                    allocated_send_bps: client.allocated_send_rate.as_bps(),
                    outgoing_queue_drain_bps: client.outgoing_queue_drain_rate.as_bps(),
                    video0_incoming_height: client
                        .video0_incoming_height
                        .unwrap_or_default()
                        .as_u16() as u64,
                    video1_incoming_height: client
                        .video1_incoming_height
                        .unwrap_or_default()
                        .as_u16() as u64,
                    video2_incoming_height: client
                        .video2_incoming_height
                        .unwrap_or_default()
                        .as_u16() as u64,
                    max_requested_height: client.max_requested_height.unwrap_or_default().as_u16()
                        as u64,
                })
                .collect::<Vec<_>>();
            metrics::Call {
                call_id: call.loggable_call_id().to_string(),
                client_count: clients.len(),
                clients,
            }
        })
        .collect::<Vec<_>>();

    let response = metrics::Response {
        call_count: calls.len(),
        client_count: calls.iter().map(|c| c.client_count).sum(),
        calls,
    };

    Ok(Json(response))
}

async fn get_participants(
    Extension(config): Extension<&'static config::Config>,
    Extension(sfu): Extension<Arc<Mutex<Sfu>>>,
    TypedHeader(authorization_header): TypedHeader<headers::Authorization<Basic>>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("get_participants():");

    let (user_id, call_id) = match parse_and_authenticate(config, &authorization_header) {
        Ok((user_id, call_id)) => (user_id, call_id),
        Err(err) => {
            warn!("get(): unauthorized {}", err);
            return Ok((StatusCode::UNAUTHORIZED, err.to_string()).into_response());
        }
    };

    let sfu = sfu.lock();

    if let Some(signaling) = sfu.get_call_signaling_info(call_id, Some(&user_id)) {
        let max_devices = sfu.config.max_clients_per_call;
        drop(sfu);
        // Release the SFU lock as early as possible. Before call lock is fine for a imut ref to a
        // call, as nothing we will do later with the reference can affect SFU decisions around call
        // dropping.

        let conference_id = conference_id_from_signaling_info(&signaling);
        let participants = signaling
            .client_ids
            .into_iter()
            .map(|(demux_id, user_id)| Participant {
                opaque_user_id: Some(user_id.into()),
                demux_id: u32::from(demux_id),
            })
            .collect();
        let pending_clients = signaling
            .pending_client_ids
            .into_iter()
            .map(|(demux_id, user_id)| Participant {
                opaque_user_id: user_id.map(String::from),
                demux_id: demux_id.as_u32(),
            })
            .collect();

        let response = ParticipantsResponse {
            conference_id,
            max_devices,
            participants,
            creator: signaling.creator_id.into(),
            pending_clients,
        };

        Ok(Json(response).into_response())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn join_conference(
    Extension(config): Extension<&'static config::Config>,
    Extension(sfu): Extension<Arc<Mutex<Sfu>>>,
    TypedHeader(authorization_header): TypedHeader<headers::Authorization<Basic>>,
    Json(join_request): Json<JoinRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("join_conference():");

    let (user_id, call_id) = match parse_and_authenticate(config, &authorization_header) {
        Ok((user_id, call_id)) => (user_id, call_id),
        Err(err) => {
            warn!("join(): unauthorized {}", err);
            return Ok((StatusCode::UNAUTHORIZED, err.to_string()).into_response());
        }
    };

    if join_request.dhe_public_key.is_empty() {
        return Ok((
            StatusCode::NOT_ACCEPTABLE,
            "Empty dhe_public_key in the request.".to_string(),
        )
            .into_response());
    }

    let client_dhe_public_key = match <[u8; 32]>::from_hex(join_request.dhe_public_key) {
        Ok(client_dhe_public_key) => client_dhe_public_key,
        Err(_) => {
            return Ok((
                StatusCode::NOT_ACCEPTABLE,
                "Invalid dhe_public_key in the request.".to_string(),
            )
                .into_response());
        }
    };

    let client_hkdf_extra_info = match join_request.hkdf_extra_info {
        None => vec![],
        Some(client_hkdf_extra_info) => match Vec::<u8>::from_hex(client_hkdf_extra_info) {
            Ok(client_hkdf_extra_info) => client_hkdf_extra_info,
            Err(_) => {
                return Ok((
                    StatusCode::NOT_ACCEPTABLE,
                    "Invalid hkdf_extra_info in the request.".to_string(),
                )
                    .into_response());
            }
        },
    };

    // Generate ids for the client.
    let demux_id = random_demux_id();
    let server_ice_ufrag = ice::random_ufrag();
    let server_ice_pwd = ice::random_pwd();

    let mut sfu = sfu.lock();
    // Make the first user to join an admin.
    let is_admin = sfu.get_call_signaling_info(call_id.clone(), None).is_none();
    match sfu.get_or_create_call_and_add_client(
        call_id.clone(),
        None,
        user_id,
        demux_id,
        server_ice_ufrag.clone(),
        server_ice_pwd.clone(),
        join_request.ice_ufrag,
        client_dhe_public_key,
        client_hkdf_extra_info,
        Region::Unset,
        config.new_clients_require_approval,
        is_admin,
        None,
    ) {
        Ok((server_dhe_public_key, client_status)) => {
            let media_server = config::ServerMediaAddress::from(config);

            let signaling = sfu
                .get_call_signaling_info(call_id, None)
                .expect("just created call");

            let response = JoinResponse {
                demux_id: demux_id.into(),
                port: media_server.ports.udp,
                port_tcp: media_server.ports.tcp,
                port_tls: media_server.ports.tls,
                ip: media_server.ip().to_string(),
                ips: media_server
                    .addresses
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect(),
                hostname: media_server.hostname,
                ice_ufrag: server_ice_ufrag,
                ice_pwd: server_ice_pwd,
                dhe_public_key: server_dhe_public_key.encode_hex(),
                conference_id: conference_id_from_signaling_info(&signaling),
                client_status: client_status.to_string(),
            };

            Ok(Json(response).into_response())
        }
        Err(err) => {
            error!("client failed to join call {}", err.to_string());
            Ok((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
        }
    }
}

fn app(sfu: Arc<Mutex<Sfu>>, config: &'static config::Config) -> Router {
    let metrics_route = Router::new()
        .route("/metrics", get(get_metrics))
        .layer(Extension(sfu.clone()));

    let routes = Router::new()
        .route(
            "/v2/conference/participants",
            get(get_participants).put(join_conference),
        )
        .layer(
            ServiceBuilder::new()
                .layer(Extension(config))
                .layer(Extension(sfu)),
        );

    Router::new().merge(metrics_route).merge(routes)
}

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    http_ender_rx: Receiver<()>,
) -> Result<()> {
    let addr = SocketAddr::new(config.binding_ip, config.signaling_port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let server = axum::serve(
        listener,
        app(sfu, config)
            .layer(middleware::from_fn(log_response))
            .into_make_service(),
    )
    .with_graceful_shutdown(async {
        let _ = http_ender_rx.await;
    });

    info!("http_server ready: {}", addr);
    if let Err(err) = server.await {
        error!("http_server returned: {}", err);
    }

    info!("http_server shutdown");
    Ok(())
}

#[cfg(test)]
mod http_server_tests {
    use std::time::Instant;

    use hex::{FromHex, ToHex};
    use once_cell::sync::Lazy;
    use rand::{thread_rng, Rng};

    use calling_common::random_hex_string;

    static CONFIG: Lazy<config::Config> = Lazy::new(config::default_test_config);

    use super::*;

    fn string_id_vector(n: usize, id_size: usize) -> Vec<String> {
        let mut vector: Vec<String> = Vec::new();
        for _ in 0..n {
            vector.push(random_hex_string(id_size));
        }
        vector
    }

    fn random_byte_vector(n: usize) -> Vec<u8> {
        let mut numbers: Vec<u8> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..n {
            numbers.push(rng.gen());
        }
        numbers
    }

    fn random_byte_id_vector(n: usize, id_size: usize) -> Vec<Vec<u8>> {
        let mut vector: Vec<Vec<u8>> = Vec::new();
        for _ in 0..n {
            vector.push(random_byte_vector(id_size));
        }
        vector
    }

    #[tokio::test]
    async fn test_hex_decode_bench() {
        // Create 1000 id's to use.
        let count = 1000;
        let ids = string_id_vector(count, 64);

        // Pre-allocate the outer vec.
        let mut ids_bytes: Vec<Vec<u8>> = Vec::with_capacity(count);

        let start = Instant::now();
        for id in ids {
            ids_bytes.push(Vec::from_hex(id).unwrap());
        }
        let end = Instant::now();

        assert_eq!(count, ids_bytes.len());
        assert_eq!(32, ids_bytes.first().unwrap().len());

        println!(
            "hex_decode() for {} ids took {}ns",
            count,
            end.duration_since(start).as_nanos()
        );
    }

    #[tokio::test]
    async fn test_hex_encode_bench() {
        // Create 1000 id's to use.
        let count = 1000;
        let ids = random_byte_id_vector(count, 32);

        // Pre-allocate the outer vec.
        let mut ids_strings: Vec<String> = Vec::with_capacity(count);

        let start = Instant::now();
        for id in ids {
            ids_strings.push(id.encode_hex::<String>());
        }
        let end = Instant::now();

        assert_eq!(count, ids_strings.len());
        assert_eq!(64, ids_strings.first().unwrap().len());

        println!(
            "hex_encode() for {} ids took {}ns",
            count,
            end.duration_since(start).as_nanos()
        );
    }

    #[tokio::test]
    async fn test_authenticate() {
        let config = &CONFIG;

        let result = authenticate(config, "1:2");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Password not valid");

        // Error: Password not valid
        assert!(authenticate(config, "").is_err());
        assert!(authenticate(config, ":").is_err());
        assert!(authenticate(config, "::").is_err());
        assert!(authenticate(config, ":::").is_err());
        assert!(authenticate(config, "::::").is_err());
        assert!(authenticate(config, ":::::").is_err());
        assert!(authenticate(config, "2:::::").is_err());
        assert!(authenticate(config, "1:2:3").is_err());
        assert!(authenticate(config, "1:2:3:4:5").is_err());

        // Error: Odd number of digits in call ID field
        assert!(authenticate(config, "2:1a:2b2:1:1:3c").is_err());

        // Error: Invalid character 'x' in call ID field
        assert!(authenticate(config, "2:1a:2x:1::").is_err());

        // Error: Unknown version
        assert!(authenticate(config, ":1a:2b:1:2:3").is_err());
        assert!(authenticate(config, "1:1a:2b:1:2:3").is_err());
        assert!(authenticate(config, "3:1a:2b:1:2:3").is_err());
        // This was the v1 auth credential format.
        assert!(authenticate(config, "1a:2b:1:").is_err());

        assert!(
            authenticate(config, "2:1a:2b:1:2:3").unwrap()
                == ("1a".to_string().into(), vec![0x2b].into())
        );

        // Even though all user IDs are current hex, we shouldn't be hardcoding that.
        assert!(
            authenticate(config, "2:not-hex:2b:1:2:3").unwrap()
                == ("not-hex".to_string().into(), vec![0x2b].into())
        );
    }

    #[tokio::test]
    async fn test_parse_and_authenticate() {
        let config = &CONFIG;

        // Version 2: "username:2:1a:2b:1:2:3"
        let result =
            parse_and_authenticate(config, &Authorization::basic("username", "2:1a:2b:1:2:3"));
        assert!(result.is_ok());
        assert!(result.unwrap() == ("1a".to_string().into(), vec![0x2b].into()));
    }
}
