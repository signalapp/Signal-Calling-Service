//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the SFU signaling server. This version is based on warp.
//! Supported REST APIs:
//!   GET /about/health
//!   GET /v1/info
//!   GET /v1/call/$call_id/clients
//!   POST /v1/call/$call_id/client/$demux_id (join)
//!   DELETE /v1/call/$call_id/client/$demux_id (leave)

use std::{
    convert::{Infallible, TryInto},
    error::Error,
    net::IpAddr,
    str::{self, FromStr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, Result};
use hex::{FromHex, ToHex};
use log::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Receiver;
use warp::{http::StatusCode, Filter, Reply};

use crate::{call, common::Instant, config, ice, sfu, sfu::Sfu};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub call_count: usize,
    pub client_count: usize,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    pub direct_access_ip: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientsResponse {
    pub endpoint_ids: Vec<String>, // Aka active_speaker_ids, a concatenation of user_id + '-' + resolution_request_id.
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub endpoint_id: String, // Aka active_speaker_id, a concatenation of user_id + '-' + resolution_request_id.
    pub client_ice_ufrag: String,
    pub client_dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub server_ip: String,
    pub server_port: u16,
    pub server_ice_ufrag: String,
    pub server_ice_pwd: String,
    pub server_dhe_public_key: String,
}

/// Struct to support warp rejection (errors) for invalid argument values.
#[derive(Debug)]
struct InvalidArgument {
    reason: String,
}
impl warp::reject::Reject for InvalidArgument {}

/// Struct to support warp rejection (errors) for internal errors.
#[derive(Debug)]
struct InternalError {
    reason: String,
}
impl warp::reject::Reject for InternalError {}

/// Get a call_id (Vec<u8>) from a string hex value.
fn call_id_from_hex(call_id: &str) -> Result<sfu::CallId> {
    if call_id.is_empty() {
        return Err(anyhow!("call_id is empty"));
    }

    Ok(Vec::from_hex(call_id)
        .map_err(|_| anyhow!("call_id is invalid"))?
        .into())
}

/// Parse a user_id hash and resolution_request_id from the provided endpoint. The endpoint
/// string has the following format: $hex(sha256(user_id))-$resolution_request_id
///
/// ```
/// use calling_server::signaling_server::parse_user_id_and_resolution_request_id_from_endpoint_id;
///
/// assert!(parse_user_id_and_resolution_request_id_from_endpoint_id("abcdef-0").unwrap() == (vec![171, 205, 239].into(), 0));
/// assert!(parse_user_id_and_resolution_request_id_from_endpoint_id("abcdef-12345").unwrap() == (vec![171, 205, 239].into(), 12345));
/// assert_eq!(parse_user_id_and_resolution_request_id_from_endpoint_id("").is_err(), true);
/// assert_eq!(parse_user_id_and_resolution_request_id_from_endpoint_id("abcdef-").is_err(), true);
/// assert_eq!(parse_user_id_and_resolution_request_id_from_endpoint_id("abcdef-a").is_err(), true);
/// assert_eq!(parse_user_id_and_resolution_request_id_from_endpoint_id("abcdef-1-").is_err(), true);
/// ```
pub fn parse_user_id_and_resolution_request_id_from_endpoint_id(
    endpoint_id: &str,
) -> Result<(sfu::UserId, u64)> {
    if let [user_id_hex, suffix] = endpoint_id.splitn(2, '-').collect::<Vec<_>>()[..] {
        let resolution_request_id = u64::from_str(suffix)?;
        let user_id = Vec::from_hex(&user_id_hex)?;

        Ok((user_id.into(), resolution_request_id))
    } else {
        Err(anyhow!("malformed endpoint_id"))
    }
}

/// Return a health response after accessing the SFU and obtaining basic information.
async fn get_health(
    sfu: Arc<Mutex<Sfu>>,
    is_healthy: Arc<AtomicBool>,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("get_health():");

    if is_healthy.load(Ordering::Relaxed) {
        let calls = sfu.lock().get_calls_snapshot(); // SFU lock released here.

        let client_count = calls
            .iter()
            .map(|call| {
                // We can take this call lock after closing the SFU lock because we are treating
                // it as read-only and can accommodate stale data.
                let call = call.lock();
                call.size()
            })
            .sum();

        let response = HealthResponse {
            call_count: calls.len(),
            client_count,
        };

        Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK).into_response())
    } else {
        // Return a server error because it is not healthy for external reasons.
        Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

/// Obtain information about the server.
async fn get_info(
    config: &'static config::Config,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("get_info():");

    if let Some(private_ip) = &config.signaling_ip {
        let response = InfoResponse {
            direct_access_ip: private_ip.to_string(),
        };

        Ok(warp::reply::json(&response).into_response())
    } else {
        Err(warp::reject::custom(InternalError {
            reason: "private_ip not set".to_string(),
        }))
    }
}

/// Return the list of clients for a given call. Returns "Not Found" if
/// the call does not exist or an empty list if there are no clients
/// currently in the call.
async fn get_clients(
    call_id: String,
    sfu: Arc<Mutex<Sfu>>,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("get_clients(): {}", call_id);

    let call_id = call_id_from_hex(&call_id).map_err(|err| {
        warp::reject::custom(InvalidArgument {
            reason: err.to_string(),
        })
    })?;

    let sfu = sfu.lock();
    if let Some(signaling) = sfu.get_call_signaling_info(call_id) {
        let response = ClientsResponse {
            endpoint_ids: signaling
                .client_ids
                .into_iter()
                .map(|(_demux_id, active_speaker_id)| active_speaker_id)
                .collect(),
        };

        Ok(warp::reply::json(&response).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

/// Handles a request for a client to join a call.
async fn join(
    call_id: String,
    demux_id: u32,
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    request: JoinRequest,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("join(): {} {}", call_id, demux_id);

    let call_id = call_id_from_hex(&call_id).map_err(|err| {
        warp::reject::custom(InvalidArgument {
            reason: err.to_string(),
        })
    })?;
    let demux_id = demux_id.try_into().map_err(|err: call::Error| {
        warp::reject::custom(InvalidArgument {
            reason: err.to_string(),
        })
    })?;

    let (user_id, resolution_request_id) =
        parse_user_id_and_resolution_request_id_from_endpoint_id(&request.endpoint_id).map_err(
            |err| {
                warp::reject::custom(InvalidArgument {
                    reason: err.to_string(),
                })
            },
        )?;

    let client_dhe_public_key =
        <[u8; 32]>::from_hex(request.client_dhe_public_key).map_err(|err| {
            warp::reject::custom(InvalidArgument {
                reason: err.to_string(),
            })
        })?;

    let client_hkdf_extra_info = match request.hkdf_extra_info {
        None => vec![],
        Some(hkdf_extra_info) => Vec::<u8>::from_hex(hkdf_extra_info).map_err(|err| {
            warp::reject::custom(InvalidArgument {
                reason: err.to_string(),
            })
        })?,
    };

    let server_ice_ufrag = ice::random_ufrag();
    let server_ice_pwd = ice::random_pwd();

    let mut sfu = sfu.lock();
    match sfu.get_or_create_call_and_add_client(
        call_id,
        &user_id,
        resolution_request_id,
        request.endpoint_id,
        demux_id,
        server_ice_ufrag.to_string(),
        server_ice_pwd.to_string(),
        request.client_ice_ufrag,
        client_dhe_public_key,
        client_hkdf_extra_info,
    ) {
        Ok(server_dhe_public_key) => {
            let media_addr = config::get_server_media_address(config);
            let server_dhe_public_key = server_dhe_public_key.encode_hex();

            let response = JoinResponse {
                server_ip: media_addr.ip().to_string(),
                server_port: media_addr.port(),
                server_ice_ufrag,
                server_ice_pwd,
                server_dhe_public_key,
            };

            Ok(warp::reply::json(&response).into_response())
        }
        Err(err) => {
            error!("client failed to join call {}", err.to_string());
            if err == sfu::SfuError::DuplicateDemuxIdDetected {
                // Invalid argument because the demux_id is a duplicate.
                Err(warp::reject::custom(InvalidArgument {
                    reason: err.to_string(),
                }))
            } else {
                Err(warp::reject::custom(InternalError {
                    reason: format!("failed to add client to call {}", err),
                }))
            }
        }
    }
}

/// Handles a request for a client to leave a call.
async fn leave(
    call_id: String,
    demux_id: u32,
    sfu: Arc<Mutex<Sfu>>,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("leave(): {} {}", call_id, demux_id);

    let call_id = call_id_from_hex(&call_id).map_err(|err| {
        warp::reject::custom(InvalidArgument {
            reason: err.to_string(),
        })
    })?;
    let demux_id = demux_id.try_into().map_err(|err: call::Error| {
        warp::reject::custom(InvalidArgument {
            reason: err.to_string(),
        })
    })?;

    sfu.lock()
        .remove_client_from_call(Instant::now(), call_id, demux_id);

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Map rejections to a format that should be presented in the response.
async fn rejection_handler(rejection: warp::Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if rejection.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "".to_string();
    } else if let Some(r) = rejection.find::<InvalidArgument>() {
        // Our detection of invalid request arguments.
        code = StatusCode::BAD_REQUEST;
        message = r.reason.to_string();
    } else if let Some(r) = rejection.find::<InternalError>() {
        // Our internal errors.
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = r.reason.to_string();
    } else if let Some(e) = rejection.find::<warp::filters::body::BodyDeserializeError>() {
        // Warp's detection of invalid requests (when deserializing json).
        code = StatusCode::BAD_REQUEST;
        message = match e.source() {
            Some(cause) => cause.to_string(),
            None => "".to_string(),
        };
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "unknown".to_string();
    }

    Ok(warp::reply::with_status(message, code))
}

/// A warp filter that provides the is_healthy flag to a route.
fn with_is_healthy(
    is_healthy: Arc<AtomicBool>,
) -> impl Filter<Extract = (Arc<AtomicBool>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || is_healthy.clone())
}

/// A warp filter that provides the config to a route.
fn with_config(
    config: &'static config::Config,
) -> impl Filter<Extract = (&'static config::Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config)
}

/// A warp filter that provides the sfu state to a route.
fn with_sfu(
    sfu: Arc<Mutex<Sfu>>,
) -> impl Filter<Extract = (Arc<Mutex<Sfu>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sfu.clone())
}

/// Filter to support the "GET /about/health" API for the server and testing.
fn get_health_api(
    sfu: Arc<Mutex<Sfu>>,
    is_healthy: Arc<AtomicBool>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("health")
        .and(warp::get())
        .and(with_sfu(sfu))
        .and(with_is_healthy(is_healthy))
        .and_then(get_health)
}

/// Filter to support the "GET /v1/info" API for the server and testing.
fn get_info_api(
    config: &'static config::Config,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("v1" / "info")
        .and(warp::get())
        .and(with_config(config))
        .and_then(get_info)
}

/// Filter to support the "GET /v1/call/$call_id/clients" API for the server and testing.
fn get_clients_api(
    sfu: Arc<Mutex<Sfu>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("v1" / "call" / String / "clients")
        .and(warp::get())
        .and(with_sfu(sfu))
        .and_then(get_clients)
}

/// Filter to support the "POST /v1/call/$call_id/client/$demux_id" API for the server and testing.
fn join_api(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("v1" / "call" / String / "client" / u32)
        .and(warp::post())
        .and(with_config(config))
        .and(with_sfu(sfu))
        .and(warp::body::json())
        .and_then(join)
}

/// Filter to support the "DELETE /v1/call/$call_id/client/$demux_id" API for the server and testing.
fn leave_api(
    sfu: Arc<Mutex<Sfu>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("v1" / "call" / String / "client" / u32)
        .and(warp::delete())
        .and(with_sfu(sfu))
        .and_then(leave)
}

/// The overall signaling api combined as a single filter for the server and testing.
pub fn signaling_api(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    is_healthy: Arc<AtomicBool>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_health_api(sfu.clone(), is_healthy)
        .or(get_info_api(config))
        .or(get_clients_api(sfu.clone()))
        .or(join_api(config, sfu.clone()))
        .or(leave_api(sfu))
}

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    ender_rx: Receiver<()>,
    is_healthy: Arc<AtomicBool>,
) -> Result<()> {
    let api = signaling_api(config, sfu, is_healthy)
        .with(warp::log("calling_service"))
        .recover(rejection_handler);

    let (addr, server) = warp::serve(api).bind_with_graceful_shutdown(
        (IpAddr::from_str(&config.binding_ip)?, config.signaling_port),
        async {
            let _ = ender_rx.await;
        },
    );

    info!("signaling_server ready: {}", addr);
    server.await;

    info!("signaling_server shutdown");
    Ok(())
}

#[cfg(test)]
mod signaling_server_tests {
    use std::convert::TryInto;

    use lazy_static::lazy_static;
    use tokio::sync::oneshot;
    use warp::test::request;

    use super::*;
    use crate::sfu::{DemuxId, DhePublicKey};

    const CALL_ID: &str = "fe076d76bffb54b1";
    const CLIENT_DHE_PUB_KEY: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    const ENDPOINT_ID_1: &str =
        "7ab9bbf0b71f81598ae1b592aaf82f9b20b638142a9610c3e37965bec7519112-5287417572362992825";
    const ENDPOINT_ID_2: &str =
        "b25387a93fd65599bacae4a8f8726e9e818ecf0bec3360593fe542cdb8e611a3-7715148009648537058";
    const UFRAG: &str = "Ouub";

    lazy_static! {
        static ref DEFAULT_CONFIG: config::Config = config::default_test_config();

        // Load a config with no signaling_ip set.
        static ref BAD_IP_CONFIG: config::Config = {
            let mut config = config::default_test_config();
            config.signaling_ip = None;
            config
        };
    }

    fn new_sfu(now: Instant, config: &'static config::Config) -> Arc<Mutex<Sfu>> {
        Arc::new(Mutex::new(
            Sfu::new(now, config).expect("Sfu::new should work"),
        ))
    }

    fn add_client_to_sfu(
        sfu: Arc<Mutex<Sfu>>,
        call_id: &str,
        endpoint_id: &str,
        demux_id: DemuxId,
        client_ice_ufrag: &str,
        client_dhe_pub_key: DhePublicKey,
    ) {
        let call_id = call_id_from_hex(call_id).unwrap();
        let (user_id, resolution_request_id) =
            parse_user_id_and_resolution_request_id_from_endpoint_id(endpoint_id).unwrap();

        let _ = sfu
            .lock()
            .get_or_create_call_and_add_client(
                call_id,
                &user_id,
                resolution_request_id,
                endpoint_id.to_string(),
                demux_id,
                ice::random_ufrag(),
                ice::random_pwd(),
                client_ice_ufrag.to_string(),
                client_dhe_pub_key,
                vec![],
            )
            .unwrap();
    }

    fn remove_client_from_sfu(sfu: Arc<Mutex<Sfu>>, call_id: &str, demux_id: DemuxId) {
        let call_id = call_id_from_hex(call_id).unwrap();

        sfu.lock()
            .remove_client_from_call(Instant::now(), call_id, demux_id);
    }

    fn check_call_exists_in_sfu(sfu: Arc<Mutex<Sfu>>, call_id: &str) -> bool {
        sfu.lock()
            .get_call_signaling_info(call_id_from_hex(call_id).unwrap())
            .is_some()
    }

    fn get_client_count_in_call_from_sfu(sfu: Arc<Mutex<Sfu>>, call_id: &str) -> usize {
        if let Some(signaling) = sfu
            .lock()
            .get_call_signaling_info(call_id_from_hex(call_id).unwrap())
        {
            signaling.size
        } else {
            0
        }
    }

    #[tokio::test]
    async fn test_start() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let (signaling_ender_tx, signaling_ender_rx) = oneshot::channel();

        let server_handle =
            tokio::spawn(async move { start(config, sfu, signaling_ender_rx, is_healthy).await });

        let closer_handle = tokio::spawn(async move { signaling_ender_tx.send(()) });

        let (server_result, _) = tokio::join!(server_handle, closer_handle,);

        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_health() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu, is_healthy.clone()).recover(rejection_handler);

        let response = request().method("GET").path("/health").reply(&api).await;

        assert_eq!(response.status(), StatusCode::OK);

        is_healthy.store(false, Ordering::Relaxed);

        let response = request().method("GET").path("/health").reply(&api).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_info() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu, is_healthy).recover(rejection_handler);

        let response = request().method("GET").path("/v1/info").reply(&api).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(response.body(), r#"{"directAccessIp":"127.0.0.1"}"#);
    }

    #[tokio::test]
    async fn test_get_info_bad_ip() {
        let config = &BAD_IP_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu, is_healthy).recover(rejection_handler);

        let response = request().method("GET").path("/v1/info").reply(&api).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_clients() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu.clone(), is_healthy).recover(rejection_handler);

        let response = request()
            .method("GET")
            .path(&format!("/v1/call/{}/clients", CALL_ID))
            .reply(&api)
            .await;

        // No clients were added.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Join with client 16.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            ENDPOINT_ID_1,
            16u32.try_into().unwrap(),
            UFRAG,
            CLIENT_DHE_PUB_KEY,
        );

        let response = request()
            .method("GET")
            .path(&format!("/v1/call/{}/clients", CALL_ID))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            response.body(),
            &format!("{{\"endpointIds\":[\"{}\"]}}", ENDPOINT_ID_1)
        );

        // Join with client 32.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            ENDPOINT_ID_2,
            32u32.try_into().unwrap(),
            UFRAG,
            CLIENT_DHE_PUB_KEY,
        );

        let response = request()
            .method("GET")
            .path(&format!("/v1/call/{}/clients", CALL_ID))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.body(),
            &format!(
                "{{\"endpointIds\":[\"{}\",\"{}\"]}}",
                ENDPOINT_ID_1, ENDPOINT_ID_2
            )
        );

        remove_client_from_sfu(sfu.clone(), CALL_ID, 16u32.try_into().unwrap());

        let response = request()
            .method("GET")
            .path(&format!("/v1/call/{}/clients", CALL_ID))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.body(),
            &format!("{{\"endpointIds\":[\"{}\"]}}", ENDPOINT_ID_2)
        );

        remove_client_from_sfu(sfu.clone(), CALL_ID, 32u32.try_into().unwrap());

        let response = request()
            .method("GET")
            .path(&format!("/v1/call/{}/clients", CALL_ID))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), "{\"endpointIds\":[]}");
    }

    #[tokio::test]
    async fn test_join() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu.clone(), is_healthy).recover(rejection_handler);

        // Join with a invalid DemuxId.
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 1))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid CallId.
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", "INVALIDNOTHEX", 16))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid endpoint_id.
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: "MALFORMEDNOHYPHEN".to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid endpoint_id.
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: "MALFORMEDNOHYPHEN".to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid DHE public key
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: "INVALID".to_string(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid HKDF extra info
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: Some("G".to_string()),
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with good parameters.
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );

        let response: JoinResponse = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(response.server_ip, "127.0.0.1");
        assert_eq!(response.server_port, 10000);
        assert_eq!(64, response.server_dhe_public_key.len());

        assert!(
            check_call_exists_in_sfu(sfu.clone(), CALL_ID),
            "Call doesn't exist"
        );
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 1);

        // Attempt to join again using the same demux_id (should be a bad request).
        let response = request()
            .method("POST")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .json(&JoinRequest {
                endpoint_id: ENDPOINT_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
            })
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 1);
    }

    #[tokio::test]
    async fn test_leave() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));

        let api = signaling_api(config, sfu.clone(), is_healthy).recover(rejection_handler);

        // Join with client 16 and verify.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            ENDPOINT_ID_1,
            16u32.try_into().unwrap(),
            UFRAG,
            CLIENT_DHE_PUB_KEY,
        );
        assert!(
            check_call_exists_in_sfu(sfu.clone(), CALL_ID),
            "Call doesn't exist"
        );
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 1);

        let response = request()
            .method("DELETE")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        assert!(
            check_call_exists_in_sfu(sfu.clone(), CALL_ID),
            "Call doesn't exist"
        );
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 0);

        // Attempt to leave again (response is indifferent since the client has already left).
        let response = request()
            .method("DELETE")
            .path(&format!("/v1/call/{}/client/{}", CALL_ID, 16))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Attempt to leave again from an unknown call.
        let response = request()
            .method("DELETE")
            .path(&format!("/v1/call/1234/client/{}", 16))
            .reply(&api)
            .await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
