//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the http server. This version is based on warp.
//! Supported APIs:
//!   GET /health
//!   GET /metrics
//!   GET /v1/conference/participants
//!   PUT /v1/conference/participants
//!   DELETE /v1/conference/participants/endpoint_id

use std::{
    convert::TryInto,
    net::IpAddr,
    str,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::UNIX_EPOCH,
};

use anyhow::{anyhow, Result};
use hex::{FromHex, ToHex};
use log::*;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot::Receiver;
use warp::{http::StatusCode, Filter, Reply};

use crate::{
    common,
    common::Instant,
    config, ice,
    sfu::{self, Sfu, SrtpMasterSourceServerPublic},
};

#[derive(Serialize, Debug)]
pub struct ParticipantsResponse {
    #[serde(rename = "conferenceId")]
    pub era_id: String,
    #[serde(rename = "maxConferenceSize")]
    pub max_devices: u32,
    pub participants: Vec<SfuParticipant>,
    // TODO: Make this with hex too.
    pub creator: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Candidate {
    pub port: u16,
    pub ip: String,
    #[serde(rename = "type")]
    pub candidate_type: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Fingerprint {
    pub fingerprint: String,
    pub hash: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Transport {
    pub candidates: Vec<Candidate>,
    #[serde(rename = "dhePublicKey")]
    pub dhe_pub_key: Option<String>,
    #[serde(rename = "hkdfExtraInfo")]
    pub hkdf_extra_info: Option<String>,
    pub fingerprints: Option<Vec<Fingerprint>>,
    pub ufrag: String,
    pub pwd: String,
}

#[derive(Deserialize, Debug)]
pub struct PayloadParameters {
    pub minptime: Option<u32>,
    pub useinbandfec: Option<u32>,
}

#[derive(Deserialize, Debug)]
pub struct RtcpFbs {
    #[serde(rename = "type")]
    pub fbs_type: String,
    pub subtype: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct PayloadType {
    pub id: u8,
    pub name: String,
    pub clockrate: u32,
    pub channels: u32,
    pub parameters: Option<PayloadParameters>,
    #[serde(rename = "rtcp-fbs")]
    pub rtcp_fbs: Option<Vec<RtcpFbs>>,
}

#[derive(Deserialize, Debug)]
pub struct HeaderExtension {
    pub id: u32,
    pub uri: String,
}

#[derive(Deserialize, Debug)]
pub struct SsrcGroup {
    pub semantics: String,
    pub sources: Vec<u32>,
}

#[derive(Deserialize, Debug)]
pub struct JoinRequest {
    pub transport: Transport,
    #[serde(rename = "audioPayloadType")]
    pub audio_payload_type: PayloadType,
    #[serde(rename = "videoPayloadType")]
    pub video_payload_type: PayloadType,
    #[serde(rename = "dataPayloadType")]
    pub data_payload_type: PayloadType,
    #[serde(rename = "audioHeaderExtensions")]
    pub audio_header_extensions: Vec<HeaderExtension>,
    #[serde(rename = "videoHeaderExtensions")]
    pub video_header_extensions: Vec<HeaderExtension>,
    #[serde(rename = "audioSsrcs")]
    pub audio_ssrcs: Vec<u32>,
    #[serde(rename = "audioSsrcGroups")]
    pub audio_ssrc_groups: Vec<SsrcGroup>,
    #[serde(rename = "dataSsrcs")]
    pub data_ssrcs: Vec<u32>,
    #[serde(rename = "dataSsrcGroups")]
    pub data_ssrc_groups: Vec<SsrcGroup>,
    #[serde(rename = "videoSsrcs")]
    pub video_ssrcs: Vec<u32>,
    #[serde(rename = "videoSsrcGroups")]
    pub video_ssrc_groups: Vec<SsrcGroup>,
}

#[derive(Serialize, Debug)]
pub struct JoinResponse {
    #[serde(rename = "endpointId", with = "hex")]
    pub leave_request_token: String,
    #[serde(rename = "opaqueUserId")]
    pub opaque_user_id: String,
    #[serde(rename = "ssrcPrefix")]
    pub demux_id: u32,
    pub transport: Transport,
}

#[derive(Serialize, Debug, Clone)]
pub struct SfuParticipant {
    #[serde(rename = "endpointId")]
    pub endpoint_id: String,
    #[serde(rename = "ssrcPrefix")]
    pub demux_id: u32,
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
        pub padding_send_bps: u64,
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

/// Obtain a demux_id from the given endpoint_id.
///
/// The demux_id is the first 112 bits of the SHA-256 hash of the endpoint_id string byte
/// representation.
///
/// ```
/// use calling_server::http_server::demux_id_from_endpoint_id;
/// use std::convert::TryInto;
///
/// assert_eq!(demux_id_from_endpoint_id("abcdef-0"), 3487943312.try_into().unwrap());
/// assert_eq!(demux_id_from_endpoint_id("abcdef-12345"), 2175944000.try_into().unwrap());
/// assert_eq!(demux_id_from_endpoint_id(""), 3820012608.try_into().unwrap());
/// ```
pub fn demux_id_from_endpoint_id(endpoint_id: &str) -> sfu::DemuxId {
    let mut hasher = Sha256::new();
    hasher.update(endpoint_id.as_bytes());

    // Get the 32-bit hash but mask out 4 bits since DemuxIDs must leave
    // these unset for "SSRC space".
    (u32::from_be_bytes(hasher.finalize()[0..4].try_into().unwrap()) & 0xfffffff0)
        .try_into()
        .unwrap()
}

/// Authenticate the header and return the (user_id, call_id) tuple or an error.
fn authenticate(
    _config: &'static config::Config,
    password: &str,
) -> Result<(sfu::UserId, sfu::CallId)> {
    let (user_id_hex, call_id_hex) = match password.split(':').collect::<Vec<_>>()[..] {
        [user_id_hex, call_id_hex, _timestamp, _mac_hex]
            if !user_id_hex.is_empty() && !call_id_hex.is_empty() =>
        {
            Ok((user_id_hex, call_id_hex))
        }
        ["2", user_id_hex, call_id_hex, _timestamp, _permission, _mac_hex]
            if !user_id_hex.is_empty() && !call_id_hex.is_empty() =>
        {
            Ok((user_id_hex, call_id_hex))
        }
        _ => Err(anyhow!("Password not valid")),
    }?;

    let user_id = Vec::from_hex(user_id_hex)?.into();
    let call_id = Vec::from_hex(call_id_hex)?.into();

    // The http_server is used for testing and therefore will not perform
    // actual GV2 auth, as this is done by the frontend.
    Ok((user_id, call_id))
}

/// Parses an authorization header using the basic authentication scheme. Returns
/// a tuple of the credentials (username, password).
fn parse_basic_authorization_header(authorization_header: &str) -> Result<(String, String)> {
    // Get the credentials from the Basic authorization header.
    if let ["Basic", base_64_encoded_values] =
        authorization_header.splitn(2, ' ').collect::<Vec<_>>()[..]
    {
        // Decode the credentials to utf-8 format.
        let decoded_values = base64::decode(base_64_encoded_values)?;
        let credentials = std::str::from_utf8(&decoded_values)?;

        // Split the credentials into the username and password.
        if let [username, password] = credentials.splitn(2, ':').collect::<Vec<_>>()[..] {
            Ok((username.to_string(), password.to_string()))
        } else {
            // Malformed token.
            Err(anyhow!("Authorization header not valid"))
        }
    } else {
        // Malformed header.
        Err(anyhow!("Could not parse authorization header"))
    }
}

fn parse_and_authenticate(
    config: &'static config::Config,
    authorization_header: &str,
) -> Result<(sfu::UserId, sfu::CallId)> {
    let (_, password) = parse_basic_authorization_header(authorization_header)?;
    authenticate(config, &password)
}

async fn get_metrics(sfu: Arc<Mutex<Sfu>>) -> Result<warp::reply::Response, warp::Rejection> {
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
                    // FIXME: Replace with client.user_id.as_slice().escape_ascii().to_string()
                    // when escape_ascii is stabilized.
                    user_id: String::from_utf8(
                        client
                            .user_id
                            .as_slice()
                            .iter()
                            .copied()
                            .map(std::ascii::escape_default)
                            .flatten()
                            .collect(),
                    )
                    .unwrap(),
                    target_send_bps: client.target_send_rate.as_bps(),
                    video0_incoming_bps: client.video0_incoming_rate.unwrap_or_default().as_bps(),
                    video1_incoming_bps: client.video1_incoming_rate.unwrap_or_default().as_bps(),
                    video2_incoming_bps: client.video2_incoming_rate.unwrap_or_default().as_bps(),
                    padding_send_bps: client.padding_send_rate.as_bps(),
                    requested_base_bps: client.requested_base_rate.as_bps(),
                    ideal_send_bps: client.ideal_send_rate.as_bps(),
                    allocated_send_bps: client.allocated_send_rate.as_bps(),
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

    Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK).into_response())
}

async fn get_participants(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    authorization_header: String,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("get():");

    let call_id = match parse_and_authenticate(config, &authorization_header) {
        Ok((_, call_id)) => call_id,
        Err(err) => {
            warn!("get(): unauthorized {}", err);
            return Ok(warp::reply::with_status(
                warp::reply::json(&err.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .into_response());
        }
    };

    let sfu = sfu.lock();

    if let Some(signaling) = sfu.get_call_signaling_info(call_id) {
        let max_devices = sfu.config.max_clients_per_call;
        drop(sfu);
        // Release the SFU lock as early as possible. Before call lock is fine for a imut ref to a
        // call, as nothing we will do later with the reference can affect SFU decisions around call
        // dropping.

        let participants = signaling
            .client_ids
            .iter()
            .map(|(demux_id, active_speaker_id)| SfuParticipant {
                endpoint_id: active_speaker_id.to_owned(),
                demux_id: u32::from(*demux_id),
            })
            .collect();

        let era_id = signaling
            .created
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
            .to_string();
        let response = ParticipantsResponse {
            // TODO: Consider handling the expectation and returning an internal server error for it.
            era_id,
            max_devices,
            participants,
            creator: signaling.creator_id.as_slice().encode_hex(),
        };

        Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

async fn join(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    authorization_header: String,
    join_request: JoinRequest,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("join():");

    let (user_id, call_id) = match parse_and_authenticate(config, &authorization_header) {
        Ok((user_id, call_id)) => (user_id, call_id),
        Err(err) => {
            warn!("join(): unauthorized {}", err);
            return Ok(warp::reply::with_status(
                warp::reply::json(&err.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .into_response());
        }
    };

    // Evaluate the request with basic assertions.
    if join_request.audio_header_extensions.len() != 3
        || join_request.audio_payload_type.id != 102
        || !join_request.audio_ssrc_groups.is_empty()
        || join_request.audio_ssrcs.len() != 1
        || join_request.data_payload_type.id != 101
        || join_request.data_ssrcs.len() != 1
        || join_request.video_header_extensions.len() != 3
        || join_request.video_payload_type.id != 108
        || join_request.video_ssrc_groups.len() != 4
        || join_request.video_ssrcs.len() != 6
    {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Missing required fields in the request.".to_string()),
            StatusCode::NOT_ACCEPTABLE,
        )
        .into_response());
    }

    let client_public = match (
        join_request.transport.dhe_pub_key,
        join_request.transport.fingerprints.as_deref(),
    ) {
        (Some(dhe_pub_key), _) => match <[u8; 32]>::from_hex(dhe_pub_key) {
            Ok(public_key) => sfu::SrtpMasterSourceClientPublic::Dhe {
                public_key,
                hkdf_extra_info: match join_request.transport.hkdf_extra_info {
                    None => vec![],
                    Some(hkdf_extra_info) => match Vec::<u8>::from_hex(hkdf_extra_info) {
                        Ok(hkdf_extra_info) => hkdf_extra_info,
                        Err(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &"Invalid hkdf_extra_info in the request.".to_string(),
                                ),
                                StatusCode::NOT_ACCEPTABLE,
                            )
                            .into_response());
                        }
                    },
                },
            },
            Err(_) => {
                return Ok(warp::reply::with_status(
                    warp::reply::json(&"Invalid dhe_pub_key in the request.".to_string()),
                    StatusCode::NOT_ACCEPTABLE,
                )
                .into_response());
            }
        },
        (None, Some([fingerprint, ..])) => {
            match common::colon_separated_hexstring_to_array(&fingerprint.fingerprint) {
                Ok(v) => sfu::SrtpMasterSourceClientPublic::DtlsFingerprint(v),
                Err(_) => {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(&"Invalid DTLS fingerprint in the request".to_string()),
                        StatusCode::NOT_ACCEPTABLE,
                    )
                    .into_response());
                }
            }
        }
        (None, _) => {
            return Ok(warp::reply::with_status(
                warp::reply::json(
                    &"Must provide either dtls_fingerprint or dhe_pub_key".to_string(),
                ),
                StatusCode::NOT_ACCEPTABLE,
            )
            .into_response());
        }
    };

    // Generate ids for the client.
    let resolution_request_id = rand::thread_rng().gen::<u64>();
    // The endpoint_id is the term currently used on the client side, it is
    // equivalent to the active_speaker_id in the Sfu.
    let user_id_string = user_id.as_slice().encode_hex::<String>();
    let endpoint_id = format!("{}-{}", user_id_string, resolution_request_id);
    let demux_id = demux_id_from_endpoint_id(&endpoint_id);
    let server_ice_ufrag = ice::random_ufrag();
    let server_ice_pwd = ice::random_pwd();

    let mut sfu = sfu.lock();
    let server_public = sfu
        .get_or_create_call_and_add_client(
            call_id,
            &user_id,
            resolution_request_id,
            endpoint_id.clone(),
            demux_id,
            server_ice_ufrag.clone(),
            server_ice_pwd.clone(),
            join_request.transport.ufrag,
            client_public,
        )
        .unwrap();
    let socket_addr = config::get_server_media_address(config);
    let candidate = Candidate {
        port: socket_addr.port(),
        ip: socket_addr.ip().to_string(),
        candidate_type: "host".to_string(),
    };

    let candidates = vec![candidate];

    let (dhe_pub_key, fingerprints) = match server_public {
        SrtpMasterSourceServerPublic::Dhe { public_key, .. } => {
            (Some(public_key.encode_hex()), None)
        }
        SrtpMasterSourceServerPublic::DtlsFingerprint(fingerprint) => (
            None,
            Some(vec![Fingerprint {
                fingerprint: common::bytes_to_colon_separated_hexstring(&fingerprint),
                hash: "sha-256".to_string(),
            }]),
        ),
    };

    let transport = Transport {
        candidates,
        dhe_pub_key,
        hkdf_extra_info: None,
        fingerprints,
        ufrag: server_ice_ufrag,
        pwd: server_ice_pwd,
    };

    let response = JoinResponse {
        demux_id: demux_id.into(),
        transport,
        opaque_user_id: user_id_string,
        leave_request_token: endpoint_id,
    };

    Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK).into_response())
}

async fn leave(
    leave_request_token: String,
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    authorization_header: String,
) -> Result<warp::reply::Response, warp::Rejection> {
    trace!("leave():");

    let call_id = match parse_and_authenticate(config, &authorization_header) {
        Ok((_, call_id)) => call_id,
        Err(err) => {
            warn!("leave(): unauthorized {}", err);
            return Ok(warp::reply::with_status(
                warp::reply::json(&err.to_string()),
                StatusCode::UNAUTHORIZED,
            )
            .into_response());
        }
    };

    // Calculate the demux_id with some simple validation of the endpoint_id.
    let endpoint_id = leave_request_token;
    let demux_id = if endpoint_id.chars().count() > 3 && endpoint_id.contains('-') {
        demux_id_from_endpoint_id(&endpoint_id)
    } else {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Invalid endpoint_id format".to_string()),
            StatusCode::BAD_REQUEST,
        )
        .into_response());
    };

    sfu.lock()
        .remove_client_from_call(Instant::now(), call_id, demux_id);

    // TODO: When the function above returns a result, handle that.
    // TODO: Also, if there was no group call, should we return NOT_FOUND?
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A warp filter for providing the config for a route.
fn with_config(
    config: &'static config::Config,
) -> impl Filter<Extract = (&'static config::Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config)
}

/// A warp filter for extracting the Sfu state for a route.
fn with_sfu(
    sfu: Arc<Mutex<Sfu>>,
) -> impl Filter<Extract = (Arc<Mutex<Sfu>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sfu.clone())
}

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<Mutex<Sfu>>,
    http_ender_rx: Receiver<()>,
    is_healthy: Arc<AtomicBool>,
) -> Result<()> {
    // Filter to support: GET /health
    let health_check_api = warp::path!("about" / "health")
        .and(warp::get())
        .map(move || {
            if is_healthy.load(Ordering::Relaxed) {
                Ok(StatusCode::OK.into_response())
            } else {
                Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        });

    // Filter to support: GET /metrics
    let metrics_api = warp::path!("metrics")
        .and(warp::get())
        .and(with_sfu(sfu.clone()))
        .and_then(get_metrics);

    // Filter to support: GET /v1/conference/participants
    let get_participants_api = warp::path!("v1" / "conference" / "participants")
        .and(warp::get())
        .and(with_config(config))
        .and(with_sfu(sfu.clone()))
        .and(warp::header("authorization"))
        .and_then(get_participants);

    // Filter to support: PUT /v1/conference/participants
    let join_api = warp::path!("v1" / "conference" / "participants")
        .and(warp::put())
        .and(with_config(config))
        .and(with_sfu(sfu.clone()))
        .and(warp::header("authorization"))
        .and(warp::body::json())
        .and_then(join);

    // Filter to support: DELETE v1/conference/participants/endpoint-id 204 Success
    let leave_api = warp::path!("v1" / "conference" / "participants" / String)
        .and(warp::delete())
        .and(with_config(config))
        .and(with_sfu(sfu))
        .and(warp::header("authorization"))
        .and_then(leave);

    let api = health_check_api
        .or(metrics_api)
        .or(get_participants_api)
        .or(join_api)
        .or(leave_api);

    // Add other options to form the final routes to be served.
    // TODO: Disabling the "with(log)" mechanism since it causes the following
    // error when trying to launch with tokio::spawn():
    //   implementation of `warp::reply::Reply` is not general enough
    //let routes = api.with(warp::log("calling_service"));

    let (addr, server) = warp::serve(api).bind_with_graceful_shutdown(
        (IpAddr::from_str(&config.binding_ip)?, config.signaling_port),
        async {
            http_ender_rx.await.ok();
        },
    );

    info!("http_server ready: {}", addr);
    server.await;

    info!("http_server shutdown");
    Ok(())
}

#[cfg(test)]
mod http_server_tests {
    use std::time::Instant;

    use hex::{FromHex, ToHex};
    use lazy_static::lazy_static;
    use rand::{thread_rng, Rng};

    use super::*;

    fn string_id_vector(n: usize, id_size: usize) -> Vec<String> {
        let mut vector: Vec<String> = Vec::new();
        for _ in 0..n {
            vector.push(common::random_hex_string(id_size));
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
        assert_eq!(32, ids_bytes.get(0).unwrap().len());

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
        assert_eq!(64, ids_strings.get(0).unwrap().len());

        println!(
            "hex_encode() for {} ids took {}ns",
            count,
            end.duration_since(start).as_nanos()
        );
    }

    #[tokio::test]
    async fn test_parse_basic_authorization_header() {
        let result = parse_basic_authorization_header("");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "Could not parse authorization header"
        );

        // Error: Could not parse authorization header
        assert!(parse_basic_authorization_header("B").is_err());
        assert!(parse_basic_authorization_header("Basic").is_err());
        assert!(parse_basic_authorization_header("Basic ").is_err());
        assert!(parse_basic_authorization_header("B X").is_err());
        assert!(parse_basic_authorization_header("Basi XYZ").is_err());

        // DecodeError: Encoded text cannot have a 6-bit remainder.
        assert!(parse_basic_authorization_header("Basic X").is_err());

        // DecodeError: Invalid last symbol 90, offset 2.
        assert!(parse_basic_authorization_header("Basic XYZ").is_err());

        // Utf8Error: invalid utf-8 sequence of 1 bytes from index 0
        assert!(parse_basic_authorization_header("Basic //3//Q==").is_err());

        // Utf8Error: invalid utf-8 sequence of 1 bytes from index 8
        assert!(
            parse_basic_authorization_header("Basic MTIzNDU2Nzj95v3n/ej96f3q/ev97P3t/e797w==")
                .is_err()
        );

        let result = parse_basic_authorization_header("Basic VGVzdA==");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "Authorization header not valid"
        );

        // Error: Authorization header not valid
        assert!(parse_basic_authorization_header("Basic MSAy").is_err());
        assert!(parse_basic_authorization_header("Basic MWIgMmI=").is_err());

        // ":"
        assert_eq!(
            parse_basic_authorization_header("Basic Og==").unwrap(),
            ("".to_string(), "".to_string())
        );

        // "username:password"
        assert_eq!(
            parse_basic_authorization_header("Basic dXNlcm5hbWU6cGFzc3dvcmQ=").unwrap(),
            ("username".to_string(), "password".to_string())
        );

        // ":password"
        assert_eq!(
            parse_basic_authorization_header("Basic OnBhc3N3b3Jk").unwrap(),
            ("".to_string(), "password".to_string())
        );

        // "username:"
        assert_eq!(
            parse_basic_authorization_header("Basic dXNlcm5hbWU6").unwrap(),
            ("username".to_string(), "".to_string())
        );

        // "::"
        assert_eq!(
            parse_basic_authorization_header("Basic Ojo=").unwrap(),
            ("".to_string(), ":".to_string())
        );

        // ":::::"
        assert_eq!(
            parse_basic_authorization_header("Basic Ojo6Ojo=").unwrap(),
            ("".to_string(), "::::".to_string())
        );

        // "1a2b3c:1a2b3c:1a2b3c:1a2b3c"
        assert_eq!(
            parse_basic_authorization_header("Basic MWEyYjNjOjFhMmIzYzoxYTJiM2M6MWEyYjNj").unwrap(),
            ("1a2b3c".to_string(), "1a2b3c:1a2b3c:1a2b3c".to_string())
        );
    }

    #[tokio::test]
    async fn test_authenticate() {
        lazy_static! {
            static ref CONFIG: config::Config = config::default_test_config();
        }
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

        // Error: Odd number of digits
        assert!(authenticate(config, "1:2b::").is_err());
        assert!(authenticate(config, "1a:2::").is_err());
        assert!(authenticate(config, "1a2:2b:1:3c").is_err());
        assert!(authenticate(config, "2:1:2b:::").is_err());
        assert!(authenticate(config, "2:1a:2:::").is_err());
        assert!(authenticate(config, "2:1a2:2b:1:1:3c").is_err());

        // Error: Invalid character 'x' at position 1
        assert!(authenticate(config, "1x:2b:1:").is_err());
        assert!(authenticate(config, "1a:2x:1:").is_err());
        assert!(authenticate(config, "2:1x:2b:1::").is_err());
        assert!(authenticate(config, "2:1a:2x:1::").is_err());

        // Error: Unknown version
        assert!(authenticate(config, ":1a:2b:1:2:3").is_err());
        assert!(authenticate(config, "1:1a:2b:1:2:3").is_err());
        assert!(authenticate(config, "3:1a:2b:1:2:3").is_err());

        assert!(
            authenticate(config, "1a:2b:1:").unwrap()
                == (sfu::UserId::from(vec![26]), sfu::CallId::from(vec![43]))
        );

        assert!(
            authenticate(config, "2:1a:2b:1:2:3").unwrap() == (vec![26].into(), vec![43].into())
        );
    }

    #[tokio::test]
    async fn test_parse_and_authenticate() {
        lazy_static! {
            static ref CONFIG: config::Config = config::default_test_config();
        }
        let config = &CONFIG;

        // Version 1: "username:1a:2b:1:"
        let result = parse_and_authenticate(config, "Basic dXNlcm5hbWU6MWE6MmI6MTo=");
        assert!(!result.is_err());
        assert!(result.unwrap() == (vec![26].into(), vec![43].into()));

        // Version 2: "username:2:1a:2b:1:2:3"
        let result = parse_and_authenticate(config, "Basic dXNlcm5hbWU6MjoxYToyYjoxOjI6Mw==");
        assert!(!result.is_err());
        assert!(result.unwrap() == (vec![26].into(), vec![43].into()));
    }
}
