//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the SFU signaling server. This version is based on axum.
//! Supported REST APIs:
//!   GET /health
//!   GET /v1/info
//!   GET /v1/call/$call_id/clients
//!   POST /v1/call/$call_id/client/$demux_id (join)

use std::{
    net::SocketAddr,
    str::{self, FromStr},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::{
    headers::{self, Header},
    TypedHeader,
};
use calling_common::{CallType, DemuxId, RoomId, SignalUserAgent};
use hex::{FromHex, ToHex};
use hyper::http::{HeaderName, HeaderValue};
use log::*;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::sync::oneshot::{self, Receiver};
use tower::ServiceBuilder;

use crate::{
    call, config, ice,
    middleware::log_response,
    region::Region,
    sfu::{self, Sfu, SfuError, UserId},
};

const SYSTEM_MONITOR_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub call_count: usize,
    pub client_count: usize,
    pub cpu_idle_pct: u8,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    pub direct_access_ip: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    demux_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientsResponse {
    #[serde(rename = "endpointIds")]
    pub user_ids: Vec<String>, // These are user IDs.

    // Parallels the user_ids list.
    pub demux_ids: Vec<u32>,

    pub pending_clients: Vec<ClientInfo>,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    #[serde(rename = "endpointId")]
    pub user_id: String,
    pub client_ice_ufrag: String,
    pub client_ice_pwd: Option<String>,
    pub client_dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
    pub region: Option<String>,
    #[serde(default)]
    pub new_clients_require_approval: bool,
    pub call_type: CallType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<SignalUserAgent>,
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<RoomId>,
    #[serde_as(as = "Option<Vec<call::UserIdAsStr>>")]
    pub approved_users: Option<Vec<UserId>>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub server_ip: String,
    pub server_ips: Vec<String>,
    pub server_port: u16,
    pub server_port_tcp: u16,
    pub server_port_tls: Option<u16>,
    pub server_hostname: Option<String>,
    pub server_ice_ufrag: String,
    pub server_ice_pwd: String,
    pub server_dhe_public_key: String,
    pub client_status: String,
}

impl Header for sfu::UserId {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-user-id");
        &NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        if values.next().is_some() {
            return Err(headers::Error::invalid());
        }
        if value.is_empty() || value.len() > 256 {
            return Err(headers::Error::invalid());
        }
        if let Ok(value) = value.to_str() {
            // Note that by not doing any other decoding we're assuming all opaque user IDs will be
            // valid HTTP header values. In practice this is "printable ASCII, no whitespace".
            Ok(Self::from(value.to_owned()))
        } else {
            Err(headers::Error::invalid())
        }
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        if let Ok(value) = HeaderValue::from_str(self.as_str()) {
            values.extend(std::iter::once(value));
        }
    }
}

/// Get a call_id (Vec<u8>) from a string hex value.
fn call_id_from_hex(call_id: &str) -> Result<sfu::CallId> {
    if call_id.is_empty() {
        return Err(anyhow!("call_id is empty"));
    }

    Ok(Vec::from_hex(call_id)
        .map_err(|_| anyhow!("call_id is invalid"))?
        .into())
}

/// Validates a user ID, converting it to our strong [`sfu::UserId`] type.
///
/// Currently any non-empty string is considered a valid user ID.
///
/// ```
/// use calling_backend::signaling_server::validate_user_id;
///
/// assert!(validate_user_id("abcdef").unwrap() == "abcdef".to_string().into());
/// assert!(validate_user_id("").is_err());
/// ```
pub fn validate_user_id(user_id_str: &str) -> Result<sfu::UserId> {
    if user_id_str.is_empty() {
        return Err(anyhow!("missing user ID"));
    }
    Ok(user_id_str.to_string().into())
}

/// Validates a room_id.
///
/// Currently any non-empty string is considered a valid room_id
pub fn validate_room_id(room_id: &Option<RoomId>) -> Result<()> {
    if room_id.as_ref().is_some_and(|id| id.as_ref().is_empty()) {
        return Err(anyhow!("missing room_id"));
    }
    Ok(())
}
/// Return a health response after accessing the SFU and obtaining basic information.
async fn get_health(
    State(sfu): State<Arc<RwLock<Sfu>>>,
    Extension(is_healthy): Extension<Arc<AtomicBool>>,
    Extension(cpu_idle_pct): Extension<Arc<AtomicU8>>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("get_health():");

    if is_healthy.load(Ordering::Relaxed) {
        let calls = sfu.read().get_calls_snapshot(); // SFU lock released here.

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
            cpu_idle_pct: cpu_idle_pct.load(Ordering::Relaxed),
        };

        Ok(Json(response))
    } else {
        // Return a server error because it is not healthy for external reasons.
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Obtain information about the server.
async fn get_info(
    Extension(config): Extension<&'static config::Config>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    trace!("get_info():");

    if let Some(private_ip) = &config.signaling_ip {
        let response = InfoResponse {
            direct_access_ip: private_ip.to_string(),
        };

        Ok(Json(response))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "private_ip not set".to_string(),
        ))
    }
}

/// Return the list of clients for a given call. Returns "Not Found" if
/// the call does not exist or an empty list if there are no clients
/// currently in the call.
async fn get_clients(
    State(sfu): State<Arc<RwLock<Sfu>>>,
    Path(call_id): Path<String>,
    requesting_user: Option<TypedHeader<sfu::UserId>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    trace!("get_clients(): {}", call_id);

    let call_id =
        call_id_from_hex(&call_id).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let sfu = sfu.read();
    if let Some(signaling) =
        sfu.get_call_signaling_info(call_id, requesting_user.as_ref().map(|header| &header.0))
    {
        let (demux_ids, user_ids) = signaling
            .client_ids
            .into_iter()
            .map(|(demux_id, user_id)| (demux_id.as_u32(), user_id.into()))
            .unzip();
        let pending_clients = signaling
            .pending_client_ids
            .into_iter()
            .map(|(demux_id, user_id)| ClientInfo {
                demux_id: demux_id.as_u32(),
                user_id: user_id.map(String::from),
            })
            .collect();
        let response = ClientsResponse {
            user_ids,
            demux_ids,
            pending_clients,
        };

        Ok(Json(response).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

/// Handles a request for a client to join a call.
async fn join(
    State(sfu): State<Arc<RwLock<Sfu>>>,
    Path((call_id, demux_id)): Path<(String, u32)>,
    Extension(config): Extension<&'static config::Config>,
    Json(request): Json<JoinRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    trace!("join(): {} {}", call_id, demux_id);

    if let Err(err) = validate_room_id(&request.room_id) {
        return Err((StatusCode::BAD_REQUEST, err.to_string()));
    }

    let user_agent = request.user_agent.unwrap_or(SignalUserAgent::Unknown);

    let call_id =
        call_id_from_hex(&call_id).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let demux_id =
        DemuxId::try_from(demux_id).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let user_id = validate_user_id(&request.user_id)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let client_dhe_public_key = <[u8; 32]>::from_hex(request.client_dhe_public_key)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let client_hkdf_extra_info = match request.hkdf_extra_info {
        None => vec![],
        Some(hkdf_extra_info) => Vec::<u8>::from_hex(hkdf_extra_info)
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?,
    };

    let server_ice_ufrag = ice::random_ufrag();
    let server_ice_pwd = ice::random_pwd();

    let region = if let Some(region) = request.region {
        Region::from_str(&region).unwrap_or(Region::Unknown)
    } else {
        Region::Unset
    };

    let mut sfu = sfu.write();
    match sfu.get_or_create_call_and_add_client(
        call_id,
        request.room_id,
        user_id,
        demux_id,
        server_ice_ufrag.to_string(),
        server_ice_pwd.to_string(),
        request.client_ice_ufrag,
        request.client_ice_pwd,
        client_dhe_public_key,
        client_hkdf_extra_info,
        region,
        request.new_clients_require_approval,
        request.call_type,
        user_agent,
        request.is_admin,
        request.approved_users,
    ) {
        Ok((server_dhe_public_key, client_status)) => {
            let media_server = config::ServerMediaAddress::from(config);
            let server_dhe_public_key = server_dhe_public_key.encode_hex();

            let response = JoinResponse {
                server_ip: media_server.ip().to_string(),
                server_ips: media_server
                    .addresses
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect(),
                server_port: media_server.ports.udp,
                server_port_tcp: media_server.ports.tcp,
                server_port_tls: media_server.ports.tls,
                server_hostname: media_server.hostname,
                server_ice_ufrag,
                server_ice_pwd,
                server_dhe_public_key,
                client_status: client_status.to_string(),
            };

            Ok(Json(response))
        }
        Err(err) => {
            error!("client failed to join call {}", err);
            match err {
                SfuError::DuplicateDemuxIdDetected => {
                    Err((StatusCode::BAD_REQUEST, err.to_string()))
                }
                SfuError::TooManyClients => Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Too many clients".to_string(),
                )),
                _ => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to add client to call {}", err),
                )),
            }
        }
    }
}

/// The overall signaling api combined as a Router for the server and testing.
pub fn signaling_api(
    config: &'static config::Config,
    sfu: Arc<RwLock<Sfu>>,
    is_healthy: Arc<AtomicBool>,
    cpu_idle_pct: Arc<AtomicU8>,
) -> Router {
    let health_route = Router::new()
        .route("/health", get(get_health))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(is_healthy))
                .layer(Extension(cpu_idle_pct)),
        )
        .with_state(sfu.clone());

    let info_route = Router::new()
        .route("/v1/info", get(get_info))
        .layer(ServiceBuilder::new().layer(Extension(config)));

    let clients_route = Router::new()
        .route("/v1/call/:call_id/clients", get(get_clients))
        .with_state(sfu.clone());

    let join_route = Router::new()
        .route("/v1/call/:call_id/client/:demux_id", post(join))
        .layer(Extension(config))
        .with_state(sfu);

    Router::new()
        .merge(health_route)
        .merge(info_route)
        .merge(clients_route)
        .merge(join_route)
}

pub async fn start(
    config: &'static config::Config,
    sfu: Arc<RwLock<Sfu>>,
    ender_rx: Receiver<()>,
    is_healthy: Arc<AtomicBool>,
) -> Result<()> {
    let addr = SocketAddr::new(config.binding_ip, config.signaling_port);

    let cpu_idle_pct = Arc::new(AtomicU8::new(0));
    let (monitor_ender_tx, monitor_ender_rx) = oneshot::channel();

    start_monitor(monitor_ender_rx, cpu_idle_pct.clone());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let server = axum::serve(
        listener,
        signaling_api(config, sfu, is_healthy, cpu_idle_pct)
            .layer(middleware::from_fn(log_response))
            .into_make_service(),
    )
    .with_graceful_shutdown(async {
        let _ = ender_rx.await;
    });

    info!("signaling_server ready: {}", addr);
    if let Err(err) = server.await {
        error!("signaling_server returned: {}", err);
    }

    info!("signaling_server shutdown");
    let _ = monitor_ender_tx.send(());
    Ok(())
}

fn start_monitor(mut ender_rx: Receiver<()>, cpu_idle_pct: Arc<AtomicU8>) {
    tokio::spawn(async move {
        match psutil::cpu::CpuPercentCollector::new() {
            Err(err) => {
                error!("cpu percent collector new failed {}", err);
                // can't do anything else, leave idle at initial value
            }
            Ok(mut cpu_percent_collector) => {
                let mut tick_interval = tokio::time::interval(SYSTEM_MONITOR_INTERVAL);
                loop {
                    tokio::select!(
                        _ = tick_interval.tick() => {
                            match cpu_percent_collector.cpu_percent() {
                                Err(err) => error!("cpu percent collector collect failed {}", err),
                                Ok(busy_cpu_percent) => cpu_idle_pct.store(100u8.saturating_sub(busy_cpu_percent as u8), Ordering::Relaxed),
                            };
                         },
                        _ = &mut ender_rx => {
                            info!("monitor task ended");
                            break;
                        }
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod signaling_server_tests {
    use axum::{
        body::Body,
        http::{self, Request},
    };
    use calling_common::{ClientStatus, DemuxId, Instant};
    use once_cell::sync::Lazy;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    use super::*;
    use crate::sfu::DhePublicKey;

    const ROOM_ID: &str = "ff0000dd";
    const CALL_ID: &str = "fe076d76bffb54b1";
    const CLIENT_DHE_PUB_KEY: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    const USER_ID_1: &str = "7ab9bbf0b71f81598ae1b592aaf82f9b20b638142a9610c3e37965bec7519112";
    const USER_ID_2: &str = "b25387a93fd65599bacae4a8f8726e9e818ecf0bec3360593fe542cdb8e611a3";

    const DEMUX_ID_1: DemuxId = DemuxId::from_const(16);
    const DEMUX_ID_2: DemuxId = DemuxId::from_const(32);

    const UFRAG: &str = "Ouub";
    const PWD: &str = "Ouub";

    static DEFAULT_CONFIG: Lazy<config::Config> = Lazy::new(config::default_test_config);

    // Load a config with no signaling_ip set.
    static BAD_IP_CONFIG: Lazy<config::Config> = Lazy::new(|| {
        let mut config = config::default_test_config();
        config.signaling_ip = None;
        config
    });

    fn new_sfu(now: Instant, config: &'static config::Config) -> Arc<RwLock<Sfu>> {
        Arc::new(RwLock::new(
            Sfu::new(now, config).expect("Sfu::new should work"),
        ))
    }

    fn add_client_to_sfu(
        sfu: Arc<RwLock<Sfu>>,
        call_id: &str,
        user_id: &str,
        demux_id: DemuxId,
        client_ice_ufrag: &str,
        client_ice_pwd: &str,
        client_dhe_pub_key: DhePublicKey,
    ) {
        let call_id = call_id_from_hex(call_id).unwrap();
        let user_id = validate_user_id(user_id).unwrap();

        let _ = sfu
            .write()
            .get_or_create_call_and_add_client(
                call_id,
                None,
                user_id,
                demux_id,
                ice::random_ufrag(),
                ice::random_pwd(),
                client_ice_ufrag.to_string(),
                Some(client_ice_pwd.to_string()),
                client_dhe_pub_key,
                vec![],
                Region::Unset,
                false,
                CallType::GroupV2,
                SignalUserAgent::Unknown,
                false,
                None,
            )
            .unwrap();
    }

    fn add_admin_to_sfu(
        sfu: Arc<RwLock<Sfu>>,
        call_id: &str,
        user_id: &str,
        demux_id: DemuxId,
        client_ice_ufrag: &str,
        client_ice_pwd: &str,
        client_dhe_pub_key: DhePublicKey,
    ) {
        let call_id = call_id_from_hex(call_id).unwrap();
        let user_id = validate_user_id(user_id).unwrap();

        let _ = sfu
            .write()
            .get_or_create_call_and_add_client(
                call_id,
                None,
                user_id,
                demux_id,
                ice::random_ufrag(),
                ice::random_pwd(),
                client_ice_ufrag.to_string(),
                Some(client_ice_pwd.to_string()),
                client_dhe_pub_key,
                vec![],
                Region::Unset,
                true,
                CallType::Adhoc,
                SignalUserAgent::Unknown,
                true,
                None,
            )
            .unwrap();
    }

    fn remove_client_from_sfu(sfu: Arc<RwLock<Sfu>>, call_id: &str, demux_id: DemuxId) {
        let call_id = call_id_from_hex(call_id).unwrap();

        sfu.write()
            .remove_client_from_call(Instant::now(), call_id, demux_id);
    }

    fn check_call_exists_in_sfu(sfu: Arc<RwLock<Sfu>>, call_id: &str) -> bool {
        sfu.read()
            .get_call_signaling_info(call_id_from_hex(call_id).unwrap(), None)
            .is_some()
    }

    fn get_client_count_in_call_from_sfu(sfu: Arc<RwLock<Sfu>>, call_id: &str) -> usize {
        if let Some(signaling) = sfu
            .read()
            .get_call_signaling_info(call_id_from_hex(call_id).unwrap(), None)
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
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu, is_healthy.clone(), cpu_idle_pct);

        let response = api
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        is_healthy.store(false, Ordering::Relaxed);

        let response = api
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_info() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu, is_healthy, cpu_idle_pct);

        let response = api
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"directAccessIp":"127.0.0.1"}"#);
    }

    #[tokio::test]
    async fn test_get_info_bad_ip() {
        let config = &BAD_IP_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu, is_healthy, cpu_idle_pct);

        let response = api
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_clients() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu.clone(), is_healthy, cpu_idle_pct);

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // No clients were added.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Join with client 16.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            USER_ID_1,
            DEMUX_ID_1,
            UFRAG,
            PWD,
            CLIENT_DHE_PUB_KEY,
        );

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[]}}"#,
                validate_user_id(USER_ID_1).unwrap().as_str(),
                DEMUX_ID_1.as_u32(),
            )
            .as_bytes()
        );

        // Join with client 32.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            USER_ID_2,
            DEMUX_ID_2,
            UFRAG,
            PWD,
            CLIENT_DHE_PUB_KEY,
        );

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}","{}"],"demuxIds":[{},{}],"pendingClients":[]}}"#,
                validate_user_id(USER_ID_1).unwrap().as_str(),
                validate_user_id(USER_ID_2).unwrap().as_str(),
                DEMUX_ID_1.as_u32(),
                DEMUX_ID_2.as_u32(),
            )
            .as_bytes()
        );

        remove_client_from_sfu(sfu.clone(), CALL_ID, DEMUX_ID_1);

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[]}}"#,
                validate_user_id(USER_ID_2).unwrap().as_str(),
                DEMUX_ID_2.as_u32(),
            )
            .as_bytes()
        );

        remove_client_from_sfu(sfu.clone(), CALL_ID, DEMUX_ID_2);

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            br#"{"endpointIds":[],"demuxIds":[],"pendingClients":[]}"#
        );
    }

    #[tokio::test]
    async fn test_get_clients_with_pending() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu.clone(), is_healthy, cpu_idle_pct);

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // No clients were added.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Join with client 16.
        add_admin_to_sfu(
            sfu.clone(),
            CALL_ID,
            USER_ID_1,
            DEMUX_ID_1,
            UFRAG,
            PWD,
            CLIENT_DHE_PUB_KEY,
        );

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[]}}"#,
                validate_user_id(USER_ID_1).unwrap().as_str(),
                DEMUX_ID_1.as_u32(),
            )
            .as_bytes()
        );

        // Join with client 32.
        add_client_to_sfu(
            sfu.clone(),
            CALL_ID,
            USER_ID_2,
            DEMUX_ID_2,
            UFRAG,
            PWD,
            CLIENT_DHE_PUB_KEY,
        );

        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[{{"demuxId":{}}}]}}"#,
                validate_user_id(USER_ID_1).unwrap().as_str(),
                DEMUX_ID_1.as_u32(),
                DEMUX_ID_2.as_u32(),
            )
            .as_bytes()
        );

        // Non-admins get the same response.
        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .header(
                        sfu::UserId::name(),
                        validate_user_id(USER_ID_2).unwrap().as_str(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[{{"demuxId":{}}}]}}"#,
                validate_user_id(USER_ID_1).unwrap().as_str(),
                DEMUX_ID_1.as_u32(),
                DEMUX_ID_2.as_u32(),
            )
            .as_bytes()
        );

        // Admins also get user IDs.
        let response = api
            .clone()
            .oneshot(
                Request::get(format!("/v1/call/{}/clients", CALL_ID))
                    .header(
                        sfu::UserId::name(),
                        validate_user_id(USER_ID_1).unwrap().as_str(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            format!(
                r#"{{"endpointIds":["{}"],"demuxIds":[{}],"pendingClients":[{{"demuxId":{},"userId":"{}"}}]}}"#,
                validate_user_id(USER_ID_1)
                    .unwrap()
                    .as_str(),
                DEMUX_ID_1.as_u32(),
                DEMUX_ID_2.as_u32(),
                validate_user_id(USER_ID_2)
                    .unwrap()
                    .as_str()
            )
            .as_bytes()
        );
    }

    #[tokio::test]
    async fn test_join() {
        let config = &DEFAULT_CONFIG;
        let sfu = new_sfu(Instant::now(), config);
        let is_healthy = Arc::new(AtomicBool::new(true));
        let cpu_idle_pct = Arc::new(AtomicU8::new(100));

        let api = signaling_api(config, sfu.clone(), is_healthy, cpu_idle_pct);

        // Join with a invalid DemuxId.
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 1))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: None,
                            region: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            user_agent: None,
                            is_admin: false,
                            room_id: Some(ROOM_ID.into()),
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid CallId.
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", "INVALIDNOTHEX", 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: None,
                            region: None,
                            new_clients_require_approval: false,
                            user_agent: None,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: Some(ROOM_ID.into()),
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid user ID.
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: "".to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: None,
                            region: None,
                            user_agent: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: None,
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid DHE public key
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: "INVALID".to_string(),
                            hkdf_extra_info: None,
                            region: None,
                            user_agent: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: None,
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with an invalid HKDF extra info
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: Some("G".to_string()),
                            region: None,
                            user_agent: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: None,
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Join with good parameters.
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: None,
                            region: None,
                            user_agent: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: None,
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.server_ip, "127.0.0.1");
        assert_eq!(response.server_port, 10000);
        assert_eq!(64, response.server_dhe_public_key.len());
        assert_eq!(ClientStatus::Active.to_string(), response.client_status);

        assert!(
            check_call_exists_in_sfu(sfu.clone(), CALL_ID),
            "Call doesn't exist"
        );
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 1);

        // Attempt to join again using the same demux_id (should be a bad request).
        let response = api
            .clone()
            .oneshot(
                Request::post(format!("/v1/call/{}/client/{}", CALL_ID, 16))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&JoinRequest {
                            user_id: USER_ID_1.to_string(),
                            client_ice_ufrag: UFRAG.to_string(),
                            client_ice_pwd: Some(PWD.to_string()),
                            client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                            hkdf_extra_info: None,
                            region: None,
                            user_agent: None,
                            new_clients_require_approval: false,
                            call_type: CallType::GroupV2,
                            is_admin: false,
                            room_id: None,
                            approved_users: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(get_client_count_in_call_from_sfu(sfu.clone(), CALL_ID), 1);
    }

    #[test]
    fn check_raw_join_request_json() {
        assert_eq!(
            serde_json::json!({
                "endpointId": USER_ID_1,
                "clientIceUfrag": UFRAG,
                "clientIcePwd": PWD,
                "clientDhePublicKey": CLIENT_DHE_PUB_KEY.encode_hex::<String>(),
                "hkdfExtraInfo": null,
                "region": "pangaea",
                "newClientsRequireApproval": false,
                "callType": "GroupV2",
                "isAdmin": false,
                "roomId": ROOM_ID,
                "userAgent": Some(SignalUserAgent::Internal),
                "approvedUsers": ["A", "B"],
            }),
            serde_json::to_value(JoinRequest {
                user_id: USER_ID_1.to_string(),
                client_ice_ufrag: UFRAG.to_string(),
                client_ice_pwd: Some(PWD.to_string()),
                client_dhe_public_key: CLIENT_DHE_PUB_KEY.encode_hex(),
                hkdf_extra_info: None,
                region: Some("pangaea".to_string()),
                user_agent: Some(SignalUserAgent::Internal),
                new_clients_require_approval: false,
                call_type: CallType::GroupV2,
                is_admin: false,
                room_id: Some(RoomId::from(ROOM_ID)),
                approved_users: Some(vec![
                    UserId::from("A".to_string()),
                    UserId::from("B".to_string())
                ]),
            })
            .unwrap()
        )
    }
}
