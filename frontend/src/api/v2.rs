//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{str, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    extract::{OriginalUri, Query, State},
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use axum_extra::TypedHeader;
use hex::ToHex;
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use subtle::ConstantTimeEq;
use zkgroup::call_links::CallLinkAuthCredentialPresentation;

use crate::{
    api::call_links::{self, verify_auth_credential_against_zkparams, CallLinkState, RoomId},
    authenticator::UserAuthorization,
    frontend::{Frontend, JoinRequestWrapper, UserId},
    metrics::Timer,
    storage::{self, CallLinkRestrictions},
};

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_user_id: Option<UserId>,
    pub demux_id: u32,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantsResponse {
    #[serde(rename = "conferenceId")]
    pub era_id: String,
    pub max_devices: u32,
    pub participants: Vec<Participant>,
    pub creator: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub pending_clients: Vec<Participant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_link_state: Option<CallLinkState>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    pub admin_passkey: Option<Vec<u8>>,
    pub ice_ufrag: String,
    pub dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub demux_id: u32,
    pub port: u16,
    pub port_tcp: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_tls: Option<u16>,
    pub ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub dhe_public_key: String,
    pub call_creator: String,
    #[serde(rename = "conferenceId")]
    pub era_id: String,
    pub client_status: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ErrorResponse<'a> {
    pub reason: &'a str,
}

fn temporary_redirect(uri: &str) -> Result<axum::response::Response, StatusCode> {
    if http::HeaderValue::try_from(uri).is_ok() {
        Ok(Redirect::temporary(uri).into_response())
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
fn not_found(reason: &str) -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(ErrorResponse { reason })).into_response()
}

fn user_id_from_uuid_ciphertext(ciphertext: &zkgroup::groups::UuidCiphertext) -> UserId {
    // Encode as hex for compatibility with existing user ids
    bincode::serialize(&ciphertext).unwrap().encode_hex()
}

impl From<storage::CallLinkState> for call_links::CallLinkState {
    fn from(value: storage::CallLinkState) -> Self {
        CallLinkState {
            name: value.encrypted_name,
            restrictions: value.restrictions,
            revoked: value.revoked,
            expiration: value.expiration,
            delete_at: value.delete_at,
        }
    }
}

/// Handler for the GET /conference/participants route.
pub async fn get_participants(
    State(frontend): State<Arc<Frontend>>,
    group_auth: Option<Extension<UserAuthorization>>,
    call_links_auth: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    room_id: Option<TypedHeader<RoomId>>,
    OriginalUri(original_uri): OriginalUri,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("get_participants:");

    let (call, user_id, call_link_state) = match (group_auth, call_links_auth, room_id) {
        (Some(Extension(user_authorization)), None, None) => (
            frontend
                .get_call_record(&user_authorization.room_id)
                .await?,
            user_authorization.user_id,
            None,
        ),
        (None, Some(Extension(auth_credential)), Some(TypedHeader(room_id))) => {
            let room_id = room_id.into();

            match frontend
                .storage
                .get_call_link_and_record(&room_id, true)
                .await
            {
                Ok((Some(state), call)) => {
                    verify_auth_credential_against_zkparams(&auth_credential, &state, &frontend)?;
                    if let Some(call) = call {
                        (
                            call,
                            user_id_from_uuid_ciphertext(&auth_credential.get_user_id()),
                            Some(state),
                        )
                    } else if state.revoked || state.expiration < SystemTime::now() {
                        return Ok(not_found("expired"));
                    } else {
                        return Err(StatusCode::NOT_FOUND);
                    }
                }
                Ok((None, _)) => return Ok(not_found("invalid")),
                Err(err) => {
                    error!("get_participants_by_room_id: {err}");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
        (_, None, Some(_)) => return Err(StatusCode::UNAUTHORIZED), // wrong auth type for call link
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    if let Some(redirect_uri) = frontend.get_redirect_uri(&call.backend_region, &original_uri) {
        return temporary_redirect(&redirect_uri);
    }

    let clients_response = frontend.get_client_ids_in_call(&call, &user_id).await?;
    let participants = clients_response
        .active_clients
        .into_iter()
        .map(|client| Participant {
            opaque_user_id: client.opaque_user_id,
            demux_id: client.demux_id.as_u32(),
        })
        .collect();
    let pending_clients = clients_response
        .pending_clients
        .into_iter()
        .map(|client| Participant {
            opaque_user_id: client.opaque_user_id,
            demux_id: client.demux_id.as_u32(),
        })
        .collect();

    let call_link_state = call_link_state.map(|s| s.into());

    Ok(Json(ParticipantsResponse {
        era_id: call.era_id,
        max_devices: frontend.config.max_clients_per_call,
        participants,
        creator: call.creator,
        pending_clients,
        call_link_state,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct Region {
    region: Option<String>,
}

/// Handler for the PUT /conference/participants route.
pub async fn join(
    State(frontend): State<Arc<Frontend>>,
    group_auth: Option<Extension<UserAuthorization>>,
    call_links_auth: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    room_id: Option<TypedHeader<RoomId>>,
    OriginalUri(original_uri): OriginalUri,
    Query(region): Query<Region>,
    Json(request): Json<JoinRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("join: ");
    // Do some simple request verification.
    if request.dhe_public_key.is_empty() {
        warn!("join: dhe_public_key is empty");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = SystemTime::now();

    let region = if let Some(region) = region.region {
        region
    } else {
        frontend.config.region.clone()
    };

    let (call, user_id, restrictions, is_admin, approved_users) = match (
        group_auth,
        call_links_auth,
        room_id,
    ) {
        (Some(Extension(user_authorization)), None, None) => {
            let get_or_create_timer =
                start_timer_us!("calling.frontend.api.v2.join.get_or_create_call_record.timed");
            let call = frontend
                .get_or_create_call_record(
                    &user_authorization.room_id,
                    user_authorization.user_permission.can_create(),
                    &user_authorization.user_id,
                )
                .await?;
            get_or_create_timer.stop();
            (
                call,
                user_authorization.user_id,
                CallLinkRestrictions::None,
                false,
                None,
            )
        }
        (None, Some(Extension(auth_credential)), Some(TypedHeader(room_id))) => {
            let room_id = room_id.into();

            match frontend
                .storage
                .get_call_link_and_record(&room_id, false)
                .await
            {
                Ok((Some(state), call)) => {
                    verify_auth_credential_against_zkparams(&auth_credential, &state, &frontend)?;

                    if state.revoked || state.expiration < now {
                        return Ok(not_found("expired"));
                    } else {
                        let is_admin = if let Some(provided_passkey) = request.admin_passkey {
                            bool::from(state.admin_passkey.ct_eq(&provided_passkey))
                        } else {
                            false
                        };
                        let user_id = user_id_from_uuid_ciphertext(&auth_credential.get_user_id());
                        let call = match call {
                            Some(call) => call,
                            None => {
                                let get_or_create_timer =
                        start_timer_us!("calling.frontend.api.v2.join_by_room_id.get_or_create_call_record.timed");
                                let can_create = true;
                                let call = frontend
                                    .get_or_create_call_record(&room_id, can_create, &user_id)
                                    .await?;
                                get_or_create_timer.stop();

                                // Reset the expiration when a call link call is started for the first time.
                                // We do this in a separate tokio task to avoid additional latency for the user trying to start a call.
                                let frontend_for_task = frontend.clone();
                                tokio::spawn(async move {
                                    time_scope_us!("calling.frontend.api.v2.join_by_room_id.reset_call_link_expiration_in_background.timed");
                                    match frontend_for_task
                                        .storage
                                        .reset_call_link_expiration(&room_id, now)
                                        .await
                                    {
                                        Ok(()) => {
                                            debug!("successfully reset call link expiration")
                                        }
                                        Err(err) => {
                                            warn!("failed to reset call link expiration on create: {err}");
                                        }
                                    }
                                });

                                call
                            }
                        };

                        (
                            call,
                            user_id,
                            state.restrictions,
                            is_admin,
                            Some(state.approved_users),
                        )
                    }
                }
                Ok((None, _)) => return Ok(not_found("invalid")),
                Err(err) => {
                    error!("join_by_room_id: {err}");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
        (_, None, Some(_)) => return Err(StatusCode::UNAUTHORIZED), // wrong auth type for call link
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    if let Some(redirect_uri) = frontend.get_redirect_uri(&call.backend_region, &original_uri) {
        return temporary_redirect(&redirect_uri);
    }

    let join_client_timer =
        start_timer_us!("calling.frontend.api.v2.join.join_client_to_call.timed");
    let response = frontend
        .join_client_to_call(
            &user_id,
            &call,
            JoinRequestWrapper {
                ice_ufrag: request.ice_ufrag,
                dhe_public_key: request.dhe_public_key,
                hkdf_extra_info: request.hkdf_extra_info,
                region,
                restrictions,
                is_admin,
                approved_users,
            },
        )
        .await?;
    join_client_timer.stop();

    Ok(Json(JoinResponse {
        demux_id: response.demux_id,
        port: response.port,
        port_tcp: response.port_tcp,
        port_tls: response.port_tls,
        ips: response.ips,
        hostname: response.hostname,
        ice_ufrag: response.ice_ufrag,
        ice_pwd: response.ice_pwd,
        dhe_public_key: response.dhe_public_key,
        call_creator: call.creator,
        era_id: call.era_id,
        client_status: response.client_status,
    })
    .into_response())
}

#[cfg(test)]
pub mod api_server_v2_tests {
    use super::*;

    use std::str;
    use std::time::SystemTime;

    use axum::body::Body;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use calling_common::{DemuxId, RoomId};
    use hex::{FromHex, ToHex};
    use hmac::Mac;
    use http::{header, Request};
    use mockall::predicate::*;
    use mockall::Sequence;
    use once_cell::sync::Lazy;
    use tower::ServiceExt;

    use crate::{
        api::app,
        api::call_links::tests::{
            create_authorization_header_for_creator,
            create_authorization_header_for_user as create_call_links_authorization_header_for_user,
            default_call_link_state, ADMIN_PASSKEY, USER_ID_1 as CALL_LINKS_USER_ID_1,
            USER_ID_1_DOUBLE_ENCODED, X_ROOM_ID,
        },
        authenticator::{Authenticator, HmacSha256, GV2_AUTH_MATCH_LIMIT},
        backend::{self, BackendError, MockBackend},
        config,
        frontend::{FrontendIdGenerator, MockIdGenerator},
        storage::{CallRecord, MockStorage},
    };

    const AUTH_KEY: &str = "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b";
    const ZKPARAMS: &str = "AMJqvmQRYwEGlm0MSy6QFPIAvgOVsqRASNX1meQyCOYHJFqxO8lITPkow5kmhPrsNbu9JhVfKFwesVSKhdZaqQko3IZlJZMqP7DDw0DgTWpdnYzSt0XBWT50DM1cw1nCUXXBZUiijdaFs+JRlTKdh54M7sf43pFxyMHlS3URH50LOeR8jVQKaUHi1bDP2GR9ZXp3Ot9Fsp0pM4D/vjL5PwoOUuzNNdpIqUSFhKVrtazwuHNn9ecHMsFsN0QPzByiDA8nhKcGpdzyWUvGjEDBvpKkBtqjo8QuXWjyS3jSl2oJ/Z4Fh3o2N1YfD2aWV/K88o+TN2/j2/k+KbaIZgmiWwppLU+SYGwthxdDfZgnbaaGT/vMYX9P5JlUWSuP3xIxDzPzxBEFho67BP0Pvux+0a5nEOEVEpfRSs61MMvwNXEKZtzkO0QFbOrFYrPntyb7ToqNi66OQNyTfl/J7kqFZg2MTm3CKjHTAIvVMFAGCIamsrT9sWXOtuNeMS94xazxDA==";

    pub static ACTIVE_CLIENT_STATUS: Lazy<String> = Lazy::new(|| "active".to_string());

    pub const USER_ID_1: &str = "1111111111111111";
    const USER_ID_2: &str = "2222222222222222";
    pub const GROUP_ID_1: &str = "aaaaaaaaaaaaaaaa";
    pub const ERA_ID_1: &str = "a1a1a1a1";
    pub const DEMUX_ID_1: u32 = 1070920496;
    const DEMUX_ID_2: u32 = 1778901216;
    pub const LOCAL_REGION: &str = "us-west1";
    const ALT_REGION: &str = "asia-northeast3";
    const REDIRECTED_URL: &str =
        "https://asia-northeast3.test.com/v2/conference/participants?region=us-west1";
    pub const CLIENT_ICE_UFRAG: &str = "client-ufrag";
    pub const CLIENT_DHE_PUBLIC_KEY: &str = "f924028e9b8021b77eb97b36f1d43e63";
    const BACKEND_ICE_UFRAG: &str = "backend-ufrag";
    const BACKEND_ICE_PWD: &str = "backend-password";
    const BACKEND_DHE_PUBLIC_KEY: &str = "24c41251f82b1f3481cce4bdaab8976a";

    const ROOM_ID: &str = "ff0000dd";

    static CONFIG: Lazy<config::Config> = Lazy::new(|| {
        let mut config = config::default_test_config();
        config.authentication_key = AUTH_KEY.to_string();
        config.region = LOCAL_REGION.to_string();
        config.regional_url_template = "https://<region>.test.com".to_string();
        config
    });

    fn generate_signed_v2_password(
        user_id_hex: &str,
        group_id_hex: &str,
        timestamp: u64,
        permission: &str,
        key: &[u8; 32],
    ) -> String {
        // Format the credentials string.
        let credentials = format!(
            "2:{}:{}:{}:{}",
            user_id_hex, group_id_hex, timestamp, permission
        );

        // Get the MAC for the credentials.
        let mut hmac = HmacSha256::new_from_slice(key).unwrap();
        hmac.update(credentials.as_bytes());
        let mac = hmac.finalize().into_bytes();
        let mac = &mac[..GV2_AUTH_MATCH_LIMIT];

        // Append the MAC to the credentials.
        format!("{}:{}", credentials, mac.encode_hex::<String>())
    }

    fn create_authorization_header(user_id: &str, permission: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let password = generate_signed_v2_password(
            user_id,
            GROUP_ID_1,
            timestamp.as_secs(),
            permission,
            &<[u8; 32]>::from_hex(AUTH_KEY).unwrap(),
        );

        // Append the username to the password, encode in base64, and prefix
        // with 'Basic' for a valid authorization_header.
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", user_id, password))
        )
    }

    fn create_authorization_header_for_user(user_id: &str) -> String {
        create_authorization_header(user_id, "1")
    }

    fn create_authorization_header_for_user_no_permission(user_id: &str) -> String {
        create_authorization_header(user_id, "0")
    }

    pub fn create_call_record(room_id: &str, backend_region: &str) -> CallRecord {
        CallRecord {
            room_id: room_id.into(),
            era_id: ERA_ID_1.to_string(),
            backend_ip: "127.0.0.1".to_string(),
            backend_region: backend_region.to_string(),
            creator: USER_ID_1.to_string(),
        }
    }

    fn create_join_request() -> JoinRequest {
        JoinRequest {
            admin_passkey: None,
            ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
            dhe_public_key: CLIENT_DHE_PUBLIC_KEY.to_string(),
            hkdf_extra_info: None,
        }
    }

    fn create_call_link_join_request(passkey: Option<&[u8]>) -> Vec<u8> {
        if let Some(passkey) = passkey {
            serde_json::to_vec(&JoinRequest {
                ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                dhe_public_key: CLIENT_DHE_PUBLIC_KEY.to_string(),
                hkdf_extra_info: None,
                admin_passkey: Some(passkey.into()),
            })
            .unwrap()
        } else {
            serde_json::to_vec(&JoinRequest {
                admin_passkey: None,
                ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                dhe_public_key: CLIENT_DHE_PUBLIC_KEY.to_string(),
                hkdf_extra_info: None,
            })
            .unwrap()
        }
    }

    fn create_clients_response_two_calls() -> backend::ClientsResponse {
        let client_ids = vec![USER_ID_1.to_string(), USER_ID_2.to_string()];
        let demux_ids = vec![DEMUX_ID_1, DEMUX_ID_2];

        backend::ClientsResponse {
            user_ids: client_ids,
            demux_ids,
            pending_clients: vec![],
        }
    }

    fn create_mocked_storage_unused() -> Box<MockStorage> {
        Box::new(MockStorage::new())
    }

    fn create_mocked_storage_no_call() -> Box<MockStorage> {
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_record()
            // room_id: &RoomId
            .with(eq(RoomId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(|_| Ok(None));
        storage
    }

    fn create_mocked_storage_with_call_for_region(region: String) -> Box<MockStorage> {
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_record()
            // room_id: &RoomId
            .with(eq(RoomId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| Ok(Some(create_call_record(GROUP_ID_1, &region))));
        storage
    }

    fn create_mocked_storage_for_join(region: &str, user: &str) -> Box<MockStorage> {
        let mut storage = Box::new(MockStorage::new());
        let mut expected_call_record = create_call_record(GROUP_ID_1, region);
        expected_call_record.creator = user.to_string();
        let resulting_call_record = create_call_record(GROUP_ID_1, region);
        storage
            .expect_get_or_add_call_record()
            // call: CallRecord
            .with(eq(expected_call_record))
            .once()
            // Result<CallRecord>
            .return_once(move |_| Ok(resulting_call_record));
        storage
    }

    fn create_mocked_backend_unused() -> Box<MockBackend> {
        Box::new(MockBackend::new())
    }

    fn create_mocked_backend_two_calls() -> Box<MockBackend> {
        let mut backend = Box::new(MockBackend::new());
        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str, user_id: Option<&UserId>,
            // We have to use 'withf' because of the nested reference in 'user_id'.
            .withf(|backend_address, call_id, user_id| {
                backend_address == &backend::Address::try_from("127.0.0.1").unwrap()
                    && call_id == ERA_ID_1
                    && user_id.is_some()
            })
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(move |_, _, _| Ok(create_clients_response_two_calls()));
        backend
    }

    fn create_frontend(
        config: &'static config::Config,
        storage: Box<MockStorage>,
        backend: Box<MockBackend>,
    ) -> Arc<Frontend> {
        Arc::new(Frontend {
            config,
            authenticator: Authenticator::from_hex_key(AUTH_KEY).unwrap(),
            zkparams: bincode::deserialize(&STANDARD.decode(ZKPARAMS).unwrap()).unwrap(),
            storage,
            backend,
            id_generator: Box::new(FrontendIdGenerator),
            api_metrics: Default::default(),
        })
    }

    fn create_frontend_with_id_generator(
        config: &'static config::Config,
        storage: Box<MockStorage>,
        backend: Box<MockBackend>,
        id_generator: Box<MockIdGenerator>,
    ) -> Arc<Frontend> {
        Arc::new(Frontend {
            config,
            authenticator: Authenticator::from_hex_key(AUTH_KEY).unwrap(),
            zkparams: bincode::deserialize(&STANDARD.decode(ZKPARAMS).unwrap()).unwrap(),
            storage,
            backend,
            id_generator,
            api_metrics: Default::default(),
        })
    }

    /// Invoke the "GET /v2/conference/participants" in the case where there is no call.
    #[tokio::test]
    async fn test_get_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_no_call();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Invoke the "GET /v2/conference/participants" in the case where there is a call
    /// with two participants.
    #[tokio::test]
    async fn test_get_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_with_call_for_region(config.region.to_string());
        let backend = create_mocked_backend_two_calls();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_2)
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
        assert!(participants_response.call_link_state.is_none());
    }

    /// Invoke the "GET /v2/conference/participants" in the case where the call is in a
    /// different region.
    #[tokio::test]
    async fn test_get_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_with_call_for_region(ALT_REGION.to_string());
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .unwrap()
                .to_str()
                .unwrap(),
            REDIRECTED_URL
        );
    }

    /// Invoke the "GET /v2/conference/participants" in the case where there is a call in storage
    /// but it is no longer present on the backend (for example it just expired).
    #[tokio::test]
    async fn test_get_with_call_but_expired_on_backend() {
        let config = &CONFIG;

        // Create mocked dependencies.
        let mut storage = Box::new(MockStorage::new());
        let mut backend = Box::new(MockBackend::new());

        // For this test, we'll make sure the calls are in sequence and make sure that
        // the call is being deleted from the database at the end since it is no longer
        // present on the backend.
        let mut seq = Sequence::new();

        // Create expectations.
        storage
            .expect_get_call_record()
            // room_id: &RoomId
            .with(eq(RoomId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| Ok(Some(create_call_record(GROUP_ID_1, &config.region))))
            .in_sequence(&mut seq);

        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str, user_id: Option<&UserId>,
            // We have to use 'withf' because of the nested reference in 'user_id'.
            .withf(|backend_address, call_id, user_id| {
                backend_address == &backend::Address::try_from("127.0.0.1").unwrap()
                    && call_id == ERA_ID_1
                    && user_id.map(|user_id| user_id.as_str()) == Some(USER_ID_1)
            })
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _, _| Err(BackendError::CallNotFound))
            .in_sequence(&mut seq);

        storage
            .expect_remove_call_record()
            // room_id: &RoomId, era_id: &str
            .with(eq(RoomId::from(GROUP_ID_1)), eq(ERA_ID_1))
            .once()
            // Result<()>
            .returning(|_, _| Ok(()))
            .in_sequence(&mut seq);

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is no call yet.
    #[tokio::test]
    async fn test_join_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_for_join(&config.region, USER_ID_1);
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));

        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());

        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_1.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: false,
                    room_id: RoomId::from(GROUP_ID_1),
                    approved_users: None,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is a call.
    #[tokio::test]
    async fn test_join_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_for_join(&config.region, USER_ID_2);
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));
        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());
        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_2))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_2.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: false,
                    room_id: RoomId::from(GROUP_ID_1),
                    approved_users: None,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_2),
            )
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the call is
    /// in a different region.
    #[tokio::test]
    async fn test_join_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut backend = Box::new(MockBackend::new());
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));
        let mut id_generator = Box::new(MockIdGenerator::new());
        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());

        let mut expected_call_record = create_call_record(GROUP_ID_1, &config.region);
        expected_call_record.creator = USER_ID_2.to_string();
        let resulting_call_record = create_call_record(GROUP_ID_1, ALT_REGION);
        storage
            .expect_get_or_add_call_record()
            // call: CallRecord
            .with(eq(expected_call_record))
            .once()
            // Result<CallRecord>
            .return_once(move |_| Ok(resulting_call_record));

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_2),
            )
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .unwrap()
                .to_str()
                .unwrap(),
            REDIRECTED_URL
        );
    }

    /// Invoke the "PUT /v2/conference/participants" to join with an empty DHE public key.
    #[tokio::test]
    async fn test_join_with_empty_dhe_public_key() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = JoinRequest {
            admin_passkey: None,
            ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
            dhe_public_key: "".to_string(),
            hkdf_extra_info: None,
        };

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is no call yet
    /// but the user has no permission to create a call.
    #[tokio::test]
    async fn test_join_with_no_call_no_create_permission() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_no_call();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user_no_permission(USER_ID_1),
            )
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the request is
    /// missing the authorization header.
    #[tokio::test]
    async fn test_join_with_no_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the authorization
    /// header is empty.
    #[tokio::test]
    async fn test_join_with_empty_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "")
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the authorization
    /// header is invalid.
    #[tokio::test]
    async fn test_join_with_invalid_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Nope")
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the authorization
    /// header has a missing token.
    #[tokio::test]
    async fn test_join_with_authorization_header_missing_token() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Basic ")
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the authorization
    /// header has an invalid token.
    #[tokio::test]
    async fn test_join_with_authorization_header_invalid_token() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_join_request();

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants")
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Basic 12345")
            .body(Body::from(serde_json::to_vec(&join_request).unwrap()))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is no call.
    #[tokio::test]
    async fn test_call_link_get_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is no call_link.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((None, None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is no call_link, but the room id collides with a group call.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call
    /// with two participants.
    #[tokio::test]
    async fn test_call_link_get_with_call() {
        let config = &CONFIG;

        let call_link_state = default_call_link_state();
        let expected_call_link_state_response = call_link_state.clone().into();

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let backend = create_mocked_backend_two_calls();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_2)
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
        assert_eq!(
            participants_response.call_link_state.unwrap(),
            expected_call_link_state_response
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call
    /// with one active participant and one pending client.
    #[tokio::test]
    async fn test_call_link_get_with_pending_client() {
        let config = &CONFIG;

        let call_link_state = default_call_link_state();
        let expected_call_link_state_response = call_link_state.clone().into();

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });

        let mut backend = Box::new(MockBackend::new());
        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str, user_id: Option<&UserId>,
            // We have to use 'withf' because of the nested reference in 'user_id'.
            .withf(|backend_address, call_id, user_id| {
                backend_address == &backend::Address::try_from("127.0.0.1").unwrap()
                    && call_id == ERA_ID_1
                    && user_id.is_some()
            })
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(move |_, _, _| {
                Ok(backend::ClientsResponse {
                    user_ids: vec![USER_ID_1.into()],
                    demux_ids: vec![DEMUX_ID_1],
                    pending_clients: vec![backend::ClientInfo {
                        demux_id: DEMUX_ID_2,
                        user_id: Some(USER_ID_2.into()),
                    }],
                })
            });

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 1);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(participants_response.pending_clients.len(), 1);
        assert_eq!(
            participants_response.pending_clients[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_2)
        );
        assert_eq!(
            participants_response.pending_clients[0].demux_id,
            DEMUX_ID_2
        );
        assert_eq!(
            participants_response.call_link_state.unwrap(),
            expected_call_link_state_response
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call with
    /// one active participant and one pending client, but the requester is not an admin and so gets
    /// no user IDs for the pending clients.
    #[tokio::test]
    async fn test_call_link_get_with_pending_client_for_non_admin() {
        let config = &CONFIG;

        let call_link_state = default_call_link_state();
        let expected_call_link_state_response = call_link_state.clone().into();

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });

        let mut backend = Box::new(MockBackend::new());
        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str, user_id: Option<&UserId>,
            // We have to use 'withf' because of the nested reference in 'user_id'.
            .withf(|backend_address, call_id, user_id| {
                backend_address == &backend::Address::try_from("127.0.0.1").unwrap()
                    && call_id == ERA_ID_1
                    && user_id.is_some()
            })
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(move |_, _, _| {
                Ok(backend::ClientsResponse {
                    user_ids: vec![USER_ID_1.into()],
                    demux_ids: vec![DEMUX_ID_1],
                    pending_clients: vec![backend::ClientInfo {
                        demux_id: DEMUX_ID_2,
                        user_id: None,
                    }],
                })
            });

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 1);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(participants_response.pending_clients.len(), 1);
        assert_eq!(
            participants_response.pending_clients[0].opaque_user_id,
            None
        );
        assert_eq!(
            participants_response.pending_clients[0].demux_id,
            DEMUX_ID_2
        );
        assert_eq!(
            participants_response.call_link_state.unwrap(),
            expected_call_link_state_response
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call
    /// with two participants, but the call link is revoked
    #[tokio::test]
    async fn test_call_link_get_with_call_link_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;
        let expected_call_link_state_response = call_link_state.clone().into();

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let backend = create_mocked_backend_two_calls();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_2)
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
        assert_eq!(
            participants_response.call_link_state.unwrap(),
            expected_call_link_state_response
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call
    /// with two participants, but the call link is expired
    #[tokio::test]
    async fn test_call_link_get_with_call_link_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;
        let expected_call_link_state_response = call_link_state.clone().into();

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let backend = create_mocked_backend_two_calls();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_1)
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1]
                .opaque_user_id
                .as_deref(),
            Some(USER_ID_2)
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
        assert_eq!(
            participants_response.call_link_state.unwrap(),
            expected_call_link_state_response
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where the call is in a
    /// different region.
    #[tokio::test]
    async fn test_call_link_get_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, ALT_REGION)),
                ))
            });
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .unwrap()
                .to_str()
                .unwrap(),
            REDIRECTED_URL
        );
    }

    /// Invoke the "GET /v2/conference/participants" for a call link in the case where there is a call in storage
    /// but it is no longer present on the backend (for example it just expired).
    #[tokio::test]
    async fn test_call_link_get_with_call_but_expired_on_backend() {
        let config = &CONFIG;

        // Create mocked dependencies.
        let mut storage = Box::new(MockStorage::new());
        let mut backend = Box::new(MockBackend::new());

        // For this test, we'll make sure the calls are in sequence and make sure that
        // the call is being deleted from the database at the end since it is no longer
        // present on the backend.
        let mut seq = Sequence::new();

        // Create expectations.
        storage
            .expect_get_call_link_and_record()
            // room_id: &RoomId
            .with(eq(RoomId::from(ROOM_ID)), eq(true))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, &config.region)),
                ))
            })
            .in_sequence(&mut seq);

        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str, user_id: Option<&UserId>,
            // We have to use 'withf' because of the nested reference in 'user_id'.
            .withf(|backend_address, call_id, user_id| {
                backend_address == &backend::Address::try_from("127.0.0.1").unwrap()
                    && call_id == ERA_ID_1
                    && user_id.is_some()
            })
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _, _| Err(BackendError::CallNotFound))
            .in_sequence(&mut seq);

        storage
            .expect_remove_call_record()
            // room_id: &RoomId, era_id: &str
            .with(eq(RoomId::from(ROOM_ID)), eq(ERA_ID_1))
            .once()
            // Result<()>
            .returning(|_, _| Ok(()))
            .in_sequence(&mut seq);

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is no call yet.
    #[tokio::test]
    async fn test_call_link_join_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut seq = Sequence::new();
        let mut storage = Box::new(MockStorage::new());
        let mut expected_call_record = create_call_record(ROOM_ID, LOCAL_REGION);
        expected_call_record.creator = USER_ID_1_DOUBLE_ENCODED.to_string();
        let resulting_call_record = create_call_record(ROOM_ID, LOCAL_REGION);

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)))
            .in_sequence(&mut seq);

        storage
            .expect_get_or_add_call_record()
            .with(eq(expected_call_record))
            .once()
            .return_once(move |_| Ok(resulting_call_record))
            .in_sequence(&mut seq);

        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));

        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());

        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_1.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec![]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();
        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is no call yet; this time, the call link requires admin approval.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_requiring_admin_approval() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut seq = Sequence::new();
        let mut storage = Box::new(MockStorage::new());
        let mut expected_call_record = create_call_record(ROOM_ID, LOCAL_REGION);
        expected_call_record.creator = USER_ID_1_DOUBLE_ENCODED.to_string();
        let resulting_call_record = create_call_record(ROOM_ID, LOCAL_REGION);

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                let mut state = default_call_link_state();
                state.restrictions = CallLinkRestrictions::AdminApproval;
                Ok((Some(state), None))
            })
            .in_sequence(&mut seq);

        storage
            .expect_get_or_add_call_record()
            .with(eq(expected_call_record))
            .once()
            .return_once(move |_| Ok(resulting_call_record))
            .in_sequence(&mut seq);

        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));

        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());

        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_1.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: true,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec![]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();
        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is no call yet; this time, the call link requires admin approval and has a list of approved users.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_and_approved_users() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut seq = Sequence::new();
        let mut storage = Box::new(MockStorage::new());
        let mut expected_call_record = create_call_record(ROOM_ID, LOCAL_REGION);
        expected_call_record.creator = USER_ID_1_DOUBLE_ENCODED.to_string();
        let resulting_call_record = create_call_record(ROOM_ID, LOCAL_REGION);

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                let mut state = default_call_link_state();
                state.restrictions = CallLinkRestrictions::AdminApproval;
                state.approved_users = vec!["11223344".to_string(), "aabbccdd".to_string()];
                Ok((Some(state), None))
            })
            .in_sequence(&mut seq);

        storage
            .expect_get_or_add_call_record()
            .with(eq(expected_call_record))
            .once()
            .return_once(move |_| Ok(resulting_call_record))
            .in_sequence(&mut seq);

        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));

        id_generator
            .expect_get_random_era_id()
            .with(eq(16))
            .once()
            .returning(|_| ERA_ID_1.to_string());

        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_1.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: true,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec!["11223344".to_string(), "aabbccdd".to_string()]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();
        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call.
    #[tokio::test]
    async fn test_call_link_join_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_2.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec![]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call, and there are also approved users.
    #[tokio::test]
    async fn test_call_link_join_with_call_and_approved_users() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .return_once(|_, _| {
                let mut state = default_call_link_state();
                state.restrictions = CallLinkRestrictions::AdminApproval;
                state.approved_users = vec!["11223344".to_string(), "aabbccdd".to_string()];
                Ok((Some(state), Some(create_call_record(ROOM_ID, LOCAL_REGION))))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_2.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: true,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec!["11223344".to_string(), "aabbccdd".to_string()]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_join_with_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let backend = create_mocked_backend_unused();
        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }
    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_join_with_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(call_link_state),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let backend = create_mocked_backend_unused();
        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call and user is admin.
    #[tokio::test]
    async fn test_call_link_join_with_call_as_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_2.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: true,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec![]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where there is a call and user has the wrong admin passkey.
    #[tokio::test]
    async fn test_call_link_join_with_call_wrong_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // DemuxId
            .returning(|_| DEMUX_ID_2.try_into().unwrap());

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    user_id: USER_ID_1_DOUBLE_ENCODED.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    new_clients_require_approval: false,
                    is_admin: false,
                    room_id: RoomId::from(ROOM_ID),
                    approved_users: Some(vec![]),
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ips: vec!["127.0.0.1".to_string()],
                    port: 8080,
                    port_tcp: 8080,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: BACKEND_DHE_PUBLIC_KEY.to_string(),
                    client_status: ACTIVE_CLIENT_STATUS.clone(),
                    hostname: None,
                    port_tls: None,
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(b"joshua"));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(join_response.ice_ufrag, BACKEND_ICE_UFRAG.to_string());
        assert_eq!(join_response.ice_pwd, BACKEND_ICE_PWD.to_string());
        assert_eq!(
            join_response.dhe_public_key,
            BACKEND_DHE_PUBLIC_KEY.to_string()
        );
        assert_eq!(&join_response.call_creator, USER_ID_1);
        assert_eq!(&join_response.era_id, ERA_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link in the case where there is no call, and no call link.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| Ok((None, None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link in the case where there is no call link, but there is a call on the room id.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the call is
    /// in a different region.
    #[tokio::test]
    async fn test_call_link_join_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)), eq(false))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, ALT_REGION)),
                ))
            });
        let backend = create_mocked_backend_unused();
        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .unwrap()
                .to_str()
                .unwrap(),
            REDIRECTED_URL
        );
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join with an empty DHE public key.
    #[tokio::test]
    async fn test_call_link_join_with_empty_dhe_public_key() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = JoinRequest {
            admin_passkey: None,
            ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
            dhe_public_key: "".to_string(),
            hkdf_extra_info: None,
        };
        let join_request = serde_json::to_vec(&join_request).unwrap();

        create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_call_links_authorization_header_for_user(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the request is
    /// missing the authorization header.
    #[tokio::test]
    async fn test_call_link_join_with_no_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header is empty.
    #[tokio::test]
    async fn test_call_link_join_with_empty_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header is invalid.
    #[tokio::test]
    async fn test_call_link_join_with_invalid_authorization_header() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Nope")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header is a group call header instead of a CallLinkAuthCredential.
    #[tokio::test]
    async fn test_call_link_join_with_group_call_auth() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header is a CreateCallLinkCredential instead of a CallLinkAuthCredential.
    #[tokio::test]
    async fn test_call_link_join_with_group_creator_auth() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, CALL_LINKS_USER_ID_1),
            )
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header has a missing token.
    #[tokio::test]
    async fn test_call_link_join_with_authorization_header_missing_token() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Bearer auth.")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/participants" for a call link to join in the case where the authorization
    /// header has an invalid token.
    #[tokio::test]
    async fn test_call_link_join_with_authorization_header_invalid_token() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_unused();
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend);

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v2/conference/participants".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Bearer Auth.12345")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_room_id_request_deserialize() {
        let serialized =
            "{\"iceUfrag\":\"client-ufrag\",\"dhePublicKey\":\"f924028e9b8021b77eb97b36f1d43e63\"}";
        println!("serialized {:?}", serialized);
        let deserialized: Result<JoinRequest, serde_json::Error> = serde_json::from_str(serialized);
        println!("deserialized {:?}", deserialized);
        assert!(deserialized.is_ok());
    }
}
