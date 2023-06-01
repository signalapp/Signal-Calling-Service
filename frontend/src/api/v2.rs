//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{str, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    response::{IntoResponse, Redirect},
    Extension, Json, TypedHeader,
};
use hex::ToHex;
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use subtle::ConstantTimeEq;
use zkgroup::call_links::CallLinkAuthCredentialPresentation;

use crate::{
    api::call_links::{verify_auth_credential_against_zkparams, RoomId},
    authenticator::UserAuthorization,
    frontend::{Frontend, JoinRequestWrapper, UserId},
    metrics::Timer,
    storage::CallLinkRestrictions,
};

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub opaque_user_id: UserId,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_tcp: Option<u16>,
    pub ip: String, // TODO remove once all clients use 'ips' field instead
    pub ips: Vec<String>,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub dhe_public_key: String,
    pub call_creator: String,
    #[serde(rename = "conferenceId")]
    pub era_id: String,
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

/// Handler for the GET /conference/:room_id/participants route.
pub async fn get_participants_by_room_id(
    frontend: State<Arc<Frontend>>,
    maybe_auth_credential: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    Path(room_id): Path<RoomId>,
    original_uri: OriginalUri,
) -> Result<impl IntoResponse, StatusCode> {
    get_participants(
        frontend,
        None,
        maybe_auth_credential,
        Some(axum::TypedHeader(room_id)),
        original_uri,
    )
    .await
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

    let call = match (group_auth, call_links_auth, room_id) {
        (Some(Extension(user_authorization)), None, None) => {
            frontend
                .get_call_record(&user_authorization.room_id)
                .await?
        }
        (None, Some(Extension(auth_credential)), Some(TypedHeader(room_id))) => {
            let room_id = room_id.into();

            match frontend.storage.get_call_link_and_record(&room_id).await {
                Ok((Some(state), call)) => {
                    verify_auth_credential_against_zkparams(&auth_credential, &state, &frontend)?;
                    if let Some(call) = call {
                        call
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

    let participants = frontend
        .get_client_ids_in_call(&call)
        .await?
        .into_iter()
        .map(|client_id| {
            Ok(Participant {
                opaque_user_id: Frontend::get_opaque_user_id_from_endpoint_id(&client_id)?,
                demux_id: Frontend::get_demux_id_from_endpoint_id(&client_id)?.as_u32(),
            })
        })
        .collect::<Result<Vec<_>>>()
        .map_err(|err| {
            error!(
                "get_participants: could not generate participants list: {}",
                err
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(ParticipantsResponse {
        era_id: call.era_id,
        max_devices: frontend.config.max_clients_per_call,
        participants,
        creator: call.creator,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct Region {
    region: Option<String>,
}

/// Handler for the PUT /conference/:room_id/participants route.
pub async fn join_by_room_id(
    frontend: State<Arc<Frontend>>,
    maybe_auth_credential: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    Path(room_id): Path<RoomId>,
    original_uri: OriginalUri,
    region: Query<Region>,
    request: Json<JoinRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    join(
        frontend,
        None,
        maybe_auth_credential,
        Some(axum::TypedHeader(room_id)),
        original_uri,
        region,
        request,
    )
    .await
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

    let region = if let Some(region) = region.region {
        region
    } else {
        frontend.config.region.clone()
    };

    let (call, user_id, restrictions, is_admin) = match (group_auth, call_links_auth, room_id) {
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
            )
        }
        (None, Some(Extension(auth_credential)), Some(TypedHeader(room_id))) => {
            let room_id = room_id.into();

            match frontend.storage.get_call_link_and_record(&room_id).await {
                Ok((Some(state), call)) => {
                    verify_auth_credential_against_zkparams(&auth_credential, &state, &frontend)?;

                    if state.revoked || state.expiration < SystemTime::now() {
                        return Ok(not_found("expired"));
                    } else {
                        let is_admin = if let Some(provided_passkey) = request.admin_passkey {
                            bool::from(state.admin_passkey.ct_eq(&provided_passkey))
                        } else {
                            false
                        };
                        let user_id = auth_credential.get_user_id();
                        // Encode as hex for compatability with existing user ids
                        let user_id = bincode::serialize(&user_id).unwrap().encode_hex();
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
                                call
                            }
                        };

                        (call, user_id, state.restrictions, is_admin)
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
            },
        )
        .await?;
    join_client_timer.stop();

    Ok(Json(JoinResponse {
        demux_id: response.demux_id,
        port: response.port,
        port_tcp: response.port_tcp,
        ip: response.ip,
        ips: response.ips,
        ice_ufrag: response.ice_ufrag,
        ice_pwd: response.ice_pwd,
        dhe_public_key: response.dhe_public_key,
        call_creator: call.creator,
        era_id: call.era_id,
    })
    .into_response())
}

#[cfg(test)]
mod api_server_v2_tests {
    use super::*;

    use std::str;
    use std::time::SystemTime;

    use hex::{FromHex, ToHex};
    use hmac::Mac;
    use http::{header, Request};
    use hyper::Body;
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
        frontend::{DemuxId, FrontendIdGenerator, MockIdGenerator, RoomId},
        storage::{CallRecord, MockStorage},
    };

    const AUTH_KEY: &str = "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b";
    const ZKPARAMS: &str = "AMJqvmQRYwEGlm0MSy6QFPIAvgOVsqRASNX1meQyCOYHJFqxO8lITPkow5kmhPrsNbu9JhVfKFwesVSKhdZaqQko3IZlJZMqP7DDw0DgTWpdnYzSt0XBWT50DM1cw1nCUXXBZUiijdaFs+JRlTKdh54M7sf43pFxyMHlS3URH50LOeR8jVQKaUHi1bDP2GR9ZXp3Ot9Fsp0pM4D/vjL5PwoOUuzNNdpIqUSFhKVrtazwuHNn9ecHMsFsN0QPzByiDA8nhKcGpdzyWUvGjEDBvpKkBtqjo8QuXWjyS3jSl2oJ/Z4Fh3o2N1YfD2aWV/K88o+TN2/j2/k+KbaIZgmiWwppLU+SYGwthxdDfZgnbaaGT/vMYX9P5JlUWSuP3xIxDzPzxBEFho67BP0Pvux+0a5nEOEVEpfRSs61MMvwNXEKZtzkO0QFbOrFYrPntyb7ToqNi66OQNyTfl/J7kqFZg2MTm3CKjHTAIvVMFAGCIamsrT9sWXOtuNeMS94xazxDA==";

    const USER_ID_1: &str = "1111111111111111";
    const USER_ID_2: &str = "2222222222222222";
    const GROUP_ID_1: &str = "aaaaaaaaaaaaaaaa";
    const ERA_ID_1: &str = "a1a1a1a1";
    const ENDPOINT_ID_1: &str = "1111111111111111-123456";
    const DEMUX_ID_1: u32 = 1070920496;
    const ENDPOINT_ID_2: &str = "2222222222222222-987654";
    const DEMUX_ID_2: u32 = 1778901216;
    const LOCAL_REGION: &str = "us-west1";
    const ALT_REGION: &str = "asia-northeast3";
    const REDIRECTED_URL: &str =
        "https://asia-northeast3.test.com/v2/conference/participants?region=us-west1";
    const REDIRECTED_CALL_LINKS_URL: &str =
        "https://asia-northeast3.test.com/v2/conference/ff0000dd/participants?region=us-west1";
    const CLIENT_ICE_UFRAG: &str = "client-ufrag";
    const CLIENT_DHE_PUBLIC_KEY: &str = "f924028e9b8021b77eb97b36f1d43e63";
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
            base64::encode(format!("{}:{}", user_id, password))
        )
    }

    fn create_authorization_header_for_user(user_id: &str) -> String {
        create_authorization_header(user_id, "1")
    }

    fn create_authorization_header_for_user_no_permission(user_id: &str) -> String {
        create_authorization_header(user_id, "0")
    }

    fn create_call_record(room_id: &str, backend_region: &str) -> CallRecord {
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
        let client_ids = vec![ENDPOINT_ID_1.to_string(), ENDPOINT_ID_2.to_string()];

        backend::ClientsResponse { client_ids }
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
            // backend_address: &BackendAddress, call_id: &str,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
            )
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _| Ok(create_clients_response_two_calls()));
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
            zkparams: bincode::deserialize(&base64::decode(ZKPARAMS).unwrap()).unwrap(),
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
            zkparams: bincode::deserialize(&base64::decode(ZKPARAMS).unwrap()).unwrap(),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
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
            // backend_address: &BackendAddress, call_id: &str,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
            )
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _| Err(BackendError::CallNotFound))
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
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_1.try_into().unwrap(), ENDPOINT_ID_1.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_1.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_2))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is a call and backend is older and does not return ips.
    #[tokio::test]
    async fn test_join_with_call_old_backend() {
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
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_2))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: None,
                    port: 8080,
                    port_tcp: None,
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call.
    #[tokio::test]
    async fn test_call_link_get_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(default_call_link_state()), None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert!(body.is_empty());
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call_link.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call_link, but the room id collides with a group call.
    #[tokio::test]
    async fn test_call_link_get_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants.
    #[tokio::test]
    async fn test_call_link_get_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants, but the call link is revoked
    #[tokio::test]
    async fn test_call_link_get_with_call_link_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants, but the call link is expired
    #[tokio::test]
    async fn test_call_link_get_with_call_link_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where the call is in a
    /// different region.
    #[tokio::test]
    async fn test_call_link_get_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call in storage
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
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, &config.region)),
                ))
            })
            .in_sequence(&mut seq);

        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
            )
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _| Err(BackendError::CallNotFound))
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is no call yet.
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
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(default_call_link_state()), None)))
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
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_1.try_into().unwrap(), ENDPOINT_ID_1.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_1.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call.
    #[tokio::test]
    async fn test_call_link_join_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_join_with_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }
    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_join_with_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call and user is admin.
    #[tokio::test]
    async fn test_call_link_join_with_call_as_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: true,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call and user has the wrong admin passkey.
    #[tokio::test]
    async fn test_call_link_join_with_call_wrong_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and no call link.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, None)));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call link, but there is a call on the room id.
    #[tokio::test]
    async fn test_call_link_join_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the call is
    /// in a different region.
    #[tokio::test]
    async fn test_call_link_join_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join with an empty DHE public key.
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the request is
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
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

    /// tests with old style urls
    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call.
    #[tokio::test]
    async fn test_call_link_old_get_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(default_call_link_state()), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert!(body.is_empty());
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_old_get_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_old_get_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call_link.
    #[tokio::test]
    async fn test_call_link_old_get_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is no call_link, but the room id collides with a group call.
    #[tokio::test]
    async fn test_call_link_old_get_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants.
    #[tokio::test]
    async fn test_call_link_old_get_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants, but the call link is revoked
    #[tokio::test]
    async fn test_call_link_old_get_with_call_link_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call
    /// with two participants, but the call link is expired
    #[tokio::test]
    async fn test_call_link_old_get_with_call_link_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let participants_response: ParticipantsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(participants_response.era_id, ERA_ID_1);
        assert_eq!(
            participants_response.max_devices,
            config.max_clients_per_call
        );
        assert_eq!(participants_response.creator, USER_ID_1);
        assert_eq!(participants_response.participants.len(), 2);

        assert_eq!(
            participants_response.participants[0].opaque_user_id,
            USER_ID_1
        );
        assert_eq!(participants_response.participants[0].demux_id, DEMUX_ID_1);
        assert_eq!(
            participants_response.participants[1].opaque_user_id,
            USER_ID_2
        );
        assert_eq!(participants_response.participants[1].demux_id, DEMUX_ID_2);
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where the call is in a
    /// different region.
    #[tokio::test]
    async fn test_call_link_old_get_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
            REDIRECTED_CALL_LINKS_URL
        );
    }

    /// Invoke the "GET /v2/conference/:room_id/participants" in the case where there is a call in storage
    /// but it is no longer present on the backend (for example it just expired).
    #[tokio::test]
    async fn test_call_link_old_get_with_call_but_expired_on_backend() {
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
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, &config.region)),
                ))
            })
            .in_sequence(&mut seq);

        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
            )
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _| Err(BackendError::CallNotFound))
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is no call yet.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut seq = Sequence::new();
        let mut storage = Box::new(MockStorage::new());
        let mut expected_call_record = create_call_record(ROOM_ID, LOCAL_REGION);
        expected_call_record.creator = USER_ID_1_DOUBLE_ENCODED.to_string();
        let resulting_call_record = create_call_record(ROOM_ID, LOCAL_REGION);

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(default_call_link_state()), None)))
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
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_1.try_into().unwrap(), ENDPOINT_ID_1.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_1.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_1.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_1);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call.
    #[tokio::test]
    async fn test_call_link_old_join_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(None);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_old_join_with_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }
    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_old_join_with_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call and user is admin.
    #[tokio::test]
    async fn test_call_link_old_join_with_call_as_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: true,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where there is a call and user has the wrong admin passkey.
    #[tokio::test]
    async fn test_call_link_old_join_with_call_wrong_admin() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, LOCAL_REGION)),
                ))
            });
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        id_generator
            .expect_get_random_demux_id_and_endpoint_id()
            // user_id: &str
            .with(eq(USER_ID_1_DOUBLE_ENCODED))
            .once()
            // Result<(DemuxId, String), FrontendError>
            .returning(|_| Ok((DEMUX_ID_2.try_into().unwrap(), ENDPOINT_ID_2.to_string())));

        let expected_demux_id: DemuxId = DEMUX_ID_2.try_into().unwrap();

        backend
            .expect_join()
            // backend_address: &BackendAddress, call_id: &str, demux_id: DemuxId, join_request: &JoinRequest,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(ERA_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                    region: LOCAL_REGION.to_string(),
                    is_admin: false,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
                    port_tcp: Some(8080),
                    ice_ufrag: BACKEND_ICE_UFRAG.to_string(),
                    ice_pwd: BACKEND_ICE_PWD.to_string(),
                    dhe_public_key: Some(BACKEND_DHE_PUBLIC_KEY.to_string()),
                })
            });

        let frontend = create_frontend_with_id_generator(config, storage, backend, id_generator);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(b"joshua"));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let join_response: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_response.demux_id, DEMUX_ID_2);
        assert_eq!(join_response.port, 8080);
        assert_eq!(join_response.ip, "127.0.0.1".to_string());
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and the call link is expired.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_call_expired() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.expiration = SystemTime::UNIX_EPOCH;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and the call link is revoked.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_call_revoked() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        let mut call_link_state = default_call_link_state();
        call_link_state.revoked = true;

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((Some(call_link_state), None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "expired");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call, and no call link.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_call_link() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, None)));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" in the case where there is no call link, but there is a call on the room id.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_call_link_collision_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());

        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok((None, Some(create_call_record(ROOM_ID, LOCAL_REGION)))));
        let backend = create_mocked_backend_unused();

        let frontend = create_frontend(config, storage, backend);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let join_request = create_call_link_join_request(Some(ADMIN_PASSKEY));

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.reason, "invalid");
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the call is
    /// in a different region.
    #[tokio::test]
    async fn test_call_link_old_join_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
            REDIRECTED_CALL_LINKS_URL
        );
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join with an empty DHE public key.
    #[tokio::test]
    async fn test_call_link_old_join_with_empty_dhe_public_key() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the request is
    /// missing the authorization header.
    #[tokio::test]
    async fn test_call_link_old_join_with_no_authorization_header() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header is empty.
    #[tokio::test]
    async fn test_call_link_old_join_with_empty_authorization_header() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header is invalid.
    #[tokio::test]
    async fn test_call_link_old_join_with_invalid_authorization_header() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Nope")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header is a group call header instead of a CallLinkAuthCredential.
    #[tokio::test]
    async fn test_call_link_old_join_with_group_call_auth() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header is a CreateCallLinkCredential instead of a CallLinkAuthCredential.
    #[tokio::test]
    async fn test_call_link_old_join_with_group_creator_auth() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header has a missing token.
    #[tokio::test]
    async fn test_call_link_old_join_with_authorization_header_missing_token() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::AUTHORIZATION, "Bearer auth.")
            .body(Body::from(join_request))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Invoke the "PUT /v2/conference/:room_id/participants" to join in the case where the authorization
    /// header has an invalid token.
    #[tokio::test]
    async fn test_call_link_old_join_with_authorization_header_invalid_token() {
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
            .uri(format!("/v2/conference/{ROOM_ID}/participants"))
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
