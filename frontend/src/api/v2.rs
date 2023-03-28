//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{str, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{OriginalUri, State},
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};

use crate::{
    authenticator::UserAuthorization,
    frontend::{Frontend, JoinRequestWrapper, UserId},
    metrics::Timer,
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
    pub call_id: String,
    pub max_devices: u32,
    pub participants: Vec<Participant>,
    pub creator: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub ice_ufrag: String,
    pub dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub demux_id: u32,
    pub port: u16,
    pub ip: String, // TODO remove once all clients use 'ips' field instead
    pub ips: Vec<String>,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub dhe_public_key: String,
    pub call_creator: String,
    #[serde(rename = "conferenceId")]
    pub call_id: String,
}

fn temporary_redirect(uri: &str) -> Result<axum::response::Response, StatusCode> {
    if http::HeaderValue::try_from(uri).is_ok() {
        Ok(Redirect::temporary(uri).into_response())
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Handler for the GET /conference/participants route.
pub async fn get_participants(
    State(frontend): State<Arc<Frontend>>,
    Extension(user_authorization): Extension<UserAuthorization>,
    OriginalUri(original_uri): OriginalUri,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("get_participants:");

    let call = frontend
        .get_call_record(&user_authorization.group_id)
        .await?;

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
        call_id: call.era_id,
        max_devices: frontend.config.max_clients_per_call,
        participants,
        creator: call.creator,
    })
    .into_response())
}

/// Handler for the PUT /conference/participants route.
pub async fn join(
    State(frontend): State<Arc<Frontend>>,
    Extension(user_authorization): Extension<UserAuthorization>,
    OriginalUri(original_uri): OriginalUri,
    Json(request): Json<JoinRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("join: ");

    // Do some simple request verification.
    if request.dhe_public_key.is_empty() {
        warn!("join: dhe_public_key is empty");
        return Err(StatusCode::BAD_REQUEST);
    }

    let get_or_create_timer =
        start_timer_us!("calling.frontend.api.v2.join.get_or_create_call_record.timed");
    let call = frontend
        .get_or_create_call_record(&user_authorization)
        .await?;
    get_or_create_timer.stop();

    if let Some(redirect_uri) = frontend.get_redirect_uri(&call.backend_region, &original_uri) {
        return temporary_redirect(&redirect_uri);
    }

    let join_client_timer =
        start_timer_us!("calling.frontend.api.v2.join.join_client_to_call.timed");
    let response = frontend
        .join_client_to_call(
            &user_authorization.user_id,
            &call,
            JoinRequestWrapper {
                ice_ufrag: request.ice_ufrag,
                dhe_public_key: request.dhe_public_key,
                hkdf_extra_info: request.hkdf_extra_info,
            },
        )
        .await?;
    join_client_timer.stop();

    Ok(Json(JoinResponse {
        demux_id: response.demux_id,
        port: response.port,
        ip: response.ip,
        ips: response.ips,
        ice_ufrag: response.ice_ufrag,
        ice_pwd: response.ice_pwd,
        dhe_public_key: response.dhe_public_key,
        call_creator: call.creator,
        call_id: call.era_id,
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
        authenticator::{Authenticator, HmacSha256, GV2_AUTH_MATCH_LIMIT},
        backend::{self, BackendError, MockBackend},
        config,
        frontend::{DemuxId, FrontendIdGenerator, GroupId, MockIdGenerator},
        storage::{MockStorage, ModernCallRecord},
    };

    const AUTH_KEY: &str = "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b";

    const USER_ID_1: &str = "1111111111111111";
    const USER_ID_2: &str = "2222222222222222";
    const GROUP_ID_1: &str = "aaaaaaaaaaaaaaaa";
    const CALL_ID_1: &str = "a1a1a1a1";
    const ENDPOINT_ID_1: &str = "1111111111111111-123456";
    const DEMUX_ID_1: u32 = 1070920496;
    const ENDPOINT_ID_2: &str = "2222222222222222-987654";
    const DEMUX_ID_2: u32 = 1778901216;
    const LOCAL_REGION: &str = "us-west-1";
    const ALT_REGION: &str = "ap-northeast-2";
    const REDIRECTED_URL: &str = "https://ap-northeast-2.test.com/v2/conference/participants";
    const CLIENT_ICE_UFRAG: &str = "client-ufrag";
    const CLIENT_DHE_PUBLIC_KEY: &str = "f924028e9b8021b77eb97b36f1d43e63";
    const BACKEND_ICE_UFRAG: &str = "backend-ufrag";
    const BACKEND_ICE_PWD: &str = "backend-password";
    const BACKEND_DHE_PUBLIC_KEY: &str = "24c41251f82b1f3481cce4bdaab8976a";

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

    fn create_call_record(backend_region: &str) -> ModernCallRecord {
        ModernCallRecord {
            room_id: GROUP_ID_1.into(),
            era_id: CALL_ID_1.to_string(),
            backend_ip: "127.0.0.1".to_string(),
            backend_region: backend_region.to_string(),
            creator: USER_ID_1.to_string(),
        }
    }

    fn create_join_request() -> JoinRequest {
        JoinRequest {
            ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
            dhe_public_key: CLIENT_DHE_PUBLIC_KEY.to_string(),
            hkdf_extra_info: None,
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
            // group_id: &GroupId
            .with(eq(GroupId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(|_| Ok(None));
        storage
    }

    fn create_mocked_storage_with_call_for_region(region: String) -> Box<MockStorage> {
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_record()
            // group_id: &GroupId
            .with(eq(GroupId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| Ok(Some(create_call_record(&region))));
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
                eq(CALL_ID_1),
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

        assert_eq!(participants_response.call_id, CALL_ID_1);
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
            // group_id: &GroupId
            .with(eq(GroupId::from(GROUP_ID_1)))
            .once()
            // Result<Option<CallRecord>>
            .returning(move |_| Ok(Some(create_call_record(&config.region))))
            .in_sequence(&mut seq);

        backend
            .expect_get_clients()
            // backend_address: &BackendAddress, call_id: &str,
            .with(
                eq(backend::Address::try_from("127.0.0.1").unwrap()),
                eq(CALL_ID_1),
            )
            .once()
            // Result<ClientsResponse, BackendError>
            .returning(|_, _| Err(BackendError::CallNotFound))
            .in_sequence(&mut seq);

        storage
            .expect_remove_call_record()
            // group_id: &GroupId, call_id: &str
            .with(eq(GroupId::from(GROUP_ID_1)), eq(CALL_ID_1))
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
        let mut storage = create_mocked_storage_no_call();
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
        backend
            .expect_select_ip()
            .once()
            // Result<String, BackendError>
            .returning(|| Ok("127.0.0.1".to_string()));

        id_generator
            .expect_get_random_call_id()
            .with(eq(16))
            .once()
            .returning(|_| CALL_ID_1.to_string());

        let expected_call_record = create_call_record(&config.region);

        storage
            .expect_get_or_add_call_record()
            // call: &CallRecord
            .with(eq(expected_call_record))
            .once()
            // Result<Option<CallRecord>, StorageError>
            .returning(move |_| Ok(Some(create_call_record(&config.region))));

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
                eq(CALL_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_1.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
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
        assert_eq!(&join_response.call_id, CALL_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is a call.
    #[tokio::test]
    async fn test_join_with_call() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_with_call_for_region(config.region.to_string());
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
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
                eq(CALL_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: Some(vec!["127.0.0.1".to_string()]),
                    port: 8080,
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
        assert_eq!(&join_response.call_id, CALL_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where there is a call and backend is older and does not return ips.
    #[tokio::test]
    async fn test_join_with_call_old_backend() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_with_call_for_region(config.region.to_string());
        let mut backend = Box::new(MockBackend::new());
        let mut id_generator = Box::new(MockIdGenerator::new());

        // Create additional expectations.
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
                eq(CALL_ID_1),
                eq(expected_demux_id),
                eq(backend::JoinRequest {
                    client_id: ENDPOINT_ID_2.to_string(),
                    ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                    dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                    hkdf_extra_info: None,
                }),
            )
            .once()
            // Result<JoinResponse, BackendError>
            .returning(|_, _, _, _| {
                Ok(backend::JoinResponse {
                    ip: "127.0.0.1".to_string(),
                    ips: None,
                    port: 8080,
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
        assert_eq!(&join_response.call_id, CALL_ID_1);
    }

    /// Invoke the "PUT /v2/conference/participants" to join in the case where the call is
    /// in a different region.
    #[tokio::test]
    async fn test_join_with_call_in_different_region() {
        let config = &CONFIG;

        // Create mocked dependencies with expectations.
        let storage = create_mocked_storage_with_call_for_region(ALT_REGION.to_string());
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
}
