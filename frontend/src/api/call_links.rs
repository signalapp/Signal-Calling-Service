//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{fmt::Debug, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    extract::State,
    headers::{self, Header, HeaderName, HeaderValue},
    response::IntoResponse,
    Extension, Json, TypedHeader,
};
use bincode::Options;
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zkgroup::call_links::{
    CallLinkAuthCredentialPresentation, CallLinkPublicParams, CreateCallLinkCredentialPresentation,
};

use crate::{
    frontend::Frontend,
    storage::{self, CallLinkDeleteError, CallLinkRestrictions, CallLinkUpdateError},
};
static X_ROOM_ID: HeaderName = HeaderName::from_static("x-room-id");
const ADMIN_PASSKEY_LIMIT: usize = 32;
const CALL_LINK_NAME_LIMIT: usize = 256;

#[inline(always)]
fn empty_json_object() -> serde_json::Value {
    serde_json::json!({})
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct CallLinkState {
    pub restrictions: storage::CallLinkRestrictions,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub name: Vec<u8>,
    pub revoked: bool,
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    pub expiration: SystemTime,
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    pub delete_at: SystemTime,
}

/// A light wrapper around [`calling_common::RoomId`] that limits the maximum size when
/// deserializing.
#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct RoomId(calling_common::RoomId);

impl TryFrom<String> for RoomId {
    type Error = StatusCode;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 128 {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(Self(value.into()))
    }
}

impl Header for RoomId {
    fn name() -> &'static HeaderName {
        &X_ROOM_ID
    }
    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        if values.next().is_some() {
            return Err(headers::Error::invalid());
        }
        if value.is_empty() || value.len() > 128 {
            return Err(headers::Error::invalid());
        }
        if let Ok(value) = value.to_str() {
            Ok(Self(value.into()))
        } else {
            Err(headers::Error::invalid())
        }
    }
    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        if let Ok(value) = HeaderValue::from_str(self.0.as_ref()) {
            values.extend(std::iter::once(value));
        }
    }
}

impl AsRef<str> for RoomId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<RoomId> for calling_common::RoomId {
    fn from(value: RoomId) -> Self {
        value.0
    }
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)] // rather than silently rejecting something a client wants to do
pub struct CallLinkUpdate {
    #[serde_as(as = "serde_with::base64::Base64")]
    admin_passkey: Vec<u8>,
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    zkparams: Option<Vec<u8>>,
    #[serde(default)]
    restrictions: Option<CallLinkRestrictions>,
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    name: Option<Vec<u8>>,
    #[serde(default)]
    revoked: Option<bool>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallLinkDelete {
    #[serde_as(as = "serde_with::base64::Base64")]
    admin_passkey: Vec<u8>,
}

impl From<CallLinkUpdate> for storage::CallLinkUpdate {
    fn from(value: CallLinkUpdate) -> Self {
        Self {
            admin_passkey: value.admin_passkey,
            restrictions: value.restrictions,
            encrypted_name: value.name,
            revoked: value.revoked,
        }
    }
}

fn current_time() -> zkgroup::Timestamp {
    zkgroup::Timestamp::from_epoch_seconds(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("server clock is correct")
            .as_secs(),
    )
}

pub fn verify_auth_credential_against_zkparams(
    auth_credential: &CallLinkAuthCredentialPresentation,
    existing_call_link: &storage::CallLinkState,
    frontend: &Frontend,
) -> Result<(), StatusCode> {
    let call_link_params: CallLinkPublicParams = bincode::deserialize(&existing_call_link.zkparams)
        .map_err(|err| {
            error!("stored zkparams corrupted: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    auth_credential
        .verify(current_time(), &frontend.zkparams, &call_link_params)
        .map_err(|_| {
            event!("calling.frontend.api.call_links.bad_credential");
            StatusCode::FORBIDDEN
        })?;
    Ok(())
}

/// Handler for the GET /call-link route.
pub async fn read_call_link(
    State(frontend): State<Arc<Frontend>>,
    Extension(auth_credential): Extension<Arc<CallLinkAuthCredentialPresentation>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("read_call_link:");

    let state = match frontend.storage.get_call_link(&room_id.into()).await {
        Ok(Some(state)) => Ok(state),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            error!("read_call_link: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }?;

    verify_auth_credential_against_zkparams(&auth_credential, &state, &frontend)?;

    Ok(Json(CallLinkState {
        restrictions: state.restrictions,
        name: state.encrypted_name,
        revoked: state.revoked,
        expiration: state.expiration,
        delete_at: state.delete_at,
    })
    .into_response())
}

/// Handler for the PUT /call-link route.
pub async fn update_call_link(
    State(frontend): State<Arc<Frontend>>,
    auth_credential: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    create_credential: Option<Extension<Arc<CreateCallLinkCredentialPresentation>>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
    Json(mut update): Json<CallLinkUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("update_call_link:");

    // Require that call link room IDs are valid hex.
    let room_id_bytes = hex::decode(room_id.as_ref()).map_err(|_| {
        event!("calling.frontend.api.update_call_link.bad_room_id");
        StatusCode::BAD_REQUEST
    })?;

    // Validate the updates.
    if update.admin_passkey.len() > ADMIN_PASSKEY_LIMIT {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if let Some(new_name) = update.name.as_ref() {
        const AES_TAG_AND_SALT_OVERHEAD: usize = 32;
        if new_name.len() > CALL_LINK_NAME_LIMIT + AES_TAG_AND_SALT_OVERHEAD {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    // Check preconditions:
    // - Credentials must be valid.
    // - If changing restrictions, there must not be an active call.
    let has_create_credential;
    let zkparams_for_create;
    if let Some(Extension(create_credential)) = create_credential {
        has_create_credential = true;
        zkparams_for_create = update.zkparams.take();
        // Verify the credential against the zkparams provided in the payload.
        // We're trying to create a room, after all, so we are *establishing* those parameters.
        // If a room with the same ID already exists, we'll find that out later.
        let call_link_params: CallLinkPublicParams = zkparams_for_create
            .as_ref()
            .and_then(|params| {
                bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .deserialize(params)
                    .ok()
            })
            .ok_or_else(|| {
                event!("calling.frontend.api.update_call_link.invalid_zkparams");
                StatusCode::BAD_REQUEST
            })?;
        create_credential
            .verify(
                &room_id_bytes,
                current_time(),
                &frontend.zkparams,
                &call_link_params,
            )
            .map_err(|_| {
                event!("calling.frontend.api.update_call_link.bad_credential");
                StatusCode::UNAUTHORIZED
            })?;
    } else if let Some(Extension(auth_credential)) = auth_credential {
        has_create_credential = false;
        zkparams_for_create = None;

        if update.zkparams.is_some() {
            event!("calling.frontend.api.update_call_link.zkparams_on_update");
            return Err(StatusCode::BAD_REQUEST);
        }

        let (maybe_existing_call_link, maybe_current_call_record) = frontend
            .storage
            .get_call_link_and_record(&room_id.clone().into(), true)
            .await
            .map_err(|err| {
                error!("update_call_link: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if let Some(existing_call_link) = maybe_existing_call_link {
            verify_auth_credential_against_zkparams(
                &auth_credential,
                &existing_call_link,
                &frontend,
            )?;
        } else {
            event!("calling.frontend.api.update_call_link.nonexistent_room");
            return Err(StatusCode::UNAUTHORIZED);
        }

        if maybe_current_call_record.is_some() && update.restrictions.is_some() {
            // Cannot change restrictions while a call is active.
            // (It is okay to change the name or revoke a link.)
            return Err(StatusCode::CONFLICT);
        }
    } else {
        error!("neither anon nor create auth provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    match frontend
        .storage
        .update_call_link(&room_id.into(), update.into(), zkparams_for_create)
        .await
    {
        Ok(state) => Ok(Json(CallLinkState {
            restrictions: state.restrictions,
            name: state.encrypted_name,
            revoked: state.revoked,
            expiration: state.expiration,
            delete_at: state.delete_at,
        })
        .into_response()),
        Err(CallLinkUpdateError::AdminPasskeyDidNotMatch) => {
            if has_create_credential {
                Err(StatusCode::CONFLICT)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
        Err(CallLinkUpdateError::RoomDoesNotExist) => {
            if has_create_credential {
                error!("update_call_link: got RoomDoesNotExist, but should have created the room");
            } else {
                error!("update_call_link: got RoomDoesNotExist, but should have checked earlier");
            }
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(CallLinkUpdateError::UnexpectedError(err)) => {
            error!("update_call_link: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for the DELETE /call-link route.
/// Idempotent, succeeds if call link is not found
pub async fn delete_call_link(
    State(frontend): State<Arc<Frontend>>,
    auth_credential: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
    Json(request): Json<CallLinkDelete>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("delete_call_link:");

    let _ = hex::decode(room_id.as_ref()).map_err(|_| {
        event!("calling.frontend.api.delete_call_link.bad_room_id");
        StatusCode::BAD_REQUEST
    })?;
    if request.admin_passkey.len() > ADMIN_PASSKEY_LIMIT {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Check preconditions:
    // - Credentials must be valid.
    // - There must not be an active call.
    if let Some(Extension(auth_credential)) = auth_credential {
        let (maybe_existing_call_link, maybe_current_call_record) = frontend
            .storage
            .get_call_link_and_record(&room_id.clone().into(), true)
            .await
            .map_err(|err| {
                error!("delete_call_link: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if let Some(existing_call_link) = maybe_existing_call_link {
            verify_auth_credential_against_zkparams(
                &auth_credential,
                &existing_call_link,
                &frontend,
            )?;
        } else {
            event!("calling.frontend.api.delete_call_link.nonexistent_room");
            return Ok(Json(empty_json_object()));
        }

        if maybe_current_call_record.is_some() {
            return Err(StatusCode::CONFLICT);
        }
    } else {
        error!("no auth creds provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    match frontend
        .storage
        .delete_call_link(&room_id.into(), &request.admin_passkey)
        .await
    {
        Ok(_) => Ok(Json(empty_json_object())),
        Err(CallLinkDeleteError::AdminPasskeyDidNotMatch) => Err(StatusCode::FORBIDDEN),
        Err(CallLinkDeleteError::RoomDoesNotExist) => Ok(Json(empty_json_object())),
        Err(CallLinkDeleteError::CallRecordConflict) => Err(StatusCode::CONFLICT),
        Err(CallLinkDeleteError::UnexpectedError(err)) => {
            error!("delete_call_link: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for the POST /call-link/reset-expiration route, used only for testing.
#[cfg(any(debug_assertions, feature = "testing"))]
pub async fn reset_call_link_expiration(
    State(frontend): State<Arc<Frontend>>,
    Extension(auth_credential): Extension<Arc<CallLinkAuthCredentialPresentation>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("reset_call_link_expiration:");

    // Require that call link room IDs are valid hex.
    let _ = hex::decode(room_id.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let existing_call_link = frontend
        .storage
        .get_call_link(&room_id.clone().into())
        .await
        .map_err(|err| {
            error!("reset_call_link_expiration: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    verify_auth_credential_against_zkparams(&auth_credential, &existing_call_link, &frontend)?;

    match frontend
        .storage
        .reset_call_link_expiration(&room_id.into(), SystemTime::now())
        .await
    {
        Ok(()) => Ok(()),
        Err(CallLinkUpdateError::AdminPasskeyDidNotMatch) => {
            unreachable!("not checked by this entry point");
        }
        Err(CallLinkUpdateError::RoomDoesNotExist) => {
            // We just checked, though there could be a race.
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(CallLinkUpdateError::UnexpectedError(err)) => {
            error!("reset_call_link_expiration: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for the DELETE /call-link/approvals route, used only for testing.
#[cfg(any(debug_assertions, feature = "testing"))]
pub async fn reset_call_link_approvals(
    State(frontend): State<Arc<Frontend>>,
    Extension(auth_credential): Extension<Arc<CallLinkAuthCredentialPresentation>>,
    TypedHeader(room_id): TypedHeader<RoomId>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("reset_call_link_approvals:");

    // Require that call link room IDs are valid hex.
    let _ = hex::decode(room_id.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let existing_call_link = frontend
        .storage
        .get_call_link(&room_id.clone().into())
        .await
        .map_err(|err| {
            error!("reset_call_link_approvals: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    verify_auth_credential_against_zkparams(&auth_credential, &existing_call_link, &frontend)?;

    match frontend
        .storage
        .update_call_link_approved_users(&room_id.into(), vec![])
        .await
    {
        Ok(()) => Ok(()),
        Err(CallLinkUpdateError::AdminPasskeyDidNotMatch) => {
            unreachable!("not checked by this entry point");
        }
        Err(CallLinkUpdateError::RoomDoesNotExist) => {
            // We just checked, though there could be a race.
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(CallLinkUpdateError::UnexpectedError(err)) => {
            error!("reset_call_link_approvals: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use calling_common::Duration;
    use hex::FromHex;
    use http::{header, Request};
    use hyper::Body;
    use mockall::predicate::*;
    use once_cell::sync::Lazy;
    use tower::ServiceExt;
    use zkgroup::call_links::CallLinkAuthCredentialResponse;
    use zkgroup::call_links::CallLinkSecretParams;
    use zkgroup::call_links::CreateCallLinkCredentialRequestContext;

    use crate::{
        api::app, api::v2::api_server_v2_tests::create_call_record, authenticator::Authenticator,
        backend::MockBackend, config, frontend::FrontendIdGenerator, storage::MockStorage,
    };

    const AUTH_KEY: &str = "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b";
    const ZKPARAMS: &str = "AMJqvmQRYwEGlm0MSy6QFPIAvgOVsqRASNX1meQyCOYHJFqxO8lITPkow5kmhPrsNbu9JhVfKFwesVSKhdZaqQko3IZlJZMqP7DDw0DgTWpdnYzSt0XBWT50DM1cw1nCUXXBZUiijdaFs+JRlTKdh54M7sf43pFxyMHlS3URH50LOeR8jVQKaUHi1bDP2GR9ZXp3Ot9Fsp0pM4D/vjL5PwoOUuzNNdpIqUSFhKVrtazwuHNn9ecHMsFsN0QPzByiDA8nhKcGpdzyWUvGjEDBvpKkBtqjo8QuXWjyS3jSl2oJ/Z4Fh3o2N1YfD2aWV/K88o+TN2/j2/k+KbaIZgmiWwppLU+SYGwthxdDfZgnbaaGT/vMYX9P5JlUWSuP3xIxDzPzxBEFho67BP0Pvux+0a5nEOEVEpfRSs61MMvwNXEKZtzkO0QFbOrFYrPntyb7ToqNi66OQNyTfl/J7kqFZg2MTm3CKjHTAIvVMFAGCIamsrT9sWXOtuNeMS94xazxDA==";

    pub const USER_ID_1: &str = "11111111111111111111111111111111";
    pub const USER_ID_1_DOUBLE_ENCODED: &str = "00b033dec3c913aa7d087a49be7bbf4115cd441453778a73d5c705f3515d500841b867748697709fe3f587f796d6c9b20104a27cd1250af6b330fc0dd4eda07005";
    const ROOM_ID: &str = "ff0000dd";
    pub const ADMIN_PASSKEY: &[u8] = b"swordfish";

    pub const X_ROOM_ID: &str = "X-Room-Id";

    const DISTANT_FUTURE_IN_EPOCH_SECONDS: u64 = 4133980800; // 2101-01-01
    const DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS: u64 =
        4133980800 + storage::CallLinkState::DELETION_TIMER.as_secs();

    static DISTANT_FUTURE: Lazy<SystemTime> = Lazy::new(|| {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(DISTANT_FUTURE_IN_EPOCH_SECONDS)
    });

    static DISTANT_FUTURE_DELETE_AT: Lazy<SystemTime> = Lazy::new(|| {
        SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(DISTANT_FUTURE_IN_EPOCH_SECONDS)
            + storage::CallLinkState::DELETION_TIMER
    });

    static CONFIG: Lazy<config::Config> = Lazy::new(|| {
        initialize_logging();
        let mut config = config::default_test_config();
        config.authentication_key = AUTH_KEY.to_string();
        config
    });

    static CALL_LINK_SECRET_PARAMS: Lazy<CallLinkSecretParams> =
        Lazy::new(|| CallLinkSecretParams::derive_from_root_key(b"testing"));

    fn initialize_logging() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("calling_frontend=info")
                .default_write_style_or("never"),
        )
        .format_timestamp_millis()
        .is_test(true)
        .try_init();
    }

    fn create_frontend(storage: Box<MockStorage>) -> Arc<Frontend> {
        Arc::new(Frontend {
            config: &CONFIG,
            authenticator: Authenticator::from_hex_key(AUTH_KEY).unwrap(),
            zkparams: bincode::deserialize(&STANDARD.decode(ZKPARAMS).unwrap()).unwrap(),
            storage,
            backend: Box::new(MockBackend::new()),
            id_generator: Box::new(FrontendIdGenerator),
            api_metrics: Default::default(),
        })
    }

    fn start_of_today() -> zkgroup::Timestamp {
        let now: Duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time moves forwards")
            .into();

        zkgroup::Timestamp::from_epoch_seconds(
            now.truncated_to(Duration::from_secs(24 * 60 * 60))
                .as_secs(),
        )
    }

    pub fn create_authorization_header_for_user(frontend: &Frontend, user_id: &str) -> String {
        let public_server_params = frontend.zkparams.get_public_params();
        let user_id = libsignal_core::Aci::from_uuid_bytes(
            FromHex::from_hex(user_id).expect("valid user ID"),
        );
        let redemption_time = start_of_today();
        let credential = CallLinkAuthCredentialResponse::issue_credential(
            user_id,
            redemption_time,
            &frontend.zkparams,
            rand::random(),
        )
        .receive(user_id, redemption_time, &public_server_params)
        .expect("just created")
        .present(
            user_id,
            redemption_time,
            &public_server_params,
            &CALL_LINK_SECRET_PARAMS,
            rand::random(),
        );
        format!(
            "Bearer auth.{}",
            STANDARD.encode(bincode::serialize(&credential).expect("can serialize"))
        )
    }

    pub fn create_authorization_header_for_creator(frontend: &Frontend, user_id: &str) -> String {
        let public_server_params = frontend.zkparams.get_public_params();
        let user_id = libsignal_core::Aci::from_uuid_bytes(
            FromHex::from_hex(user_id).expect("valid user ID"),
        );
        let room_id = Vec::from_hex(ROOM_ID).expect("valid room ID");

        let request_context = CreateCallLinkCredentialRequestContext::new(&room_id, rand::random());
        let response = request_context.get_request().issue(
            user_id,
            start_of_today(),
            &frontend.zkparams,
            rand::random(),
        );

        let credential = request_context
            .receive(response, user_id, &public_server_params)
            .expect("just created")
            .present(
                &room_id,
                user_id,
                &public_server_params,
                &CALL_LINK_SECRET_PARAMS,
                rand::random(),
            );
        format!(
            "Bearer create.{}",
            STANDARD.encode(bincode::serialize(&credential).expect("can serialize"))
        )
    }

    pub fn default_call_link_state() -> storage::CallLinkState {
        storage::CallLinkState {
            admin_passkey: ADMIN_PASSKEY.into(),
            zkparams: bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params())
                .expect("can serialize"),
            restrictions: CallLinkRestrictions::None,
            encrypted_name: vec![],
            revoked: false,
            expiration: *DISTANT_FUTURE,
            delete_at: *DISTANT_FUTURE_DELETE_AT,
            approved_users: vec![],
        }
    }

    #[tokio::test]
    async fn test_get_not_found() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok(None));
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_wrong_zkparams() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok(Some(storage::CallLinkState {
                    zkparams: bincode::serialize(
                        &CallLinkSecretParams::derive_from_root_key(b"different")
                            .get_public_params(),
                    )
                    .unwrap(),
                    ..default_call_link_state()
                }))
            });
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_missing_room_id() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_multiple_room_id() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_success() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| Ok(Some(default_call_link_state())));
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "none",
                "name": "",
                "revoked": false,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_get_success_alternate_values() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)))
            .once()
            .return_once(|_| {
                Ok(Some(storage::CallLinkState {
                    encrypted_name: b"abc".to_vec(),
                    revoked: true,
                    restrictions: CallLinkRestrictions::AdminApproval,
                    ..default_call_link_state()
                }))
            });
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .body(Body::empty())
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "adminApproval",
                "name": STANDARD.encode(b"abc"),
                "revoked": true,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_create_missing_admin_passkey() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params()).unwrap(),
                    )
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        // This error comes from the Json extractor.
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_create_missing_zkparams() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_wrong_zkparams() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let wrong_params = CallLinkSecretParams::derive_from_root_key(b"wrong");
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&wrong_params.get_public_params()).unwrap(),
                    )
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_success() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: None,
                        encrypted_name: None,
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_some());
                Ok(default_call_link_state())
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params()).unwrap(),
                    )
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "none",
                "name": "",
                "revoked": false,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_create_with_initial_values() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: Some(CallLinkRestrictions::AdminApproval),
                        encrypted_name: Some(b"abc".to_vec()),
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_some());
                // Remember that we're not testing the storage logic here.
                // This is the return value the real storage implementation will produce
                // for a new room, or for an existing room whose parameters all match.
                Ok(storage::CallLinkState {
                    encrypted_name: b"abc".to_vec(),
                    restrictions: CallLinkRestrictions::AdminApproval,
                    ..default_call_link_state()
                })
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params()).unwrap(),
                    ),
                    "restrictions": "adminApproval",
                    "name": STANDARD.encode(b"abc"),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "adminApproval",
                "name": STANDARD.encode(b"abc"),
                "revoked": false,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_create_conflict() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: None,
                        encrypted_name: None,
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_some());
                Err(storage::CallLinkUpdateError::AdminPasskeyDidNotMatch)
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_creator(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params()).unwrap(),
                    ),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_update_missing_admin_passkey() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({})).unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        // This error comes from the Json extractor.
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_update_with_zkparams() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "zkparams": STANDARD.encode(
                        bincode::serialize(&CALL_LINK_SECRET_PARAMS.get_public_params()).unwrap(),
                    ),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_not_found() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((None, None)));
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_update_wrong_zkparams() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(storage::CallLinkState {
                        zkparams: bincode::serialize(
                            &CallLinkSecretParams::derive_from_root_key(b"different")
                                .get_public_params(),
                        )
                        .unwrap(),
                        ..default_call_link_state()
                    }),
                    None,
                ))
            });
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_wrong_passkey() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: b"different".to_vec(),
                        restrictions: None,
                        encrypted_name: None,
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_none());
                Err(storage::CallLinkUpdateError::AdminPasskeyDidNotMatch)
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(b"different"),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_success() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: Some(CallLinkRestrictions::AdminApproval),
                        encrypted_name: Some(b"abc".to_vec()),
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_none());
                // Remember that we're not testing the storage logic here.
                Ok(storage::CallLinkState {
                    encrypted_name: b"abc".to_vec(),
                    restrictions: CallLinkRestrictions::AdminApproval,
                    ..default_call_link_state()
                })
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "restrictions": "adminApproval",
                    "name": STANDARD.encode(b"abc"),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "adminApproval",
                "name": STANDARD.encode(b"abc"),
                "revoked": false,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_update_title_during_active_call() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, "pangaea")),
                ))
            });
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: None,
                        encrypted_name: Some(b"abc".to_vec()),
                        revoked: None,
                    }
                );
                assert!(zkparams_for_creation.is_none());
                // Remember that we're not testing the storage logic here.
                Ok(storage::CallLinkState {
                    encrypted_name: b"abc".to_vec(),
                    restrictions: CallLinkRestrictions::None,
                    ..default_call_link_state()
                })
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "name": STANDARD.encode(b"abc"),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "none",
                "name": STANDARD.encode(b"abc"),
                "revoked": false,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_update_revocation_during_active_call() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, "pangaea")),
                ))
            });
        storage.expect_update_call_link().once().return_once(
            |room_id, new_attributes, zkparams_for_creation| {
                assert_eq!(room_id.as_ref(), ROOM_ID);
                assert_eq!(
                    new_attributes,
                    storage::CallLinkUpdate {
                        admin_passkey: ADMIN_PASSKEY.into(),
                        restrictions: None,
                        encrypted_name: None,
                        revoked: Some(true),
                    }
                );
                assert!(zkparams_for_creation.is_none());
                // Remember that we're not testing the storage logic here.
                Ok(storage::CallLinkState {
                    encrypted_name: vec![],
                    restrictions: CallLinkRestrictions::None,
                    revoked: true,
                    ..default_call_link_state()
                })
            },
        );
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "revoked": true,
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        // Compare as JSON values to check the encoding of the non-primitive types.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "restrictions": "none",
                "name": "",
                "revoked": true,
                "expiration": DISTANT_FUTURE_IN_EPOCH_SECONDS,
                "delete_at": DISTANT_FUTURE_DELETE_AT_IN_EPOCH_SECONDS,
            })
        );
    }

    #[tokio::test]
    async fn test_update_restrictions_during_active_call_fails() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, "pangaea")),
                ))
            });
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                    "restrictions": "adminApproval",
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_link_during_active_call_fails() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| {
                Ok((
                    Some(default_call_link_state()),
                    Some(create_call_record(ROOM_ID, "pangaea")),
                ))
            });
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_link_succeeds() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage
            .expect_delete_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(ADMIN_PASSKEY))
            .once()
            .return_once(|_, _| Ok(()));

        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).expect("valid utf-8");
        assert_eq!(body, "{}");
    }

    #[tokio::test]
    async fn test_delete_link_absent_succeeds() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((None, None)));
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_link_no_auth_fails() {
        // Create mocked dependencies with expectations.
        let storage = Box::new(MockStorage::new());
        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Submit the request.
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_link_storage_call_conflict_fails() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage
            .expect_delete_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(ADMIN_PASSKEY))
            .once()
            .return_once(|_, _| Err(CallLinkDeleteError::CallRecordConflict));

        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        // Call Record Conflict case
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_link_storage_room_not_found_succeeds() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage
            .expect_delete_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(ADMIN_PASSKEY))
            .once()
            .return_once(|_, _| Err(CallLinkDeleteError::RoomDoesNotExist));

        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_link_storage_adminkey_mismatch_fails() {
        // Create mocked dependencies with expectations.
        let mut storage = Box::new(MockStorage::new());
        storage
            .expect_get_call_link_and_record()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(true))
            .once()
            .return_once(|_, _| Ok((Some(default_call_link_state()), None)));
        storage
            .expect_delete_call_link()
            .with(eq(calling_common::RoomId::from(ROOM_ID)), eq(ADMIN_PASSKEY))
            .once()
            .return_once(|_, _| Err(CallLinkDeleteError::AdminPasskeyDidNotMatch));

        let frontend = create_frontend(storage);

        // Create an axum application.
        let app = app(frontend.clone());

        // Create the request.
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("/v1/call-link".to_string())
            .header(X_ROOM_ID, ROOM_ID)
            .header(header::USER_AGENT, "test/user/agent")
            .header(
                header::AUTHORIZATION,
                create_authorization_header_for_user(&frontend, USER_ID_1),
            )
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "adminPasskey": STANDARD.encode(ADMIN_PASSKEY),
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
