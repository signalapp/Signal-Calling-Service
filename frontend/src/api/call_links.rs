//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{str, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zkgroup::call_links::{
    CallLinkAuthCredentialPresentation, CallLinkPublicParams, CreateCallLinkCredentialPresentation,
};

use crate::{
    frontend::{self, Frontend},
    storage::{self, CallLinkRestrictions, CallLinkUpdateError},
};

#[serde_as]
#[derive(Serialize, Debug)]
struct CallLinkState {
    restrictions: storage::CallLinkRestrictions,
    #[serde_as(as = "serde_with::base64::Base64")]
    name: Vec<u8>,
    revoked: bool,
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    expiration: SystemTime,
}

/// A light wrapper around frontend::RoomId that limits the maximum size when deserializing.
#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct RoomId(frontend::RoomId);

impl TryFrom<String> for RoomId {
    type Error = StatusCode;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 128 {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(Self(value.into()))
    }
}

impl AsRef<str> for RoomId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<RoomId> for frontend::RoomId {
    fn from(value: RoomId) -> Self {
        value.0
    }
}

#[serde_as]
#[derive(Deserialize)]
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

fn current_time_in_seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("server clock is correct")
        .as_secs()
}

fn verify_auth_credential_against_zkparams(
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
        .verify(
            current_time_in_seconds_since_epoch(),
            &frontend.zkparams,
            &call_link_params,
        )
        .map_err(|_| {
            event!("calling.frontend.api.call_links.bad_credential");
            StatusCode::FORBIDDEN
        })?;
    Ok(())
}

/// Handler for the GET /call-link/{room_id} route.
pub async fn read_call_link(
    State(frontend): State<Arc<Frontend>>,
    Extension(auth_credential): Extension<Arc<CallLinkAuthCredentialPresentation>>,
    Path(room_id): Path<RoomId>,
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
    })
    .into_response())
}

/// Handler for the PUT /call-link/{room_id} route.
pub async fn update_call_link(
    State(frontend): State<Arc<Frontend>>,
    auth_credential: Option<Extension<Arc<CallLinkAuthCredentialPresentation>>>,
    create_credential: Option<Extension<Arc<CreateCallLinkCredentialPresentation>>>,
    Path(room_id): Path<RoomId>,
    Json(mut update): Json<CallLinkUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("update_call_link:");

    // Require that call link room IDs are valid hex.
    let room_id_bytes = hex::decode(room_id.as_ref()).map_err(|_| {
        event!("calling.frontend.api.update_call_link.bad_room_id");
        StatusCode::BAD_REQUEST
    })?;

    // Validate the updates.
    if let Some(new_name) = update.name.as_ref() {
        const AES_TAG_AND_SALT_OVERHEAD: usize = 32;
        if new_name.len() > 256 + AES_TAG_AND_SALT_OVERHEAD {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    // Check the credentials.
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
            .and_then(|params| bincode::deserialize(params).ok())
            .ok_or_else(|| {
                event!("calling.frontend.api.update_call_link.invalid_zkparams");
                StatusCode::BAD_REQUEST
            })?;
        create_credential
            .verify(
                &room_id_bytes,
                current_time_in_seconds_since_epoch(),
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
        let existing_call_link = frontend
            .storage
            .get_call_link(&room_id.clone().into())
            .await
            .map_err(|err| {
                error!("update_call_link: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or_else(|| {
                event!("calling.frontend.api.update_call_link.nonexistent_room");
                StatusCode::UNAUTHORIZED
            })?;

        verify_auth_credential_against_zkparams(&auth_credential, &existing_call_link, &frontend)?;
    } else {
        error!("middleware should have enforced either anon or create auth");
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
