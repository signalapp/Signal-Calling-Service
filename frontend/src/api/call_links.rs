//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{str, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

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
        if value.len() > 128 {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(Self(value.into()))
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
    #[serde(default)]
    restrictions: Option<CallLinkRestrictions>,
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    name: Option<Vec<u8>>,
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

/// Handler for the GET /call-link/{room_id} route.
// TODO: authorization
pub async fn read_call_link(
    State(frontend): State<Arc<Frontend>>,
    Path(room_id): Path<RoomId>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("read_call_link:");

    match frontend.storage.get_call_link(&room_id.into()).await {
        Ok(Some(state)) => Ok(Json(CallLinkState {
            restrictions: state.restrictions,
            name: state.encrypted_name,
            revoked: state.revoked,
            expiration: state.expiration,
        })
        .into_response()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            error!("read_call_link: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for the PUT /call-link/{room_id} route.
// TODO: authorization
pub async fn update_call_link(
    State(frontend): State<Arc<Frontend>>,
    Path(room_id): Path<RoomId>,
    Json(update): Json<CallLinkUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    trace!("update_call_link:");

    // Validate the updates.
    if let Some(new_name) = update.name.as_ref() {
        const AES_TAG_AND_SALT_OVERHEAD: usize = 32;
        if new_name.len() > 256 + AES_TAG_AND_SALT_OVERHEAD {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    // FIXME: test with has_create_credential = true too
    let has_create_credential = true;

    match frontend
        .storage
        .update_call_link(&room_id.into(), &update.into(), !has_create_credential)
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
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        Err(CallLinkUpdateError::UnexpectedError(err)) => {
            error!("update_call_link: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
