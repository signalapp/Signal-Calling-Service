//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    convert::TryFrom,
    fmt::{self, Write as _},
};

use anyhow::{anyhow, Error, Result};
use calling_common::random_hex_string;
use http::Uri;
use log::*;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use urlencoding::encode;

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::{
    api::ApiMetrics,
    authenticator::Authenticator,
    backend::{self, Backend, BackendError},
    config,
    storage::{CallLinkRestrictions, CallRecord, Storage},
};

pub type UserId = String;

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct RoomId(String);

impl From<String> for RoomId {
    fn from(room_id_string: String) -> Self {
        Self(room_id_string)
    }
}

impl From<&str> for RoomId {
    fn from(room_id: &str) -> Self {
        Self(room_id.to_string())
    }
}

impl From<RoomId> for String {
    fn from(room_id: RoomId) -> Self {
        room_id.0
    }
}

impl AsRef<str> for RoomId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// Implement Display for RoomId to redact most of the string.
impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

/// Implement Debug for RoomId to redact most of the string.
impl fmt::Debug for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

/// A wrapper around a u32 with the 4 LSBs set to 0.
/// Uniquely identifies a client within a call (scoped to the call era).
#[derive(Clone, Debug, Eq, PartialEq, Copy, Hash, PartialOrd, Ord)]
pub struct DemuxId(u32);

impl DemuxId {
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for DemuxId {
    type Error = anyhow::Error;
    fn try_from(demux_id: u32) -> Result<Self> {
        if demux_id & 0b1111 == 0 {
            Ok(Self(demux_id))
        } else {
            Err(anyhow!("value provided for demux_id is not valid"))
        }
    }
}

impl From<DemuxId> for u32 {
    fn from(demux_id: DemuxId) -> u32 {
        demux_id.0
    }
}

#[cfg_attr(test, automock)]
pub trait IdGenerator: Sync + Send {
    // The user ID isn't used by the real generator, but it's an extra thing we can check in tests.
    fn get_random_demux_id(&self, user_id: &str) -> DemuxId;
    fn get_random_era_id(&self, n: usize) -> String;
}

pub struct FrontendIdGenerator;

impl IdGenerator for FrontendIdGenerator {
    fn get_random_demux_id(&self, _user_id: &str) -> DemuxId {
        let unmasked_id = rand::thread_rng().gen::<u32>();
        DemuxId::try_from(unmasked_id & !0b1111).expect("valid")
    }

    fn get_random_era_id(&self, n: usize) -> String {
        random_hex_string(n)
    }
}

pub struct JoinRequestWrapper {
    pub ice_ufrag: String,
    pub dhe_public_key: String,
    pub hkdf_extra_info: Option<String>,
    pub region: String,
    pub restrictions: CallLinkRestrictions,
    pub is_admin: bool,
}

pub struct JoinResponseWrapper {
    pub demux_id: u32,
    pub port: u16,
    pub port_tcp: Option<u16>,
    pub ip: String,
    pub ips: Vec<String>,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub dhe_public_key: String,
}

pub struct ClientInfo {
    pub opaque_user_id: Option<UserId>,
    pub demux_id: DemuxId,
}

pub struct ClientsResponseWrapper {
    pub active_clients: Vec<ClientInfo>,
    pub pending_clients: Vec<ClientInfo>,
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum FrontendError {
    #[error("CallNotFound")]
    CallNotFound,
    #[error("NoPermissionToCreateCall")]
    NoPermissionToCreateCall,
    #[error("InternalError")]
    InternalError,
}

/// The Frontend doesn't maintain session state. However, this struct includes objects
/// that need to be passed around for accessing various dependent services.
pub struct Frontend {
    pub config: &'static config::Config,
    pub authenticator: Authenticator,
    pub zkparams: zkgroup::generic_server_params::GenericServerSecretParams,
    pub storage: Box<dyn Storage>,
    pub backend: Box<dyn Backend>,
    pub id_generator: Box<dyn IdGenerator>,
    pub api_metrics: Mutex<ApiMetrics>,
}

impl Frontend {
    /// Return the user_id part of the given endpoint_id.
    ///
    /// The user_id is the string before the hyphen in an endpoint_id and must not be empty.
    /// This function also accepts hyphen-less input, in which case the entire string is treated as
    /// the user_id.
    ///
    /// ```
    /// use calling_frontend::frontend::Frontend;
    /// use std::convert::TryInto;
    ///
    /// assert_eq!(Frontend::get_opaque_user_id_from_endpoint_id("abcdef").unwrap(), "abcdef".to_string());
    /// assert_eq!(Frontend::get_opaque_user_id_from_endpoint_id("abcdef-").unwrap(), "abcdef".to_string());
    /// assert_eq!(Frontend::get_opaque_user_id_from_endpoint_id("abcdef-0").unwrap(), "abcdef".to_string());
    /// assert_eq!(Frontend::get_opaque_user_id_from_endpoint_id("abcdef-12345").unwrap(), "abcdef".to_string());
    /// assert!(Frontend::get_opaque_user_id_from_endpoint_id("").is_err());
    /// assert!(Frontend::get_opaque_user_id_from_endpoint_id("-").is_err());
    /// assert!(Frontend::get_opaque_user_id_from_endpoint_id("-12345").is_err());
    /// ```
    pub fn get_opaque_user_id_from_endpoint_id(endpoint_id: &str) -> Result<String> {
        let user_id = endpoint_id
            .split_once('-')
            .unwrap_or((endpoint_id, ""))
            .0
            .to_string();

        if user_id.is_empty() {
            return Err(anyhow!("invalid user_id from endpoint_id"));
        }

        Ok(user_id)
    }

    /// Get the uri the call should be redirected to or None. If the local region is not
    /// the region where the call is hosted, create the uri necessary to get there.
    pub fn get_redirect_uri(&self, backend_region: &str, original_uri: &Uri) -> Option<String> {
        if backend_region != self.config.region {
            Some(format!(
                "{}{}?region={}",
                self.config
                    .regional_url_template
                    .replace("<region>", backend_region),
                original_uri.path(),
                encode(&self.config.region),
            ))
        } else {
            None
        }
    }

    pub async fn get_call_record(&self, room_id: &RoomId) -> Result<CallRecord, FrontendError> {
        self.storage
            .get_call_record(room_id)
            .await
            .map_err(|err| {
                Frontend::log_error("get_call_record", err.into());
                FrontendError::InternalError
            })?
            .ok_or(FrontendError::CallNotFound)
    }

    pub async fn get_client_ids_in_call(
        &self,
        call: &CallRecord,
        user_id: &UserId,
    ) -> Result<ClientsResponseWrapper, FrontendError> {
        // Get the direct address to the Calling Backend.
        let backend_address = backend::Address::try_from(&call.backend_ip).map_err(|err| {
            warn!(
                "get_client_ids_in_call: failed to parse backend_ip: {}",
                err
            );
            FrontendError::InternalError
        })?;

        match self
            .backend
            .get_clients(&backend_address, &call.era_id, Some(user_id))
            .await
            .and_then(|response| {
                if response.demux_ids.len() != response.user_ids.len() {
                    return Err(BackendError::UnexpectedError(anyhow!(
                        "mismatched lists in ClientResponse"
                    )));
                }
                let active_clients = response
                    .user_ids
                    .into_iter()
                    .zip(response.demux_ids.into_iter())
                    .map(|(user_id, raw_demux_id)| {
                        let opaque_user_id =
                            Frontend::get_opaque_user_id_from_endpoint_id(&user_id)?;
                        anyhow::Ok(ClientInfo {
                            opaque_user_id: Some(opaque_user_id),
                            demux_id: DemuxId::try_from(raw_demux_id)?,
                        })
                    })
                    .collect::<Result<_>>()?;
                let pending_clients = response
                    .pending_clients
                    .into_iter()
                    .map(|client| {
                        anyhow::Ok(ClientInfo {
                            opaque_user_id: client.user_id,
                            demux_id: DemuxId::try_from(client.demux_id)?,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(ClientsResponseWrapper {
                    active_clients,
                    pending_clients,
                })
            }) {
            Ok(result) => Ok(result),
            Err(BackendError::CallNotFound) => {
                if let Err(err) = self
                    .storage
                    .remove_call_record(&call.room_id, &call.era_id)
                    .await
                {
                    // Warn about the error, but keep going.
                    Frontend::log_warning(
                        "get_client_ids_in_call: failed to remove call record not found on backend",
                        err.into(),
                    );
                }
                Err(FrontendError::CallNotFound)
            }
            Err(BackendError::UnexpectedError(err)) => {
                Frontend::log_error("get_client_ids_in_call", err);
                Err(FrontendError::InternalError)
            }
            Err(BackendError::Timeout(err)) => {
                Frontend::log_error("get_client_ids_in_call", Error::new(err));
                Err(FrontendError::InternalError)
            }
        }
    }

    pub async fn get_or_create_call_record(
        &self,
        room_id: &RoomId,
        can_create: bool,
        user_id: &UserId,
    ) -> Result<CallRecord, FrontendError> {
        if !can_create {
            // Either a call already exists or it doesn't.
            return self
                .storage
                .get_call_record(room_id)
                .await
                .map_err(|err| {
                    Frontend::log_error("get_or_create_call_record", err.into());
                    FrontendError::InternalError
                })
                .transpose()
                .unwrap_or(Err(FrontendError::NoPermissionToCreateCall));
        }

        // Create a call if we need to. First, access a backend server through load balancing and
        // get its IP address.
        let backend_ip = self.backend.select_ip().await.map_err(|err| {
            Frontend::log_error("get_or_create_call_record", err.into());
            FrontendError::InternalError
        })?;

        let call_record = CallRecord {
            room_id: room_id.clone(),
            era_id: self.id_generator.get_random_era_id(16),
            backend_ip,
            backend_region: self.config.region.to_string(),
            creator: user_id.to_string(),
        };

        self.storage
            .get_or_add_call_record(call_record.clone())
            .await
            .map_err(|err| {
                Frontend::log_error("get_or_create_call_record", err.into());
                FrontendError::InternalError
            })
    }

    pub async fn join_client_to_call(
        &self,
        user_id: &str,
        call: &CallRecord,
        join_request: JoinRequestWrapper,
    ) -> Result<JoinResponseWrapper, FrontendError> {
        let demux_id = self.id_generator.get_random_demux_id(user_id);

        // Get the direct address to the Calling Backend.
        let backend_address = backend::Address::try_from(&call.backend_ip).map_err(|err| {
            error!("join_client_to_call: failed to parse backend_ip: {}", err);
            FrontendError::InternalError
        })?;

        let backend_join_response = self
            .backend
            .join(
                &backend_address,
                &call.era_id,
                demux_id,
                &backend::JoinRequest {
                    user_ids: user_id.to_string(),
                    ice_ufrag: join_request.ice_ufrag,
                    dhe_public_key: Some(join_request.dhe_public_key),
                    hkdf_extra_info: join_request.hkdf_extra_info,
                    region: join_request.region,
                    new_clients_require_approval: join_request.restrictions
                        == CallLinkRestrictions::AdminApproval,
                    is_admin: join_request.is_admin,
                },
            )
            .await
            .map_err(|err| {
                Frontend::log_error("join_client_to_call", err.into());
                FrontendError::InternalError
            })?;

        let backend_dhe_public_key = backend_join_response.dhe_public_key.ok_or_else(|| {
            error!("join_client_to_call: failed to receive dhe_public_key from the backend");
            FrontendError::InternalError
        })?;

        let ips = match backend_join_response.ips {
            Some(ips) => ips,
            None => vec![backend_join_response.ip.clone()],
        };

        Ok(JoinResponseWrapper {
            demux_id: demux_id.as_u32(),
            port: backend_join_response.port,
            port_tcp: backend_join_response.port_tcp,
            ip: backend_join_response.ip,
            ips,
            ice_ufrag: backend_join_response.ice_ufrag,
            ice_pwd: backend_join_response.ice_pwd,
            dhe_public_key: backend_dhe_public_key,
        })
    }

    pub async fn remove_call_record(
        &self,
        room_id: &RoomId,
        era_id: &str,
    ) -> Result<(), FrontendError> {
        self.storage
            .remove_call_record(room_id, era_id)
            .await
            .map_err(|err| {
                Frontend::log_error("remove_call_record", err.into());
                FrontendError::InternalError
            })
    }

    #[track_caller]
    fn log_error(context: &str, err: Error) {
        // Custom format the error using up to the first two errors in the chain. This is
        // enough to get single line description of the error.
        let mut error_string = err.to_string();
        err.chain().skip(1).take(1).for_each(|cause| {
            let _ = write!(error_string, ": {}", cause);
        });
        let location = std::panic::Location::caller();
        log::logger().log(
            &Record::builder()
                .level(log::Level::Error)
                .target(module_path!())
                .file(Some(location.file()))
                .line(Some(location.line()))
                .args(format_args!("{context}: {error_string}"))
                .build(),
        );
    }

    #[track_caller]
    fn log_warning(context: &str, err: Error) {
        let location = std::panic::Location::caller();
        log::logger().log(
            &Record::builder()
                .level(log::Level::Warn)
                .target(module_path!())
                .file(Some(location.file()))
                .line(Some(location.line()))
                .args(format_args!("{}: {}", context, err.root_cause()))
                .build(),
        );
    }
}
