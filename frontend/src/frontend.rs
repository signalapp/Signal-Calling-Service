//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{convert::TryFrom, fmt::Write};

use anyhow::{anyhow, Error, Result};
use calling_common::{random_hex_string, DemuxId, RoomId};
use http::Uri;
use log::*;
use parking_lot::Mutex;
use rand::Rng;
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
    pub approved_users: Option<Vec<UserId>>,
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
    pub client_status: Option<String>,
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

        let result = self
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
                        anyhow::Ok(ClientInfo {
                            opaque_user_id: Some(user_id),
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
            });
        match result {
            Ok(client_response) => Ok(client_response),
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
                    user_id: user_id.to_string(),
                    ice_ufrag: join_request.ice_ufrag,
                    dhe_public_key: Some(join_request.dhe_public_key),
                    hkdf_extra_info: join_request.hkdf_extra_info,
                    region: join_request.region,
                    new_clients_require_approval: join_request.restrictions
                        == CallLinkRestrictions::AdminApproval,
                    is_admin: join_request.is_admin,
                    room_id: call.room_id.clone(),
                    approved_users: join_request.approved_users,
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
            client_status: backend_join_response.client_status,
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
        // Custom format the error using up to the first three errors in the chain. This is
        // enough to get single line description of the error. We do a third error in case
        // a library wraps their errors
        let mut error_string = err.to_string();
        err.chain().skip(1).take(2).for_each(|cause| {
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
