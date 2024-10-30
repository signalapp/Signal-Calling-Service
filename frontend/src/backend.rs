//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use calling_common::{CallType, DemuxId, RoomId};
use log::*;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use tokio::time::{error::Elapsed, Duration};

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::{config, frontend, load_balancer::LoadBalancer};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A wrapper around a SocketAddr used when directly accessing the Calling Server.
#[derive(Debug, PartialEq)]
pub struct Address(SocketAddr);

impl Address {
    pub fn as_socket_addr(self) -> SocketAddr {
        self.0
    }
    pub fn ip(&self) -> IpAddr {
        self.0.ip()
    }
    pub fn port(&self) -> u16 {
        self.0.port()
    }
}

impl TryFrom<&String> for Address {
    type Error = Error;
    fn try_from(ip: &String) -> Result<Self, Error> {
        Self::try_from(ip.as_str())
    }
}

impl TryFrom<&str> for Address {
    type Error = Error;
    fn try_from(ip: &str) -> Result<Self, Error> {
        let ip: IpAddr = ip.parse().map_err(|_| anyhow!("Can't parse backend ip"))?;
        Ok(Self((ip, 8080).into()))
    }
}

#[derive(Deserialize, Debug)]
pub struct InfoResponse {
    #[serde(rename = "directAccessIp")]
    pub backend_direct_ip: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub demux_id: u32,
    pub user_id: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ClientsResponse {
    #[serde(rename = "endpointIds")]
    pub user_ids: Vec<String>,

    // Parallels the user_ids list.
    #[serde(rename = "demuxIds")]
    pub demux_ids: Vec<u32>,

    #[serde(rename = "pendingClients", default)]
    pub pending_clients: Vec<ClientInfo>,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    #[serde(rename = "endpointId")]
    pub user_id: String,
    #[serde(rename = "clientIceUfrag")]
    pub ice_ufrag: String,
    #[serde(rename = "clientDhePublicKey")]
    pub dhe_public_key: Option<String>,
    pub hkdf_extra_info: Option<String>,
    pub region: String,
    pub new_clients_require_approval: bool,
    pub is_admin: bool,
    pub room_id: RoomId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_users: Option<Vec<String>>,
    pub call_type: CallType,
}

#[derive(Deserialize, Debug)]
pub struct JoinResponse {
    #[serde(rename = "serverIps")]
    pub ips: Vec<String>,
    #[serde(rename = "serverPort")]
    pub port: u16,
    #[serde(rename = "serverPortTcp")]
    pub port_tcp: u16,
    #[serde(rename = "serverPortTls", default)]
    pub port_tls: Option<u16>,
    #[serde(rename = "serverHostname", default)]
    pub hostname: Option<String>,
    #[serde(rename = "serverIceUfrag")]
    pub ice_ufrag: String,
    #[serde(rename = "serverIcePwd")]
    pub ice_pwd: String,
    #[serde(rename = "serverDhePublicKey")]
    pub dhe_public_key: String,
    #[serde(rename = "clientStatus")]
    pub client_status: String,
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("No such call exists")]
    CallNotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
    #[error(transparent)]
    Timeout(#[from] Elapsed),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Backend: Sync + Send {
    async fn select_ip(&self) -> Result<String, BackendError>;
    async fn get_info(&self) -> Result<InfoResponse, BackendError>;
    async fn get_clients<'a>(
        &self,
        backend_address: &Address,
        call_id: &str,
        user_id: Option<&'a frontend::UserId>,
    ) -> Result<ClientsResponse, BackendError>;
    async fn join(
        &self,
        backend_address: &Address,
        call_id: &str,
        demux_id: DemuxId,
        join_request: &JoinRequest,
    ) -> Result<JoinResponse, BackendError>;
}

pub struct BackendHttpClient {
    http_client: reqwest::Client,
    /// URL used when invoking the get_info() API so that the request goes through
    /// an external load balancer.
    base_url: Option<String>,
    /// internal load balancing provided from this crate
    load_balancer: Option<LoadBalancer>,
}

impl BackendHttpClient {
    pub async fn from_config(config: &'static config::Config) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .unwrap();
        let base_url = config.calling_server_url.as_ref().cloned();
        let load_balancer = match (
            config.backend_list_instances_url.as_ref(),
            config.oauth2_token_url.as_ref(),
            config.backend_ip.as_ref(),
        ) {
            (None, _, None) => None,
            (Some(url), Some(identity_url), None) => {
                Some(LoadBalancer::new_with_instance_url(url.clone(), identity_url.clone()).await?)
            }
            (Some(_), None, None) => {
                return Err(anyhow!(
                    "must supply oauth2-token-url with backend-list-instances-url"
                ))
            }
            (None, _, Some(ips)) => Some(LoadBalancer::new_with_ips(ips.to_vec()).await?),
            (_, _, _) => {
                return Err(anyhow!(
                "no more than one of backend-ip and backend-list-instances-url may be configured"
            ))
            }
        };

        Ok(Self {
            http_client,
            base_url,
            load_balancer,
        })
    }
}

#[async_trait]
impl Backend for BackendHttpClient {
    async fn select_ip(&self) -> Result<String, BackendError> {
        if let Some(load_balancer) = &self.load_balancer {
            if let Ok(ip) = load_balancer.select_ip().await {
                return Ok(ip);
            }
        }
        let result = self.get_info().await.map(|i| i.backend_direct_ip);
        if self.load_balancer.is_some() && self.base_url.is_some() && result.is_ok() {
            info!("load_balancer failed, base_url fallback successful");
        }

        return result;
    }

    async fn get_info(&self) -> Result<InfoResponse, BackendError> {
        let base_v1_info_uri_string = match &self.base_url {
            None => {
                return Err(BackendError::UnexpectedError(anyhow!(
                    "calling_server_url not set but fallback attempted"
                )))
            }
            Some(url) => format!("{}/v1/info", url),
        };

        let url: Url = base_v1_info_uri_string
            .parse()
            .context("failed to parse info uri for backend")?;

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .context("failed to make backend request `get info`")?;

        match response.status() {
            StatusCode::OK => {
                let info_response = response
                    .json()
                    .await
                    .context("failed to convert body to info response")?;

                Ok(info_response)
            }
            _ => Err(BackendError::UnexpectedError(anyhow!(format!(
                "failed `get info` with unexpected status {}",
                response.status()
            )))),
        }
    }

    async fn get_clients<'a>(
        &self,
        backend_address: &Address,
        call_id: &str,
        user_id: Option<&'a frontend::UserId>,
    ) -> Result<ClientsResponse, BackendError> {
        let uri_string = format!(
            "http://{}:{}/v1/call/{}/clients",
            backend_address.ip(),
            backend_address.port(),
            call_id
        );

        let mut request = self.http_client.get(uri_string);
        if let Some(user_id) = user_id {
            request = request.header("X-User-Id", user_id.as_str());
        }

        let response = request.send().await.with_context(|| {
            format!(
                "failed to make backend request `get clients` to `{}`",
                backend_address.ip()
            )
        })?;

        match response.status() {
            StatusCode::OK => {
                let clients_response = response
                    .json()
                    .await
                    .context("failed to convert body to clients response")?;

                Ok(clients_response)
            }
            StatusCode::NOT_FOUND => Err(BackendError::CallNotFound),
            _ => Err(BackendError::UnexpectedError(anyhow!(format!(
                "failed `get clients` with unexpected status {}",
                response.status()
            )))),
        }
    }

    async fn join(
        &self,
        backend_address: &Address,
        call_id: &str,
        demux_id: DemuxId,
        join_request: &JoinRequest,
    ) -> Result<JoinResponse, BackendError> {
        let uri_string = format!(
            "http://{}:{}/v1/call/{}/client/{}",
            backend_address.ip(),
            backend_address.port(),
            call_id,
            demux_id.as_u32(),
        );

        if let Some(approved_users) = &join_request.approved_users {
            if approved_users.len() > 100 {
                warn!("more than 100 approved users in join");
            }
        }

        let response = self
            .http_client
            .post(uri_string)
            .json(join_request)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to make backend request `post client` to `{}`",
                    backend_address.ip()
                )
            })?;

        match response.status() {
            StatusCode::OK => {
                let join_response = response
                    .json()
                    .await
                    .context("failed to convert body to join response")?;

                Ok(join_response)
            }
            _ => Err(BackendError::UnexpectedError(anyhow!(format!(
                "failed `post client` with unexpected status {}",
                response.status()
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::v2_tests::{
        CLIENT_DHE_PUBLIC_KEY, CLIENT_ICE_UFRAG, GROUP_ID_1, LOCAL_REGION, USER_ID_1,
    };

    #[test]
    fn check_raw_join_request_json() {
        assert_eq!(
            serde_json::json!({
                "endpointId": USER_ID_1,
                "clientIceUfrag": CLIENT_ICE_UFRAG,
                "clientDhePublicKey": CLIENT_DHE_PUBLIC_KEY,
                "hkdfExtraInfo": null,
                "region": LOCAL_REGION,
                "newClientsRequireApproval": false,
                "isAdmin": false,
                "roomId": GROUP_ID_1,
                "approvedUsers": ["A", "B"],
                "callType": "GroupV2",
            }),
            serde_json::to_value(JoinRequest {
                user_id: USER_ID_1.to_string(),
                ice_ufrag: CLIENT_ICE_UFRAG.to_string(),
                dhe_public_key: Some(CLIENT_DHE_PUBLIC_KEY.to_string()),
                hkdf_extra_info: None,
                region: LOCAL_REGION.to_string(),
                new_clients_require_approval: false,
                is_admin: false,
                room_id: RoomId::from(GROUP_ID_1),
                approved_users: Some(vec!["A".to_string(), "B".to_string()]),
                call_type: CallType::GroupV2,
            })
            .unwrap()
        )
    }
}
