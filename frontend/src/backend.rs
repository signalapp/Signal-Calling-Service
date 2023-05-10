//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use http::{header, Method, Request, StatusCode};
use hyper::{
    body::Buf,
    client::HttpConnector,
    {Body, Client as HttpClient},
};
use log::*;
use serde::{Deserialize, Serialize};
use tokio::time::{error::Elapsed, timeout, Duration};

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::{config, frontend::DemuxId, load_balancer::LoadBalancer};

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
pub struct ClientsResponse {
    #[serde(rename = "endpointIds")]
    pub client_ids: Vec<String>, // Aka endpoint_id or active_speaker_id, a concatenation of user_id + '-' + resolution_request_id.
}

#[derive(Serialize, Debug, PartialEq)]
pub struct JoinRequest {
    #[serde(rename = "endpointId")]
    pub client_id: String, // Aka endpoint_id or active_speaker_id, a concatenation of user_id + '-' + resolution_request_id.
    #[serde(rename = "clientIceUfrag")]
    pub ice_ufrag: String,
    #[serde(rename = "clientDhePublicKey")]
    pub dhe_public_key: Option<String>,
    #[serde(rename = "hkdfExtraInfo")]
    pub hkdf_extra_info: Option<String>,
    pub region: String,
}

#[derive(Deserialize, Debug)]
pub struct JoinResponse {
    #[serde(rename = "serverIp")]
    pub ip: String,
    #[serde(rename = "serverIps")]
    pub ips: Option<Vec<String>>,
    #[serde(rename = "serverPort")]
    pub port: u16,
    #[serde(rename = "serverPortTcp", default)]
    pub port_tcp: Option<u16>,
    #[serde(rename = "serverIceUfrag")]
    pub ice_ufrag: String,
    #[serde(rename = "serverIcePwd")]
    pub ice_pwd: String,
    #[serde(rename = "serverDhePublicKey")]
    pub dhe_public_key: Option<String>,
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
    async fn get_clients(
        &self,
        backend_address: &Address,
        call_id: &str,
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
    http_client: HttpClient<HttpConnector>,
    /// URL used when invoking the get_info() API so that the request goes through
    /// an external load balancer.
    base_url: Option<String>,
    /// internal load balancing provided from this crate
    load_balancer: Option<LoadBalancer>,
}

impl BackendHttpClient {
    pub async fn from_config(config: &'static config::Config) -> anyhow::Result<Self> {
        let http_client = HttpClient::builder().build_http();
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

        let uri = base_v1_info_uri_string
            .parse()
            .context("failed to parse info uri for backend")?;

        let response = timeout(DEFAULT_TIMEOUT, self.http_client.get(uri))
            .await?
            .context("failed to make backend request `get info`")?;

        match response.status() {
            StatusCode::OK => {
                let body = hyper::body::aggregate(response)
                    .await
                    .context("failed to aggregate body for info response")?;

                let info_response = serde_json::from_reader(body.reader())
                    .context("failed to convert body to info response")?;

                Ok(info_response)
            }
            _ => Err(BackendError::UnexpectedError(anyhow!(format!(
                "failed `get info` with unexpected status {}",
                response.status()
            )))),
        }
    }

    async fn get_clients(
        &self,
        backend_address: &Address,
        call_id: &str,
    ) -> Result<ClientsResponse, BackendError> {
        let uri_string = format!(
            "http://{}:{}/v1/call/{}/clients",
            backend_address.ip(),
            backend_address.port(),
            call_id
        );

        let uri = uri_string
            .parse()
            .context("failed to parse get clients uri for backend")?;

        let response = timeout(DEFAULT_TIMEOUT, self.http_client.get(uri))
            .await?
            .context(format!(
                "failed to make backend request `get clients` to `{}`",
                backend_address.ip()
            ))?;

        match response.status() {
            StatusCode::OK => {
                let body = hyper::body::aggregate(response)
                    .await
                    .context("failed to aggregate body for clients response")?;

                let clients_response = serde_json::from_reader(body.reader())
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

        let request_body =
            serde_json::to_vec(join_request).context("failed to convert join request to body")?;

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri_string)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(request_body))
            .context("failed to form the join request")?;

        let response = timeout(DEFAULT_TIMEOUT, self.http_client.request(request))
            .await?
            .context(format!(
                "failed to make backend request `post client` to `{}`",
                backend_address.ip()
            ))?;

        match response.status() {
            StatusCode::OK => {
                let body = hyper::body::aggregate(response)
                    .await
                    .context("failed to aggregate body for join response")?;

                let join_response = serde_json::from_reader(body.reader())
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
