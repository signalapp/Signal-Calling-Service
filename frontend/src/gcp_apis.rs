//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{anyhow, Context, Result};
use log::*;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};
use tokio::{
    sync::oneshot,
    time::{self, Duration, Instant},
};

use crate::load_balancer::{LoadBalancer, LoadBalancerSender};

const INSTANCE_LIST_INTERVAL: Duration = Duration::from_secs(30);

struct GoogleToken {
    url: Url,
    adjusted_expiration: Duration,
    backoff: Duration,
    fetch_start: Instant,
    fetch_attempt: Instant,
    token: Option<String>,
}

const GCP_TIMEOUT: Duration = Duration::from_secs(5);

/// from https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#applications
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    /// in seconds
    expires_in: u64,
}

impl GoogleToken {
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(300);

    fn new(url: String) -> Result<Self> {
        let now = Instant::now();
        Ok(Self {
            url: url.parse()?,
            fetch_start: now,
            fetch_attempt: now,
            adjusted_expiration: Duration::ZERO,
            backoff: Self::INITIAL_BACKOFF,
            token: None,
        })
    }

    async fn refresh(&mut self, client: reqwest::Client) -> Result<&str> {
        let now = Instant::now();
        if self.token.is_none()
            || (now.duration_since(self.fetch_start) > self.adjusted_expiration
                && now.duration_since(self.fetch_attempt) > self.backoff)
        {
            self.fetch_attempt = now;
            match self.fetch(client).await {
                Ok(()) => {
                    self.fetch_start = now;
                    self.backoff = Self::INITIAL_BACKOFF;
                    Ok(self.token.as_ref().unwrap())
                }
                Err(err) if self.token.is_some() => {
                    warn!("failed to refresh Google token: {}", err);
                    self.double_backoff();
                    Ok(self.token.as_ref().unwrap())
                }
                Err(err) => Err(err),
            }
        } else {
            Ok(self.token.as_ref().unwrap())
        }
    }

    async fn fetch(&mut self, client: reqwest::Client) -> Result<()> {
        let response = client
            .get(self.url.clone())
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let token: TokenResponse = response
                    .json()
                    .await
                    .context("failed to convert body to token response")?;
                self.token = Some(token.access_token);
                self.adjusted_expiration =
                    Duration::from_secs(token.expires_in).saturating_sub(Self::MAX_BACKOFF);
                Ok(())
            }
            s => Err(anyhow!("failed Google Token with unexpected status {}", s)),
        }
    }
    fn double_backoff(&mut self) {
        self.backoff += self.backoff;
        if self.backoff > Self::MAX_BACKOFF {
            self.backoff = Self::MAX_BACKOFF;
        }
    }
}

/// from https://cloud.google.com/compute/docs/reference/rest/v1/regionInstanceGroups/listInstances
#[derive(Deserialize)]
struct GroupList {
    kind: String,
    items: Option<Vec<GroupInstance>>,
}

#[derive(Deserialize)]
struct GroupInstance {
    #[serde(rename = "instance")]
    instance_url: String,
    status: String,
}

/// from https://cloud.google.com/compute/docs/reference/rest/v1/instances/get
#[derive(Deserialize)]
struct Instance {
    #[serde(rename = "networkInterfaces")]
    network_interfaces: Vec<NetworkInterface>,
}

#[derive(Deserialize)]
struct NetworkInterface {
    #[serde(rename = "networkIP")]
    network_ip: String,
}

pub struct InstanceLister {
    instance_group_url: Url,
    token: GoogleToken,
    client: reqwest::Client,
}

impl InstanceLister {
    pub async fn start(
        instance_group_url: String,
        identity_token_url: String,
        load_balancer_sender: LoadBalancerSender,
    ) -> Result<oneshot::Sender<()>> {
        let client = reqwest::Client::builder()
            .timeout(GCP_TIMEOUT)
            .build()
            .unwrap();

        let mut lister = Self {
            instance_group_url: instance_group_url.parse()?,
            token: GoogleToken::new(identity_token_url)?,
            client,
        };

        let (canceller_tx, mut canceller_rx) = oneshot::channel();
        let instance_group = lister.get_list().await?;
        let (mut map, _changed) = lister
            .get_instances(instance_group, &HashMap::new())
            .await?;
        LoadBalancer::set_host_list_impl(
            load_balancer_sender.clone(),
            map.values().cloned().collect(),
        )
        .await?;

        tokio::spawn(async move {
            let mut succeeded = false;
            loop {
                let timeout = time::sleep(INSTANCE_LIST_INTERVAL);
                let request = lister.get_list();
                tokio::pin!(timeout);

                tokio::select!(
                    _ = &mut timeout => (),
                    _ = &mut canceller_rx => {
                        info!("instance lister shutdown");
                        break;
                    },
                    instance_group = request => {
                        match instance_group {
                            Ok(g) => match lister.get_instances(g, &map).await {
                                Ok((new_map, true)) => {
                                    if !succeeded {
                                        succeeded = true;
                                        info!("instance group fetched successfully");
                                    }
                                    map = new_map;
                                    let _ = LoadBalancer::set_host_list_impl(
                                        load_balancer_sender.clone(),
                                        map.values().cloned().collect(),
                                    )
                                    .await;
                                }
                                Ok((_, false)) => {
                                    if !succeeded {
                                        succeeded = true;
                                        info!("instance group fetched successfully");
                                    }
                                }
                                Err(err) => {
                                    succeeded = false;
                                    warn!("Error fetching instances {}, will retry", err);
                                }
                            },
                            Err(err) => {
                                succeeded = false;
                                warn!("Error fetching instance group {}, will retry", err)
                            }
                        };
                        timeout.await;
                    }
                );
            }
        });
        Ok(canceller_tx)
    }

    async fn get_list(&mut self) -> Result<Vec<String>> {
        let token = self.token.refresh(self.client.clone()).await?;
        let response = self
            .client
            .post(self.instance_group_url.clone())
            .json("{}")
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let list_response: GroupList = response
                    .json()
                    .await
                    .context("failed to convert body to list response")?;

                if list_response.kind != "compute#regionInstanceGroupsListInstances" {
                    return Err(anyhow!("list response invalid kind {}", list_response.kind));
                }

                if let Some(items) = list_response.items {
                    let mut ret = Vec::with_capacity(items.len());
                    for item in items {
                        if item.status == "RUNNING" {
                            ret.push(item.instance_url);
                        }
                    }
                    Ok(ret)
                } else {
                    Ok(Vec::new())
                }
            }
            s => Err(anyhow!(
                "failed instance group list with unexpected status {}",
                s
            )),
        }
    }

    async fn get_instance_ip(&mut self, instance_url: String) -> Result<Ipv4Addr> {
        let token = self.token.refresh(self.client.clone()).await?;
        let url: Url = format!("{}?fields=networkInterfaces.networkIP", instance_url).parse()?;
        let response = self
            .client
            .get(url)
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let instance_response: Instance = response
                    .json()
                    .await
                    .context("failed to convert body to instance response")?;
                if let Some(interface) = instance_response.network_interfaces.first() {
                    Ok(Ipv4Addr::from_str(&interface.network_ip)?)
                } else {
                    Err(anyhow!("instance {} has no interfaces", instance_url))
                }
            }
            s => Err(anyhow!(
                "failed instance group list with unexpected status {}",
                s
            )),
        }
    }

    async fn get_instances(
        &mut self,
        instance_group: Vec<String>,
        map: &HashMap<String, Ipv4Addr>,
    ) -> Result<(HashMap<String, Ipv4Addr>, bool)> {
        let mut new_map = HashMap::with_capacity(instance_group.len());
        let mut changed = false;
        let instance_group_empty = instance_group.is_empty();
        for instance in instance_group {
            if let Some(ip) = map.get(&instance) {
                new_map.insert(instance, *ip);
            } else {
                match self.get_instance_ip(instance.clone()).await {
                    Ok(ip) => {
                        changed = true;
                        new_map.insert(instance, ip);
                    }
                    Err(e) => {
                        error!("error fetching instance {}: {}", instance, e);
                    }
                }
            }
        }
        if map.len() != new_map.len() {
            changed = true;
        }
        match (new_map.is_empty(), map.is_empty(), instance_group_empty) {
            (true, true, false) => Err(anyhow!("unable to fetch instances")),
            (true, _, true) => Ok((new_map, changed)),
            (true, false, false) => {
                error!("could not fetch instances, using old map");
                Ok((map.clone(), false))
            }
            (false, _, _) => Ok((new_map, changed)),
        }
    }
}
