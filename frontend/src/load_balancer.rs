//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{anyhow, Result};
use log::*;
use rand::{thread_rng, Rng};
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::{
    sync::{mpsc, oneshot},
    time::{self, Duration},
};

use crate::gcp_apis::InstanceLister;

const BACKEND_PORT: u16 = 8080;
const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(1); // Note: also the healthcheck timeout
const MAX_HOSTS: usize = 256; // somewhat arbitrary

pub type LoadBalancerSender = mpsc::Sender<LoadBalancerMessage>;
type LoadBalancerReceiver = mpsc::Receiver<LoadBalancerMessage>;
type HostListReplySender = oneshot::Sender<Result<()>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub cpu_idle_pct: u8,
}

#[derive(Debug)]
pub enum LoadBalancerMessage {
    Choose(oneshot::Sender<Result<Ipv4Addr>>),
    HostList(HostListReplySender, LoadBalancerSender, Vec<Ipv4Addr>),
    HostWeight(Ipv4Addr, u8),
}

struct ServerHealth {
    /// actual weight, None before first healthcheck
    weight: Option<u8>,
    /// how much weight in the current load balancing period
    weight_left: u8,
    /// last logged weight
    reported_weight: u8,
    _checker: oneshot::Sender<()>, // keep this, but don't use it. When it's dropped, the healthchecker task will end
}

type StartHealthcheck = fn(Ipv4Addr, oneshot::Receiver<()>, LoadBalancerSender);

struct LoadBalancerTask {
    map: HashMap<Ipv4Addr, ServerHealth>,
    total_weight: u16,
    total_weight_left: u16,
    start_healthcheck: StartHealthcheck,
    unchecked_servers: u16,
    host_list_reply: Option<HostListReplySender>,
}

impl LoadBalancerTask {
    fn default() -> Self {
        LoadBalancerTask {
            map: HashMap::default(),
            total_weight: 0,
            total_weight_left: 0,
            start_healthcheck: LoadBalancerTask::start_healthcheck,
            unchecked_servers: 0,
            host_list_reply: None,
        }
    }

    async fn start(rx: LoadBalancerReceiver) {
        let mut h = LoadBalancerTask::default();
        h.recv(rx).await
    }

    #[cfg(test)]
    async fn start_with_healthcheck(rx: LoadBalancerReceiver, start_healthcheck: StartHealthcheck) {
        let mut h = LoadBalancerTask::default();
        h.start_healthcheck = start_healthcheck;
        h.recv(rx).await
    }

    async fn recv(&mut self, mut rx: LoadBalancerReceiver) {
        while let Some(m) = rx.recv().await {
            match m {
                LoadBalancerMessage::Choose(sender) => {
                    let _ = sender.send(self.choose());
                }
                LoadBalancerMessage::HostList(reply_sender, health_sender, ips) => {
                    if let Some(s) = self.host_list_reply.take() {
                        let _ = s.send(Err(anyhow!("concurrent updates")));
                    }
                    self.host_list_reply = Some(reply_sender);
                    self.replace_map(health_sender, ips)
                }
                LoadBalancerMessage::HostWeight(ip, w) => self.update_weight(ip, w),
            }
        }
        info!("load_balancer shutdown");
    }

    fn maybe_send_host_list_reply(&mut self) {
        if self.unchecked_servers == 0 {
            if let Some(s) = self.host_list_reply.take() {
                let _ = s.send(Ok(()));
            }
        }
    }

    fn update_weight(&mut self, ip: Ipv4Addr, weight: u8) {
        if let Some(server_health) = self.map.get_mut(&ip) {
            if weight > 0 && self.total_weight == 0 {
                info!(
                    "{} weight {:?} -> {}, first healthy host",
                    ip, server_health.weight, weight
                );
                server_health.reported_weight = weight;
            } else if weight == 0 && self.total_weight == server_health.weight.unwrap_or(0) as u16 {
                warn!(
                    "{} weight {:?} -> {}, all hosts unhealthy",
                    ip, server_health.weight, weight
                );
                server_health.reported_weight = weight;
            } else if server_health.reported_weight == 0 || weight == 0 {
                info!("{} weight {:?} -> {}", ip, server_health.weight, weight);
                server_health.reported_weight = weight;
            }

            if weight == 0 {
                // just remove our remaining weight
                self.total_weight_left = self
                    .total_weight_left
                    .saturating_sub(server_health.weight_left as u16);
            } else {
                // restart selection with our new weight
                self.total_weight_left = 0;
            }
            server_health.weight_left = weight;

            if let Some(old_weight) = server_health.weight.replace(weight) {
                self.total_weight = self.total_weight.saturating_sub(old_weight as u16);
            } else {
                self.unchecked_servers -= 1;
                self.maybe_send_host_list_reply();
            }
            self.total_weight += weight as u16;
        }
    }

    fn replace_map(&mut self, sender: LoadBalancerSender, host_list: Vec<Ipv4Addr>) {
        let mut new_map = HashMap::with_capacity(host_list.len());
        for host_ip in host_list {
            if let Some(old_server_health) = self.map.remove(&host_ip) {
                new_map.insert(host_ip, old_server_health);
            } else {
                let (tx, rx) = oneshot::channel();
                (self.start_healthcheck)(host_ip, rx, sender.clone());
                let sh = ServerHealth {
                    weight: None,
                    weight_left: 0,
                    reported_weight: 0,
                    _checker: tx,
                };
                new_map.insert(host_ip, sh);
                self.unchecked_servers += 1;
            }
        }
        let was_healthy = self.total_weight != 0;
        // remove weight of remaining hosts
        for server_health in self.map.values() {
            if let Some(weight) = server_health.weight {
                self.total_weight -= weight as u16;
                self.total_weight_left -= server_health.weight_left as u16;
            } else {
                self.unchecked_servers -= 1;
            }
        }

        self.maybe_send_host_list_reply();
        if self.total_weight == 0 && was_healthy {
            warn!("{} hosts removed, no more healthy hosts", self.map.len());
        } else if !self.map.is_empty() {
            info!("{} hosts removed", self.map.len());
        }
        self.map = new_map;
    }

    fn start_healthcheck(ip: Ipv4Addr, mut rx: oneshot::Receiver<()>, tx: LoadBalancerSender) {
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(HEALTHCHECK_INTERVAL)
                .build()
                .unwrap();
            let mut last_weight = None;
            let uri = format!("http://{}:{}/health", ip, BACKEND_PORT);

            loop {
                let request = client.get(uri.clone()).send();
                let timeout = time::sleep(HEALTHCHECK_INTERVAL);
                tokio::pin!(timeout);

                let weight = tokio::select!(
                    _ = &mut rx => {
                        info!("healthchecker shutdown {}", ip);
                        break;
                    },
                    response = request => match response {
                        Ok(r) if r.status() == StatusCode::OK => {
                            // if status is OK, return at least 1
                            if let Ok(h) = r.json::<HealthResponse>().await {
                                1 + h.cpu_idle_pct
                            } else {
                                1
                            }
                        },
                        _ => 0
                    }
                );

                if last_weight != Some(weight) {
                    last_weight = Some(weight);
                    if tx
                        .send(LoadBalancerMessage::HostWeight(ip, weight))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                timeout.await;
            }
        });
    }

    fn choose(&mut self) -> Result<Ipv4Addr> {
        if self.map.is_empty() {
            return Err(anyhow!("no hosts in load balancer"));
        }
        if self.total_weight > 0 {
            // distribution is an urn problem
            // total_weight_left is the total balls left, and h.weight_left counts how many balls for each server
            // when the urn is empty, refill the urn
            if self.total_weight_left == 0 {
                self.total_weight_left = self.total_weight;
                for h in self.map.values_mut() {
                    h.weight_left = h.weight.unwrap_or(0);
                }
            }
            let mut rng = thread_rng();
            let mut n = rng.gen_range(0..self.total_weight_left);
            for (ipv4, h) in self.map.iter_mut() {
                if n < h.weight_left.into() {
                    h.weight_left -= 1;
                    self.total_weight_left -= 1;
                    return Ok(*ipv4);
                } else {
                    n -= h.weight_left as u16;
                }
            }
        }
        warn!("no healthy hosts");
        Err(anyhow!("no healthy hosts"))
    }
}

pub struct LoadBalancer {
    tx: LoadBalancerSender,
    _instance_lister: Option<oneshot::Sender<()>>, // keep this, but don't use it. When it's dropped, the instance lister task will end
}

impl LoadBalancer {
    pub async fn new_with_instance_url(
        instance_group_url: String,
        identity_token_url: String,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(128); // TODO good bound?
        tokio::spawn(LoadBalancerTask::start(rx));

        let lister =
            InstanceLister::start(instance_group_url, identity_token_url, tx.clone()).await?;
        Ok(Self {
            tx,
            _instance_lister: Some(lister),
        })
    }

    pub async fn new_with_ips(instance_ips: Vec<Ipv4Addr>) -> Result<Self> {
        if instance_ips.len() > MAX_HOSTS {
            return Err(anyhow!(
                "Too many hosts: {} > MAX_HOSTS ({})",
                instance_ips.len(),
                MAX_HOSTS
            ));
        }
        let (tx, rx) = mpsc::channel(128); // TODO good bound?
        tokio::spawn(LoadBalancerTask::start(rx));
        let ret = Self {
            tx,
            _instance_lister: None,
        };
        ret.set_host_list(instance_ips).await?;
        Ok(ret)
    }

    #[cfg(test)]
    async fn new_with_ips_and_healthcheck(
        instance_ips: Vec<Ipv4Addr>,
        healthcheck: StartHealthcheck,
    ) -> Result<Self> {
        if instance_ips.len() > MAX_HOSTS {
            return Err(anyhow!(
                "Too many hosts: {} > MAX_HOSTS ({})",
                instance_ips.len(),
                MAX_HOSTS
            ));
        }
        let (tx, rx) = mpsc::channel(MAX_HOSTS + 1);
        tokio::spawn(LoadBalancerTask::start_with_healthcheck(rx, healthcheck));
        let ret = Self {
            tx,
            _instance_lister: None,
        };
        ret.set_host_list(instance_ips).await?;
        Ok(ret)
    }

    #[cfg(test)]
    async fn update_weight(&self, ip: Ipv4Addr, weight: u8) -> Result<()> {
        self.tx
            .send(LoadBalancerMessage::HostWeight(ip, weight))
            .await?;
        Ok(())
    }

    pub async fn select_ip(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .clone()
            .send(LoadBalancerMessage::Choose(tx))
            .await?;
        let ipv4 = rx.await??;
        Ok(ipv4.to_string())
    }

    pub async fn set_host_list(&self, ips: Vec<Ipv4Addr>) -> Result<()> {
        LoadBalancer::set_host_list_impl(self.tx.clone(), ips).await
    }

    // Separate function for drop handler and instance listeer
    pub async fn set_host_list_impl(sender: LoadBalancerSender, ips: Vec<Ipv4Addr>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        sender
            .send(LoadBalancerMessage::HostList(tx, sender.clone(), ips))
            .await?;
        rx.await?
    }
}

impl Drop for LoadBalancer {
    fn drop(&mut self) {
        // clear the host list to allow the channel to shutdown

        let tx_clone = self.tx.clone();
        tokio::spawn(async move {
            let _ = LoadBalancer::set_host_list_impl(tx_clone, vec![]).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn zero_up() -> Result<()> {
        n_up(0).await
    }

    #[tokio::test]
    async fn one_up() -> Result<()> {
        n_up(1).await
    }

    #[tokio::test]
    async fn two_up() -> Result<()> {
        n_up(2).await
    }

    #[tokio::test]
    async fn three_up() -> Result<()> {
        n_up(3).await
    }

    #[tokio::test]
    async fn max_up() -> Result<()> {
        n_up(MAX_HOSTS).await
    }

    #[tokio::test]
    async fn zero_down() -> Result<()> {
        n_down(0).await
    }

    #[tokio::test]
    async fn one_down() -> Result<()> {
        n_down(1).await
    }

    #[tokio::test]
    async fn two_down() -> Result<()> {
        n_down(2).await
    }

    #[tokio::test]
    async fn three_down() -> Result<()> {
        n_down(3).await
    }

    #[tokio::test]
    async fn max_down() -> Result<()> {
        n_down(MAX_HOSTS).await
    }

    #[tokio::test]
    async fn zero_odd() -> Result<()> {
        n_odd(0).await
    }

    #[tokio::test]
    async fn one_odd() -> Result<()> {
        n_odd(1).await
    }

    #[tokio::test]
    async fn two_odd() -> Result<()> {
        n_odd(2).await
    }

    #[tokio::test]
    async fn three_odd() -> Result<()> {
        n_odd(3).await
    }

    #[tokio::test]
    async fn max_odd() -> Result<()> {
        n_odd(MAX_HOSTS).await
    }

    #[tokio::test]
    async fn one_weighted() -> Result<()> {
        n_weighted(1).await
    }

    #[tokio::test]
    async fn two_weighted() -> Result<()> {
        n_weighted(2).await
    }

    #[tokio::test]
    async fn three_weighted() -> Result<()> {
        n_weighted(3).await
    }

    #[tokio::test]
    async fn max_weighted() -> Result<()> {
        n_weighted(MAX_HOSTS).await
    }

    #[tokio::test]
    async fn two_hosts_up_then_even_fail_then_recover() -> Result<()> {
        n_hosts_up_then_even_fail_then_recover(2).await
    }

    #[tokio::test]
    async fn three_hosts_up_then_even_fail_then_recover() -> Result<()> {
        n_hosts_up_then_even_fail_then_recover(3).await
    }
    #[tokio::test]
    async fn four_hosts_up_then_even_fail_then_recover() -> Result<()> {
        n_hosts_up_then_even_fail_then_recover(4).await
    }

    #[tokio::test]
    async fn max_hosts_up_then_even_fail_then_recover() -> Result<()> {
        n_hosts_up_then_even_fail_then_recover(MAX_HOSTS).await
    }

    #[tokio::test]
    async fn too_many_hosts() -> Result<()> {
        let (ips, _) = tests::gen_ips(MAX_HOSTS + 1, always_up)?;
        let lb = LoadBalancer::new_with_ips(ips).await;
        assert!(lb.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn all_up_max_hosts_add_from_zero_hosts() -> Result<()> {
        let lb = LoadBalancer::new_with_ips_and_healthcheck(vec![], all_up).await?;
        for n in 0..=MAX_HOSTS {
            let _ = lb.select_ip().await; // fetch one result to test that selection restarts with new weights
            let (ips, expected) = tests::gen_ips(n, always_up)?;
            lb.set_host_list(ips).await?;
            check_expected(expected, &lb).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn weighted_16_hosts_add_from_zero_hosts() -> Result<()> {
        let lb = LoadBalancer::new_with_ips_and_healthcheck(vec![], weighted).await?;
        for n in 0..=16 {
            let _ = lb.select_ip().await; // fetch one result to test that selection restarts with new weights
            let (ips, expected) = tests::gen_ips(n, weight_by_ip)?;
            lb.set_host_list(ips).await?;
            check_expected(expected, &lb).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn weighted_16_hosts_drop_to_zero_hosts() -> Result<()> {
        let lb = LoadBalancer::new_with_ips_and_healthcheck(vec![], weighted).await?;
        for n in (0..=16).rev() {
            let (ips, expected) = tests::gen_ips(n, weight_by_ip)?;
            lb.set_host_list(ips).await?;
            check_expected(expected, &lb).await?;
        }
        Ok(())
    }

    async fn n_hosts_up_then_even_fail_then_recover(n: usize) -> Result<()> {
        let (ips, expected) = tests::gen_ips(n, always_up)?;
        let lb = LoadBalancer::new_with_ips_and_healthcheck(ips, all_up).await?;
        check_expected(expected, &lb).await?;
        let (ips, expected) = tests::gen_ips(n, odd_ip)?;
        for ip in ips {
            if odd_ip(ip) == 0 {
                // is even
                lb.update_weight(ip, 0).await?;
            }
        }
        check_expected(expected, &lb).await?;
        let (ips, expected) = tests::gen_ips(n, always_up)?;
        for ip in ips {
            if odd_ip(ip) == 0 {
                let _ = lb.select_ip().await; // fetch one result to test that selection restarts with new weights
                lb.update_weight(ip, 1).await?;
            }
        }
        check_expected(expected, &lb).await
    }

    async fn n_up(n: usize) -> Result<()> {
        let (ips, expected) = tests::gen_ips(n, always_up)?;
        let lb = LoadBalancer::new_with_ips_and_healthcheck(ips, all_up).await?;
        check_expected(expected, &lb).await
    }

    async fn n_down(n: usize) -> Result<()> {
        let (ips, expected) = tests::gen_ips(n, always_down)?;
        let lb = LoadBalancer::new_with_ips_and_healthcheck(ips, all_down).await?;
        check_expected(expected, &lb).await
    }

    async fn n_odd(n: usize) -> Result<()> {
        let (ips, expected) = tests::gen_ips(n, odd_ip)?;
        let lb = LoadBalancer::new_with_ips_and_healthcheck(ips, odd_up).await?;
        check_expected(expected, &lb).await
    }

    async fn n_weighted(n: usize) -> Result<()> {
        let (ips, expected) = tests::gen_ips(n, weight_by_ip)?;
        let lb = LoadBalancer::new_with_ips_and_healthcheck(ips, weighted).await?;
        check_expected(expected, &lb).await
    }

    // RFC 5737: The blocks 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24
    // (TEST-NET-2), and 203.0.113.0/24 (TEST-NET-3) are provided for use in
    // documentation.

    fn gen_ips(
        n: usize,
        weight: fn(Ipv4Addr) -> u8,
    ) -> Result<(Vec<Ipv4Addr>, HashMap<Ipv4Addr, u8>)> {
        let mut ips = Vec::with_capacity(n);
        let mut map = HashMap::with_capacity(n);
        for i in 0..n {
            let ip = if i < 256 {
                Ipv4Addr::new(192, 0, 2, i.try_into()?)
            } else if i < 512 {
                Ipv4Addr::new(198, 51, 100, (i - 256).try_into()?)
            } else {
                Ipv4Addr::new(203, 0, 113, (i - 512).try_into()?)
            };
            ips.push(ip);
            map.insert(ip, weight(ip));
        }
        Ok((ips, map))
    }

    async fn check_expected(ips: HashMap<Ipv4Addr, u8>, lb: &LoadBalancer) -> Result<()> {
        let mut seen: HashMap<String, usize> = HashMap::new();

        let mut total: usize = 0;
        let mut num_weight_zero: usize = 0;
        for weight in ips.values() {
            total += *weight as usize;
            if *weight == 0 {
                num_weight_zero += 1;
            }
        }

        if total == 0 {
            lb.select_ip().await.unwrap_err();
            return Ok(());
        }

        const FULL_ITERATIONS: usize = 3;
        let rounds = total * FULL_ITERATIONS;
        info!("rounds {}", rounds);

        for _ in 0..rounds {
            let ip = lb.select_ip().await?;
            *seen.entry(ip).or_default() += 1;
        }

        // we saw the right number of unique responses
        assert_eq!(seen.len(), ips.len() - num_weight_zero);

        for (ip, weight) in ips {
            let count = if weight > 0 {
                *seen.get(&ip.to_string()).unwrap()
            } else {
                seen.get(&ip.to_string()).ok_or("not found").unwrap_err();
                0
            };
            assert_eq!(count, weight as usize * FULL_ITERATIONS);
        }

        Ok(())
    }

    fn always_up(_ip: Ipv4Addr) -> u8 {
        1
    }
    fn all_up(ip: Ipv4Addr, mut _rx: oneshot::Receiver<()>, tx: LoadBalancerSender) {
        assert!(tx.try_send(LoadBalancerMessage::HostWeight(ip, 1)).is_ok());
    }

    /// return weight 1 if last octet is odd, 0 otherwise
    fn odd_ip(ip: Ipv4Addr) -> u8 {
        ip.octets()[3] % 2
    }
    fn odd_up(ip: Ipv4Addr, mut _rx: oneshot::Receiver<()>, tx: LoadBalancerSender) {
        assert!(tx
            .try_send(LoadBalancerMessage::HostWeight(ip, odd_ip(ip)))
            .is_ok());
    }

    fn always_down(_ip: Ipv4Addr) -> u8 {
        0
    }
    fn all_down(ip: Ipv4Addr, mut _rx: oneshot::Receiver<()>, tx: LoadBalancerSender) {
        assert!(tx.try_send(LoadBalancerMessage::HostWeight(ip, 0)).is_ok());
    }
    fn weight_by_ip(ip: Ipv4Addr) -> u8 {
        (ip.octets()[3] % 128) + 1
    }
    fn weighted(ip: Ipv4Addr, mut _rx: oneshot::Receiver<()>, tx: LoadBalancerSender) {
        assert!(tx
            .try_send(LoadBalancerMessage::HostWeight(ip, weight_by_ip(ip)))
            .is_ok());
    }
}
