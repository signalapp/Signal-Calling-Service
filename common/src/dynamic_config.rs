//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    fmt::{Debug, Formatter},
    ops::Deref,
    sync::{Arc, LazyLock},
};

use log::{error, info};
#[cfg(test)]
use mockall::automock;
use object_store::{self, gcp, GetOptions, ObjectStore};
use serde::Deserialize;
use thiserror::Error;
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
};

use crate::{Duration, Instant};

#[derive(Debug, Error)]
pub enum DynamicConfigError {
    #[error("Config not found in path: {path:?}")]
    ConfigNotFound { path: String },
    #[error("Error when parsing config. Error {error:?}\n. Raw config: {raw_config:?}")]
    ConfigParseError {
        raw_config: String,
        error: anyhow::Error,
    },
    #[error("Config fetcher state led to bad refresh")]
    BadConfigFetcherState,
    #[error("{0:?}")]
    UnknownConfigRefreshError(#[from] anyhow::Error),
}

// cannot use EnumIter to generate tag sets because of inner Errors, manually create them here
static NOT_FOUND: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec!["error-type:not-found"]);
static PARSE_ERROR: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec!["error-type:parse-error"]);
static BAD_STATE: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec!["error-type:bad-state"]);
static UNKNOWN: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec!["error-type:unknown"]);

impl DynamicConfigError {
    pub fn as_tag(&self) -> &'static str {
        match self {
            DynamicConfigError::ConfigNotFound { .. } => "error-type:not-found",
            DynamicConfigError::ConfigParseError { .. } => "error-type:parse-error",
            DynamicConfigError::BadConfigFetcherState => "error-type:bad-state",
            DynamicConfigError::UnknownConfigRefreshError(..) => "error-type:unknown",
        }
    }

    pub fn as_tag_set(&self) -> &'static Vec<&'static str> {
        match self {
            DynamicConfigError::ConfigNotFound { .. } => &NOT_FOUND,
            DynamicConfigError::ConfigParseError { .. } => &PARSE_ERROR,
            DynamicConfigError::BadConfigFetcherState => &BAD_STATE,
            DynamicConfigError::UnknownConfigRefreshError(_) => &UNKNOWN,
        }
    }
}

pub trait DynamicConfig:
    Clone + for<'a> Deserialize<'a> + Default + Debug + Sync + 'static + Send
{
}

impl<T: Clone + for<'a> Deserialize<'a> + Default + Debug + Sync + Send + 'static> DynamicConfig
    for T
{
}

#[cfg_attr(test, automock)]
pub trait DynamicConfigFetcher<C>: Send + 'static
where
    C: DynamicConfig,
{
    /// Fetches the dynamic config.
    /// returns Ok(None) if the config has not been updated since the last time it was fetched
    // explicitly desugar async so we can signify it is Send to satisfy tokio::spawn
    fn get_config(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<(C, RefreshMeta)>, DynamicConfigError>> + Send;
}

pub trait ErrorCallback: Fn(DynamicConfigError) + Sync + Send + 'static {}
impl<T: Fn(DynamicConfigError) + Sync + Send + 'static> ErrorCallback for T {}

/// Compatible with any Apache arrow storage client (AWS, GCP, Azure, in-memory, local filesystem)
pub struct ApacheDynamicConfigFetcher<T>
where
    T: ObjectStore,
{
    storage_client: T,
    /// storage path to the dynamic config
    config_path: object_store::path::Path,
    /// saves metadata from the last successful refresh
    refresh_meta: Option<RefreshMeta>,
}

#[derive(Clone, Debug)]
pub struct RefreshMeta {
    /// ETag identifying the object returned by the server
    e_tag: String,
    /// Last modified time of the object
    last_modified: chrono::DateTime<chrono::Utc>,
    /// Instant of last refresh by this fetcher
    refreshed_at: Instant,
}

impl<T> ApacheDynamicConfigFetcher<T>
where
    T: ObjectStore,
{
    pub fn new(storage_client: T, config_path: &str) -> Self {
        let config_path = object_store::path::Path::from(config_path);
        Self {
            storage_client,
            config_path,
            refresh_meta: None,
        }
    }
}

impl<T, C> DynamicConfigFetcher<C> for ApacheDynamicConfigFetcher<T>
where
    T: ObjectStore,
    C: DynamicConfig,
{
    async fn get_config(&mut self) -> Result<Option<(C, RefreshMeta)>, DynamicConfigError> {
        // only fetch config if the file has changed
        let opts = GetOptions {
            if_none_match: self.refresh_meta.as_ref().map(|meta| meta.e_tag.clone()),
            ..Default::default()
        };

        let get_result = match self.storage_client.get_opts(&self.config_path, opts).await {
            Ok(result) => result,
            Err(object_store::Error::NotModified { .. }) => return Ok(None),
            Err(object_store::Error::NotFound { path, .. }) => {
                return Err(DynamicConfigError::ConfigNotFound { path })
            }
            Err(err) => {
                return Err(DynamicConfigError::UnknownConfigRefreshError(
                    anyhow::anyhow!(err),
                ))
            }
        };

        let refresh_meta = RefreshMeta {
            e_tag: get_result.meta.e_tag.clone().unwrap(),
            last_modified: get_result.meta.last_modified,
            refreshed_at: Instant::now(),
        };

        match get_result.bytes().await {
            Ok(bytes) => {
                let data = bytes.as_ref();
                let config = serde_yaml::from_slice(data).map_err(|err| {
                    DynamicConfigError::ConfigParseError {
                        raw_config: String::from_utf8_lossy(data).to_string(),
                        error: anyhow::anyhow!(err),
                    }
                })?;
                self.refresh_meta = Some(refresh_meta.clone());
                Ok(Some((config, refresh_meta)))
            }
            Err(err) => Err(DynamicConfigError::UnknownConfigRefreshError(
                anyhow::anyhow!(err),
            )),
        }
    }
}

/// Similar to a read lock-guard acquired from a RwLock
pub struct SubscriptionGuard<'a, T>(watch::Ref<'a, T>);

impl<T> Deref for SubscriptionGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0.deref()
    }
}

impl<T: Debug> Debug for SubscriptionGuard<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Similar to a read-only view of RwLock - wraps a watch::Receiver to use read-only methods
#[derive(Debug, Clone)]
pub struct Subscription<T>(watch::Receiver<T>);

impl<T> Subscription<T> {
    pub fn new(listener: watch::Receiver<T>) -> Self {
        Self(listener)
    }

    /// Like any synchronized values, caller should hold returned reference since it can be
    /// expensive to get, but release it when done using and before calling async code
    pub fn get(&self) -> SubscriptionGuard<'_, T> {
        // we borrow the value but never mark it seen
        SubscriptionGuard(self.0.borrow())
    }
}

impl<T: PartialEq> PartialEq<T> for SubscriptionGuard<'_, T> {
    fn eq(&self, other: &T) -> bool {
        self.0.deref().eq(other)
    }
}

/// Use to refresh dynamic config asynchronously.
#[derive(Debug)]
pub struct DynamicConfigManager<T, C, F>
where
    T: DynamicConfigFetcher<C>,
    C: DynamicConfig,
    F: ErrorCallback,
{
    refresh_interval: Duration,
    config_fetcher: T,

    config: C,
    last_updated: Option<Instant>,
    on_error: Option<Arc<F>>,

    // wrapped in Mutex to allow DynamicConfigManager to be Send
    sender: Mutex<watch::Sender<C>>,
    receiver: watch::Receiver<C>,
}

impl<T, C, F> DynamicConfigManager<T, C, F>
where
    T: DynamicConfigFetcher<C>,
    C: DynamicConfig,
    F: ErrorCallback,
{
    pub fn new(config_fetcher: T, refresh_interval: Duration, on_error: Option<F>) -> Self {
        let config = C::default();
        let (sender, receiver) = watch::channel(config.clone());
        Self {
            refresh_interval,
            config_fetcher,

            config,
            last_updated: None,
            on_error: on_error.map(Arc::new),

            sender: Mutex::new(sender),
            receiver,
        }
    }

    pub fn get_config(&self) -> &C {
        &self.config
    }

    fn handle_error(&self, err: DynamicConfigError) {
        if let Some(error_callback) = self.on_error.as_ref() {
            error_callback(err);
        }
    }

    pub fn subscribe(&self) -> Subscription<C> {
        Subscription::new(self.receiver.clone())
    }

    pub async fn start(
        mut self,
        mut stop_signal: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), DynamicConfigError> {
        let mut delayer = tokio::time::interval(self.refresh_interval.into());
        loop {
            if stop_signal.try_recv().is_ok() {
                return Ok(());
            }
            match self.config_fetcher.get_config().await {
                Ok(Some((new_config, refresh_meta))) => {
                    info!(
                        "Found new dynamic config: etag={}, config_last_modified={} config=\n{:?}",
                        refresh_meta.e_tag, refresh_meta.last_modified, new_config
                    );
                    self.config = new_config;
                    self.last_updated = Some(refresh_meta.refreshed_at);
                    self.sender.lock().await.send(self.config.clone()).unwrap();
                }
                Ok(None) => {
                    if self.last_updated.is_none() {
                        error!("Dynamic config reported as unchanged, but never got a config before. Did you pass in a fresh DynamicConfigFetcher?");
                        self.handle_error(DynamicConfigError::BadConfigFetcherState);
                    }
                }
                Err(err) => {
                    self.handle_error(err);
                }
            };

            delayer.tick().await;
        }
    }
}

#[allow(clippy::type_complexity)]
pub fn start_config_manager<C: DynamicConfig>(
    config_path: &str,
    refresh_interval: Duration,
    stop_signal_rx: tokio::sync::oneshot::Receiver<()>,
    on_error: Option<fn(DynamicConfigError)>,
) -> anyhow::Result<(JoinHandle<Result<(), DynamicConfigError>>, Subscription<C>)> {
    if config_path.starts_with("gs://") {
        let storage = gcp::GoogleCloudStorageBuilder::new()
            .with_url(config_path)
            .build()
            .expect("GCP config path should be valid");
        let fetcher = ApacheDynamicConfigFetcher::new(storage, config_path);
        let config_manager =
            DynamicConfigManager::<_, C, _>::new(fetcher, refresh_interval, on_error);
        let subscription = config_manager.subscribe();
        let handle = tokio::spawn(async move { config_manager.start(stop_signal_rx).await });
        Ok((handle, subscription))
    } else if config_path.starts_with("file://") {
        let config_path = config_path.strip_prefix("file://").unwrap();
        let config_path = std::path::absolute(config_path)?;
        let storage = object_store::local::LocalFileSystem::new();
        let fetcher = ApacheDynamicConfigFetcher::new(storage, config_path.to_str().unwrap());
        let config_manager =
            DynamicConfigManager::<_, C, _>::new(fetcher, refresh_interval, on_error);
        let subscription = config_manager.subscribe();
        let handle = tokio::spawn(async move { config_manager.start(stop_signal_rx).await });
        Ok((handle, subscription))
    } else {
        Err(anyhow::anyhow!(
            "Unsupported config path, expected gs:// or file:// schemes: {}",
            config_path
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ops::{Deref, Mul},
        sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError},
    };

    use once_cell::sync::Lazy;
    use serde::{Deserialize, Serialize};
    use tokio::{
        io::AsyncWriteExt,
        sync::{oneshot, Mutex},
        time::sleep,
    };

    use super::{
        start_config_manager, DynamicConfigError, DynamicConfigManager, MockDynamicConfigFetcher,
    };
    use crate::Duration;

    #[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestConfig {
        field1: String,
        field2: usize,
        field3: bool,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct BadConfig {
        unknown_field: usize,
    }

    fn create_test_manager(
        configure_fetcher: impl Fn(&mut MockDynamicConfigFetcher<TestConfig>),
    ) -> DynamicConfigManager<
        MockDynamicConfigFetcher<TestConfig>,
        TestConfig,
        fn(DynamicConfigError),
    > {
        let mut fetcher = MockDynamicConfigFetcher::new();
        configure_fetcher(&mut fetcher);
        DynamicConfigManager::new(fetcher, Duration::from_secs(5), None)
    }

    #[test]
    fn manager_starts_with_default() {
        let manager = create_test_manager(|_| {});
        assert_eq!(&TestConfig::default(), manager.get_config());
    }

    #[tokio::test]
    async fn test_live() {
        // Lazy does not allow static as mutable, so wrap channel in mutex
        static ERROR_CHANNEL: Lazy<(
            Sender<DynamicConfigError>,
            Mutex<Receiver<DynamicConfigError>>,
        )> = Lazy::new(|| {
            let (sender, receiver) = channel();
            (sender, Mutex::new(receiver))
        });
        static FILEPATH: Lazy<String> = Lazy::new(|| {
            std::path::absolute("./test_dynamic_config.yaml")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        });
        static INTERVAL: Lazy<Duration> = Lazy::new(|| Duration::from_secs(1));

        async fn wait_interval() {
            sleep((*INTERVAL).into()).await
        }

        fn send_error(err: DynamicConfigError) {
            ERROR_CHANNEL.0.send(err).unwrap();
        }

        async fn receive_error() -> DynamicConfigError {
            tokio::time::timeout(Duration::from_millis(5000).into(), async {
                loop {
                    match ERROR_CHANNEL.1.lock().await.try_recv() {
                        Ok(dynamic_config_error) => return dynamic_config_error,
                        Err(TryRecvError::Empty) => {}
                        Err(err) => panic!("Got unexpected error: {:?}", err),
                    }
                    wait_interval().await;
                }
            })
            .await
            .unwrap()
        }

        async fn clear_not_found_errors() {
            loop {
                wait_interval().await;
                match ERROR_CHANNEL.1.lock().await.try_recv() {
                    Ok(DynamicConfigError::ConfigNotFound { .. }) => {}
                    _ => return,
                }
            }
        }

        async fn expect_no_error() {
            match ERROR_CHANNEL
                .1
                .lock()
                .await
                .recv_timeout(INTERVAL.mul(2).into())
            {
                Ok(err) => panic!("Expected no DynamicConfigError, got {:?}", err),
                Err(RecvTimeoutError::Timeout) => {}
                Err(err) => panic!("Channel failed unexpectedly {:?}", err),
            }
        }

        async fn write_config<T: Serialize>(config: &T, absolute_path: &str) {
            let mut f = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(absolute_path)
                .await
                .unwrap();
            let value = serde_yaml::to_string(&config).unwrap();
            f.write_all(value.as_bytes()).await.unwrap();
        }

        fn cleanup_config() {
            let _ = std::fs::remove_file(FILEPATH.as_str());
        }

        cleanup_config();
        let mut current_config = TestConfig::default();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (handle, subscription) = start_config_manager::<TestConfig>(
            format!("file://{}", *FILEPATH).as_str(),
            *INTERVAL,
            stop_rx,
            Some(send_error),
        )
        .unwrap();

        assert_eq!(
            &current_config,
            subscription.get().deref(),
            "Should be default until refresh"
        );

        wait_interval().await;
        match receive_error().await {
            DynamicConfigError::ConfigNotFound { path } => {
                assert_eq!(path, FILEPATH.to_string());
            }
            err => panic!("unexpected error {:?}", err),
        }
        assert_eq!(
            &current_config,
            subscription.get().deref(),
            "Should be previous value even after error"
        );

        write_config(&current_config, &FILEPATH).await;
        clear_not_found_errors().await;
        expect_no_error().await;
        assert_eq!(
            &current_config,
            subscription.get().deref(),
            "Should match the file"
        );

        let previous_config_pointer = subscription.get().deref() as *const _;
        write_config(&current_config, &FILEPATH).await;
        clear_not_found_errors().await;
        expect_no_error().await;
        assert_eq!(
            previous_config_pointer,
            subscription.get().deref() as *const _,
            "Config fetcher should ignore refreshes when ETAG does not change"
        );

        current_config.field1 = "test an update".to_string();
        write_config(&current_config, &FILEPATH).await;
        clear_not_found_errors().await;
        expect_no_error().await;
        assert_eq!(
            &current_config,
            subscription.get().deref(),
            "Should match update"
        );

        write_config(&BadConfig::default(), &FILEPATH).await;
        match receive_error().await {
            DynamicConfigError::ConfigParseError { .. } => {}
            err => panic!(
                "Expected ConfigParseError, received unexpected error: {:?}",
                err
            ),
        }
        assert_eq!(
            &current_config,
            subscription.get().deref(),
            "Should be previous value even after error"
        );

        stop_tx.send(()).unwrap();
        let _ = handle.await.unwrap();
        cleanup_config();
    }
}
