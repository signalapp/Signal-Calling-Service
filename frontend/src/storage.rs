//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_dynamodb::{
    operation::delete_item::DeleteItemError,
    operation::update_item::UpdateItemError,
    types::{AttributeValue, ReturnValue, Select},
    Client, Config,
};
use aws_smithy_async::rt::sleep::default_async_sleep;
use aws_smithy_types::{retry::RetryConfigBuilder, timeout::TimeoutConfig};
use aws_types::region::Region;
use calling_common::{Duration, RoomId};
use hyper::client::HttpConnector;
use hyper::{Body, Method, Request};
use log::*;
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_item, to_item, Item};
use serde_with::{ser::SerializeAsWrap, serde_as, Bytes};
use tokio::{io::AsyncWriteExt, sync::oneshot::Receiver};

use std::{collections::HashMap, path::PathBuf, time::SystemTime};

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::{config, frontend::UserId, metrics::Timer};

const ROOM_ID_KEY: &str = "roomId";
const RECORD_TYPE_KEY: &str = "recordType";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallRecord {
    /// The room that the client is authorized to join.
    /// Provided to the frontend by the client.
    #[serde(skip_serializing)]
    pub room_id: RoomId,
    /// A random id generated and sent back to the client to let it know
    /// about the specific call "in" the room.
    ///
    /// Also used as the call ID within the backend.
    pub era_id: String,
    /// The IP of the backend Calling Server that hosts the call.
    pub backend_ip: String,
    /// The region of the backend Calling Server that hosts the call.
    #[serde(rename = "region")]
    pub backend_region: String,
    /// The ID of the user that created the call.
    ///
    /// This will not be a plain UUID; it will be encoded in some way that clients can identify.
    pub creator: UserId,
}

impl CallRecord {
    const RECORD_TYPE: &str = "ActiveCall";
    // 'region' is a DynamoDB reserved word, so anyone using this list has to provide an alias with
    // '#region'.
    const ATTRIBUTES: &str = "roomId,eraId,backendIp,#region,creator";
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum CallLinkRestrictions {
    None,
    AdminApproval,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallLinkState {
    /// Bytes chosen by the room creator to identify admins.
    #[serde_as(as = "Bytes")]
    pub admin_passkey: Vec<u8>,
    /// A serialized CallLinkPublicParams, used to verify credentials.
    #[serde_as(as = "Bytes")]
    pub zkparams: Vec<u8>,
    /// Controls access to the room.
    pub restrictions: CallLinkRestrictions,
    /// The name of the room, decryptable by clients who know the call link's root key.
    ///
    /// May be empty.
    #[serde_as(as = "Bytes")]
    pub encrypted_name: Vec<u8>,
    /// Whether or not the call link has been manually revoked.
    pub revoked: bool,
    /// When the link expires.
    ///
    /// Note that records are preserved after expiration, at least for a while, so clients can fetch
    /// the name of an expired link.
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    pub expiration: SystemTime,
    /// List of approved users.
    ///
    /// Only fetched by certain APIs, will be empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_users: Vec<UserId>,
}

impl CallLinkState {
    const RECORD_TYPE: &str = "CallLinkState";
    const PEEK_ATTRIBUTES: &str =
        "adminPasskey,zkparams,restrictions,encryptedName,revoked,expiration";

    const EXPIRATION_TIMER: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 90);

    pub fn new(admin_passkey: Vec<u8>, zkparams: Vec<u8>, now: SystemTime) -> Self {
        Self {
            admin_passkey,
            zkparams,
            restrictions: CallLinkRestrictions::None,
            encrypted_name: vec![],
            revoked: false,
            expiration: now + Self::EXPIRATION_TIMER,
            approved_users: vec![],
        }
    }
}

#[serde_as]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallLinkUpdate {
    /// Bytes chosen by the room creator to identify admins.
    #[serde_as(as = "Bytes")]
    pub admin_passkey: Vec<u8>,
    /// Controls access to the room. If None, will not be updated.
    pub restrictions: Option<CallLinkRestrictions>,
    /// The name of the room, decryptable by clients who know the call link's root key.
    ///
    /// May be empty. If None, will not be updated.
    #[serde_as(as = "Option<Bytes>")]
    pub encrypted_name: Option<Vec<u8>>,
    /// Whether or not the call link has been manually revoked. If None, will not be updated.
    pub revoked: Option<bool>,
}

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum CallLinkUpdateError {
    #[error("room does not exist")]
    RoomDoesNotExist,
    #[error("admin passkey does not match")]
    AdminPasskeyDidNotMatch,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Storage: Sync + Send {
    /// Gets an existing call from the table matching the given room_id or returns None.
    async fn get_call_record(&self, room_id: &RoomId) -> Result<Option<CallRecord>, StorageError>;
    /// Adds the given call to the table but if there is already a call with the same
    /// room_id, returns that instead.
    async fn get_or_add_call_record(&self, call: CallRecord) -> Result<CallRecord, StorageError>;
    /// Removes the given call from the table as long as the era_id of the record that
    /// exists in the table is the same.
    async fn remove_call_record(&self, room_id: &RoomId, era_id: &str) -> Result<(), StorageError>;
    /// Returns a list of all calls in the table that are in the given region.
    async fn get_call_records_for_region(
        &self,
        region: &str,
    ) -> Result<Vec<CallRecord>, StorageError>;

    /// Fetches the current state for a call link.
    async fn get_call_link(&self, room_id: &RoomId) -> Result<Option<CallLinkState>, StorageError>;
    /// Updates some or all of a call link's attributes.
    async fn update_call_link(
        &self,
        room_id: &RoomId,
        new_attributes: CallLinkUpdate,
        zkparams_for_creation: Option<Vec<u8>>,
    ) -> Result<CallLinkState, CallLinkUpdateError>;
    /// Updates some or all of a call link's attributes.
    async fn reset_call_link_expiration(
        &self,
        room_id: &RoomId,
        now: SystemTime,
    ) -> Result<(), CallLinkUpdateError>;
    /// Fetches both the current state for a call link and the call record.
    ///
    /// Includes the list of approved users in the CallLinkState unless `peek_info_only` is set to
    /// `true`.
    async fn get_call_link_and_record(
        &self,
        room_id: &RoomId,
        peek_info_only: bool,
    ) -> Result<(Option<CallLinkState>, Option<CallRecord>), StorageError>;
    async fn update_call_link_approved_users(
        &self,
        room_id: &RoomId,
        approved_users: Vec<UserId>,
    ) -> Result<(), CallLinkUpdateError>;
}

pub struct DynamoDb {
    client: Client,
    table_name: String,
}

impl DynamoDb {
    pub async fn new(config: &config::Config) -> Result<Self> {
        let sleep_impl =
            default_async_sleep().ok_or_else(|| anyhow!("failed to create sleep_impl"))?;

        let client = match &config.storage_endpoint {
            Some(endpoint) => {
                const KEY: &str = "DUMMY_KEY";
                const PASSWORD: &str = "DUMMY_PASSWORD";

                info!("Using endpoint for DynamodDB testing: {}", endpoint);

                let aws_config = Config::builder()
                    .credentials_provider(Credentials::from_keys(KEY, PASSWORD, None))
                    .endpoint_url(endpoint)
                    .sleep_impl(sleep_impl)
                    .region(Region::new(config.storage_region.clone()))
                    .build();
                Client::from_conf(aws_config)
            }
            _ => {
                info!(
                    "Using region for DynamodDB access: {}",
                    config.storage_region.as_str()
                );

                let retry_config = RetryConfigBuilder::new()
                    .max_attempts(4)
                    .initial_backoff(std::time::Duration::from_millis(100))
                    .build();

                let timeout_config = TimeoutConfig::builder()
                    .operation_timeout(core::time::Duration::from_secs(30))
                    .operation_attempt_timeout(core::time::Duration::from_secs(10))
                    .read_timeout(core::time::Duration::from_millis(3100))
                    .connect_timeout(core::time::Duration::from_millis(3100))
                    .build();

                let aws_config = aws_config::from_env()
                    .sleep_impl(sleep_impl)
                    .retry_config(retry_config)
                    .timeout_config(timeout_config)
                    .region(Region::new(config.storage_region.clone()))
                    .load()
                    .await;

                Client::new(&aws_config)
            }
        };

        Ok(Self {
            client,
            table_name: config.storage_table.to_string(),
        })
    }
}

/// A wrapper around [`Item`] that can generate "upsert"-like update expressions.
///
/// Note that if there *is* an existing record, but it does *not* have all of the attributes
/// specified, those attributes will be added to the existing record. This differs from a
/// conditional expression, which will leave an existing record untouched.
///
/// ```dynamodb
/// SET #foo = if_not_exists(#foo, :foo), #bar = if_not_exists(#bar, :bar)
/// ```
struct UpsertableItem {
    update_attributes: Item,
    default_attributes: Item,
}

impl UpsertableItem {
    fn with_updates(attributes: Item) -> Self {
        Self::new(attributes, Default::default())
    }

    fn with_defaults(attributes: Item) -> Self {
        Self::new(Default::default(), attributes)
    }

    fn new(update_attributes: Item, default_attributes: Item) -> Self {
        Self {
            update_attributes,
            default_attributes,
        }
    }

    fn generate_update_expression(&self) -> String {
        let update_expressions = self
            .update_attributes
            .keys()
            .map(|k| format!("#{k} = :{k}"));
        let default_expressions = self
            .default_attributes
            .keys()
            .filter(|k| !self.update_attributes.contains_key(k.as_str()))
            .map(|k| format!("#{k} = if_not_exists(#{k}, :{k})"));

        // We don't technically need to sort the expressions, but it's better to be deterministic.
        // (And easier to test.)
        let mut expressions = update_expressions
            .chain(default_expressions)
            .collect::<Vec<_>>();
        assert!(
            !expressions.is_empty(),
            "no attributes besides primary keys, no need for upsert"
        );
        expressions.sort();
        format!("SET {}", expressions.join(","))
    }

    fn generate_attribute_names(&self) -> HashMap<String, String> {
        self.update_attributes
            .keys()
            .chain(self.default_attributes.keys())
            .map(|k| (format!("#{k}"), k.to_string()))
            .collect()
    }

    fn into_attribute_values(mut self) -> HashMap<String, AttributeValue> {
        let update_attributes = std::mem::take(&mut self.update_attributes)
            .into_inner()
            .into_iter();
        let default_attributes = std::mem::take(&mut self.default_attributes)
            .into_inner()
            .into_iter();

        // Allow update-attributes to override default-attributes if both have an entry for the same
        // field.
        default_attributes
            .chain(update_attributes)
            .map(|(k, v)| (format!(":{k}"), v.into()))
            .collect()
    }
}

#[async_trait]
impl Storage for DynamoDb {
    async fn get_call_record(&self, room_id: &RoomId) -> Result<Option<CallRecord>, StorageError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
            )
            .consistent_read(true)
            .send()
            .await
            .context("failed to get_item from storage")?;

        Ok(response
            .item
            .map(|item| from_item(item).context("failed to convert item to CallRecord"))
            .transpose()?)
    }

    async fn get_or_add_call_record(&self, call: CallRecord) -> Result<CallRecord, StorageError> {
        let call_as_item = UpsertableItem::with_defaults(
            to_item(&call).expect("failed to convert CallRecord to item"),
        );
        let response = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .update_expression(call_as_item.generate_update_expression())
            .key(
                ROOM_ID_KEY,
                AttributeValue::S(call.room_id.as_ref().to_string()),
            )
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
            )
            .set_expression_attribute_names(Some(call_as_item.generate_attribute_names()))
            .set_expression_attribute_values(Some(call_as_item.into_attribute_values()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;

        match response {
            Ok(response) => Ok(from_item(
                response.attributes().expect("requested attributes").clone(),
            )
            .context("failed to convert item to CallRecord")?),
            Err(err) => Err(StorageError::UnexpectedError(
                anyhow::Error::from(err)
                    .context("failed to update_item in storage for get_or_add_call_record"),
            )),
        }
    }

    async fn remove_call_record(&self, room_id: &RoomId, era_id: &str) -> Result<(), StorageError> {
        let response = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            // Delete the item for the given key.
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
            )
            // But only if the given era_id matches the expected value, otherwise the
            // previous call was removed and a new one created already.
            .condition_expression("eraId = :value")
            .expression_attribute_values(":value", AttributeValue::S(era_id.to_string()))
            .send()
            .await;

        match response {
            Ok(_) => Ok(()),
            Err(err) => match err.into_service_error() {
                DeleteItemError::ConditionalCheckFailedException(_) => Ok(()),
                err => Err(StorageError::UnexpectedError(err.into())),
            },
        }
    }

    async fn get_call_records_for_region(
        &self,
        region: &str,
    ) -> Result<Vec<CallRecord>, StorageError> {
        let response = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name("region-index")
            .key_condition_expression("#region = :value and recordType = :recordType")
            .expression_attribute_names("#region", "region")
            .expression_attribute_values(":value", AttributeValue::S(region.to_string()))
            .expression_attribute_values(
                ":recordType",
                AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
            )
            .consistent_read(false)
            .select(Select::AllAttributes)
            .send()
            .await
            .context("failed to query for calls in a region")?;

        if let Some(items) = response.items {
            return Ok(items
                .into_iter()
                .map(|item| from_item(item).context("failed to convert item to CallRecord"))
                .collect::<Result<_>>()?);
        }

        Ok(vec![])
    }

    async fn get_call_link(&self, room_id: &RoomId) -> Result<Option<CallLinkState>, StorageError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .projection_expression(CallLinkState::PEEK_ATTRIBUTES)
            .consistent_read(true)
            .send()
            .await
            .context("failed to get_item from storage")?;

        Ok(response
            .item
            .map(|item| from_item(item).context("failed to convert item to CallLinkState"))
            .transpose()?)
    }

    /// Updates some or all of a call link's attributes.
    async fn update_call_link(
        &self,
        room_id: &RoomId,
        new_attributes: CallLinkUpdate,
        zkparams_for_creation: Option<Vec<u8>>,
    ) -> Result<CallLinkState, CallLinkUpdateError> {
        let mut call_as_item = UpsertableItem::with_updates(
            to_item(&new_attributes).expect("failed to convert CallLinkUpdate to item"),
        );

        let must_exist;
        let condition;
        if let Some(zkparams_for_creation) = zkparams_for_creation {
            call_as_item.default_attributes = to_item(CallLinkState::new(
                new_attributes.admin_passkey,
                zkparams_for_creation,
                SystemTime::now(),
            ))
            .expect("failed to convert CallLinkState to item");
            must_exist = false;
            condition = concat!(
                "(adminPasskey = :adminPasskey OR attribute_not_exists(adminPasskey)) AND ",
                "(zkparams = :zkparams OR attribute_not_exists(zkparams))"
            );
        } else {
            must_exist = true;
            condition = "adminPasskey = :adminPasskey";
        }

        let response = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .update_expression(call_as_item.generate_update_expression())
            .condition_expression(condition)
            .set_expression_attribute_names(Some(call_as_item.generate_attribute_names()))
            .set_expression_attribute_values(Some(call_as_item.into_attribute_values()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;

        match response {
            Ok(response) => Ok(from_item(
                response.attributes().expect("requested attributes").clone(),
            )
            .context("failed to convert item to CallLinkState")?),
            Err(err) => match err.into_service_error() {
                UpdateItemError::ConditionalCheckFailedException(_) => {
                    if !must_exist {
                        // The only way this could have failed is if there *was* a room but the admin passkey (or zkparams) was wrong.
                        Err(CallLinkUpdateError::AdminPasskeyDidNotMatch)
                    } else {
                        // Check if the room exists.
                        match self.get_call_link(room_id).await {
                            Ok(Some(_)) => Err(CallLinkUpdateError::AdminPasskeyDidNotMatch),
                            Ok(None) => Err(CallLinkUpdateError::RoomDoesNotExist),
                            Err(inner_err) => Err(CallLinkUpdateError::UnexpectedError(
                                anyhow::Error::from(inner_err)
                                    .context("failed to check for existing room after failing to update_item in storage for update_call_link"),
                            ))
                        }
                    }
                }
                err => Err(CallLinkUpdateError::UnexpectedError(
                    anyhow::Error::from(err)
                        .context("failed to update_item in storage for update_call_link"),
                )),
            },
        }
    }

    async fn reset_call_link_expiration(
        &self,
        room_id: &RoomId,
        now: SystemTime,
    ) -> Result<(), CallLinkUpdateError> {
        let expiration = now + CallLinkState::EXPIRATION_TIMER;
        // Must match the serialization used by CallLinkState's expiration property.
        let attribute_value: AttributeValue =
            serde_dynamo::to_attribute_value(
                SerializeAsWrap::<_, serde_with::TimestampSeconds<i64>>::new(&expiration),
            )
            .expect("failed to convert timestamp to attribute");

        let response = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .update_expression("SET expiration = :newExpiration")
            .condition_expression("attribute_exists(recordType)")
            .expression_attribute_values(":newExpiration", attribute_value)
            .send()
            .await;

        match response {
            Ok(_) => Ok(()),
            Err(err) => match err.into_service_error() {
                UpdateItemError::ConditionalCheckFailedException(_) => {
                    Err(CallLinkUpdateError::RoomDoesNotExist)
                }
                err => Err(CallLinkUpdateError::UnexpectedError(
                    anyhow::Error::from(err)
                        .context("failed to update_item in storage for reset_call_link_expiration"),
                )),
            },
        }
    }

    async fn get_call_link_and_record(
        &self,
        room_id: &RoomId,
        peek_info_only: bool,
    ) -> Result<(Option<CallLinkState>, Option<CallRecord>), StorageError> {
        let query = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("roomId = :value")
            .expression_attribute_values(":value", AttributeValue::S(room_id.as_ref().to_string()))
            .consistent_read(true);
        let query = if peek_info_only {
            query
                .projection_expression(format!(
                    "{},{},{}",
                    RECORD_TYPE_KEY,
                    CallLinkState::PEEK_ATTRIBUTES,
                    CallRecord::ATTRIBUTES
                ))
                .expression_attribute_names("#region", "region")
        } else {
            query
        };
        let response = query
            .send()
            .await
            .context("failed to query for call link and record from storage")?;

        let mut link_state = None;
        let mut call_record = None;

        if let Some(items) = response.items {
            for item in items {
                if let Some(AttributeValue::S(record_type)) = item.get(RECORD_TYPE_KEY) {
                    match record_type.as_str() {
                        CallRecord::RECORD_TYPE => {
                            call_record = Some(
                                from_item(item).context("failed to convert item to CallRecord")?,
                            )
                        }
                        CallLinkState::RECORD_TYPE => {
                            link_state = Some(
                                from_item(item)
                                    .context("failed to convert item to CallLinkState")?,
                            )
                        }
                        _ => {
                            warn!("unexpected record_type: {}", record_type);
                        }
                    }
                }
            }
        }

        Ok((link_state, call_record))
    }

    async fn update_call_link_approved_users(
        &self,
        room_id: &RoomId,
        approved_users: Vec<UserId>,
    ) -> Result<(), CallLinkUpdateError> {
        let request = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id.as_ref().to_string()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .condition_expression("attribute_exists(recordType)");
        let request = if approved_users.is_empty() {
            request.update_expression("REMOVE approvedUsers")
        } else {
            request
                .update_expression("SET approvedUsers = :value")
                .expression_attribute_values(":value", AttributeValue::Ss(approved_users))
        };

        match request.send().await {
            Ok(_) => Ok(()),
            Err(err) => match err.into_service_error() {
                UpdateItemError::ConditionalCheckFailedException(_) => {
                    Err(CallLinkUpdateError::RoomDoesNotExist)
                }
                err => Err(CallLinkUpdateError::UnexpectedError(
                    anyhow::Error::from(err).context(
                        "failed to update_item in storage for update_call_link_approved_users",
                    ),
                )),
            },
        }
    }
}

/// Supports the DynamoDB storage implementation by periodically refreshing an identity
/// token file at the location given by `identity_token_path`.
pub struct IdentityFetcher {
    client: hyper::Client<HttpConnector>,
    fetch_interval: Duration,
    identity_token_path: PathBuf,
    identity_token_url: Option<String>,
}

impl IdentityFetcher {
    pub fn new(config: &'static config::Config, identity_token_path: &str) -> Self {
        IdentityFetcher {
            client: hyper::client::Client::builder().build_http(),
            fetch_interval: Duration::from_millis(config.identity_fetcher_interval_ms),
            identity_token_path: PathBuf::from(identity_token_path),
            identity_token_url: config.identity_token_url.to_owned(),
        }
    }

    pub async fn fetch_token(&self) -> Result<()> {
        if let Some(url) = &self.identity_token_url {
            let request = Request::builder()
                .method(Method::GET)
                .uri(url)
                .header("Metadata-Flavor", "Google")
                .body(Body::empty())?;

            debug!("Fetching identity token from {}", url);

            let body = self.client.request(request).await?;
            let body = hyper::body::to_bytes(body).await?;
            let temp_name = self.identity_token_path.with_extension("bak");
            let mut temp_file = tokio::fs::File::create(&temp_name).await?;
            temp_file.write_all(&body).await?;
            tokio::fs::rename(temp_name, &self.identity_token_path).await?;

            debug!(
                "Successfully wrote identity token to {:?}",
                &self.identity_token_path
            );
        }
        Ok(())
    }

    pub async fn start(self, ender_rx: Receiver<()>) -> Result<()> {
        // Periodically fetch a new web identity from GCP.
        let fetcher_handle = tokio::spawn(async move {
            loop {
                // Use sleep() instead of interval() so that we never wait *less* than one
                // interval to do the next tick.
                tokio::time::sleep(self.fetch_interval.into()).await;

                let timer = start_timer_us!("calling.frontend.identity_fetcher.timed");

                let result = &self.fetch_token().await;
                if let Err(e) = result {
                    event!("calling.frontend.identity_fetcher.error");
                    error!("Failed to fetch identity token : {:?}", e);
                }
                timer.stop();
            }
        });

        info!("fetcher ready");

        // Wait for any task to complete and cancel the rest.
        tokio::select!(
            _ = fetcher_handle => {},
            _ = ender_rx => {},
        );

        info!("fetcher shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::types::{DeleteRequest, PutRequest, WriteRequest};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use futures::FutureExt;
    use once_cell::sync::Lazy;

    use std::future::Future;

    use crate::config::default_test_config;

    use super::*;

    fn make_item(kv_pairs: &[(&'static str, &'static str)]) -> Item {
        kv_pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    serde_dynamo::AttributeValue::S(v.to_string()),
                )
            })
            .collect::<HashMap<_, _>>()
            .into()
    }

    #[test]
    fn upsertable_item_attribute_merging() {
        let default_attributes =
            make_item(&[("defaultOnly", "default"), ("defaultAndUpdate", "default")]);
        let update_attributes =
            make_item(&[("updateOnly", "update"), ("defaultAndUpdate", "update")]);

        let item = UpsertableItem::new(update_attributes, default_attributes);
        assert_eq!(
            item.generate_update_expression(),
            "SET #defaultAndUpdate = :defaultAndUpdate,#defaultOnly = if_not_exists(#defaultOnly, :defaultOnly),#updateOnly = :updateOnly"
        );
        assert_eq!(
            item.generate_attribute_names(),
            HashMap::from_iter(
                [
                    ("#defaultOnly", "defaultOnly"),
                    ("#defaultAndUpdate", "defaultAndUpdate"),
                    ("#updateOnly", "updateOnly")
                ]
                .map(|(k, v)| (k.to_string(), v.to_string()))
            )
        );

        assert_eq!(
            item.into_attribute_values(),
            make_item(&[
                (":defaultOnly", "default"),
                (":defaultAndUpdate", "update"),
                (":updateOnly", "update"),
            ])
            .into_inner()
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect()
        );
    }

    fn timestamp_to_string(timestamp: SystemTime) -> String {
        timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    static TESTING_EXPIRATION: Lazy<SystemTime> =
        Lazy::new(|| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2524608000)); // 2050-01-01

    fn default_call_link_state_json(room_id: &str) -> serde_json::Value {
        serde_json::json!({
            ROOM_ID_KEY: {"S": room_id},
            RECORD_TYPE_KEY: {"S": CallLinkState::RECORD_TYPE},
            "adminPasskey": {"B": STANDARD.encode([1, 2, 3])},
            "zkparams": {"B": ""},
            "restrictions": {"S": "adminApproval"},
            "encryptedName": {"B": STANDARD.encode(b"abc")},
            "revoked": {"BOOL": false},
            "expiration": {"N": timestamp_to_string(*TESTING_EXPIRATION)},
        })
    }

    fn default_call_link_state_json_with(
        room_id: &str,
        mut extra_keys: serde_json::Value,
    ) -> serde_json::Value {
        let mut state = default_call_link_state_json(room_id);
        state
            .as_object_mut()
            .unwrap()
            .append(extra_keys.as_object_mut().unwrap());
        state
    }

    fn with_approved_users_sorted(
        full_info: &mut (Option<CallLinkState>, Option<CallRecord>),
    ) -> &(Option<CallLinkState>, Option<CallRecord>) {
        if let Some(CallLinkState { approved_users, .. }) = &mut full_info.0 {
            approved_users.sort()
        }
        full_info
    }

    async fn with_db_items<R>(
        storage: &DynamoDb,
        items: impl IntoIterator<Item = serde_json::Value>,
        pending_deletes: impl IntoIterator<Item = (&str, &str)>,
        test: impl Future<Output = R>,
    ) -> R {
        let (mut deletes, puts): (Vec<_>, Vec<_>) = items
            .into_iter()
            .map(|item| {
                (
                    WriteRequest::builder()
                        .delete_request(
                            DeleteRequest::builder()
                                .key(
                                    ROOM_ID_KEY,
                                    serde_json::from_value::<serde_dynamo::AttributeValue>(
                                        item.as_object().unwrap().get(ROOM_ID_KEY).unwrap().clone(),
                                    )
                                    .unwrap()
                                    .into(),
                                )
                                .key(
                                    RECORD_TYPE_KEY,
                                    serde_json::from_value::<serde_dynamo::AttributeValue>(
                                        item.as_object()
                                            .unwrap()
                                            .get(RECORD_TYPE_KEY)
                                            .unwrap()
                                            .clone(),
                                    )
                                    .unwrap()
                                    .into(),
                                )
                                .build(),
                        )
                        .build(),
                    WriteRequest::builder()
                        .put_request(
                            PutRequest::builder()
                                .set_item(Some(
                                    serde_json::from_value::<Item>(item).unwrap().into(),
                                ))
                                .build(),
                        )
                        .build(),
                )
            })
            .unzip();

        deletes.extend(
            pending_deletes
                .into_iter()
                .map(|(partition_key, sort_key)| {
                    WriteRequest::builder()
                        .delete_request(
                            DeleteRequest::builder()
                                .key(ROOM_ID_KEY, AttributeValue::S(partition_key.to_string()))
                                .key(RECORD_TYPE_KEY, AttributeValue::S(sort_key.to_string()))
                                .build(),
                        )
                        .build()
                }),
        );

        storage
            .client
            .batch_write_item()
            .request_items(&storage.table_name, puts)
            .send()
            .await
            .expect("can initialize table");

        // Why is this safe?
        // Well, the only thing we do after panicking is run the cleanup code.
        // But if the panic comes from the DynamoDB client, this might not actually be safe.
        // There's not really anything we can do about that (short of reinitializing the client).
        let result = std::panic::AssertUnwindSafe(test).catch_unwind().await;

        storage
            .client
            .batch_write_item()
            .request_items(&storage.table_name, deletes)
            .send()
            .await
            .expect("can clean up table");

        result.unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn test_absent_call_link() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        assert_eq!(
            storage
                .get_call_link(&RoomId::from("testing-nonexistent".to_string()))
                .await?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_present_call_link() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [default_call_link_state_json(&room_id)],
            [],
            async {
                assert_eq!(
                    storage.get_call_link(&RoomId::from(room_id)).await?,
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![],
                    })
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_skips_approved_users() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [default_call_link_state_json_with(
                &room_id,
                serde_json::json!({
                    "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                }),
            )],
            [],
            async {
                assert_eq!(
                    storage.get_call_link(&RoomId::from(room_id)).await?,
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![],
                    })
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_absent() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        assert_eq!(
            storage
                .get_call_link_and_record(&RoomId::from("testing-nonexistent".to_string()), false)
                .await?,
            (None, None)
        );
        assert_eq!(
            storage
                .get_call_link_and_record(&RoomId::from("testing-nonexistent".to_string()), true)
                .await?,
            (None, None)
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_with_no_call() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [default_call_link_state_json(&room_id)],
            [],
            async {
                let expected = (
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![],
                    }),
                    None,
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                        .await?,
                    &expected
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), true)
                        .await?,
                    &expected
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_with_no_call_and_approved_users() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [default_call_link_state_json_with(
                &room_id,
                serde_json::json!({
                    "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                }),
            )],
            [],
            async {
                let mut expected = (
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![
                            "Brian".to_string(),
                            "Meredith".to_string(),
                            "Moxie".to_string(),
                        ],
                    }),
                    None,
                );
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                            .await?
                    ),
                    &expected
                );
                expected.0.as_mut().unwrap().approved_users = vec![];
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), true)
                            .await?
                    ),
                    &expected
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_with_call() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [
                default_call_link_state_json(&room_id),
                serde_json::json!({
                    ROOM_ID_KEY: {"S": room_id},
                    RECORD_TYPE_KEY: {"S": CallRecord::RECORD_TYPE},
                    "eraId": {"S": "mesozoic"},
                    "backendIp": {"S": "127.0.0.1"},
                    "region": {"S": "pangaea"},
                    "creator": {"S": "Peter"},
                }),
            ],
            [],
            async {
                let expected = (
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![],
                    }),
                    Some(CallRecord {
                        room_id: RoomId::from(room_id.clone()),
                        era_id: "mesozoic".to_string(),
                        backend_ip: "127.0.0.1".to_string(),
                        backend_region: "pangaea".to_string(),
                        creator: "Peter".to_string(),
                    }),
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                        .await?,
                    &expected
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), true)
                        .await?,
                    &expected
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_with_call_and_approved_users() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [
                default_call_link_state_json_with(
                    &room_id,
                    serde_json::json!({
                        "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                    }),
                ),
                serde_json::json!({
                    ROOM_ID_KEY: {"S": room_id},
                    RECORD_TYPE_KEY: {"S": CallRecord::RECORD_TYPE},
                    "eraId": {"S": "mesozoic"},
                    "backendIp": {"S": "127.0.0.1"},
                    "region": {"S": "pangaea"},
                    "creator": {"S": "Peter"},
                }),
            ],
            [],
            async {
                let mut expected = (
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec![
                            "Brian".to_string(),
                            "Meredith".to_string(),
                            "Moxie".to_string(),
                        ],
                    }),
                    Some(CallRecord {
                        room_id: RoomId::from(room_id.clone()),
                        era_id: "mesozoic".to_string(),
                        backend_ip: "127.0.0.1".to_string(),
                        backend_region: "pangaea".to_string(),
                        creator: "Peter".to_string(),
                    }),
                );
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                            .await?
                    ),
                    &expected
                );
                expected.0.as_mut().unwrap().approved_users = vec![];
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), true)
                            .await?
                    ),
                    &expected
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_call_link_and_record_non_call_link_call() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [
                // This indicates a group call that coincidentally matches the call link we looked up.
                // But there's no call link state, so this API should ignore it.
                // (This is fantastically unlikely in practice.)
                serde_json::json!({
                    ROOM_ID_KEY: {"S": room_id},
                    RECORD_TYPE_KEY: {"S": CallRecord::RECORD_TYPE},
                    "eraId": {"S": "mesozoic"},
                    "backendIp": {"S": "127.0.0.1"},
                    "region": {"S": "pangaea"},
                    "creator": {"S": "Peter"},
                }),
            ],
            [],
            async {
                let expected = (
                    None,
                    Some(CallRecord {
                        room_id: RoomId::from(room_id.clone()),
                        era_id: "mesozoic".to_string(),
                        backend_ip: "127.0.0.1".to_string(),
                        backend_region: "pangaea".to_string(),
                        creator: "Peter".to_string(),
                    }),
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                        .await?,
                    &expected
                );
                assert_eq!(
                    &storage
                        .get_call_link_and_record(&RoomId::from(room_id.clone()), true)
                        .await?,
                    &expected
                );
                Ok(())
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore]
    async fn test_update_call_link_approved_users() -> Result<()> {
        let storage = DynamoDb::new(&default_test_config()).await?;
        let room_id = format!("testing-room-{}", line!());
        with_db_items(
            &storage,
            [default_call_link_state_json(&room_id)],
            [],
            async {
                storage
                    .update_call_link_approved_users(
                        &RoomId::from(room_id.clone()),
                        vec!["me".to_string()],
                    )
                    .await?;

                let mut expected = (
                    Some(CallLinkState {
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        approved_users: vec!["me".to_string()],
                    }),
                    None,
                );
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                            .await?
                    ),
                    &expected
                );

                storage
                    .update_call_link_approved_users(
                        &RoomId::from(room_id.clone()),
                        vec!["me".to_string(), "you".to_string()],
                    )
                    .await?;
                expected.0.as_mut().unwrap().approved_users =
                    vec!["me".to_string(), "you".to_string()];
                assert_eq!(
                    with_approved_users_sorted(
                        &mut storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), false)
                            .await?
                    ),
                    &expected
                );

                Ok(())
            },
        )
        .await
    }

    #[test]
    fn check_call_record_attributes() {
        let example_record = Some(CallRecord {
            room_id: RoomId::from("testing".to_string()),
            era_id: "mesozoic".to_string(),
            backend_ip: "127.0.0.1".to_string(),
            backend_region: "pangaea".to_string(),
            creator: "Peter".to_string(),
        });
        let record_as_json = serde_json::to_value(example_record).expect("can serialize");
        let mut serialized_keys: Vec<&str> = record_as_json
            .as_object()
            .expect("serialized as object")
            .keys()
            .map(|s| s.as_str())
            // roomId isn't serialized because it's part of the primary key,
            // but we still want to fetch it, so we add it to our expected list.
            .chain(std::iter::once(ROOM_ID_KEY))
            .collect();
        serialized_keys.sort();

        let mut known_keys: Vec<&str> = CallRecord::ATTRIBUTES
            .split(',')
            // '#region' is escaped because it's a DynamoDB keyword.
            .map(|s| s.trim_start_matches('#'))
            .collect();
        known_keys.sort();
        assert_eq!(serialized_keys, known_keys);
    }

    #[test]
    fn check_call_link_state_peek_attributes() {
        let example_record = Some(CallLinkState {
            admin_passkey: vec![1, 2, 3],
            zkparams: vec![10, 20, 30],
            restrictions: CallLinkRestrictions::AdminApproval,
            encrypted_name: b"abc".to_vec(),
            revoked: true,
            expiration: *TESTING_EXPIRATION,
            // Deliberately empty to be left out of this serialization.
            approved_users: vec![],
        });
        let record_as_json = serde_json::to_value(example_record).expect("can serialize");
        let mut serialized_keys: Vec<&str> = record_as_json
            .as_object()
            .expect("serialized as object")
            .keys()
            .map(|s| s.as_str())
            .collect();
        serialized_keys.sort();

        let mut known_keys: Vec<&str> = CallLinkState::PEEK_ATTRIBUTES.split(',').collect();
        known_keys.sort();
        assert_eq!(serialized_keys, known_keys);
    }
}
