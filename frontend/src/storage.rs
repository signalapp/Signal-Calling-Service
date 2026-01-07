//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{collections::HashMap, path::PathBuf, time::SystemTime};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_dynamodb::{
    operation::{
        delete_item::DeleteItemError, transact_write_items::TransactWriteItemsError,
        update_item::UpdateItemError,
    },
    types::{
        AttributeValue, BatchStatementErrorCodeEnum, ConditionCheck, Delete, ReturnValue, Select,
        TransactWriteItem,
    },
    Client, Config,
};
use aws_smithy_async::rt::sleep::default_async_sleep;
use aws_smithy_types::{retry::RetryConfigBuilder, timeout::TimeoutConfig};
use aws_types::region::Region;
use calling_common::{CallLinkEpoch, Duration, RoomId};
use log::*;
use metrics::{metric_config::Timer, *};
#[cfg(test)]
use mockall::{automock, predicate::*};
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_item, to_item, Item};
use serde_with::{ser::SerializeAsWrap, serde_as, Bytes};
use tokio::{io::AsyncWriteExt, sync::oneshot::Receiver};

use crate::{api::call_links::CallLinkEpochGenerator, config, frontend::UserId};

const ROOM_ID_KEY: &str = "roomId";
const RECORD_TYPE_KEY: &str = "recordType";

pub(super) fn call_link_room_key(room_id: &RoomId) -> String {
    call_link_room_key_str(room_id.as_ref())
}

fn call_link_room_key_str(room_id: &str) -> String {
    if !room_id.starts_with("adhoc:") {
        format!("adhoc:{}", room_id)
    } else {
        room_id.to_string()
    }
}

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
    const RECORD_TYPE: &'static str = "ActiveCall";
    // 'region' is a DynamoDB reserved word, so anyone using this list has to provide an alias with
    // '#region'.
    const ATTRIBUTES: &'static str = "roomId,eraId,backendIp,#region,creator";
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallRecordKey {
    pub room_id: RoomId,
    pub era_id: String,
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
    /// Call link epoch.
    ///
    /// This value will be None for those links created prior to the introduction of call link
    /// epochs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<CallLinkEpoch>,
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
    /// When the link record is deleted.
    ///
    /// Deletes the dynamodb record at the given time.
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    pub delete_at: SystemTime,
    /// List of approved users.
    ///
    /// Only fetched by certain APIs, will be empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_users: Vec<UserId>,
}

impl CallLinkState {
    const RECORD_TYPE: &'static str = "CallLinkState";
    const GET_CALL_LINK_ATTRIBUTES_WITHOUT_APPROVED_USERS: &'static str =
        "adminPasskey,zkparams,restrictions,encryptedName,revoked,expiration,deleteAt,epoch";
    const GET_CALL_LINK_ATTRIBUTES: &'static str =
        "adminPasskey,zkparams,restrictions,encryptedName,revoked,expiration,deleteAt,epoch,approvedUsers";

    pub const EXPIRATION_TIMER: std::time::Duration =
        std::time::Duration::from_secs(60 * 60 * 24 * 90);
    pub const DELETION_TIMER: std::time::Duration =
        std::time::Duration::from_secs(60 * 60 * 24 * 90);

    pub fn new(
        admin_passkey: Vec<u8>,
        zkparams: Vec<u8>,
        epoch: Option<CallLinkEpoch>,
        now: SystemTime,
    ) -> Self {
        Self {
            admin_passkey,
            epoch,
            zkparams,
            restrictions: CallLinkRestrictions::None,
            encrypted_name: vec![],
            revoked: false,
            expiration: now + Self::EXPIRATION_TIMER,
            delete_at: now + Self::EXPIRATION_TIMER + Self::DELETION_TIMER,
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
    #[error("too many items in batch, provided {provided}, limit is {limit}")]
    BatchLimitExceeded { provided: usize, limit: usize },
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

#[derive(thiserror::Error, Debug)]
pub enum CallLinkDeleteError {
    #[error("room does not exist")]
    RoomDoesNotExist,
    #[error("admin passkey does not match")]
    AdminPasskeyDidNotMatch,
    #[error("call record for this call link was found")]
    CallRecordConflict,
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
    /// Removes a batch of call records from the table, applying the same checks as remove_call_record.
    /// The batch delete is all or nothing. Caller should issue serial deletes in case of error.
    async fn remove_batch_call_records(
        &self,
        call_keys: Vec<CallRecordKey>,
    ) -> Result<(), StorageError>;
    /// Returns a list of all calls in the table that are in the given region.
    async fn get_call_records_for_region(
        &self,
        region: &str,
    ) -> Result<Vec<CallRecord>, StorageError>;

    /// Fetches the current state for a call link.
    async fn get_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
    ) -> Result<Option<CallLinkState>, StorageError>;
    /// Updates some or all of a call link's attributes.
    async fn update_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        new_attributes: CallLinkUpdate,
        zkparams_for_creation: Option<Vec<u8>>,
    ) -> Result<CallLinkState, CallLinkUpdateError>;
    /// Updates some or all of a call link's attributes.
    async fn reset_call_link_expiration(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        now: SystemTime,
    ) -> Result<(), CallLinkUpdateError>;
    /// Deletes a call link, ensuring that a matching call record does not exist
    /// at the same time
    async fn delete_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        admin_passkey: &[u8],
    ) -> Result<(), CallLinkDeleteError>;
    /// Fetches both the current state for a call link and the call record.
    ///
    /// Includes the list of approved users in the CallLinkState unless `peek_info_only` is set to
    /// `true`.
    async fn get_call_link_and_record(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
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
    call_link_epoch_generator: Box<dyn CallLinkEpochGenerator>,
}

impl DynamoDb {
    const TRANSACT_WRITE_ITEMS_LIMIT: usize = 100;

    pub async fn new(
        config: &config::Config,
        call_link_epoch_generator: Box<dyn CallLinkEpochGenerator>,
    ) -> Result<Self> {
        let sleep_impl =
            default_async_sleep().ok_or_else(|| anyhow!("failed to create sleep_impl"))?;

        let client = match &config.storage_endpoint {
            Some(endpoint) => {
                const KEY: &str = "DummyAccessKey";
                const PASSWORD: &str = "DummyPassword";

                info!("Using endpoint for DynamodDB testing: {}", endpoint);

                let aws_config = Config::builder()
                    .behavior_version(BehaviorVersion::v2025_08_07())
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

                let aws_config = aws_config::defaults(BehaviorVersion::v2025_08_07())
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
            call_link_epoch_generator,
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
    condition_attributes: Item,
}

impl UpsertableItem {
    fn with_updates(attributes: Item) -> Self {
        Self::new(attributes, Default::default(), Default::default())
    }

    fn with_defaults(attributes: Item) -> Self {
        Self::new(Default::default(), attributes, Default::default())
    }

    fn new(update_attributes: Item, default_attributes: Item, condition_attributes: Item) -> Self {
        Self {
            update_attributes,
            default_attributes,
            condition_attributes,
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
        let condition_attributes = std::mem::take(&mut self.condition_attributes)
            .into_inner()
            .into_iter();

        // Allow update-attributes to override default-attributes if both have an entry for the same
        // field.
        default_attributes
            .chain(update_attributes)
            .chain(condition_attributes)
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

    async fn remove_batch_call_records(
        &self,
        call_keys: Vec<CallRecordKey>,
    ) -> Result<(), StorageError> {
        if call_keys.is_empty() {
            return Ok(());
        }
        if call_keys.len() == 1 {
            return self
                .remove_call_record(&call_keys[0].room_id, &call_keys[0].era_id)
                .await;
        }
        if call_keys.len() > DynamoDb::TRANSACT_WRITE_ITEMS_LIMIT {
            error!("Error during remove_batch_call_records: BatchLimitExceeded");
            return Err(StorageError::BatchLimitExceeded {
                provided: call_keys.len(),
                limit: DynamoDb::TRANSACT_WRITE_ITEMS_LIMIT,
            });
        }

        let delete_requests = call_keys
            .into_iter()
            .map(|k| {
                Delete::builder()
                    .table_name(&self.table_name)
                    .key(ROOM_ID_KEY, AttributeValue::S(k.room_id.into()))
                    .key(
                        RECORD_TYPE_KEY,
                        AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
                    )
                    .condition_expression("eraId = :value")
                    .expression_attribute_values(":value", AttributeValue::S(k.era_id))
                    .build()
                    .map(|delete| {
                        TransactWriteItem::builder()
                            .set_delete(Some(delete))
                            .build()
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                error!("Failed to build a Delete item: {:?}", err);
                StorageError::UnexpectedError(
                    anyhow::Error::from(err).context("failed to build a Delete item"),
                )
            })?;

        let response = self
            .client
            .transact_write_items()
            .set_transact_items(Some(delete_requests))
            .send()
            .await;
        match response {
            Ok(_) => Ok(()),
            Err(err) => {
                // A ConditionalCheckFailed occurs when a record does not exist. If all deletes failed due to this
                // reason, then we can assume that the batch was previously deleted.
                let err = err.into_service_error();
                if let TransactWriteItemsError::TransactionCanceledException(ref cancellation) = err
                {
                    if cancellation.cancellation_reasons().iter().all(|reason| {
                        reason.code()
                            == Some(BatchStatementErrorCodeEnum::ConditionalCheckFailed.as_str())
                    }) {
                        return Ok(());
                    }
                }

                Err(StorageError::UnexpectedError(err.into()))
            }
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

    async fn get_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
    ) -> Result<Option<CallLinkState>, StorageError> {
        let query = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("roomId = :roomId AND recordType = :recordType")
            .expression_attribute_values(":roomId", AttributeValue::S(call_link_room_key(room_id)))
            .expression_attribute_values(
                ":recordType",
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            );
        let query = if let Some(epoch) = epoch {
            query
                .filter_expression("epoch = :epoch")
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(epoch.as_ref().to_string()),
                )
        } else {
            query.filter_expression("attribute_not_exists(epoch)")
        };

        let response = query
            .projection_expression(CallLinkState::GET_CALL_LINK_ATTRIBUTES_WITHOUT_APPROVED_USERS)
            .consistent_read(true)
            .limit(1)
            .send()
            .await
            .context("failed to query storage")?;

        Ok(response.items.and_then(|items| {
            items
                .into_iter()
                .next()
                .map(|item| from_item(item).expect("failed to convert item to CallLinkState"))
        }))
    }

    /// Updates some or all of a call link's attributes.
    async fn update_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        new_attributes: CallLinkUpdate,
        zkparams_for_creation: Option<Vec<u8>>,
    ) -> Result<CallLinkState, CallLinkUpdateError> {
        // Serialize the new attributes into an "upsertable" item. An item is a a hash map that
        // maps attribute names to their corresponding values (instances of AttributeValue).
        let mut upsertable_item = UpsertableItem::with_updates(
            to_item(&new_attributes).expect("failed to convert CallLinkUpdate to item"),
        );

        let must_exist;
        let condition;
        if let Some(zkparams_for_creation) = zkparams_for_creation {
            let epoch = self.call_link_epoch_generator.new_epoch();
            // This is a new call link. Generate a CallLinkState instance initialized with
            // default values and convert it into an "item". A "union" of this set of attributes
            // and the attributes in "new_attributes" represents the final call link record.
            upsertable_item.default_attributes = to_item(CallLinkState::new(
                new_attributes.admin_passkey,
                zkparams_for_creation,
                epoch,
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
            if let Some(epoch) = epoch {
                let attr_val = AttributeValue::N(epoch.as_ref().to_string());
                upsertable_item
                    .condition_attributes
                    .as_mut()
                    .insert("epoch".to_string(), attr_val.into());
                condition = "adminPasskey = :adminPasskey AND epoch = :epoch";
            } else {
                condition = "adminPasskey = :adminPasskey AND attribute_not_exists(epoch)";
            }
        }

        let response = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(call_link_room_key(room_id)))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .update_expression(upsertable_item.generate_update_expression())
            .condition_expression(condition)
            .set_expression_attribute_names(Some(upsertable_item.generate_attribute_names()))
            .set_expression_attribute_values(Some(upsertable_item.into_attribute_values()))
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
                        match self.get_call_link(room_id, epoch).await {
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

    /// Deletes a call link
    async fn delete_call_link(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        admin_passkey: &[u8],
    ) -> Result<(), CallLinkDeleteError> {
        let room_id_key = call_link_room_key(room_id);

        let delete_link = Delete::builder()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id_key.clone()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            );
        let delete_link = if let Some(epoch) = epoch {
            delete_link
                .condition_expression("adminPasskey = :adminPasskey AND epoch = :epoch")
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(epoch.as_ref().to_string()),
                )
        } else {
            delete_link.condition_expression(
                "adminPasskey = :adminPasskey AND attribute_not_exists(epoch)",
            )
        };
        let delete_link = delete_link
            .expression_attribute_values(":adminPasskey", AttributeValue::B(admin_passkey.into()))
            .build()
            .map(|d| TransactWriteItem::builder().delete(d).build())
            .map_err(|err| {
                error!("Failed to build a Delete item: {:?}", err);
                CallLinkDeleteError::UnexpectedError(
                    anyhow::Error::from(err).context("failed to build a Delete item"),
                )
            })?;

        let active_call_check = ConditionCheck::builder()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(room_id_key.clone()))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallRecord::RECORD_TYPE.to_string()),
            )
            .condition_expression(format!("attribute_not_exists({})", ROOM_ID_KEY))
            .build()
            .map(|c| TransactWriteItem::builder().condition_check(c).build())
            .map_err(|err| {
                error!("Failed to build a ConditionCheck item: {:?}", err);
                CallLinkDeleteError::UnexpectedError(
                    anyhow::Error::from(err).context("failed to build a ConditionCheck item"),
                )
            })?;

        let response = self
            .client
            .transact_write_items()
            .transact_items(delete_link)
            .transact_items(active_call_check)
            .send()
            .await;

        match response {
            Ok(_) => Ok(()),
            Err(err) => match err.into_service_error() {
                TransactWriteItemsError::TransactionCanceledException(ref cancellation) => {
                    let reasons = cancellation.cancellation_reasons();
                    if let Some(code) = reasons[0].code() {
                        if code == BatchStatementErrorCodeEnum::ConditionalCheckFailed.as_str() {
                            // disambiguate check error
                            return match self.get_call_link(room_id, epoch).await {
                                Ok(Some(_)) => Err(CallLinkDeleteError::AdminPasskeyDidNotMatch),
                                Ok(None) => Err(CallLinkDeleteError::RoomDoesNotExist),
                                Err(inner_err) => Err(CallLinkDeleteError::UnexpectedError(
                                    anyhow::Error::from(inner_err)
                                        .context("failed to check for existing room after failing to transact_write_items in storage for delete_call_link"),
                                ))
                            };
                        }
                    }
                    if let Some(code) = reasons[1].code() {
                        if code == BatchStatementErrorCodeEnum::ConditionalCheckFailed.as_str() {
                            return Err(CallLinkDeleteError::CallRecordConflict);
                        }
                    }
                    Err(CallLinkDeleteError::UnexpectedError(anyhow::Error::from(
                        cancellation.clone(),
                    )))
                }

                inner_err => Err(CallLinkDeleteError::UnexpectedError(anyhow::Error::from(
                    inner_err,
                ))),
            },
        }
    }

    async fn reset_call_link_expiration(
        &self,
        room_id: &RoomId,
        epoch: Option<CallLinkEpoch>,
        now: SystemTime,
    ) -> Result<(), CallLinkUpdateError> {
        let expiration = now + CallLinkState::EXPIRATION_TIMER;
        let delete_at = expiration + CallLinkState::DELETION_TIMER;
        // Must match the serialization used by CallLinkState's expiration property.
        let expiration_attribute_value: AttributeValue = serde_dynamo::to_attribute_value(
            SerializeAsWrap::<_, serde_with::TimestampSeconds<i64>>::new(&expiration),
        )
        .expect("failed to convert timestamp to attribute");
        let delete_at_attribute_value: AttributeValue = serde_dynamo::to_attribute_value(
            SerializeAsWrap::<_, serde_with::TimestampSeconds<i64>>::new(&delete_at),
        )
        .expect("failed to convert timestamp to attribute");

        let builder = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(ROOM_ID_KEY, AttributeValue::S(call_link_room_key(room_id)))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            )
            .update_expression("SET expiration = :newExpiration, deleteAt = :newDeleteAt")
            .condition_expression("attribute_exists(recordType)")
            .expression_attribute_values(":newExpiration", expiration_attribute_value)
            .expression_attribute_values(":newDeleteAt", delete_at_attribute_value);
        let builder = if let Some(epoch) = epoch {
            builder
                .condition_expression("attribute_exists(recordType) AND epoch = :epoch")
                .expression_attribute_values(
                    ":epoch",
                    AttributeValue::N(epoch.as_ref().to_string()),
                )
        } else {
            builder.condition_expression(
                "attribute_exists(recordType) AND attribute_not_exists(epoch)",
            )
        };

        let response = builder.send().await;

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
        epoch: Option<CallLinkEpoch>,
        peek_info_only: bool,
    ) -> Result<(Option<CallLinkState>, Option<CallRecord>), StorageError> {
        let call_link_projection_attributes = if peek_info_only {
            CallLinkState::GET_CALL_LINK_ATTRIBUTES_WITHOUT_APPROVED_USERS
        } else {
            CallLinkState::GET_CALL_LINK_ATTRIBUTES
        };

        let response = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("roomId = :value")
            .expression_attribute_values(":value", AttributeValue::S(call_link_room_key(room_id)))
            .consistent_read(true)
            .projection_expression(format!(
                "{},{},{}",
                RECORD_TYPE_KEY,
                call_link_projection_attributes,
                CallRecord::ATTRIBUTES
            ))
            .expression_attribute_names("#region", "region")
            .send()
            .await
            .context("failed to query for call link and record from storage")?;

        let mut link_state: Option<CallLinkState> = None;
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

        // Ideally, we would want to have DynamoDB exclude the records if there is an epoch
        // mismatch. We, however, cannot do that since the filter expression is applied to all
        // matching records, regardless of their type. Call records do *not* have the epoch field
        // and, therefore, they always get excluded. *If* we could use the record type field in the
        // filter expression we could work around this issue, but, alas, we cannot.
        if let Some(link_state) = &link_state {
            if link_state.epoch != epoch {
                return Ok((None, None));
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
            .key(ROOM_ID_KEY, AttributeValue::S(call_link_room_key(room_id)))
            .key(
                RECORD_TYPE_KEY,
                AttributeValue::S(CallLinkState::RECORD_TYPE.to_string()),
            );

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
    client: reqwest::Client,
    fetch_interval: Duration,
    identity_token_path: PathBuf,
    identity_token_url: Option<String>,
}

impl IdentityFetcher {
    pub fn new(config: &'static config::Config, identity_token_path: &str) -> Self {
        IdentityFetcher {
            client: reqwest::Client::new(),
            fetch_interval: Duration::from_millis(config.identity_fetcher_interval_ms),
            identity_token_path: PathBuf::from(identity_token_path),
            identity_token_url: config.identity_token_url.to_owned(),
        }
    }

    pub async fn fetch_token(&self) -> Result<()> {
        if let Some(url) = &self.identity_token_url {
            debug!("Fetching identity token from {}", url);

            let response = self
                .client
                .get(url)
                .header("Metadata-Flavor", "Google")
                .send()
                .await?;
            let body = response.bytes().await?;
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
        let condition_attributes = make_item(&[]);

        let item = UpsertableItem::new(update_attributes, default_attributes, condition_attributes);
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

    #[cfg(feature = "storage-tests")]
    mod test_operations {
        use std::{collections::HashSet, future::Future, process::Command};

        use aws_sdk_dynamodb::{
            error::SdkError,
            types::{DeleteRequest, PutRequest, WriteRequest},
        };
        use base64::{engine::general_purpose::STANDARD, Engine};
        use futures::FutureExt;
        use lazy_static::lazy_static;
        use once_cell::sync::Lazy;

        use super::*;
        use crate::{
            api::call_links::{DefaultCallLinkEpochGenerator, NullCallLinkEpochGenerator},
            config::default_test_config,
        };

        lazy_static! {
            static ref DYNAMODB_STATUS: std::process::ExitStatus = start_dynamodb();
        }

        static TESTING_EXPIRATION: Lazy<SystemTime> =
            Lazy::new(|| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2524608000)); // 2050-01-01
        static TESTING_DELETE_AT: Lazy<SystemTime> = Lazy::new(|| {
            SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(2524608000)
                + CallLinkState::DELETION_TIMER
        }); // 2050-04-01

        const ERA_ID_KEY: &str = "eraId";

        fn default_call_link_call_record_state(room_id: &str, era_id: &str) -> serde_json::Value {
            default_call_record_state(&call_link_room_key_str(room_id), era_id)
        }

        fn default_call_record_state(room_id: &str, era_id: &str) -> serde_json::Value {
            serde_json::json!({
            ROOM_ID_KEY: {"S": room_id},
            RECORD_TYPE_KEY: {"S": CallRecord::RECORD_TYPE},
            ERA_ID_KEY: {"S": era_id},
            "backendIp": {"S": "127.0.0.1"},
            "region": {"S": "pangaea"},
            "creator": {"S": "Peter"},
            })
        }

        fn default_call_link_state_json_without_epoch(room_id: &str) -> serde_json::Value {
            serde_json::json!({
            ROOM_ID_KEY: {"S": call_link_room_key_str(room_id)},
            RECORD_TYPE_KEY: {"S": CallLinkState::RECORD_TYPE},
            "adminPasskey": {"B": STANDARD.encode([1, 2, 3])},
            "zkparams": {"B": ""},
            "restrictions": {"S": "adminApproval"},
            "encryptedName": {"B": STANDARD.encode(b"abc")},
            "revoked": {"BOOL": false},
            "expiration": {"N": timestamp_to_string(*TESTING_EXPIRATION)},
            "deleteAt": {"N": timestamp_to_string(*TESTING_DELETE_AT)},
            })
        }

        fn default_call_link_state_json_with_epoch(
            room_id: &str,
            epoch: &str,
        ) -> serde_json::Value {
            serde_json::json!({
            ROOM_ID_KEY: {"S": call_link_room_key_str(room_id)},
            RECORD_TYPE_KEY: {"S": CallLinkState::RECORD_TYPE},
            "epoch": {"N": epoch},
            "adminPasskey": {"B": STANDARD.encode([1, 2, 3])},
            "zkparams": {"B": ""},
            "restrictions": {"S": "adminApproval"},
            "encryptedName": {"B": STANDARD.encode(b"abc")},
            "revoked": {"BOOL": false},
            "expiration": {"N": timestamp_to_string(*TESTING_EXPIRATION)},
            "deleteAt": {"N": timestamp_to_string(*TESTING_DELETE_AT)},
            })
        }

        fn default_call_link_state_json(
            room_id: &str,
            epoch: Option<CallLinkEpoch>,
        ) -> serde_json::Value {
            if let Some(epoch) = epoch {
                default_call_link_state_json_with_epoch(room_id, &epoch.as_ref().to_string())
            } else {
                default_call_link_state_json_without_epoch(room_id)
            }
        }

        fn default_call_link_state_json_with(
            room_id: &str,
            epoch: Option<CallLinkEpoch>,
            mut extra_keys: serde_json::Value,
        ) -> serde_json::Value {
            let mut state = default_call_link_state_json(room_id, epoch);
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

        fn timestamp_to_string(timestamp: SystemTime) -> String {
            timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string()
        }

        #[derive(thiserror::Error, Debug)]
        enum BootstrapError {
            #[error(transparent)]
            UnexpectedError(#[from] anyhow::Error),

            #[error("failed to run `docker compose run bootstrap from workspace root`")]
            StartupError,
        }

        #[derive(Default)]
        struct StaticCallLinkEpochGenerator;

        impl StaticCallLinkEpochGenerator {
            const GENERATED_EPOCH: Option<CallLinkEpoch> = Some(CallLinkEpoch::new(0));
        }

        impl CallLinkEpochGenerator for StaticCallLinkEpochGenerator {
            fn new_epoch(&self) -> Option<calling_common::CallLinkEpoch> {
                Self::GENERATED_EPOCH
            }
        }

        // Create a local DynamoDb client. The client will be set up to use the default call link
        // epoch generator. Attempt to contact local DynamoDb, if fail - bring up local DynamoDb
        // using Docker Compose and retry.
        async fn bootstrap_storage() -> Result<DynamoDb, BootstrapError> {
            bootstrap_storage_with_epoch_generator(Box::new(DefaultCallLinkEpochGenerator)).await
        }

        // Create a local DynamoDb client. The client will be set up not to use an epoch generator.
        // Attempt to contact local DynamoDb, if fail - bring up local DynamoDb using Docker Compose and retry.
        async fn bootstrap_storage_without_epoch_generator() -> Result<DynamoDb, BootstrapError> {
            bootstrap_storage_with_epoch_generator(Box::new(NullCallLinkEpochGenerator)).await
        }

        // Create a local DynamoDb client. The client will be set up to use the given epoch
        // generator. Attempt to contact local DynamoDb, if fail - bring up local DynamoDb using
        // Docker Compose and retry.
        async fn bootstrap_storage_with_epoch_generator(
            generator: Box<dyn CallLinkEpochGenerator>,
        ) -> Result<DynamoDb, BootstrapError> {
            let client = DynamoDb::new(&default_test_config(), generator)
                .await
                .unwrap();
            println!("Checking local DynamoDB connection...");
            match client.client.list_tables().send().await {
                Ok(_) => {
                    println!("Reusing existing local DynamoDB instance.");
                    Ok(client)
                }
                Err(err) => {
                    if let SdkError::DispatchFailure { .. } = err {
                        println!("Local DynamoDB not running, starting...");
                        // Ensure we only start the container once by referencing static variable
                        if DYNAMODB_STATUS.success() {
                            Ok(client)
                        } else {
                            Err(BootstrapError::StartupError)
                        }
                    } else {
                        Err(BootstrapError::UnexpectedError(err.into()))
                    }
                }
            }
        }

        fn start_dynamodb() -> std::process::ExitStatus {
            // Note: --build flag checks for container existence, not freshness.
            // use `docker compose build bootstrap` when bootstrap image is stale
            Command::new("docker")
                .args(["compose", "run", "bootstrap", "--build"])
                .status()
                .expect("failed to run docker compose - check executing directory and whether docker is installed")
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
                                            item.as_object()
                                                .unwrap()
                                                .get(ROOM_ID_KEY)
                                                .unwrap()
                                                .clone(),
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
                                    .build()
                                    .unwrap(),
                            )
                            .build(),
                        WriteRequest::builder()
                            .put_request(
                                PutRequest::builder()
                                    .set_item(Some(
                                        serde_json::from_value::<Item>(item).unwrap().into(),
                                    ))
                                    .build()
                                    .unwrap(),
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
                                    .build()
                                    .unwrap(),
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
        async fn test_absent_call_link_with_epoch() -> Result<()> {
            let storage = bootstrap_storage().await?;
            assert_eq!(
                storage
                    .get_call_link(
                        &RoomId::from("testing-nonexistent".to_string()),
                        StaticCallLinkEpochGenerator::GENERATED_EPOCH,
                    )
                    .await?,
                None
            );
            Ok(())
        }

        #[tokio::test]
        async fn test_absent_call_link_without_epoch() -> Result<()> {
            let storage = bootstrap_storage().await?;
            assert_eq!(
                storage
                    .get_call_link(&RoomId::from("testing-nonexistent".to_string()), None)
                    .await?,
                None
            );
            Ok(())
        }

        #[tokio::test]
        async fn test_present_call_link_with_epoch() -> Result<()> {
            // Attempting to retrieve a call with an epoch.
            let room_id = format!("testing-room-{}", line!());
            test_present_call_link(&room_id, StaticCallLinkEpochGenerator::GENERATED_EPOCH).await
        }

        #[tokio::test]
        async fn test_present_call_link_without_epoch() -> Result<()> {
            // Attempting to retrieve a call without an epoch.
            let room_id = format!("testing-room-{}", line!());
            test_present_call_link(&room_id, None).await
        }

        async fn test_present_call_link(room_id: &str, epoch: Option<CallLinkEpoch>) -> Result<()> {
            let storage = bootstrap_storage().await?;
            with_db_items(
                &storage,
                [default_call_link_state_json(room_id, epoch)],
                [],
                async {
                    assert_eq!(
                        storage.get_call_link(&RoomId::from(room_id), epoch).await?,
                        Some(CallLinkState {
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec![],
                            epoch,
                        })
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_present_call_link_with_epoch_not_provided() -> Result<()> {
            // Attempting to retrieve a call link with an epoch without providing an epoch.
            let room_id = format!("testing-room-{}", line!());
            let epoch = StaticCallLinkEpochGenerator::GENERATED_EPOCH;
            let storage = bootstrap_storage().await?;
            with_db_items(
                &storage,
                [default_call_link_state_json(room_id.as_str(), epoch)],
                [],
                async {
                    assert_eq!(
                        storage
                            .get_call_link(&RoomId::from(room_id.as_str()), None)
                            .await?,
                        None
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_skips_approved_users_with_epoch() -> Result<()> {
            let room_id = format!("testing-room-{}", line!());
            test_get_call_link_skips_approved_users(
                &room_id,
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_skips_approved_users_without_epoch() -> Result<()> {
            let room_id = format!("testing-room-{}", line!());
            test_get_call_link_skips_approved_users(&room_id, None).await
        }

        async fn test_get_call_link_skips_approved_users(
            room_id: &str,
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            with_db_items(
                &storage,
                [default_call_link_state_json_with(
                    room_id,
                    epoch,
                    serde_json::json!({
                    "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                    }),
                )],
                [],
                async {
                    assert_eq!(
                        storage.get_call_link(&RoomId::from(room_id), epoch).await?,
                        Some(CallLinkState {
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec![],
                        })
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_absent_with_epoch() -> Result<()> {
            test_get_call_link_and_record_absent(StaticCallLinkEpochGenerator::GENERATED_EPOCH)
                .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_absent_without_epoch() -> Result<()> {
            test_get_call_link_and_record_absent(None).await
        }

        async fn test_get_call_link_and_record_absent(epoch: Option<CallLinkEpoch>) -> Result<()> {
            let storage = bootstrap_storage().await?;
            assert_eq!(
                storage
                    .get_call_link_and_record(
                        &RoomId::from("testing-nonexistent".to_string()),
                        epoch,
                        false
                    )
                    .await?,
                (None, None)
            );
            assert_eq!(
                storage
                    .get_call_link_and_record(
                        &RoomId::from("testing-nonexistent".to_string()),
                        epoch,
                        true
                    )
                    .await?,
                (None, None)
            );
            Ok(())
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_no_call_with_epoch() -> Result<()> {
            test_get_call_link_and_record_with_no_call(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_no_call_without_epoch() -> Result<()> {
            test_get_call_link_and_record_with_no_call(None).await
        }

        async fn test_get_call_link_and_record_with_no_call(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [default_call_link_state_json(&room_id, epoch)],
                [],
                async {
                    let expected = (
                        Some(CallLinkState {
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec![],
                        }),
                        None,
                    );
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), epoch, false)
                            .await?,
                        &expected
                    );
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), epoch, true)
                            .await?,
                        &expected
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_no_call_and_approved_users_with_epoch(
        ) -> Result<()> {
            test_get_call_link_and_record_with_no_call_and_approved_users(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_no_call_and_approved_users_without_epoch(
        ) -> Result<()> {
            test_get_call_link_and_record_with_no_call_and_approved_users(None).await
        }

        async fn test_get_call_link_and_record_with_no_call_and_approved_users(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [default_call_link_state_json_with(
                    &room_id,
                    epoch,
                    serde_json::json!({
                    "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                    }),
                )],
                [],
                async {
                    let mut expected = (
                        Some(CallLinkState {
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
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
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    false
                                )
                                .await?
                        ),
                        &expected
                    );
                    expected.0.as_mut().unwrap().approved_users = vec![];
                    assert_eq!(
                        with_approved_users_sorted(
                            &mut storage
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    true
                                )
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
        async fn test_get_call_link_and_record_with_call_with_epoch() -> Result<()> {
            test_get_call_link_and_record_with_call(Some(CallLinkEpoch::from(0))).await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_call_without_epoch() -> Result<()> {
            test_get_call_link_and_record_with_call(None).await
        }

        async fn test_get_call_link_and_record_with_call(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [
                    default_call_link_state_json(&room_id, epoch),
                    default_call_link_call_record_state(&room_id, "mesozoic"),
                ],
                [],
                async {
                    let expected = (
                        Some(CallLinkState {
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec![],
                        }),
                        Some(CallRecord {
                            room_id: RoomId::from(call_link_room_key_str(&room_id)),
                            era_id: "mesozoic".to_string(),
                            backend_ip: "127.0.0.1".to_string(),
                            backend_region: "pangaea".to_string(),
                            creator: "Peter".to_string(),
                        }),
                    );
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), epoch, false)
                            .await?,
                        &expected
                    );
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), epoch, true)
                            .await?,
                        &expected
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_call_and_approved_users_with_epoch(
        ) -> Result<()> {
            test_get_call_link_and_record_with_call_and_approved_users(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_get_call_link_and_record_with_call_and_approved_users_without_epoch(
        ) -> Result<()> {
            test_get_call_link_and_record_with_call_and_approved_users(None).await
        }

        async fn test_get_call_link_and_record_with_call_and_approved_users(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [
                    default_call_link_state_json_with(
                        &room_id,
                        epoch,
                        serde_json::json!({
                        "approvedUsers": {"SS": ["Moxie", "Brian", "Meredith"]},
                        }),
                    ),
                    default_call_link_call_record_state(&room_id, "mesozoic"),
                ],
                [],
                async {
                    let mut expected = (
                        Some(CallLinkState {
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec![
                                "Brian".to_string(),
                                "Meredith".to_string(),
                                "Moxie".to_string(),
                            ],
                        }),
                        Some(CallRecord {
                            room_id: RoomId::from(call_link_room_key_str(&room_id)),
                            era_id: "mesozoic".to_string(),
                            backend_ip: "127.0.0.1".to_string(),
                            backend_region: "pangaea".to_string(),
                            creator: "Peter".to_string(),
                        }),
                    );
                    assert_eq!(
                        with_approved_users_sorted(
                            &mut storage
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    false
                                )
                                .await?
                        ),
                        &expected
                    );
                    expected.0.as_mut().unwrap().approved_users = vec![];
                    assert_eq!(
                        with_approved_users_sorted(
                            &mut storage
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    true
                                )
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
        async fn test_get_call_link_and_record_non_call_link_call() -> Result<()> {
            let storage = bootstrap_storage().await?;
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
                    let expected = (None, None);
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), None, false)
                            .await?,
                        &expected
                    );
                    assert_eq!(
                        &storage
                            .get_call_link_and_record(&RoomId::from(room_id.clone()), None, true)
                            .await?,
                        &expected
                    );
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_update_call_link_approved_users() -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            let epoch = StaticCallLinkEpochGenerator::GENERATED_EPOCH;
            with_db_items(
                &storage,
                [default_call_link_state_json(&room_id, epoch)],
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
                            epoch,
                            admin_passkey: vec![1, 2, 3],
                            zkparams: vec![],
                            restrictions: CallLinkRestrictions::AdminApproval,
                            encrypted_name: b"abc".to_vec(),
                            revoked: false,
                            expiration: *TESTING_EXPIRATION,
                            delete_at: *TESTING_DELETE_AT,
                            approved_users: vec!["me".to_string()],
                        }),
                        None,
                    );
                    assert_eq!(
                        with_approved_users_sorted(
                            &mut storage
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    false
                                )
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
                                .get_call_link_and_record(
                                    &RoomId::from(room_id.clone()),
                                    epoch,
                                    false
                                )
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
        async fn test_create_call_link_with_epoch() -> Result<()> {
            let storage =
                bootstrap_storage_with_epoch_generator(Box::new(StaticCallLinkEpochGenerator))
                    .await?;
            let room_id = format!("testing-room-{}", line!());

            let update_result = storage
                .update_call_link(
                    &RoomId::from(room_id.clone()),
                    None,
                    CallLinkUpdate {
                        admin_passkey: vec![1, 2, 3],
                        restrictions: Some(CallLinkRestrictions::AdminApproval),
                        encrypted_name: Some(b"abc".to_vec()),
                        revoked: Some(false),
                    },
                    Some(vec![]),
                )
                .await?;

            let fetch_result = storage
                .get_call_link(
                    &RoomId::from(room_id.clone()),
                    StaticCallLinkEpochGenerator::GENERATED_EPOCH,
                )
                .await?;

            storage
                .delete_call_link(
                    &RoomId::from(room_id.clone()),
                    update_result.epoch,
                    &update_result.admin_passkey,
                )
                .await?;

            assert_eq!(fetch_result, Some(update_result));

            Ok(())
        }

        #[tokio::test]
        async fn test_create_call_link_without_epoch() -> Result<()> {
            let storage = bootstrap_storage_without_epoch_generator().await?;
            let room_id = format!("testing-room-{}", line!());

            let update_result = storage
                .update_call_link(
                    &RoomId::from(room_id.clone()),
                    None,
                    CallLinkUpdate {
                        admin_passkey: vec![1, 2, 3],
                        restrictions: Some(CallLinkRestrictions::AdminApproval),
                        encrypted_name: Some(b"abc".to_vec()),
                        revoked: Some(false),
                    },
                    Some(vec![]),
                )
                .await?;

            let fetch_result = storage
                .get_call_link(&RoomId::from(room_id.clone()), None)
                .await?;

            storage
                .delete_call_link(
                    &RoomId::from(room_id.clone()),
                    None,
                    &update_result.admin_passkey,
                )
                .await?;

            assert_eq!(fetch_result, Some(update_result));

            Ok(())
        }

        #[tokio::test]
        async fn test_update_call_link_with_epoch() -> Result<()> {
            // Test call link update with a valid epoch
            test_update_call_link(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_update_call_link_without_epoch() -> Result<()> {
            // Test call link update without an epoch
            test_update_call_link(None, None).await
        }

        #[tokio::test]
        async fn test_update_call_link_with_mismatched_epoch_1() -> Result<()> {
            // Test call link update failure; epoch does not exist in the DB, but is given as a
            // lookup parameter.
            test_update_call_link_failure(None, StaticCallLinkEpochGenerator::GENERATED_EPOCH).await
        }

        #[tokio::test]
        async fn test_update_call_link_with_mismatched_epoch_2() -> Result<()> {
            // Test call link update failure; epoch exists in the DB, but is not given as a lookup
            // parameter.
            test_update_call_link_failure(StaticCallLinkEpochGenerator::GENERATED_EPOCH, None).await
        }

        async fn test_update_call_link(
            epoch_at_creation: Option<CallLinkEpoch>,
            epoch_at_update: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [default_call_link_state_json(&room_id, epoch_at_creation)],
                [],
                async {
                    let call_link = storage
                        .update_call_link(
                            &RoomId::from(room_id.clone()),
                            epoch_at_update,
                            CallLinkUpdate {
                                admin_passkey: vec![1, 2, 3],
                                restrictions: Some(CallLinkRestrictions::AdminApproval),
                                encrypted_name: Some(b"abc".to_vec()),
                                revoked: Some(false),
                            },
                            None,
                        )
                        .await?;

                    let expected = CallLinkState {
                        epoch: epoch_at_creation,
                        admin_passkey: vec![1, 2, 3],
                        zkparams: vec![],
                        restrictions: CallLinkRestrictions::AdminApproval,
                        encrypted_name: b"abc".to_vec(),
                        revoked: false,
                        expiration: *TESTING_EXPIRATION,
                        delete_at: *TESTING_DELETE_AT,
                        approved_users: vec![],
                    };

                    assert_eq!(&call_link, &expected);

                    Ok(())
                },
            )
            .await
        }

        async fn test_update_call_link_failure(
            epoch_at_creation: Option<CallLinkEpoch>,
            epoch_at_update: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            with_db_items(
                &storage,
                [default_call_link_state_json(&room_id, epoch_at_creation)],
                [],
                async {
                    let result = storage
                        .update_call_link(
                            &RoomId::from(room_id.clone()),
                            epoch_at_update,
                            CallLinkUpdate {
                                admin_passkey: vec![1, 2, 3],
                                restrictions: Some(CallLinkRestrictions::AdminApproval),
                                encrypted_name: Some(b"abc".to_vec()),
                                revoked: Some(false),
                            },
                            None,
                        )
                        .await;

                    assert!(result.is_err());

                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_present_succeeds_with_epoch() -> Result<()> {
            // Delete call link with an epoch
            test_delete_call_link_present_succeeds(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_present_succeeds_without_epoch() -> Result<()> {
            // Delete call link without an epoch
            test_delete_call_link_present_succeeds(None, None).await
        }

        async fn test_delete_call_link_present_succeeds(
            epoch_at_creation: Option<CallLinkEpoch>,
            epoch_at_deletion: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id_raw = format!("testing-room-{}", line!());
            let room_id = RoomId::from(room_id_raw.clone());
            let admin_passkey = vec![1, 2, 3];
            with_db_items(
                &storage,
                [default_call_link_state_json(
                    &room_id_raw,
                    epoch_at_creation,
                )],
                [],
                async {
                    if let Err(err) = storage
                        .delete_call_link(&room_id, epoch_at_deletion, &admin_passkey)
                        .await
                    {
                        panic!("{:?}", err)
                    }

                    match storage.get_call_link(&room_id, epoch_at_creation).await? {
                        None => Ok(()),
                        _ => panic!("expected call link to be deleted"),
                    }
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_present_fails_epoch_mismatch_1() -> Result<()> {
            // Attempt and fail to delete a call link with an epoch without providing an epoch
            test_delete_call_link_present_fails(StaticCallLinkEpochGenerator::GENERATED_EPOCH, None)
                .await
        }

        #[tokio::test]
        async fn test_delete_call_link_present_fails_epoch_mismatch_2() -> Result<()> {
            // Attempt and fail to delete a call link without an epoch by providing an epoch
            test_delete_call_link_present_fails(None, StaticCallLinkEpochGenerator::GENERATED_EPOCH)
                .await
        }

        async fn test_delete_call_link_present_fails(
            epoch_at_creation: Option<CallLinkEpoch>,
            epoch_at_deletion: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id_raw = format!("testing-room-{}", line!());
            let room_id = RoomId::from(room_id_raw.clone());
            let admin_passkey = vec![1, 2, 3];
            with_db_items(
                &storage,
                [default_call_link_state_json(
                    &room_id_raw,
                    epoch_at_creation,
                )],
                [],
                async {
                    if storage
                        .delete_call_link(&room_id, epoch_at_deletion, &admin_passkey)
                        .await
                        .is_ok()
                    {
                        panic!("did not expect to be able to delete call link");
                    }
                    Ok(())
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_absent_fails_with_epoch() -> Result<()> {
            test_delete_call_link_absent_fails(StaticCallLinkEpochGenerator::GENERATED_EPOCH).await
        }

        #[tokio::test]
        async fn test_delete_call_link_absent_fails_without_epoch() -> Result<()> {
            test_delete_call_link_absent_fails(None).await
        }

        async fn test_delete_call_link_absent_fails(epoch: Option<CallLinkEpoch>) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            let admin_passkey = vec![1, 2, 3];
            match storage
                .delete_call_link(&RoomId::from(room_id), epoch, &admin_passkey)
                .await
            {
                Err(CallLinkDeleteError::RoomDoesNotExist) => Ok(()),
                Err(err) => panic!("{:?}", err),
                _ => panic!("expected RoomDoesNotExist error"),
            }
        }

        #[tokio::test]
        async fn test_delete_call_link_mismatched_admin_key_fails_with_epoch() -> Result<()> {
            test_delete_call_link_mismatched_admin_key_fails(
                StaticCallLinkEpochGenerator::GENERATED_EPOCH,
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_mismatched_admin_key_fails_without_epoch() -> Result<()> {
            test_delete_call_link_mismatched_admin_key_fails(None).await
        }

        async fn test_delete_call_link_mismatched_admin_key_fails(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            let admin_passkey = vec![1, 2, 4];
            with_db_items(
                &storage,
                [default_call_link_state_json(&room_id, epoch)],
                [],
                async {
                    match storage
                        .delete_call_link(&RoomId::from(room_id), epoch, &admin_passkey)
                        .await
                    {
                        Err(CallLinkDeleteError::AdminPasskeyDidNotMatch) => Ok(()),
                        Err(err) => panic!("{:?}", err),
                        _ => panic!("Expected AdminPasskeyDidNotMatch error"),
                    }
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_delete_call_link_active_call_fails_with_epoch() -> Result<()> {
            test_delete_call_link_active_call_fails(StaticCallLinkEpochGenerator::GENERATED_EPOCH)
                .await
        }

        #[tokio::test]
        async fn test_delete_call_link_active_call_fails_without_epoch() -> Result<()> {
            test_delete_call_link_active_call_fails(None).await
        }

        async fn test_delete_call_link_active_call_fails(
            epoch: Option<CallLinkEpoch>,
        ) -> Result<()> {
            let storage = bootstrap_storage().await?;
            let room_id = format!("testing-room-{}", line!());
            let era_id = format!("{:x}", line!());
            let admin_passkey = vec![1, 2, 3];
            with_db_items(
                &storage,
                [
                    default_call_link_state_json(&room_id, epoch),
                    default_call_link_call_record_state(&room_id, &era_id),
                ],
                [],
                async {
                    match storage
                        .delete_call_link(&RoomId::from(room_id), epoch, &admin_passkey)
                        .await
                    {
                        Err(CallLinkDeleteError::CallRecordConflict) => Ok(()),
                        Err(err) => panic!("{:?}", err),
                        _ => panic!("Expected CallRecordConflict error"),
                    }
                },
            )
            .await
        }

        #[tokio::test]
        async fn test_remove_batch_call_records_success() -> Result<()> {
            let storage = bootstrap_storage().await?;
            let call_keys = (0..10)
                .map(|i| CallRecordKey {
                    room_id: RoomId::from(format!("testing-room-{}-{}", line!(), i)),
                    era_id: format!("testing-era-id-{}-{}", line!(), i),
                })
                .collect::<Vec<_>>();
            let items = call_keys
                .iter()
                .map(|k| default_call_record_state(k.room_id.as_ref(), &k.era_id));

            let (delete, save) = call_keys.split_at(5);
            let save: HashSet<&RoomId> = save.iter().map(|k| &k.room_id).collect();

            with_db_items(&storage, items, [], async {
                storage.remove_batch_call_records(delete.to_vec()).await?;
                let remaining = storage.get_call_records_for_region("pangaea").await?;
                assert_eq!(remaining.len(), save.len());
                assert!(remaining.iter().all(|item| save.contains(&item.room_id)));
                Ok(())
            })
            .await
        }

        #[tokio::test]
        async fn test_remove_nonexistent_call_records_success() -> Result<()> {
            let storage = bootstrap_storage().await?;
            let call_keys = (0..10)
                .map(|i| CallRecordKey {
                    room_id: RoomId::from(format!("testing-room-{}-{}", line!(), i)),
                    era_id: format!("testing-era-id-{}-{}", line!(), i),
                })
                .collect::<Vec<_>>();
            let items = call_keys
                .iter()
                .map(|k| default_call_record_state(k.room_id.as_ref(), &k.era_id));

            let (delete, save) = call_keys.split_at(5);
            let save: HashSet<&RoomId> = save.iter().map(|k| &k.room_id).collect();

            with_db_items(&storage, items, [], async {
                storage.remove_batch_call_records(delete.to_vec()).await?;
                // call a second time to ensure removing nonexistent records doesn't fail
                storage.remove_batch_call_records(delete.to_vec()).await?;
                let remaining = storage.get_call_records_for_region("pangaea").await?;
                assert_eq!(remaining.len(), save.len());
                assert!(remaining.iter().all(|item| save.contains(&item.room_id)));
                Ok(())
            })
            .await
        }

        #[tokio::test]
        async fn test_remove_partial_nonexistent_call_records_fails() -> Result<()> {
            let storage = bootstrap_storage().await?;
            let call_keys = (0..10)
                .map(|i| CallRecordKey {
                    room_id: RoomId::from(format!("testing-room-{}-{}", line!(), i)),
                    era_id: format!("testing-era-id-{}-{}", line!(), i),
                })
                .collect::<Vec<_>>();
            let items = call_keys
                .iter()
                .map(|k| default_call_record_state(k.room_id.as_ref(), &k.era_id));

            let (delete, save) = call_keys.split_at(5);
            let save: HashSet<&RoomId> = save.iter().map(|k| &k.room_id).collect();

            with_db_items(&storage, items, [], async {
                storage.remove_batch_call_records(delete.to_vec()).await?;

                match storage
                    .remove_batch_call_records(call_keys.clone())
                    .await
                    .unwrap_err()
                {
                    StorageError::UnexpectedError(_) => {
                        let remaining = storage.get_call_records_for_region("pangaea").await?;
                        assert_eq!(remaining.len(), save.len());
                        assert!(remaining.iter().all(|item| save.contains(&item.room_id)));
                    }
                    _ => panic!("should have been unexpected error"),
                }

                Ok(())
            })
            .await
        }

        #[tokio::test]
        async fn test_remove_batch_call_records_limit_exceeded() -> Result<()> {
            let storage = bootstrap_storage().await?;
            let call_keys = (0..DynamoDb::TRANSACT_WRITE_ITEMS_LIMIT + 1)
                .map(|i| CallRecordKey {
                    room_id: RoomId::from(format!("testing-room-{}-{}", line!(), i)),
                    era_id: format!("testing-era-id-{}-{}", line!(), i),
                })
                .collect::<Vec<_>>();
            match storage
                .remove_batch_call_records(call_keys)
                .await
                .unwrap_err()
            {
                StorageError::BatchLimitExceeded { provided, limit } => {
                    assert_eq!(limit, DynamoDb::TRANSACT_WRITE_ITEMS_LIMIT);
                    assert_eq!(provided, DynamoDb::TRANSACT_WRITE_ITEMS_LIMIT + 1);
                }
                _ => panic!("unexpected error"),
            }
            Ok(())
        }
    }
}
