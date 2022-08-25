//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_dynamodb::{
    model::{AttributeValue, Select},
    types::SdkError,
    Client, Config, Endpoint,
};
use aws_smithy_types::retry::RetryConfigBuilder;
use aws_types::{region::Region, Credentials};
use http::Uri;
use log::*;
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_item, to_item};

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::{
    config,
    frontend::{GroupId, UserId},
};

const GROUP_CONFERENCE_ID_STRING: &str = "groupConferenceId";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CallRecord {
    /// The group_id that the client is authorized to join and provided to the frontend
    /// by the client.
    #[serde(rename = "groupConferenceId")]
    pub group_id: GroupId,
    /// The call_id is a random id generated and sent back to the client to let it know
    /// about the specific instance of the group_id (aka era).
    #[serde(rename = "jvbConferenceId")]
    pub call_id: String,
    /// The IP of the backend Calling Server that hosts the call.
    #[serde(rename = "jvbHost")]
    pub backend_ip: String,
    /// The region of the backend Calling Server that hosts the call.
    #[serde(rename = "region")]
    pub backend_region: String,
    /// The user_id of the user that created the call.
    pub creator: UserId,
}

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Storage: Sync + Send {
    /// Gets an existing call from the table matching the given group_id or returns None.
    async fn get_call_record(&self, group_id: &GroupId)
        -> Result<Option<CallRecord>, StorageError>;
    /// Adds the given call to the table but if there is already a call with the same
    /// group_id, returns that instead.
    async fn get_or_add_call_record(
        &self,
        call: CallRecord,
    ) -> Result<Option<CallRecord>, StorageError>;
    /// Removes the given call from the table as long as the call_id of the record that
    /// exists in the table is the same.
    async fn remove_call_record(
        &self,
        group_id: &GroupId,
        call_id: &str,
    ) -> Result<(), StorageError>;
    /// Returns a list of all calls in the table that are in the given region.
    async fn get_call_records_for_region(
        &self,
        region: &str,
    ) -> Result<Vec<CallRecord>, StorageError>;
}

pub struct DynamoDb {
    client: Client,
    table_name: String,
}

impl DynamoDb {
    pub async fn new(config: &'static config::Config) -> Self {
        let client = match &config.storage_endpoint {
            None => {
                info!(
                    "Using region for DynamodDB access: {}",
                    config.storage_region.as_str()
                );

                let retry_config = RetryConfigBuilder::new()
                    .max_attempts(4)
                    .initial_backoff(std::time::Duration::from_millis(100))
                    .build();

                let aws_config = Config::builder()
                    .credentials_provider(Credentials::from_keys(
                        &config.storage_key,
                        &config.storage_password,
                        None,
                    ))
                    .retry_config(retry_config)
                    .region(Region::new(&config.storage_region))
                    .build();
                Client::from_conf(aws_config)
            }
            Some(endpoint) => {
                info!("Using endpoint for DynamodDB testing: {}", endpoint);
                let aws_config = Config::builder()
                    .credentials_provider(Credentials::from_keys(
                        &config.storage_key,
                        &config.storage_password,
                        None,
                    ))
                    .endpoint_resolver(Endpoint::immutable(Uri::from_static(endpoint)))
                    .region(Region::new(&config.storage_region))
                    .build();
                Client::from_conf(aws_config)
            }
        };

        Self {
            client,
            table_name: config.storage_table.to_string(),
        }
    }
}

#[async_trait]
impl Storage for DynamoDb {
    async fn get_call_record(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<CallRecord>, StorageError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(
                GROUP_CONFERENCE_ID_STRING,
                AttributeValue::S(group_id.as_ref().to_string()),
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

    async fn get_or_add_call_record(
        &self,
        call: CallRecord,
    ) -> Result<Option<CallRecord>, StorageError> {
        let response = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(
                to_item(&call).context("failed to convert CallRecord to item")?,
            ))
            // Don't overwrite the item if it already exists.
            .condition_expression("attribute_not_exists(groupConferenceId)".to_string())
            .send()
            .await;

        match response {
            Ok(_) => Ok(Some(call)),
            Err(SdkError::ServiceError { err: e, raw: _ })
                if e.is_conditional_check_failed_exception() =>
            {
                // TODO: This log replicates behavior of the old server, remove if not useful.
                info!("Conditional check failed, call now already exists");
                Ok(self
                    .get_call_record(&call.group_id)
                    .await
                    .context("failed to get call from storage after conditional check failed")?)
            }
            Err(err) => Err(StorageError::UnexpectedError(
                anyhow::Error::from(err)
                    .context("failed to put_item to storage for get_or_add_call_record"),
            )),
        }
    }

    async fn remove_call_record(
        &self,
        group_id: &GroupId,
        call_id: &str,
    ) -> Result<(), StorageError> {
        let response = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            // Delete the item for the given key.
            .key(
                GROUP_CONFERENCE_ID_STRING,
                AttributeValue::S(group_id.as_ref().to_string()),
            )
            // But only if the given call_id matches the expected value, otherwise the
            // previous call was removed and a new one created already.
            .condition_expression("jvbConferenceId = :value".to_string())
            .expression_attribute_values(
                ":value".to_string(),
                AttributeValue::S(call_id.to_string()),
            )
            .send()
            .await;

        match response {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError { err: e, raw: _ })
                if e.is_conditional_check_failed_exception() =>
            {
                // TODO: This log replicates behavior of the old server, remove if not useful.
                info!("Item already removed or replaced: {:.6}", call_id);
                Ok(())
            }
            Err(err) => Err(StorageError::UnexpectedError(err.into())),
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
            .key_condition_expression("#region = :value".to_string())
            .expression_attribute_names("#region".to_string(), "region".to_string())
            .expression_attribute_values(
                ":value".to_string(),
                AttributeValue::S(region.to_string()),
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
}
