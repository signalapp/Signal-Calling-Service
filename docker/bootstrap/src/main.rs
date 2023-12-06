//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use aws_sdk_dynamodb::{
    config::Region,
    operation::create_table::builders::CreateTableFluentBuilder,
    types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ProvisionedThroughput, ScalarAttributeType,
    },
    Client, Error,
};

async fn build_table(
    client: &Client,
    table_name: &str,
    describe_table: impl FnOnce(CreateTableFluentBuilder) -> CreateTableFluentBuilder,
) -> Result<(), Error> {
    println!("Attempting to create table {}; please wait...", table_name);

    let create_table_response = describe_table(client.create_table().table_name(table_name))
        .send()
        .await;

    match create_table_response {
        Ok(_) => {
            eprintln!("  Added table {}!", table_name);
            Ok(())
        }
        Err(err) => {
            eprintln!("  Error: {}", err);
            Err(err.into())
        }
    }
}

#[tokio::main]
#[allow(clippy::result_large_err)]
async fn main() -> Result<(), Error> {
    // Be sure that AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are defined in the environment.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::v2023_11_09())
        .endpoint_url("http://dynamodb:8000")
        .region(Region::new("us-west-1"))
        .load()
        .await;

    let client = Client::new(&sdk_config);

    // Poll for DynamoDb to be ready, fail after 10 seconds.
    const MAX_ATTEMPTS: u32 = 20;
    for attempt in 1..=MAX_ATTEMPTS {
        match client.list_tables().send().await {
            Err(..) if attempt == MAX_ATTEMPTS => {
                eprintln!("Poll {}: DynamoDB is not ready, failing...", attempt);
                std::process::exit(1);
            }
            Err(err) => {
                println!("Poll {}: DynamoDB is not ready: {}", attempt, err);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Ok(_) => {
                println!("Poll {}: DynamoDB is ready!", attempt);
                break;
            }
        }
    }

    let provisional_throughput = ProvisionedThroughput::builder()
        .read_capacity_units(5)
        .write_capacity_units(1)
        .build()?;

    let attribute_definition_id = AttributeDefinition::builder()
        .attribute_name("roomId")
        .attribute_type(ScalarAttributeType::S)
        .build()?;

    let attribute_definition_record_type = AttributeDefinition::builder()
        .attribute_name("recordType")
        .attribute_type(ScalarAttributeType::S)
        .build()?;

    let attribute_definition_region = AttributeDefinition::builder()
        .attribute_name("region")
        .attribute_type(ScalarAttributeType::S)
        .build()?;

    let partition_key = KeySchemaElement::builder()
        .attribute_name("roomId")
        .key_type(KeyType::Hash)
        .build()?;

    let sort_key = KeySchemaElement::builder()
        .attribute_name("recordType")
        .key_type(KeyType::Range)
        .build()?;

    let global_secondary_index = GlobalSecondaryIndex::builder()
        .index_name("region-index")
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(10)
                .write_capacity_units(1)
                .build()?,
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("region")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("recordType")
                .key_type(KeyType::Range)
                .build()?,
        )
        .build()?;

    build_table(&client, "Rooms", |table| {
        table
            .provisioned_throughput(provisional_throughput)
            .attribute_definitions(attribute_definition_id)
            .attribute_definitions(attribute_definition_record_type)
            .attribute_definitions(attribute_definition_region)
            .key_schema(partition_key)
            .key_schema(sort_key)
            .global_secondary_indexes(global_secondary_index)
    })
    .await?;

    Ok(())
}
