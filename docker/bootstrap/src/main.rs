//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use aws_sdk_dynamodb::{
    client::fluent_builders::CreateTable,
    model::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ProvisionedThroughput, ScalarAttributeType,
    },
    Client, Error, Region,
};

async fn build_table(
    client: &Client,
    table_name: &str,
    describe_table: impl FnOnce(CreateTable) -> CreateTable,
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
async fn main() -> Result<(), Error> {
    // Be sure that AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are defined in the environment.
    let sdk_config = aws_config::from_env()
        .endpoint_url("http://dynamodb:8000")
        .region(Region::new("us-west-1"))
        .load()
        .await;

    let client = Client::new(&sdk_config);

    build_table(&client, "Conferences", |table| {
        let provisional_throughput = ProvisionedThroughput::builder()
            .read_capacity_units(5)
            .write_capacity_units(1)
            .build();

        let attribute_definition_id = AttributeDefinition::builder()
            .attribute_name("groupConferenceId")
            .attribute_type(ScalarAttributeType::S)
            .build();

        let attribute_definition_region = AttributeDefinition::builder()
            .attribute_name("region")
            .attribute_type(ScalarAttributeType::S)
            .build();

        let key_schema_element = KeySchemaElement::builder()
            .attribute_name("groupConferenceId")
            .key_type(KeyType::Hash)
            .build();

        let global_secondary_index = GlobalSecondaryIndex::builder()
            .index_name("region-index")
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .read_capacity_units(10)
                    .write_capacity_units(1)
                    .build(),
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
                    .build(),
            )
            .build();

        table
            .provisioned_throughput(provisional_throughput)
            .attribute_definitions(attribute_definition_id)
            .attribute_definitions(attribute_definition_region)
            .key_schema(key_schema_element)
            .global_secondary_indexes(global_secondary_index)
    })
    .await?;

    build_table(&client, "Rooms", |table| {
        let provisional_throughput = ProvisionedThroughput::builder()
            .read_capacity_units(5)
            .write_capacity_units(1)
            .build();

        let attribute_definition_id = AttributeDefinition::builder()
            .attribute_name("roomId")
            .attribute_type(ScalarAttributeType::S)
            .build();

        let attribute_definition_record_type = AttributeDefinition::builder()
            .attribute_name("recordType")
            .attribute_type(ScalarAttributeType::S)
            .build();

        let attribute_definition_region = AttributeDefinition::builder()
            .attribute_name("region")
            .attribute_type(ScalarAttributeType::S)
            .build();

        let partition_key = KeySchemaElement::builder()
            .attribute_name("roomId")
            .key_type(KeyType::Hash)
            .build();

        let sort_key = KeySchemaElement::builder()
            .attribute_name("recordType")
            .key_type(KeyType::Range)
            .build();

        let global_secondary_index = GlobalSecondaryIndex::builder()
            .index_name("region-index")
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .read_capacity_units(10)
                    .write_capacity_units(1)
                    .build(),
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
                    .build(),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("recordType")
                    .key_type(KeyType::Range)
                    .build(),
            )
            .build();

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
