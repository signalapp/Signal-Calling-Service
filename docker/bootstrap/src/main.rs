//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use aws_sdk_dynamodb::model::{
    AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType, ProvisionedThroughput, ScalarAttributeType,
};
use aws_sdk_dynamodb::{Client, Endpoint, Error, Region};
use http::Uri;

#[tokio::main]
async fn main() -> Result<(), Error> {
    println!("Attempting to create table; please wait...");

    let table_name = "Conferences";

    // Be sure that AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are defined in the environment.
    let sdk_config = aws_config::from_env()
        .endpoint_resolver(Endpoint::immutable(Uri::from_static(
            "http://dynamodb:8000",
        )))
        .region(Region::new("us-west-1"))
        .load()
        .await;

    let client = Client::new(&sdk_config);

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

    let create_table_response = client
        .create_table()
        .table_name(table_name)
        .provisioned_throughput(provisional_throughput)
        .attribute_definitions(attribute_definition_id)
        .attribute_definitions(attribute_definition_region)
        .key_schema(key_schema_element)
        .global_secondary_indexes(global_secondary_index)
        .send()
        .await;

    match create_table_response {
        Ok(_) => {
            println!("  Added table {}!", table_name);
            Ok(())
        }
        Err(err) => {
            eprintln!("  Error: {}", err);
            Err(Error::Unhandled(Box::new(err)))
        }
    }
}
