//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    let protos = ["protobuf/group_call.proto"];
    prost_build::compile_protos(&protos, &["protobuf"]).expect("Protobufs are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
