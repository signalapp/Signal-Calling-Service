//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_backend::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    _ = rtp::DependencyDescriptor::read(&data, None);
});

