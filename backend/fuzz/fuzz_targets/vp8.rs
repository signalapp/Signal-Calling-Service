//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_backend::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vp8::ParsedHeader::read(data).ok();
});
