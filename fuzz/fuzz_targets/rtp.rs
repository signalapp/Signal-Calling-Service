//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_server::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    if rtp::looks_like_rtp(&data) {
        let _ = rtp::parse_and_forward_rtp_for_fuzzing(data);
    }
});
