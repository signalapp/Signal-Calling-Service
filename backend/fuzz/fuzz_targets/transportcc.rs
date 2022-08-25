//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_backend::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], transportcc::FullSequenceNumber)| {
    let data = input.0;
    let mut seqnum = input.1;
    // Assume we never get close to the max seqnum
    if seqnum > u64::MAX - u32::MAX as u64 {
        return
    }
    let _ = transportcc::read_feedback(data, &mut seqnum);
});
