//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_common::try_scoped;
use calling_backend::ice::BindingRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    let _ = try_scoped(|| {
        if let Some(request) = BindingRequest::try_from_buffer(&data)? {
            request.verify_integrity(&[0u8; 20])?;
        }
        Ok(())
    });
});
