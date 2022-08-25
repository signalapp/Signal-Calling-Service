//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use calling_common::try_scoped;
use calling_backend::{
    ice::{BindingRequest, VerifiedBindingRequest},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    let _ = try_scoped(|| {
        if BindingRequest::looks_like_header(&data) {
            let ice_binding_request = BindingRequest::parse(&data)?;
            let ice_request_username = ice_binding_request.username();
            let pwd = &[0u8; 20];

            let _ = ice_binding_request.verify_hmac(pwd);

            VerifiedBindingRequest::new_for_fuzzing(&ice_binding_request)
                .to_binding_response(ice_request_username, pwd);
        }

        Ok(())
    });
});
