//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::{Method, StatusCode};
use std::marker::PhantomData;

pub struct KnownTags<T> {
    phantom: PhantomData<T>,
}

impl KnownTags<StatusCode> {
    pub fn tag_from(value: &StatusCode) -> String {
        format!("http_status:{}", value.as_str())
    }
}

impl KnownTags<Method> {
    pub fn tag_from(value: &Method) -> String {
        format!("http_method:{}", value.as_str())
    }
}
