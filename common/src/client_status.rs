//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

#[derive(PartialEq, Eq, Debug)]
pub enum ClientStatus {
    Active,
    Pending,
    Blocked,
}

impl fmt::Display for ClientStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClientStatus::Active => "ACTIVE",
            ClientStatus::Pending => "PENDING",
            ClientStatus::Blocked => "BLOCKED",
        })
    }
}
