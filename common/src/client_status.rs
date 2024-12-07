//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

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

#[derive(EnumIter, Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalUserAgent {
    Ios,
    Android,
    DesktopMac,
    DesktopWindows,
    DesktopLinux,
    DesktopUnknown,
    Internal,
    Unknown,
}

impl SignalUserAgent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
            Self::DesktopMac => "desktop_mac",
            Self::DesktopWindows => "desktop_windows",
            Self::DesktopLinux => "desktop_linux",
            Self::DesktopUnknown => "desktop_unknown",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }

    pub const fn as_tag(&self) -> &'static str {
        match self {
            SignalUserAgent::Ios => "user-agent:signal-ios",
            SignalUserAgent::Android => "user-agent:signal-android",
            SignalUserAgent::DesktopMac => "user-agent:signal-desktop-mac",
            SignalUserAgent::DesktopWindows => "user-agent:signal-desktop-windows",
            SignalUserAgent::DesktopLinux => "user-agent:signal-desktop-linux",
            SignalUserAgent::DesktopUnknown => "user-agent:signal-desktop-unknown",
            SignalUserAgent::Internal => "user-agent:signal-internal",
            SignalUserAgent::Unknown => "user-agent:unknown",
        }
    }
}

impl From<String> for SignalUserAgent {
    fn from(value: String) -> Self {
        value.as_str().into()
    }
}

impl From<&str> for SignalUserAgent {
    fn from(value: &str) -> Self {
        let value = value.to_lowercase();

        if value.starts_with("signal-ios") {
            Self::Ios
        } else if value.starts_with("signal-android") {
            Self::Android
        } else if value.starts_with("signal-desktop") {
            if value.contains("macos") {
                Self::DesktopMac
            } else if value.contains("windows") {
                Self::DesktopWindows
            } else if value.contains("linux") {
                Self::DesktopLinux
            } else {
                Self::DesktopUnknown
            }
        } else if value.starts_with("signal-internal") {
            Self::Internal
        } else {
            Self::Unknown
        }
    }
}
