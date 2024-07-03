//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub type PayloadType = u8;
pub type FullSequenceNumber = u64; // Really u48 due to limitations of SRTP
pub type TruncatedSequenceNumber = u16; // What actually goes in the packet
pub type FullTimestamp = u64;
pub type TruncatedTimestamp = u32;
pub type Ssrc = u32;
