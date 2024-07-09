//
// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub type PayloadType = u8;
pub type FullSequenceNumber = u64; // Really u48 due to limitations of SRTP
pub type TruncatedSequenceNumber = u16; // What actually goes in the packet
pub type FullTimestamp = u64;
pub type TruncatedTimestamp = u32;
// We'll treat this as a u64 for simplicity even though it's an i64 in WebRTC.
// u64 is good enough because we won't get near to 2^63 (30 fps with one number
// per layer = 90 numbers used per second, and this starts at 1).
pub type FullFrameNumber = u64;
pub type TruncatedFrameNumber = u16;
pub type Ssrc = u32;
