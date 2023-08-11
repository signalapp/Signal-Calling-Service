//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

/// A wrapper around a u32 with the 4 LSBs set to 0.
/// Uniquely identifies a client within a call (scoped to the call era).
#[derive(Clone, Debug, Eq, PartialEq, Copy, Hash, PartialOrd, Ord)]
pub struct DemuxId(u32);

impl DemuxId {
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// For testing
    pub const fn from_const(raw: u32) -> Self {
        assert!(raw & 0b1111 == 0, "lowest 4 bits must be clear");
        Self(raw)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid demux ID: {0} ({0:#x})")]
pub struct InvalidDemuxIdError(u32);

impl TryFrom<u32> for DemuxId {
    type Error = InvalidDemuxIdError;
    fn try_from(demux_id: u32) -> Result<Self, InvalidDemuxIdError> {
        if demux_id & 0b1111 == 0 {
            Ok(Self(demux_id))
        } else {
            Err(InvalidDemuxIdError(demux_id))
        }
    }
}

pub const DUMMY_DEMUX_ID: DemuxId = DemuxId(0);

impl From<DemuxId> for u32 {
    fn from(demux_id: DemuxId) -> u32 {
        demux_id.0
    }
}
