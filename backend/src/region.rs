//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Enum of valid regions; used to constrain logging to known strings.

use strum_macros::{Display, EnumString};

#[derive(EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum Region {
    Unset,
    Unknown,
    AsiaEast1,
    AsiaEast2,
    AsiaNortheast1,
    AsiaNortheast3,
    AsiaSouth1,
    AsiaSoutheast1,
    AsiaSoutheast2,
    AustralianSoutheast2,
    EuropeNorth1,
    EuropeWest1,
    EuropeWest2,
    EuropeWest3,
    EuropeWest4,
    EuropeWest6,
    NorthamericaNortheast1,
    SouthamericaEast1,
    UsCentral1,
    UsEast1,
    UsEast4,
    UsWest1,
    UsWest2,
    UsWest3,
    UsWest4,
}
