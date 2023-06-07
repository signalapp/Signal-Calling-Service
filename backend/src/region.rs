//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Enum of valid regions; used to constrain logging to known strings.

use strum_macros::{Display, EnumString};

#[derive(EnumString, Display, PartialEq)]
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

// Google sometimes calls this "location"
#[derive(PartialEq)]
enum GlobalArea {
    AsiaPacific,
    Europe,
    NorthAmerica,
    SouthAmerica,
}

impl Region {
    fn area(&self) -> Option<GlobalArea> {
        match self {
            Region::AsiaEast1
            | Region::AsiaEast2
            | Region::AsiaNortheast1
            | Region::AsiaNortheast3
            | Region::AsiaSouth1
            | Region::AsiaSoutheast1
            | Region::AsiaSoutheast2
            | Region::AustralianSoutheast2 => Some(GlobalArea::AsiaPacific),
            Region::EuropeNorth1
            | Region::EuropeWest1
            | Region::EuropeWest2
            | Region::EuropeWest3
            | Region::EuropeWest4
            | Region::EuropeWest6 => Some(GlobalArea::Europe),
            Region::NorthamericaNortheast1
            | Region::UsCentral1
            | Region::UsEast1
            | Region::UsEast4
            | Region::UsWest1
            | Region::UsWest2
            | Region::UsWest3
            | Region::UsWest4 => Some(GlobalArea::NorthAmerica),
            Region::SouthamericaEast1 => Some(GlobalArea::SouthAmerica),
            Region::Unset | Region::Unknown => None,
        }
    }
    pub fn same_area(&self, other: &Region) -> bool {
        let myarea = self.area();
        myarea.is_some() && myarea == other.area()
    }
}
