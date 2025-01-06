//
// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Enum of valid regions; used to constrain logging to known strings.

use strum_macros::{Display, EnumIter, EnumString};

#[derive(EnumString, Clone, Copy, Display, PartialEq)]
#[strum(serialize_all = "kebab-case")]
pub enum Region {
    Unset,
    Unknown,
    AfricaSouth1,
    AsiaEast1,
    AsiaEast2,
    AsiaNortheast1,
    AsiaNortheast2,
    AsiaNortheast3,
    AsiaSouth1,
    AsiaSouth2,
    AsiaSoutheast1,
    AsiaSoutheast2,
    AustraliaSoutheast1,
    AustraliaSoutheast2,
    EuropeCentral2,
    EuropeNorth1,
    EuropeSouthwest1,
    EuropeWest1,
    EuropeWest2,
    EuropeWest3,
    EuropeWest4,
    EuropeWest6,
    EuropeWest8,
    EuropeWest9,
    EuropeWest12,
    MeCentral1,
    MeCentral2,
    MeWest1,
    NorthamericaNortheast1,
    NorthamericaNortheast2,
    NorthamericaSouth1,
    SouthamericaEast1,
    SouthamericaWest1,
    UsCentral1,
    UsEast1,
    UsEast4,
    UsSouth1,
    UsWest1,
    UsWest2,
    UsWest3,
    UsWest4,
}

// Google sometimes calls this "location"
#[derive(PartialEq)]
enum GlobalArea {
    Africa,
    AsiaPacific,
    Australia, // GCP considers Australia part of AsiaPacific
    Europe,
    NorthAmerica, // GCP considers NorthAmerica part of Americas
    MiddleEast,
    SouthAmerica, // GCP considers SouthAmerica part of Americas
}

impl Region {
    fn area(&self) -> Option<GlobalArea> {
        match self {
            Region::AfricaSouth1 => Some(GlobalArea::Africa),
            Region::AsiaEast1
            | Region::AsiaEast2
            | Region::AsiaNortheast1
            | Region::AsiaNortheast2
            | Region::AsiaNortheast3
            | Region::AsiaSouth1
            | Region::AsiaSouth2
            | Region::AsiaSoutheast1
            | Region::AsiaSoutheast2 => Some(GlobalArea::AsiaPacific),
            Region::AustraliaSoutheast1 | Region::AustraliaSoutheast2 => {
                Some(GlobalArea::Australia)
            }
            Region::EuropeCentral2
            | Region::EuropeNorth1
            | Region::EuropeSouthwest1
            | Region::EuropeWest1
            | Region::EuropeWest2
            | Region::EuropeWest3
            | Region::EuropeWest4
            | Region::EuropeWest6
            | Region::EuropeWest8
            | Region::EuropeWest9
            | Region::EuropeWest12 => Some(GlobalArea::Europe),
            Region::MeCentral1 | Region::MeCentral2 | Region::MeWest1 => {
                Some(GlobalArea::MiddleEast)
            }
            Region::NorthamericaNortheast1
            | Region::NorthamericaNortheast2
            | Region::NorthamericaSouth1
            | Region::UsCentral1
            | Region::UsEast1
            | Region::UsEast4
            | Region::UsSouth1
            | Region::UsWest1
            | Region::UsWest2
            | Region::UsWest3
            | Region::UsWest4 => Some(GlobalArea::NorthAmerica),
            Region::SouthamericaEast1 | Region::SouthamericaWest1 => Some(GlobalArea::SouthAmerica),
            Region::Unset | Region::Unknown => None,
        }
    }
    pub fn same_area(&self, other: &Region) -> bool {
        let myarea = self.area();
        myarea.is_some() && myarea == other.area()
    }
}

#[derive(EnumString, EnumIter, Clone, Copy, Display, Eq, PartialEq, Hash)]
pub enum RegionRelation {
    Unknown,
    SameRegion,
    SameArea,
    DifferentArea,
}

impl RegionRelation {
    // Use &str to avoid strings or iteration code to take references to Strings
    pub const fn as_tag(&self) -> &'static str {
        match self {
            RegionRelation::Unknown => "region-relation:unknown",
            RegionRelation::SameRegion => "region-relation:same_region",
            RegionRelation::SameArea => "region-relation:same_area",
            RegionRelation::DifferentArea => "region-relation:different_area",
        }
    }
}
