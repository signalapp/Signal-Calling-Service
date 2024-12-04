//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg(test)]

use std::fmt::Debug;

use crate::histogram::Histogram;

/// Compares the contents of a hash map with an expected vector of Key-Value pairs.
pub fn assert_map_eq<K, V>(actual: impl Iterator<Item = (K, V)>, mut expected: Vec<(K, V)>)
where
    K: Ord + PartialEq + Debug + Copy,
    V: PartialEq + Debug + Copy,
{
    let mut actual: Vec<(K, V)> = actual.into_iter().collect::<Vec<_>>();
    actual.sort_unstable_by(|(k1, _), (k2, _)| k1.cmp(k2));
    expected.sort_unstable_by(|(k1, _), (k2, _)| k1.cmp(k2));
    assert_eq!(actual, expected);
}

pub fn assert_histogram_eq<K>(histogram: &Histogram<K>, expected: Vec<(K, usize)>)
where
    K: Ord + PartialEq + Debug + Copy,
{
    assert_map_eq(histogram.iter().map(|(k, v)| (*k, *v)), expected)
}
