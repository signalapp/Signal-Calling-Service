//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{collections::HashMap, hash::Hash, iter::FromIterator};

pub struct Histogram<T> {
    counts_by_value: HashMap<T, usize>,
}

impl<T> Histogram<T> {
    pub fn push_n(&mut self, value: T, n: usize)
    where
        T: Hash + Eq + Copy,
    {
        if n == 0 {
            return;
        }
        let count = self.counts_by_value.entry(value).or_insert(0);
        *count += n;
    }

    pub fn push(&mut self, value: T)
    where
        T: Hash + Eq + Copy,
    {
        self.push_n(value, 1)
    }

    pub fn push_all(&mut self, values: impl IntoIterator<Item = T>)
    where
        T: Hash + Eq + Copy,
    {
        for a in values {
            self.push(a);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.counts_by_value.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&T, &usize)> {
        self.counts_by_value.iter()
    }
}

impl<T> Default for Histogram<T> {
    fn default() -> Self {
        Histogram {
            counts_by_value: HashMap::new(),
        }
    }
}

impl<A: Hash + Eq + Copy> FromIterator<A> for Histogram<A> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let mut histogram = Histogram::default();
        histogram.push_all(iter);
        histogram
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::test_utils::assert_histogram_eq;

    #[test]
    fn collect_i32_values_into_histogram() {
        let items = vec![1, 2, 3];

        let histogram = items.into_iter().collect::<Histogram<_>>();

        assert_histogram_eq(&histogram, vec![(1, 1), (2, 1), (3, 1)]);
    }

    #[test]
    fn collect_u128_values_into_histogram() {
        let items = vec![1u128, 100u128, 100u128, 100u128];

        let histogram = items.into_iter().collect::<Histogram<_>>();

        assert_histogram_eq(&histogram, vec![(1u128, 1), (100u128, 3)]);
    }

    #[test]
    fn new_histogram() {
        let histogram: Histogram<u32> = Histogram::default();

        assert_histogram_eq(&histogram, vec![]);
    }

    #[test]
    fn push_single_value_to_histogram() {
        let mut histogram = Histogram::default();

        histogram.push(100);

        assert_histogram_eq(&histogram, vec![(100, 1)]);
    }

    #[test]
    fn push_two_values_to_histogram() {
        let mut histogram = Histogram::default();

        histogram.push(20);
        histogram.push(20);

        assert_histogram_eq(&histogram, vec![(20, 2)]);
    }

    #[test]
    fn push_n_values_to_histogram() {
        let mut histogram = Histogram::default();

        histogram.push_n(20, 5);

        assert_histogram_eq(&histogram, vec![(20, 5)]);
    }

    #[test]
    fn push_0_values_to_histogram() {
        let mut histogram = Histogram::default();

        histogram.push_n(20, 0);

        assert_histogram_eq(&histogram, vec![]);
    }

    #[test]
    fn push_all_to_histogram() {
        let mut histogram: Histogram<i32> = Histogram::default();

        histogram.push_all(vec![100, 100, 200]);

        assert_histogram_eq(&histogram, vec![(100, 2), (200, 1)]);
    }

    #[test]
    fn push_and_push_all_histogram() {
        let mut histogram = Histogram::default();

        histogram.push(50);
        histogram.push_all(vec![100, 100, 200, 50]);
        histogram.push(50);

        assert_histogram_eq(&histogram, vec![(50, 3), (100, 2), (200, 1)]);
    }
}
