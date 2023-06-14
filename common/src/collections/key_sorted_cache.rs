//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::BTreeMap;

/// A (Key, Value) cache, that keeps the largest keys (by Ord trait) up to the size limit specified
/// dropping the smallest key on insert if full.
pub struct KeySortedCache<K, V> {
    limit: usize,
    value_by_key: BTreeMap<K, V>,
}

impl<K: Ord, V> KeySortedCache<K, V> {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            value_by_key: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        self.value_by_key.insert(key, value);
        if self.value_by_key.len() > self.limit {
            self.value_by_key.pop_first();
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        self.value_by_key.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> + '_ {
        self.value_by_key.iter_mut()
    }

    pub fn remove(&mut self, key: &K) {
        self.value_by_key.remove(key);
    }

    pub fn is_empty(&self) -> bool {
        self.value_by_key.is_empty()
    }

    pub fn retain(&mut self, f: impl FnMut(&K, &mut V) -> bool) {
        self.value_by_key.retain(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_buffer() {
        let mut buffer = KeySortedCache::new(2);
        assert!(buffer.is_empty());
        buffer.insert(1, "A");
        assert!(!buffer.is_empty());
        buffer.insert(2, "B");
        assert!(!buffer.is_empty());

        assert_eq!(
            vec![(&1, &"A"), (&2, &"B")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn overfill_buffer() {
        let mut buffer = KeySortedCache::new(2);
        buffer.insert(1, "A");
        buffer.insert(2, "B");
        buffer.insert(3, "C");

        assert_eq!(
            vec![(&2, &"B"), (&3, &"C")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn overfill_buffer_with_lower_key() {
        let mut buffer = KeySortedCache::new(2);
        buffer.insert(2, "B");
        buffer.insert(3, "C");
        buffer.insert(1, "A");

        assert_eq!(
            vec![(&2, &"B"), (&3, &"C")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn overfill_buffer_with_middle_key() {
        let mut buffer = KeySortedCache::new(2);
        buffer.insert(1, "A");
        buffer.insert(3, "C");
        buffer.insert(2, "B");

        assert_eq!(
            vec![(&2, &"B"), (&3, &"C")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn replace_key() {
        let mut buffer = KeySortedCache::new(3);
        buffer.insert(1, "A");
        buffer.insert(2, "B");
        buffer.insert(1, "C");

        assert_eq!(
            vec![(&1, &"C"), (&2, &"B")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn replace_key_once_full() {
        let mut buffer = KeySortedCache::new(2);
        buffer.insert(1, "A");
        buffer.insert(2, "B");
        buffer.insert(1, "C");

        assert_eq!(
            vec![(&1, &"C"), (&2, &"B")],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn remove_key() {
        let mut buffer = KeySortedCache::new(3);
        buffer.insert(1, "A");
        buffer.insert(2, "B");
        buffer.remove(&1);

        assert_eq!(vec![(&2, &"B")], buffer.iter().collect::<Vec<_>>());
    }

    #[test]
    fn iter_mut_update_value() {
        let mut buffer = KeySortedCache::new(3);
        buffer.insert(1, "A".to_string());
        buffer.insert(2, "B".to_string());
        buffer.insert(3, "C".to_string());

        for (_k, v) in buffer.iter_mut() {
            *v = format!("{}x{}", v, v);
        }

        assert_eq!(
            vec![
                (&1, &"AxA".to_string()),
                (&2, &"BxB".to_string()),
                (&3, &"CxC".to_string())
            ],
            buffer.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn retain() {
        let mut buffer = KeySortedCache::new(4);
        buffer.insert(1, "A");
        buffer.insert(2, "B");
        buffer.insert(3, "C");
        buffer.insert(4, "D");
        buffer.retain(|key, _value| *key > 2);

        assert_eq!(
            vec![(&3, &"C"), (&4, &"D")],
            buffer.iter().collect::<Vec<_>>()
        );
    }
}
