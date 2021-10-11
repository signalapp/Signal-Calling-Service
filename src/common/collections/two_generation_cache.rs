//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{borrow::Borrow, collections::HashMap, hash::Hash, mem};

use crate::common::{Duration, Instant};

/// A cache that keeps values for at least the specified generation lifetime, and at most around 2x
/// generation lifetime assuming regular invocations of [insert]. Note ejections are only done
/// on [insert] so it is possible that an entry can be returned after 2x generation_lifetime has
/// passed.
///
/// Users should consider the implications of dropping potentially large numbers of items at once.
///
/// [insert]: TwoGenerationCache::insert
pub struct TwoGenerationCache<K, V>(TwoGenerationCacheWithManualRemoveOld<K, V>)
where
    K: Hash + Eq;

impl<K, V> TwoGenerationCache<K, V>
where
    K: Hash + Eq,
{
    pub fn new(generation_lifetime: Duration, now: Instant) -> Self {
        Self(TwoGenerationCacheWithManualRemoveOld::new(
            generation_lifetime,
            now,
        ))
    }

    pub fn insert(&mut self, key: K, value: V, now: Instant) {
        self.0.swap_generations_if_its_been_too_long(now);
        self.0.insert_without_removing_old(key, value);
    }

    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.get(key)
    }

    pub fn remove<Q: ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.remove(key)
    }

    #[cfg(test)]
    pub fn generation0_len(&self) -> usize {
        self.0.generation0.len()
    }

    #[cfg(test)]
    pub fn generation1_len(&self) -> usize {
        self.0.generation1.len()
    }
}

pub struct TwoGenerationCacheWithManualRemoveOld<K, V>
where
    K: Hash + Eq,
{
    generation_lifetime: Duration,
    generation0: HashMap<K, V>,
    generation1: HashMap<K, V>,
    generation1_expires: Instant,
}

impl<K, V> TwoGenerationCacheWithManualRemoveOld<K, V>
where
    K: Hash + Eq,
{
    pub fn new(generation_lifetime: Duration, now: Instant) -> Self {
        Self {
            generation_lifetime,
            generation0: Default::default(),
            generation1: Default::default(),
            generation1_expires: now + generation_lifetime,
        }
    }

    pub fn insert_without_removing_old(&mut self, key: K, value: V) {
        self.generation0.insert(key, value);
    }

    pub fn remove_old(&mut self, now: Instant) -> Vec<K> {
        if let Some(mut removed_gen) = self.swap_generations_if_its_been_too_long(now) {
            removed_gen
                .drain()
                .map(|(k, _v)| k)
                .filter(|k| !self.generation1.contains_key(k))
                .collect()
        } else {
            vec![]
        }
    }

    fn swap_generations_if_its_been_too_long(&mut self, now: Instant) -> Option<HashMap<K, V>> {
        if now >= self.generation1_expires {
            let removed_gen = mem::replace(&mut self.generation1, mem::take(&mut self.generation0));
            self.generation1_expires = now + self.generation_lifetime;
            Some(removed_gen)
        } else {
            None
        }
    }

    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.generation0
            .get(key)
            .or_else(|| self.generation1.get(key))
    }

    pub fn remove<Q: ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let removed0 = self.generation0.remove(key);
        let removed1 = self.generation1.remove(key);
        removed0.or(removed1)
    }
}

#[cfg(test)]
mod two_generation_cache_tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut lru = TwoGenerationCache::new(Duration::from_secs(1), Instant::now());

        lru.insert("K", "V", Instant::now());

        assert_eq!(Some(&"V"), lru.get("K"));
    }

    #[test]
    fn can_still_read_from_second_generation() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("K1", "V1", now);
        now += lifetime;
        lru.insert("K2", "V2", now);

        assert_eq!(Some(&"V1"), lru.get("K1"));
        assert_eq!(Some(&"V2"), lru.get("K2"));
    }

    #[test]
    fn not_present_after_two_generations() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("K1", "V1", now);
        now += lifetime;
        lru.insert("K2", "V2", now);
        now += lifetime;
        lru.insert("K3", "V3", now);

        assert_eq!(None, lru.get("K1"));
        assert_eq!(Some(&"V2"), lru.get("K2"));
        assert_eq!(Some(&"V3"), lru.get("K3"));
    }

    #[test]
    fn not_present_after_three_generations() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("K1", "V1", now);
        now += lifetime;
        lru.insert("K2", "V2", now);
        now += lifetime;
        lru.insert("K3", "V3", now);
        now += lifetime;
        lru.insert("K4", "V4", now);

        assert_eq!(None, lru.get("K1"));
        assert_eq!(None, lru.get("K2"));
        assert_eq!(Some(&"V3"), lru.get("K3"));
        assert_eq!(Some(&"V4"), lru.get("K4"));
    }

    #[test]
    fn generation_expiry_resets_to_last_inserted_time_plus_duration() {
        let lifetime = Duration::from_secs(2);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("K1", "V1", now);
        now += lifetime;
        lru.insert("K2", "V2", now);
        now += lifetime;
        lru.insert("K3", "V3", now);
        now += Duration::from_millis(1999);
        lru.insert("K4", "V4", now);

        assert_eq!(None, lru.get("K1"));

        // Generation 1
        assert_eq!(Some(&"V2"), lru.get("K2"));

        // Generation 0
        assert_eq!(Some(&"V3"), lru.get("K3"));
        assert_eq!(Some(&"V4"), lru.get("K4"));
    }

    #[test]
    fn longest_and_shortest_lifetime_is_in_range_1_2x_lifetime() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        let longest_insert_time = now;
        lru.insert("KLongest", "VLongest", longest_insert_time);
        now += lifetime;
        let shortest_insert_time = now - Duration::from_nanos(1);
        lru.insert("KShortest", "VShortest", shortest_insert_time);

        assert_eq!((2, 0), (lru.generation0_len(), lru.generation1_len()));

        // Cause the generation to shift
        lru.insert("KTrigger", "VTrigger", now);
        assert_eq!((1, 2), (lru.generation0_len(), lru.generation1_len()));

        assert_eq!(Some(&"VLongest"), lru.get("KLongest"));
        assert_eq!(Some(&"VShortest"), lru.get("KShortest"));

        // Insert, just before the next eviction time
        now += lifetime;
        now -= Duration::from_nanos(1);
        lru.insert("KTrigger2", "VTrigger2", now);
        assert_eq!((2, 2), (lru.generation0_len(), lru.generation1_len()));

        // These are the longest lifetimes we will see for these, [1..2) * lifetime.
        assert_eq!(
            (lifetime * 2).checked_sub(Duration::from_nanos(1)),
            now.checked_duration_since(longest_insert_time)
        );
        assert_eq!(
            lifetime,
            now.checked_duration_since(shortest_insert_time).unwrap()
        );

        // Cause ejection of generation1
        now += Duration::from_nanos(1);
        lru.insert("KTrigger3", "VTrigger3", now);
        assert_eq!((1, 2), (lru.generation0_len(), lru.generation1_len()));

        assert_eq!(None, lru.get("KLongest"));
        assert_eq!(None, lru.get("KShortest"));
    }

    #[test]
    fn remove_when_in_gen_0() {
        let lifetime = Duration::from_secs(1);
        let now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("R1", "V1", now);

        assert_eq!(Some(&"V1"), lru.get("R1"));
        assert_eq!(Some("V1"), lru.remove("R1"));
        assert_eq!(None, lru.get("R1"));
        assert_eq!(None, lru.remove("R1"));
    }

    #[test]
    fn remove_when_in_gen_1() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("R1", "V1", now);
        now += lifetime;
        lru.insert("K1", "V2", now);
        assert_eq!((1, 1), (lru.generation0_len(), lru.generation1_len()));

        assert_eq!(Some(&"V1"), lru.get("R1"));
        assert_eq!(Some("V1"), lru.remove("R1"));
        assert_eq!(None, lru.get("R1"));
        assert_eq!(None, lru.remove("R1"));
    }

    #[test]
    fn remove_when_in_both_generations() {
        let lifetime = Duration::from_secs(1);
        let mut now = Instant::now();
        let mut lru = TwoGenerationCache::new(lifetime, now);

        lru.insert("R1", "V1", now);
        now += lifetime;
        lru.insert("R1", "V2", now);
        assert_eq!((1, 1), (lru.generation0_len(), lru.generation1_len()));

        assert_eq!(Some(&"V2"), lru.get("R1"));
        assert_eq!(Some("V2"), lru.remove("R1"));
        assert_eq!(None, lru.get("R1"));
        assert_eq!(None, lru.remove("R1"));
    }

    #[test]
    fn remove_old() {
        let lifetime = Duration::from_secs(1);
        let now = Instant::now();
        let mut lru: TwoGenerationCacheWithManualRemoveOld<u32, String> =
            TwoGenerationCacheWithManualRemoveOld::new(lifetime, now);

        lru.insert_without_removing_old(1, "a".to_owned());
        lru.insert_without_removing_old(2, "b".to_owned());
        lru.insert_without_removing_old(3, "c".to_owned());

        assert_eq!(
            vec![0u32; 0],
            lru.remove_old(now + Duration::from_millis(999))
        );
        assert_eq!(Some(&"a".to_owned()), lru.get(&1));
        assert_eq!(Some(&"b".to_owned()), lru.get(&2));
        assert_eq!(Some(&"c".to_owned()), lru.get(&3));

        assert_eq!(
            vec![0u32; 0],
            lru.remove_old(now + Duration::from_millis(1001))
        );
        assert_eq!(Some(&"a".to_owned()), lru.get(&1));
        assert_eq!(Some(&"b".to_owned()), lru.get(&2));
        assert_eq!(Some(&"c".to_owned()), lru.get(&3));

        lru.insert_without_removing_old(4, "d".to_owned());

        let mut removed = lru.remove_old(now + Duration::from_millis(2001));
        removed.sort_unstable();
        assert_eq!(vec![1, 2, 3], removed,);
        assert_eq!(None, lru.get(&1));
        assert_eq!(None, lru.get(&2));
        assert_eq!(None, lru.get(&3));
        assert_eq!(Some(&"d".to_owned()), lru.get(&4));

        assert_eq!(vec![4], lru.remove_old(now + Duration::from_millis(3001)));
    }
}
