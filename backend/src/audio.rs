//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{cmp::min, collections::VecDeque, default::Default};

use calling_common::{Duration, Instant, RingBuffer};
use itertools::{FoldWhile, Itertools};
use log::*;

// Higher is louder
pub type Level = u8;

// TODO: Consider rewriting this in the googcc async stream style.
#[derive(Clone, Copy, Default)]
struct LevelFloorTracker {
    floor: Option<Level>,
    floor_since_reset: Option<Level>,
    samples_since_reset: u32,
}

impl LevelFloorTracker {
    const RECALCULCATION_INTERVAL: Duration = Duration::from_secs(15);
    const ASSUMED_SAMPLE_DURATION: Duration = Duration::from_millis(20);
    const SAMPLES_PER_RECALCULATION: u32 = (Self::RECALCULCATION_INTERVAL.as_millis()
        / Self::ASSUMED_SAMPLE_DURATION.as_millis())
        as u32;

    fn reset(floor: Level) -> Self {
        Self {
            floor: Some(floor),
            ..Self::default()
        }
    }

    fn get(self) -> Option<Level> {
        self.floor
    }

    fn update(self, sample: Level) -> Self {
        if sample == 0 {
            // We ignore 0 levels for calculation.
            // The input is likely muted and would throw off the unmute value.
            return self;
        }

        if self.floor.is_none() {
            // We treat our first sample as the initial floor.
            return Self::reset(sample);
        }
        let floor = self.floor.unwrap();

        if sample < floor {
            // Any time we get a sample below the floor, immediately drop to
            // that level as if it were the first value.
            return Self::reset(sample);
        }

        if self.floor_since_reset.is_none() {
            // Our first value since a reset becomes our new floor_since_reset.
            return Self {
                floor: Some(floor),
                floor_since_reset: Some(sample),
                samples_since_reset: 1,
            };
        }
        let floor_since_reset = min(sample, self.floor_since_reset.unwrap());
        let samples_since_reset = self.samples_since_reset + 1;

        // We have enough samples to trigger an average and reset.
        // This slowly creeps up the floor if it increases over time.
        if samples_since_reset >= Self::SAMPLES_PER_RECALCULATION {
            let average_floor = ((floor as f32) * (floor_since_reset as f32)).sqrt() as Level;
            return Self::reset(average_floor);
        }

        // We don't have enough samples to recalculate, so track the state until we do.
        Self {
            floor: Some(floor),
            floor_since_reset: Some(floor_since_reset),
            samples_since_reset,
        }
    }
}

// Based on the "dominant speaker identification" algorithm found at
// https://github.com/jitsi/jitsi-utils/blob/master/src/main/java/org/jitsi/utils/dsi/DominantSpeakerIdentification.java
// which is based on the paper "Dominant Speaker Identification for Multipoint Videoconferencing"
// by Ilana Volfin and Israel Cohen found at
// https://israelcohen.com/wp-content/uploads/2018/05/IEEEI2012_Volfin.pdf
// Although this code does much less math, it should produce the same results,
// at least for the range of audio levels 0-127.
pub struct LevelsTracker {
    floor: LevelFloorTracker,
    // tracks the level and time the sample was received
    levels: RingBuffer<(Level, Instant)>,
}

impl Default for LevelsTracker {
    fn default() -> Self {
        Self {
            floor: LevelFloorTracker::default(),
            levels: RingBuffer::new(50),
        }
    }
}

impl LevelsTracker {
    pub fn push(&mut self, mut sample: Level, ts: Instant) {
        self.floor = self.floor.update(sample);
        let threshold = self.floor.get().unwrap_or(0) + 10;
        // Treat anything near the floor as 0
        // for the purposes of tracking levels
        // and which levels are more active.
        if sample <= threshold {
            sample = 0;
        }
        self.levels.push((sample, ts));
    }

    fn iter_latest_first(&self) -> impl Iterator<Item = (Level, Instant)> + '_ {
        self.levels.iter().rev().copied()
    }

    fn latest(&self) -> Option<Level> {
        self.iter_latest_first().next().map(|(level, _)| level)
    }

    fn count_latest_chunk_above_threshold(&self, n: usize, threshold: Level) -> usize {
        self.iter_latest_first()
            .take(n)
            .filter(|(level, _)| *level > threshold)
            .count()
    }

    /// returns a vector of whether the chunk was above the threshold and the timestamp of the first
    /// sample in each chunk
    fn map_chunks_above_threshold(
        &self,
        chunk_size: usize,
        threshold: Level,
    ) -> (usize, Vec<(bool, Instant)>) {
        let (active_count, chunks_ratings) = self
            .iter_latest_first()
            .chunks(chunk_size)
            .into_iter()
            .map(|chunk| chunk.collect_vec())
            .filter(|chunk| chunk.len() == chunk_size)
            .map(|chunk| {
                (
                    chunk.iter().all(|(level, _)| *level > threshold),
                    chunk.last().unwrap_or(&(0, Instant::now())).1,
                )
            })
            .fold((0, VecDeque::new()), |(active_count, mut acc), element| {
                let is_active = element.0;
                acc.push_front(element);
                (active_count + is_active as usize, acc)
            });
        (active_count, chunks_ratings.into())
    }

    /// returns whether more active than the specified most active. If true, returns the timestamp
    /// of the first chunk when this tracker became more active
    pub fn more_active_than_most_active(
        &self,
        most_active: &LevelsTracker,
        now: Instant,
    ) -> (bool, Instant) {
        const HIGH: Level = 70;
        const LOW: Level = 40;
        const CHUNK_SIZE: usize = 5;

        if self.latest().unwrap_or(0) <= LOW {
            trace!(
                "The contender isn't active enough (latest sample = {:?})",
                self.latest()
            );
            return (false, now);
        }

        if most_active.latest().unwrap_or(0) >= LOW {
            trace!("The most active is still active (latest sample)");
            return (false, now);
        }

        let most_active_first_chunk =
            most_active.count_latest_chunk_above_threshold(CHUNK_SIZE, HIGH);

        if most_active_first_chunk > 0 {
            trace!("The most active is still active (latest chunk)");
            // The most active is too active.
            return (false, now);
        }

        let self_first_chunk = self.count_latest_chunk_above_threshold(CHUNK_SIZE, HIGH);

        if self_first_chunk < CHUNK_SIZE {
            trace!("The contender isn't active enough (latest chunk)");
            // We're not active enough.
            return (false, now);
        }

        let (self_high_chunk_count, self_high_chunks) =
            self.map_chunks_above_threshold(CHUNK_SIZE, HIGH);
        let (most_active_high_chunks_count, most_active_high_chunks) =
            most_active.map_chunks_above_threshold(CHUNK_SIZE, HIGH);

        if self_high_chunk_count <= most_active_high_chunks_count {
            trace!("The most active is more active (number of active chunk)");
            return (false, now);
        }

        // We know that self has been active for the latest chunk, that the self active chunk count
        // is higher than most_active, and that most_active either is inactive or has no samples.
        // There are a few possibilities at this point:
        // 1. If most_active has no samples, then return true and the first timestamp of the first
        //    active chunk in self
        // 2. most_active has samples, then find the contiguous inactive chunks for most active.
        //    Given the timestamp of the first inactive chunk MAI_TS, return the lowest self chunk
        //    timestamp >= MAI_ts when self was active or the timestamp of the latest chunk

        // Case 1: most_active has no samples, return the first active timestamp of self
        if most_active_high_chunks_count == 0 {
            let ts = self_high_chunks
                .iter()
                .find(|(is_active, _)| *is_active)
                .cloned()
                .unwrap_or((true, now))
                .1;
            return (true, ts);
        }

        // Case 2: Find the timestamp of the first chunk in the contiguous inactive period of most_active.
        // Then return the timestamp of the first active chunk in self or the latest chunk's timestamp
        let most_active_became_inactive_ts: Instant = most_active_high_chunks
            .iter()
            .fold_while(now, |acc, (is_active, ts)| {
                if *is_active {
                    FoldWhile::Continue(*ts)
                } else {
                    FoldWhile::Done(acc)
                }
            })
            .into_inner();
        let self_became_more_active_ts: Instant = self_high_chunks
            .iter()
            .find_or_last(|(_, ts)| *ts >= most_active_became_inactive_ts)
            .cloned()
            .unwrap_or((true, now))
            .1;

        (true, self_became_more_active_ts)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_audio_noise_floor_tracker() {
        let floor = LevelFloorTracker::default();
        assert_eq!(None, floor.get());

        let floor = floor.update(10);
        assert_eq!(Some(10), floor.get());

        // Not enough to do another reset
        let mut floor = floor;
        for i in 0..749u16 {
            floor = floor.update(20 + (i % 20) as Level);
        }
        assert_eq!(Some(10), floor.get());

        // Now enough to do another reset
        let floor = floor.update(20);
        assert_eq!(Some(14), floor.get());

        // And another
        let mut floor = floor;
        for i in 0..750u16 {
            floor = floor.update(20 + (i % 20) as Level);
        }
        assert_eq!(Some(16), floor.get());

        // Another low value pushes it back down
        let floor = floor.update(12);
        assert_eq!(Some(12), floor.get());
    }

    #[test]
    fn test_audio_activity() {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut most_active = LevelsTracker::default();
        let mut contender = LevelsTracker::default();
        let now = Instant::now();

        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        // Establishes the noise floor
        contender.push(60, now);
        // Shows activity
        for _ in 0..4 {
            contender.push(80, now);
        }
        // Not quite active enough yet
        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        // OK, now we have enough
        contender.push(80, now);
        assert!(contender.more_active_than_most_active(&most_active, now).0);

        // Not any more, though
        contender.push(70, now);
        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        // OK, active enough again
        for _ in 0..5 {
            contender.push(80, now);
        }
        assert!(contender.more_active_than_most_active(&most_active, now).0);

        // But not if the most active is active again
        most_active.push(50, now); // Establishes noise floor
        assert!(contender.more_active_than_most_active(&most_active, now).0);
        most_active.push(60, now); // Not yet above noise floor
        assert!(contender.more_active_than_most_active(&most_active, now).0);
        most_active.push(80, now); // Now it is
        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        // If it goes inactive a little, that's not enough.
        most_active.push(50, now);
        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        // But if it's inactive a long time, we win.
        for _ in 0..4 {
            most_active.push(50, now);
        }
        assert!(contender.more_active_than_most_active(&most_active, now).0);

        // Unless it was also active even longer ago.  Then it's harder to dislodge.
        for _ in 0..5 {
            most_active.push(80, now);
        }
        for _ in 0..5 {
            most_active.push(50, now);
        }
        assert!(!contender.more_active_than_most_active(&most_active, now).0);

        assert_eq!(1, most_active.map_chunks_above_threshold(5, 70).0);
        assert_eq!(1, contender.map_chunks_above_threshold(5, 70).0);

        // But it is possible with enough activity
        for _ in 0..5 {
            contender.push(80, now);
        }
        assert_eq!(1, most_active.map_chunks_above_threshold(5, 70).0);
        assert_eq!(2, contender.map_chunks_above_threshold(5, 70).0);
        assert!(contender.more_active_than_most_active(&most_active, now).0);
    }
}
