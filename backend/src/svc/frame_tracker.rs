//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::VecDeque;

use calling_common::{Duration, Instant};
use smallvec::SmallVec;
use thiserror::Error;

use crate::{
    rtp::{FullFrameNumber, FullSequenceNumber},
    svc::simple_bitset::SimpleBitset,
};

/// Default maximum number of frames in flight. Since we expect minimal frame overlap and that
/// frames need to be processed quickly, this number can be kept low.
pub const MAX_FRAMES_IN_FLIGHT: usize = 10;
/// The dependency descriptor allows frames to refer to frames that were seen 4096 frames "ago".
/// We therefore default to 4096 here, which is unlikely.
pub const DEFAULT_COMPLETE_FRAMES_TRACKED: usize = 4096;
/// Default period of time between two consecutive calls to `FrameTracker::do_periodic_cleanup`
/// that will result in cleanup being performed.
pub const DEFAULT_PRUNE_PERIOD: Duration = Duration::from_millis(500);
/// Default period of time a frame is allowed to remain in the "frame-in-flight" state before
/// it is discarded.
pub const DEFAULT_FRAME_LIFETIME: Duration = Duration::from_secs(5);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FrameTrackerError {
    #[error("Start flag already set for frame {0}")]
    StartFlagAlreadySet(FullFrameNumber),
    #[error("End flag already set for frame {0}")]
    EndFlagAlreadySet(FullFrameNumber),
    #[error("Frame too large {0}")]
    FrameTooLarge(FullFrameNumber),
    #[error("The frame is invalid {0}")]
    FrameIsInvalid(FullFrameNumber),
    #[error("Too many frames in flight")]
    TooManyFramesInFlight,
}

/// Instances of `FrameTracker` are used to track which frames have been fully received
/// for a particular RTP stream. A frame that has been fully received is considered to
/// be *complete* and has the following characteristics:
///  - It has a start seqnum
///  - It has an end seqnum
///  - It has no missed packets
///
/// A frame that is being tracked but is not yet in the *complete* state is considered
/// to be a frame in flight. A frame can be a frame in flight only for a relatively short
/// period. After that period expires, the frame is purged and is considered lost.
///
/// Please see `FrameTrackerConfig` for information on how to configure a `FrameTracker`
/// instance.
///
/// **IMPORTANT**
///
/// The frame tracker assumes that it is communicating with a WebRTC endpoint. Consequently,
/// it expects that there will be no frame overlap. In other words, all packets received
/// between the first and the last packets of a frame will belong to that same frame.
#[derive(Debug)]
pub struct FrameTracker {
    max_complete_frames: usize,
    complete_frames: VecDeque<FullFrameNumber>,
    frames_in_flight: SmallVec<[FrameInfo; MAX_FRAMES_IN_FLIGHT]>,
    next_prune_time: Option<Instant>,
    prune_period: Duration,
    frame_lifetime: Duration,
}

impl Default for FrameTracker {
    fn default() -> Self {
        Self::new(FrameTrackerConfig::default())
    }
}

#[derive(Debug)]
pub struct FrameTrackerConfig {
    /// Maximum number of frame numbers identifying complete frames to store.
    pub max_complete_frames: usize,
    /// How frequently to perform the pruning operation that discards stale frames in flight.
    pub prune_period: Duration,
    /// How long a frame is allowed to remain in the "frame-in-flight" state before it
    /// is discarded.
    pub frame_lifetime: Duration,
}

impl Default for FrameTrackerConfig {
    fn default() -> Self {
        Self {
            max_complete_frames: DEFAULT_COMPLETE_FRAMES_TRACKED,
            prune_period: DEFAULT_PRUNE_PERIOD,
            frame_lifetime: DEFAULT_FRAME_LIFETIME,
        }
    }
}

#[derive(Debug, Default)]
pub struct PacketInfo {
    pub seqnum: FullSequenceNumber,
    pub frame_number: FullFrameNumber,
    pub start_frame_flag: bool,
    pub end_frame_flag: bool,
}

impl FrameTracker {
    pub fn new(config: FrameTrackerConfig) -> Self {
        let FrameTrackerConfig {
            max_complete_frames,
            prune_period,
            frame_lifetime,
        } = config;
        Self {
            max_complete_frames,
            prune_period,
            frame_lifetime,
            complete_frames: VecDeque::new(),
            frames_in_flight: SmallVec::new(),
            next_prune_time: None,
        }
    }

    fn push_complete_frame(&mut self, frame_number: FullFrameNumber) {
        // Guard against a pathological case where the max_complete_frames is set to 0.
        if self.max_complete_frames == 0 {
            return;
        }
        if self.complete_frames.len() >= self.max_complete_frames {
            // If the new frame is older than the frame we have sitting at the head
            // of the deque we'll simply drop it as it is too old to be worth
            // tracking.
            if self
                .complete_frames
                .front()
                .is_some_and(|front| frame_number < *front)
            {
                return;
            }
            self.complete_frames.pop_front();
        }
        // Find an appropriate place for the frame number so that the list remains sorted.
        // Start scanning from the back as the insertion point will generally be at the very
        // end of the list or very close to it.
        if let Some(index) = self.complete_frames.iter().rposition(|v| *v < frame_number) {
            self.complete_frames.insert(index + 1, frame_number);
        } else {
            self.complete_frames.push_front(frame_number);
        }
    }

    /// Returns `true` if the frame with the given frame number can be considered *complete*.
    /// A complete frame is the one that has a start seqnum, end seqnum, and for which
    /// there are no missed packets.
    pub fn is_complete(&self, frame_number: FullFrameNumber) -> bool {
        const EXPECTED_REFERENCE_RANGE: usize = 10;

        // We expect the frame to be close to the end of the list. We do a reverse
        // sequential scan over the expected reference range at the end of the list.
        // If the frame is not found, we do a full binary search.
        self.complete_frames
            .iter()
            .rev()
            .take(EXPECTED_REFERENCE_RANGE)
            .any(|n| *n == frame_number)
            || self.complete_frames.binary_search(&frame_number).is_ok()
    }

    pub fn update(
        &mut self,
        now: Instant,
        packet_info: PacketInfo,
    ) -> Result<(), FrameTrackerError> {
        let PacketInfo { frame_number, .. } = packet_info;

        if let Some(index) = self
            .frames_in_flight
            .iter()
            .position(|frame| frame.frame_number == frame_number)
        {
            let frame = &mut self.frames_in_flight[index];
            frame.handle_packet(packet_info)?;
            if frame.is_complete() {
                self.push_complete_frame(frame_number);
                self.frames_in_flight.swap_remove(index);
            }
        } else {
            // Guard against repeated inclusion of frames we already know are complete.
            if self.is_complete(frame_number) {
                return Ok(());
            }
            let expires_at = now + self.frame_lifetime;
            let mut frame = FrameInfo::new(frame_number, expires_at);
            frame.handle_packet(packet_info)?;
            if frame.is_complete() {
                self.push_complete_frame(frame_number);
            } else {
                if self.frames_in_flight.len() >= MAX_FRAMES_IN_FLIGHT {
                    return Err(FrameTrackerError::TooManyFramesInFlight);
                }
                self.frames_in_flight.push(frame);
            }
        }

        Ok(())
    }

    /// Performs periodic cleanup tasks. This should be invoked periodically to release
    /// resources that are considered expired.
    pub fn do_periodic_cleanup(&mut self, now: Instant) {
        if self.next_prune_time.is_none_or(|v| v <= now) {
            self.next_prune_time = Some(now + self.prune_period);
            self.frames_in_flight.retain(|frame| frame.expires_at > now);
        }
    }

    /// Returns the number of frames in flight that are being tracked.
    #[must_use]
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.frames_in_flight.len()
    }

    /// Returns `true` if there are no frames in flight.
    #[must_use]
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.frames_in_flight.is_empty()
    }
}

#[derive(Debug)]
struct FrameInfo {
    expires_at: Instant,
    frame_number: FullFrameNumber,
    valid: bool,
    start_seen: bool,
    end_seqnum: Option<FullSequenceNumber>,
    min_seqnum: Option<FullSequenceNumber>,
    seqnums_seen: SimpleBitset<2, u128>,
}

impl FrameInfo {
    fn new(frame_number: FullFrameNumber, expires_at: Instant) -> Self {
        Self {
            expires_at,
            frame_number,
            valid: true,
            start_seen: false,
            end_seqnum: None,
            min_seqnum: None,
            seqnums_seen: SimpleBitset::new(),
        }
    }

    #[inline]
    fn is_complete(&self) -> bool {
        if let (Some(end), Some(offset)) = (self.end_seqnum, self.min_seqnum) {
            self.valid
                && self.start_seen
                && self
                    .seqnums_seen
                    .all_bits_in_subset_set((end - offset) as usize)
                    .unwrap_or(false)
        } else {
            false
        }
    }

    fn handle_packet(&mut self, packet_info: PacketInfo) -> Result<(), FrameTrackerError> {
        let PacketInfo {
            start_frame_flag,
            end_frame_flag,
            seqnum,
            ..
        } = packet_info;
        if !self.valid {
            return Err(FrameTrackerError::FrameIsInvalid(self.frame_number));
        }
        if start_frame_flag && self.start_seen {
            return Err(FrameTrackerError::StartFlagAlreadySet(self.frame_number));
        }
        if end_frame_flag && self.end_seqnum.is_some() {
            return Err(FrameTrackerError::EndFlagAlreadySet(self.frame_number));
        }
        let offset = if let Some(min_seqnum) = self.min_seqnum {
            // If this seqnum is below the minimum seqnum then we need to make room
            // for it in our bit vector by shifting to the left. Flag the frame as
            // being too large if any bits get shifted out.
            if seqnum < min_seqnum {
                if self.seqnums_seen.shift_left((min_seqnum - seqnum) as usize) {
                    self.valid = false;
                    return Err(FrameTrackerError::FrameTooLarge(self.frame_number));
                }
                self.min_seqnum = Some(seqnum);
                seqnum
            } else {
                min_seqnum
            }
        } else {
            self.min_seqnum = Some(seqnum);
            seqnum
        };
        // seqnum is either equal to the offset or larger. The frame is too large
        // if the index of the bit that we want to set exceeds the bit vector's
        // capacity.
        if self.seqnums_seen.set((seqnum - offset) as usize).is_err() {
            self.valid = false;
            return Err(FrameTrackerError::FrameTooLarge(self.frame_number));
        }
        if start_frame_flag {
            self.start_seen = true;
        }
        if end_frame_flag {
            self.end_seqnum = Some(seqnum);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::svc::frame_tracker::*;

    #[test]
    fn test_handle_packet() -> Result<(), FrameTrackerError> {
        let config = FrameTrackerConfig::default();
        let mut frame_tracker = FrameTracker::new(config);

        let now = Instant::now();

        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 0,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 3,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 4,
            },
        )?;

        assert!(!frame_tracker.is_complete(0));

        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 2,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 1,
            },
        )?;

        assert!(frame_tracker.is_complete(0));

        Ok(())
    }

    #[test]
    fn test_minseq() -> Result<(), FrameTrackerError> {
        let config = FrameTrackerConfig::default();
        let mut frame_tracker = FrameTracker::new(config);

        let now = Instant::now();

        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 2,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 3,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 0,
            },
        )?;
        frame_tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 1,
            },
        )?;

        assert!(frame_tracker.is_complete(0));

        Ok(())
    }

    #[test]
    fn test_single_frame() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut frames = FrameTracker::new(FrameTrackerConfig::default());
        frames.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 1,
            },
        )?;
        assert_eq!(frames.len(), 1);
        frames.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 2,
            },
        )?;
        assert!(frames.is_empty());

        Ok(())
    }

    #[test]
    fn test_multiple_frames() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        const FRAME_COUNT: FullFrameNumber = 10;
        let mut frames = FrameTracker::new(FrameTrackerConfig::default());
        let mut seqnum = 0;
        for i in 0..FRAME_COUNT {
            frames.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum,
                },
            )?;
            seqnum += 3;
        }
        seqnum = 2;
        for i in 0..FRAME_COUNT {
            frames.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: false,
                    end_frame_flag: true,
                    seqnum,
                },
            )?;
            seqnum += 3;
        }
        seqnum = 1;
        for i in 0..FRAME_COUNT {
            frames.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: false,
                    end_frame_flag: false,
                    seqnum,
                },
            )?;
            seqnum += 3;
        }
        assert!(frames.is_empty());

        Ok(())
    }

    #[test]
    fn test_single_packet_frame() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: true,
                seqnum: 42,
            },
        )?;
        assert!(tracker.is_empty());
        assert!(tracker.is_complete(1));
        Ok(())
    }

    #[test]
    fn test_duplicate_start_flag_returns_error() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 1,
                },
            )
            .unwrap();
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 2,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::StartFlagAlreadySet(1)));
    }

    #[test]
    fn test_duplicate_end_flag_returns_error() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: false,
                    end_frame_flag: true,
                    seqnum: 1,
                },
            )
            .unwrap();
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 2,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::EndFlagAlreadySet(1)));
    }

    #[test]
    fn test_frame_expiry_via_periodic_cleanup() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 1,
                },
            )
            .unwrap();
        assert_eq!(tracker.len(), 1);

        // Advance past frame_lifetime (5s) and prune_period (500ms).
        let expired = now + DEFAULT_FRAME_LIFETIME + Duration::from_millis(1);
        tracker.do_periodic_cleanup(expired);
        assert!(tracker.is_empty());
        assert!(!tracker.is_complete(1));
    }

    #[test]
    fn test_max_complete_frames_evicts_oldest() -> Result<(), FrameTrackerError> {
        let config = FrameTrackerConfig {
            max_complete_frames: 3,
            prune_period: DEFAULT_PRUNE_PERIOD,
            frame_lifetime: DEFAULT_FRAME_LIFETIME,
        };
        let now = Instant::now();
        let mut tracker = FrameTracker::new(config);
        for i in 0..4 {
            tracker.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: true,
                    end_frame_flag: true,
                    seqnum: i,
                },
            )?;
        }
        assert!(!tracker.is_complete(0)); // evicted
        assert!(tracker.is_complete(1));
        assert!(tracker.is_complete(2));
        assert!(tracker.is_complete(3));
        Ok(())
    }

    #[test]
    fn test_is_complete_binary_search_fallback() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        // Complete 15 frames. Frame 0 is 14 positions from the end of complete_frames,
        // past the 10-element linear scan, so binary search is exercised.
        for i in 0..15 {
            tracker.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: true,
                    end_frame_flag: true,
                    seqnum: i,
                },
            )?;
        }
        assert!(tracker.is_complete(0)); // found via binary search
        assert!(tracker.is_complete(14)); // found via linear scan
        Ok(())
    }

    #[test]
    fn test_duplicate_seqnum_is_ignored() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 5,
            },
        )?;
        // Same seqnum should not error.
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 5,
            },
        )?;
        assert_eq!(tracker.len(), 1);
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 6,
            },
        )?;
        assert!(tracker.is_empty());
        assert!(tracker.is_complete(1));
        Ok(())
    }

    #[test]
    fn test_frame_too_large() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 0,
                },
            )
            .unwrap();
        // Seqnum 256 is exactly one past the bitmap capacity (2 * 128 bits).
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 256,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::FrameTooLarge(1)));
    }

    // Frames that complete out of order must still be stored sorted so binary_search works.
    #[test]
    fn test_out_of_order_completion_ordering() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        for frame_number in [10u64, 3, 7] {
            tracker.update(
                now,
                PacketInfo {
                    frame_number,
                    start_frame_flag: true,
                    end_frame_flag: true,
                    seqnum: frame_number,
                },
            )?;
        }
        assert!(tracker.is_complete(3));
        assert!(tracker.is_complete(7));
        assert!(tracker.is_complete(10));
        Ok(())
    }

    // All existing tests use seqnums near 0. This one uses a realistic RTP base
    // and exercises the relative-offset arithmetic end-to-end.
    #[test]
    fn test_non_zero_seqnum_base() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());

        // Arrive out of order: end, middle, then start (each triggers a bitmap shift).
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 1003,
            },
        )?;
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 1002,
            },
        )?;
        assert!(!tracker.is_complete(1));
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: 1001,
            },
        )?;
        assert!(tracker.is_complete(1));
        Ok(())
    }

    #[test]
    fn test_frame_survives_cleanup_if_not_expired() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 1,
                },
            )
            .unwrap();
        // Past prune_period so cleanup fires, but well before frame_lifetime (5s).
        let t = now + DEFAULT_PRUNE_PERIOD + Duration::from_millis(1);
        tracker.do_periodic_cleanup(t);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_max_complete_frames_zero() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let config = FrameTrackerConfig {
            max_complete_frames: 0,
            ..FrameTrackerConfig::default()
        };
        let mut tracker = FrameTracker::new(config);
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: true,
                seqnum: 1,
            },
        )?;
        assert!(!tracker.is_complete(1));
        Ok(())
    }

    #[test]
    fn test_late_packet_for_complete_frame() -> Result<(), FrameTrackerError> {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: true,
                seqnum: 42,
            },
        )?;
        assert!(tracker.is_complete(1));
        assert!(tracker.is_empty());

        // Late retransmission — should not error or corrupt state.
        tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: true,
                end_frame_flag: true,
                seqnum: 42,
            },
        )?;
        assert!(tracker.is_complete(1));
        assert!(tracker.is_empty());
        Ok(())
    }

    #[test]
    fn test_is_complete_returns_false_for_unknown_frame() {
        let tracker = FrameTracker::new(FrameTrackerConfig::default());
        assert!(!tracker.is_complete(42));
    }

    #[test]
    fn test_too_many_frames_in_flight() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        for i in 0..MAX_FRAMES_IN_FLIGHT as FullFrameNumber {
            tracker
                .update(
                    now,
                    PacketInfo {
                        frame_number: i,
                        start_frame_flag: true,
                        end_frame_flag: false,
                        seqnum: i,
                    },
                )
                .unwrap();
        }
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT);
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: MAX_FRAMES_IN_FLIGHT as FullFrameNumber,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: MAX_FRAMES_IN_FLIGHT as FullSequenceNumber,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::TooManyFramesInFlight));
    }

    #[test]
    fn test_too_many_frames_in_flight_completing_frame_frees_slot() -> Result<(), FrameTrackerError>
    {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        for i in 0..MAX_FRAMES_IN_FLIGHT as FullFrameNumber {
            tracker.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: i,
                },
            )?;
        }
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT);
        // Complete frame 0 by sending its end packet at the same seqnum — frees one slot.
        tracker.update(
            now,
            PacketInfo {
                frame_number: 0,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 0,
            },
        )?;
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT - 1);
        tracker.update(
            now,
            PacketInfo {
                frame_number: MAX_FRAMES_IN_FLIGHT as FullFrameNumber,
                start_frame_flag: true,
                end_frame_flag: false,
                seqnum: MAX_FRAMES_IN_FLIGHT as FullSequenceNumber,
            },
        )?;
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT);
        Ok(())
    }

    #[test]
    fn test_single_packet_frame_does_not_consume_slot_at_capacity() -> Result<(), FrameTrackerError>
    {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        for i in 0..MAX_FRAMES_IN_FLIGHT as FullFrameNumber {
            tracker.update(
                now,
                PacketInfo {
                    frame_number: i,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: i,
                },
            )?;
        }
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT);
        // A single-packet frame completes before entering frames_in_flight, so no cap applies.
        tracker.update(
            now,
            PacketInfo {
                frame_number: MAX_FRAMES_IN_FLIGHT as FullFrameNumber,
                start_frame_flag: true,
                end_frame_flag: true,
                seqnum: 999,
            },
        )?;
        assert_eq!(tracker.len(), MAX_FRAMES_IN_FLIGHT);
        assert!(tracker.is_complete(MAX_FRAMES_IN_FLIGHT as FullFrameNumber));
        Ok(())
    }

    // test_frame_too_large exercises the set()-out-of-bounds path. This test exercises
    // the shift-carry path: seqnum 256 fills bit 255 exactly, then seqnum 0 would shift
    // it to bit 256, producing carry.
    #[test]
    fn test_frame_too_large_via_shift_overflow() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        // seqnum 1 → min=1, bit 0 set.
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 1,
                },
            )
            .unwrap();
        // seqnum 256 → bit 255 (bitmap exactly full, no error).
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: false,
                    end_frame_flag: false,
                    seqnum: 256,
                },
            )
            .unwrap();
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: false,
                seqnum: 0,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::FrameTooLarge(1)));
    }

    #[test]
    fn test_frame_is_invalid_after_too_large() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 0,
                },
            )
            .unwrap();
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: false,
                    end_frame_flag: false,
                    seqnum: 512,
                },
            )
            .unwrap_err();
        let result = tracker.update(
            now,
            PacketInfo {
                frame_number: 1,
                start_frame_flag: false,
                end_frame_flag: true,
                seqnum: 1,
            },
        );
        assert_eq!(result, Err(FrameTrackerError::FrameIsInvalid(1)));
    }

    #[test]
    fn test_invalid_frame_pruned_by_cleanup() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 0,
                },
            )
            .unwrap();
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: false,
                    end_frame_flag: false,
                    seqnum: 512,
                },
            )
            .unwrap_err();
        assert_eq!(tracker.len(), 1);
        let expired = now + DEFAULT_FRAME_LIFETIME + Duration::from_millis(1);
        tracker.do_periodic_cleanup(expired);
        assert!(tracker.is_empty());
    }

    // Replaces test_cleanup_does_not_fire_before_prune_period, whose name and comment
    // described the old eager-initialization behavior. next_prune_time is now None at
    // construction, so the first cleanup call always fires; subsequent calls within the
    // same prune period are suppressed.
    #[test]
    fn test_cleanup_throttled_after_first_fire() {
        let now = Instant::now();
        let mut tracker = FrameTracker::new(FrameTrackerConfig::default());
        // First call fires immediately (next_prune_time is None) and arms the timer.
        tracker.do_periodic_cleanup(now);
        tracker
            .update(
                now,
                PacketInfo {
                    frame_number: 1,
                    start_frame_flag: true,
                    end_frame_flag: false,
                    seqnum: 1,
                },
            )
            .unwrap();
        // Second call at the same now — timer not yet elapsed, retain does not run.
        tracker.do_periodic_cleanup(now);
        assert_eq!(tracker.len(), 1);
    }
}
