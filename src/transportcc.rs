//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the transport protocol detailed here
//! https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01

use std::{
    collections::{btree_map, BTreeMap},
    ops::{Add, AddAssign},
};

use byteorder::{ReadBytesExt, BE};
use log::*;

use crate::common::{DataSize, Duration, Instant, TwoGenerationCache, Writable, Writer, U24};
pub use crate::rtp::{expand_seqnum, FullSequenceNumber, TruncatedSequenceNumber};

/// A remote instant, internally represented as a duration since a remote-chosen epoch.
///
/// RemoteInstants can only meaningfully be compared if they come from the same connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemoteInstant(Duration);

impl RemoteInstant {
    pub fn from_micros(micros: u64) -> Self {
        Self(Duration::from_micros(micros))
    }

    pub fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    pub fn saturating_duration_since(self, other: RemoteInstant) -> Duration {
        self.0.saturating_sub(other.0)
    }

    pub fn checked_sub(self, offset: Duration) -> Option<RemoteInstant> {
        self.0.checked_sub(offset).map(RemoteInstant)
    }
}

impl Add<Duration> for RemoteInstant {
    type Output = Self;

    fn add(self, offset: Duration) -> Self {
        Self(self.0 + offset)
    }
}

impl AddAssign<Duration> for RemoteInstant {
    fn add_assign(&mut self, offset: Duration) {
        self.0 += offset;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ack {
    pub size: DataSize,
    pub departure: Instant,
    pub arrival: RemoteInstant,
    pub feedback_arrival: Instant,
}

pub struct Sender {
    next_send_seqnum: FullSequenceNumber,
    max_received_seqnum: FullSequenceNumber,
    size_by_seqnum: TwoGenerationCache<FullSequenceNumber, (DataSize, Instant)>,
}

// The state for sending transport-cc, which keeps track of packets sent and
// feedback received.  It also updates outgoing packets to have a different
// transport-cc seqnum.
impl Sender {
    pub fn new(now: Instant) -> Self {
        Self {
            next_send_seqnum: 1,
            max_received_seqnum: 0,
            // WebRTC limits this to 60 seconds, and Jitsi to 1000 packets.
            // At 20mbps (the max rate), 1000 packets can be used in 60ms, which doesn't seem long enough.
            // A feedback message might take longer than that.
            // So we'll go with the WebRTC way.  However, 60 seconds seems a bit long, so let's go with 10 seconds.
            // TODO: Consider making this configurable
            size_by_seqnum: TwoGenerationCache::new(Duration::from_secs(10), now),
        }
    }

    pub fn increment_seqnum(&mut self) -> FullSequenceNumber {
        let seqnum = self.next_send_seqnum;
        self.next_send_seqnum += 1;
        seqnum
    }

    pub fn remember_sent(&mut self, seqnum: FullSequenceNumber, size: DataSize, now: Instant) {
        let departure = now;
        self.size_by_seqnum.insert(seqnum, (size, departure), now);
    }

    pub fn process_feedback_and_correlate_acks(
        &mut self,
        feedback: impl Iterator<Item = impl AsRef<[u8]>>,
        feedback_arrival: Instant,
    ) -> Vec<Ack> {
        let mut acks = Vec::new();
        for feedback in feedback {
            if let Some((_feedback_seqnum, arrivals)) =
                read_feedback(feedback.as_ref(), &mut self.max_received_seqnum)
            {
                for (seqnum, arrival) in arrivals {
                    if let Some((size, departure)) = self.size_by_seqnum.remove(&seqnum) {
                        acks.push(Ack {
                            // seqnum,
                            size,
                            departure,
                            arrival,
                            feedback_arrival,
                        });
                    }
                }
            } else {
                warn!("Failed to parse TCC feedback");
            }
        }
        acks
    }
}

// The state for receiving transport-cc, which keeps track of packets received with
// a transport-cc seqnum and then occasionally triggers sending a feedback message.
pub struct Receiver {
    // The SSRC to use when sending ACKs
    // It can be any SSRC the sender uses to send TCC seqnums
    ssrc: u32,

    // The timestamps of ACKs are all based off of this time.
    epoch: Instant,

    // Each ACK has a short seqnum that rolls over regularly.
    next_feedback_seqnum: u8,

    // This contains all the seqnums that have not been acked.
    // It is cleared whenever ACKs are sent.
    // We need a map to ignore seqnums received more than once
    // and for it to be sorted to properly construct ACKs.
    unacked_arrival_by_seqnum: BTreeMap<FullSequenceNumber, Instant>,
}

impl Receiver {
    pub fn new(ssrc: u32, epoch: Instant) -> Self {
        Self {
            ssrc,
            epoch,
            next_feedback_seqnum: 1,
            unacked_arrival_by_seqnum: BTreeMap::new(),
        }
    }

    pub fn remember_received(&mut self, seqnum: FullSequenceNumber, arrival: Instant) {
        if let btree_map::Entry::Vacant(entry) = self.unacked_arrival_by_seqnum.entry(seqnum) {
            entry.insert(arrival);
        } else {
            // If a seqnum arrives more than once, ignore the subsequent ones.
        }
    }

    // Returns Writers for feedback payload to allow for efficient construction of full RTCP packets.
    #[allow(clippy::needless_lifetimes)]
    pub fn send_acks<'receiver>(
        &'receiver mut self,
    ) -> impl Iterator<Item = impl Writer> + 'receiver {
        let next_feedback_seqnum = &mut self.next_feedback_seqnum;
        let unacked_arrival_by_seqnum = std::mem::take(&mut self.unacked_arrival_by_seqnum);
        write_feedback(
            self.ssrc,
            next_feedback_seqnum,
            self.epoch,
            unacked_arrival_by_seqnum.into_iter(),
        )
    }
}

const MICROS_PER_REFERENCE_TICK: u16 = 250 << 8;
const MICROS_PER_DELTA_TICK: u16 = 250;

// Returns Writers for feedback payload to allow for efficient construction of full RTCP packets.
// The SSRC can be any SSRC the sender uses to send TCC seqnums
pub fn write_feedback<'a>(
    ssrc: u32,
    next_feedback_seqnum: &'a mut u8,
    epoch: Instant,
    arrivals: impl Iterator<Item = (FullSequenceNumber, Instant)> + 'a,
) -> impl Iterator<Item = impl Writer> + 'a {
    let mut arrivals = arrivals.peekable();
    std::iter::from_fn(move || {
        let (first_seqnum, first_arrival) = *arrivals.peek()?;
        let reference_time_ticks = ticks_from_duration(
            first_arrival.saturating_duration_since(epoch),
            MICROS_PER_REFERENCE_TICK,
        );
        // The reference time is not the first arrival time because it has to be quantized to its tick frequency.
        // In other words, the first delta is not zero because deltas have higher tick precision than the reference time.
        let reference_time =
            epoch + duration_from_ticks(reference_time_ticks, MICROS_PER_REFERENCE_TICK);

        let mut prev_seqnum = first_seqnum;
        let mut prev_arrival = reference_time;

        let mut encoded_receive_deltas = Vec::new();
        let mut status_chunks = PacketStatusChunks::new();
        while let Some((seqnum, arrival)) = arrivals.peek() {
            let (seqnum, arrival) = (*seqnum, *arrival);
            if seqnum > (first_seqnum + (u16::MAX as FullSequenceNumber)) {
                // This seqnum can't fit into the packet, so we need to return this packet and then process another one.
                break;
            }
            if encoded_receive_deltas.len() + status_chunks.written_len() > 1100 {
                // The RTCP packet is getting too big.  Let's cap it off and send another one.
                break;
            }
            for _ in (prev_seqnum + 1)..seqnum {
                status_chunks.push(PacketStatus::NotReceived);
            }
            let delta_ticks =
                ticks_from_before_and_after(prev_arrival, arrival, MICROS_PER_DELTA_TICK);
            const MAX_SMALL_DELTA_TICKS: i64 = u8::MAX as i64;
            const MAX_LARGE_DELTA_TICKS: i64 = i16::MAX as i64;
            const MIN_LARGE_DELTA_TICKS: i64 = i16::MIN as i64;

            // Overlapping here is intentional.
            #[allow(clippy::match_overlapping_arm)]
            match delta_ticks {
                0..=MAX_SMALL_DELTA_TICKS => {
                    encoded_receive_deltas.push(delta_ticks as u8);
                    status_chunks.push(PacketStatus::ReceivedSmallDelta);
                }
                MIN_LARGE_DELTA_TICKS..=MAX_LARGE_DELTA_TICKS => {
                    encoded_receive_deltas.extend_from_slice(&(delta_ticks as i16).to_be_bytes());
                    status_chunks.push(PacketStatus::ReceivedLargeOrNegativeDelta);
                }
                _ => {
                    // This delta can't fit into the packet, so we need to return this packet and then process another one.
                    break;
                }
            };

            // Consume what we were peeking because it fit into the packet.
            arrivals.next();

            prev_seqnum = seqnum;
            prev_arrival = arrival;
        }

        let feedback_seqnum =
            std::mem::replace(next_feedback_seqnum, next_feedback_seqnum.wrapping_add(1));
        let last_seqnum = prev_seqnum;
        let status_count = (last_seqnum - first_seqnum + 1) as u16;
        let header = (
            ssrc,
            first_seqnum as u16,
            status_count,
            U24::truncate(reference_time_ticks as u32),
            [feedback_seqnum],
        );
        let writer = (header, status_chunks, encoded_receive_deltas);
        Some(writer)
    })
}

fn ticks_from_before_and_after(before: Instant, after: Instant, micros_per_tick: u16) -> i64 {
    if after > before {
        ticks_from_duration(
            after.checked_duration_since(before).unwrap(),
            micros_per_tick,
        ) as i64
    } else {
        // Negative!
        -(ticks_from_duration(
            before.checked_duration_since(after).unwrap(),
            micros_per_tick,
        ) as i64)
    }
}

fn ticks_from_duration(duration: Duration, micros_per_tick: u16) -> u64 {
    // Round down.  If we round up the reference time, that will force the first
    // ack to be the 2-byte variety, which is less efficient to encode.
    (duration.as_micros() as u64) / (micros_per_tick as u64)
}

fn duration_from_ticks(ticks: u64, micros_per_tick: u16) -> Duration {
    Duration::from_micros(ticks * micros_per_tick as u64)
}

pub fn read_feedback(
    mut payload: &[u8],
    max_seqnum: &mut FullSequenceNumber,
) -> Option<(u8, Vec<(FullSequenceNumber, RemoteInstant)>)> {
    let _ssrc = payload.read_u32::<BE>().ok()?;
    let base_seqnum = payload.read_u16::<BE>().ok()?;
    let base_seqnum: FullSequenceNumber = expand_seqnum(base_seqnum, max_seqnum);
    let status_count = payload.read_u16::<BE>().ok()?;
    let reference_time_ticks = payload.read_u24::<BE>().ok()?;
    let feedback_seqnum = payload.read_u8().ok()?;

    let mut status_chunks = Vec::new();
    let mut status_chunks_sum_count = 0;
    while status_chunks_sum_count < (status_count as usize) {
        let encoded_status_chunk = payload.read_u16::<BE>().ok()?;
        let status_chunk = PacketStatusChunk::from_u16(encoded_status_chunk)?;
        status_chunks.push(status_chunk);
        status_chunks_sum_count += status_chunk.len();
    }
    let mut arrivals = Vec::new();
    let mut arrivals_sum_delta_ticks: i32 = 0;
    for (seqnum, status) in (base_seqnum..(base_seqnum + status_count as u64))
        .zip(status_chunks.iter().copied().flatten())
    {
        if let Some(delta_ticks) = match status? {
            PacketStatus::NotReceived => None,
            PacketStatus::ReceivedSmallDelta => {
                let delta_ticks = payload.read_u8().ok()?;
                Some(delta_ticks as i32)
            }
            PacketStatus::ReceivedLargeOrNegativeDelta => {
                let delta_ticks = payload.read_i16::<BE>().ok()?;
                Some(delta_ticks as i32)
            }
        } {
            arrivals_sum_delta_ticks += delta_ticks;
            let arrival_micros = ((MICROS_PER_REFERENCE_TICK as i64
                * u64::from(reference_time_ticks) as i64)
                + (MICROS_PER_DELTA_TICK as i64 * arrivals_sum_delta_ticks as i64))
                as u64;
            arrivals.push((seqnum, RemoteInstant::from_micros(arrival_micros)));
        }
    }
    Some((feedback_seqnum, arrivals))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum PacketStatus {
    /// O bytes of receive delta
    NotReceived = 0,
    /// 1 byte of receive delta
    ReceivedSmallDelta = 1,
    /// 2 bytes of receive delta
    ReceivedLargeOrNegativeDelta = 2,
}

impl PacketStatus {
    fn from_u8(size: u8) -> Option<Self> {
        match size {
            0b00 => Some(PacketStatus::NotReceived),
            0b01 => Some(PacketStatus::ReceivedSmallDelta),
            0b10 => Some(PacketStatus::ReceivedLargeOrNegativeDelta),
            0b11 => None,
            _ => unreachable!("We expect this to be only called with 2 bits"),
        }
    }
}

// A complicated way of encoding a sequence of PacketStatus.
// Which is a complicated way of encoding a sequence of [0, 1, 2].
// I hope the efficiency is worth the trouble!
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum PacketStatusChunk {
    // Must all be of the same type
    RunLength {
        len: u16, // Up to 8191
        status: PacketStatus,
    },
    Vector1 {
        len: u8,   // up to 14
        bits: u16, // of 1-bit each
    },
    Vector2 {
        len: u8,   // up to 7
        bits: u16, // of 2-bit each
    },
}

impl PacketStatusChunk {
    fn len(self) -> usize {
        match self {
            Self::RunLength { len, .. } => len as usize,
            Self::Vector1 { len, .. } => len as usize,
            Self::Vector2 { len, .. } => len as usize,
        }
    }
}

impl IntoIterator for PacketStatusChunk {
    type Item = Option<PacketStatus>;
    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::RunLength { status, len, .. } => {
                Box::new(std::iter::repeat(Some(status)).take(len as usize))
            }
            Self::Vector1 { len, bits } => Box::new(
                (2..=15)
                    .map(move |i| PacketStatus::from_u8(((bits >> (15 - i)) & 0b1) as u8))
                    .take(len as usize),
            ),
            Self::Vector2 { len, bits } => Box::new(
                (2..=14)
                    .step_by(2)
                    .map(move |i| PacketStatus::from_u8(((bits >> (14 - i)) & 0b11) as u8))
                    .take(len as usize),
            ),
        }
    }
}

impl PacketStatusChunk {
    fn from_u16(encoded: u16) -> Option<Self> {
        let chunk = match encoded >> 14 {
            0b01 | 0b00 => Self::RunLength {
                len: encoded & 0b0001_1111_1111_1111,
                status: PacketStatus::from_u8(((encoded >> 13) & 0b11) as u8)?,
            },
            0b10 => Self::Vector1 {
                len: 14,
                bits: encoded & 0b0011_1111_1111_1111,
            },
            0b11 => Self::Vector2 {
                len: 7,
                bits: encoded & 0b0011_1111_1111_1111,
            },
            _ => {
                unreachable!("All two bit values are covered above");
            }
        };
        Some(chunk)
    }

    fn as_16(self) -> u16 {
        match self {
            Self::RunLength { status, len, .. } => ((status as u16) << 13) | len,
            Self::Vector1 { bits, .. } => (0b10 << 14) | bits,
            Self::Vector2 { bits, .. } => (0b11 << 14) | bits,
        }
    }

    // Returns 1-2 chunks because the push may require splitting the current one into 2,
    // or creating a new one.
    fn push(self, status: PacketStatus) -> (Self, Option<Self>) {
        use PacketStatus::*;
        use PacketStatusChunk::*;
        match self {
            RunLength {
                len: 8191..=u16::MAX,
                ..
            }
            | Vector1 {
                len: 14..=u8::MAX, ..
            }
            | Vector2 {
                len: 7..=u8::MAX, ..
            } => {
                // Full, so create a new one.
                (self, Some(PacketStatusChunk::RunLength { len: 1, status }))
            }
            RunLength {
                len: len @ 0..=8190,
                status: existing_status,
                ..
            } if status == existing_status => {
                // Fits on the RunLength, so just increment the existing len
                let len = len + 1;
                (RunLength { len, status }, None)
            }
            RunLength {
                len: 0..=13,
                status: existing_status,
            } if status != ReceivedLargeOrNegativeDelta
                && existing_status != ReceivedLargeOrNegativeDelta =>
            {
                // Doesn't fit in the existing RunLength, but can be converted into a Vector1.
                Self::vector1_from_iter(self).push(status)
            }
            RunLength { len: 0..=6, .. } => {
                // status == ReceivedLargeDelta
                // Doesn't fit in the existing RunLength or Vector1, but can be converted into a Vector2.
                Self::vector2_from_iter(self).push(status)
            }
            RunLength { len: 7..=8190, .. } => {
                // status != existing_status
                // Can't continue or convert
                (self, Some(PacketStatusChunk::RunLength { len: 1, status }))
            }
            Vector1 {
                len: len @ 0..=13,
                bits,
            } if status != ReceivedLargeOrNegativeDelta => {
                // Fits on the Vector1, so splice in a bit and increment the existing len
                let bits = bits | (status as u16) << (13 - len);
                let len = len + 1;
                (Vector1 { len, bits }, None)
            }
            Vector1 { len: 0..=6, .. } => {
                // status == ReceivedLargeDelta
                // Doesn't fit into a Vector1, but can be converted into a Vector2
                Self::vector2_from_iter(self).push(status)
            }
            Vector1 { len: 7..=13, .. } => {
                // status == ReceivedLargeDelta
                // Doesn't fit into a Vector1, nor into a Vector2, but can be converted into 2 Vector2s.
                (
                    Self::vector2_from_iter(self.into_iter().take(7)),
                    Some(
                        Self::vector2_from_iter(self.into_iter().skip(7))
                            .push(status)
                            .0,
                    ),
                )
            }
            Vector2 {
                len: len @ 0..=6,
                bits,
            } => {
                // Fits on the Vector2, so splice in 2 bits and increment the existing len
                let bits = bits | (status as u16) << (2 * (6 - len));
                let len = len + 1;
                (Vector2 { len, bits }, None)
            }
        }
    }

    fn vector1_from_iter(statuses: impl IntoIterator<Item = Option<PacketStatus>>) -> Self {
        let mut len = 0;
        let mut bits = 0;
        for (i, status) in statuses.into_iter().take(14).enumerate() {
            debug_assert!(status.unwrap() != PacketStatus::ReceivedLargeOrNegativeDelta);
            bits |= (status.unwrap() as u16) << (13 - i);
            len += 1;
        }
        Self::Vector1 { len, bits }
    }

    fn vector2_from_iter(statuses: impl IntoIterator<Item = Option<PacketStatus>>) -> Self {
        let mut len = 0;
        let mut bits = 0;
        for (i, status) in statuses.into_iter().take(7).enumerate() {
            bits |= (status.unwrap() as u16) << (2 * (6 - i));
            len += 1;
        }
        Self::Vector2 { len, bits }
    }
}

// A complicated way of encoding a sequence of PacketStatusChunks.
// Which is a complicated way of encoding a sequence of [0, 1, 2].
// I hope the efficiency is worth the trouble!
// The trailing PacketStatusChunk may not be full.
#[derive(Debug)]
struct PacketStatusChunks {
    chunks: Vec<PacketStatusChunk>,
}

impl PacketStatusChunks {
    fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    // Return a "new" one, not a full one.
    fn push(&mut self, status: PacketStatus) {
        if let Some(last) = self.chunks.last_mut() {
            let (last1, last2) = last.push(status);
            *last = last1;
            if let Some(last2) = last2 {
                self.chunks.push(last2);
            }
        } else {
            self.chunks
                .push(PacketStatusChunk::RunLength { len: 1, status })
        }
    }
}

impl Writer for PacketStatusChunks {
    fn written_len(&self) -> usize {
        2 * self.chunks.len()
    }

    fn write(&self, out: &mut dyn Writable) {
        for chunk in &self.chunks {
            chunk.as_16().write(out);
        }
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;

    fn collect_feedback(writers: impl Iterator<Item = impl Writer>) -> Vec<Vec<u8>> {
        writers.map(|writer| writer.to_vec()).collect::<Vec<_>>()
    }

    fn read_all_feedback(
        feedback: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> Vec<(u8, Vec<(FullSequenceNumber, RemoteInstant)>)> {
        feedback
            .filter_map(|feedback| read_feedback(feedback.as_ref(), &mut 0))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_tcc_sender() {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let bytes = DataSize::from_bytes;

        let mut sender = Sender::new(now);
        sender.remember_sent(1, bytes(1201), at(10));
        sender.remember_sent(2, bytes(1202), at(20));
        sender.remember_sent(3, bytes(1203), at(30));
        sender.remember_sent(4, bytes(1204), at(40));
        sender.remember_sent(5, bytes(1205), at(50));

        let mut next_feedback_seqnum = 2;
        let feedback = collect_feedback(write_feedback(
            1000,
            &mut next_feedback_seqnum,
            at(15),
            vec![(1, at(15)), (2, at(38)), (3, at(37)), (5, at(59))].into_iter(),
        ));
        assert_eq!(
            vec![
                Ack {
                    size: bytes(1201),
                    departure: at(10),
                    arrival: RemoteInstant::from_millis(0),
                    feedback_arrival: at(50),
                },
                Ack {
                    size: bytes(1202),
                    departure: at(20),
                    arrival: RemoteInstant::from_millis(23),
                    feedback_arrival: at(50),
                },
                Ack {
                    size: bytes(1203),
                    departure: at(30),
                    arrival: RemoteInstant::from_millis(22),
                    feedback_arrival: at(50),
                },
                Ack {
                    size: bytes(1205),
                    departure: at(50),
                    arrival: RemoteInstant::from_millis(44),
                    feedback_arrival: at(50),
                }
            ],
            sender.process_feedback_and_correlate_acks(feedback.iter(), at(50))
        );
        assert_eq!(3, next_feedback_seqnum);

        // Way past the expiration time for seqnum 4.
        sender.remember_sent(6, bytes(1206), at(20000));
        sender.remember_sent(7, bytes(1207), at(30000));
        let feedback = collect_feedback(write_feedback(
            1000,
            &mut next_feedback_seqnum,
            at(15),
            vec![(4, at(60))].into_iter(),
        ));
        assert_eq!(
            0,
            sender
                .process_feedback_and_correlate_acks(feedback.iter(), at(20000))
                .len()
        );
        assert_eq!(4, next_feedback_seqnum);
    }

    #[test]
    fn test_write_feedback_seqnum_overflow() {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        let mut next_feedback_seqnum = 5;
        let feedback = collect_feedback(write_feedback(
            0x01020304,
            &mut next_feedback_seqnum,
            at(15),
            vec![(1, at(15)), (2, at(38)), (3, at(39)), (0x1_0002, at(59))].into_iter(),
        ));
        assert_eq!(2, feedback.len());

        assert_eq!(
            &hex!(
                "
                      /* ssrc */ 01020304
              /* first_seqnum */ 0001
                     /* count */ 0003
                      /* time */ 000000
                    /* seqnum */ 05
                    /* status */ 2003
                    /* deltas */ 00 5C 04
            "
            )[..],
            &feedback[0][..],
        );
        assert_eq!(
            &hex!(
                "
                      /* ssrc */ 01020304
              /* first_seqnum */ 0002
                     /* count */ 0001
                      /* time */ 000000
                    /* seqnum */ 06
                    /* status */ 2001
                    /* deltas */ B0
            "
            )[..],
            &feedback[1][..],
        );
    }

    #[test]
    fn test_write_feedback_delta_overflow() {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);

        let mut next_feedback_seqnum = 5;
        let feedback = collect_feedback(write_feedback(
            0x01020304,
            &mut next_feedback_seqnum,
            at(15),
            vec![(1, at(15)), (2, at(38)), (3, at(0x100)), (4, at(0x2_0000))].into_iter(),
        ));
        assert_eq!(2, feedback.len());

        assert_eq!(
            &hex!(
                "
                      /* ssrc */ 01020304
              /* first_seqnum */ 0001
                     /* count */ 0003
                      /* time */ 000000
                    /* seqnum */ 05
                    /* status */ D600
                    /* deltas */ 00 5C 0368
            "
            )[..],
            &feedback[0][..],
        );
        assert_eq!(
            &hex!(
                "
                      /* ssrc */ 01020304
              /* first_seqnum */ 0004
                     /* count */ 0001
                      /* time */ 0007FF
                    /* seqnum */ 06
                    /* status */ 2001
                    /* deltas */ C4
            "
            )[..],
            &feedback[1][..],
        );
    }

    #[test]
    fn test_tcc_receiver() {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let ssrc = 1u32;
        let send_acks = |receiver: &mut Receiver| {
            read_all_feedback(collect_feedback(receiver.send_acks()).into_iter())
        };

        let mut receiver = Receiver::new(ssrc, now);
        let empty: Vec<(u8, Vec<(FullSequenceNumber, RemoteInstant)>)> = vec![];
        assert_eq!(empty, send_acks(&mut receiver));
        for seqnum in 1..=2000 {
            receiver.remember_received(seqnum, at(seqnum));
        }
        let feedback = send_acks(&mut receiver);
        // This makes reading a failed diff easier to read.
        assert_eq!(
            vec![(1, 1099), (2, 901)],
            feedback
                .iter()
                .map(|(feedback_seqnum, feedback)| (*feedback_seqnum, feedback.len()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![
                (
                    1,
                    (1..=1099)
                        .map(|seqnum| (seqnum, RemoteInstant::from_millis(seqnum)))
                        .collect::<Vec<_>>()
                ),
                (
                    2,
                    (1100..=2000)
                        .map(|seqnum| (seqnum, RemoteInstant::from_millis(seqnum)))
                        .collect::<Vec<_>>()
                )
            ],
            feedback
        );
        assert_eq!(empty, send_acks(&mut receiver));
    }

    #[test]
    fn test_tcc_receiver_repeat() {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let ssrc = 1u32;
        let send_acks = |receiver: &mut Receiver| {
            read_all_feedback(collect_feedback(receiver.send_acks()).into_iter())
        };

        let mut receiver = Receiver::new(ssrc, now);
        let empty: Vec<(u8, Vec<(FullSequenceNumber, RemoteInstant)>)> = vec![];
        assert_eq!(empty, send_acks(&mut receiver));
        for seqnum in 1..=2000 {
            // Ignore the duplicates.
            receiver.remember_received(seqnum % 1000, at(seqnum));
        }
        let feedback = send_acks(&mut receiver);
        // This makes reading a failed diff easier to read.
        assert_eq!(
            vec![(1, 1000)],
            feedback
                .iter()
                .map(|(feedback_seqnum, feedback)| (*feedback_seqnum, feedback.len()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![(
                1,
                (0..=999)
                    .map(|seqnum| (
                        seqnum,
                        RemoteInstant::from_millis(if seqnum == 0 { 1000 } else { seqnum })
                    ))
                    .collect::<Vec<_>>()
            )],
            feedback
        );
        assert_eq!(empty, send_acks(&mut receiver));
    }

    #[test]
    fn test_packet_status_chunks_run_length_overflow() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1.. {
            chunks.push(PacketStatus::ReceivedSmallDelta);
            if chunks.chunks.len() != 1 {
                break;
            }
            assert_eq!(
                vec![PacketStatusChunk::RunLength {
                    len: i,
                    status: PacketStatus::ReceivedSmallDelta,
                }],
                chunks.chunks
            );
        }
        assert_eq!(
            vec![
                PacketStatusChunk::RunLength {
                    len: 8191,
                    status: PacketStatus::ReceivedSmallDelta,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::ReceivedSmallDelta,
                }
            ],
            chunks.chunks
        );
        assert_eq!(
            ((PacketStatus::ReceivedSmallDelta as u16) << 13) + 8191,
            chunks.chunks[0].as_16(),
        )
    }

    #[test]
    fn test_packet_status_chunks_vector1_overflow() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1.. {
            let next_status = if i % 2 == 0 {
                PacketStatus::NotReceived
            } else {
                PacketStatus::ReceivedSmallDelta
            };
            chunks.push(next_status);
            if chunks.chunks.len() != 1 {
                break;
            }
            if i > 1 {
                let mut expected_bits = 0b10_1010_1010_1010;
                expected_bits >>= 14 - i;
                expected_bits <<= 14 - i;
                assert_eq!(
                    vec![PacketStatusChunk::Vector1 {
                        len: i,
                        bits: expected_bits,
                    }],
                    chunks.chunks
                );
            }
        }
        assert_eq!(
            vec![
                PacketStatusChunk::Vector1 {
                    len: 14,
                    bits: 0b10_1010_1010_1010,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::ReceivedSmallDelta,
                }
            ],
            chunks.chunks
        );
        assert_eq!(0b1010_1010_1010_1010, chunks.chunks[0].as_16());
    }

    #[test]
    fn test_packet_status_chunks_vector2_overflow() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1.. {
            let next_status = if i % 2 == 0 {
                PacketStatus::NotReceived
            } else {
                PacketStatus::ReceivedLargeOrNegativeDelta
            };
            chunks.push(next_status);
            if chunks.chunks.len() != 1 {
                break;
            }
            if i > 1 {
                let mut expected_bits = 0b10_0010_0010_0010;
                expected_bits >>= 2 * (7 - i);
                expected_bits <<= 2 * (7 - i);
                assert_eq!(
                    vec![PacketStatusChunk::Vector2 {
                        len: i,
                        bits: expected_bits,
                    }],
                    chunks.chunks
                );
            }
        }
        assert_eq!(
            vec![
                PacketStatusChunk::Vector2 {
                    len: 7,
                    bits: 0b10_0010_0010_0010,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::NotReceived,
                }
            ],
            chunks.chunks
        );
        assert_eq!(0b1110_0010_0010_0010, chunks.chunks[0].as_16());
    }

    #[test]
    fn test_packet_status_chunks_vector2_overflow_opposite_order() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1.. {
            let next_status = if i % 2 == 0 {
                PacketStatus::ReceivedLargeOrNegativeDelta
            } else {
                PacketStatus::NotReceived
            };
            chunks.push(next_status);
            if chunks.chunks.len() != 1 {
                break;
            }
            if i > 1 {
                let mut expected_bits = 0b00_1000_1000_1000;
                expected_bits >>= 2 * (7 - i);
                expected_bits <<= 2 * (7 - i);
                assert_eq!(
                    vec![PacketStatusChunk::Vector2 {
                        len: i,
                        bits: expected_bits,
                    }],
                    chunks.chunks
                );
            }
        }
        assert_eq!(
            vec![
                PacketStatusChunk::Vector2 {
                    len: 7,
                    bits: 0b00_1000_1000_1000,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::ReceivedLargeOrNegativeDelta,
                }
            ],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_run_length_can_convert_to_vector1() {
        let mut chunks = PacketStatusChunks::new();
        for _ in 1..=13 {
            chunks.push(PacketStatus::ReceivedSmallDelta);
        }
        assert_eq!(
            vec![PacketStatusChunk::RunLength {
                len: 13,
                status: PacketStatus::ReceivedSmallDelta,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::NotReceived);
        assert_eq!(
            vec![PacketStatusChunk::Vector1 {
                len: 14,
                bits: 0b11_1111_1111_1110,
            },],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_run_length_can_convert_to_vector2() {
        let mut chunks = PacketStatusChunks::new();
        for _ in 1..=6 {
            chunks.push(PacketStatus::ReceivedLargeOrNegativeDelta);
        }
        assert_eq!(
            vec![PacketStatusChunk::RunLength {
                len: 6,
                status: PacketStatus::ReceivedLargeOrNegativeDelta,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::ReceivedSmallDelta);
        assert_eq!(
            vec![PacketStatusChunk::Vector2 {
                len: 7,
                bits: 0b10_1010_1010_1001,
            },],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_run_length_cannot_convert_to_vector1_must_split() {
        let mut chunks = PacketStatusChunks::new();
        for _ in 1..=14 {
            chunks.push(PacketStatus::NotReceived);
        }
        assert_eq!(
            vec![PacketStatusChunk::RunLength {
                len: 14,
                status: PacketStatus::NotReceived,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::ReceivedSmallDelta);
        assert_eq!(
            vec![
                PacketStatusChunk::RunLength {
                    len: 14,
                    status: PacketStatus::NotReceived,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::ReceivedSmallDelta,
                }
            ],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_run_length_cannot_convert_to_vector2_must_split() {
        let mut chunks = PacketStatusChunks::new();
        for _ in 1..=7 {
            chunks.push(PacketStatus::ReceivedLargeOrNegativeDelta);
        }
        assert_eq!(
            vec![PacketStatusChunk::RunLength {
                len: 7,
                status: PacketStatus::ReceivedLargeOrNegativeDelta,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::ReceivedSmallDelta);
        assert_eq!(
            vec![
                PacketStatusChunk::RunLength {
                    len: 7,
                    status: PacketStatus::ReceivedLargeOrNegativeDelta,
                },
                PacketStatusChunk::RunLength {
                    len: 1,
                    status: PacketStatus::ReceivedSmallDelta,
                }
            ],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_vector1_can_convert_to_vector2() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1..=6 {
            let next_status = if i % 2 == 0 {
                PacketStatus::NotReceived
            } else {
                PacketStatus::ReceivedSmallDelta
            };
            chunks.push(next_status);
        }
        assert_eq!(
            vec![PacketStatusChunk::Vector1 {
                len: 6,
                bits: 0b10_1010_0000_0000,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::ReceivedLargeOrNegativeDelta);
        assert_eq!(
            vec![PacketStatusChunk::Vector2 {
                len: 7,
                bits: 0b01_0001_0001_0010,
            },],
            chunks.chunks
        );
    }

    #[test]
    fn test_packet_status_chunks_vector1_can_convert_to_two_vector2_chunks() {
        let mut chunks = PacketStatusChunks::new();
        for i in 1..=13 {
            let next_status = if i % 2 == 0 {
                PacketStatus::NotReceived
            } else {
                PacketStatus::ReceivedSmallDelta
            };
            chunks.push(next_status);
        }
        assert_eq!(
            vec![PacketStatusChunk::Vector1 {
                len: 13,
                bits: 0b10_1010_1010_1010,
            }],
            chunks.chunks
        );
        chunks.push(PacketStatus::ReceivedLargeOrNegativeDelta);
        assert_eq!(
            vec![
                PacketStatusChunk::Vector2 {
                    len: 7,
                    bits: 0b01_0001_0001_0001,
                },
                PacketStatusChunk::Vector2 {
                    len: 7,
                    bits: 0b00_0100_0100_0110,
                },
            ],
            chunks.chunks
        );
    }
}
