//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{cmp::Ordering, collections::BinaryHeap};

use crate::rtp::{FullSequenceNumber, Packet};

/// Simple packet buffer. Stores up to some maximum number of packets via
/// [`PacketBuffer::push_packet_and_yield`], before it starts yielding packets. The packets
/// that it yields are ordered by their seqnum.
///
/// Note that this packet buffer will not de-duplicate packets. If packets with the same seqnum
/// are pushed into the buffer, both packets will potentially (or eventually) be yielded.
#[derive(Debug)]
pub struct PacketBuffer {
    max_packets: usize,
    // Note: since we always want to yield the smallest element, this is a min-heap;
    // BufferedPacket's Ord implementation reverses the comparison of seqnums in order
    // to achieve this.
    packets: BinaryHeap<BufferedPacket>,
}

#[derive(Debug)]
struct BufferedPacket {
    seqnum: FullSequenceNumber,
    packet: Box<Packet<Vec<u8>>>,
}

impl BufferedPacket {
    fn new(packet: &Packet<&[u8]>) -> Self {
        Self {
            seqnum: packet.seqnum(),
            packet: Box::new(packet.to_owned()),
        }
    }
}

impl Eq for BufferedPacket {}

impl PartialEq for BufferedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seqnum == other.seqnum
    }
}

impl Ord for BufferedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seqnum.cmp(&other.seqnum).reverse()
    }
}

impl PartialOrd for BufferedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PacketBuffer {
    /// Creates a new `PacketBuffer` instance. Up to `max_packets` will be buffered before
    /// the buffer starts yielding packets.
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            packets: BinaryHeap::with_capacity(max_packets + 1),
        }
    }

    /// Removes all packets that are currently in the buffer. The packets in the returned
    /// vector are sorted according to their seqnums, in the ascending order.
    pub fn drain(&mut self) -> Vec<Packet<Vec<u8>>> {
        let mut packets = Vec::with_capacity(self.packets.len());
        while let Some(buffered) = self.packets.pop() {
            packets.push(*buffered.packet);
        }
        packets
    }

    /// Pushes a packet into the buffer. If the buffer is full, a buffered packet with the smallest
    /// seqnum will be removed from the buffer and yielded.
    pub fn push_packet_and_yield(&mut self, packet: &Packet<&[u8]>) -> Option<Packet<Vec<u8>>> {
        self.packets.push(BufferedPacket::new(packet));
        if self.packets.len() > self.max_packets {
            self.packets.pop().map(|buffered| *buffered.packet)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::{DependencyDescriptor, MandatoryDescriptorFields, VP9_PAYLOAD_TYPE};

    fn make_packet(seqnum: FullSequenceNumber) -> Packet<Vec<u8>> {
        Packet::with_dependency_descriptor(
            VP9_PAYLOAD_TYPE,
            seqnum,
            0,
            0x12345678,
            DependencyDescriptor {
                mandatory_fields: MandatoryDescriptorFields {
                    start_of_frame: true,
                    end_of_frame: true,
                    frame_dependency_template_id: 0,
                    frame_number: seqnum as u16,
                },
                extended_fields: None,
            },
            &[],
        )
    }

    fn seqnums(packets: &[Packet<Vec<u8>>]) -> Vec<FullSequenceNumber> {
        packets.iter().map(|p| p.seqnum()).collect()
    }

    // --- push_packet: capacity ---

    #[test]
    fn push_packet_does_not_yield_until_full() {
        let mut buf = PacketBuffer::new(3);
        assert!(
            buf.push_packet_and_yield(&make_packet(1).borrow())
                .is_none()
        );
        assert!(
            buf.push_packet_and_yield(&make_packet(2).borrow())
                .is_none()
        );
        assert!(
            buf.push_packet_and_yield(&make_packet(3).borrow())
                .is_none()
        );
    }

    #[test]
    fn push_packet_yields_on_overflow() {
        let mut buf = PacketBuffer::new(3);
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        buf.push_packet_and_yield(&make_packet(3).borrow());
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(4).borrow())
                .unwrap()
                .seqnum(),
            1
        );
    }

    #[test]
    fn push_packet_max_zero_is_passthrough() {
        let mut buf = PacketBuffer::new(0);
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(5).borrow())
                .unwrap()
                .seqnum(),
            5
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(3).borrow())
                .unwrap()
                .seqnum(),
            3
        );
    }

    // --- push_packet: ordering ---

    #[test]
    fn push_packet_yields_in_seqnum_order_for_in_order_arrivals() {
        let mut buf = PacketBuffer::new(3);
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        buf.push_packet_and_yield(&make_packet(3).borrow());
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(4).borrow())
                .unwrap()
                .seqnum(),
            1
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(5).borrow())
                .unwrap()
                .seqnum(),
            2
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(6).borrow())
                .unwrap()
                .seqnum(),
            3
        );
    }

    #[test]
    fn push_packet_reorders_out_of_order_arrivals() {
        let mut buf = PacketBuffer::new(4);
        buf.push_packet_and_yield(&make_packet(3).borrow());
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(4).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(5).borrow())
                .unwrap()
                .seqnum(),
            1
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(6).borrow())
                .unwrap()
                .seqnum(),
            2
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(7).borrow())
                .unwrap()
                .seqnum(),
            3
        );
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(8).borrow())
                .unwrap()
                .seqnum(),
            4
        );
    }

    #[test]
    fn push_packet_late_arrival_beyond_window_returned_immediately() {
        // Buffer is full with [10, 11, 12, 13]. A very late packet (seqnum 2) is the
        // minimum across all buffered packets, so it comes straight back out.
        let mut buf = PacketBuffer::new(4);
        buf.push_packet_and_yield(&make_packet(10).borrow());
        buf.push_packet_and_yield(&make_packet(11).borrow());
        buf.push_packet_and_yield(&make_packet(12).borrow());
        buf.push_packet_and_yield(&make_packet(13).borrow());
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(2).borrow())
                .unwrap()
                .seqnum(),
            2
        );
        // The window [10, 11, 12, 13] remains intact.
        assert_eq!(seqnums(&buf.drain()), vec![10, 11, 12, 13]);
    }

    // --- drain ---

    #[test]
    fn drain_empty_buffer_returns_empty() {
        let mut buf = PacketBuffer::new(5);
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn drain_returns_all_buffered_packets_ascending() {
        let mut buf = PacketBuffer::new(5);
        buf.push_packet_and_yield(&make_packet(3).borrow());
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(5).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        buf.push_packet_and_yield(&make_packet(4).borrow());
        assert_eq!(seqnums(&buf.drain()), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn drain_partial_fill_is_sorted() {
        let mut buf = PacketBuffer::new(5);
        buf.push_packet_and_yield(&make_packet(3).borrow());
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        assert_eq!(seqnums(&buf.drain()), vec![1, 2, 3]);
    }

    #[test]
    fn drain_empties_buffer_and_subsequent_pushes_rebuffer() {
        let mut buf = PacketBuffer::new(2);
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        buf.drain();
        // Buffer is now empty; two more pushes should buffer without yielding.
        assert!(
            buf.push_packet_and_yield(&make_packet(3).borrow())
                .is_none()
        );
        assert!(
            buf.push_packet_and_yield(&make_packet(4).borrow())
                .is_none()
        );
        // Third push overflows again.
        assert_eq!(
            buf.push_packet_and_yield(&make_packet(5).borrow())
                .unwrap()
                .seqnum(),
            3
        );
    }

    #[test]
    fn drain_after_partial_overflow_returns_remainder_sorted() {
        let mut buf = PacketBuffer::new(3);
        buf.push_packet_and_yield(&make_packet(1).borrow());
        buf.push_packet_and_yield(&make_packet(2).borrow());
        buf.push_packet_and_yield(&make_packet(3).borrow());
        buf.push_packet_and_yield(&make_packet(4).borrow()); // yields seqnum 1
        // Remaining buffer: [2, 3, 4]
        assert_eq!(seqnums(&buf.drain()), vec![2, 3, 4]);
    }

    // --- duplicate seqnums ---

    #[test]
    fn duplicate_seqnum_both_copies_eventually_returned() {
        let mut buf = PacketBuffer::new(1);
        buf.push_packet_and_yield(&make_packet(5).borrow()); // buffered
        let first = buf.push_packet_and_yield(&make_packet(5).borrow()).unwrap(); // overflow: one copy out
        assert_eq!(first.seqnum(), 5);
        let remaining = buf.drain();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].seqnum(), 5);
    }
}
