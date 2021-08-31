//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::VecDeque;

/// A fixed size RingBuffer. On insert drops the oldest inserted item iff full.
pub struct RingBuffer<T> {
    limit: usize,
    values: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            // + 1 as we push before pop
            values: VecDeque::with_capacity(limit + 1),
        }
    }

    /// Iff pushing popped off an old value, return it.
    pub fn push(&mut self, value: T) -> Option<T> {
        self.values.push_back(value);
        if self.values.len() > self.limit {
            self.values.pop_front()
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + ExactSizeIterator + Clone + '_ {
        self.values.iter()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::RingBuffer;

    #[test]
    fn is_empty() {
        let mut buffer = RingBuffer::new(3);
        assert!(buffer.is_empty());
        buffer.push(1);
        assert!(!buffer.is_empty());
        buffer.push(2);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn len() {
        let mut buffer = RingBuffer::new(3);
        assert_eq!(0, buffer.len());
        buffer.push(1);
        assert_eq!(1, buffer.len());
        buffer.push(1);
        assert_eq!(2, buffer.len());
        buffer.push(1);
        assert_eq!(3, buffer.len());
        buffer.push(1);
        assert_eq!(3, buffer.len());
    }

    #[test]
    fn full() {
        let mut buffer = RingBuffer::new(3);
        assert!(!buffer.is_full());
        buffer.push(1);
        assert!(!buffer.is_full());
        buffer.push(1);
        assert!(!buffer.is_full());
        buffer.push(1);
        assert!(buffer.is_full());
        buffer.push(2);
        assert!(buffer.is_full());
    }

    #[test]
    fn push_to_limit() {
        let mut buffer = RingBuffer::new(3);
        assert_eq!(None, buffer.push(1));
        assert_eq!(None, buffer.push(3));
        assert_eq!(None, buffer.push(5));
        assert_eq!(vec![1, 3, 5], buffer.iter().copied().collect::<Vec<_>>());
    }

    #[test]
    fn push_beyond_limit() {
        let mut buffer = RingBuffer::new(2);
        assert_eq!(None, buffer.push(1));
        assert_eq!(None, buffer.push(3));
        assert_eq!(Some(1), buffer.push(5));
        assert_eq!(vec![3, 5], buffer.iter().copied().collect::<Vec<_>>());
    }

    #[test]
    fn push_beyond_twice_limit() {
        let mut buffer = RingBuffer::new(2);
        assert_eq!(None, buffer.push(1));
        assert_eq!(None, buffer.push(3));
        assert_eq!(Some(1), buffer.push(5));
        assert_eq!(Some(3), buffer.push(7));
        assert_eq!(Some(5), buffer.push(9));
        assert_eq!(vec![7, 9], buffer.iter().copied().collect::<Vec<_>>());
    }
}
