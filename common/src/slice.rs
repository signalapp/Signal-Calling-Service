//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub trait ReadSliceExt: std::io::Read {
    /// Like `std::io::read_exact`, but borrows from `self` instead.
    fn read_slice(&mut self, n: usize) -> std::io::Result<&[u8]>;
}

impl ReadSliceExt for &'_ [u8] {
    fn read_slice(&mut self, n: usize) -> std::io::Result<&[u8]> {
        if self.len() < n {
            Err(std::io::ErrorKind::UnexpectedEof.into())
        } else {
            let (result, rest) = self.split_at(n);
            *self = rest;
            Ok(result)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty() {
        let mut slice: &[u8] = &[];

        assert_eq!(&[] as &[u8], slice.read_slice(0).unwrap());
        assert_eq!(&[] as &[u8], slice);

        assert_eq!(
            std::io::ErrorKind::UnexpectedEof,
            slice.read_slice(1).unwrap_err().kind()
        );
    }

    #[test]
    fn test_nonempty() {
        let mut slice: &[u8] = &[1, 2, 3];

        assert_eq!(&[] as &[u8], slice.read_slice(0).unwrap());
        assert_eq!(&[1, 2, 3], slice);

        assert_eq!(&[1, 2], slice.read_slice(2).unwrap());
        assert_eq!(&[3], slice);

        assert_eq!(&[3], slice.read_slice(1).unwrap());
        assert_eq!(&[] as &[u8], slice);
    }

    #[test]
    fn test_eof() {
        let mut slice: &[u8] = &[1, 2, 3];
        assert_eq!(
            std::io::ErrorKind::UnexpectedEof,
            slice.read_slice(4).unwrap_err().kind()
        );
    }
}
