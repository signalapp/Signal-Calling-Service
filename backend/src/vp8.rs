//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use calling_common::expand_truncated_counter;

pub type TruncatedPictureId = u16;
pub type FullPictureId = u64;
pub type TruncatedTl0PicIdx = u8;
pub type FullTl0PicIdx = u64;

// This assumes that the picture ID and TL0 PIC IDX are present in the packet
// and that the picture ID is of the 15-bit variety.
// If they aren't, the payload will be corrupted
pub fn modify_header(
    rtp_payload: &mut [u8],
    picture_id: TruncatedPictureId,
    tl0_pic_idx: TruncatedTl0PicIdx,
) {
    rtp_payload[2..4].copy_from_slice(&((picture_id | 0b1000_0000_0000_0000).to_be_bytes()));
    rtp_payload[4] = tl0_pic_idx;
}

pub fn expand_picture_id(truncated: TruncatedPictureId, max: &mut FullPictureId) -> FullPictureId {
    expand_truncated_counter(truncated, max, 15)
}

pub fn expand_tl0_pic_idx(truncated: TruncatedTl0PicIdx, max: &mut FullTl0PicIdx) -> FullTl0PicIdx {
    expand_truncated_counter(truncated, max, 8)
}
