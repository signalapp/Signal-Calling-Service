//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use calling_common::DemuxId;
use log::error;

use crate::{
    call::{Client, Clients},
    svc::allocator::{SelectedDecodeTargets, SenderAllocationInfo},
};

/// Builds a list of `SenderAllocationInfo` structures, one for each SVC sender.
/// This list is then submitted to an implementation of an SVC allocator. The returned
/// array of [`SenderAllocationInfo`] structures is sorted by the (requested height,
/// active speaker time) key, in reverse order.
pub(super) fn get_sender_allocation_info<'a>(
    clients: &'a Clients,
    receiver: &'a Client,
    active_speaker_id: Option<DemuxId>,
) -> Vec<SenderAllocationInfo<'a>> {
    let mut sender_allocation_info: Vec<_> = clients
        .iter()
        .filter_map(|client| {
            if let Some(svc_state) = client.scalable_video_state.as_ref()
                && client.demux_id != receiver.demux_id
            {
                let requested_height =
                    Some(receiver.requested_height_for(client.demux_id, active_speaker_id));
                let decode_target_info_list = svc_state.get_decode_targets();
                let active_decode_target =
                    svc_state.get_decode_target_for_receiver(receiver.demux_id);
                Some(SenderAllocationInfo {
                    demux_id: client.demux_id,
                    became_active_speaker: client.became_active_speaker,
                    decode_target_info_list,
                    requested_height,
                    active_decode_target,
                })
            } else {
                None
            }
        })
        .collect();

    sender_allocation_info.sort_by_key(|target_info| {
        std::cmp::Reverse((
            target_info.requested_height,
            target_info.became_active_speaker,
        ))
    });

    sender_allocation_info
}

/// Updates decode targets for the given receiver. This only affects SVC senders
/// identified in the given `SelectedDecodeTargets` structure.
pub(super) fn update_selected_targets(
    clients: &mut Clients,
    receiver_demux_id: DemuxId,
    selected_decode_targets: &SelectedDecodeTargets,
) {
    for selected_decode_target in selected_decode_targets {
        if selected_decode_target.demux_id == receiver_demux_id {
            continue;
        }
        let Some(svc_state) = clients
            .get_mut(selected_decode_target.demux_id)
            .and_then(|client| client.scalable_video_state.as_mut())
        else {
            continue;
        };
        if let Err(e) = svc_state
            .set_decode_target_for_receiver(receiver_demux_id, selected_decode_target.decode_target)
        {
            error!(
                "svc: {receiver_demux_id:?}: failed to set decode target: {:?}: {e}",
                selected_decode_target.decode_target
            );
        }
    }
}
