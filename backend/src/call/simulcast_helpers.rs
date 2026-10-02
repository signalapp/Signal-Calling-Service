//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use calling_common::{DataRate, DemuxId};
use log::warn;

use crate::{
    call::{Client, Clients, LayerId, Vp8SimulcastRtpForwarder},
    simulcast,
    simulcast::AllocatableVideo,
};

/// Determines which video layers should be forwarded from other clients to
/// `receiver_demux_id` based on what congestion control calculated.
pub(super) fn allocate_video_layers(
    clients: &mut Clients,
    receiver_demux_id: DemuxId,
    new_target_send_rate: DataRate,
    min_target_send_rate: DataRate,
    ideal_send_rate: DataRate,
    drain_rate: DataRate,
    allocatable_videos: &Vec<AllocatableVideo>,
) -> DataRate {
    let Some(receiver) = clients.get_mut(receiver_demux_id) else {
        warn!("allocate_video_layers called with a bad demux id: {receiver_demux_id:?}");
        return DataRate::ZERO;
    };

    let allocated_video_by_sender_demux_id = simulcast::allocate_send_rate(
        new_target_send_rate,
        min_target_send_rate,
        ideal_send_rate,
        drain_rate,
        allocatable_videos,
    );

    // We have to collect these because we can't get a mutable ref to the receiver while getting
    // immutable refs to the senders.
    let sender_demux_ids: Vec<DemuxId> = allocatable_videos
        .iter()
        .map(|video| video.sender_demux_id)
        .filter(|sender_demux_id| *sender_demux_id != receiver.demux_id)
        .collect();

    receiver.allocated_height_by_sender_demux_id.clear();
    for sender_demux_id in sender_demux_ids {
        let desired_incoming_ssrc = allocated_video_by_sender_demux_id
            .get(&sender_demux_id)
            .map(|allocated_video| {
                receiver
                    .allocated_height_by_sender_demux_id
                    .insert(sender_demux_id, allocated_video.height);

                let layer_id =
                    LayerId::from_video_layer_index(allocated_video.layer_index).unwrap();
                layer_id.to_ssrc(allocated_video.sender_demux_id)
            });
        let forwarder = receiver
            .video_forwarder_by_sender_demux_id
            .entry(sender_demux_id)
            .or_insert_with(|| {
                let outgoing_ssrc = LayerId::Video0.to_ssrc(sender_demux_id);
                Vp8SimulcastRtpForwarder::new(outgoing_ssrc)
            });
        forwarder.set_desired_ssrc(desired_incoming_ssrc);
    }

    // Calculate the total allocate rate
    allocated_video_by_sender_demux_id
        .values()
        .map(|allocated| allocated.rate)
        .sum()
}

/// Builds a list of `AllocatableVideo` structures for the given receiver, one for
/// each sender. The structures are sorted by the requested height, and by the time
/// the sender last became active speaker.
pub(super) fn get_allocatable_videos(
    clients: &Clients,
    receiver: &Client,
    active_speaker_id: Option<DemuxId>,
) -> Vec<AllocatableVideo> {
    let mut allocatable_videos = clients
        .iter()
        .filter_map(|sender| {
            // Ignore SVC sources and the receiver itself
            if sender.scalable_video_state.is_some() || sender.demux_id == receiver.demux_id {
                return None;
            }

            let requested_height =
                receiver.requested_height_for(sender.demux_id, active_speaker_id);

            let allocated_layer_index = receiver
                .video_forwarder_by_sender_demux_id
                .get(&sender.demux_id)
                .and_then(|f| f.forwarding_ssrc())
                .and_then(LayerId::layer_index_from_ssrc);

            let layers = sender
                .incoming_video
                .each_ref()
                .map(|v| v.as_allocatable_layer());

            let ideal_layer_index = simulcast::ideal_video_layer_index(requested_height, &layers);

            Some(AllocatableVideo {
                sender_demux_id: sender.demux_id,
                layers: sender
                    .incoming_video
                    .each_ref()
                    .map(|v| v.as_allocatable_layer()),
                requested_height,
                allocated_layer_index,
                ideal_layer_index,
                interesting: sender.became_active_speaker,
            })
        })
        .collect::<Vec<AllocatableVideo>>();

    // Biggest first and then (for the same size), most recently interesting first
    allocatable_videos
        .sort_by_key(|video| std::cmp::Reverse((video.requested_height, video.interesting)));

    allocatable_videos
}
