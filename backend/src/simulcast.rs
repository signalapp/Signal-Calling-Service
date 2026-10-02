//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    cmp::{max, min},
    collections::HashMap,
};

use calling_common::{DataRate, DemuxId, Instant, VideoHeight};
use log::trace;

use crate::call::TARGET_RATE_MINIMUM_ALLOCATION_RATIO;

// This is spatial layers, not temporal layers
#[derive(Clone, Debug)]
pub struct AllocatableVideoLayer {
    pub incoming_rate: DataRate,
    pub incoming_height: VideoHeight,
}

#[derive(Clone, Debug)]
pub struct AllocatableVideo {
    pub sender_demux_id: DemuxId,
    // This is spatial layers, not temporal layers
    // lower index == lower resolution
    pub layers: [AllocatableVideoLayer; 3],
    pub requested_height: VideoHeight,
    pub allocated_layer_index: Option<usize>,
    pub ideal_layer_index: Option<usize>,
    // AKA became active speaker
    pub interesting: Option<Instant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedVideo {
    pub sender_demux_id: DemuxId,
    pub layer_index: usize,
    // It is a convenience to include the following fields.
    // They could be derived from AllocatableVideo + layer_index.
    pub rate: DataRate,
    pub height: VideoHeight,
}

pub fn ideal_video_layer_index(
    requested_height: VideoHeight,
    layers: &[AllocatableVideoLayer],
) -> Option<usize> {
    let has_rate = |layer: &AllocatableVideoLayer| layer.incoming_rate.as_bps() > 0;
    let has_height = |layer: &AllocatableVideoLayer| layer.incoming_height > VideoHeight::from(0);
    let has_height_and_rate = |layer: &AllocatableVideoLayer| has_rate(layer) && has_height(layer);
    let has_enough_height_and_rate = |layer: &AllocatableVideoLayer| {
        layer.incoming_height >= requested_height && has_rate(layer)
    };

    if requested_height == VideoHeight::from(0) {
        // Nothing was requested, so nothing is ideal.
        None
    } else if let Some(first_layer_which_has_enough) =
        layers.iter().position(has_enough_height_and_rate)
    {
        // It's possible for several layers to have the ideal height.
        // The ideal layer is the highest layer with the ideal height.
        let ideal_height = layers[first_layer_which_has_enough].incoming_height;

        layers.iter().rposition(|layer: &AllocatableVideoLayer| {
            layer.incoming_height == ideal_height && has_rate(layer)
        })
    } else {
        // None of the layers have enough height and rate, so just take the
        // highest layer that has any height and rate.
        layers.iter().rposition(has_height_and_rate)
    }
}

pub fn ideal_send_rate(videos: &[AllocatableVideo], max_requested_send_rate: DataRate) -> DataRate {
    let allocatable: DataRate = videos
        .iter()
        .filter_map(|video| {
            let ideal_layer_index = video.ideal_layer_index?;
            Some(video.layers[ideal_layer_index].incoming_rate)
        })
        .sum();
    min(allocatable, max_requested_send_rate)
}

pub fn base_video_layer_index(video: &AllocatableVideo) -> Option<usize> {
    if video.requested_height == VideoHeight::from(0) || video.layers[0].incoming_rate.as_bps() == 0
    {
        // Nothing was requested or the base layer doesn't have a rate
        None
    } else {
        Some(0)
    }
}

pub fn requested_base_rate(
    videos: &[AllocatableVideo],
    max_requested_send_rate: DataRate,
) -> DataRate {
    let allocatable: DataRate = videos
        .iter()
        .filter_map(|video| {
            let base_layer_index = base_video_layer_index(video)?;
            Some(video.layers[base_layer_index].incoming_rate)
        })
        .sum();
    min(allocatable, max_requested_send_rate)
}

pub fn allocate_send_rate(
    target_send_rate: DataRate,
    min_target_send_rate: DataRate,
    ideal_send_rate: DataRate,
    outgoing_queue_drain_rate: DataRate,
    videos: &Vec<AllocatableVideo>,
) -> HashMap<DemuxId, AllocatedVideo> {
    // We leave some target send rate unallocated to allow the queue to drain.
    // But if the ideal rate is lower than the target rate, there is room
    // between the ideal rate and the target rate to drain the queue.

    // First use whichever is greater of (minimum target rate minus queue
    // drain rate) and the minimum allocation ratio.
    let allocatable_rate_for_different_layers = max(
        min_target_send_rate.saturating_sub(outgoing_queue_drain_rate),
        min_target_send_rate * TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
    );
    // Now use the lesser of that result and the ideal send rate; layers
    // must be under this bitrate to be allocated, if not currently
    // selected.
    let allocatable_rate_for_different_layers =
        min(allocatable_rate_for_different_layers, ideal_send_rate);

    // Do the same process with the current target rate
    let allocatable_rate_for_existing_layers = max(
        target_send_rate.saturating_sub(outgoing_queue_drain_rate),
        target_send_rate * TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
    );

    // This bitrate will be equal to or greater than the rate for different
    // layers; allowing more bandwidth to be used to keep a currently
    // selected layer than to switch layers, so there's less layer switching
    // as available bandwidth changes.
    let allocatable_rate_for_existing_layers =
        min(allocatable_rate_for_existing_layers, ideal_send_rate);

    let mut allocated_by_sender_demux_id: HashMap<DemuxId, AllocatedVideo> = HashMap::new();
    let mut allocated_rate = DataRate::ZERO;

    // We try to get the lowest layers for each one before trying to get the higher layer for any one.
    // In the future we may want to allow clients to prioritize a video to a degree
    // that it gets all of its layers first.
    for layer_index in 0..=2 {
        trace!("Allocating layer {}", layer_index);
        for video in videos {
            let mut candidate_layer_index = layer_index;
            let mut layer = &video.layers[candidate_layer_index];

            trace!(
                "Allocating {:?}.{} = ({}, {:?})",
                video.sender_demux_id,
                layer_index,
                layer.incoming_rate.as_kbps(),
                layer.incoming_height
            );
            if layer.incoming_height == VideoHeight::from(0) && layer.incoming_rate.as_bps() == 0 {
                trace!("Skipped layer with nothing coming in.");
                continue;
            }

            if let Some(ideal_layer_index) = video.ideal_layer_index {
                if ideal_layer_index < layer_index {
                    trace!(
                        "Skipped layer that's not requested (ideal layer index: {:?}).",
                        ideal_layer_index
                    );
                    continue;
                }

                for possible_layer_index in layer_index + 1..=ideal_layer_index {
                    let possible_layer = &video.layers[possible_layer_index];
                    if possible_layer.incoming_height != VideoHeight::from(0)
                        && possible_layer.incoming_rate.as_bps() != 0
                        && possible_layer.incoming_rate < layer.incoming_rate
                    {
                        candidate_layer_index = possible_layer_index;
                        layer = possible_layer;
                    }
                }
            } else {
                trace!("Skipped layer that's not requested (ideal layer index: None).");
                continue;
            }

            let layer_rate = layer.incoming_rate;
            let lower_layer_rate = allocated_by_sender_demux_id
                .get(&video.sender_demux_id)
                .map(|allocated| allocated.rate)
                .unwrap_or_default();
            let rate_increase = layer_rate.saturating_sub(lower_layer_rate);
            let increased_allocated_rate = allocated_rate + rate_increase;
            let allocatable_rate = if Some(candidate_layer_index) == video.allocated_layer_index {
                allocatable_rate_for_existing_layers
            } else {
                allocatable_rate_for_different_layers
            };

            if increased_allocated_rate > allocatable_rate {
                trace!(
                    "Skipped layer that's too big ({}/{} allocated and {}={}-{} increase)",
                    allocated_rate.as_kbps(),
                    allocatable_rate.as_kbps(),
                    rate_increase.as_kbps(),
                    layer_rate.as_kbps(),
                    lower_layer_rate.as_kbps()
                );
                continue;
            }

            allocated_by_sender_demux_id.insert(
                video.sender_demux_id,
                AllocatedVideo {
                    sender_demux_id: video.sender_demux_id,
                    layer_index: candidate_layer_index,
                    rate: layer.incoming_rate,
                    height: layer.incoming_height,
                },
            );

            allocated_rate = increased_allocated_rate;
            trace!(
                "Allocated layer.  New allocated_rate: {:?}",
                allocated_rate.as_kbps()
            );
        }
    }

    allocated_by_sender_demux_id
}
