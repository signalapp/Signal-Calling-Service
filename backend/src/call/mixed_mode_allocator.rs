//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::min;

use calling_common::{DataRate, DemuxId, Instant, VideoHeight};
use log::warn;
use metrics::{metric_config::TimingOptions, time_scope};

use crate::{
    call::{Clients, TARGET_RATE_MINIMUM_ALLOCATION_RATIO, simulcast_helpers, svc_helpers},
    simulcast::{self, AllocatableVideo},
    svc::{self, allocator::SenderAllocationInfo},
};

/// Performs a full reallocation, invoking `allocate` for every receiver in the call at
/// their current send rate.
pub(super) fn reallocate(clients: &mut Clients, active_speaker_id: Option<DemuxId>, now: Instant) {
    time_scope!(
        "calling.allocator.call_allocate",
        TimingOptions::microsecond_1000_per_minute()
    );

    let receivers: Vec<_> = clients
        .iter()
        .map(|client| (client.demux_id, client.target_send_rate))
        .collect();

    for (receiver_demux_id, target_send_rate) in receivers {
        allocate(
            clients,
            receiver_demux_id,
            active_speaker_id,
            target_send_rate,
            now,
        );
    }
}

/// The priority sender's lowest possible rate (base rate), and whether the layer or decode
/// target carrying it is the one already being forwarded to the receiver.
struct PrioritySenderBase {
    rate: DataRate,
    forwarded: bool,
}

/// Represents the pool (SVC/simulcast) the priority sender is in, and the sender's base.
enum PrioritySenderInfo {
    Svc(PrioritySenderBase),
    Simulcast(PrioritySenderBase),
}

/// Finds the priority sender. The parameters are lists of allocation info structures, containing
/// simulcast and SVC allocation information, respectively, for each sender.
/// Both of the lists are expected to have been sorted in the descending
/// (height, last-time-became-speaker) order. Consequently, each list will have its own
/// priority sender as the very first element. This function determines which sender, if
/// any, is the "real" priority sender.
///
/// In the unlikely event of a tie (both height and last-time-became-speaker) are the same,
/// this function will prefer the SVC priority sender.
///
/// Returns the sender's pool and base, or `None` if there are no senders, if the receiver has
/// not requested the sender's video, or if its rate cannot be determined.
fn get_priority_sender_info(
    simulcast_allocatable_videos: &[AllocatableVideo],
    svc_sender_allocation_info: &[SenderAllocationInfo<'_>],
) -> Option<PrioritySenderInfo> {
    let (sender_info, allocatable_video) = (
        svc_sender_allocation_info.first(),
        simulcast_allocatable_videos.first(),
    );
    let is_svc = match (sender_info, allocatable_video) {
        (Some(info), Some(video)) => {
            (
                info.requested_height.unwrap_or_default(),
                info.became_active_speaker,
            ) >= (video.requested_height, video.interesting)
        }
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => return None,
    };

    if is_svc {
        // SVC pool: find the sender's lowermost decode target.
        // We cannot get here if sender_info is None.
        let sender_info = sender_info.expect("SVC has the priority sender");
        // Ignore a suppressed sender (height is zero).
        if sender_info
            .requested_height
            .is_some_and(|v| v == VideoHeight::from(0))
        {
            return None;
        }
        let decode_target = sender_info
            .decode_target_info_list
            .iter()
            .position(|info| info.rate != DataRate::ZERO)?;
        Some(PrioritySenderInfo::Svc(PrioritySenderBase {
            rate: sender_info.decode_target_info_list[decode_target].rate,
            forwarded: sender_info.active_decode_target == Some(decode_target),
        }))
    } else {
        // Simulcast pool: find the sender's lowermost video layer.
        // We cannot get here if allocatable_video is None.
        let allocatable_video = allocatable_video.expect("simulcast has the priority sender");
        // Ignore a suppressed sender (no ideal layer).
        allocatable_video.ideal_layer_index?;
        let layer_index = allocatable_video
            .layers
            .iter()
            .position(|layer| layer.incoming_rate != DataRate::ZERO)?;
        Some(PrioritySenderInfo::Simulcast(PrioritySenderBase {
            rate: allocatable_video.layers[layer_index].incoming_rate,
            forwarded: allocatable_video.allocated_layer_index == Some(layer_index),
        }))
    }
}

struct SplitTargetSendRateArgs<'a> {
    target_send_rate: DataRate,
    min_target_send_rate: DataRate,
    drain_rate: DataRate,
    svc_target_rate_fraction: f64,
    simulcast_target_rate_fraction: f64,
    svc_requested_base_rate: DataRate,
    simulcast_requested_base_rate: DataRate,
    svc_sender_allocation_info: &'a [SenderAllocationInfo<'a>],
    simulcast_allocatable_videos: &'a [AllocatableVideo],
}

/// Divides `target_send_rate` between the SVC and simulcast pools. Each pool's base rate is
/// reserved first, and only the surplus is split in proportion to ideal demand. If both base
/// rates don't fit, the split is proportional, except that a pool never keeps more than its
/// reservation while the other pool is short of its own.
///
/// Just enough is then moved into the priority sender's pool (see `get_priority_sender_info`)
/// to cover the priority sender's base rate, if necessary.
///
/// Reserved rates are scaled up so that they survive `drain_rate`.
///
/// The priority sender's base rate, if it isn't being forwarded yet, is also scaled so that
/// it survives a running minimum (`min_target_send_rate`) that lags the target.
///
/// Both sender lists must be sorted the way the pool allocators sort them.
fn split_target_send_rate(args: SplitTargetSendRateArgs<'_>) -> (DataRate, DataRate) {
    /// Headroom that absorbs the truncating `DataRate` arithmetic between a pool's reservation
    /// and the budget its allocator derives from it.
    const ROUNDING_MARGIN: DataRate = DataRate::from_bps(4);

    /// Scales `rate`, plus the rounding margin, up so that `fraction` of the result still covers
    /// it. A zero rate stays zero.
    fn scale_rate(rate: DataRate, fraction: f64) -> DataRate {
        if rate > DataRate::ZERO {
            (rate + ROUNDING_MARGIN) * (1.0 / fraction)
        } else {
            DataRate::ZERO
        }
    }

    let SplitTargetSendRateArgs {
        target_send_rate,
        min_target_send_rate,
        drain_rate,
        svc_target_rate_fraction,
        simulcast_target_rate_fraction,
        svc_requested_base_rate,
        simulcast_requested_base_rate,
        svc_sender_allocation_info,
        simulcast_allocatable_videos,
    } = args;

    // The fractions of a pool's share its allocator can spend on layers it is already
    // forwarding, and on layers it isn't. This is exactly how the pool allocators derive
    // their budgets from the pool's share of the running minimum and the drain rate.
    let (spendable_fraction, change_fraction) = if target_send_rate > DataRate::ZERO {
        let min_target_send_rate = min(min_target_send_rate, target_send_rate);
        let drain_rate = min(drain_rate, target_send_rate);
        (
            f64::max(
                1.0 - (drain_rate / target_send_rate),
                TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
            ),
            f64::max(
                min_target_send_rate.saturating_sub(drain_rate) / target_send_rate,
                min_target_send_rate / target_send_rate * TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
            ),
        )
    } else {
        (1.0, 1.0)
    };

    let svc_reserved_rate = scale_rate(svc_requested_base_rate, spendable_fraction);
    let simulcast_reserved_rate = scale_rate(simulcast_requested_base_rate, spendable_fraction);
    let reserved = svc_reserved_rate + simulcast_reserved_rate;
    let (svc_rate, simulcast_rate) = if reserved <= target_send_rate {
        let surplus = target_send_rate - reserved;
        (
            svc_reserved_rate + surplus * svc_target_rate_fraction,
            simulcast_reserved_rate + surplus * simulcast_target_rate_fraction,
        )
    } else {
        // Not enough for both pools' reservations. Split in proportion to ideal demand, but
        // never leave a pool more than its reservation while the other pool is short.
        let svc_rate = target_send_rate * svc_target_rate_fraction;
        let simulcast_rate = target_send_rate * simulcast_target_rate_fraction;
        if svc_rate > svc_reserved_rate {
            (svc_reserved_rate, target_send_rate - svc_reserved_rate)
        } else if simulcast_rate > simulcast_reserved_rate {
            (
                target_send_rate - simulcast_reserved_rate,
                simulcast_reserved_rate,
            )
        } else {
            (svc_rate, simulcast_rate)
        }
    };

    // How much to move into the priority sender's pool so that its allocator can forward the
    // priority sender's base layer: nothing if the pool already can, or if the priority sender
    // wouldn't fit in the whole target.
    let priority_rate_to_transfer =
        |base: PrioritySenderBase, priority_pool_rate: DataRate, other_pool_rate| {
            let fraction = if base.forwarded {
                spendable_fraction
            } else {
                change_fraction
            };
            if fraction <= 0.0 {
                return DataRate::ZERO;
            }
            let required_rate = scale_rate(base.rate, fraction);
            if required_rate > target_send_rate {
                return DataRate::ZERO;
            }
            min(
                required_rate.saturating_sub(priority_pool_rate),
                other_pool_rate,
            )
        };

    let priority_sender =
        get_priority_sender_info(simulcast_allocatable_videos, svc_sender_allocation_info);
    match priority_sender {
        Some(PrioritySenderInfo::Svc(base)) => {
            let delta = priority_rate_to_transfer(base, svc_rate, simulcast_rate);
            (svc_rate + delta, simulcast_rate - delta)
        }
        Some(PrioritySenderInfo::Simulcast(base)) => {
            let delta = priority_rate_to_transfer(base, simulcast_rate, svc_rate);
            (svc_rate - delta, simulcast_rate + delta)
        }
        None => (svc_rate, simulcast_rate),
    }
}

/// Scales a receiver-wide rate, such as the running minimum send rate or the outgoing queue
/// drain rate, into one pool's share of the budget.
fn scale_to_pool_share(
    rate: DataRate,
    pool_target_send_rate: DataRate,
    allocation_target_send_rate: DataRate,
) -> DataRate {
    if allocation_target_send_rate == DataRate::ZERO {
        return DataRate::ZERO;
    }
    let capped_rate = min(rate, allocation_target_send_rate);
    capped_rate * (pool_target_send_rate / allocation_target_send_rate)
}

/// Performs a complete allocation for a single receiver.
pub(super) fn allocate(
    clients: &mut Clients,
    receiver_demux_id: DemuxId,
    active_speaker_demux_id: Option<DemuxId>,
    target_send_rate: DataRate,
    now: Instant,
) {
    let Some(client) = clients.get(receiver_demux_id) else {
        warn!("Attempting to allocate for a non-existent client: {receiver_demux_id:?}");
        return;
    };

    time_scope!(
        "calling.allocator.receiver_allocate",
        TimingOptions::microsecond_1000_per_minute()
    );

    let simulcast_allocatable_videos =
        simulcast_helpers::get_allocatable_videos(clients, client, active_speaker_demux_id);
    let svc_sender_allocation_info =
        svc_helpers::get_sender_allocation_info(clients, client, active_speaker_demux_id);

    let min_target_send_rate = client.min_target_send_rate();
    let requested_max_send_rate = client.requested_max_send_rate;

    // Determine the allocation target send rate.
    let allocation_target_send_rate = min(target_send_rate, requested_max_send_rate);

    // Get the ideal send rate for the simulcast senders.
    let simulcast_ideal_send_rate_uncapped =
        simulcast::ideal_send_rate(&simulcast_allocatable_videos);
    let simulcast_ideal_send_rate =
        min(simulcast_ideal_send_rate_uncapped, requested_max_send_rate);

    // Get the ideal send rate for the SVC senders.
    let svc_ideal_decode_targets =
        svc::allocator::find_ideal_decode_targets(&svc_sender_allocation_info);
    let svc_ideal_send_rate_uncapped = svc::allocator::calculate_ideal_send_rate(
        &svc_sender_allocation_info,
        &svc_ideal_decode_targets,
    );

    // Determine the requested base rates
    let simulcast_requested_base_rate =
        simulcast::requested_base_rate(&simulcast_allocatable_videos, requested_max_send_rate);
    let svc_requested_base_rate = min(
        svc::allocator::calculate_base_rate(&svc_sender_allocation_info, &svc_ideal_decode_targets),
        requested_max_send_rate,
    );

    // Determine the proportional split between SVC and simulcast.
    let ideal_total = svc_ideal_send_rate_uncapped + simulcast_ideal_send_rate_uncapped;
    let (svc_target_rate_fraction, simulcast_target_rate_fraction) = if ideal_total > DataRate::ZERO
    {
        let svc_frac = svc_ideal_send_rate_uncapped / ideal_total;
        (svc_frac, 1.0 - svc_frac)
    } else {
        (0.0, 0.0)
    };

    // Derive the actual bandwidth partition sizes.
    let (svc_target_send_rate, simulcast_target_send_rate) =
        split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: allocation_target_send_rate,
            min_target_send_rate,
            drain_rate: client.outgoing_queue_drain_rate,
            svc_target_rate_fraction,
            simulcast_target_rate_fraction,
            svc_requested_base_rate,
            simulcast_requested_base_rate,
            svc_sender_allocation_info: &svc_sender_allocation_info,
            simulcast_allocatable_videos: &simulcast_allocatable_videos,
        });

    // Adjust the drain rates
    let simulcast_drain_rate = scale_to_pool_share(
        client.outgoing_queue_drain_rate,
        simulcast_target_send_rate,
        allocation_target_send_rate,
    );
    let svc_drain_rate = scale_to_pool_share(
        client.outgoing_queue_drain_rate,
        svc_target_send_rate,
        allocation_target_send_rate,
    );

    // Perform the actual allocation for the SVC senders against the SVC share of the budget.
    // The minimum is scaled by the share the pool actually received, not by the raw
    // ideal-demand fraction.
    let svc_min_target_send_rate = scale_to_pool_share(
        min_target_send_rate,
        svc_target_send_rate,
        allocation_target_send_rate,
    );

    let svc::allocator::AllocationResult {
        allocated_rate: svc_allocated_rate,
        selected_decode_targets: svc_selected_decode_targets,
    } = svc::allocator::allocate(
        svc_target_send_rate,
        svc_min_target_send_rate,
        TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
        svc_drain_rate,
        svc_ideal_send_rate_uncapped,
        &svc_sender_allocation_info,
        &svc_ideal_decode_targets,
    );

    // Perform the actual allocation for the simulcast senders against the simulcast share of
    // the budget. The minimum is scaled by the share the pool actually received, not by
    // the raw ideal-demand fraction.
    let simulcast_min_target_send_rate = scale_to_pool_share(
        min_target_send_rate,
        simulcast_target_send_rate,
        allocation_target_send_rate,
    );
    let simulcast_allocated_rate = simulcast_helpers::allocate_video_layers(
        clients,
        receiver_demux_id,
        simulcast_target_send_rate,
        simulcast_min_target_send_rate,
        simulcast_ideal_send_rate,
        simulcast_drain_rate,
        &simulcast_allocatable_videos,
    );

    // Set the SVC decode targets.
    svc_helpers::update_selected_targets(clients, receiver_demux_id, &svc_selected_decode_targets);

    // Finally, update the allocation info in the client record so that it can be
    // properly communicated to the congestion controller.
    let client = clients
        .get_mut(receiver_demux_id)
        .expect("Client must exist");
    client.ideal_send_rate = min(
        svc_ideal_send_rate_uncapped + simulcast_ideal_send_rate,
        requested_max_send_rate,
    );
    client.requested_base_rate = min(
        svc_requested_base_rate + simulcast_requested_base_rate,
        requested_max_send_rate,
    );
    client.allocated_send_rate = svc_allocated_rate + simulcast_allocated_rate;
    client.target_send_rate = target_send_rate;
    client.send_rate_allocated = now;
}

#[cfg(test)]
mod tests {
    use std::cmp::{Reverse, max};

    use calling_common::VideoHeight;
    use smallvec::SmallVec;

    use super::*;
    use crate::{
        rtp::Resolution,
        simulcast::AllocatableVideoLayer,
        svc::{DecodeTargetInfo, DecodeTargetInfoList, MAX_EXPECTED_CLIENTS},
    };

    /// Mirrors how `allocate` derives the fractions from the two pools' ideal rates.
    fn fractions(svc_ideal: DataRate, simulcast_ideal: DataRate) -> (f64, f64) {
        let ideal_total = svc_ideal + simulcast_ideal;
        if ideal_total > DataRate::ZERO {
            let svc_frac = svc_ideal / ideal_total;
            (svc_frac, 1.0 - svc_frac)
        } else {
            (0.0, 0.0)
        }
    }

    fn kbps(kbps: u64) -> DataRate {
        DataRate::from_kbps(kbps)
    }

    /// Outgoing queue drain rates, as fractions of the target, from 0% to 50%.
    const DRAIN_RATIOS: [f64; 5] = [0.0, 0.125, 0.25, 0.375, 0.5];
    /// Running minimum send rates, as fractions of the target, from 50% to 100%.
    const MIN_RATIOS: [f64; 5] = [0.5, 0.625, 0.75, 0.875, 1.0];
    /// Base rate of every SVC sender, in kbps.
    const SVC_SENDER_BASE_RATE_KBPS: u64 = 100;
    /// Base rate of every simulcast sender, in kbps.
    const SIMULCAST_SENDER_BASE_RATE_KBPS: u64 = 150;
    /// Targets each test splits, in kbps.
    const TARGET_RATES_KBPS: [u64; 20] = [
        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 3000,
        4000, 5000, 7000, 10_000,
    ];
    /// Rates of each generated sender's layers or decode targets, as multiples of its base rate.
    const LAYER_RATE_MULTIPLIERS: [f64; 3] = [1.0, 3.0, 7.5];
    /// Heights of each generated sender's layers or decode targets.
    const LAYER_HEIGHTS: [u16; 3] = [180, 360, 720];

    /// Generates the decode targets of `sender_count` SVC senders whose base rates add up to
    /// `required_bitrate`. Each sender has one decode target per entry of `LAYER_HEIGHTS`, at
    /// the matching `LAYER_RATE_MULTIPLIERS` multiple of its base rate.
    fn generate_svc_pool_entries(
        required_bitrate: DataRate,
        sender_count: usize,
    ) -> Vec<DecodeTargetInfoList> {
        let total_bps = required_bitrate.as_bps();
        let sender_count = sender_count as u64;
        (0..sender_count)
            .map(|i| {
                // Spread the remainder over the first senders so the base rates add up exactly.
                let base_rate = DataRate::from_bps(
                    total_bps / sender_count + u64::from(i < total_bps % sender_count),
                );
                LAYER_RATE_MULTIPLIERS
                    .into_iter()
                    .zip(LAYER_HEIGHTS)
                    .map(|(multiplier, height)| DecodeTargetInfo {
                        rate: base_rate * multiplier,
                        resolution: Resolution {
                            width: height * 16 / 9,
                            height,
                        },
                        chain_index: 0,
                    })
                    .collect::<SmallVec<_>>()
                    .into()
            })
            .collect()
    }

    /// Wraps each sender's decode targets in the allocation info the SVC allocator sees, with
    /// demux IDs 0x1000, 0x1010 and so on, clear of `generate_simulcast_entries`' IDs. Each
    /// sender is requested at its top height, `LAYER_HEIGHTS[2]`.
    fn get_sender_allocation_info(
        senders: &[DecodeTargetInfoList],
    ) -> Vec<SenderAllocationInfo<'_>> {
        senders
            .iter()
            .enumerate()
            .map(|(i, decode_target_info_list)| SenderAllocationInfo {
                demux_id: DemuxId::from_const(0x1000 + ((i as u32) << 4)),
                became_active_speaker: None,
                requested_height: Some(VideoHeight::from(LAYER_HEIGHTS[2])),
                decode_target_info_list,
                active_decode_target: None,
            })
            .collect()
    }

    /// Generates `sender_count` simulcast senders whose base rates add up to `required_bitrate`,
    /// with demux IDs 0x10, 0x20 and so on. Each sender has one layer per entry of
    /// `LAYER_HEIGHTS`, at the matching `LAYER_RATE_MULTIPLIERS` multiple of its base rate, and
    /// is requested at its top height, `LAYER_HEIGHTS[2]`.
    fn generate_simulcast_entries(
        required_bitrate: DataRate,
        sender_count: usize,
    ) -> Vec<AllocatableVideo> {
        let total_bps = required_bitrate.as_bps();
        let sender_count = sender_count as u64;
        (0..sender_count)
            .map(|i| {
                // Spread the remainder over the first senders so the base rates add up exactly.
                let base_rate = DataRate::from_bps(
                    total_bps / sender_count + u64::from(i < total_bps % sender_count),
                );
                let layers = std::array::from_fn(|layer_index| AllocatableVideoLayer {
                    incoming_rate: base_rate * LAYER_RATE_MULTIPLIERS[layer_index],
                    incoming_height: VideoHeight::from(LAYER_HEIGHTS[layer_index]),
                });
                let requested_height = VideoHeight::from(LAYER_HEIGHTS[2]);
                AllocatableVideo {
                    sender_demux_id: DemuxId::from_const(((i + 1) << 4) as u32),
                    ideal_layer_index: simulcast::ideal_video_layer_index(
                        requested_height,
                        &layers,
                    ),
                    layers,
                    requested_height,
                    allocated_layer_index: None,
                    interesting: None,
                }
            })
            .collect()
    }

    /// A pseudo-random entry of `LAYER_HEIGHTS` for the `index`th sender of the call `seed`
    /// stands for (splitmix64), so that every run requests the same heights.
    fn random_layer_height(seed: u64, index: usize) -> VideoHeight {
        let mut z = (seed << 8)
            .wrapping_add(index as u64)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        VideoHeight::from(LAYER_HEIGHTS[(z % LAYER_HEIGHTS.len() as u64) as usize])
    }

    /// Splits each of `target_rates_kbps` between an SVC pool of `svc_sender_count` senders and a
    /// simulcast pool of `simulcast_sender_count` senders, whose base rates add up to the
    /// pools' required bitrates, and returns whether the priority sender is shown at every target
    /// where it can be. The receiver's outgoing queue drains at `drain_ratio` of the target, and
    /// its running minimum send rate is `min_ratio` of the target.
    ///
    /// Every sender is requested at a pseudo-random entry of `LAYER_HEIGHTS`, fixed by the pool
    /// sizes (see `run_split_with_heights`).
    fn run_split_with_priority_sender(
        svc_sender_count: usize,
        svc_required_bitrate: DataRate,
        simulcast_sender_count: usize,
        simulcast_required_bitrate: DataRate,
        target_rates_kbps: &[u64],
        drain_ratio: f64,
        min_ratio: f64,
    ) -> bool {
        let height_seed = ((svc_sender_count as u64) << 32) | simulcast_sender_count as u64;
        let svc_heights: Vec<_> = (0..svc_sender_count)
            .map(|index| random_layer_height(height_seed, index))
            .collect();
        let simulcast_heights: Vec<_> = (0..simulcast_sender_count)
            .map(|index| random_layer_height(height_seed, svc_sender_count + index))
            .collect();
        run_split_with_heights(
            &svc_heights,
            svc_required_bitrate,
            &simulcast_heights,
            simulcast_required_bitrate,
            target_rates_kbps,
            drain_ratio,
            min_ratio,
        )
        .is_none_or(|outcome| outcome.failed_target_kbps.is_none())
    }

    /// What `run_split_with_heights` found.
    struct SplitOutcome {
        /// Whether the priority sender is in the SVC pool, rather than the simulcast pool.
        priority_in_svc_pool: bool,
        /// Whether `get_priority_sender_info` put the priority sender in the SVC pool, rather
        /// than the simulcast pool, or `None` if it found no priority sender.
        get_priority_sender_info_in_svc_pool: Option<bool>,
        /// The first target, in kbps, at which the priority sender wasn't shown although it can
        /// be, or `None` if it was shown at every such target.
        failed_target_kbps: Option<u64>,
    }

    /// Splits each of `target_rates_kbps` between an SVC pool of one sender per entry of
    /// `svc_heights` and a simulcast pool of one sender per entry of `simulcast_heights`, whose
    /// base rates add up to the pools' required bitrates, and reports which pool the priority
    /// sender is in, which pool `get_priority_sender_info` puts it in, and the first target where
    /// it can be shown but isn't. The receiver's outgoing queue drains at `drain_ratio` of the
    /// target, and its running minimum send rate is `min_ratio` of the target. Returns `None` if
    /// the call has no senders.
    ///
    /// Each sender is requested at its entry of `svc_heights` or `simulcast_heights`, and the
    /// active speaker is the first simulcast sender (the first SVC sender in an SVC-only call).
    /// Both pools are then sorted the way the pool allocators sort them. The priority sender is
    /// worked out independently of `get_priority_sender_info`, as the first of all the senders in
    /// that order, with SVC senders first among exact ties. It must be shown whenever the call's
    /// budget for new layers, `max(min - drain, 0.9 * min)`, covers its base rate.
    fn run_split_with_heights(
        svc_heights: &[VideoHeight],
        svc_required_bitrate: DataRate,
        simulcast_heights: &[VideoHeight],
        simulcast_required_bitrate: DataRate,
        target_rates_kbps: &[u64],
        drain_ratio: f64,
        min_ratio: f64,
    ) -> Option<SplitOutcome> {
        let svc_lists = generate_svc_pool_entries(svc_required_bitrate, svc_heights.len());
        let mut svc_senders = get_sender_allocation_info(&svc_lists);
        let mut simulcast_videos =
            generate_simulcast_entries(simulcast_required_bitrate, simulcast_heights.len());

        for (info, &height) in svc_senders.iter_mut().zip(svc_heights) {
            info.requested_height = Some(height);
        }
        for (video, &height) in simulcast_videos.iter_mut().zip(simulcast_heights) {
            video.requested_height = height;
            video.ideal_layer_index =
                simulcast::ideal_video_layer_index(video.requested_height, &video.layers);
        }
        let now = Instant::now();
        if let Some(video) = simulcast_videos.first_mut() {
            video.interesting = Some(now);
        } else if let Some(info) = svc_senders.first_mut() {
            info.became_active_speaker = Some(now);
        }
        svc_senders
            .sort_by_key(|info| Reverse((info.requested_height, info.became_active_speaker)));
        simulcast_videos.sort_by_key(|video| Reverse((video.requested_height, video.interesting)));

        // The priority sender: the first of all the senders, SVC senders first, by requested
        // height and then by when they last became the active speaker. `min_by_key` keeps the
        // first of equal keys.
        let senders = svc_senders
            .iter()
            .map(|info| {
                let key = (
                    info.requested_height.unwrap_or_default(),
                    info.became_active_speaker,
                );
                (key, info.demux_id, info.decode_target_info_list[0].rate)
            })
            .chain(simulcast_videos.iter().map(|video| {
                let key = (video.requested_height, video.interesting);
                (key, video.sender_demux_id, video.layers[0].incoming_rate)
            }));
        let (_, priority_demux_id, priority_base_rate) =
            senders.min_by_key(|(key, _, _)| Reverse(*key))?;
        let priority_in_svc_pool = svc_senders
            .iter()
            .any(|info| info.demux_id == priority_demux_id);
        let get_priority_sender_info_in_svc_pool =
            get_priority_sender_info(&simulcast_videos, &svc_senders)
                .map(|sender| matches!(sender, PrioritySenderInfo::Svc(_)));

        let svc_ideal_targets = svc::allocator::find_ideal_decode_targets(&svc_senders);
        let svc_ideal = svc::allocator::calculate_ideal_send_rate(&svc_senders, &svc_ideal_targets);
        let svc_base = svc::allocator::calculate_base_rate(&svc_senders, &svc_ideal_targets);
        let simulcast_ideal = simulcast::ideal_send_rate(&simulcast_videos);
        let simulcast_base = simulcast::requested_base_rate(&simulcast_videos, DataRate::MAX);
        let (svc_frac, simulcast_frac) = fractions(svc_ideal, simulcast_ideal);

        // The first target at which the priority sender can be shown but isn't.
        let failed_target_kbps = target_rates_kbps.iter().copied().find(|&target_kbps| {
            let target = kbps(target_kbps);
            let drain_rate = target * drain_ratio;
            let min_target = target * min_ratio;
            // The priority sender isn't forwarded yet, so no split can show it unless the call's
            // budget for new layers covers its base rate (plus a little room for rounding). It
            // isn't checked at a target where it can't be shown.
            let call_new_layer_budget = max(
                min_target.saturating_sub(drain_rate),
                min_target * TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
            );
            if call_new_layer_budget < priority_base_rate + DataRate::from_bps(10) {
                return false;
            }

            let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
                target_send_rate: target,
                min_target_send_rate: min_target,
                drain_rate,
                svc_target_rate_fraction: svc_frac,
                simulcast_target_rate_fraction: simulcast_frac,
                svc_requested_base_rate: svc_base,
                simulcast_requested_base_rate: simulcast_base,
                svc_sender_allocation_info: &svc_senders,
                simulcast_allocatable_videos: &simulcast_videos,
            });

            // Allocate both pools as `allocate` would, with the running minimum and the drain
            // rate scaled to each pool's share.
            let svc_result = svc::allocator::allocate(
                svc_budget,
                scale_to_pool_share(min_target, svc_budget, target),
                TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
                scale_to_pool_share(drain_rate, svc_budget, target),
                svc_ideal,
                &svc_senders,
                &svc_ideal_targets,
            );
            let simulcast_result = simulcast::allocate_send_rate(
                simulcast_budget,
                scale_to_pool_share(min_target, simulcast_budget, target),
                simulcast_ideal,
                scale_to_pool_share(drain_rate, simulcast_budget, target),
                &simulcast_videos,
            );
            let shown = simulcast_result.contains_key(&priority_demux_id)
                || svc_result.selected_decode_targets.iter().any(|selected| {
                    selected.demux_id == priority_demux_id && selected.decode_target.is_some()
                });
            !shown
        });
        Some(SplitOutcome {
            priority_in_svc_pool,
            get_priority_sender_info_in_svc_pool,
            failed_target_kbps,
        })
    }

    /// Checks that the priority sender of a call whose senders are requested at `svc_heights` and
    /// `simulcast_heights` (see `run_split_with_heights`) is in the SVC pool if
    /// `priority_in_svc_pool` is set, and in the simulcast pool otherwise, both by the test's own
    /// ranking and by `get_priority_sender_info`, and that it is shown at every `DRAIN_RATIOS`,
    /// `MIN_RATIOS` and `TARGET_RATES_KBPS` combination where it can be.
    /// SVC senders have a `SVC_SENDER_BASE_RATE_KBPS` base rate and simulcast senders a
    /// `SIMULCAST_SENDER_BASE_RATE_KBPS` one.
    fn check_priority_sender_shown(
        svc_heights: &[u16],
        simulcast_heights: &[u16],
        priority_in_svc_pool: bool,
    ) {
        let svc_heights: Vec<_> = svc_heights.iter().copied().map(VideoHeight::from).collect();
        let simulcast_heights: Vec<_> = simulcast_heights
            .iter()
            .copied()
            .map(VideoHeight::from)
            .collect();
        for drain_ratio in DRAIN_RATIOS {
            for min_ratio in MIN_RATIOS {
                let outcome = run_split_with_heights(
                    &svc_heights,
                    kbps(svc_heights.len() as u64 * SVC_SENDER_BASE_RATE_KBPS),
                    &simulcast_heights,
                    kbps(simulcast_heights.len() as u64 * SIMULCAST_SENDER_BASE_RATE_KBPS),
                    &TARGET_RATES_KBPS,
                    drain_ratio,
                    min_ratio,
                )
                .expect("call must have senders");
                assert_eq!(
                    outcome.priority_in_svc_pool, priority_in_svc_pool,
                    "the test's ranking put the priority sender in the wrong pool"
                );
                assert_eq!(
                    outcome.get_priority_sender_info_in_svc_pool,
                    Some(priority_in_svc_pool),
                    "get_priority_sender_info put the priority sender in the wrong pool"
                );
                assert_eq!(
                    outcome.failed_target_kbps, None,
                    "priority sender not shown at svc_heights={svc_heights:?}, \
                     simulcast_heights={simulcast_heights:?}, drain_ratio={drain_ratio}, \
                     min_ratio={min_ratio}, target_kbps={:?}",
                    outcome.failed_target_kbps
                );
            }
        }
    }

    /// The priority sender of an SVC-only call is the SVC active speaker.
    #[test]
    fn test_split_shows_priority_sender_svc_only() {
        check_priority_sender_shown(&[720], &[], true);
    }

    /// The priority sender of a simulcast-only call is the simulcast active speaker.
    #[test]
    fn test_split_shows_priority_sender_simulcast_only() {
        check_priority_sender_shown(&[], &[720], false);
    }

    /// When the simulcast active speaker is requested as large as any SVC sender, it ranks first,
    /// so rate is moved into the simulcast pool if needed.
    #[test]
    fn test_split_shows_priority_sender_simulcast_active_speaker() {
        check_priority_sender_shown(&[720], &[720], false);
    }

    /// When an SVC sender is requested larger than every simulcast sender, including the active
    /// speaker, it ranks first, so rate is moved into the SVC pool if needed.
    #[test]
    fn test_split_shows_priority_sender_larger_svc_sender() {
        check_priority_sender_shown(&[720, 360], &[360, 360, 180], true);
    }

    /// When the top SVC and simulcast senders are requested at the same height and neither is the
    /// active speaker (who is requested smaller), the tie goes to the SVC pool.
    #[test]
    fn test_split_shows_priority_sender_exact_tie() {
        check_priority_sender_shown(&[720, 360, 180], &[360, 720], true);
    }

    /// Checks that the priority sender is shown regardless of how a call's senders are split
    /// between the pools and what heights they're requested at, under queue drain and a lagging
    /// running minimum.
    ///
    /// Covers every call of `j` senders, from 1 to `MAX_EXPECTED_CLIENTS - 1`, split every way
    /// between `i` SVC senders and `j - i` simulcast senders. SVC senders have a
    /// `SVC_SENDER_BASE_RATE_KBPS` base rate and simulcast senders a
    /// `SIMULCAST_SENDER_BASE_RATE_KBPS` one. Each split runs at every `DRAIN_RATIOS` and
    /// `MIN_RATIOS` combination, against every target in `TARGET_RATES_KBPS`. Fails at the first
    /// split where the priority sender isn't shown at a target where it can be (see
    /// `run_split_with_priority_sender`).
    ///
    /// Ignored by default, since it takes about 20 seconds. The
    /// `test_split_shows_priority_sender_*` tests cover the same five kinds of split (SVC-only,
    /// simulcast-only, and mixed with an SVC priority sender, a simulcast one, or an exact tie),
    /// which are all the current split logic distinguishes, but only with up to five senders and
    /// fixed heights.
    #[test]
    #[ignore]
    fn test_split_priority_sender() {
        for j in 1..MAX_EXPECTED_CLIENTS {
            for i in 0..=j {
                let n_svc = i;
                let n_sim = j - i;
                for drain_ratio in DRAIN_RATIOS {
                    for min_ratio in MIN_RATIOS {
                        assert!(
                            run_split_with_priority_sender(
                                n_svc,
                                kbps(n_svc as u64 * SVC_SENDER_BASE_RATE_KBPS),
                                n_sim,
                                kbps(n_sim as u64 * SIMULCAST_SENDER_BASE_RATE_KBPS),
                                &TARGET_RATES_KBPS,
                                drain_ratio,
                                min_ratio,
                            ),
                            "failed at svc={n_svc}, simulcast={n_sim}, \
                             drain_ratio={drain_ratio}, min_ratio={min_ratio}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_split_reserves_base_rate_for_the_smaller_pool() {
        // One SVC sender dominating the ideal demand alongside a single VP8 sender. The
        // simulcast pool's proportional share alone would be ~70kbps, below its 150kbps base
        // layer, which would forward nothing at all.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: kbps(1000),
            min_target_send_rate: kbps(1000),
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: kbps(200),
            simulcast_requested_base_rate: kbps(150),
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert!(
            simulcast_budget >= kbps(150),
            "simulcast pool must cover its base layer, got {simulcast_budget:?}"
        );
        // The dominant pool still gets the lion's share of the surplus.
        assert!(svc_budget > simulcast_budget * 3.0, "got {svc_budget:?}");
        assert!(svc_budget + simulcast_budget <= kbps(1000));
    }

    #[test]
    fn test_split_falls_back_to_proportional_when_bases_do_not_fit() {
        // Base layers total 350kbps against a 100kbps budget, so neither pool can be made
        // whole; the split degrades to straight proportional.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: kbps(100),
            min_target_send_rate: kbps(100),
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: kbps(200),
            simulcast_requested_base_rate: kbps(150),
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert_eq!(svc_budget, kbps(100) * svc_frac);
        assert_eq!(simulcast_budget, kbps(100) * simulcast_frac);
        assert!(svc_budget + simulcast_budget <= kbps(100));
    }

    #[test]
    fn test_split_never_over_commits_the_target() {
        let target = kbps(1000);
        for svc_ideal in [0, 100, 1500, 20_000] {
            for simulcast_ideal in [0, 100, 1500, 20_000] {
                for svc_base in [0, 150, 900] {
                    for simulcast_base in [0, 150, 900] {
                        let (svc_frac, simulcast_frac) =
                            fractions(kbps(svc_ideal), kbps(simulcast_ideal));
                        let (svc_budget, simulcast_budget) =
                            split_target_send_rate(SplitTargetSendRateArgs {
                                target_send_rate: target,
                                min_target_send_rate: target,
                                drain_rate: DataRate::ZERO,
                                svc_target_rate_fraction: svc_frac,
                                simulcast_target_rate_fraction: simulcast_frac,
                                svc_requested_base_rate: kbps(svc_base),
                                simulcast_requested_base_rate: kbps(simulcast_base),
                                svc_sender_allocation_info: &[],
                                simulcast_allocatable_videos: &[],
                            });

                        assert!(
                            svc_budget + simulcast_budget <= target,
                            "over-committed with ideals ({svc_ideal}, {simulcast_ideal}) \
                             and bases ({svc_base}, {simulcast_base}): \
                             {svc_budget:?} + {simulcast_budget:?} > {target:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_split_preserves_the_layer_hysteresis_invariant() {
        // `allocate` scales the receiver's minimum by the share the simulcast pool actually
        // received. Since min_target_send_rate() <= target_send_rate and both use the same
        // fraction, the scaled minimum can never exceed the pool's budget -- which is what
        // simulcast::allocate_send_rate needs for "existing layers >= different layers".
        let target = kbps(1000);
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (_svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: target,
            min_target_send_rate: target,
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: kbps(200),
            simulcast_requested_base_rate: kbps(150),
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        let simulcast_budget_fraction = simulcast_budget / target;
        for min_target in [0, 250, 500, 1000] {
            let scaled_min = kbps(min_target) * simulcast_budget_fraction;
            assert!(
                scaled_min <= simulcast_budget,
                "min {min_target}kbps scaled to {scaled_min:?} exceeds budget {simulcast_budget:?}"
            );
        }
    }

    #[test]
    fn test_split_allocates_nothing_when_the_client_requests_zero() {
        // A client asking for max_kbps: 0 caps the whole allocation budget at zero, whatever
        // congestion control says the link can carry.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: DataRate::ZERO,
            min_target_send_rate: DataRate::ZERO,
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: kbps(200),
            simulcast_requested_base_rate: kbps(150),
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert_eq!(svc_budget, DataRate::ZERO);
        assert_eq!(simulcast_budget, DataRate::ZERO);
    }

    #[test]
    fn test_scale_to_pool_share_is_zero_without_a_budget() {
        // The zero budget a max_kbps: 0 client produces must not be divided by. The minimum is
        // deliberately nonzero here: the guard has to key off the budget, not the minimum.
        assert_eq!(
            scale_to_pool_share(kbps(500), DataRate::ZERO, DataRate::ZERO),
            DataRate::ZERO
        );
        assert_eq!(
            scale_to_pool_share(kbps(500), kbps(150), DataRate::ZERO),
            DataRate::ZERO
        );
    }

    #[test]
    fn test_scale_to_pool_share_never_exceeds_the_pool_budget() {
        let allocation_target = kbps(1000);
        for pool_budget in [0, 70, 200, 1000] {
            for min_target in [0, 250, 1000, 5000] {
                let scaled =
                    scale_to_pool_share(kbps(min_target), kbps(pool_budget), allocation_target);

                assert!(
                    scaled <= kbps(pool_budget),
                    "min {min_target}kbps scaled to {scaled:?}, above pool budget \
                     {pool_budget}kbps"
                );
            }
        }
    }

    #[test]
    fn test_split_allocates_nothing_without_demand() {
        let (svc_frac, simulcast_frac) = fractions(DataRate::ZERO, DataRate::ZERO);
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: kbps(1000),
            min_target_send_rate: kbps(1000),
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: DataRate::ZERO,
            simulcast_requested_base_rate: DataRate::ZERO,
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert_eq!(svc_budget, DataRate::ZERO);
        assert_eq!(simulcast_budget, DataRate::ZERO);
    }

    #[test]
    fn test_split_gives_the_whole_budget_to_the_only_pool_with_demand() {
        // An SVC-only call: the simulcast pool has no senders, so it must not hold back any
        // of the receiver's budget.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), DataRate::ZERO);
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: kbps(1000),
            min_target_send_rate: kbps(1000),
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: kbps(200),
            simulcast_requested_base_rate: DataRate::ZERO,
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert_eq!(simulcast_budget, DataRate::ZERO);
        assert_eq!(svc_budget, kbps(1000));
    }

    #[test]
    fn test_split_ignores_a_declined_priority_sender() {
        // The receiver has declined every sender's video, so the first sender in each pool is
        // declined too and its pool allocator will skip it. The split must not move rate for
        // it: the result must match a split with no senders to look at.
        let svc_lists = generate_svc_pool_entries(kbps(40 * 100), 40);
        let mut svc_senders = get_sender_allocation_info(&svc_lists);
        let mut simulcast_videos = generate_simulcast_entries(kbps(5 * 150), 5);
        for info in &mut svc_senders {
            info.requested_height = Some(VideoHeight::from(0));
        }
        for video in &mut simulcast_videos {
            video.requested_height = VideoHeight::from(0);
            video.ideal_layer_index = None;
        }

        for (svc_frac, simulcast_frac) in [(0.99, 0.01), (0.01, 0.99)] {
            let split = |svc_sender_allocation_info, simulcast_allocatable_videos| {
                split_target_send_rate(SplitTargetSendRateArgs {
                    target_send_rate: kbps(1000),
                    min_target_send_rate: kbps(1000),
                    drain_rate: DataRate::ZERO,
                    svc_target_rate_fraction: svc_frac,
                    simulcast_target_rate_fraction: simulcast_frac,
                    svc_requested_base_rate: kbps(40 * 100),
                    simulcast_requested_base_rate: kbps(5 * 150),
                    svc_sender_allocation_info,
                    simulcast_allocatable_videos,
                })
            };
            assert_eq!(
                split(&svc_senders, &simulcast_videos),
                split(&[], &[]),
                "fractions ({svc_frac}, {simulcast_frac})"
            );
        }
    }

    #[test]
    fn test_split_gives_the_short_pool_any_excess_over_a_reservation() {
        // The base rates don't both fit, and SVC dominates the ideal demand: its proportional
        // share (837kbps) is more than its reservation (750kbps), while the simulcast pool's
        // share (63kbps) is short of its own (300kbps). The SVC pool keeps its reservation and
        // the simulcast pool gets the rest, rather than the SVC pool keeping the excess.
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: kbps(900),
            min_target_send_rate: kbps(900),
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: 0.93,
            simulcast_target_rate_fraction: 0.07,
            svc_requested_base_rate: kbps(750),
            simulcast_requested_base_rate: kbps(300),
            svc_sender_allocation_info: &[],
            simulcast_allocatable_videos: &[],
        });

        assert!(svc_budget >= kbps(750), "got {svc_budget:?}");
        assert!(svc_budget < kbps(751), "got {svc_budget:?}");
        assert_eq!(svc_budget + simulcast_budget, kbps(900));
    }

    #[test]
    fn test_split_protects_a_sender_requested_above_the_speaker() {
        // The receiver pins an SVC sender at 720p, above the simulcast speaker at 360p and 40
        // simulcast thumbnails at 180p. The pinned sender is first in the order the pool
        // allocators serve, so it's the one the split must protect, even though the simulcast
        // pool's ideal demand leaves the SVC pool a proportional share (83kbps) below the pinned
        // sender's 100kbps base.
        let svc_lists = generate_svc_pool_entries(kbps(100), 1);
        let svc_senders = get_sender_allocation_info(&svc_lists);
        let pinned = svc_senders[0].demux_id;
        let mut simulcast_videos = generate_simulcast_entries(kbps(41 * 150), 41);
        for video in &mut simulcast_videos {
            video.requested_height = VideoHeight::from(LAYER_HEIGHTS[0]);
        }
        simulcast_videos[0].requested_height = VideoHeight::from(LAYER_HEIGHTS[1]);
        simulcast_videos[0].interesting = Some(Instant::now());
        for video in &mut simulcast_videos {
            video.ideal_layer_index =
                simulcast::ideal_video_layer_index(video.requested_height, &video.layers);
        }
        let speaker = simulcast_videos[0].sender_demux_id;

        let target = kbps(800);
        let svc_ideal_targets = svc::allocator::find_ideal_decode_targets(&svc_senders);
        let svc_ideal = svc::allocator::calculate_ideal_send_rate(&svc_senders, &svc_ideal_targets);
        let svc_base = svc::allocator::calculate_base_rate(&svc_senders, &svc_ideal_targets);
        let simulcast_ideal = simulcast::ideal_send_rate(&simulcast_videos);
        let simulcast_base = simulcast::requested_base_rate(&simulcast_videos, DataRate::MAX);
        let (svc_frac, simulcast_frac) = fractions(svc_ideal, simulcast_ideal);
        let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
            target_send_rate: target,
            min_target_send_rate: target,
            drain_rate: DataRate::ZERO,
            svc_target_rate_fraction: svc_frac,
            simulcast_target_rate_fraction: simulcast_frac,
            svc_requested_base_rate: svc_base,
            simulcast_requested_base_rate: simulcast_base,
            svc_sender_allocation_info: &svc_senders,
            simulcast_allocatable_videos: &simulcast_videos,
        });

        let svc_result = svc::allocator::allocate(
            svc_budget,
            scale_to_pool_share(target, svc_budget, target),
            TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
            DataRate::ZERO,
            svc_ideal,
            &svc_senders,
            &svc_ideal_targets,
        );
        let simulcast_result = simulcast::allocate_send_rate(
            simulcast_budget,
            scale_to_pool_share(target, simulcast_budget, target),
            simulcast_ideal,
            DataRate::ZERO,
            &simulcast_videos,
        );
        assert!(
            svc_result
                .selected_decode_targets
                .iter()
                .any(|selected| selected.demux_id == pinned && selected.decode_target.is_some()),
            "pinned sender not shown: svc budget {svc_budget}"
        );
        // There's still room for the speaker, which is first in the simulcast pool.
        assert!(
            simulcast_result.contains_key(&speaker),
            "speaker not shown: simulcast budget {simulcast_budget}"
        );
    }

    #[test]
    fn test_split_protects_the_active_speaker_on_a_tie() {
        // Every sender is requested at the same height, so being the active speaker is what
        // makes a sender the priority sender, whichever pool it's in. The speaker is alone in its
        // pool, next to 40 senders in the other one, so its pool's proportional share at 1Mbps is
        // below its base rate.
        for speaker_in_svc in [false, true] {
            let (n_svc, n_sim) = if speaker_in_svc { (1, 40) } else { (40, 1) };
            let svc_lists =
                generate_svc_pool_entries(kbps(n_svc as u64 * SVC_SENDER_BASE_RATE_KBPS), n_svc);
            let mut svc_senders = get_sender_allocation_info(&svc_lists);
            let mut simulcast_videos = generate_simulcast_entries(
                kbps(n_sim as u64 * SIMULCAST_SENDER_BASE_RATE_KBPS),
                n_sim,
            );
            let now = Instant::now();
            let speaker = if speaker_in_svc {
                svc_senders[0].became_active_speaker = Some(now);
                svc_senders[0].demux_id
            } else {
                simulcast_videos[0].interesting = Some(now);
                simulcast_videos[0].sender_demux_id
            };

            let target = kbps(1000);
            let svc_ideal_targets = svc::allocator::find_ideal_decode_targets(&svc_senders);
            let svc_ideal =
                svc::allocator::calculate_ideal_send_rate(&svc_senders, &svc_ideal_targets);
            let svc_base = svc::allocator::calculate_base_rate(&svc_senders, &svc_ideal_targets);
            let simulcast_ideal = simulcast::ideal_send_rate(&simulcast_videos);
            let simulcast_base = simulcast::requested_base_rate(&simulcast_videos, DataRate::MAX);
            let (svc_frac, simulcast_frac) = fractions(svc_ideal, simulcast_ideal);
            let (svc_budget, simulcast_budget) = split_target_send_rate(SplitTargetSendRateArgs {
                target_send_rate: target,
                min_target_send_rate: target,
                drain_rate: DataRate::ZERO,
                svc_target_rate_fraction: svc_frac,
                simulcast_target_rate_fraction: simulcast_frac,
                svc_requested_base_rate: svc_base,
                simulcast_requested_base_rate: simulcast_base,
                svc_sender_allocation_info: &svc_senders,
                simulcast_allocatable_videos: &simulcast_videos,
            });

            let shown = if speaker_in_svc {
                svc::allocator::allocate(
                    svc_budget,
                    scale_to_pool_share(target, svc_budget, target),
                    TARGET_RATE_MINIMUM_ALLOCATION_RATIO,
                    DataRate::ZERO,
                    svc_ideal,
                    &svc_senders,
                    &svc_ideal_targets,
                )
                .selected_decode_targets[0]
                    .decode_target
                    .is_some()
            } else {
                simulcast::allocate_send_rate(
                    simulcast_budget,
                    scale_to_pool_share(target, simulcast_budget, target),
                    simulcast_ideal,
                    DataRate::ZERO,
                    &simulcast_videos,
                )
                .contains_key(&speaker)
            };
            assert!(
                shown,
                "speaker in svc={speaker_in_svc} not shown: budgets ({svc_budget}, \
                 {simulcast_budget})"
            );
        }
    }
}
