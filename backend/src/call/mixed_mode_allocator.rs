//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::min;

use calling_common::{DataRate, DemuxId, Instant};
use log::{trace, warn};

use crate::{
    call::{Clients, TARGET_RATE_MINIMUM_ALLOCATION_RATIO, simulcast_helpers, svc_helpers},
    simulcast, svc,
};

/// Performs a full reallocation, invoking `allocate` for every receiver in the call at
/// their current send rate.
pub(super) fn reallocate(clients: &mut Clients, active_speaker_id: Option<DemuxId>, now: Instant) {
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

/// Divides `target_send_rate` between the SVC and simulcast pools. Each pool's base rate is
/// reserved first, and only the surplus is split in proportion to ideal demand.
fn split_target_send_rate(
    target_send_rate: DataRate,
    svc_target_rate_fraction: f64,
    simulcast_target_rate_fraction: f64,
    svc_requested_base_rate: DataRate,
    simulcast_requested_base_rate: DataRate,
) -> (DataRate, DataRate) {
    let reserved = svc_requested_base_rate + simulcast_requested_base_rate;
    if reserved <= target_send_rate {
        let surplus = target_send_rate - reserved;
        (
            svc_requested_base_rate + surplus * svc_target_rate_fraction,
            simulcast_requested_base_rate + surplus * simulcast_target_rate_fraction,
        )
    } else {
        // Not enough budget for both pools' base layers. Fall back to a straight proportional
        // split and let each pool's own priority ordering decide who goes without.
        (
            target_send_rate * svc_target_rate_fraction,
            target_send_rate * simulcast_target_rate_fraction,
        )
    }
}

/// Scales the receiver's running minimum send rate into one pool's share of the budget.
fn scaled_pool_minimum(
    min_target_send_rate: DataRate,
    pool_target_send_rate: DataRate,
    allocation_target_send_rate: DataRate,
) -> DataRate {
    if allocation_target_send_rate == DataRate::ZERO {
        return DataRate::ZERO;
    }
    let capped_min = min(min_target_send_rate, allocation_target_send_rate);
    capped_min * (pool_target_send_rate / allocation_target_send_rate)
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

    let simulcast_allocatable_videos =
        simulcast_helpers::get_allocatable_videos(clients, client, active_speaker_demux_id);
    let svc_sender_allocation_info =
        svc_helpers::get_sender_allocation_info(clients, client, active_speaker_demux_id);

    // Get the ideal send rate for the simulcast senders.
    let requested_max_send_rate = client.requested_max_send_rate;
    // Determine the allocation target send rate.
    let allocation_target_send_rate = min(target_send_rate, requested_max_send_rate);

    let simulcast_ideal_send_rate_uncapped =
        simulcast::ideal_send_rate(&simulcast_allocatable_videos, DataRate::MAX);
    let simulcast_ideal_send_rate =
        simulcast::ideal_send_rate(&simulcast_allocatable_videos, requested_max_send_rate);
    let simulcast_requested_base_rate =
        simulcast::requested_base_rate(&simulcast_allocatable_videos, requested_max_send_rate);

    // Get the ideal send rate for the SVC senders. Unlike the simulcast ideal send rate,
    // the SVC ideal send rate is *uncapped*.
    let svc::allocator::AllocationResult {
        allocated_rate: svc_ideal_send_rate,
        ..
    } = svc::allocator::calculate_ideal_send_rate(&svc_sender_allocation_info);

    // Determine the proportional split between SVC and simulcast.
    let ideal_total = svc_ideal_send_rate + simulcast_ideal_send_rate_uncapped;
    let (svc_target_rate_fraction, simulcast_target_rate_fraction) = if ideal_total > DataRate::ZERO
    {
        let svc_frac = svc_ideal_send_rate / ideal_total;
        (svc_frac, 1.0 - svc_frac)
    } else {
        (0.0, 0.0)
    };

    let svc_requested_base_rate = min(
        svc::allocator::calculate_base_rate(&svc_sender_allocation_info),
        requested_max_send_rate,
    );

    // Derive the actual bandwidth partition sizes. Each pool's (SVC and simulcast) base rate is
    // reserved first, and only the surplus is split in proportion to the ideal demand. For more
    // information see split_target_send_rate().
    let (svc_target_send_rate, simulcast_target_send_rate) = split_target_send_rate(
        allocation_target_send_rate,
        svc_target_rate_fraction,
        simulcast_target_rate_fraction,
        svc_requested_base_rate,
        simulcast_requested_base_rate,
    );

    // Adjust the drain rates
    let simulcast_drain_rate = scaled_pool_minimum(
        client.outgoing_queue_drain_rate,
        simulcast_target_send_rate,
        allocation_target_send_rate,
    );
    let svc_drain_rate = scaled_pool_minimum(
        client.outgoing_queue_drain_rate,
        svc_target_send_rate,
        allocation_target_send_rate,
    );

    // Perform the actual allocation for the SVC senders against the SVC share of the budget.
    // The minimum is scaled by the share the pool actually received, not by the raw
    // ideal-demand fraction.
    let svc_min_target_send_rate = scaled_pool_minimum(
        client.min_target_send_rate(),
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
        svc_ideal_send_rate,
        &svc_sender_allocation_info,
    );

    // Perform the actual allocation for the simulcast senders against the simulcast share of
    // the budget. The minimum is scaled by the share the pool actually received, not by
    // the raw ideal-demand fraction.
    let min_target_send_rate = scaled_pool_minimum(
        client.min_target_send_rate(),
        simulcast_target_send_rate,
        allocation_target_send_rate,
    );
    let simulcast_allocated_rate = simulcast_helpers::allocate_video_layers(
        clients,
        receiver_demux_id,
        simulcast_target_send_rate,
        min_target_send_rate,
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
        svc_ideal_send_rate + simulcast_ideal_send_rate,
        requested_max_send_rate,
    );
    client.requested_base_rate = min(
        svc_requested_base_rate + simulcast_requested_base_rate,
        requested_max_send_rate,
    );
    client.allocated_send_rate = svc_allocated_rate + simulcast_allocated_rate;
    client.target_send_rate = target_send_rate;
    client.send_rate_allocated = now;

    trace!(
        "svc: {receiver_demux_id:?}: allocate: target_send_rate={target_send_rate:?}, \
            svc_frac={svc_target_rate_fraction} \
            simulcast_ideal={simulcast_ideal_send_rate}, svc_ideal={svc_ideal_send_rate}, \
            simulcast_target={simulcast_target_send_rate}, svc_target={svc_target_send_rate}, \
            simulcast_alloc={simulcast_allocated_rate}, svc_alloc={svc_allocated_rate}, \
            simulcast_req={simulcast_requested_base_rate}, svc_req={svc_requested_base_rate} \
            rate_diff={}",
        target_send_rate.saturating_sub(svc_allocated_rate + simulcast_allocated_rate)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn split_reserves_base_rate_for_the_smaller_pool() {
        // One SVC sender dominating the ideal demand alongside a single VP8 sender. The
        // simulcast pool's proportional share alone would be ~70kbps, below its 150kbps base
        // layer, which would forward nothing at all.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) =
            split_target_send_rate(kbps(1000), svc_frac, simulcast_frac, kbps(200), kbps(150));

        assert!(
            simulcast_budget >= kbps(150),
            "simulcast pool must cover its base layer, got {simulcast_budget:?}"
        );
        // The dominant pool still gets the lion's share of the surplus.
        assert!(svc_budget > simulcast_budget * 3.0, "got {svc_budget:?}");
        assert!(svc_budget + simulcast_budget <= kbps(1000));
    }

    #[test]
    fn split_falls_back_to_proportional_when_bases_do_not_fit() {
        // Base layers total 350kbps against a 100kbps budget, so neither pool can be made
        // whole; the split degrades to straight proportional.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) =
            split_target_send_rate(kbps(100), svc_frac, simulcast_frac, kbps(200), kbps(150));

        assert_eq!(svc_budget, kbps(100) * svc_frac);
        assert_eq!(simulcast_budget, kbps(100) * simulcast_frac);
        assert!(svc_budget + simulcast_budget <= kbps(100));
    }

    #[test]
    fn split_never_over_commits_the_target() {
        let target = kbps(1000);
        for svc_ideal in [0, 100, 1500, 20_000] {
            for simulcast_ideal in [0, 100, 1500, 20_000] {
                for svc_base in [0, 150, 900] {
                    for simulcast_base in [0, 150, 900] {
                        let (svc_frac, simulcast_frac) =
                            fractions(kbps(svc_ideal), kbps(simulcast_ideal));
                        let (svc_budget, simulcast_budget) = split_target_send_rate(
                            target,
                            svc_frac,
                            simulcast_frac,
                            kbps(svc_base),
                            kbps(simulcast_base),
                        );

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
    fn split_preserves_the_layer_hysteresis_invariant() {
        // `allocate` scales the receiver's minimum by the share the simulcast pool actually
        // received. Since min_target_send_rate() <= target_send_rate and both use the same
        // fraction, the scaled minimum can never exceed the pool's budget -- which is what
        // simulcast::allocate_send_rate needs for "existing layers >= different layers".
        let target = kbps(1000);
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (_svc_budget, simulcast_budget) =
            split_target_send_rate(target, svc_frac, simulcast_frac, kbps(200), kbps(150));

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
    fn split_allocates_nothing_when_the_client_requests_zero() {
        // A client asking for max_kbps: 0 caps the whole allocation budget at zero, whatever
        // congestion control says the link can carry.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), kbps(150));
        let (svc_budget, simulcast_budget) = split_target_send_rate(
            DataRate::ZERO,
            svc_frac,
            simulcast_frac,
            kbps(200),
            kbps(150),
        );

        assert_eq!(svc_budget, DataRate::ZERO);
        assert_eq!(simulcast_budget, DataRate::ZERO);
    }

    #[test]
    fn scaled_pool_minimum_is_zero_without_a_budget() {
        // The zero budget a max_kbps: 0 client produces must not be divided by. The minimum is
        // deliberately nonzero here: the guard has to key off the budget, not the minimum.
        assert_eq!(
            scaled_pool_minimum(kbps(500), DataRate::ZERO, DataRate::ZERO),
            DataRate::ZERO
        );
        assert_eq!(
            scaled_pool_minimum(kbps(500), kbps(150), DataRate::ZERO),
            DataRate::ZERO
        );
    }

    #[test]
    fn scaled_pool_minimum_never_exceeds_the_pool_budget() {
        let allocation_target = kbps(1000);
        for pool_budget in [0, 70, 200, 1000] {
            for min_target in [0, 250, 1000, 5000] {
                let scaled =
                    scaled_pool_minimum(kbps(min_target), kbps(pool_budget), allocation_target);

                assert!(
                    scaled <= kbps(pool_budget),
                    "min {min_target}kbps scaled to {scaled:?}, above pool budget \
                     {pool_budget}kbps"
                );
            }
        }
    }

    #[test]
    fn split_allocates_nothing_without_demand() {
        let (svc_frac, simulcast_frac) = fractions(DataRate::ZERO, DataRate::ZERO);
        let (svc_budget, simulcast_budget) = split_target_send_rate(
            kbps(1000),
            svc_frac,
            simulcast_frac,
            DataRate::ZERO,
            DataRate::ZERO,
        );

        assert_eq!(svc_budget, DataRate::ZERO);
        assert_eq!(simulcast_budget, DataRate::ZERO);
    }

    #[test]
    fn split_gives_the_whole_budget_to_the_only_pool_with_demand() {
        // An SVC-only call: the simulcast pool has no senders, so it must not hold back any
        // of the receiver's budget.
        let (svc_frac, simulcast_frac) = fractions(kbps(2000), DataRate::ZERO);
        let (svc_budget, simulcast_budget) = split_target_send_rate(
            kbps(1000),
            svc_frac,
            simulcast_frac,
            kbps(200),
            DataRate::ZERO,
        );

        assert_eq!(simulcast_budget, DataRate::ZERO);
        assert_eq!(svc_budget, kbps(1000));
    }
}
