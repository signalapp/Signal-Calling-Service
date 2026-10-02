//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::{max, min};

use calling_common::{DataRate, DemuxId, Instant, VideoHeight};
use smallvec::SmallVec;

use crate::{
    rtp::MAX_DECODE_TARGETS,
    svc::{DecodeTarget, DecodeTargetInfo, DecodeTargetInfoList, MAX_EXPECTED_CLIENTS},
};

/// This structure represents a selected decode target.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelectedDecodeTarget {
    /// The demux ID of the sender to which the decode target belongs.
    pub demux_id: DemuxId,
    /// The selected decode target, if any.
    pub decode_target: Option<DecodeTarget>,
}

pub type SelectedDecodeTargets = SmallVec<[SelectedDecodeTarget; MAX_EXPECTED_CLIENTS]>;

/// A structure representing the result of an allocation process.
#[derive(Debug, Default, PartialEq)]
pub struct AllocationResult {
    /// The bandwidth that has been allocated.
    pub allocated_rate: DataRate,
    /// Collection of optional `DecodeTarget` values, one for each sender.
    pub selected_decode_targets: SelectedDecodeTargets,
}

/// A structure representing per-sender allocation information.
/// This structure can be generated in the context of a particular receiver. In that case,
/// the [`active_decode_target`] field will contain the sender's active decode target for
/// that particular receiver, if one exists.
#[derive(Debug, Clone, Copy)]
pub struct SenderAllocationInfo<'a> {
    /// Sender's demux ID.
    pub demux_id: DemuxId,
    /// The optional timestamp when the sender last became an active speaker.
    pub became_active_speaker: Option<Instant>,
    /// The optional requested height.
    pub requested_height: Option<VideoHeight>,
    /// Sender's decode target information.
    pub decode_target_info_list: &'a DecodeTargetInfoList,
    /// Currently active decode target for the receiver
    pub active_decode_target: Option<DecodeTarget>,
}

/// Returns the ideal decode target for `requested_height`: the lowest target whose
/// resolution satisfies the request, or the highest target being sent if none does.
/// `None` means the receiver wants nothing from this sender.
fn ideal_decode_target(
    requested_height: Option<VideoHeight>,
    decode_target_info_list: &DecodeTargetInfoList,
) -> Option<DecodeTarget> {
    // Targets that have been "turned off" by the sender have a rate of 0.
    let has_rate = |info: &DecodeTargetInfo| info.rate > DataRate::ZERO;

    // A receiver that has not asked for a height gets the lowest target being sent,
    // matching the simulcast path's default.
    let requested_height = requested_height.unwrap_or(VideoHeight::from(1));
    if requested_height == VideoHeight::from(0) {
        return None;
    }

    let first_sufficient = decode_target_info_list
        .iter()
        .position(|info| has_rate(info) && requested_height <= info.resolution.height.into());

    match first_sufficient {
        // Several targets can share the ideal height; take the highest of those.
        Some(i) => {
            let ideal_height = decode_target_info_list[i].resolution.height;
            decode_target_info_list
                .iter()
                .rposition(|info| has_rate(info) && info.resolution.height == ideal_height)
        }
        // Nothing is tall enough, so settle for the highest target being sent.
        None => decode_target_info_list.iter().rposition(has_rate),
    }
}

/// Performs a multi-pass allocation over senders, mirroring the simulcast approach.
fn do_allocation_pass(
    rate_budget_for_existing: DataRate,
    rate_budget_for_different: DataRate,
    sender_allocation_info: &[SenderAllocationInfo<'_>],
    max_targets: usize,
    selected_decode_targets: &mut SelectedDecodeTargets,
) -> DataRate {
    let mut allocated_rate = DataRate::ZERO;

    let ideal_targets: SmallVec<[Option<DecodeTarget>; MAX_EXPECTED_CLIENTS]> =
        sender_allocation_info
            .iter()
            .map(|info| ideal_decode_target(info.requested_height, info.decode_target_info_list))
            .collect();

    for decode_target in 0..max_targets {
        for i in 0..sender_allocation_info.len() {
            let Some(ideal) = ideal_targets[i] else {
                continue;
            };
            if decode_target > ideal {
                continue;
            }

            let sender_info = sender_allocation_info[i];

            let rate = sender_info
                .decode_target_info_list
                .get(decode_target)
                .map(|decode_target_info| decode_target_info.rate)
                .unwrap_or_default();
            if rate == DataRate::ZERO {
                continue;
            }

            let current_rate = selected_decode_targets
                .get(i)
                .and_then(|selected| {
                    selected.decode_target.map(|selected_decode_target| {
                        sender_info.decode_target_info_list[selected_decode_target].rate
                    })
                })
                .unwrap_or_default();

            let rate_increase = rate.saturating_sub(current_rate);
            let increased_allocated_rate = allocated_rate + rate_increase;
            let allocatable_rate = if Some(decode_target) == sender_info.active_decode_target {
                rate_budget_for_existing
            } else {
                rate_budget_for_different
            };
            if increased_allocated_rate > allocatable_rate {
                continue;
            }

            allocated_rate = increased_allocated_rate;
            selected_decode_targets[i].decode_target = Some(decode_target);
        }
    }

    // Calculate the allocated rate total
    selected_decode_targets
        .iter()
        .enumerate()
        .filter_map(|(i, selected)| {
            selected.decode_target.map(|decode_target| {
                sender_allocation_info[i].decode_target_info_list[decode_target].rate
            })
        })
        .sum()
}

/// Performs bandwidth allocation. The allocations are guaranteed to fit within
/// the given `rate_budget`. The senders in the `sender_allocation_info` array
/// are expected to be sorted in the order of preference.
pub fn allocate(
    rate_budget: DataRate,
    min_rate_budget: DataRate,
    rate_budget_floor_coeff: f64,
    drain_rate: DataRate,
    ideal_rate: DataRate,
    sender_allocation_info: &[SenderAllocationInfo<'_>],
) -> AllocationResult {
    let max_targets = sender_allocation_info
        .iter()
        .map(|info| info.decode_target_info_list.len())
        .max()
        .unwrap_or(0);

    debug_assert!(max_targets <= MAX_DECODE_TARGETS);

    let mut selected_decode_targets = SelectedDecodeTargets::default();
    for info in sender_allocation_info {
        selected_decode_targets.push(SelectedDecodeTarget {
            demux_id: info.demux_id,
            decode_target: None,
        });
    }

    if max_targets == 0 {
        return AllocationResult {
            allocated_rate: DataRate::ZERO,
            selected_decode_targets,
        };
    }

    // The greater rate budget to use when considering the current decode target.
    // Consequently, the existing decode target is always preferred.
    let rate_budget_for_existing = min(
        ideal_rate,
        max(
            rate_budget.saturating_sub(drain_rate),
            rate_budget * rate_budget_floor_coeff,
        ),
    );
    // The smaller rate budget to use when considering decode targets other than
    // the current decode target.
    let rate_budget_for_different = min(
        ideal_rate,
        max(
            min_rate_budget.saturating_sub(drain_rate),
            min_rate_budget * rate_budget_floor_coeff,
        ),
    );

    let allocated_rate = do_allocation_pass(
        rate_budget_for_existing,
        rate_budget_for_different,
        sender_allocation_info,
        max_targets,
        &mut selected_decode_targets,
    );

    AllocationResult {
        allocated_rate,
        selected_decode_targets,
    }
}

/// Calculates the ideal send rate. The senders in the `sender_allocation_info` array
/// are expected to be sorted in the order of preference.
pub fn calculate_ideal_send_rate(
    sender_allocation_info: &[SenderAllocationInfo<'_>],
) -> AllocationResult {
    // The ideal send rate is basically an uncapped send rate -- allocate as though we
    // have unlimited bandwidth at our disposal.
    allocate(
        DataRate::MAX,
        DataRate::MAX,
        1.0,
        DataRate::ZERO,
        DataRate::MAX,
        sender_allocation_info,
    )
}

/// Calculates the base rate. The senders in the `sender_allocation_info` array
/// are expected to be sorted in the order of preference.
pub fn calculate_base_rate(target_infos: &[SenderAllocationInfo<'_>]) -> DataRate {
    target_infos
        .iter()
        .filter(|target_info| {
            // A sender the receiver wants nothing from contributes no base rate.
            ideal_decode_target(
                target_info.requested_height,
                target_info.decode_target_info_list,
            )
            .is_some()
        })
        .filter_map(|target_info| target_info.decode_target_info_list.first())
        .map(|info| info.rate)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::Resolution;

    fn target(rate_kbps: u64, height: u16) -> DecodeTargetInfo {
        DecodeTargetInfo {
            rate: DataRate::from_kbps(rate_kbps),
            resolution: Resolution {
                width: height * 16 / 9,
                height,
            },
            chain_index: 0,
        }
    }

    fn target_list(infos: &[(u64, u16)]) -> DecodeTargetInfoList {
        let targets: SmallVec<[DecodeTargetInfo; 16]> = infos
            .iter()
            .map(|&(rate_kbps, height)| target(rate_kbps, height))
            .collect();
        targets.into()
    }

    fn info(
        demux_id: u32,
        decode_target_info_list: &DecodeTargetInfoList,
        requested_height: Option<u16>,
        became_active_speaker: Option<Instant>,
    ) -> SenderAllocationInfo<'_> {
        SenderAllocationInfo {
            demux_id: DemuxId::from_const(demux_id),
            became_active_speaker,
            requested_height: requested_height.map(VideoHeight::from),
            decode_target_info_list,
            active_decode_target: None,
        }
    }

    // Single-budget allocation with no drain and no ideal cap, for tests that exercise
    // core allocation logic without hysteresis.
    fn alloc(budget: DataRate, infos: &[SenderAllocationInfo<'_>]) -> AllocationResult {
        allocate(budget, budget, 1.0, DataRate::ZERO, DataRate::MAX, infos)
    }

    fn selected_targets(pairs: &[(u32, Option<usize>)]) -> SelectedDecodeTargets {
        pairs
            .iter()
            .map(|&(demux_id, decode_target)| SelectedDecodeTarget {
                demux_id: DemuxId::from_const(demux_id),
                decode_target,
            })
            .collect()
    }

    #[test]
    fn allocate_empty_input_returns_zero() {
        let result = alloc(DataRate::from_kbps(1000), &[]);
        assert_eq!(result.allocated_rate, DataRate::ZERO);
        assert!(result.selected_decode_targets.is_empty());
    }

    #[test]
    fn allocate_single_target_fits_budget() {
        let list = target_list(&[(100, 180)]);
        let infos = [info(16, &list, None, None)];

        let result = alloc(DataRate::from_kbps(200), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(100));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn allocate_no_target_fits_budget() {
        let list = target_list(&[(500, 180)]);
        let infos = [info(16, &list, None, None)];

        let result = alloc(DataRate::from_kbps(100), &infos);

        assert_eq!(result.allocated_rate, DataRate::ZERO);
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, None)])
        );
    }

    #[test]
    fn allocate_picks_highest_affordable_tier() {
        // 720p is the ideal tier, but it doesn't fit the budget, so the next tier down is
        // selected rather than nothing at all.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(720), None)];

        let result = alloc(DataRate::from_kbps(400), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn allocate_respects_requested_height_when_affordable() {
        // The multi-pass commits 180p first (base tier, 100 kbps), then upgrades to 360p
        // (+200 kbps incremental, 300 kbps total), which fits the 500 kbps budget.
        // The ideal target is capped at index 1 (360p), so 720p is never attempted.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(360), None)];

        let result = alloc(DataRate::from_kbps(500), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn allocate_falls_back_below_requested_height_when_nothing_else_fits() {
        // The ideal target is 360p (index 1). The multi-pass commits 180p as the base tier
        // (100 kbps, fits the budget), then the 360p upgrade (+200 kbps incremental, 300 kbps
        // total) exceeds the 100 kbps budget and is rejected. The sender stays at 180p; the
        // height ceiling is still enforced — 720p is never attempted.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(360), None)];

        let result = alloc(DataRate::from_kbps(100), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(100));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn allocate_does_not_exceed_requested_height_when_budget_allows() {
        // `requested_height` is a cap, not a floor: a receiver asking for 180p tiles gets the
        // 180p tier even though the whole 720p tier would fit the budget.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(180), None)];

        let result = alloc(DataRate::from_kbps(10_000), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(100));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn allocate_picks_lowest_tier_that_satisfies_requested_height() {
        // Several tiers meet the 200p request; the lowest sufficient one is ideal.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(200), None)];

        let result = alloc(DataRate::from_kbps(10_000), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn allocate_with_no_requested_height_uses_lowest_tier() {
        // A receiver that has not asked for a height gets the lowest tier being sent, matching
        // the simulcast path's `VideoHeight::from(1)` default.
        let list = target_list(&[(100, 180), (900, 720)]);
        let infos = [info(16, &list, None, None)];

        let result = alloc(DataRate::from_kbps(10_000), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(100));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn calculate_ideal_send_rate_respects_requested_height() {
        // The ideal rate must not count quality the receiver never asked for -- otherwise it
        // inflates googcc's ideal request and skews the mixed-mode SVC/simulcast rate split.
        let list = target_list(&[(100, 180), (300, 360), (900, 720)]);
        let infos = [info(16, &list, Some(360), None)];

        let result = calculate_ideal_send_rate(&infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn allocate_skips_sender_with_no_decode_targets() {
        let list_a = target_list(&[(100, 180)]);
        let list_b = DecodeTargetInfoList::default();
        let infos = [info(16, &list_a, None, None), info(32, &list_b, None, None)];

        let result = alloc(DataRate::from_kbps(200), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(100));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0)), (32, None)])
        );
    }

    #[test]
    fn allocate_first_sender_can_starve_later_senders_of_even_base_layer() {
        // In the decode_target 0 pass, sender A commits its only tier (1080p, 1000 kbps),
        // exhausting the entire budget. Sender B cannot then commit its 50 kbps base tier
        // (1000 + 50 > 1000) and gets nothing. A sender's position in the array (set by
        // BasicAllocationStrategy's priority sort) can therefore starve later senders of
        // even their base layer -- this is intentional, not a bug (confirmed 2026-08-25).
        let list_a = target_list(&[(1000, 1080)]);
        let list_b = target_list(&[(50, 180)]);
        let infos = [info(16, &list_a, None, None), info(32, &list_b, None, None)];

        let result = alloc(DataRate::from_kbps(1000), &infos);

        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0)), (32, None)])
        );
    }

    #[test]
    fn allocate_selects_target_when_rate_exactly_matches_remaining_budget() {
        let list = target_list(&[(500, 360)]);
        let infos = [info(16, &list, None, None)];

        let result = alloc(DataRate::from_kbps(500), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(500));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    // --- Multi-pass structure ---

    #[test]
    fn allocate_base_layer_shared_before_upgrades() {
        // Multi-pass allocation commits base layers for all senders before any sender
        // upgrades.  A's 360p upgrade (+300 kbps on top of the 300 kbps base) would
        // consume 600 kbps total, leaving no room for B's 200 kbps base layer inside a
        // 600 kbps budget.  The pass commits A=180p and B=180p first (500 kbps), then
        // finds A cannot upgrade (500+300=800>600).  Both senders keep their base tier.
        let list_a = target_list(&[(300, 180), (600, 360)]);
        let list_b = target_list(&[(200, 180)]);
        let infos = [
            info(16, &list_a, Some(360), None),
            info(32, &list_b, Some(180), None),
        ];

        let result = alloc(DataRate::from_kbps(600), &infos);

        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0)), (32, Some(0))])
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(500));
    }

    #[test]
    fn allocate_lower_priority_sender_can_upgrade_when_higher_priority_cannot() {
        // After committing base tiers for both senders (500 kbps combined), the budget
        // remaining is 300 kbps.  Sender A's upgrade costs 400 kbps incrementally (300→700)
        // and is rejected.  Sender B's upgrade costs only 200 kbps incrementally (200→400)
        // and is accepted.  A lower-priority sender can therefore end up at a higher tier
        // than a higher-priority sender when their upgrade costs differ.
        let list_a = target_list(&[(300, 180), (700, 360)]);
        let list_b = target_list(&[(200, 180), (400, 360)]);
        let infos = [
            info(16, &list_a, Some(360), None),
            info(32, &list_b, Some(360), None),
        ];

        let result = alloc(DataRate::from_kbps(800), &infos);

        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0)), (32, Some(1))])
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(700));
    }

    // --- Two-budget hysteresis ---

    #[test]
    fn hysteresis_existing_target_survives_below_different_budget_threshold() {
        // rate_budget_for_existing = 900, rate_budget_for_different = 500.
        // A 600 kbps target exceeds the different-budget ceiling but fits the existing one.
        // When it matches active_decode_target it is kept; otherwise it would not be selected.
        let list = target_list(&[(600, 360)]);
        let result = allocate(
            DataRate::from_kbps(900),
            DataRate::from_kbps(500),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[SenderAllocationInfo {
                active_decode_target: Some(0),
                ..info(16, &list, None, None)
            }],
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(600));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn hysteresis_different_target_rejected_below_different_budget_threshold() {
        // Same budgets and target as above, but active_decode_target is None — the target is
        // treated as a candidate switch. The strict different-budget ceiling (500 kbps) rejects
        // the 600 kbps target even though the raw rate_budget would allow it.
        let list = target_list(&[(600, 360)]);
        let result = allocate(
            DataRate::from_kbps(900),
            DataRate::from_kbps(500),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[info(16, &list, None, None)],
        );
        assert_eq!(result.allocated_rate, DataRate::ZERO);
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, None)])
        );
    }

    #[test]
    fn hysteresis_protects_existing_target_under_accumulated_budget_pressure() {
        // Sender A (higher priority) claims 400 kbps from a shared pool where the existing
        // ceiling is 800 kbps and the different ceiling is 600 kbps.
        // After Sender A, accumulated_rate = 400.  Sender B's 300 kbps target then:
        //   400 + 300 = 700 ≤ 800 (existing) → kept when active_decode_target matches
        //   400 + 300 = 700 > 600 (different) → rejected when treated as a switch
        let list_a = target_list(&[(400, 360)]);
        let list_b = target_list(&[(300, 360)]);
        let info_a = info(16, &list_a, None, None);

        let result_keeps = allocate(
            DataRate::from_kbps(800),
            DataRate::from_kbps(600),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[
                info_a,
                SenderAllocationInfo {
                    active_decode_target: Some(0),
                    ..info(32, &list_b, None, None)
                },
            ],
        );
        assert_eq!(
            result_keeps.selected_decode_targets[1].decode_target,
            Some(0)
        );

        let result_rejects = allocate(
            DataRate::from_kbps(800),
            DataRate::from_kbps(600),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[info_a, info(32, &list_b, None, None)],
        );
        assert_eq!(
            result_rejects.selected_decode_targets[1].decode_target,
            None
        );
    }

    #[test]
    fn hysteresis_preserves_upper_tier_via_incremental_cost() {
        // A sender at decode_target 1 (360p) is checked with rate_budget_for_existing
        // at the upgrade step.  The incremental cost from base (200→600 = +400 kbps)
        // brings total allocated to 600 kbps, which fits within the 900 kbps existing
        // ceiling.  Without an active decode target, the same +400 kbps increment against
        // the 500 kbps different ceiling (200+400=600>500) is rejected, so the sender
        // falls back to the 180p base tier.
        let list = target_list(&[(200, 180), (600, 360)]);

        let result_existing = allocate(
            DataRate::from_kbps(900),
            DataRate::from_kbps(500),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[SenderAllocationInfo {
                active_decode_target: Some(1),
                ..info(16, &list, Some(360), None)
            }],
        );
        assert_eq!(result_existing.allocated_rate, DataRate::from_kbps(600));
        assert_eq!(
            result_existing.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );

        let result_different = allocate(
            DataRate::from_kbps(900),
            DataRate::from_kbps(500),
            1.0,
            DataRate::ZERO,
            DataRate::MAX,
            &[info(16, &list, Some(360), None)],
        );
        assert_eq!(result_different.allocated_rate, DataRate::from_kbps(200));
        assert_eq!(
            result_different.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    // --- Budget parameter interactions ---

    #[test]
    fn allocate_respects_ideal_rate_cap() {
        // ideal_rate = 300 kbps acts as a hard ceiling on both effective budgets regardless
        // of the raw rate_budget (1000 kbps). The 400 kbps ideal tier is unreachable; the
        // 200 kbps tier is selected as the best affordable alternative.
        let list = target_list(&[(200, 180), (400, 360)]);
        let result = allocate(
            DataRate::from_kbps(1000),
            DataRate::from_kbps(1000),
            1.0,
            DataRate::ZERO,
            DataRate::from_kbps(300),
            &[info(16, &list, Some(360), None)],
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(200));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(0))])
        );
    }

    #[test]
    fn allocate_drain_rate_reduces_effective_budget() {
        // rate_budget_for_existing  = max(1000-300, 1000×0.9) = max(700, 900) = 900
        // rate_budget_for_different = max( 400-300,  400×0.9) = max(100, 360) = 360
        // A 500 kbps target passes the existing-budget check but not the different one.
        let list = target_list(&[(500, 360)]);

        let result_existing = allocate(
            DataRate::from_kbps(1000),
            DataRate::from_kbps(400),
            0.9,
            DataRate::from_kbps(300),
            DataRate::MAX,
            &[SenderAllocationInfo {
                active_decode_target: Some(0),
                ..info(16, &list, None, None)
            }],
        );
        assert_eq!(result_existing.allocated_rate, DataRate::from_kbps(500));

        let result_different = allocate(
            DataRate::from_kbps(1000),
            DataRate::from_kbps(400),
            0.9,
            DataRate::from_kbps(300),
            DataRate::MAX,
            &[info(16, &list, None, None)],
        );
        assert_eq!(result_different.allocated_rate, DataRate::ZERO);
    }

    // --- ideal_decode_target edge cases ---

    #[test]
    fn allocate_picks_highest_index_at_ideal_height() {
        // Indices 1 and 2 both resolve to 360p — the ideal height for a 360p request.
        // Index 2 carries more temporal detail and should be preferred over index 1.
        let list = target_list(&[(100, 180), (200, 360), (300, 360), (900, 720)]);
        let result = alloc(
            DataRate::from_kbps(1000),
            &[info(16, &list, Some(360), None)],
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(2))])
        );
    }

    #[test]
    fn allocate_skips_disabled_intermediate_tier() {
        // The 360p tier has rate=0 (sender disabled it). ideal_decode_target skips it and
        // selects 720p as the lowest active tier that still satisfies the height constraint.
        let list = target_list(&[(300, 180), (0, 360), (600, 720)]);
        let result = alloc(
            DataRate::from_kbps(1000),
            &[info(16, &list, Some(360), None)],
        );
        assert_eq!(result.allocated_rate, DataRate::from_kbps(600));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(2))])
        );
    }

    #[test]
    fn allocate_settles_for_highest_tier_when_requested_height_exceeds_all_tiers() {
        // When requested_height (1080p) exceeds every available tier, ideal_decode_target
        // falls back to the highest active tier (360p at index 1) rather than returning
        // None.  The sender is fully upgraded to its best tier.
        let list = target_list(&[(100, 180), (300, 360)]);
        let infos = [info(16, &list, Some(1080), None)];

        let result = alloc(DataRate::from_kbps(10_000), &infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(300));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn calculate_ideal_send_rate_ignores_budget() {
        let list = target_list(&[(100, 180), (5_000_000, 1080)]);
        let infos = [info(16, &list, Some(1080), None)];

        let result = calculate_ideal_send_rate(&infos);

        assert_eq!(result.allocated_rate, DataRate::from_kbps(5_000_000));
        assert_eq!(
            result.selected_decode_targets,
            selected_targets(&[(16, Some(1))])
        );
    }

    #[test]
    fn calculate_base_rate_sums_first_tier_only() {
        let list_a = target_list(&[(100, 180), (900, 720)]);
        let list_b = target_list(&[(50, 180)]);
        let list_c = DecodeTargetInfoList::default();
        let infos = vec![
            info(16, &list_a, None, None),
            info(32, &list_b, None, None),
            info(48, &list_c, None, None),
        ];

        let base_rate = calculate_base_rate(&infos);

        assert_eq!(base_rate, DataRate::from_kbps(150));
    }

    #[test]
    fn calculate_base_rate_skips_declined_senders() {
        // A receiver that has collapsed its grid requests height 0 from everyone. Nothing is
        // forwarded, so nothing may be reported as the base rate either.
        let list_a = target_list(&[(100, 180), (900, 720)]);
        let list_b = target_list(&[(50, 180)]);
        let infos = vec![
            info(16, &list_a, Some(0), None),
            info(32, &list_b, Some(0), None),
        ];

        assert_eq!(calculate_base_rate(&infos), DataRate::ZERO);
        assert_eq!(
            alloc(DataRate::from_kbps(10_000), &infos).allocated_rate,
            DataRate::ZERO
        );
    }

    #[test]
    fn calculate_base_rate_counts_requested_senders_only() {
        // Mixed grid: only the sender the receiver still wants contributes a base rate.
        let list_a = target_list(&[(100, 180), (900, 720)]);
        let list_b = target_list(&[(50, 180)]);
        let infos = vec![
            info(16, &list_a, Some(180), None),
            info(32, &list_b, Some(0), None),
        ];

        let base_rate = calculate_base_rate(&infos);

        assert_eq!(base_rate, DataRate::from_kbps(100));
    }

    #[test]
    fn calculate_base_rate_adds_zero_for_disabled_first_tier() {
        // The first decode target has rate=0 (sender disabled it). ideal_decode_target
        // returns Some(1), so the sender IS included in the base-rate sum — but
        // first().rate = 0, silently contributing nothing. The base rate is underestimated
        // relative to what is actually being forwarded (360p at 500 kbps).
        let list = target_list(&[(0, 180), (500, 360)]);
        let base_rate = calculate_base_rate(&[info(16, &list, None, None)]);
        assert_eq!(base_rate, DataRate::ZERO);
    }
}
