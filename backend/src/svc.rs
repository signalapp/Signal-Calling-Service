//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

pub mod allocator;
mod frame_tracker;
mod simple_bitset;

use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::LazyLock,
};

use calling_common::{DataRate, DataRateTracker, DemuxId, Duration, Instant};
use log::{error, info, trace, warn};
use metrics::event;
use smallvec::SmallVec;
use thiserror::Error;

use crate::{
    call::RtpToSend,
    rtp,
    rtp::{
        ActiveDecodeTargetsBitmask, DependencyDescriptor, Dti, ExtendedDescriptorFields,
        FrameDependencyDefinition, FullFrameNumber, FullSequenceNumber, MandatoryDescriptorFields,
        Resolution, RtpStreamAllocation, TemplateDependencyStructure, expand_frame_number,
    },
    svc::{
        ScalableVideoError::{
            ActiveDecodeTargetsBitmaskNotAvailable, DecodeTargetChainIndicesNotAvailable,
            DependencyDescriptorNotAvailable, DependencyStructureNotAvailable,
            FailedToCreatePacket, InconsistentState, InvalidChainIndex, InvalidDecodeTarget,
            InvalidDemuxId, InvalidFrameDependencyTemplateId, ResolutionsNotAvailable,
            VideoLayerAllocationNotAvailable,
        },
        frame_tracker::{FrameTracker, PacketInfo},
    },
};

/// Maximum number of expected clients. For best performance, this constant should reflect
/// the maximum number of expected clients. Heap allocations will be performed If the number
/// of clients exceeds this value.
pub const MAX_EXPECTED_CLIENTS: usize = 75;

/// Periodic report generation period
const PERIODIC_REPORT_GENERATION_PERIOD: Duration = Duration::from_secs(10);
/// The decode target switching mechanism cannot request keyframes more requently than this
const KEYFRAME_REQUEST_PERIOD: Duration = Duration::from_millis(3000);
/// Base layer target
const BASE_LAYER_TARGET: DecodeTarget = 0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScalableVideoError {
    #[error("Dependency structure not available")]
    DependencyStructureNotAvailable,
    #[error("Dependency descriptor not available")]
    DependencyDescriptorNotAvailable,
    #[error("Failed to create packet")]
    FailedToCreatePacket,
    #[error("Decode target chain indices not available")]
    DecodeTargetChainIndicesNotAvailable,
    #[error("Invalid frame dependency template ID {0:?}")]
    InvalidFrameDependencyTemplateId(u8),
    #[error("Invalid DTI {0:?}")]
    InvalidDti(usize),
    #[error("Invalid frame delta {0:?}")]
    InvalidFrameDelta(u8),
    #[error("Invalid chain index {0:?}")]
    InvalidChainIndex(usize),
    #[error("Invalid active decode targets bitmask")]
    InvalidActiveDecodeTargetsBitmask,
    #[error("Invalid decode target {0:?}")]
    InvalidDecodeTarget(usize),
    #[error("No suitable decode target found")]
    NoSuitableDecodeTargetFound,
    #[error("Resolutions are not available")]
    ResolutionsNotAvailable,
    #[error("Invalid video layer allocation size")]
    InvalidVideoLayerAllocationSize,
    #[error("Invalid demux ID {0:?}")]
    InvalidDemuxId(DemuxId),
    #[error("Inconsistent state")]
    InconsistentState,
    #[error("Active decode targets bitmask is not available")]
    ActiveDecodeTargetsBitmaskNotAvailable,
    #[error("Video layer allocation is not available")]
    VideoLayerAllocationNotAvailable,
    #[error("Frame tracker error")]
    FrameTrackerError(#[from] frame_tracker::FrameTrackerError),
}

#[derive(Default, Debug)]
struct Stats {
    n_recv: usize,
    n_sent: usize,
    n_chain_broken: usize,
    n_decode_target_switch: usize,
}

pub struct ScalableVideoState {
    demux_id: DemuxId,
    sender: ScalableVideoSender,
    receivers: Receivers,
    current_target_rate: DataRate,
    requested_target_rate: Option<DataRate>,
    available_rate: Option<DataRate>,
    next_periodic_report_time: Instant,
}

#[derive(Default)]
struct Receivers(HashMap<DemuxId, ScalableVideoReceiver>);

/// Represents a scalable video receiver.
struct ScalableVideoReceiver {
    // The receiver's demux ID.
    demux_id: DemuxId,
    seqnum: FullSequenceNumber,
    seqnum_offset: FullSequenceNumber,
    max_inbound_seqnum: Option<FullSequenceNumber>,
    // The decode target to which the receiver is about to switch
    switch_decode_target: Option<DecodeTarget>,
    // The decode target bitmask to which the receiver is about to switch.
    switch_decode_target_bitmask: ActiveDecodeTargetsBitmask,
    // The active decode target
    active_decode_target: Option<DecodeTarget>,
    // The active deocode target bitmask
    active_decode_target_bitmask: ActiveDecodeTargetsBitmask,
    // Current frame number
    current_frame_number: Option<FullFrameNumber>,
    // Current rate.
    send_rate: DataRateTracker,
    // Current send/receive stats.
    stats: Stats,
}

/// Represents a scalable video sender, providing functionality
/// to handle and track dependencies, allocation, and decode target
/// information.
///
/// The `ScalableVideoSender` struct is primarily designed to manage the
/// structure of scalable video streams, ensuring proper handling of
/// dependencies, tracking frames, and maintaining allocation details for
/// RTP streams.
#[derive(Debug, Default)]
struct ScalableVideoSender {
    // An optional `TemplateDependencyStructure`, which defines the dependency
    // relationships between the layers of the scalable video stream.
    dependency_structure: Option<TemplateDependencyStructure>,
    // Currently active decode targets.
    active_decode_targets_bitmask: ActiveDecodeTargetsBitmask,
    // Allocation details for the RTP video layers.
    video_layer_allocation: RtpStreamAllocation,
    // Frame tracker for this sender. Keeps track of which frames have been
    // fully received and which frames are currently in flight.
    frame_tracker: FrameTracker,
    max_frame_number: FullFrameNumber,
    // List of `DecodeTargetInfo` structures containing information about each
    // available target in the scalable video stream. This information is
    // updated whenever a new template dependency structure is received.
    decode_targets: DecodeTargetInfoList,
    // Will be set to true if a PLI needs to be sent to the sender.
    needs_keyframe: bool,
    // PLI request throttling. Used by this module only. See `KEYFRAME_REQUEST_PERIOD`
    // for the throttling period.
    next_keyframe_request_time: Option<Instant>,
}

#[derive(Debug)]
pub struct ExtendedPacketInfo {
    pub full_frame_number: FullFrameNumber,
    pub needs_allocation: bool,
    pub frame_dependency_definition: FrameDependencyDefinition,
    pub end_of_frame: bool,
}

#[derive(Debug)]
pub struct ScalableVideoTickResult {
    pub updated_target_rate: Option<DataRate>,
}

/// The `DecodeTargetInfo` struct holds metadata about a target's decoding parameters,
/// including its data rate, resolution, and associated chain index.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DecodeTargetInfo {
    /// Target's data rate, as reported by the sender.
    pub rate: DataRate,
    /// Target's resolution.
    pub resolution: Resolution,
    /// Index of the chain protecting the target.
    pub chain_index: usize,
}

pub type DecodeTargetInfoLists<'a> = SmallVec<[&'a DecodeTargetInfoList; 16]>;

type DecodeTarget = usize;

#[derive(Debug, Default, PartialEq)]
pub struct DecodeTargetInfoList(SmallVec<[DecodeTargetInfo; 16]>);

impl From<SmallVec<[DecodeTargetInfo; 16]>> for DecodeTargetInfoList {
    fn from(slice: SmallVec<[DecodeTargetInfo; 16]>) -> Self {
        DecodeTargetInfoList(slice)
    }
}

impl Deref for DecodeTargetInfoList {
    type Target = SmallVec<[DecodeTargetInfo; 16]>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DecodeTargetInfoList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DecodeTargetInfoList {
    pub fn empty() -> &'static Self {
        static EMPTY_DECODE_TARGET_LIST: LazyLock<DecodeTargetInfoList> =
            LazyLock::new(DecodeTargetInfoList::default);

        &EMPTY_DECODE_TARGET_LIST
    }
}

impl Stats {
    fn inc(counter: &mut usize) {
        *counter = counter.saturating_add(1);
    }

    fn inc_recv(&mut self) {
        Self::inc(&mut self.n_recv);
    }

    fn inc_sent(&mut self) {
        Self::inc(&mut self.n_sent);
    }

    fn inc_chain_broken(&mut self) {
        Self::inc(&mut self.n_chain_broken);
    }

    fn inc_decode_target_switch(&mut self) {
        Self::inc(&mut self.n_decode_target_switch);
    }
}

impl Receivers {
    fn get_mut(&mut self, demux_id: DemuxId) -> Option<&mut ScalableVideoReceiver> {
        self.0.get_mut(&demux_id)
    }

    fn remove(&mut self, demux_id: DemuxId) {
        self.0.remove(&demux_id);
    }

    fn insert(&mut self, demux_id: DemuxId, receiver: ScalableVideoReceiver) {
        self.0.insert(demux_id, receiver);
    }

    fn tick(&mut self, now: Instant) {
        for receiver in self.0.values_mut() {
            receiver.tick(now);
        }
    }

    fn suppress_forwarding(&mut self) {
        for receiver in self.0.values_mut() {
            receiver.suppress_forwarding();
        }
    }

    fn log_periodic_report(&self, sender: &ScalableVideoSender) {
        for receiver in self.0.values() {
            receiver.log_periodic_report(sender);
        }
    }

    fn dispatch_packet(
        &mut self,
        inbound_rtp: &rtp::Packet<&[u8]>,
        ext_info: ExtendedPacketInfo,
        sender: &ScalableVideoSender,
        now: Instant,
    ) -> Result<(Vec<RtpToSend>, bool), ScalableVideoError> {
        let mut rtp_to_send = Vec::with_capacity(self.0.len());
        let mut needs_keyframe = false;
        for receiver in self.0.values_mut() {
            let keyframe_requested =
                receiver.dispatch_packet(inbound_rtp, &ext_info, sender, now, &mut rtp_to_send)?;
            if !needs_keyframe {
                needs_keyframe = keyframe_requested;
            }
        }
        Ok((rtp_to_send, needs_keyframe))
    }
}

#[cfg(test)]
impl Default for ScalableVideoState {
    fn default() -> Self {
        Self {
            demux_id: DemuxId::from_const(0),
            sender: ScalableVideoSender::default(),
            receivers: Receivers::default(),
            requested_target_rate: None,
            available_rate: None,
            current_target_rate: DataRate::ZERO,
            next_periodic_report_time: Instant::now(),
        }
    }
}

impl ScalableVideoState {
    pub fn get_template_dependency_structure(&self) -> Option<TemplateDependencyStructure> {
        self.sender.dependency_structure.clone()
    }

    pub fn new(
        demux_id: DemuxId,
        initial_target_rate: DataRate,
        initial_requested_target_rate: DataRate,
        now: Instant,
    ) -> Self {
        event!("calling.svc.client");
        Self {
            demux_id,
            sender: Default::default(),
            receivers: Default::default(),
            current_target_rate: initial_target_rate,
            requested_target_rate: Some(initial_requested_target_rate),
            available_rate: None,
            next_periodic_report_time: now + PERIODIC_REPORT_GENERATION_PERIOD,
        }
    }

    pub fn needs_keyframe(&self) -> bool {
        self.sender.needs_keyframe
    }

    pub fn add_receiver(&mut self, receiver_demux_id: DemuxId, now: Instant) {
        trace!(
            "svc: {:?}: new receiver: {receiver_demux_id:?}",
            self.demux_id
        );
        self.sender.needs_keyframe = true;
        self.receivers.insert(
            receiver_demux_id,
            ScalableVideoReceiver::new(receiver_demux_id, now),
        );
    }

    pub fn remove_receiver(&mut self, receiver_demux_id: DemuxId) {
        self.receivers.remove(receiver_demux_id);
    }

    /// Initiates a PLI send to the sender.
    pub fn set_needs_keyframe_immediately(&mut self) {
        self.sender.needs_keyframe = true;
    }

    /// Initiates a PLI send to the sendr. This is throttled so that only one keyframe request
    /// can be made during a `KEYFRAME_REQUEST_PERIOD`.
    fn set_needs_keyframe(&mut self, now: Instant) {
        if self
            .sender
            .next_keyframe_request_time
            .is_none_or(|v| v < now)
        {
            self.sender.next_keyframe_request_time = Some(now + KEYFRAME_REQUEST_PERIOD);
            self.sender.needs_keyframe = true;
        }
    }

    /// Returns the list of active decode targets. This list will not include those
    /// targets for which we did not get VLA information.
    pub fn get_decode_targets(&self) -> &DecodeTargetInfoList {
        &self.sender.decode_targets
    }

    /// Sets the requested target rate according to what the client signaled.
    /// The possible reallocation will take place during periodic tick processing.
    pub fn set_requested_target_rate(&mut self, target_rate: DataRate) {
        self.requested_target_rate = Some(target_rate);
    }

    /// Sets the avaialble rate according to what congestion control has calculated.
    /// The possible reallocation will take place during periodic tick processing.
    pub fn set_available_rate(&mut self, available_rate: DataRate) {
        self.available_rate = Some(available_rate);
    }

    /// Retrieves the current target rate. This must always be the smaller of
    /// the requested and available target values.
    pub fn get_target_rate(&self) -> DataRate {
        self.current_target_rate
    }

    /// Sets or clears the decode target for the given receiver.
    /// Passing `None` for `decode_target` effectively shuts down forwarding
    /// for the given client.
    pub fn set_decode_target_for_receiver(
        &mut self,
        receiver_demux_id: DemuxId,
        decode_target: Option<DecodeTarget>,
    ) -> Result<(), ScalableVideoError> {
        let decode_target_params = if let Some(decode_target) = decode_target {
            match self.sender.active_decode_targets_bitmask.size() {
                Some(size) if size > decode_target => Some((decode_target, size)),
                Some(_) => {
                    warn!("svc: {receiver_demux_id:?} bad decode target: {decode_target}");
                    return Err(InvalidDecodeTarget(decode_target));
                }
                None => {
                    warn!("svc: {receiver_demux_id:?} no decode targets");
                    return Err(ActiveDecodeTargetsBitmaskNotAvailable);
                }
            }
        } else {
            None
        };
        self.receivers
            .get_mut(receiver_demux_id)
            .ok_or(InvalidDemuxId(receiver_demux_id))?
            .request_decode_target_switch(decode_target_params);
        Ok(())
    }

    /// Performs initial packet handling. If the packet contains *updated* dependency
    /// information, the internal structures are updated.
    pub fn handle_packet(
        &mut self,
        inbound_rtp: &rtp::Packet<&[u8]>,
        now: Instant,
    ) -> Result<ExtendedPacketInfo, ScalableVideoError> {
        match self.sender.handle_packet(inbound_rtp, now) {
            Ok(ext_info) => {
                // Allocation is required if the underlying dependency structure has been
                // updated. Reset decode targets for all receivers since they could/are
                // invalid at this point.
                if ext_info.needs_allocation {
                    self.receivers.suppress_forwarding();
                }
                Ok(ext_info)
            }
            Err(DependencyDescriptorNotAvailable) => {
                trace!("svc: needs keyframe");
                self.sender.needs_keyframe = true;
                Err(DependencyDescriptorNotAvailable)
            }
            Err(e) => {
                trace!("svc: error: {e}");
                Err(e)
            }
        }
    }

    pub fn dispatch_packet(
        &mut self,
        inbound_rtp: &rtp::Packet<&[u8]>,
        ext_info: ExtendedPacketInfo,
        now: Instant,
    ) -> Result<Vec<RtpToSend>, ScalableVideoError> {
        match self
            .receivers
            .dispatch_packet(inbound_rtp, ext_info, &self.sender, now)
        {
            Ok((rtp_to_send, needs_keyframe)) => {
                if needs_keyframe {
                    self.set_needs_keyframe(now);
                }
                Ok(rtp_to_send)
            }
            Err(e) => {
                error!("svc: {:?}: failed to dispatch packet: {e}", self.demux_id);
                self.sender.needs_keyframe = true;
                self.receivers.suppress_forwarding();
                Err(e)
            }
        }
    }

    fn update_target_rate(&mut self) -> Option<DataRate> {
        let new_target_rate = match (self.requested_target_rate, self.available_rate) {
            (Some(requested_target_rate), Some(available_rate)) => {
                available_rate.min(requested_target_rate)
            }
            (Some(requested_target_rate), None) => requested_target_rate,
            (None, Some(available_rate)) => available_rate,
            _ => DataRate::ZERO,
        };
        if self.current_target_rate != new_target_rate {
            self.current_target_rate = new_target_rate;
            Some(new_target_rate)
        } else {
            None
        }
    }

    /// Advances time-dependent state for all receivers and the sender, emits a periodic log
    /// report if due, and recomputes the target send rate.
    ///
    /// Returns `updated_target_rate` as `Some` only when the effective rate (the minimum of the
    /// requested and available rates) has changed since the last tick, so callers can skip
    /// reconfiguration when nothing has changed.
    pub fn tick(&mut self, now: Instant) -> ScalableVideoTickResult {
        self.receivers.tick(now);
        self.sender.tick(now);
        self.log_periodic_report(now);
        let updated_target_rate = self.update_target_rate();
        ScalableVideoTickResult {
            updated_target_rate,
        }
    }

    fn log_periodic_report(&mut self, now: Instant) {
        if now >= self.next_periodic_report_time {
            self.next_periodic_report_time = now + PERIODIC_REPORT_GENERATION_PERIOD;
            info!(
                "svc: {:?}: requested={:?}, current={:?}, available={:?}, req-keyframe={}",
                self.demux_id,
                self.requested_target_rate,
                self.current_target_rate,
                self.available_rate,
                self.sender.needs_keyframe
            );
            self.receivers.log_periodic_report(&self.sender);
        }
    }
}

impl ScalableVideoReceiver {
    fn new(demux_id: DemuxId, _now: Instant) -> Self {
        Self {
            demux_id,
            seqnum: 0,
            seqnum_offset: 0,
            max_inbound_seqnum: None,
            current_frame_number: None,
            switch_decode_target: None,
            switch_decode_target_bitmask: ActiveDecodeTargetsBitmask::Uninitialized,
            active_decode_target: None,
            active_decode_target_bitmask: ActiveDecodeTargetsBitmask::Uninitialized,
            send_rate: DataRateTracker::default(),
            stats: Stats::default(),
        }
    }

    /// Must be invoked for every dropped packet. Updates stats and adjusts the seqnum
    /// generation logic to take into account the dropped packet.
    #[inline]
    fn on_dropped_packet<T>(&mut self, inbound_rtp: &rtp::Packet<T>) {
        let inbound_seqnum = inbound_rtp.seqnum();
        if self.max_inbound_seqnum.is_none_or(|v| v < inbound_seqnum) {
            self.max_inbound_seqnum = Some(inbound_seqnum);
            self.seqnum_offset += 1;
        }
    }

    #[inline]
    fn on_sent(&mut self, outbound_rtp: &rtp::Packet<Vec<u8>>, now: Instant) {
        self.stats.inc_sent();
        self.send_rate.push(outbound_rtp.size(), now);
    }

    #[inline]
    fn bump_seqnum(&mut self, inbound_seqnum: FullSequenceNumber) -> FullSequenceNumber {
        self.seqnum = inbound_seqnum.saturating_sub(self.seqnum_offset);
        self.seqnum
    }

    #[inline]
    fn switch_decode_target(&mut self) {
        debug_assert!(
            self.switch_decode_target.is_some()
                && self.switch_decode_target_bitmask != ActiveDecodeTargetsBitmask::Uninitialized
        );
        if self.active_decode_target != self.switch_decode_target {
            self.active_decode_target = self.switch_decode_target;
            self.active_decode_target_bitmask = self.switch_decode_target_bitmask;
            self.switch_decode_target = None;
            self.switch_decode_target_bitmask = ActiveDecodeTargetsBitmask::Uninitialized;
            self.stats.inc_decode_target_switch();
            trace!(
                "svc: {:?}: decode target switch: {:?}",
                self.demux_id, self.active_decode_target,
            );
        }
    }

    /// Attempts to downgrade the currently selected active decode target by checking
    /// the chains of the available lower decode targets, looking for the best one with
    /// its chain intact. Once an appropriate decode target is found, a request is
    /// made for a decode target switch. If no appropriate decode target can be found,
    /// the decode target that selects the base layer will be selected (0).
    fn on_chain_broken(
        &mut self,
        sender: &ScalableVideoSender,
        frame_dep: &FrameDependencyDefinition,
    ) -> Result<(), ScalableVideoError> {
        self.stats.inc_chain_broken();
        let (Some(active_decode_target), Some(current_frame_number)) =
            (self.active_decode_target, self.current_frame_number)
        else {
            return Ok(());
        };
        let (Some(bitmask), Some(size)) = (
            sender.active_decode_targets_bitmask.bitmask(),
            sender.active_decode_targets_bitmask.size(),
        ) else {
            self.suppress_forwarding();
            return Ok(());
        };

        let mut selected_target = Some((BASE_LAYER_TARGET, size));
        for target in (0..=active_decode_target).rev() {
            if bitmask & (1 << target) != 0
                && sender.is_chain_intact(target, current_frame_number, frame_dep)?
            {
                selected_target = Some((target, size));
                break;
            }
        }
        trace!(
            "svc: {:?}: will downshift to {selected_target:?}",
            self.demux_id
        );

        self.request_decode_target_switch(selected_target);

        Ok(())
    }

    /// Removes the currently selecte active decode target and clears the pending decode
    /// target switch request.
    fn suppress_forwarding(&mut self) {
        trace!("svc: {:?}: suppressing forwarding", self.demux_id);
        self.active_decode_target = None;
        self.active_decode_target_bitmask = ActiveDecodeTargetsBitmask::Uninitialized;
        self.switch_decode_target = None;
        self.switch_decode_target_bitmask = ActiveDecodeTargetsBitmask::Uninitialized;
    }

    /// Requests a decode target switch. The actual switch will be performed at a later point,
    /// when the next packet is processed. Passing `None` for the decode target will result
    /// in immediate suppression of forwarding.
    fn request_decode_target_switch(&mut self, decode_target: Option<(DecodeTarget, usize)>) {
        if let Some((target, size)) = decode_target {
            if self.switch_decode_target != Some(target) {
                let v = 1 << target;
                let bitmask = ActiveDecodeTargetsBitmask::Available {
                    bitmask: v | (v - 1),
                    size,
                };
                self.switch_decode_target = Some(target);
                self.switch_decode_target_bitmask = bitmask;
            }
        } else {
            self.suppress_forwarding();
        }
    }

    fn tick(&mut self, now: Instant) {
        self.send_rate.update(now);
    }

    /// Evaluates whether decode target switch can be performed. It is always invoked on the frame
    /// boundary. Returns `Some(result)` if it was able to conclusively determine if a switch can
    /// be performed. If `None` is returned it indicates that the switch is a temporal-only switch,
    /// and that the frame dependency structure needs to be consulted.
    ///
    /// This is primarily optimized to handle LxTy_KEY and SxTy layering schemes due to their
    /// dependence on keyframes.
    fn evaluate_switching_point(
        active_target: Option<DecodeTarget>,
        switch_target: DecodeTarget,
        dependency_structure: &TemplateDependencyStructure,
        inbound_rtp: &rtp::Packet<&[u8]>,
    ) -> Result<Option<bool>, ScalableVideoError> {
        let is_keyframe = inbound_rtp
            .dependency_descriptor
            .as_ref()
            .map(|(descriptor, _)| descriptor.is_key_frame())
            .unwrap_or(false);
        // If we don't currently have an active decode target, but this is a keyframe,
        // we can switch.
        let Some(active_target) = active_target else {
            return Ok(Some(is_keyframe));
        };
        let active_layer = dependency_structure
            .decode_target_layers
            .get(active_target)
            .ok_or(InconsistentState)?;
        let switch_layer = dependency_structure
            .decode_target_layers
            .get(switch_target)
            .ok_or(InconsistentState)?;
        // If there is no spatial switch we return None to indicate that the frame
        // dependency structure should be consulted for a temporal layer switch.
        if active_layer.spatial_id == switch_layer.spatial_id {
            Ok(None)
        } else {
            // Otherwise, we are doing a spatial switch and we should only switch if
            // this is a keyframe. This should be avoided if the mode is not one of
            // the SxTy or LxTy_KEY modes.
            Ok(Some(is_keyframe))
        }
    }

    /// This method manages packet forwarding for the receiver. If there is a pending request to switch
    /// the decode target, it will be evaluated here, prior to the evaluation of the packet. Finally,
    /// if the packet is determined that it can be forwarded, it will be added to the `rtp_to_send`
    /// list.
    ///
    /// This method returns `true` if this receiver requires a keyframe from the sender. This will
    /// happen if there currently is no active decode target.
    fn dispatch_packet(
        &mut self,
        inbound_rtp: &rtp::Packet<&[u8]>,
        ext_info: &ExtendedPacketInfo,
        sender: &ScalableVideoSender,
        now: Instant,
        rtp_to_send: &mut Vec<RtpToSend>,
    ) -> Result<bool, ScalableVideoError> {
        let ExtendedPacketInfo {
            frame_dependency_definition: frame_dep,
            full_frame_number: frame_number,
            end_of_frame,
            ..
        } = ext_info;

        self.stats.inc_recv();

        // If this is a packet that belongs to one of the previous frames we'll reject it
        // (since we're not buffering packet (yet?)).
        if self.current_frame_number.is_some_and(|v| v > *frame_number) {
            self.on_dropped_packet(inbound_rtp);
            return Ok(false);
        }

        let mut needs_keyframe = false;

        if self.current_frame_number.is_none_or(|v| v != *frame_number) {
            self.current_frame_number = Some(*frame_number);
            // If there is a switch pending, and we're at a switch point we'll perform a switch
            // here since we're starting a new frame. Otherwise, if there is a switch pending,
            // but this frame is not a good switching point, we'll resume processing frames with
            // the currently selected decode target until the switching point comes around.
            if let Some(switch_target) = self.switch_decode_target {
                let switch_eval_decision = Self::evaluate_switching_point(
                    self.active_decode_target,
                    switch_target,
                    frame_dep.template_dependency_structure(),
                    inbound_rtp,
                )?;
                let can_switch = match switch_eval_decision {
                    Some(can_switch) => {
                        // If we cannot switch because we're waiting for a keyframe we'll request
                        // one here in order to avoid a possible decoder stall. Note: keyframe
                        // requests are throttled in the SVC layer, as well as in the lower
                        // layer that is responsible for putting them on the wire.
                        needs_keyframe = !can_switch;
                        can_switch
                    }
                    None => {
                        let dti = frame_dep
                            .dti(switch_target)
                            .map_err(|_| InvalidDecodeTarget(switch_target))?;
                        dti == Dti::Switch
                    }
                };
                if can_switch {
                    self.switch_decode_target();
                    if !sender.is_chain_intact(switch_target, *frame_number, frame_dep)? {
                        self.on_chain_broken(sender, frame_dep)?;
                    }
                }
            }
        }

        // At this point, if we sill don't have a decode target we'll request a keyframe.
        let Some(decode_target) = self.active_decode_target else {
            self.on_dropped_packet(inbound_rtp);
            return Ok(true);
        };

        let dti = frame_dep
            .dti(decode_target)
            .map_err(|_| InvalidDecodeTarget(decode_target))?;
        if dti != Dti::NotPresent {
            let outbound_rtp = self.rewrite_packet(inbound_rtp, *end_of_frame)?;
            self.on_sent(&outbound_rtp, now);
            rtp_to_send.push((self.demux_id, outbound_rtp));
        } else {
            self.on_dropped_packet(inbound_rtp);
        }

        Ok(needs_keyframe)
    }

    /// Creates a copy of the given packet that incldues the active decode target bitmask.
    /// If the packet already contains the dependency descriptor with the extended fields,
    /// the decode target bitmask will be updated with the current value. Otherwise, a new
    /// decode target bitmask field will be added.
    fn rewrite_packet(
        &mut self,
        inbound_rtp: &rtp::Packet<&[u8]>,
        marker: bool,
    ) -> Result<rtp::Packet<Vec<u8>>, ScalableVideoError> {
        let (mut descriptor, _) = inbound_rtp
            .dependency_descriptor
            .as_ref()
            .ok_or(DependencyDescriptorNotAvailable)?
            .clone();
        if let Some(ext_fields) = descriptor.extended_fields.as_mut() {
            ext_fields.active_decode_targets_bitmask = self.active_decode_target_bitmask;
        } else {
            descriptor.extended_fields = Some(ExtendedDescriptorFields {
                active_decode_targets_bitmask: self.active_decode_target_bitmask,
                ..Default::default()
            });
        }
        let seqnum = self.bump_seqnum(inbound_rtp.seqnum());
        inbound_rtp
            .rewrite_with_dependency_descriptor(seqnum, marker, &descriptor)
            .ok_or(FailedToCreatePacket)
    }

    fn log_periodic_report(&self, sender: &ScalableVideoSender) {
        let dependency_structure = sender.dependency_structure.as_ref();
        let (layer, resolution) = if let (Some(decode_target), Some(dependency_structure)) =
            (self.active_decode_target, dependency_structure)
        {
            let layer = dependency_structure.decode_target_layers.get(decode_target);
            let resolution = layer.and_then(|layer| {
                dependency_structure
                    .resolutions
                    .as_ref()
                    .and_then(|resolutions| resolutions.get(layer.spatial_id as usize))
            });
            (layer, resolution)
        } else {
            (None, None)
        };
        let fraction_sent =
            (self.stats.n_recv > 0).then_some(self.stats.n_sent as f32 / self.stats.n_recv as f32);
        info!(
            "svc: {:?}: active-target={:?}, send-rate={:?}, stats={:?}, seqnum-offset={:?}, \
            layer={layer:?}, resolution={resolution:?}, fraction-sent={fraction_sent:?}",
            self.demux_id,
            self.active_decode_target,
            self.send_rate.rate(),
            self.stats,
            self.seqnum_offset,
        );
    }
}

impl ScalableVideoSender {
    fn tick(&mut self, now: Instant) {
        self.frame_tracker.do_periodic_cleanup(now);
    }

    fn get_frame_dependency_structure(
        &self,
        descriptor: &DependencyDescriptor,
    ) -> Result<FrameDependencyDefinition, ScalableVideoError> {
        let dependency_structure = self
            .dependency_structure
            .as_ref()
            .ok_or(DependencyStructureNotAvailable)?;
        let MandatoryDescriptorFields {
            frame_dependency_template_id,
            ..
        } = descriptor.mandatory_fields;
        FrameDependencyDefinition::new(
            dependency_structure,
            descriptor.extended_fields.as_ref(),
            frame_dependency_template_id,
        )
        .map_err(|_| InvalidFrameDependencyTemplateId(frame_dependency_template_id))
    }

    fn handle_packet(
        &mut self,
        incoming_rtp: &rtp::Packet<&[u8]>,
        now: Instant,
    ) -> Result<ExtendedPacketInfo, ScalableVideoError> {
        let (descriptor, _) = incoming_rtp
            .dependency_descriptor
            .as_ref()
            .ok_or(DependencyDescriptorNotAvailable)?;

        let vla_updated = self.update_vla(incoming_rtp);

        let needs_allocation = self.update_dependency_state(descriptor, vla_updated);

        let frame_dependency_definition = self.get_frame_dependency_structure(descriptor)?;

        let MandatoryDescriptorFields {
            start_of_frame,
            end_of_frame,
            frame_number,
            ..
        } = descriptor.mandatory_fields;
        let full_frame_number = expand_frame_number(frame_number, &mut self.max_frame_number);
        let seqnum = incoming_rtp.seqnum();

        let packet_info = PacketInfo {
            frame_number: full_frame_number,
            start_frame_flag: start_of_frame,
            end_frame_flag: end_of_frame,
            seqnum,
        };
        self.frame_tracker.update(now, packet_info)?;

        Ok(ExtendedPacketInfo {
            full_frame_number,
            needs_allocation,
            frame_dependency_definition,
            end_of_frame,
        })
    }

    fn update_vla(&mut self, incoming_rtp: &rtp::Packet<&[u8]>) -> bool {
        if let Some(vla) = incoming_rtp
            .video_layers_allocation
            .as_ref()
            .and_then(|vla| vla.first())
            && *vla != self.video_layer_allocation
        {
            trace!("svc: vla: {vla:?}");
            self.video_layer_allocation = vla.clone();
            return true;
        }
        false
    }

    fn update_decode_targets(&mut self) -> Result<bool, ScalableVideoError> {
        let vla = &self.video_layer_allocation;
        if vla.is_empty() {
            return Err(VideoLayerAllocationNotAvailable);
        }
        let dependency_structure = self
            .dependency_structure
            .as_ref()
            .ok_or(DependencyStructureNotAvailable)?;
        let chain_indices = dependency_structure
            .decode_target_chain_indices
            .as_ref()
            .ok_or(DecodeTargetChainIndicesNotAvailable)?;
        let n = dependency_structure.decode_target_count;
        if dependency_structure.decode_target_layers.len() < n || chain_indices.len() < n {
            return Err(InconsistentState);
        }
        let resolutions = dependency_structure
            .resolutions
            .as_ref()
            .ok_or(ResolutionsNotAvailable)?;
        let bitmask = self
            .active_decode_targets_bitmask
            .bitmask()
            .ok_or(ActiveDecodeTargetsBitmaskNotAvailable)?;

        let mut targets = DecodeTargetInfoList::default();
        for i in 0..n {
            let layer = dependency_structure.decode_target_layers[i];
            let spatial_id = layer.spatial_id as usize;
            if spatial_id >= vla.len() {
                break;
            }
            let resolution = *(resolutions
                .get(layer.spatial_id as usize)
                .ok_or(InconsistentState)?);
            let rate = if (bitmask & (1 << i)) != 0 {
                let spatial_layer = &vla[spatial_id];
                *(spatial_layer
                    .temporal_layer_rates
                    .get(layer.temporal_id as usize)
                    .ok_or(InconsistentState)?)
            } else {
                DataRate::ZERO
            };
            let chain_index = chain_indices[i] as usize;
            targets.push(DecodeTargetInfo {
                rate,
                resolution,
                chain_index,
            });
        }

        let targets_updated = if targets != self.decode_targets {
            trace!("svc: targets updated: {targets:?}");
            self.decode_targets = targets;
            true
        } else {
            false
        };

        Ok(targets_updated)
    }

    fn update_dependency_state(
        &mut self,
        descriptor: &DependencyDescriptor,
        vla_updated: bool,
    ) -> bool {
        let mut needs_update = vla_updated;

        if let Some(ExtendedDescriptorFields {
            template_dependency_structure: dependency_structure,
            active_decode_targets_bitmask: bitmask,
            ..
        }) = descriptor.extended_fields.as_ref()
        {
            if dependency_structure.is_some() {
                needs_update = true;
                trace!("svc: dependency structure: {dependency_structure:?}");
                self.dependency_structure = dependency_structure.clone();
                self.needs_keyframe = false;
            }
            if (bitmask.is_available() || bitmask.is_all_implicitly_active())
                && self.active_decode_targets_bitmask != *bitmask
            {
                needs_update = true;
                trace!("svc: bitmask: {bitmask:?}");
                self.active_decode_targets_bitmask = *bitmask;
            }
        }
        if !needs_update {
            return false;
        }
        match self.update_decode_targets() {
            Err(InconsistentState) => {
                event!("calling.svc.inconsistent_state");
                warn!("failed to update decode targets: inconsistent state");
                self.active_decode_targets_bitmask = ActiveDecodeTargetsBitmask::Uninitialized;
                self.needs_keyframe = true;
                false
            }
            Err(e) => {
                warn!("failed to update decode targets: {e}");
                false
            }
            Ok(targets_updated) => targets_updated,
        }
    }

    fn is_chain_intact(
        &self,
        decode_target: DecodeTarget,
        frame_number: FullFrameNumber,
        frame_dep: &FrameDependencyDefinition,
    ) -> Result<bool, ScalableVideoError> {
        let chain_index = self
            .decode_targets
            .get(decode_target)
            .ok_or(InvalidDecodeTarget(decode_target))?
            .chain_index;
        let frame_delta = match frame_dep.custom_chains.as_ref() {
            Some(chains) => chains
                .get(chain_index)
                .ok_or(InvalidChainIndex(chain_index))?,
            None => {
                let template = frame_dep.template();
                template
                    .chains
                    .get(chain_index)
                    .ok_or(InvalidChainIndex(chain_index))?
            }
        };
        if *frame_delta == 0 {
            Ok(true)
        } else {
            let frame_number = frame_number
                .checked_sub(*frame_delta as FullFrameNumber)
                .ok_or(ScalableVideoError::InvalidFrameDelta(*frame_delta))?;
            Ok(self.frame_tracker.is_complete(frame_number))
        }
    }
}

#[cfg(test)]
mod tests {
    use calling_common::{DataRate, DemuxId, Instant};
    use smallvec::smallvec;

    use crate::{
        rtp::{
            ActiveDecodeTargetsBitmask, DependencyDescriptor, Dti, ExtendedDescriptorFields,
            Fdiffs, Layer, MandatoryDescriptorFields, Packet, Resolution, RtpStreamAllocation,
            SpatialLayer, Template, TemplateDependencyStructure, TemplateDependencyStructureFields,
            VP8_PAYLOAD_TYPE,
        },
        svc::{
            DecodeTargetInfo, DecodeTargetInfoList,
            ScalableVideoError::{
                ActiveDecodeTargetsBitmaskNotAvailable, DependencyDescriptorNotAvailable,
                DependencyStructureNotAvailable, InvalidDecodeTarget, InvalidDemuxId,
            },
            ScalableVideoSender, ScalableVideoState,
        },
    };

    const DEMUX_A: DemuxId = DemuxId::from_const(16);
    const DEMUX_B: DemuxId = DemuxId::from_const(32);

    /// Minimal L1T1 structure: 1 spatial layer, 1 temporal layer, 1 decode target, 1 chain.
    /// The single template marks the decode target as Required with chain delta 0 (always intact).
    fn make_l1t1_structure() -> TemplateDependencyStructure {
        TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            decode_target_count: 1,
            chain_count: 1,
            max_layer: Layer::zero(),
            layers: [Layer::zero()].into(),
            templates: vec![Template {
                layer: Layer::zero(),
                dtis: [Dti::Required].into(),
                fdiffs: Fdiffs::default(),
                chains: [0u8].into(),
            }],
            decode_target_layers: [Layer::zero()].into(),
            decode_target_chain_indices: Some([0u8].into()),
            resolutions: Some(
                [Resolution {
                    width: 640,
                    height: 360,
                }]
                .into(),
            ),
        })
    }

    /// Like `make_l1t1_structure` but the template marks the decode target as Switch.
    fn make_l1t1_structure_switch() -> TemplateDependencyStructure {
        TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            decode_target_count: 1,
            chain_count: 1,
            max_layer: Layer::zero(),
            layers: [Layer::zero()].into(),
            templates: vec![Template {
                layer: Layer::zero(),
                dtis: [Dti::Switch].into(),
                fdiffs: Fdiffs::default(),
                chains: [0u8].into(),
            }],
            decode_target_layers: [Layer::zero()].into(),
            decode_target_chain_indices: Some([0u8].into()),
            resolutions: Some(
                [Resolution {
                    width: 640,
                    height: 360,
                }]
                .into(),
            ),
        })
    }

    fn make_keyframe_packet(
        seqnum: u64,
        frame_number: u16,
        structure: TemplateDependencyStructure,
        vla: Option<Vec<RtpStreamAllocation>>,
    ) -> Packet<Vec<u8>> {
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: true,
                end_of_frame: true,
                frame_dependency_template_id: 0,
                frame_number,
            },
            extended_fields: Some(ExtendedDescriptorFields {
                template_dependency_structure: Some(structure),
                active_decode_targets_bitmask: ActiveDecodeTargetsBitmask::Available {
                    bitmask: 1,
                    size: 1,
                },
                ..Default::default()
            }),
        };
        let mut packet = Packet::with_dependency_descriptor(
            VP8_PAYLOAD_TYPE,
            seqnum,
            0,
            0x12345678,
            descriptor,
            &[],
        );
        packet.video_layers_allocation = vla;
        packet
    }

    fn make_delta_packet(seqnum: u64, frame_number: u16) -> Packet<Vec<u8>> {
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: true,
                end_of_frame: true,
                frame_dependency_template_id: 0,
                frame_number,
            },
            extended_fields: None,
        };
        Packet::with_dependency_descriptor(VP8_PAYLOAD_TYPE, seqnum, 0, 0x12345678, descriptor, &[])
    }

    fn make_vla(kbps: u64) -> Vec<RtpStreamAllocation> {
        vec![vec![SpatialLayer {
            temporal_layer_rates: vec![DataRate::from_kbps(kbps)],
            size: None,
        }]]
    }

    fn make_packet(
        seqnum: u64,
        frame_number: u16,
        template_id: u8,
        start: bool,
        end: bool,
    ) -> Packet<Vec<u8>> {
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: start,
                end_of_frame: end,
                frame_dependency_template_id: template_id,
                frame_number,
            },
            extended_fields: None,
        };
        Packet::with_dependency_descriptor(VP8_PAYLOAD_TYPE, seqnum, 0, 0x12345678, descriptor, &[])
    }

    /// 3-DT, 3-chain structure for intermediate-layer downgrade tests.
    /// Template 0: DTI=[Switch, Switch, Switch], chain deltas=[0, 0, 0] (all intact).
    /// Template 1: DTI=[Required, Required, Required], chain deltas=[0, 0, 1] (DT2 chain references previous frame).
    fn make_3dt_chain_structure() -> TemplateDependencyStructure {
        TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            decode_target_count: 3,
            chain_count: 3,
            max_layer: Layer::zero(),
            layers: [Layer::zero(), Layer::zero(), Layer::zero()].into(),
            templates: vec![
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Switch, Dti::Switch, Dti::Switch].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8, 0u8, 0u8].into(),
                },
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Required, Dti::Required, Dti::Required].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8, 0u8, 1u8].into(),
                },
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Required, Dti::Required, Dti::Required].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8, 0u8, 1u8].into(),
                },
            ],
            decode_target_layers: [Layer::zero(), Layer::zero(), Layer::zero()].into(),
            decode_target_chain_indices: Some([0u8, 1u8, 2u8].into()),
            resolutions: Some(
                [Resolution {
                    width: 640,
                    height: 360,
                }]
                .into(),
            ),
        })
    }

    fn make_keyframe_packet_3dt(
        seqnum: u64,
        frame_number: u16,
        structure: TemplateDependencyStructure,
    ) -> Packet<Vec<u8>> {
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: true,
                end_of_frame: true,
                frame_dependency_template_id: 0,
                frame_number,
            },
            extended_fields: Some(ExtendedDescriptorFields {
                template_dependency_structure: Some(structure),
                active_decode_targets_bitmask: ActiveDecodeTargetsBitmask::Available {
                    bitmask: 0b111,
                    size: 3,
                },
                ..Default::default()
            }),
        };
        let mut packet = Packet::with_dependency_descriptor(
            VP8_PAYLOAD_TYPE,
            seqnum,
            0,
            0x12345678,
            descriptor,
            &[],
        );
        packet.video_layers_allocation = Some(vec![vec![SpatialLayer {
            temporal_layer_rates: vec![DataRate::from_kbps(500)],
            size: None,
        }]]);
        packet
    }

    /// 1-DT, 2-template structure. Template 0 has Switch DTI (keyframe / switch-point);
    /// template 1 has Required DTI (delta frames). Used to test Required-DTI forwarding.
    fn make_switch_then_required_structure() -> TemplateDependencyStructure {
        TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            decode_target_count: 1,
            chain_count: 1,
            max_layer: Layer::zero(),
            layers: [Layer::zero(), Layer::zero()].into(),
            templates: vec![
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Switch].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8].into(),
                },
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Required].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8].into(),
                },
            ],
            decode_target_layers: [Layer::zero()].into(),
            decode_target_chain_indices: Some([0u8].into()),
            resolutions: Some(
                [Resolution {
                    width: 640,
                    height: 360,
                }]
                .into(),
            ),
        })
    }

    /// 2-DT, 2-template structure for testing `Dti::NotPresent` and mid-frame switch deferral.
    /// Template 0: DT0=Switch, DT1=NotPresent (only DT0 receives these packets).
    /// Template 1: DT0=Switch, DT1=Switch (both DTs can switch / receive these packets).
    fn make_2dt_structure() -> TemplateDependencyStructure {
        TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            decode_target_count: 2,
            chain_count: 2,
            max_layer: Layer::zero(),
            layers: [Layer::zero(), Layer::zero()].into(),
            templates: vec![
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Switch, Dti::NotPresent].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8, 0u8].into(),
                },
                Template {
                    layer: Layer::zero(),
                    dtis: [Dti::Switch, Dti::Switch].into(),
                    fdiffs: Fdiffs::default(),
                    chains: [0u8, 0u8].into(),
                },
            ],
            decode_target_layers: [Layer::zero(), Layer::zero()].into(),
            decode_target_chain_indices: Some([0u8, 1u8].into()),
            resolutions: Some(
                [
                    Resolution {
                        width: 640,
                        height: 360,
                    },
                    Resolution {
                        width: 1280,
                        height: 720,
                    },
                ]
                .into(),
            ),
        })
    }

    /// Keyframe using template 1 (Switch for both DTs) with a 2-DT active bitmask.
    fn make_keyframe_packet_2dt(
        seqnum: u64,
        frame_number: u16,
        structure: TemplateDependencyStructure,
    ) -> Packet<Vec<u8>> {
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: true,
                end_of_frame: true,
                frame_dependency_template_id: 1,
                frame_number,
            },
            extended_fields: Some(ExtendedDescriptorFields {
                template_dependency_structure: Some(structure),
                active_decode_targets_bitmask: ActiveDecodeTargetsBitmask::Available {
                    bitmask: 0b11,
                    size: 2,
                },
                ..Default::default()
            }),
        };
        let mut packet = Packet::with_dependency_descriptor(
            VP8_PAYLOAD_TYPE,
            seqnum,
            0,
            0x12345678,
            descriptor,
            &[],
        );
        packet.video_layers_allocation = Some(vec![vec![SpatialLayer {
            temporal_layer_rates: vec![DataRate::from_kbps(500)],
            size: None,
        }]]);
        packet
    }

    // === Rate management ===

    #[test]
    fn test_update_target_rate_uses_min_of_requested_and_available() {
        let mut state = ScalableVideoState::default();
        state.set_requested_target_rate(DataRate::from_kbps(1000));
        state.set_available_rate(DataRate::from_kbps(800));
        assert_eq!(state.update_target_rate(), Some(DataRate::from_kbps(800)));
        assert_eq!(state.get_target_rate(), DataRate::from_kbps(800));
    }

    #[test]
    fn test_update_target_rate_available_lower_than_requested() {
        let mut state = ScalableVideoState::default();
        state.set_requested_target_rate(DataRate::from_kbps(500));
        state.set_available_rate(DataRate::from_kbps(1000));
        assert_eq!(state.update_target_rate(), Some(DataRate::from_kbps(500)));
    }

    #[test]
    fn test_update_target_rate_with_only_requested() {
        let mut state = ScalableVideoState::default();
        state.set_requested_target_rate(DataRate::from_kbps(1000));
        assert_eq!(state.update_target_rate(), Some(DataRate::from_kbps(1000)));
    }

    #[test]
    fn test_update_target_rate_with_only_available() {
        let mut state = ScalableVideoState::default();
        state.set_available_rate(DataRate::from_kbps(600));
        assert_eq!(state.update_target_rate(), Some(DataRate::from_kbps(600)));
    }

    #[test]
    fn test_update_target_rate_neither_set_no_change() {
        let mut state = ScalableVideoState::default();
        // current_target_rate starts at ZERO, neither rate is set → no change
        assert_eq!(state.update_target_rate(), None);
    }

    #[test]
    fn test_update_target_rate_unchanged_returns_none() {
        let mut state = ScalableVideoState::default();
        state.set_requested_target_rate(DataRate::from_kbps(1000));
        state.update_target_rate();
        assert_eq!(state.update_target_rate(), None);
    }

    // === Receiver management ===

    #[test]
    fn test_add_receiver_sets_needs_keyframe() {
        let mut state = ScalableVideoState::default();
        assert!(!state.needs_keyframe());
        state.add_receiver(DEMUX_A, Instant::now());
        assert!(state.needs_keyframe());
    }

    #[test]
    fn test_keyframe_clears_needs_keyframe() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        assert!(!state.needs_keyframe());
    }

    #[test]
    fn test_add_second_receiver_re_sets_needs_keyframe() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        assert!(!state.needs_keyframe());
        state.add_receiver(DEMUX_B, Instant::now());
        assert!(state.needs_keyframe());
    }

    // === handle_packet errors ===

    #[test]
    fn test_handle_packet_without_dependency_descriptor_returns_error() {
        let mut state = ScalableVideoState::default();
        let packet = Packet::with_empty_tag(VP8_PAYLOAD_TYPE, 100, 0, 0x12345678, None, None, &[]);
        assert!(matches!(
            state.handle_packet(&packet.borrow(), Instant::now()),
            Err(DependencyDescriptorNotAvailable)
        ));
    }

    #[test]
    fn test_handle_packet_without_prior_structure_returns_error() {
        let mut state = ScalableVideoState::default();
        // Delta packet with no extended fields and no prior dependency structure.
        let delta = make_delta_packet(100, 1);
        assert!(matches!(
            state.handle_packet(&delta.borrow(), Instant::now()),
            Err(DependencyStructureNotAvailable)
        ));
    }

    // === update_decode_target_for_receiver errors ===

    #[test]
    fn test_update_decode_target_invalid_demux_id() {
        let mut state = ScalableVideoState::default();
        // Process a keyframe so the sender bitmask is initialized — the bitmask check
        // happens before the receiver lookup, so we need a valid bitmask to reach
        // the InvalidDemuxId error path.
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        // DEMUX_B was never added as a receiver.
        assert_eq!(
            state.set_decode_target_for_receiver(DEMUX_B, Some(0)),
            Err(InvalidDemuxId(DEMUX_B))
        );
    }

    #[test]
    fn test_update_decode_target_no_active_bitmask() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        // No keyframe processed yet; sender bitmask is Uninitialized.
        assert_eq!(
            state.set_decode_target_for_receiver(DEMUX_A, Some(0)),
            Err(ActiveDecodeTargetsBitmaskNotAvailable)
        );
    }

    #[test]
    fn test_update_decode_target_out_of_bounds() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        // size=1, so index 1 is out of bounds
        assert_eq!(
            state.set_decode_target_for_receiver(DEMUX_A, Some(1)),
            Err(InvalidDecodeTarget(1))
        );
    }

    #[test]
    fn test_update_decode_target_none_clears_target() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state.set_decode_target_for_receiver(DEMUX_A, None).unwrap();
        // After clearing, packets should not be forwarded.
        let delta = make_delta_packet(2, 1);
        let ext = state.handle_packet(&delta.borrow(), now).unwrap();
        let forwarded = state.dispatch_packet(&delta.borrow(), ext, now).unwrap();
        assert!(forwarded.is_empty());
    }

    // === Dispatch / forwarding pipeline ===

    #[test]
    fn test_dispatch_packet_no_receivers_returns_empty() {
        let mut state = ScalableVideoState::default();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        let ext = state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        let forwarded = state
            .dispatch_packet(&kf.borrow(), ext, Instant::now())
            .unwrap();
        assert!(forwarded.is_empty());
    }

    #[test]
    fn test_dispatch_packet_required_dti_forwarded() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();
        // Keyframe uses template 0 (Switch) to establish the decode target. Arm the
        // receiver before dispatching the keyframe so dispatching it completes the
        // initial switch: `is_key_frame()` requires the triggering packet itself to
        // carry the dependency structure for a receiver's very first activation.
        let kf = make_keyframe_packet(
            1,
            0,
            make_switch_then_required_structure(),
            Some(make_vla(500)),
        );
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state.dispatch_packet(&kf.borrow(), ext, now).unwrap();

        // Template 1 (Required): should be forwarded to the receiver.
        let required_pkt = make_packet(2, 1, 1, true, true);
        let ext = state.handle_packet(&required_pkt.borrow(), now).unwrap();
        let forwarded = state
            .dispatch_packet(&required_pkt.borrow(), ext, now)
            .unwrap();

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].0, DEMUX_A);
    }

    #[test]
    fn test_dispatch_packet_switch_dti_forwarded() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();
        // Use a structure with Switch DTI; the receiver should still receive the packet.
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure_switch(), Some(make_vla(500)));
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        // Dispatching the keyframe itself completes the initial switch (see note above).
        state.dispatch_packet(&kf.borrow(), ext, now).unwrap();

        let delta = make_delta_packet(2, 1);
        let ext = state.handle_packet(&delta.borrow(), now).unwrap();
        let forwarded = state.dispatch_packet(&delta.borrow(), ext, now).unwrap();

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].0, DEMUX_A);
    }

    #[test]
    fn test_dispatch_packet_multiple_receivers() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        state.add_receiver(DEMUX_B, Instant::now());
        let now = Instant::now();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure_switch(), Some(make_vla(500)));
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_B, Some(0))
            .unwrap();
        // Dispatching the keyframe itself completes the initial switch for both
        // receivers (see note in test_dispatch_packet_required_dti_forwarded).
        state.dispatch_packet(&kf.borrow(), ext, now).unwrap();

        let delta = make_delta_packet(2, 1);
        let ext = state.handle_packet(&delta.borrow(), now).unwrap();
        let forwarded = state.dispatch_packet(&delta.borrow(), ext, now).unwrap();

        assert_eq!(forwarded.len(), 2);
        let demux_ids: std::collections::HashSet<_> = forwarded.iter().map(|(id, _)| *id).collect();
        assert!(demux_ids.contains(&DEMUX_A));
        assert!(demux_ids.contains(&DEMUX_B));
    }

    #[test]
    fn test_remove_receiver_stops_forwarding() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure_switch(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state.remove_receiver(DEMUX_A);

        let delta = make_delta_packet(2, 1);
        let ext = state.handle_packet(&delta.borrow(), now).unwrap();
        let forwarded = state.dispatch_packet(&delta.borrow(), ext, now).unwrap();
        assert!(forwarded.is_empty());
    }

    #[test]
    fn test_dispatch_seqnum_increments_per_packet() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure_switch(), Some(make_vla(500)));
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        // Dispatching the keyframe itself completes the initial switch (see note in
        // test_dispatch_packet_required_dti_forwarded).
        state.dispatch_packet(&kf.borrow(), ext, now).unwrap();

        let delta1 = make_delta_packet(2, 1);
        let ext1 = state.handle_packet(&delta1.borrow(), now).unwrap();
        let fwd1 = state.dispatch_packet(&delta1.borrow(), ext1, now).unwrap();
        let seqnum1 = fwd1[0].1.seqnum();

        let delta2 = make_delta_packet(3, 2);
        let ext2 = state.handle_packet(&delta2.borrow(), now).unwrap();
        let fwd2 = state.dispatch_packet(&delta2.borrow(), ext2, now).unwrap();
        let seqnum2 = fwd2[0].1.seqnum();

        assert_eq!(seqnum2, seqnum1 + 1);
    }

    #[test]
    fn test_tick_propagates_rate_update() {
        let now = Instant::now();
        let mut state = ScalableVideoState::default();
        state.set_requested_target_rate(DataRate::from_kbps(1000));
        state.set_available_rate(DataRate::from_kbps(800));
        let result = state.tick(now);
        assert_eq!(result.updated_target_rate, Some(DataRate::from_kbps(800)));
        assert_eq!(state.get_target_rate(), DataRate::from_kbps(800));
    }

    #[test]
    fn test_get_decode_targets_populated_after_keyframe() {
        let mut state = ScalableVideoState::default();
        let now = Instant::now();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), now).unwrap();
        let targets = state.get_decode_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].rate, DataRate::from_kbps(500));
        assert_eq!(targets[0].chain_index, 0);
        assert_eq!(
            targets[0].resolution,
            Resolution {
                width: 640,
                height: 360
            }
        );
    }

    // === Chain integrity ===

    /// When the highest-layer chain breaks but an intermediate layer chain is intact,
    /// the receiver downgrades to the intermediate layer rather than all the way to the
    /// base layer, so needs_keyframe is NOT set.
    #[test]
    fn test_downgrade_to_intermediate_layer() {
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, Instant::now());
        let now = Instant::now();

        // Keyframe establishes 3-DT structure. Arm the receiver for DT0 before
        // dispatching the keyframe so dispatching it completes the initial switch
        // (see note in test_dispatch_packet_required_dti_forwarded).
        let kf = make_keyframe_packet_3dt(1, 0, make_3dt_chain_structure());
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state.dispatch_packet(&kf.borrow(), ext, now).unwrap();
        assert!(!state.needs_keyframe());

        // Schedule a switch to DT2.
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(2))
            .unwrap();

        // Template-0 has DTI[2]=Switch; dispatching it completes the switch to DT2.
        let trigger = make_packet(2, 1, 0, true, true);
        let ext = state.handle_packet(&trigger.borrow(), now).unwrap();
        state.dispatch_packet(&trigger.borrow(), ext, now).unwrap();

        // Frame 5 uses template 1, which has chain delta=1 for DT2 → references frame 4
        // (never received, so incomplete). DT1 chain delta=0 → always intact.
        // try_downgrade selects DT1, not DT0, so is_switching_to(BASE_LAYER) is false.
        let frame5 = make_packet(3, 5, 1, true, true);
        let ext = state.handle_packet(&frame5.borrow(), now).unwrap();
        state.dispatch_packet(&frame5.borrow(), ext, now).unwrap();

        assert!(!state.needs_keyframe());
    }

    // === NotPresent DTI ===

    #[test]
    fn test_not_present_dti_drops_packet_and_offsets_seqnum() {
        let now = Instant::now();
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, now);

        // Keyframe (template 1, Switch for both DTs) establishes a 2-DT structure.
        let kf = make_keyframe_packet_2dt(1, 0, make_2dt_structure());
        let ext = state.handle_packet(&kf.borrow(), now).unwrap();

        // Receiver targets DT1; template 0 has DT1=NotPresent. Dispatching the keyframe
        // itself completes the initial switch to DT1 (see note in
        // test_dispatch_packet_required_dti_forwarded) and forwards it.
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(1))
            .unwrap();
        let fwd = state.dispatch_packet(&kf.borrow(), ext, now).unwrap();
        assert_eq!(fwd.len(), 1);
        let seqnum_after_switch = fwd[0].1.seqnum();

        // Template 0 (DT1=NotPresent): packet must be dropped and seqnum_offset incremented.
        let not_present_pkt = make_packet(2, 1, 0, true, true);
        let ext = state.handle_packet(&not_present_pkt.borrow(), now).unwrap();
        let fwd = state
            .dispatch_packet(&not_present_pkt.borrow(), ext, now)
            .unwrap();
        assert!(fwd.is_empty(), "packet with NotPresent DTI must be dropped");

        // Next forwarded packet accounts for the skipped seqnum.
        let next_pkt = make_packet(3, 2, 1, true, true);
        let ext = state.handle_packet(&next_pkt.borrow(), now).unwrap();
        let fwd = state.dispatch_packet(&next_pkt.borrow(), ext, now).unwrap();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].1.seqnum(), seqnum_after_switch + 1);
    }

    // === Dependency-structure update suppresses forwarding ===

    #[test]
    fn test_new_structure_suppresses_forwarding_until_target_reset() {
        let now = Instant::now();
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, now);

        // First keyframe; arm the receiver and dispatch it to complete the initial
        // switch (see note in test_dispatch_packet_required_dti_forwarded).
        let kf1 = make_keyframe_packet(1, 0, make_l1t1_structure_switch(), Some(make_vla(500)));
        let ext = state.handle_packet(&kf1.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        state.dispatch_packet(&kf1.borrow(), ext, now).unwrap();

        // A subsequent non-keyframe packet should be forwarded normally.
        let p1 = make_delta_packet(2, 1);
        let ext = state.handle_packet(&p1.borrow(), now).unwrap();
        let fwd = state.dispatch_packet(&p1.borrow(), ext, now).unwrap();
        assert_eq!(
            fwd.len(),
            1,
            "packet should be forwarded before structure change"
        );

        // Second keyframe with different VLA: decode targets change → needs_allocation=true → suppress_forwarding.
        let kf2 = make_keyframe_packet(3, 2, make_l1t1_structure_switch(), Some(make_vla(1000)));
        let ext = state.handle_packet(&kf2.borrow(), now).unwrap();
        assert!(ext.needs_allocation);
        let fwd = state.dispatch_packet(&kf2.borrow(), ext, now).unwrap();
        assert!(
            fwd.is_empty(),
            "forwarding should be suppressed after new structure"
        );

        // Re-arm and verify forwarding resumes once a fresh keyframe arrives. A plain
        // delta packet can't complete this re-activation (see note in
        // test_dispatch_packet_required_dti_forwarded), so a real keyframe is used as
        // the resuming trigger, arming the receiver after `handle_packet` so the
        // re-suppression it causes doesn't clobber the freshly-armed switch target.
        let kf3 = make_keyframe_packet(4, 3, make_l1t1_structure_switch(), Some(make_vla(1000)));
        let ext = state.handle_packet(&kf3.borrow(), now).unwrap();
        state
            .set_decode_target_for_receiver(DEMUX_A, Some(0))
            .unwrap();
        let fwd = state.dispatch_packet(&kf3.borrow(), ext, now).unwrap();
        assert_eq!(
            fwd.len(),
            1,
            "forwarding should resume after re-arming with a keyframe"
        );
    }

    // === API smoke tests ===

    #[test]
    fn test_set_needs_keyframe() {
        let now = Instant::now();
        let mut state = ScalableVideoState::default();
        assert!(!state.needs_keyframe());
        state.set_needs_keyframe(now);
        assert!(state.needs_keyframe());
    }

    #[test]
    fn test_get_template_dependency_structure_none_before_keyframe() {
        let state = ScalableVideoState::default();
        assert!(state.get_template_dependency_structure().is_none());
    }

    #[test]
    fn test_get_template_dependency_structure_some_after_keyframe() {
        let mut state = ScalableVideoState::default();
        let kf = make_keyframe_packet(1, 0, make_l1t1_structure(), Some(make_vla(500)));
        state.handle_packet(&kf.borrow(), Instant::now()).unwrap();
        assert!(state.get_template_dependency_structure().is_some());
    }

    // === ScalableVideoSender::update_vla ===

    #[test]
    fn test_update_vla_empty_list_is_noop() {
        let mut sender = ScalableVideoSender::default();
        let mut packet = make_delta_packet(1, 0);
        packet.video_layers_allocation = Some(vec![]);

        assert!(!sender.update_vla(&packet.borrow()));
        assert_eq!(
            sender.video_layer_allocation,
            RtpStreamAllocation::default()
        );
    }

    #[test]
    fn test_update_vla_first_update_returns_true_and_stores_it() {
        let mut sender = ScalableVideoSender::default();
        let mut packet = make_delta_packet(1, 0);
        packet.video_layers_allocation = Some(make_vla(500));

        assert!(sender.update_vla(&packet.borrow()));
        assert_eq!(sender.video_layer_allocation, make_vla(500)[0]);
    }

    #[test]
    fn test_update_vla_repeated_identical_update_returns_false() {
        let mut sender = ScalableVideoSender::default();
        let mut packet = make_delta_packet(1, 0);
        packet.video_layers_allocation = Some(make_vla(500));

        assert!(sender.update_vla(&packet.borrow()));
        assert!(!sender.update_vla(&packet.borrow()));
    }

    #[test]
    fn test_update_vla_changed_update_returns_true() {
        let mut sender = ScalableVideoSender::default();
        let mut packet = make_delta_packet(1, 0);
        packet.video_layers_allocation = Some(make_vla(500));
        assert!(sender.update_vla(&packet.borrow()));

        packet.video_layers_allocation = Some(make_vla(1000));
        assert!(sender.update_vla(&packet.borrow()));
        assert_eq!(sender.video_layer_allocation, make_vla(1000)[0]);
    }

    // === NotPresent DTI drop bookkeeping (isolated from switch evaluation) ===

    #[test]
    fn test_not_present_dti_increments_seqnum_offset_for_active_receiver() {
        let now = Instant::now();
        let mut state = ScalableVideoState::default();
        state.add_receiver(DEMUX_A, now);

        // Keyframe establishes a 2-DT structure.
        let kf = make_keyframe_packet_2dt(1, 0, make_2dt_structure());
        state.handle_packet(&kf.borrow(), now).unwrap();

        // Directly activate DT1 on the receiver, bypassing the switch-pending flow
        // (switch_decode_target stays `None`), so this test isolates just the
        // NotPresent-drop bookkeeping added to `dispatch_packet`.
        {
            let receiver = state.receivers.0.get_mut(&DEMUX_A).unwrap();
            receiver.active_decode_target = Some(1);
            receiver.active_decode_target_bitmask = ActiveDecodeTargetsBitmask::Available {
                bitmask: 0b11,
                size: 2,
            };
        }

        // Template 0 (DT1 = NotPresent): packet must be dropped and seqnum_offset incremented.
        let dropped_pkt = make_packet(2, 1, 0, true, true);
        let ext = state.handle_packet(&dropped_pkt.borrow(), now).unwrap();
        let fwd = state
            .dispatch_packet(&dropped_pkt.borrow(), ext, now)
            .unwrap();
        assert!(fwd.is_empty(), "packet with NotPresent DTI must be dropped");

        // Next forwarded packet's seqnum must account for the skipped one.
        let next_pkt = make_packet(3, 2, 1, true, true);
        let ext = state.handle_packet(&next_pkt.borrow(), now).unwrap();
        let fwd = state.dispatch_packet(&next_pkt.borrow(), ext, now).unwrap();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].1.seqnum(), next_pkt.seqnum() - 1);
    }

    // === DecodeTargetInfoList PartialEq (derived) ===

    fn make_decode_target_info(rate_kbps: u64, chain_index: usize) -> DecodeTargetInfo {
        DecodeTargetInfo {
            rate: DataRate::from_kbps(rate_kbps),
            resolution: Resolution {
                width: 640,
                height: 360,
            },
            chain_index,
        }
    }

    #[test]
    fn test_decode_target_info_list_partial_eq() {
        let a: DecodeTargetInfoList = smallvec![make_decode_target_info(500, 0)].into();
        let b: DecodeTargetInfoList = smallvec![make_decode_target_info(500, 0)].into();
        let c: DecodeTargetInfoList = smallvec![make_decode_target_info(1000, 0)].into();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
