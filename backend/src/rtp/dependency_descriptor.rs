//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

// Implements parsing and serialization of the Dependency Descriptor as defined in Appendix A
// of the AV1 RTP specification (https://aomediacodec.github.io/av1-rtp-spec/).

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{anyhow, bail, Result};
use calling_common::PixelSize;
use smallvec::SmallVec;

use crate::bitstream::{BitstreamReader, BitstreamWriter};

pub type DefaultBitstreamWriter = BitstreamWriter<128>;

/// RTP header extension containing frame dependency metadata for scalable video streams.
///
/// # Structure
///
/// - **Mandatory fields** (3 bytes minimum): Present in every descriptor, containing
///   frame boundaries, template ID, and frame number.
/// - **Extended fields** (optional): Present when descriptor size > 3 bytes, containing
///   template dependency structure, active decode targets, and custom overrides.
///
/// # Key Frame vs Delta Frame
///
/// - **Key frames** include a `template_dependency_structure` that defines the entire
///   scalability structure (templates, layers, decode targets, chains).
/// - **Delta frames** reference templates from the most recent key frame, optionally
///   overriding DTIs, Fdiffs, or Chains with custom values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct DependencyDescriptor {
    pub mandatory_fields: MandatoryDescriptorFields,
    pub extended_fields: Option<ExtendedDescriptorFields>,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct MandatoryDescriptorFields {
    /// MUST be set to `true` if the first payload byte of the RTP packet is the beginning of a new
    /// frame, and MUST be set to `false` otherwise. Note that this frame might not be the first
    /// frame of a temporal unit.
    pub start_of_frame: bool,
    /// MUST be set to `true` for the final RTP packet of a frame, and MUST be set to 0 otherwise.
    /// Note  that, if spatial scalability is in use, more frames from the same temporal unit may
    /// follow.
    pub end_of_frame: bool,
    /// ID of the Frame dependency template to use. MUST be in the range of template_id_offset to
    /// (template_id_offset + TemplateCnt - 1), inclusive. frame_dependency_template_id MUST be
    /// the same for all packets of the same frame.
    pub frame_dependency_template_id: u8,
    /// The frame number is represented using 16 bits and increases strictly monotonically in decode
    /// order. frame_number MAY start on a random number, and MUST wrap after reaching the maximum
    /// value. All packets of the same frame MUST have the same frame_number value.
    pub frame_number: u16,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ExtendedDescriptorFields {
    /// This field defines a set of frame templates that describe how frames relate to each other
    /// in a scalable video stream. This field is transmitted in key frames to establish
    /// the decoding framework.
    pub template_dependency_structure: Option<TemplateDependencyStructure>,
    /// active_decode_targets_bitmask contains a bitmask that indicates which Decode targets are
    /// available for decoding. Bit i is equal to 1 if Decode target i is available for decoding,
    /// 0 otherwise. The least significant bit corresponds to Decode target 0.
    pub active_decode_targets_bitmask: ActiveDecodeTargetsBitmask,
    /// Frame DTIs, if present
    pub custom_dtis: Option<Dtis>,
    /// Frame Fdiffs, if present
    pub custom_fdiffs: Option<CustomFdiffs>,
    /// Frame chains, if present
    pub custom_chains: Option<CustomChains>,
}

/// Represents the state and availability of decode targets in the dependency descriptor.
/// - **Uninitialized**: Default state before any decode targets are configured.
/// - **AllImplicitlyActive**: All decode targets are implicitly active based on template
///   dependency structure. Contains the bitmask derived from decode target count where all
///   targets are enabled.
/// - **Available**: Explicitly specifies which decode targets are active via a custom bitmask.
///   Present when the active decode targets present bit is set in extended descriptor fields.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub enum ActiveDecodeTargetsBitmask {
    #[default]
    Uninitialized,
    AllImplicitlyActive {
        bitmask: u32,
        size: usize,
    },
    Available {
        bitmask: u32,
        size: usize,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Template {
    pub layer: Layer,
    pub dtis: Dtis,
    pub fdiffs: Fdiffs,
    pub chains: Chains,
}

// This is a simple macro that implements Deref and DerefMut for simple containers that wrap
// SmallVec. Specifically, this is used for Dtis, Fdiffs, Chains, Resolutions, and Layers.
// Improves legibility.
macro_rules! impl_smallvec_container {
    ($name:ident, $inner_type:ty, $initial_size:tt) => {
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub struct $name(SmallVec<[$inner_type; $initial_size]>);

        impl $name {
            fn push(&mut self, item: $inner_type) {
                self.0.push(item);
            }
        }

        impl Deref for $name {
            type Target = [$inner_type];
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        #[cfg(any(test, feature = "load_test"))]
        impl<const N: usize> From<[$inner_type; N]> for $name {
            fn from(v: [$inner_type; N]) -> Self {
                Self(SmallVec::from_iter(v.into_iter()))
            }
        }
    };
}

impl_smallvec_container!(Layers, Layer, 16);
impl_smallvec_container!(DecodeTargetChainIndices, u8, 16);
impl_smallvec_container!(Resolutions, Resolution, 8);
impl_smallvec_container!(Chains, u8, 16);
impl_smallvec_container!(CustomChains, u8, 16);
impl_smallvec_container!(Fdiffs, u8, 16);
impl_smallvec_container!(CustomFdiffs, u16, 16);
impl_smallvec_container!(Dtis, Dti, 16);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Layer {
    pub spatial_id: u8,
    pub temporal_id: u8,
}

impl Layer {
    pub const fn zero() -> Self {
        Self {
            spatial_id: 0,
            temporal_id: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    pub width: u16,
    pub height: u16,
}

impl Resolution {
    pub const fn zero() -> Self {
        Self {
            width: 0,
            height: 0,
        }
    }
}

impl From<Resolution> for PixelSize {
    fn from(resolution: Resolution) -> Self {
        let Resolution { width, height } = resolution;
        Self { width, height }
    }
}

impl From<PixelSize> for Resolution {
    fn from(pixel_size: PixelSize) -> Self {
        let PixelSize { width, height } = pixel_size;
        Self { width, height }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemplateDependencyStructureFields {
    pub template_id_offset: usize,    // Starting template ID (6 bits, 0-63)
    pub decode_target_count: usize,   // Number of decode targets
    pub chain_count: usize,           // Number of chains for loss detection
    pub max_layer: Layer,             // Highest spatial/temporal layer
    pub layers: Layers,               // All layer combinations
    pub templates: Vec<Template>,     // Frame templates
    pub decode_target_layers: Layers, // Max layer per decode target
    pub decode_target_chain_indices: Option<DecodeTargetChainIndices>,
    pub resolutions: Option<Resolutions>, // Resolution per spatial layer
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TemplateDependencyStructure(Arc<TemplateDependencyStructureFields>);

#[cfg(any(test, feature = "load_test"))]
impl TemplateDependencyStructure {
    pub fn new(template_dependency_structure: TemplateDependencyStructureFields) -> Self {
        Self(Arc::new(template_dependency_structure))
    }
}

impl Deref for TemplateDependencyStructure {
    type Target = TemplateDependencyStructureFields;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dti {
    /// No payload for this decode target is present.
    NotPresent = 0,
    /// Payload for this decode target is present and discardable.
    Discardable = 1,
    /// Payload for this decode target is present and switch is possible.
    Switch = 2,
    /// Payload for this decode target is present but it is neither discardable nor is it
    /// a switch indication.
    Required = 3,
}

impl TryFrom<u8> for Dti {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Dti::NotPresent),
            1 => Ok(Dti::Discardable),
            2 => Ok(Dti::Switch),
            3 => Ok(Dti::Required),
            _ => Err(anyhow!("Invalid DTI value: {}", value)),
        }
    }
}

impl DependencyDescriptor {
    pub fn read(
        bytes: &[u8],
        dependency_structure: Option<&TemplateDependencyStructure>,
    ) -> Result<Self> {
        let mut buffer = BitstreamReader::new(bytes);
        let mandatory_fields = MandatoryDescriptorFields::read(&mut buffer)?;
        let extended_fields = if bytes.len() > 3 {
            Some(ExtendedDescriptorFields::read(
                dependency_structure,
                &mut buffer,
            )?)
        } else {
            None
        };
        Ok(Self {
            mandatory_fields,
            extended_fields,
        })
    }

    pub fn write(&self, writer: &mut DefaultBitstreamWriter) {
        self.mandatory_fields.write(writer);
        if let Some(extended_fields) = &self.extended_fields {
            extended_fields.write(writer);
        }
        writer.write_padding();
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = DefaultBitstreamWriter::default();
        self.write(&mut writer);
        writer.as_slice().to_owned()
    }

    /// Returns `true` if the frame that this descriptor is accompanying is a key frame.
    pub fn is_key_frame(&self) -> bool {
        self.extended_fields
            .as_ref()
            .is_some_and(|v| v.template_dependency_structure.is_some())
    }

    /// Returns the frame number.
    pub fn truncated_frame_number(&self) -> u16 {
        self.mandatory_fields.frame_number
    }

    /// Returns the frame resolution, if one is available. This method will should only be used
    /// if the caller is certain that there will only one resolution be available in
    /// the template dependency structure. This should be the case for simulcast.
    pub fn resolution(&self) -> Option<PixelSize> {
        self.extended_fields
            .as_ref()
            .and_then(|extended_fields| extended_fields.template_dependency_structure.as_ref())
            .and_then(|dependency_structure| dependency_structure.resolutions.as_ref())
            .and_then(|resolutions| resolutions.first().map(|v| (*v).into()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FrameDependencyDefinition {
    template_dependency_structure: TemplateDependencyStructure,
    template_index: usize,
    pub custom_dtis: Option<Dtis>,
    pub custom_fdiffs: Option<CustomFdiffs>,
    pub custom_chains: Option<CustomChains>,
}

impl FrameDependencyDefinition {
    /// Builds a new `FrameDependencyDefinition` from the information in the given dependency
    /// descriptor and the given extended descriptor fields. This method will fail if
    /// the frame dependency template ID is not in the valid range for the given template
    /// dependency structure.
    pub fn new(
        dependency_structure: &TemplateDependencyStructure,
        extended_descriptor_fields: Option<&ExtendedDescriptorFields>,
        frame_dependency_template_id: u8,
    ) -> Result<Self> {
        let template_id = frame_dependency_template_id as usize;
        let template_index = (template_id + 64 - dependency_structure.template_id_offset) % 64;
        if template_index >= dependency_structure.templates.len() {
            bail!("Template ID out of bounds: {}", template_id);
        }
        let template_dependency_structure = dependency_structure.clone();
        let (custom_dtis, custom_fdiffs, custom_chains) = match extended_descriptor_fields {
            Some(v) => (
                v.custom_dtis.clone(),
                v.custom_fdiffs.clone(),
                v.custom_chains.clone(),
            ),
            None => (None, None, None),
        };
        Ok(Self {
            template_index,
            template_dependency_structure,
            custom_dtis,
            custom_fdiffs,
            custom_chains,
        })
    }

    pub fn template_dependency_structure(&self) -> &TemplateDependencyStructure {
        &self.template_dependency_structure
    }

    /// Retrieves the frame's template.
    pub fn template(&self) -> &Template {
        &self.template_dependency_structure.templates[self.template_index]
    }

    /// Retrieves the frame's resolution, if available.
    pub fn resolution(&self) -> Option<Resolution> {
        let index = self.template().layer.spatial_id as usize;
        self.template_dependency_structure
            .resolutions
            .as_ref()
            .map(|resolutions| resolutions[index])
    }

    /// Retrieves the DTI for the given active decode target.
    pub fn dti(&self, active_decode_target: usize) -> Result<Dti> {
        let dti = {
            if let Some(dtis) = self.custom_dtis.as_ref() {
                dtis.get(active_decode_target)
                    .ok_or_else(|| anyhow!("Dependency target out of range"))?
            } else {
                self.template()
                    .dtis
                    .get(active_decode_target)
                    .ok_or_else(|| anyhow!("Dependency target out of range"))?
            }
        };
        Ok(*dti)
    }

    /// Retrieves the frame's layer.
    pub fn layer(&self) -> Layer {
        self.template().layer
    }
}

impl ExtendedDescriptorFields {
    const TEMPLATE_DEPENDENCY_STRUCTURE_PRESENT_BIT: u8 = 1 << 4;
    const ACTIVE_DECODE_TARGETS_PRESENT_BIT: u8 = 1 << 3;
    const CUSTOM_DTIS_PRESENT_BIT: u8 = 1 << 2;
    const CUSTOM_FDIFFS_PRESENT_BIT: u8 = 1 << 1;
    const CUSTOM_CHAINS_PRESENT_BIT: u8 = 1;

    fn read(
        dependency_structure: Option<&TemplateDependencyStructure>,
        buffer: &mut BitstreamReader,
    ) -> Result<Self> {
        let (mut decode_target_count, mut chain_count) = match dependency_structure {
            Some(v) => (Some(v.decode_target_count), Some(v.chain_count)),
            None => (None, None),
        };

        let mut extended_descriptor_fields = Self::default();

        let flags = buffer.read_u8(5)?;

        if flags & Self::TEMPLATE_DEPENDENCY_STRUCTURE_PRESENT_BIT != 0 {
            let dependency_structure = TemplateDependencyStructure::read(buffer)?;
            decode_target_count = Some(dependency_structure.decode_target_count);
            chain_count = Some(dependency_structure.chain_count);
            extended_descriptor_fields.active_decode_targets_bitmask =
                ActiveDecodeTargetsBitmask::AllImplicitlyActive {
                    bitmask: ((1u64 << dependency_structure.decode_target_count) - 1) as u32,
                    size: dependency_structure.decode_target_count,
                };
            extended_descriptor_fields.template_dependency_structure = Some(dependency_structure);
        }
        if flags & Self::ACTIVE_DECODE_TARGETS_PRESENT_BIT != 0 {
            let decode_target_count =
                decode_target_count.ok_or_else(|| anyhow!("Missing dependency structure"))?;
            let active_decode_target_bitmask = buffer.read_u32(decode_target_count)?;
            extended_descriptor_fields.active_decode_targets_bitmask =
                ActiveDecodeTargetsBitmask::Available {
                    bitmask: active_decode_target_bitmask,
                    size: decode_target_count,
                };
        }
        if flags & Self::CUSTOM_DTIS_PRESENT_BIT != 0 {
            let decode_target_count =
                decode_target_count.ok_or_else(|| anyhow!("Missing dependency structure"))?;
            extended_descriptor_fields.custom_dtis = Some(Dtis::read(decode_target_count, buffer)?);
        }
        if flags & Self::CUSTOM_FDIFFS_PRESENT_BIT != 0 {
            extended_descriptor_fields.custom_fdiffs = Some(CustomFdiffs::read(buffer)?);
        }
        if flags & Self::CUSTOM_CHAINS_PRESENT_BIT != 0 {
            let chain_count = chain_count.ok_or_else(|| anyhow!("Missing dependency structure"))?;
            extended_descriptor_fields.custom_chains =
                Some(CustomChains::read(chain_count, buffer)?);
        }

        Ok(extended_descriptor_fields)
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        let mut flags = 0;
        if self.custom_chains.is_some() {
            flags |= Self::CUSTOM_CHAINS_PRESENT_BIT;
        }
        if self.custom_dtis.is_some() {
            flags |= Self::CUSTOM_DTIS_PRESENT_BIT;
        }
        if self.custom_fdiffs.is_some() {
            flags |= Self::CUSTOM_FDIFFS_PRESENT_BIT;
        }
        if let ActiveDecodeTargetsBitmask::Available { .. } = self.active_decode_targets_bitmask {
            flags |= Self::ACTIVE_DECODE_TARGETS_PRESENT_BIT;
        }
        if self.template_dependency_structure.is_some() {
            flags |= Self::TEMPLATE_DEPENDENCY_STRUCTURE_PRESENT_BIT;
        }
        writer.write_u8(flags, 5);
        if let Some(template_dependency_structure) = self.template_dependency_structure.as_ref() {
            template_dependency_structure.write(writer);
        }
        if let ActiveDecodeTargetsBitmask::Available { bitmask, size } =
            self.active_decode_targets_bitmask
        {
            writer.write_u32(bitmask, size);
        }
        if let Some(custom_dtis) = self.custom_dtis.as_ref() {
            custom_dtis.write(writer);
        }
        if let Some(custom_fdiffs) = self.custom_fdiffs.as_ref() {
            custom_fdiffs.write(writer);
        }
        if let Some(custom_chains) = self.custom_chains.as_ref() {
            custom_chains.write(writer);
        }
    }
}

impl TemplateDependencyStructure {
    /// Returns `true` if the frame packet is a part of an active chain. This method will fail if
    /// the decode target chain indices are not (yet) available, for whatever reason.
    pub fn is_part_of_active_chain(
        &self,
        active_decode_targets_bitmask: u32,
        chain_index: usize,
        frame_dependency: &FrameDependencyDefinition,
    ) -> Result<bool> {
        if !self.chain_has_active_decode_targets(active_decode_targets_bitmask, chain_index)? {
            Ok(false)
        } else {
            let decode_target_chain_indices = self
                .decode_target_chain_indices
                .as_ref()
                .ok_or_else(|| anyhow!("Missing decode target chain indices"))?;
            for i in 0..self.decode_target_count {
                let dti = frame_dependency.dti(i)?;
                if decode_target_chain_indices[i] as usize == chain_index
                    && matches!(dti, Dti::NotPresent | Dti::Discardable)
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    /// Returns `true` if the given chain has active decode targets. This method will fail if
    /// the decode target chain indices are not (yet) available, for whatever reason.
    pub fn chain_has_active_decode_targets(
        &self,
        active_decode_target_bitmask: u32,
        chain_index: usize,
    ) -> Result<bool> {
        let decode_target_chain_indices = self
            .decode_target_chain_indices
            .as_ref()
            .ok_or_else(|| anyhow!("Missing decode target chain indices"))?;
        for i in 0..self.decode_target_count {
            if decode_target_chain_indices[i] as usize == chain_index
                && ((active_decode_target_bitmask >> i) & 1) == 1
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read(buffer: &mut BitstreamReader) -> Result<Self> {
        let template_id_offset = buffer.read_u8(6)? as usize;
        let decode_target_count = 1 + buffer.read_u8(5)? as usize;
        let (max_layer, layers) = Layers::read(buffer)?;

        let mut templates: Vec<_> = layers
            .iter()
            .map(|layer| Template {
                layer: *layer,
                ..Default::default()
            })
            .collect();

        for template in &mut templates {
            template
                .dtis
                .extend_from_buffer(decode_target_count, buffer)?;
        }
        for template in &mut templates {
            template.fdiffs.extend_from_buffer(buffer)?;
        }

        let chain_count = buffer.read_non_symmetric(decode_target_count as u8 + 1)? as usize;
        let decode_target_chain_indices = if chain_count > 0 {
            let decode_target_chain_indices =
                DecodeTargetChainIndices::read(decode_target_count, chain_count, buffer)?;
            for template in &mut templates {
                template.chains.extend_from_buffer(chain_count, buffer)?;
            }
            Some(decode_target_chain_indices)
        } else {
            None
        };

        // Associate each decode target with a layer. Specifically, we select
        // the largest layer from the set of templates that are associated with
        // the given decode target.
        let mut decode_target_layers = Layers::default();
        for i in 0..decode_target_count {
            let mut layer = Layer::zero();
            for template in &templates {
                if template.dtis[i] != Dti::NotPresent {
                    layer.spatial_id = layer.spatial_id.max(template.layer.spatial_id);
                    layer.temporal_id = layer.temporal_id.max(template.layer.temporal_id);
                }
            }
            decode_target_layers.push(layer);
        }

        let resolutions = if buffer.read_u8(1)? == 1 {
            Some(Resolutions::read(max_layer.spatial_id as usize, buffer)?)
        } else {
            None
        };

        Ok(Self(Arc::new(TemplateDependencyStructureFields {
            template_id_offset,
            chain_count,
            max_layer,
            layers,
            templates,
            decode_target_count,
            decode_target_layers,
            decode_target_chain_indices,
            resolutions,
        })))
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        writer.write_u8(self.template_id_offset as u8, 6);
        writer.write_u8((self.decode_target_count as u8).saturating_sub(1), 5);

        self.layers.write(writer);

        for template in &self.templates {
            template.dtis.write(writer);
        }
        for template in &self.templates {
            template.fdiffs.write(writer);
        }

        writer.write_non_symmetric(
            self.decode_target_count.saturating_add(1),
            self.chain_count as u8,
        );
        if let Some(decode_target_chain_indices) = self.decode_target_chain_indices.as_ref() {
            decode_target_chain_indices.write(self.chain_count, writer);
            for template in &self.templates {
                template.chains.write(writer);
            }
        }

        if let Some(resolutions) = self.resolutions.as_ref() {
            writer.write_u8(1, 1);
            resolutions.write(writer);
        } else {
            writer.write_u8(0, 1);
        }
    }
}

impl MandatoryDescriptorFields {
    fn read(buffer: &mut BitstreamReader) -> Result<Self> {
        let start_of_frame = buffer.read_u8(1)? == 1;
        let end_of_frame = buffer.read_u8(1)? == 1;
        let frame_dependency_template_id = buffer.read_u8(6)?;
        let frame_number = buffer.read_u16(16)?;
        Ok(Self {
            start_of_frame,
            end_of_frame,
            frame_dependency_template_id,
            frame_number,
        })
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        writer.write_u8(self.start_of_frame.into(), 1);
        writer.write_u8(self.end_of_frame.into(), 1);
        writer.write_u8(self.frame_dependency_template_id, 6);
        writer.write_u16(self.frame_number, 16);
    }
}

impl Dtis {
    fn read(count: usize, buffer: &mut BitstreamReader) -> Result<Self> {
        let mut result = Self::default();
        result.extend_from_buffer(count, buffer)?;
        Ok(result)
    }

    fn extend_from_buffer(&mut self, count: usize, buffer: &mut BitstreamReader) -> Result<()> {
        for _ in 0..count {
            let dti = buffer.read_u8(2)?;
            self.push(dti.try_into()?);
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for dti in &self.0 {
            writer.write_u8(*dti as u8, 2);
        }
    }
}

impl Fdiffs {
    fn extend_from_buffer(&mut self, buffer: &mut BitstreamReader) -> Result<()> {
        while buffer.read_u8(1)? != 0 {
            self.push(buffer.read_u8(4)? + 1);
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for fdiff in &self.0 {
            writer.write_u8(1, 1);
            writer.write_u8(*fdiff - 1, 4);
        }
        writer.write_u8(0, 1);
    }
}

impl CustomFdiffs {
    const VAL_MASK: u16 = 0x1fff;
    const LEN_MASK: u16 = 0xe000;
    const LEN_SHIFT: u16 = 13;

    fn read(buffer: &mut BitstreamReader) -> Result<Self> {
        let mut result = Self::default();
        result.extend_from_buffer(buffer)?;
        Ok(result)
    }

    fn extend_from_buffer(&mut self, buffer: &mut BitstreamReader) -> Result<()> {
        loop {
            let n = buffer.read_u8(2)? as usize;
            if n == 0 {
                break;
            }
            let fdiff = buffer.read_u16(n * 4)? + 1;
            self.push((n as u16) << Self::LEN_SHIFT | fdiff);
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for fdiff in &self.0 {
            let n = ((fdiff & Self::LEN_MASK) >> Self::LEN_SHIFT) as usize;
            writer.write_u8(n as u8, 2);
            writer.write_u16((fdiff & Self::VAL_MASK) - 1, n * 4);
        }
        writer.write_u8(0, 2);
    }

    pub fn get(&self, index: usize) -> Option<u16> {
        self.0.get(index).map(|v| v & Self::VAL_MASK)
    }
}

impl Chains {
    fn extend_from_buffer(&mut self, count: usize, buffer: &mut BitstreamReader) -> Result<()> {
        for _ in 0..count {
            self.push(buffer.read_u8(4)?);
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for chain in &self.0 {
            writer.write_u8(*chain, 4);
        }
    }
}

impl CustomChains {
    fn read(count: usize, buffer: &mut BitstreamReader) -> Result<Self> {
        let mut result = Self::default();
        result.extend_from_buffer(count, buffer)?;
        Ok(result)
    }

    fn extend_from_buffer(&mut self, count: usize, buffer: &mut BitstreamReader) -> Result<()> {
        for _ in 0..count {
            self.push(buffer.read_u8(8)?);
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for chain in &self.0 {
            writer.write_u8(*chain, 8);
        }
    }
}

impl Resolutions {
    fn read(count: usize, buffer: &mut BitstreamReader) -> Result<Self> {
        let mut result = Self::default();
        result.extend_from_buffer(count, buffer)?;
        Ok(result)
    }

    fn extend_from_buffer(&mut self, count: usize, buffer: &mut BitstreamReader) -> Result<()> {
        for _ in 0..=count {
            let width = buffer
                .read_u16(16)?
                .checked_add(1)
                .ok_or(anyhow!("Invalid resolution"))?;
            let height = buffer
                .read_u16(16)?
                .checked_add(1)
                .ok_or(anyhow!("Invalid resolution"))?;
            self.push(Resolution { width, height });
        }
        Ok(())
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        for resolution in &self.0 {
            writer.write_u16(resolution.width - 1, 16);
            writer.write_u16(resolution.height - 1, 16);
        }
    }
}

impl DecodeTargetChainIndices {
    fn read(
        decode_target_count: usize,
        chain_count: usize,
        buffer: &mut BitstreamReader,
    ) -> Result<Self> {
        let mut result = Self::default();
        result.extend_from_buffer(decode_target_count, chain_count, buffer)?;
        Ok(result)
    }

    fn extend_from_buffer(
        &mut self,
        decode_target_count: usize,
        chain_count: usize,
        buffer: &mut BitstreamReader,
    ) -> Result<()> {
        for _ in 0..decode_target_count {
            let index = buffer.read_non_symmetric(chain_count as u8)?;
            self.push(index);
        }
        Ok(())
    }

    fn write(&self, chain_count: usize, writer: &mut DefaultBitstreamWriter) {
        for index in &self.0 {
            writer.write_non_symmetric(chain_count, *index);
        }
    }
}

impl Layers {
    fn read(buffer: &mut BitstreamReader) -> Result<(Layer, Layers)> {
        let mut decode_target_layers = Layers::default();
        let (mut spatial_id, mut temporal_id, mut max_temporal_id) = (0, 0, 0);
        loop {
            decode_target_layers.push(Layer {
                spatial_id,
                temporal_id,
            });
            match buffer.read_u8(2)? {
                0 => {}
                1 => {
                    temporal_id = temporal_id
                        .checked_add(1)
                        .ok_or(anyhow!("Temporal ID overflow"))?;
                    max_temporal_id = max_temporal_id.max(temporal_id);
                }
                2 => {
                    temporal_id = 0;
                    spatial_id = spatial_id
                        .checked_add(1)
                        .ok_or(anyhow!("Spatial ID overflow"))?;
                }
                3 => break,
                _ => unreachable!(),
            }
        }
        let max_layer = Layer {
            spatial_id,
            temporal_id: max_temporal_id,
        };
        Ok((max_layer, decode_target_layers))
    }

    fn write(&self, writer: &mut DefaultBitstreamWriter) {
        let (mut spatial_id, mut temporal_id) = (0, 0);

        for i in 1..self.0.len() {
            let layer = self.0[i];
            if layer.spatial_id == spatial_id {
                if layer.temporal_id == temporal_id {
                    writer.write_u8(0, 2);
                } else {
                    writer.write_u8(1, 2);
                    temporal_id = layer.temporal_id;
                }
            } else {
                writer.write_u8(2, 2);
                spatial_id = layer.spatial_id;
                temporal_id = 0;
            }
        }

        writer.write_u8(3, 2);
    }
}

#[cfg(test)]
mod tests {
    use calling_common::PixelSize;

    use crate::rtp::{
        dependency_descriptor::DependencyDescriptor, ActiveDecodeTargetsBitmask, Dti,
        ExtendedDescriptorFields, FrameDependencyDefinition, Layer, MandatoryDescriptorFields,
        Template, TemplateDependencyStructure, TemplateDependencyStructureFields,
    };

    #[test]
    fn test_decode_encode() {
        let bytes = [
            // stert of frame: true, end of frame: false
            // template dependency structure present
            // decode targets present
            0b10101001, 0b00000100, 0b00110011, 0b11000101, 0b00000101, 0b00010100, 0b10000101,
            0b00111010, 0b10111111, 0b10101010, 0b10100001, 0b10001111, 0b00000100, 0b00110000,
            0b01000011, 0b00000010, 0b10100000, 0b00101010, 0b00000000, 0b01100000, 0b00000001,
            0b00000000, 0b00011011, 0b10010011, 0b01000101, 0b00010101, 0b11100000, 0b10000010,
            0b01110000, 0b01000110, 0b00001000, 0b11000000, 0b11000111, 0b10000111, 0b00000000,
            0b01000011, 0b00100001, 0b01100101, 0b00010001, 0b00010001, 0b01010100, 0b00110010,
            0b01110110, 0b10000000, 0b10011111, 0b10000000, 0b01110111, 0b10000001, 0b00111111,
            0b10000000, 0b11101111, 0b10000000,
        ];

        let deserialized = DependencyDescriptor::read(&bytes, None).expect("decode succeeds");
        assert_eq!(bytes, deserialized.serialize().as_slice());
    }

    #[test]
    fn test_encode_decode_with_custom_fields() {
        let template = Template {
            dtis: [Dti::Required, Dti::NotPresent, Dti::NotPresent].into(),
            chains: [5, 6, 7].into(),
            ..Default::default()
        };
        let template_dependency_structure =
            TemplateDependencyStructure::new(TemplateDependencyStructureFields {
                decode_target_count: 3,
                chain_count: 3,
                decode_target_chain_indices: Some([0, 1, 2].into()),
                decode_target_layers: [Layer::zero(), Layer::zero(), Layer::zero()].into(),
                layers: [Layer::zero()].into(),
                templates: [template].into(),
                ..Default::default()
            });
        let descriptor = DependencyDescriptor {
            mandatory_fields: MandatoryDescriptorFields {
                start_of_frame: true,
                end_of_frame: false,
                frame_dependency_template_id: 0,
                frame_number: 0xc350,
            },
            extended_fields: Some(ExtendedDescriptorFields {
                template_dependency_structure: Some(template_dependency_structure),
                active_decode_targets_bitmask: ActiveDecodeTargetsBitmask::Available {
                    bitmask: 3,
                    size: 3,
                },
                custom_dtis: Some([Dti::Required, Dti::NotPresent, Dti::NotPresent].into()),
                custom_fdiffs: Some([0x6001, 0x6002, 0x6003].into()),
                custom_chains: Some([10, 11, 12].into()),
            }),
        };

        let serialized = descriptor.serialize();
        let deserialized = DependencyDescriptor::read(&serialized, None).expect("decode succeeds");
        assert_eq!(deserialized, descriptor);
    }

    #[test]
    fn read_camera_layer_0() -> anyhow::Result<()> {
        let bytes = [
            0b11000000,
            0b00000000,
            0b00000001,
            0b10000000, // The first bit in this byte indicates that this is for a key frame.
            0b00000010,
            0b00000100,
            0b01001110,
            0b10101010,
            0b10101111,
            0b00101000,
            0b01100000,
            0b01000001,
            0b01001101,
            0b00110100,
            0b01010011,
            0b10001010,
            0b00001001,
            0b01000000,
            // The resolution is 160x120, but the value on the wire is one pixel smaller than the
            // real resolution. 159x119 in binary is 0b1001_1111 x 0b0111_0111 and each value is
            // stored as 2 bytes.
            //
            // The second bit in the following byte indicates that a resolution is included.
            // The third bit is where the width starts.
            0b01_000000,
            0b00_100111,
            // The third bit in the following byte is where the height starts.
            0b11_000000,
            0b00_011101,
            0b11_000000,
        ];

        let descriptor = DependencyDescriptor::read(&bytes, None)?;

        assert!(descriptor.is_key_frame());
        assert_eq!(
            descriptor.resolution(),
            Some(PixelSize {
                width: 160,
                height: 120
            })
        );

        Ok(())
    }

    #[test]
    fn read_screenshare() -> anyhow::Result<()> {
        let bytes = [
            0b10000000,
            0b00001011,
            0b00001011,
            0b10000000, // The first bit in this byte indicates that this is for a key frame.
            0b00000001,
            0b00000100,
            0b11101010,
            0b10101100,
            0b10000101,
            0b00010100,
            0b01010000,
            0b01000110,
            0b0000_0100, // width - 1 is 2879 / 0b0000_1011_0011_1111 (starting on the 7th bit)
            0b0010_1100,
            0b1111_1100, // height - 1 is 1619 / 0b0000_0110_0101_0011 (from the 7th bit)
            0b0001_1001,
            0b0100_1100,
        ];

        let descriptor = DependencyDescriptor::read(&bytes, None)?;

        assert!(descriptor.is_key_frame());
        assert_eq!(
            descriptor.resolution(),
            Some(PixelSize {
                width: 2880,
                height: 1620
            })
        );

        Ok(())
    }

    #[test]
    fn read_no_dependency_structure() -> anyhow::Result<()> {
        let bytes = [0b10000011, 0b00000001, 0b01100101];
        let descriptor = DependencyDescriptor::read(&bytes, None)?;

        assert!(!descriptor.is_key_frame());
        assert_eq!(descriptor.resolution(), None);

        Ok(())
    }

    #[test]
    fn read_ignore_custom_fdiffs() -> anyhow::Result<()> {
        let bytes = [
            0b10000010,
            0b00001011,
            0b00101100,
            // The first bit in the following byte indicates that this isn't a keyframe. The fourth
            // bit indicates that there are custom fdiffs.
            0b0001_0010,
            0b01000000,
        ];

        let descriptor = DependencyDescriptor::read(&bytes, None)?;

        assert!(!descriptor.is_key_frame());
        assert_eq!(descriptor.resolution(), None);

        Ok(())
    }

    #[test]
    fn valid_template_id() -> anyhow::Result<()> {
        let template = TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 4,
            templates: [Template::default(), Template::default()].into(),
            ..Default::default()
        });
        assert!(FrameDependencyDefinition::new(&template, None, 0).is_err());
        FrameDependencyDefinition::new(&template, None, 4)?;
        FrameDependencyDefinition::new(&template, None, 5)?;
        assert!(FrameDependencyDefinition::new(&template, None, 6).is_err());

        let template = TemplateDependencyStructure::new(TemplateDependencyStructureFields {
            template_id_offset: 0,
            templates: [Template::default(), Template::default()].into(),
            ..Default::default()
        });
        assert!(FrameDependencyDefinition::new(&template, None, 15).is_err());
        FrameDependencyDefinition::new(&template, None, 1)?;
        FrameDependencyDefinition::new(&template, None, 0)?;
        assert!(FrameDependencyDefinition::new(&template, None, 2).is_err());

        Ok(())
    }
}
