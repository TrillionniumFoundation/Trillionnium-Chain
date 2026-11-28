//! Pure profile checks over the original guard's private metadata projection.
//! Standalone controls for this file do not exercise or authenticate an owner.

use crate::{pft_native_loader_v1 as loader, pft_readout_f64_v1 as core};
use sha2::{Digest, Sha256};

pub const PROFILE: &str = "trnm.pft.selected-candidate-inspection.v1";
pub const CANDIDATE_PATH: &str = "pft/online-candidate.json";
const MAX_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PftSelectedBindingErrorV1 {
    Profile,
    Selection,
    Payload,
    Candidate(loader::NativePftErrorV1),
}

/// Only the original owner adapter constructs this projection in production.
pub(super) struct SelectedMetadata<'a> {
    pub version: [u8; 64],
    pub revision: u64,
    pub generation: u64,
    pub family: &'a str,
    pub loader_profile: [u8; 32],
    pub base: [u8; 32],
    pub layout: [u8; 32],
    pub tokenizer: [u8; 32],
    pub file_count: usize,
    pub roots: &'a [u16],
    pub path: &'a str,
    pub is_base: bool,
    pub dependencies: &'a [u16],
    pub payload_sha256: [u8; 32],
    pub payload_bytes: u64,
}

/// Nonauthorizing metadata only; contains no weights or executable model handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PftSelectedInspectionV1 {
    version: [u8; 64],
    revision: u64,
    generation: u64,
    model: core::PftModelDescriptorV1,
}

impl PftSelectedInspectionV1 {
    pub fn version_commitment(&self) -> [u8; 64] {
        self.version
    }
    pub fn selection_revision(&self) -> u64 {
        self.revision
    }
    pub fn model_generation(&self) -> u64 {
        self.generation
    }
    pub fn model_descriptor(&self) -> &core::PftModelDescriptorV1 {
        &self.model
    }
}

pub fn loader_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    for component in [
        "trnm.pft.selected-candidate-profile.v1",
        core::FAMILY,
        loader::PROFILE,
        core::PROFILE,
    ] {
        hash.update(component.as_bytes());
        hash.update([0]);
    }
    hash.finalize().into()
}

pub fn no_tokenizer_digest() -> [u8; 32] {
    Sha256::digest(b"trnm.pft.expanded-features-no-tokenizer.v1\0").into()
}

pub(super) fn inspect(
    selected: SelectedMetadata<'_>,
    candidate: &[u8],
) -> Result<PftSelectedInspectionV1, PftSelectedBindingErrorV1> {
    use PftSelectedBindingErrorV1 as Error;
    if selected.version == [0; 64] || selected.revision == 0 || selected.generation == 0 {
        return Err(Error::Selection);
    }
    if selected.family != core::FAMILY
        || selected.loader_profile != loader_profile_digest()
        || selected.tokenizer != no_tokenizer_digest()
        || selected.file_count != 1
        || selected.roots != [0]
        || selected.path != CANDIDATE_PATH
        || !selected.is_base
        || !selected.dependencies.is_empty()
    {
        return Err(Error::Profile);
    }
    if candidate.is_empty()
        || candidate.len() > MAX_CANDIDATE_BYTES
        || candidate.len() as u64 != selected.payload_bytes
    {
        return Err(Error::Payload);
    }
    let model = loader::inspect_selected_candidate(
        candidate,
        selected.payload_sha256,
        selected.layout,
        selected.base,
    )
    .map_err(Error::Candidate)?;
    Ok(PftSelectedInspectionV1 {
        version: selected.version,
        revision: selected.revision,
        generation: selected.generation,
        model,
    })
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;
