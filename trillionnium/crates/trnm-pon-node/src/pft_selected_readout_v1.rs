//! Compute a pinned PFT readout while the original selected-owner fence is held.
//! The caller retains its real input, permission, resource and FinalUse owners.

use crate::{pft_native_loader_v1 as loader, pft_readout_f64_v1 as core};
use sha2::{Digest, Sha256};
use trnm_data_availability::cell::{CellAdoptionUseV1, CellErrorV1, CellFileRoleV1};

pub const PROFILE: &str = "trnm.pft.selected-research-readout.v1";
const CANDIDATE_PATH: &str = "pft/online-candidate.json";
const MAX_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum PftSelectedReadoutErrorV1 {
    Owner(CellErrorV1),
    Profile,
    Payload,
    ModelIdentity,
    Loader(loader::NativePftErrorV1),
    Numeric(core::PftErrorV1),
}

/// Numerical observation bound to one current selection and one pinned input.
/// This value carries no model handle, current permission or settlement right.
pub struct PftSelectedReadoutV1 {
    version: [u8; 64],
    revision: u64,
    generation: u64,
    model: core::PftModelDescriptorV1,
    input: core::PftInputDescriptorV1,
    prediction: core::PftPredictionV1,
}

impl PftSelectedReadoutV1 {
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
    pub fn input_descriptor(&self) -> &core::PftInputDescriptorV1 {
        &self.input
    }
    pub fn prediction(&self) -> &core::PftPredictionV1 {
        &self.prediction
    }
}

/// A fresh TCD1 profile, distinct from metadata-only inspection and int257.
pub fn loader_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    for component in [PROFILE, core::FAMILY, loader::PROFILE, core::PROFILE] {
        hash.update(component.as_bytes());
        hash.update([0]);
    }
    hash.finalize().into()
}

/// Read actual catalog metadata, check complete immutable candidate/input bytes,
/// then compute under the same SQLite writer fence. No selected model can be
/// substituted by the caller's comparison packet. A cooperating adopt/rollback
/// cannot run between the owner check and the final numeric checkpoint.
///
/// `check_current` must consult the caller's existing live execution/resource
/// guard. It is checked before parsing, between bounded arithmetic blocks and
/// before returning. This callback does not authenticate its own caller, impose
/// a CPU quota, preempt parsing, or create permission. The caller must keep its
/// original FinalUse guard around any subsequent external effect. Returned
/// metadata is an observation and can become stale after this call.
pub fn predict_selected_pft(
    choice: CellAdoptionUseV1<'_>,
    candidate: &[u8],
    features: &[u8],
    expected: &loader::PftNativeExpectationsV1,
    mut check_current: impl FnMut() -> bool,
) -> Result<PftSelectedReadoutV1, PftSelectedReadoutErrorV1> {
    use PftSelectedReadoutErrorV1 as Error;
    let commitment = choice
        .snapshot
        .selected()
        .ok_or(Error::Owner(CellErrorV1::Invalid(
            "PFT no selected version",
        )))?;
    let revision = choice.snapshot.revision();
    choice
        .owner
        .with_selected_manifest_guard(choice.snapshot, commitment, choice.execution, |selected| {
            let mut compute = || -> Result<PftSelectedReadoutV1, Error> {
                if !check_current() {
                    return Err(Error::Numeric(core::PftErrorV1::ResourceBoundary));
                }
                let closure = selected.model().closure();
                let context = closure.release().context();
                let files = closure.files();
                if context.family != core::FAMILY
                    || closure.loader_profile() != loader_profile_digest()
                    || context.tokenizer != crate::pft_selected_inspection_v1::no_tokenizer_digest()
                    || files.len() != 1
                    || closure.roots() != [0]
                    || files[0].path != CANDIDATE_PATH
                    || files[0].role != CellFileRoleV1::Base
                    || !files[0].dependencies.is_empty()
                {
                    return Err(Error::Profile);
                }
                let file = &files[0];
                if candidate.is_empty()
                    || candidate.len() > MAX_CANDIDATE_BYTES
                    || candidate.len() as u64 != file.payload_bytes
                {
                    return Err(Error::Payload);
                }
                let model = loader::inspect_selected_candidate(
                    candidate,
                    file.payload_sha256,
                    context.layout,
                    context.base,
                )
                .map_err(Error::Loader)?;
                if expected.model != model {
                    return Err(Error::ModelIdentity);
                }
                if !check_current() {
                    return Err(Error::Numeric(core::PftErrorV1::ResourceBoundary));
                }
                let loaded = loader::load_pinned_pft(candidate, features, expected)
                    .map_err(Error::Loader)?;
                let prediction = loaded
                    .predict_checked(&mut check_current)
                    .map_err(Error::Numeric)?;
                Ok(PftSelectedReadoutV1 {
                    version: selected.commitment(),
                    revision,
                    generation: closure.selected_generation(),
                    model,
                    input: loaded.expectations().input.clone(),
                    prediction,
                })
            };
            Ok(compute())
        })
        .map_err(Error::Owner)?
}

#[cfg(test)]
#[path = "pft_selected_readout_v1/tests.rs"]
mod tests;
