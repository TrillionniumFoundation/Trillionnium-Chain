//! Inspect a new PFT profile using pins borrowed from the real selected owner.
//! Never returns an executable handle or grants Current/FinalUse authority.

use trnm_data_availability::cell::{CellAdoptionUseV1, CellErrorV1, CellFileRoleV1};

mod binding;
#[cfg(test)]
mod owner_tests;
pub use binding::{
    loader_profile_digest, no_tokenizer_digest, PftSelectedBindingErrorV1, PftSelectedInspectionV1,
    CANDIDATE_PATH, PROFILE,
};

#[derive(Debug)]
pub enum PftSelectedInspectionErrorV1 {
    Owner(CellErrorV1),
    Binding(PftSelectedBindingErrorV1),
}

/// Borrow the catalog's actual selected TCV1 under its existing writer fence.
/// All model comparison pins come from that value. No caller manifest or
/// expected-model packet is accepted. This performs no prediction; the returned
/// metadata observation can become stale immediately after the callback ends.
pub fn inspect_selected_pft(
    choice: CellAdoptionUseV1<'_>,
    candidate: &[u8],
) -> Result<PftSelectedInspectionV1, PftSelectedInspectionErrorV1> {
    let commitment = choice
        .snapshot
        .selected()
        .ok_or(PftSelectedInspectionErrorV1::Owner(CellErrorV1::Invalid(
            "PFT no selected version",
        )))?;
    let revision = choice.snapshot.revision();
    let result = choice
        .owner
        .with_selected_manifest_guard(choice.snapshot, commitment, choice.execution, |selected| {
            let closure = selected.model().closure();
            let context = closure.release().context();
            let Some(file) = closure.files().first() else {
                return Ok(Err(PftSelectedBindingErrorV1::Profile));
            };
            Ok(binding::inspect(
                binding::SelectedMetadata {
                    version: selected.commitment(),
                    revision,
                    generation: closure.selected_generation(),
                    family: &context.family,
                    loader_profile: closure.loader_profile(),
                    base: context.base,
                    layout: context.layout,
                    tokenizer: context.tokenizer,
                    file_count: closure.files().len(),
                    roots: closure.roots(),
                    path: &file.path,
                    is_base: file.role == CellFileRoleV1::Base,
                    dependencies: &file.dependencies,
                    payload_sha256: file.payload_sha256,
                    payload_bytes: file.payload_bytes,
                },
                candidate,
            ))
        })
        .map_err(PftSelectedInspectionErrorV1::Owner)?;
    result.map_err(PftSelectedInspectionErrorV1::Binding)
}
