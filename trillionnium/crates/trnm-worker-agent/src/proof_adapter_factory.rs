use crate::proof_adapter_selector::ProofAdapterKind;

use super::{ProofAdapter, StandardProofAdapter, TeeReceiptProofAdapter, ZkReceiptProofAdapter};

pub(crate) fn build_proof_adapter_of_kind(
    kind: ProofAdapterKind,
) -> Result<Box<dyn ProofAdapter>, String> {
    Ok(match kind {
        ProofAdapterKind::Standard => Box::new(StandardProofAdapter),
        ProofAdapterKind::TeeReceipt => Box::new(TeeReceiptProofAdapter),
        ProofAdapterKind::ZkReceipt => Box::new(ZkReceiptProofAdapter),
    })
}

#[cfg(test)]
#[path = "proof_adapter_factory_tests.rs"]
mod tests;
