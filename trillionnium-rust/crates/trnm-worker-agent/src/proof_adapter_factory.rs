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
mod tests {
    use super::build_proof_adapter_of_kind;
    use crate::proof_adapter_selector::ProofAdapterKind;

    #[test]
    fn build_proof_adapter_of_kind_maps_all_variants() {
        assert!(build_proof_adapter_of_kind(ProofAdapterKind::Standard).is_ok());
        assert!(build_proof_adapter_of_kind(ProofAdapterKind::TeeReceipt).is_ok());
        assert!(build_proof_adapter_of_kind(ProofAdapterKind::ZkReceipt).is_ok());
    }
}
