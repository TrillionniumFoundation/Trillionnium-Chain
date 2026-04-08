use super::build_proof_adapter_of_kind;
use crate::proof_adapter_selector::ProofAdapterKind;

#[test]
fn build_proof_adapter_of_kind_maps_all_variants() {
    assert!(build_proof_adapter_of_kind(ProofAdapterKind::Standard).is_ok());
    assert!(build_proof_adapter_of_kind(ProofAdapterKind::TeeReceipt).is_ok());
    assert!(build_proof_adapter_of_kind(ProofAdapterKind::ZkReceipt).is_ok());
}
