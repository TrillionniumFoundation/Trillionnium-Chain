#[path = "proof_adapter_core.rs"]
mod proof_adapter_core;
#[path = "proof_adapter_factory.rs"]
mod proof_adapter_factory;

pub(crate) use proof_adapter_core::{
    build_proof_adapter, ProofAdapter, StandardProofAdapter, TeeReceiptProofAdapter,
    ZkReceiptProofAdapter, DEFAULT_PROOF_ADAPTER,
};

#[cfg(test)]
#[path = "proof_adapter_tests.rs"]
mod tests;
