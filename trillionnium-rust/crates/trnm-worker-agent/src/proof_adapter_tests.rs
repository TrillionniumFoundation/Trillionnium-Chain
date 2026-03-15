#[cfg(test)]
#[allow(unused_imports)]
use super::{
    build_proof_adapter, ProofAdapter, StandardProofAdapter, TeeReceiptProofAdapter,
    ZkReceiptProofAdapter, DEFAULT_PROOF_ADAPTER,
};

#[cfg(test)]
#[path = "proof_adapter_tests_core.rs"]
mod tests_core;
