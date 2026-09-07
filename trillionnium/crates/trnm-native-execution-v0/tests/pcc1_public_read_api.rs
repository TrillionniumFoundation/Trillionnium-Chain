//! Positive external-crate coverage: a missing export must not make the
//! read-result's non-Clone compile-fail example pass for the wrong reason.
use trnm_consensus_crypto::StrictFinalityProofV0;
use trnm_native_execution_v0::{FinalizedNativeApplicationReadV0, PocoFinalizedApplicationReadV0};

#[test]
fn strict_read_result_is_nameable_and_only_exposes_shared_views() {
    let _: fn(&PocoFinalizedApplicationReadV0) -> &FinalizedNativeApplicationReadV0 =
        PocoFinalizedApplicationReadV0::application;
    let _: fn(&PocoFinalizedApplicationReadV0) -> &StrictFinalityProofV0 =
        PocoFinalizedApplicationReadV0::finality;
}
