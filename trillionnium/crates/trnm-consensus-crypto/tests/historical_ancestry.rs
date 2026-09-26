use serde_json::Value;
use trnm_consensus_crypto::{
    verify_historical_header_ancestry_v1, HistoricalAncestryErrorV1, HistoricalAncestryLimitsV1,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact,
    decode_validator_set_v0_exact, Cev0AdmissionBudgetV0,
};

const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn seed() -> (
    trnm_consensus_types::BlockHeader,
    trnm_consensus_types::ValidatorSet,
    trnm_consensus_types::ConsensusParametersV0,
) {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus["positive"];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let parent = raw("preheader", "checkpoint_parent_header_cev0_hex");
    let set =
        decode_validator_set_v0_exact(&raw("preheader", "old_validator_set_cev0_hex")).unwrap();
    let params =
        decode_consensus_parameters_v0_exact(&raw("preheader", "old_parameters_cev0_hex")).unwrap();
    (decode_block_header_v0_exact(&parent).unwrap(), set, params)
}

#[test]
fn caller_limits_cannot_widen_hard_header_cap() {
    let (anchor, set, params) = seed();
    let bytes = anchor.try_cev0_bytes().unwrap();
    let headers = (0..257).map(|_| bytes.as_slice()).collect::<Vec<_>>();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &headers,
        &[],
        &[1],
        HistoricalAncestryLimitsV1 {
            maximum_headers: usize::MAX,
            maximum_transitions: usize::MAX,
            maximum_total_bytes: usize::MAX,
        },
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history count/proof bound")
    ));
}

#[test]
fn empty_terminal_proof_and_zero_total_budget_fail_before_decode() {
    let (anchor, set, params) = seed();
    let bytes = anchor.try_cev0_bytes().unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &[bytes.as_slice()],
        &[],
        &[],
        HistoricalAncestryLimitsV1 {
            maximum_headers: 1,
            maximum_transitions: 0,
            maximum_total_bytes: 0,
        },
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history count/proof bound")
    ));
}

fn evidence_with_roots(
    roots: [&[u8]; 8],
) -> trnm_consensus_types::EpochActivationEvidencePreimagesV0<'static> {
    trnm_consensus_types::EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: Box::leak(roots[0].to_vec().into_boxed_slice()),
        next_epoch_commitment: Box::leak(roots[1].to_vec().into_boxed_slice()),
        authorization_kernel: Box::leak(roots[2].to_vec().into_boxed_slice()),
        old_validator_set: Box::leak(roots[3].to_vec().into_boxed_slice()),
        old_consensus_parameters: Box::leak(roots[4].to_vec().into_boxed_slice()),
        new_validator_set: Box::leak(roots[5].to_vec().into_boxed_slice()),
        new_consensus_parameters: Box::leak(roots[6].to_vec().into_boxed_slice()),
        authenticated_checkpoint_parent_header: Box::leak(roots[7].to_vec().into_boxed_slice()),
    }
}

#[test]
fn every_activation_root_is_screened_before_semantic_decode() {
    let (anchor, set, params) = seed();
    let header = anchor.try_cev0_bytes().unwrap();
    let maxima = [
        8 * 1024 * 1024,
        4096,
        8 * 1024 * 1024,
        1024 * 1024,
        4096,
        1024 * 1024,
        4096,
        4096,
    ];
    for (index, maximum) in maxima.into_iter().enumerate() {
        let mut roots = [&[1u8][..]; 8];
        roots[index] = Box::leak(vec![1u8; maximum + 1].into_boxed_slice());
        let evidence = evidence_with_roots(roots);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let error = verify_historical_header_ancestry_v1(
            &anchor,
            &set,
            &params,
            &[header.as_slice()],
            &[evidence],
            &[1],
            HistoricalAncestryLimitsV1 {
                maximum_headers: 1,
                maximum_transitions: 1,
                maximum_total_bytes: usize::MAX,
            },
            &mut budget,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                HistoricalAncestryErrorV1::Invalid("history activation root bound")
            ),
            "root {index}: {error:?}"
        );
    }
}

#[test]
fn header_proof_count_and_aggregate_bounds_are_distinct() {
    let (anchor, set, params) = seed();
    let header = anchor.try_cev0_bytes().unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let oversized_header = vec![0u8; 4097];
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &[oversized_header.as_slice()],
        &[],
        &[1],
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history header bound")
    ));
    let oversized_proof = vec![0u8; 8 * 1024 * 1024 + 1];
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &[header.as_slice()],
        &[],
        &oversized_proof,
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history count/proof bound")
    ));
    let headers = vec![header.as_slice()];
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &headers,
        &[],
        &[1],
        HistoricalAncestryLimitsV1 {
            maximum_headers: 1,
            maximum_transitions: 0,
            maximum_total_bytes: 1,
        },
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history aggregate bytes")
    ));
    let many = (0..33)
        .map(|_| evidence_with_roots([&[1u8][..]; 8]))
        .collect::<Vec<_>>();
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &headers,
        &many,
        &[1],
        HistoricalAncestryLimitsV1 {
            maximum_headers: 1,
            maximum_transitions: usize::MAX,
            maximum_total_bytes: usize::MAX,
        },
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        HistoricalAncestryErrorV1::Invalid("history count/proof bound")
    ));
}

#[test]
fn genuine_checkpoint_successor_path_reaches_strict_terminal_verifier() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus["positive"];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let anchor_bytes = raw("preheader", "checkpoint_parent_header_cev0_hex");
    let anchor = decode_block_header_v0_exact(&anchor_bytes).unwrap();
    let set =
        decode_validator_set_v0_exact(&raw("preheader", "old_validator_set_cev0_hex")).unwrap();
    let params =
        decode_consensus_parameters_v0_exact(&raw("preheader", "old_parameters_cev0_hex")).unwrap();
    let proof = raw("checkpoint_finality", "raw_finality_proof_cev0_hex");
    let decoded = trnm_consensus_types::decode_finality_proof_v0_exact_with_budget(
        &proof,
        &set,
        &params,
        anchor.timestamp_ms(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let target = decoded.finalized_block().header().try_cev0_bytes().unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let result = verify_historical_header_ancestry_v1(
        &anchor,
        &set,
        &params,
        &[target.as_slice()],
        &[],
        &proof,
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    );
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn anchor_context_must_match_the_independent_validator_set() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let positive = &corpus["positive"];
    let raw =
        |case: &Value, section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let anchor_bytes = raw(positive, "preheader", "checkpoint_parent_header_cev0_hex");
    let anchor = decode_block_header_v0_exact(&anchor_bytes).unwrap();
    let unrelated_set =
        decode_validator_set_v0_exact(&raw(positive, "preheader", "new_validator_set_cev0_hex"))
            .unwrap();
    let unrelated_params = decode_consensus_parameters_v0_exact(&raw(
        positive,
        "preheader",
        "new_parameters_cev0_hex",
    ))
    .unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let error = verify_historical_header_ancestry_v1(
        &anchor,
        &unrelated_set,
        &unrelated_params,
        &[anchor_bytes.as_slice()],
        &[],
        &[1],
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            HistoricalAncestryErrorV1::Invalid("historical anchor context")
        ),
        "{error:?}"
    );
}
