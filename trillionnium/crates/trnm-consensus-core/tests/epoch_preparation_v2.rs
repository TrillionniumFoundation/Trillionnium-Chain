use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    prepare_epoch_handoff_evidence_v1, prepare_epoch_handoff_evidence_v2,
    recover_epoch_preparation_v1, recover_epoch_preparation_v2, EpochPreparationEntryV2,
    EpochPreparationErrorV2, EpochPreparationV2,
};
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0,
    recover_successor_epoch_activation_authority_strict_v1, StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::{
    Cev0AdmissionBudgetV0, EpochActivationEvidenceBytesV0, EpochActivationEvidencePreimagesV0,
    MAX_CEV0_ROOT_BYTES_V0,
};

// Test-only signing material. This module has no production feature/export.
#[allow(dead_code)]
#[path = "../../trnm-consensus-crypto/tests/support/epoch_successor_fixture_v1.rs"]
mod fixture;

struct Case {
    facts: fixture::GenuineSuccessorFixtureV1,
    headers: Vec<Vec<u8>>,
}
impl Case {
    fn new(bad: fixture::SuccessorBadSignature) -> Self {
        let context =
            StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap();
        let mut facts = fixture::genuine_successor_fixture_v1(&context, true);
        if !matches!(bad, fixture::SuccessorBadSignature::None) {
            let (evidence, _, _, binding, _) =
                fixture::successor_evidence_variant(&context, true, bad);
            facts.second_roots = owned_roots(evidence);
            facts.terminal_binding = binding;
        }
        let headers = facts
            .canonical_ancestry
            .iter()
            .map(|h| h.try_cev0_bytes().unwrap())
            .collect();
        Self { facts, headers }
    }
    fn refs(&self) -> Vec<&[u8]> {
        self.headers.iter().map(Vec::as_slice).collect()
    }
    fn entries<'a>(&'a self, headers: &'a [&'a [u8]]) -> [EpochPreparationEntryV2<'a>; 2] {
        [
            EpochPreparationEntryV2 {
                binding_ref: self.facts.root_binding,
                retained_ancestry: &[],
                evidence: preimages(&self.facts.original_roots),
            },
            EpochPreparationEntryV2 {
                binding_ref: self.facts.terminal_binding,
                retained_ancestry: headers,
                evidence: preimages(&self.facts.second_roots),
            },
        ]
    }
    fn prepare(
        &self,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<EpochPreparationV2, EpochPreparationErrorV2> {
        prepare_epoch_handoff_evidence_v2(
            &self.entries(&self.refs()),
            &self.facts.root_validator_set,
            &self.facts.root_parameters,
            self.facts.root_binding,
            self.facts.terminal_binding,
            budget,
        )
    }
    fn recover(
        &self,
        bytes: &[u8],
        digest: [u8; 32],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<EpochPreparationV2, EpochPreparationErrorV2> {
        recover_epoch_preparation_v2(
            bytes,
            &self.facts.root_validator_set,
            &self.facts.root_parameters,
            self.facts.root_binding,
            self.facts.terminal_binding,
            digest,
            budget,
        )
    }
}
fn owned_roots(e: EpochActivationEvidenceBytesV0) -> [Vec<u8>; 8] {
    [
        e.old_checkpoint_finality,
        e.next_epoch_commitment,
        e.authorization_kernel,
        e.old_validator_set,
        e.old_consensus_parameters,
        e.new_validator_set,
        e.new_consensus_parameters,
        e.authenticated_checkpoint_parent_header,
    ]
}
fn preimages(r: &[Vec<u8>; 8]) -> EpochActivationEvidencePreimagesV0<'_> {
    EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: &r[0],
        next_epoch_commitment: &r[1],
        authorization_kernel: &r[2],
        old_validator_set: &r[3],
        old_consensus_parameters: &r[4],
        new_validator_set: &r[5],
        new_consensus_parameters: &r[6],
        authenticated_checkpoint_parent_header: &r[7],
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"trnm.consensus-core.epoch-preparation-provenance.v2\0");
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}
fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
// Independent inert framing allows malformed but canonically signed-shape
// evidence to reach recovery. It creates no verified preparation owner.
fn record(case: &Case) -> Vec<u8> {
    let mut bytes = b"TRNMEP02\0\x02\0".to_vec();
    bytes.extend_from_slice(&case.facts.root_binding);
    bytes.extend_from_slice(&case.facts.terminal_binding);
    bytes.extend_from_slice(&2u32.to_be_bytes());
    for (binding, headers, roots) in [
        (case.facts.root_binding, &[][..], &case.facts.original_roots),
        (
            case.facts.terminal_binding,
            case.headers.as_slice(),
            &case.facts.second_roots,
        ),
    ] {
        bytes.extend_from_slice(&binding);
        bytes.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        for header in headers {
            frame(&mut bytes, header);
        }
        for root in roots {
            frame(&mut bytes, root);
        }
    }
    bytes
}

#[test]
fn genuine_mixed_successor_roundtrip_preserves_original_roots_and_independent_digest() {
    let case = Case::new(fixture::SuccessorBadSignature::None);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let prepared = case.prepare(&mut budget).unwrap();
    let bytes = prepared.record_v2().encode_v2().unwrap();
    assert_eq!(bytes, record(&case));
    assert_eq!(prepared.record_v2().digest_v2(), digest(&bytes));
    assert_eq!(prepared.record_v2().entry_count_v2(), 2);
    assert_eq!(
        prepared.record_v2().root_binding_v2(),
        case.facts.root_binding
    );
    assert_eq!(
        prepared.record_v2().terminal_binding_v2(),
        case.facts.terminal_binding
    );
    assert_ne!(case.facts.root_binding, case.facts.terminal_binding);
    let mut reopened_budget = Cev0AdmissionBudgetV0::protocol_v0();
    let reopened = case
        .recover(&bytes, digest(&bytes), &mut reopened_budget)
        .unwrap();
    assert_eq!(prepared.record_v2(), reopened.record_v2());
    for owner in [&prepared, &reopened] {
        assert_eq!(
            owner.root_validator_set_v2(),
            &case.facts.root_validator_set
        );
        assert_eq!(owner.root_parameters_v2(), &case.facts.root_parameters);
        assert_ne!(
            owner.root_validator_set_v2(),
            owner.authority_v2().old_validator_set()
        );
    }
    assert_eq!(
        *reopened.authority_v2().binding_ref().as_bytes(),
        case.facts.terminal_binding
    );
    assert_eq!(budget.signature_work(), reopened_budget.signature_work());
    assert!(budget.signature_work() > 0);
}

#[test]
fn exact_one_less_and_precharged_budgets_cover_the_entire_chain() {
    let case = Case::new(fixture::SuccessorBadSignature::None);
    let mut measurement = Cev0AdmissionBudgetV0::protocol_v0();
    let prepared = case.prepare(&mut measurement).unwrap();
    let required = measurement.signature_work();
    let mut exact = Cev0AdmissionBudgetV0::new(MAX_CEV0_ROOT_BYTES_V0, required);
    drop(case.prepare(&mut exact).unwrap());
    assert_eq!(exact.signature_work(), required);
    let mut short = Cev0AdmissionBudgetV0::new(MAX_CEV0_ROOT_BYTES_V0, required - 1);
    assert!(case.prepare(&mut short).is_err());
    assert!(short.signature_work() > 0);
    assert!(short.signature_work() < required);
    let mut prepaid = Cev0AdmissionBudgetV0::new(MAX_CEV0_ROOT_BYTES_V0, required + 7);
    prepaid.charge_signature_work(7).unwrap();
    drop(
        case.recover(
            prepared.record_v2().as_bytes_v2(),
            prepared.record_v2().digest_v2(),
            &mut prepaid,
        )
        .unwrap(),
    );
    assert_eq!(prepaid.signature_work(), required + 7);
    let mut prepaid_short = Cev0AdmissionBudgetV0::new(MAX_CEV0_ROOT_BYTES_V0, required + 6);
    prepaid_short.charge_signature_work(7).unwrap();
    assert!(case
        .recover(
            prepared.record_v2().as_bytes_v2(),
            prepared.record_v2().digest_v2(),
            &mut prepaid_short
        )
        .is_err());
    assert!(prepaid_short.signature_work() > 7);
    assert!(prepaid_short.signature_work() <= required + 6);
}

#[test]
fn v1_bytes_remain_exact_and_contextual_successor_cannot_downgrade() {
    let case = Case::new(fixture::SuccessorBadSignature::None);
    let root = recover_epoch_activation_authority_strict_v0(
        preimages(&case.facts.original_roots),
        &case.facts.root_validator_set,
        &case.facts.root_parameters,
        case.facts.root_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor = recover_successor_epoch_activation_authority_strict_v1(
        &root,
        &case.facts.canonical_ancestry,
        preimages(&case.facts.second_roots),
        case.facts.terminal_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert!(prepare_epoch_handoff_evidence_v1(successor).is_err());
    let prepared = prepare_epoch_handoff_evidence_v1(root).unwrap();
    let mut expected = b"TRNMEP01\0\x01\0".to_vec();
    expected.extend_from_slice(&case.facts.root_binding);
    for root in &case.facts.original_roots {
        frame(&mut expected, root);
    }
    assert_eq!(prepared.record_v1().encode_v1().unwrap(), expected);
    let reopened = recover_epoch_preparation_v1(
        &expected,
        &case.facts.root_validator_set,
        &case.facts.root_parameters,
        case.facts.root_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(reopened.record_v1().encode_v1().unwrap(), expected);
}

#[test]
fn every_truncation_and_wrong_digest_reject_before_signature_work() {
    let case = Case::new(fixture::SuccessorBadSignature::None);
    let bytes = case
        .prepare(&mut Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap()
        .record_v2()
        .encode_v2()
        .unwrap();
    for end in 0..bytes.len() {
        let truncated = &bytes[..end];
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        // Rehash the actual truncated bytes so this exercises framing, not a
        // shortcut that rejects all mutants solely for stale digest pins.
        assert!(
            case.recover(truncated, digest(truncated), &mut budget)
                .is_err(),
            "accepted prefix {end}"
        );
        assert_eq!(
            budget.signature_work(),
            7,
            "charged work for truncated prefix {end}"
        );
    }
    let mut wrong = digest(&bytes);
    wrong[0] ^= 1;
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    assert!(matches!(
        case.recover(&bytes, wrong, &mut budget),
        Err(EpochPreparationErrorV2::DigestMismatch)
    ));
    assert_eq!(budget.signature_work(), 7);
}

#[test]
fn canonical_bad_second_tc_and_handoff_signatures_retain_work_on_both_entrypoints() {
    let honest = Case::new(fixture::SuccessorBadSignature::None);
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    drop(honest.prepare(&mut measured).unwrap());
    let required = measured.signature_work();
    for bad in [
        fixture::SuccessorBadSignature::Seal2Timeout,
        fixture::SuccessorBadSignature::NewHandoff,
    ] {
        let case = Case::new(bad);
        let bytes = record(&case);
        for recovery in [false, true] {
            let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
            budget.charge_signature_work(7).unwrap();
            let result = if recovery {
                case.recover(&bytes, digest(&bytes), &mut budget)
            } else {
                case.prepare(&mut budget)
            };
            assert!(matches!(result, Err(EpochPreparationErrorV2::Successor(_))));
            assert_eq!(budget.signature_work(), required + 7);
        }
    }
}

#[test]
fn authenticated_parent_interval_cannot_be_substituted_or_reordered() {
    let mut case = Case::new(fixture::SuccessorBadSignature::None);
    assert!(case.headers.len() > 2);
    let original = case.headers.clone();
    for variant in 0..3 {
        case.headers = original.clone();
        match variant {
            0 => case.headers.swap(0, 1),
            1 => {
                case.headers.remove(1);
            }
            _ => case.headers[0] = original[1].clone(),
        }
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(matches!(
            case.prepare(&mut budget),
            Err(EpochPreparationErrorV2::Successor(_))
        ));
        assert!(budget.signature_work() > 0); // Strict root work is retained.
    }
}
