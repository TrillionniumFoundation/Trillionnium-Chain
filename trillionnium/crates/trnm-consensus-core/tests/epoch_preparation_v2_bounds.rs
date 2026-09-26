//! Framing/resource rejection tests. Dummy large roots and headers below are
//! deliberately not cryptographic fixtures: every rejection must precede decode.
use serde_json::Value;
use trnm_consensus_core::{
    prepare_epoch_handoff_evidence_v2, recover_epoch_preparation_v2, EpochPreparationEntryV2,
    EpochPreparationErrorV2, EPOCH_PREPARATION_RECORD_MAGIC_V2, EPOCH_PREPARATION_RECORD_SCHEMA_V2,
    MAX_EPOCH_PREPARATION_RECORD_BYTES_V2,
};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, EpochActivationEvidencePreimagesV0, ValidatorSet,
    MAX_CEV0_ROOT_BYTES_V0,
};

// The shared genuine predecessor corpus also used by the M01 successor fixture.
const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);
const PRECHARGED: usize = 7;

struct RootFixture {
    roots: [Vec<u8>; 8],
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    binding: [u8; 32],
}
impl RootFixture {
    fn new() -> Self {
        let corpus: Value = serde_json::from_str(CORPUS).unwrap();
        let case = &corpus["positive"];
        let read = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
        let roots = [
            read("checkpoint_finality", "raw_finality_proof_cev0_hex"),
            read("preheader", "commitment_cev0_hex"),
            read("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
            read("preheader", "old_validator_set_cev0_hex"),
            read("preheader", "old_parameters_cev0_hex"),
            read("preheader", "new_validator_set_cev0_hex"),
            read("preheader", "new_parameters_cev0_hex"),
            read("preheader", "checkpoint_parent_header_cev0_hex"),
        ];
        Self {
            set: decode_validator_set_v0_exact(&roots[3]).unwrap(),
            parameters: decode_consensus_parameters_v0_exact(&roots[4]).unwrap(),
            roots,
            binding: unhex("4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f")
                .try_into()
                .unwrap(),
        }
    }
    fn entry(&self) -> EpochPreparationEntryV2<'_> {
        EpochPreparationEntryV2 {
            binding_ref: self.binding,
            retained_ancestry: &[],
            evidence: preimages(self.roots.each_ref().map(Vec::as_slice)),
        }
    }
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}
fn preimages(roots: [&[u8]; 8]) -> EpochActivationEvidencePreimagesV0<'_> {
    EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: roots[0],
        next_epoch_commitment: roots[1],
        authorization_kernel: roots[2],
        old_validator_set: roots[3],
        old_consensus_parameters: roots[4],
        new_validator_set: roots[5],
        new_consensus_parameters: roots[6],
        authenticated_checkpoint_parent_header: roots[7],
    }
}
fn budget(cap: usize) -> Cev0AdmissionBudgetV0 {
    let mut budget = Cev0AdmissionBudgetV0::new(
        cap,
        Cev0AdmissionBudgetV0::protocol_v0().maximum_signature_work(),
    );
    budget.charge_signature_work(PRECHARGED).unwrap();
    budget
}
fn reject_preparation(
    root: &RootFixture,
    entries: &[EpochPreparationEntryV2<'_>],
    tip: [u8; 32],
    cap: usize,
) -> EpochPreparationErrorV2 {
    let mut meter = budget(cap);
    let error = prepare_epoch_handoff_evidence_v2(
        entries,
        &root.set,
        &root.parameters,
        root.binding,
        tip,
        &mut meter,
    )
    .unwrap_err();
    assert_eq!(meter.signature_work(), PRECHARGED);
    error
}

#[test]
fn borrowed_counts_and_late_header_bounds_precede_any_signature_work() {
    let root = RootFixture::new();
    for count in [0, 33] {
        assert!(matches!(
            reject_preparation(
                &root,
                &vec![root.entry(); count],
                root.binding,
                MAX_CEV0_ROOT_BYTES_V0
            ),
            EpochPreparationErrorV2::Invalid("entry count")
        ));
    }
    for count in [0, 1, 257] {
        let headers = vec![&[1][..]; count];
        let entries = [
            root.entry(),
            EpochPreparationEntryV2 {
                binding_ref: [2; 32],
                retained_ancestry: &headers,
                ..root.entry()
            },
        ];
        assert!(matches!(
            reject_preparation(&root, &entries, [2; 32], MAX_CEV0_ROOT_BYTES_V0),
            EpochPreparationErrorV2::Invalid("ancestry count")
        ));
    }
    for header in [Vec::new(), vec![0; 4097]] {
        let headers = [&[1][..], header.as_slice()];
        let entries = [
            root.entry(),
            EpochPreparationEntryV2 {
                binding_ref: [2; 32],
                retained_ancestry: &headers,
                ..root.entry()
            },
        ];
        assert!(matches!(
            reject_preparation(&root, &entries, [2; 32], MAX_CEV0_ROOT_BYTES_V0),
            EpochPreparationErrorV2::LengthLimit
        ));
    }
}

#[test]
fn borrowed_eight_root_aggregate_and_caller_cap_are_not_widened() {
    let root = RootFixture::new();
    let large = vec![0; MAX_CEV0_ROOT_BYTES_V0 - 6];
    let mut roots = [&[1][..]; 8];
    roots[0] = &large;
    // Each root fits individually; their combined length is exactly 8 MiB + 1.
    assert_eq!(
        roots.iter().map(|value| value.len()).sum::<usize>(),
        MAX_CEV0_ROOT_BYTES_V0 + 1
    );
    let entry = EpochPreparationEntryV2 {
        evidence: preimages(roots),
        ..root.entry()
    };
    assert!(matches!(
        reject_preparation(&root, &[entry], root.binding, MAX_CEV0_ROOT_BYTES_V0),
        EpochPreparationErrorV2::LengthLimit
    ));
    let real_size = root.roots.iter().map(Vec::len).sum::<usize>();
    assert!(matches!(
        reject_preparation(&root, &[root.entry()], root.binding, real_size - 1),
        EpochPreparationErrorV2::LengthLimit
    ));
}

#[test]
fn borrowed_whole_record_bound_checks_all_entries_before_decoding() {
    let root = RootFixture::new();
    // Nine entries share one 1 MiB allocation, forming nine separate 8 MiB
    // root groups. No 72 MiB serialized record or copied evidence is needed.
    let one_mib = vec![0; 1024 * 1024];
    let evidence = preimages([one_mib.as_slice(); 8]);
    let headers = [&[1][..]; 2];
    let mut entries = vec![EpochPreparationEntryV2 {
        evidence,
        ..root.entry()
    }];
    for index in 2..=9 {
        entries.push(EpochPreparationEntryV2 {
            binding_ref: [index; 32],
            retained_ancestry: &headers,
            evidence,
        });
    }
    assert!(matches!(
        reject_preparation(&root, &entries, [9; 32], MAX_CEV0_ROOT_BYTES_V0),
        EpochPreparationErrorV2::LengthLimit
    ));
}

#[test]
fn authenticated_parameter_cap_rejects_before_unrelated_context_mismatch() {
    let mut root = RootFixture::new();
    let mut fields = root.parameters.fields();
    fields.max_consensus_message_bytes = 1;
    fields.max_block_bytes = 1;
    root.parameters = ConsensusParametersV0::new(fields).unwrap();
    // Deliberately retain the genuine original roots/set. This tests only the
    // earlier configured byte screen: a proof/parameter hash error is not a pass.
    assert!(matches!(
        reject_preparation(&root, &[root.entry()], root.binding, MAX_CEV0_ROOT_BYTES_V0),
        EpochPreparationErrorV2::LengthLimit
    ));
}

fn frame(root: [u8; 32], tip: [u8; 32], entries: &[EpochPreparationEntryV2<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EPOCH_PREPARATION_RECORD_MAGIC_V2);
    bytes.extend_from_slice(&EPOCH_PREPARATION_RECORD_SCHEMA_V2.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&tip);
    bytes.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.binding_ref);
        bytes.extend_from_slice(
            &u32::try_from(entry.retained_ancestry.len())
                .unwrap()
                .to_be_bytes(),
        );
        for header in entry.retained_ancestry {
            blob(&mut bytes, header);
        }
        let evidence = entry.evidence;
        for root in [
            evidence.old_checkpoint_finality,
            evidence.next_epoch_commitment,
            evidence.authorization_kernel,
            evidence.old_validator_set,
            evidence.old_consensus_parameters,
            evidence.new_validator_set,
            evidence.new_consensus_parameters,
            evidence.authenticated_checkpoint_parent_header,
        ] {
            blob(&mut bytes, root);
        }
    }
    bytes
}
fn blob(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
}
fn reject_recovery(
    fixture: &RootFixture,
    bytes: &[u8],
    root: [u8; 32],
    tip: [u8; 32],
) -> EpochPreparationErrorV2 {
    let mut meter = budget(MAX_CEV0_ROOT_BYTES_V0);
    let error = recover_epoch_preparation_v2(
        bytes,
        &fixture.set,
        &fixture.parameters,
        root,
        tip,
        [0; 32],
        &mut meter,
    )
    .unwrap_err();
    assert_eq!(meter.signature_work(), PRECHARGED);
    // Each caller pins a framing error, so a later digest mismatch cannot hide
    // a missed screen. These malformed records intentionally have no valid pin.
    error
}

#[test]
fn recovery_whole_record_and_entry_counts_are_screened_before_copy() {
    let root = RootFixture::new();
    let too_large = vec![0; MAX_EPOCH_PREPARATION_RECORD_BYTES_V2 + 1];
    assert!(matches!(
        reject_recovery(&root, &too_large, root.binding, root.binding),
        EpochPreparationErrorV2::LengthLimit
    ));
    let mut empty = frame(root.binding, root.binding, &[]);
    for count in [0u32, 33, u32::MAX] {
        empty[75..79].copy_from_slice(&count.to_be_bytes());
        assert!(matches!(
            reject_recovery(&root, &empty, root.binding, root.binding),
            EpochPreparationErrorV2::Invalid("entry count")
        ));
    }
}

#[test]
fn recovery_complete_framing_and_independent_pins_precede_crypto() {
    let root = RootFixture::new();
    let original = frame(root.binding, root.binding, &[root.entry()]);
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(matches!(
        reject_recovery(&root, &trailing, root.binding, root.binding),
        EpochPreparationErrorV2::Invalid("trailing bytes")
    ));
    let mut truncated = original.clone();
    truncated.pop();
    assert!(matches!(
        reject_recovery(&root, &truncated, root.binding, root.binding),
        EpochPreparationErrorV2::Invalid("truncated record")
    ));
    for (expected_root, expected_tip) in [([9; 32], root.binding), (root.binding, [9; 32])] {
        assert!(matches!(
            reject_recovery(&root, &original, expected_root, expected_tip),
            EpochPreparationErrorV2::BindingMismatch
        ));
    }
    let headers = [&[1][..]; 2];
    let duplicate = frame(
        root.binding,
        root.binding,
        &[
            root.entry(),
            EpochPreparationEntryV2 {
                retained_ancestry: &headers,
                ..root.entry()
            },
        ],
    );
    assert!(matches!(
        reject_recovery(&root, &duplicate, root.binding, root.binding),
        EpochPreparationErrorV2::Invalid("entry count or duplicate/zero binding")
    ));
    let mut entries = [
        root.entry(),
        EpochPreparationEntryV2 {
            binding_ref: [2; 32],
            retained_ancestry: &headers,
            ..root.entry()
        },
    ];
    for index in [0, 1] {
        let original_binding = entries[index].binding_ref;
        entries[index].binding_ref = [9; 32];
        let wrong_endpoint = frame(root.binding, [2; 32], &entries);
        assert!(matches!(
            reject_recovery(&root, &wrong_endpoint, root.binding, [2; 32]),
            EpochPreparationErrorV2::BindingMismatch
        ));
        entries[index].binding_ref = original_binding;
    }
    entries[1].evidence.old_checkpoint_finality = &[];
    let late_empty_root = frame(root.binding, [2; 32], &entries);
    assert!(matches!(
        reject_recovery(&root, &late_empty_root, root.binding, [2; 32]),
        EpochPreparationErrorV2::LengthLimit
    ));
}
