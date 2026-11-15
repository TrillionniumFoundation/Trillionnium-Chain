use std::io::{self, Cursor, Read};

use sha2::{Digest, Sha256, Sha512};
use trnm_protocol::{
    content_commitment::ContentCommitmentError,
    crypto_profile::{BoundCryptoProfile, CryptoProfile, ProfileBinding, ProfileScope},
};

use super::*;

const PAYLOAD: &[u8] = b"TCM2 model payload readback\n";
const DEPENDENCIES: [&[u8]; CELL_CONTENT_DEPENDENCY_COUNT_V2] = [
    b"base model bytes",
    b"parent model bytes",
    b"tokenizer bytes",
    b"layout bytes",
    b"runtime bytes",
];

fn profile() -> BoundCryptoProfile {
    CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 10,
            retirement_height: Some(100),
        })
        .unwrap()
}

fn context(kind: ContentKind) -> ContentContextV1 {
    ContentContextV1::new(&profile(), kind, [7; 64], 9).unwrap()
}

fn metadata() -> CellContextV1 {
    CellContextV1 {
        family: "test-cell".into(),
        base: [0x11; 32],
        parent: [0x22; 32],
        tokenizer: [0x33; 32],
        layout: [0x44; 32],
        runtime: [0x55; 32],
    }
}

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(64, 1_048_576).unwrap()
}

fn payload_observation(bytes: &[u8]) -> ObservedContentV1 {
    observe_bytes(&context(ContentKind::ModelPayload), &mut budget(), bytes).unwrap()
}

fn dependency_observation(index: usize, bytes: &[u8]) -> ObservedContentV1 {
    let context = ContentContextV1::new(
        &profile(),
        ContentKind::ModelPayload,
        [11 + index as u8; 64],
        20 + index as u64,
    )
    .unwrap();
    observe_bytes(&context, &mut budget(), bytes).unwrap()
}

fn pin(closure: &CellContentClosureV2) -> ContentClaimV1 {
    closure
        .observe_closure(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap()
        .claim()
        .clone()
}

fn fixture() -> (CellContentClosureV2, ContentClaimV1) {
    let dependencies: [ObservedContentV1; CELL_CONTENT_DEPENDENCY_COUNT_V2] =
        std::array::from_fn(|index| dependency_observation(index, DEPENDENCIES[index]));
    let closure = CellContentClosureV2::from_observed_contents(
        metadata(),
        &payload_observation(PAYLOAD),
        std::array::from_fn(|index| &dependencies[index]),
    )
    .unwrap();
    let claim = pin(&closure);
    (closure, claim)
}

fn verify_bytes(
    closure: &CellContentClosureV2,
    expected: &ContentClaimV1,
    payload: &[u8],
    dependencies: [&[u8]; CELL_CONTENT_DEPENDENCY_COUNT_V2],
    read_budget: &mut ContentReadBudget,
) -> Result<CellContentClosureReadbackV2, CellContentErrorV2> {
    let mut readers = dependencies.map(Cursor::new);
    let [base, parent, tokenizer, layout, runtime] = &mut readers;
    closure.verify_readers(
        expected,
        read_budget,
        &mut Cursor::new(payload),
        [base, parent, tokenizer, layout, runtime],
    )
}

#[test]
fn complete_dependency_closure_matches_independent_python_wire_and_readback() {
    // Python hashlib vectors use explicit TCC2/BE32/TCM2 and role-tagged CCH1
    // framing, with no import or execution of the Rust encoder. Dependencies
    // have instances 0b..0f repeated 64 times and generations 20..24.
    let (closure, expected) = fixture();
    let wire = closure.encode();
    assert_eq!(wire.len(), 1465);
    assert_eq!(
        hex::encode(expected.digest()),
        concat!(
            "8dc8a9240e154c23a6f1860671a5474c756e40a9ee67466841bf398d05cebca313",
            "b72f5bd5d86389c55d89756a3c4581bf04d7dc9a0f020dc3acee50bfbd78a8"
        )
    );
    assert_eq!(
        hex::encode(Sha512::digest(&wire)),
        concat!(
            "0ec3c4d7b0c3be155fc5f98275ba4b1aa60bce1343567cd34d6a890f92bd4432e",
            "8b1341a44b187f6ebbc0a962f12b8f0ace231287929127adcdd61977b59f7e5"
        )
    );
    let decoded = CellContentClosureV2::decode(&wire).unwrap();
    assert_eq!(decoded, closure);
    let mut read_budget = budget();
    let readback =
        verify_bytes(&decoded, &expected, PAYLOAD, DEPENDENCIES, &mut read_budget).unwrap();
    assert_eq!(readback.closure_observation().claim(), &expected);
    assert_eq!(
        readback.payload_observation().claim(),
        closure.manifest().payload_claim()
    );
    for (index, role) in CellContentDependencyV2::ALL.into_iter().enumerate() {
        let dependency = closure.dependency_claim(role);
        assert_eq!(readback.dependency_observation(role).claim(), dependency);
        assert_eq!(dependency.context().instance(), &[11 + index as u8; 64]);
        assert_eq!(dependency.context().generation(), 20 + index as u64);
    }
    assert_eq!(read_budget.reads_reserved(), 7);
    assert_eq!(read_budget.bytes_reserved(), 1574);
}

#[test]
fn any_actual_payload_or_dependency_change_refuses_the_whole_closure() {
    let (closure, expected) = fixture();
    let mut payload = PAYLOAD.to_vec();
    payload[0] ^= 1;
    assert!(verify_bytes(&closure, &expected, &payload, DEPENDENCIES, &mut budget()).is_err());
    for changed_index in 0..CELL_CONTENT_DEPENDENCY_COUNT_V2 {
        let mut bytes = DEPENDENCIES.map(<[u8]>::to_vec);
        bytes[changed_index][0] ^= 1;
        let result = verify_bytes(
            &closure,
            &expected,
            PAYLOAD,
            std::array::from_fn(|index| bytes[index].as_slice()),
            &mut budget(),
        );
        assert!(matches!(
            result,
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Mismatch
            ))
        ));
    }
}

#[test]
fn swapped_dependency_readers_or_claims_cannot_reuse_a_pinned_closure() {
    let (closure, expected) = fixture();
    let mut swapped_readers = DEPENDENCIES;
    swapped_readers.swap(0, 1);
    assert!(verify_bytes(&closure, &expected, PAYLOAD, swapped_readers, &mut budget()).is_err());

    // Preserve the fixed role tags but exchange the complete strong claims.
    // This is a well-formed *different* declaration, so the original pin fails.
    let mut swapped_claims = closure.encode();
    let start = 8 + closure.manifest().encode().len();
    for offset in 0..CONTENT_CLAIM_BYTES {
        swapped_claims.swap(start + 1 + offset, start + SLOT_BYTES + 1 + offset);
    }
    let swapped = CellContentClosureV2::decode(&swapped_claims).unwrap();
    assert!(verify_bytes(&swapped, &expected, PAYLOAD, swapped_readers, &mut budget()).is_err());

    let mut reordered_tags = closure.encode();
    reordered_tags.swap(start, start + SLOT_BYTES);
    assert!(CellContentClosureV2::decode(&reordered_tags).is_err());
}

#[test]
fn omitted_or_extra_dependency_bytes_never_produce_complete_readback() {
    let (closure, expected) = fixture();
    for index in 0..CELL_CONTENT_DEPENDENCY_COUNT_V2 {
        let mut omitted = DEPENDENCIES;
        omitted[index] = &[];
        assert!(matches!(
            verify_bytes(&closure, &expected, PAYLOAD, omitted, &mut budget()),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Truncated
            ))
        ));
        let mut with_tail = DEPENDENCIES[index].to_vec();
        with_tail.push(0);
        let mut extra = DEPENDENCIES;
        extra[index] = &with_tail;
        assert!(matches!(
            verify_bytes(&closure, &expected, PAYLOAD, extra, &mut budget()),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::TrailingBytes
            ))
        ));
    }
}

#[test]
fn legacy_digest_observations_and_sha512_wrappers_do_not_upgrade_dependencies() {
    // Each real dependency has 32 bytes. A 32-byte old digest therefore cannot
    // be rejected merely by checking length; complete-byte binding must fail.
    let real_bytes: [Vec<u8>; CELL_CONTENT_DEPENDENCY_COUNT_V2] =
        std::array::from_fn(|index| vec![31 + index as u8; 32]);
    let real_observations: [ObservedContentV1; CELL_CONTENT_DEPENDENCY_COUNT_V2] =
        std::array::from_fn(|index| dependency_observation(index, &real_bytes[index]));
    for wrapped_index in 0..CELL_CONTENT_DEPENDENCY_COUNT_V2 {
        let legacy = Sha256::digest(&real_bytes[wrapped_index]);
        let wrapped = dependency_observation(wrapped_index, &legacy);
        let closure = CellContentClosureV2::from_observed_contents(
            metadata(),
            &payload_observation(PAYLOAD),
            std::array::from_fn(|index| {
                if index == wrapped_index {
                    &wrapped
                } else {
                    &real_observations[index]
                }
            }),
        )
        .unwrap();
        assert!(matches!(
            verify_bytes(
                &closure,
                &pin(&closure),
                PAYLOAD,
                std::array::from_fn(|index| real_bytes[index].as_slice()),
                &mut budget(),
            ),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Mismatch
            ))
        ));
    }

    let (original, _) = fixture();
    let mut wire = original.encode();
    let runtime_digest =
        8 + original.manifest().encode().len() + 4 * SLOT_BYTES + 1 + CONTENT_CLAIM_BYTES - 64;
    wire[runtime_digest..runtime_digest + 64]
        .copy_from_slice(&Sha512::digest(Sha256::digest(DEPENDENCIES[4])));
    let forged = CellContentClosureV2::decode(&wire).unwrap();
    assert!(matches!(
        verify_bytes(&forged, &pin(&forged), PAYLOAD, DEPENDENCIES, &mut budget()),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
}

#[test]
fn wrong_dependency_purpose_or_profile_is_refused_at_construction_and_decode() {
    let real: [ObservedContentV1; CELL_CONTENT_DEPENDENCY_COUNT_V2] =
        std::array::from_fn(|index| dependency_observation(index, DEPENDENCIES[index]));
    let (closure, _) = fixture();
    let candidate87 = CryptoProfile::CandidateMlDsa87V1
        .bind(*profile().binding())
        .unwrap();
    let wrong_contexts = [
        context(ContentKind::StateSnapshot),
        context(ContentKind::ReleaseArtifact),
        context(ContentKind::ModelManifest),
        context(ContentKind::MigrationCheckpoint),
        ContentContextV1::new(&candidate87, ContentKind::ModelPayload, [11; 64], 20).unwrap(),
    ];
    for wrong_context in wrong_contexts {
        let wrong = observe_bytes(&wrong_context, &mut budget(), DEPENDENCIES[0]).unwrap();
        assert!(CellContentClosureV2::from_observed_contents(
            metadata(),
            &payload_observation(PAYLOAD),
            [&wrong, &real[1], &real[2], &real[3], &real[4]],
        )
        .is_err());
        let mut wire = closure.encode();
        let claim_start = 8 + closure.manifest().encode().len() + 1;
        wire[claim_start..claim_start + CONTENT_CLAIM_BYTES]
            .copy_from_slice(&wrong.claim().encode());
        assert!(CellContentClosureV2::decode(&wire).is_err());
    }
}

#[test]
fn closure_parser_rejects_every_truncation_tail_unknown_role_and_legacy_manifest() {
    let (closure, _) = fixture();
    let wire = closure.encode();
    for length in 0..wire.len() {
        assert!(CellContentClosureV2::decode(&wire[..length]).is_err());
    }
    let mut tail = wire.clone();
    tail.push(0);
    assert!(CellContentClosureV2::decode(&tail).is_err());
    let mut unknown = wire.clone();
    unknown[8 + closure.manifest().encode().len()] = 6;
    assert!(CellContentClosureV2::decode(&unknown).is_err());
    let mut huge_manifest = wire.clone();
    huge_manifest[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellContentClosureV2::decode(&huge_manifest).is_err());
    let mut old_namespace = wire;
    old_namespace[..4].copy_from_slice(b"TCC1");
    assert!(CellContentClosureV2::decode(&old_namespace).is_err());
    assert!(CellContentClosureV2::decode(&closure.manifest().encode()).is_err());
    assert!(CellContentManifestV2::decode(&closure.encode()).is_err());
}

#[test]
fn zero_or_oversized_dependency_claims_cannot_stand_for_missing_content() {
    let (closure, _) = fixture();
    for role in CellContentDependencyV2::ALL {
        for length in [0, MAX_CELL_BYTES + 1, u64::MAX] {
            let mut wire = closure.encode();
            let start = 8
                + closure.manifest().encode().len()
                + role.index() * SLOT_BYTES
                + 1
                + CONTENT_CLAIM_BYTES
                - 72;
            wire[start..start + 8].copy_from_slice(&length.to_be_bytes());
            assert!(CellContentClosureV2::decode(&wire).is_err());
        }
    }
}

#[test]
fn payload_only_pin_cannot_replace_the_complete_dependency_closure_pin() {
    let (closure, _) = fixture();
    let inner = closure
        .manifest()
        .observe_manifest(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap();
    assert!(matches!(
        verify_bytes(
            &closure,
            inner.claim(),
            PAYLOAD,
            DEPENDENCIES,
            &mut budget()
        ),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
}

#[test]
fn closure_reservations_are_cumulative_and_failed_late_reads_are_not_refunded() {
    let (closure, expected) = fixture();
    let total = (closure.encode().len()
        + PAYLOAD.len()
        + DEPENDENCIES.iter().map(|bytes| bytes.len()).sum::<usize>()
        + 7) as u64;
    let mut exact = ContentReadBudget::new(7, total).unwrap();
    verify_bytes(&closure, &expected, PAYLOAD, DEPENDENCIES, &mut exact).unwrap();
    assert_eq!(exact.reads_reserved(), 7);
    assert_eq!(exact.bytes_reserved(), total);
    for mut short in [
        ContentReadBudget::new(6, total).unwrap(),
        ContentReadBudget::new(7, total - 1).unwrap(),
    ] {
        assert!(matches!(
            verify_bytes(&closure, &expected, PAYLOAD, DEPENDENCIES, &mut short),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Budget
            ))
        ));
        assert!(short.exhausted());
    }
    let mut failed = ContentReadBudget::new(7, total).unwrap();
    let mut missing_last = DEPENDENCIES;
    missing_last[4] = &[];
    assert!(verify_bytes(&closure, &expected, PAYLOAD, missing_last, &mut failed).is_err());
    assert_eq!(failed.reads_reserved(), 7);
    assert_eq!(failed.bytes_reserved(), total);
    assert!(matches!(
        verify_bytes(&closure, &expected, PAYLOAD, DEPENDENCIES, &mut failed),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Budget
        ))
    ));
}

struct FailAtEof<'a>(Cursor<&'a [u8]>);

impl Read for FailAtEof<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.0.position() == self.0.get_ref().len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled at EOF",
            ));
        }
        self.0.read(output)
    }
}

#[test]
fn cancellation_after_last_dependency_bytes_still_refuses_complete_closure() {
    let (closure, expected) = fixture();
    let mut payload = Cursor::new(PAYLOAD);
    let mut readers = DEPENDENCIES.map(Cursor::new);
    let [base, parent, tokenizer, layout, _] = &mut readers;
    let mut interrupted = FailAtEof(Cursor::new(DEPENDENCIES[4]));
    let mut read_budget = budget();
    assert!(matches!(
        closure.verify_readers(
            &expected,
            &mut read_budget,
            &mut payload,
            [base, parent, tokenizer, layout, &mut interrupted],
        ),
        Err(CellContentErrorV2::Commitment(ContentCommitmentError::Io(error)))
            if error.kind() == io::ErrorKind::Interrupted
    ));
    assert_eq!(interrupted.0.position(), DEPENDENCIES[4].len() as u64);
    assert_eq!(read_budget.reads_reserved(), 7);
}

#[test]
fn full_closure_observation_joins_actual_cpq1_release_signature_verification() {
    use trnm_crypto_primitives::{
        pq_candidate::{CandidateAlgorithm, CandidateSigningKey},
        pq_content_auth::verify_candidate_content,
        pq_profile_auth::CandidateProfileVerifier,
    };
    use trnm_protocol::crypto_profile::{
        CandidateEnvelope, CandidateVerificationBudget, CryptoPurpose,
    };
    use zeroize::Zeroizing;

    let (closure, expected_claim) = fixture();
    let readback = verify_bytes(
        &closure,
        &expected_claim,
        PAYLOAD,
        DEPENDENCIES,
        &mut budget(),
    )
    .unwrap();
    let key =
        CandidateSigningKey::from_owned_seed(CandidateAlgorithm::MlDsa65, Zeroizing::new([19; 32]))
            .unwrap();
    let selected = profile();
    let verifier =
        CandidateProfileVerifier::from_pinned_keys(selected.clone(), &[key.public_key()]).unwrap();
    let payload = expected_claim.encode();
    let expected = CandidateEnvelope {
        purpose: CryptoPurpose::Release,
        owner_generation: 9,
        key_epoch: 1,
        sequence: 1,
        valid_from_height: 10,
        valid_until_height: 99,
        signer_ids: verifier.signer_ids(),
        payload: &payload,
    };
    let message = selected.candidate_message(&expected).unwrap();
    let signature = key.sign(&message).unwrap();
    let wire = selected
        .candidate_wire(&expected, &[key.public_key()], &[&signature])
        .unwrap();
    let result = verify_candidate_content(
        &verifier,
        &mut CandidateVerificationBudget::new(),
        &wire,
        &expected,
        &expected_claim,
        readback.closure_observation(),
    )
    .unwrap();
    assert_eq!(result.claim(), &expected_claim);
}
