use ml_dsa::{KeyExport, KeyInit, Keypair, MlDsa65, SigningKey};
use trnm_research_protocol::*;

const CHAIN: &str = "trnm-pq-recovery";
const DID: &str = "did:trnm:external-witness";

fn key() -> SigningKey<MlDsa65> {
    SigningKey::<MlDsa65>::new_from_slice(&[43; 32]).unwrap()
}
fn head() -> LocalRecoveryHeadV1 {
    LocalRecoveryHeadV1 {
        tip: [1; 32],
        state_root: [2; 32],
        effect_journal_head: [3; 32],
        height: 72,
        owner_generation: 9,
    }
}
fn witness(sk: &SigningKey<MlDsa65>) -> SignedPqRecoveryWitnessV1 {
    SignedPqRecoveryWitnessV1::sign(
        PqRecoveryWitnessStatementV1 {
            chain_id: CHAIN.into(),
            witness_did: DID.into(),
            genesis: [4; 32],
            observed: head(),
            sequence: 19,
            challenge: [5; 32],
            issued_unix_s: 1000,
            expires_unix_s: 1150,
        },
        sk,
    )
    .unwrap()
}
fn expected<'a>(
    key: &'a [u8],
    local: &'a LocalRecoveryHeadV1,
) -> ExternalRecoveryExpectationV1<'a> {
    ExternalRecoveryExpectationV1 {
        chain_id: CHAIN,
        witness_did: DID,
        trusted_ml_dsa65_public_key: key,
        genesis: [4; 32],
        outstanding_challenge: [5; 32],
        last_external_sequence: 18,
        now_unix_s: 1100,
        actual_local: local,
    }
}

#[test]
fn fresh_independently_pinned_witness_can_confirm_exact_recovery_state() {
    let sk = key();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let original = witness(&sk);
    let parsed =
        SignedPqRecoveryWitnessV1::from_canonical_bytes(&original.canonical_bytes()).unwrap();
    assert_eq!(parsed.canonical_bytes(), original.canonical_bytes());
    assert!(parsed.canonical_bytes().len() < MAX_PQ_RECOVERY_WITNESS_BYTES);
    parsed.verify_for_recovery(&expected(&pk, &head())).unwrap();
}

#[test]
fn full_sqlite_rollback_or_local_divergence_is_detected_against_external_head() {
    let sk = key();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let signed = witness(&sk);
    for part in 0..5 {
        let mut old = head();
        match part {
            0 => old.height -= 1,
            1 => old.owner_generation -= 1,
            2 => old.tip[0] ^= 1,
            3 => old.state_root[0] ^= 1,
            _ => old.effect_journal_head[0] ^= 1,
        }
        assert!(matches!(
            signed.verify_for_recovery(&expected(&pk, &old)),
            Err(PqRecoveryWitnessError::LocalRollbackOrDivergence)
        ));
    }
    let mut newer = head();
    newer.height += 1;
    // Without an externally witnessed ancestry check, fail closed on newer tips too.
    assert!(signed.verify_for_recovery(&expected(&pk, &newer)).is_err());
}

#[test]
fn challenge_sequence_lifetime_and_classic_key_downgrade_refuse() {
    let sk = key();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let signed = witness(&sk);
    let local = head();

    let mut e = expected(&pk, &local);
    e.last_external_sequence = 19;
    assert!(matches!(
        signed.verify_for_recovery(&e),
        Err(PqRecoveryWitnessError::StaleSequence)
    ));
    e = expected(&pk, &local);
    e.outstanding_challenge = [0x44; 32];
    assert!(signed.verify_for_recovery(&e).is_err());
    e = expected(&pk, &local);
    e.now_unix_s = 1151;
    assert!(matches!(
        signed.verify_for_recovery(&e),
        Err(PqRecoveryWitnessError::TimeWindow)
    ));
    e = expected(&pk, &local);
    e.now_unix_s = 999;
    assert!(signed.verify_for_recovery(&e).is_err());
    e = expected(&pk, &local);
    e.trusted_ml_dsa65_public_key = &[0x22; 32];
    assert!(signed.verify_for_recovery(&e).is_err());
    e = expected(&pk, &local);
    e.witness_did = "did:trnm:other";
    assert!(signed.verify_for_recovery(&e).is_err());
    e = expected(&pk, &local);
    e.chain_id = "foreign-chain";
    assert!(signed.verify_for_recovery(&e).is_err());
}

#[test]
fn signing_domain_bytes_and_canonical_input_have_no_implicit_authority() {
    let sk = key();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let signed = witness(&sk);
    let mut mutated = signed.clone();
    mutated.signature[0] ^= 1;
    assert!(mutated
        .verify_for_recovery(&expected(&pk, &head()))
        .is_err());
    mutated = signed.clone();
    mutated.sequence += 1;
    assert!(mutated
        .verify_for_recovery(&expected(&pk, &head()))
        .is_err());
    mutated = signed.clone();
    mutated.public_key[0] ^= 1;
    assert!(mutated
        .verify_for_recovery(&expected(&pk, &head()))
        .is_err());

    let original = signed.canonical_bytes();
    for n in [0, 1, 15, original.len() - 1] {
        assert!(SignedPqRecoveryWitnessV1::from_canonical_bytes(&original[..n]).is_err());
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(SignedPqRecoveryWitnessV1::from_canonical_bytes(&trailing).is_err());
    let mut wrong_version = original.clone();
    wrong_version[1] = 2;
    assert!(SignedPqRecoveryWitnessV1::from_canonical_bytes(&wrong_version).is_err());
    assert!(matches!(
        SignedPqRecoveryWitnessV1::from_canonical_bytes(&vec![
            0;
            MAX_PQ_RECOVERY_WITNESS_BYTES + 1
        ]),
        Err(PqRecoveryWitnessError::WireTooLarge)
    ));
}

const QUORUM_DIDS: [&str; 3] = [
    "did:trnm:recovery-quorum-a",
    "did:trnm:recovery-quorum-b",
    "did:trnm:recovery-quorum-c",
];

fn quorum_fixture() -> (Vec<Vec<u8>>, Vec<SignedPqRecoveryWitnessV1>) {
    let mut keys = Vec::new();
    let mut receipts = Vec::new();
    for (i, witness_did) in QUORUM_DIDS.iter().enumerate() {
        let sk = SigningKey::<MlDsa65>::new_from_slice(&[51 + i as u8; 32]).unwrap();
        keys.push(sk.verifying_key().to_bytes().to_vec());
        receipts.push(
            SignedPqRecoveryWitnessV1::sign(
                PqRecoveryWitnessStatementV1 {
                    chain_id: CHAIN.into(),
                    witness_did: (*witness_did).into(),
                    genesis: [4; 32],
                    observed: head(),
                    sequence: 30 + i as u64,
                    challenge: [10 + i as u8; 32],
                    issued_unix_s: 1000,
                    expires_unix_s: 1150,
                },
                &sk,
            )
            .unwrap(),
        );
    }
    (keys, receipts)
}

fn quorum_roster(keys: &[Vec<u8>]) -> Vec<PqRecoveryTrustedSignerV1<'_>> {
    (0..3)
        .map(|i| PqRecoveryTrustedSignerV1 {
            witness_did: QUORUM_DIDS[i],
            trusted_ml_dsa65_public_key: &keys[i],
            last_external_sequence: 29 + i as u64,
            outstanding_challenge: [10 + i as u8; 32],
        })
        .collect()
}

fn quorum_policy<'a>(
    roster: &'a [PqRecoveryTrustedSignerV1<'a>],
    local: &'a LocalRecoveryHeadV1,
) -> PqRecoveryQuorumPolicyV1<'a> {
    PqRecoveryQuorumPolicyV1 {
        chain_id: CHAIN,
        genesis: [4; 32],
        now_unix_s: 1100,
        actual_local: local,
        roster,
        threshold: 2,
    }
}

#[test]
fn two_of_three_distinct_pq_witnesses_confirm_exact_state_only() {
    let (keys, receipts) = quorum_fixture();
    let roster = quorum_roster(&keys);
    let local = head();
    let policy = quorum_policy(&roster, &local);
    assert_eq!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &policy)
            .unwrap()
            .verified_signers(),
        2
    );
    assert_eq!(
        verify_pq_recovery_quorum_v1(&receipts, &policy)
            .unwrap()
            .verified_signers(),
        3
    );
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&receipts[..1], &policy),
        Err(PqRecoveryQuorumErrorV1::InsufficientQuorum)
    ));
}

#[test]
fn duplicate_or_disjoint_witness_identities_never_count_toward_quorum() {
    let (keys, receipts) = quorum_fixture();
    let local = head();
    let roster = quorum_roster(&keys);
    let policy = quorum_policy(&roster, &local);
    let repeated = vec![receipts[0].clone(), receipts[0].clone()];
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&repeated, &policy),
        Err(PqRecoveryQuorumErrorV1::DuplicateWitness)
    ));
    let mut outsider = receipts[1].clone();
    outsider.witness_did = "did:trnm:untrusted".into();
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&[receipts[0].clone(), outsider], &policy),
        Err(PqRecoveryQuorumErrorV1::UntrustedWitness)
    ));
    assert!(verify_pq_recovery_quorum_v1(
        &[
            receipts[0].clone(),
            receipts[1].clone(),
            receipts[2].clone(),
            receipts[0].clone(),
        ],
        &policy,
    )
    .is_err());
    let mut dup_did = quorum_roster(&keys);
    dup_did[1].witness_did = QUORUM_DIDS[0];
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&dup_did, &local)),
        Err(PqRecoveryQuorumErrorV1::DuplicateRosterIdentity)
    ));
    let mut dup_key = quorum_roster(&keys);
    dup_key[1].trusted_ml_dsa65_public_key = &keys[0];
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&dup_key, &local)),
        Err(PqRecoveryQuorumErrorV1::DuplicateRosterIdentity)
    ));
}

#[test]
fn one_of_three_policy_or_untrusted_roster_cannot_weaken_recovery() {
    let (keys, receipts) = quorum_fixture();
    let local = head();
    let roster = quorum_roster(&keys);
    let mut policy = quorum_policy(&roster, &local);
    policy.threshold = 1;
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &policy),
        Err(PqRecoveryQuorumErrorV1::InvalidPolicy)
    ));
    policy.threshold = 4;
    assert!(verify_pq_recovery_quorum_v1(&receipts[..2], &policy).is_err());
    policy.threshold = 2;
    policy.genesis = [0; 32];
    assert!(verify_pq_recovery_quorum_v1(&receipts[..2], &policy).is_err());

    let mut bad_roster = quorum_roster(&keys);
    bad_roster[0].trusted_ml_dsa65_public_key = &[9; 32];
    assert!(matches!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&bad_roster, &local)),
        Err(PqRecoveryQuorumErrorV1::InvalidPolicy)
    ));
    let empty: [PqRecoveryTrustedSignerV1<'_>; 0] = [];
    assert!(verify_pq_recovery_quorum_v1(&[], &quorum_policy(&empty, &local)).is_err());
}

#[test]
fn freshness_rollback_key_swap_and_invalid_extra_fail_closed() {
    let (keys, receipts) = quorum_fixture();
    let local = head();
    let mut roster = quorum_roster(&keys);
    roster[0].last_external_sequence = 30;
    assert!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&roster, &local),).is_err()
    );
    roster[0].last_external_sequence = 29;
    roster[1].outstanding_challenge = [42; 32];
    assert!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&roster, &local),).is_err()
    );
    roster[1].outstanding_challenge = [11; 32];
    let mut rolled_back = local;
    rolled_back.effect_journal_head[0] ^= 1;
    assert!(
        verify_pq_recovery_quorum_v1(&receipts[..2], &quorum_policy(&roster, &rolled_back),)
            .is_err()
    );

    let mut swapped = receipts[1].clone();
    swapped.public_key = keys[0].clone();
    assert!(verify_pq_recovery_quorum_v1(
        &[receipts[0].clone(), swapped],
        &quorum_policy(&roster, &local),
    )
    .is_err());
    let mut invalid_extra = receipts[2].clone();
    invalid_extra.signature[0] ^= 1;
    assert!(verify_pq_recovery_quorum_v1(
        &[receipts[0].clone(), receipts[1].clone(), invalid_extra],
        &quorum_policy(&roster, &local),
    )
    .is_err());
}

#[test]
fn no_valid_quorum_from_expired_or_conflicting_signed_state() {
    let (keys, receipts) = quorum_fixture();
    let local = head();
    let roster = quorum_roster(&keys);
    let mut policy = quorum_policy(&roster, &local);
    policy.now_unix_s = 1151;
    assert!(verify_pq_recovery_quorum_v1(&receipts[..2], &policy).is_err());

    let mut divergent = receipts[1].clone();
    divergent.observed.height += 1;
    assert!(verify_pq_recovery_quorum_v1(
        &[receipts[0].clone(), divergent],
        &quorum_policy(&roster, &local),
    )
    .is_err());
}
