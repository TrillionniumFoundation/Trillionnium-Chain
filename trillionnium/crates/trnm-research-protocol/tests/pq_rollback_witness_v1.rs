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
        CHAIN.into(),
        DID.into(),
        [4; 32],
        head(),
        19,
        [5; 32],
        1000,
        1150,
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
