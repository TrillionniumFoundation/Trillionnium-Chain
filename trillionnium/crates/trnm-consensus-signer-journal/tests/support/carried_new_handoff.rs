//! Real schema1/Ed25519 producer-consumer regressions. The external watermark
//! fixture is process-local; none of these tests qualify HSM or power loss.
use super::*;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_signer_journal::StrictCarriedNewSetHandoffAdmissionV1;
use trnm_consensus_types::{HandoffCertificateV0, SignatureShareV0, VotingPower};

fn new_admission(fixture: &AuthorityFixture) -> StrictCarriedNewSetHandoffAdmissionV1 {
    StrictCarriedNewSetHandoffAdmissionV1::verify(
        &fixture.new_handoff_intent(),
        &fixture.finality,
        &fixture.commitment,
        &fixture.old_set,
        &fixture.old_parameters,
        &fixture.new_set,
        &fixture.new_parameters,
        &fixture.checkpoint_parent,
    )
    .unwrap()
}
fn initialized() -> (
    TempDir,
    AuthorityFixture,
    MemoryWatermark,
    ExactProducer,
    SqliteHandoffSignerJournalV1<MemoryWatermark>,
) {
    let temporary = TempDir::new().unwrap();
    let fixture = authority_fixture();
    let watermark = MemoryWatermark::default();
    let producer = ExactProducer::new(fixture.signing_key.clone());
    let journal = SqliteHandoffSignerJournalV1::create_new(
        protected_path(&temporary, "carried.sqlite3"),
        fixture.profile(),
        watermark.clone(),
    )
    .unwrap();
    (temporary, fixture, watermark, producer, journal)
}
fn sign_old(
    journal: &mut SqliteHandoffSignerJournalV1<MemoryWatermark>,
    fixture: &AuthorityFixture,
    producer: &mut ExactProducer,
) -> SignatureBytes {
    journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            producer,
        )
        .unwrap()
}

#[test]
fn carried_new_requires_a_real_durable_old_signature_before_any_effect() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    let before = (
        namespace_snapshot(temporary.path()),
        watermark.snapshot(),
        producer.calls(),
    );
    assert!(journal
        .sign_carried_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &new_admission(&fixture),
            &mut producer,
        )
        .is_err());
    // Readback is allowed; no durable write, external CAS or custody call is.
    assert_eq!(namespace_snapshot(temporary.path()), before.0);
    assert_eq!(watermark.snapshot().value, before.1.value);
    assert_eq!(watermark.snapshot().compares, before.1.compares);
    assert_eq!(producer.calls(), before.2);
}

#[test]
fn both_roles_are_persisted_separately_and_replay_without_resigning() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    let old = sign_old(&mut journal, &fixture, &mut producer);
    let admission = new_admission(&fixture);
    let new = journal
        .sign_carried_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &admission,
            &mut producer,
        )
        .unwrap();
    assert_ne!(old, new);
    assert_eq!(
        new.as_bytes(),
        &fixture
            .signing_key
            .sign(fixture.new_handoff_intent().signing_root().as_bytes())
            .to_bytes()
    );
    assert_eq!(producer.calls(), (0, 2));
    assert_eq!(table_counts(journal.path()), (2, 4, 1));
    assert!(journal
        .sign_old_epoch_exact_v1(&vote(&fixture.profile(), 1, 12, 77), &mut producer)
        .is_err());
    drop(journal);
    let mut reopened = SqliteHandoffSignerJournalV1::open_existing(
        temporary.path().join("carried.sqlite3"),
        fixture.profile(),
        watermark,
    )
    .unwrap();
    assert_eq!(sign_old(&mut reopened, &fixture, &mut producer), old);
    assert_eq!(
        reopened
            .sign_carried_new_set_handoff_exact_v1(
                &fixture.new_handoff_intent(),
                &admission,
                &mut producer,
            )
            .unwrap(),
        new
    );
    assert_eq!(producer.calls(), (0, 2));
}

#[test]
fn changed_membership_keys_or_weights_cannot_use_carried_admission() {
    let fixture = authority_fixture();
    for variant in 0..3 {
        let mut validators = fixture.new_set.validators().to_vec();
        let v = validators.pop().unwrap();
        validators.push(
            Validator::new(
                if variant == 0 {
                    ValidatorId::from_bytes(b"validator-z").unwrap()
                } else {
                    v.id()
                },
                if variant == 1 {
                    trnm_consensus_types::ConsensusPublicKey::new(
                        SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes(),
                    )
                } else {
                    v.consensus_key()
                },
                if variant == 2 {
                    VotingPower::new(v.voting_power().get() + 1).unwrap()
                } else {
                    v.voting_power()
                },
            )
            .unwrap(),
        );
        let changed = ValidatorSet::new(
            fixture.new_set.genesis_hash(),
            fixture.new_set.chain_id(),
            fixture.new_set.protocol_version(),
            fixture.new_set.epoch(),
            fixture.new_parameters.hash(),
            validators,
        )
        .unwrap();
        assert!(StrictCarriedNewSetHandoffAdmissionV1::verify(
            &fixture.new_handoff_intent(),
            &fixture.finality,
            &fixture.commitment,
            &fixture.old_set,
            &fixture.old_parameters,
            &changed,
            &fixture.new_parameters,
            &fixture.checkpoint_parent,
        )
        .is_err());
    }
}

#[test]
fn lost_new_signature_reply_requires_observed_exact_recovery_not_new_intent() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    sign_old(&mut journal, &fixture, &mut producer);
    let admission = new_admission(&fixture);
    producer.fail_after_sign_once();
    assert!(journal
        .sign_carried_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &admission,
            &mut producer,
        )
        .is_err());
    assert_eq!(table_counts(journal.path()), (2, 3, 1));
    drop(journal);
    let path = temporary.path().join("carried.sqlite3");
    assert!(SqliteHandoffSignerJournalV1::open_existing(
        &path,
        fixture.profile(),
        watermark.clone()
    )
    .is_err());
    let observed = SignatureBytes::from_array(
        fixture
            .signing_key
            .sign(fixture.new_handoff_intent().signing_root().as_bytes())
            .to_bytes(),
    );
    let (mut recovered, result) =
        SqliteHandoffSignerJournalV1::recover_carried_new_set_handoff_signature_v1(
            &path,
            fixture.profile(),
            watermark,
            &fixture.new_handoff_intent(),
            &admission,
            observed,
        )
        .unwrap();
    assert_eq!(result, observed);
    assert_eq!(table_counts(&path), (2, 4, 1));
    assert_eq!(
        recovered
            .sign_carried_new_set_handoff_exact_v1(
                &fixture.new_handoff_intent(),
                &admission,
                &mut producer,
            )
            .unwrap(),
        observed
    );
    assert_eq!(producer.calls(), (0, 2));
}

#[test]
fn signed_new_tail_repairs_only_its_single_external_cas_lag() {
    for applied in [false, true] {
        let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
        sign_old(&mut journal, &fixture, &mut producer);
        if applied {
            watermark.apply_then_fail(4);
        } else {
            watermark.fail_before_apply(4);
        }
        let admission = new_admission(&fixture);
        assert!(journal
            .sign_carried_new_set_handoff_exact_v1(
                &fixture.new_handoff_intent(),
                &admission,
                &mut producer,
            )
            .is_err());
        assert_eq!(table_counts(journal.path()), (2, 4, 1));
        drop(journal);
        let observed = SignatureBytes::from_array(
            fixture
                .signing_key
                .sign(fixture.new_handoff_intent().signing_root().as_bytes())
                .to_bytes(),
        );
        let (recovered, signature) =
            SqliteHandoffSignerJournalV1::recover_carried_new_set_handoff_signature_v1(
                temporary.path().join("carried.sqlite3"),
                fixture.profile(),
                watermark.clone(),
                &fixture.new_handoff_intent(),
                &admission,
                observed,
            )
            .unwrap();
        assert_eq!(signature, observed);
        assert_eq!(watermark.snapshot().value.unwrap().sequence(), 4);
        assert_eq!(table_counts(recovered.path()), (2, 4, 1));
        assert_eq!(producer.calls(), (0, 2));
    }
}

#[test]
fn unanchored_new_prepare_cannot_be_completed_with_a_supplied_signature() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    sign_old(&mut journal, &fixture, &mut producer);
    watermark.fail_before_apply(3);
    let admission = new_admission(&fixture);
    assert!(journal
        .sign_carried_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &admission,
            &mut producer,
        )
        .is_err());
    assert_eq!(producer.calls(), (0, 1));
    drop(journal);
    let path = temporary.path().join("carried.sqlite3");
    let before = (fs::read(&path).unwrap(), watermark.snapshot());
    let observed = SignatureBytes::from_array(
        fixture
            .signing_key
            .sign(fixture.new_handoff_intent().signing_root().as_bytes())
            .to_bytes(),
    );
    assert!(
        SqliteHandoffSignerJournalV1::recover_carried_new_set_handoff_signature_v1(
            &path,
            fixture.profile(),
            watermark.clone(),
            &fixture.new_handoff_intent(),
            &admission,
            observed,
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), before.0);
    assert_eq!(watermark.snapshot().value, before.1.value);
}

#[test]
fn old_signature_cannot_be_reused_as_a_new_role_signature() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    let old = sign_old(&mut journal, &fixture, &mut producer);
    producer.fail_after_sign_once();
    let admission = new_admission(&fixture);
    assert!(journal
        .sign_carried_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &admission,
            &mut producer,
        )
        .is_err());
    drop(journal);
    let before = namespace_snapshot(temporary.path());
    assert!(
        SqliteHandoffSignerJournalV1::recover_carried_new_set_handoff_signature_v1(
            temporary.path().join("carried.sqlite3"),
            fixture.profile(),
            watermark,
            &fixture.new_handoff_intent(),
            &admission,
            old,
        )
        .is_err()
    );
    assert_eq!(namespace_snapshot(temporary.path()), before);
}

#[test]
fn held_admission_rejects_another_author_before_mutation() {
    let (temporary, fixture, watermark, mut producer, mut journal) = initialized();
    sign_old(&mut journal, &fixture, &mut producer);
    let other = CanonicalHandoffSignIntentV1::new_set(
        &fixture.descriptor,
        &fixture.old_set,
        &fixture.new_set,
        &fixture.old_parameters,
        &fixture.new_parameters,
        ValidatorId::from_bytes(b"validator-b").unwrap(),
    )
    .unwrap();
    let before = (
        namespace_snapshot(temporary.path()),
        watermark.snapshot(),
        producer.calls(),
    );
    assert!(journal
        .sign_carried_new_set_handoff_exact_v1(&other, &new_admission(&fixture), &mut producer)
        .is_err());
    assert_eq!(
        before,
        (
            namespace_snapshot(temporary.path()),
            watermark.snapshot(),
            producer.calls()
        )
    );
}

#[test]
fn real_journals_produce_both_quorums_consumed_by_existing_joint_certificate() {
    let mut fixture = authority_fixture();
    let mut old_shares = Vec::new();
    let mut new_shares = Vec::new();
    for name in ["validator-a", "validator-b", "validator-c", "validator-d"] {
        fixture.author = ValidatorId::from_bytes(name.as_bytes()).unwrap();
        let seed: [u8; 32] = Sha256::digest(
            format!("trnm.poco-bft.checkpoint-finality.private-fixture.v0:{name}").as_bytes(),
        )
        .into();
        fixture.signing_key = SigningKey::from_bytes(&seed);
        let temporary = TempDir::new().unwrap();
        let mut journal = SqliteHandoffSignerJournalV1::create_new(
            protected_path(&temporary, "joint.sqlite3"),
            fixture.profile(),
            MemoryWatermark::default(),
        )
        .unwrap();
        let mut producer = ExactProducer::new(fixture.signing_key.clone());
        let old = sign_old(&mut journal, &fixture, &mut producer);
        let new = journal
            .sign_carried_new_set_handoff_exact_v1(
                &fixture.new_handoff_intent(),
                &new_admission(&fixture),
                &mut producer,
            )
            .unwrap();
        old_shares.push(SignatureShareV0::new(fixture.author, old).unwrap());
        new_shares.push(SignatureShareV0::new(fixture.author, new).unwrap());
    }
    let certificate = HandoffCertificateV0::new(
        fixture.descriptor.clone(),
        old_shares,
        new_shares,
        &fixture.old_set,
        &fixture.new_set,
    )
    .unwrap();
    certificate
        .verify(&fixture.old_set, &fixture.new_set, &StrictEd25519Verifier)
        .unwrap();
    let corpus: Value = serde_json::from_str(AUTHORITY_VECTOR).unwrap();
    assert_eq!(
        certificate.try_cev0_bytes().unwrap(),
        raw(
            object(object(&corpus, "positive"), "handoff"),
            "certificate_cev0_hex"
        )
    );
}
