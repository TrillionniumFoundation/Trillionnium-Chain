//! Storage atomicity tests. The local sealed verifier fixture below does not
//! establish cryptographic acceptance; the sibling restored-native-WAL test
//! supplies that path using real Ed25519 finality and native execution.
use super::*;
use std::process::Command;
use trnm_mempool::{CanonicalTxDigest, ResourceLimits};

const NAMESPACE: [u8; 32] = [0x17; 32];
const SIGNER: [u8; 32] = [0x27; 32];

#[derive(Debug)]
struct TestFloorVerifier;
impl replay_floor_verifier_seal_v1::Sealed for TestFloorVerifier {}
impl TxAdmissionReplayFloorVerifierV1 for TestFloorVerifier {
    fn verify_replay_floor_v1(
        &self,
        _: &TxAdmissionReplayFloorEvidenceV1,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        Ok(())
    }
}
fn evidence(nonce: u64, height: u64) -> TxAdmissionReplayFloorEvidenceV1 {
    TxAdmissionReplayFloorEvidenceV1::new(
        NAMESPACE,
        CanonicalSignerId::from_bytes(SIGNER).unwrap(),
        nonce,
        Height::new(height),
        StateRoot::new([0x31; 32]),
        [0x32; 32],
        [0x33; 32],
    )
    .unwrap()
}
fn floor(nonce: u64, height: u64) -> VerifiedTxAdmissionReplayFloorV1 {
    evidence(nonce, height)
        .verify_with(&TestFloorVerifier)
        .unwrap()
}
fn terminal(a: &SqlitePendingNonceAuthorityV0, nonce: u64) {
    let digest = [nonce as u8; 32];
    let checksum = tombstone_digest_v1(
        NAMESPACE,
        SIGNER,
        nonce,
        digest,
        STATE_RELEASED_V0,
        0,
        [0; 32],
    )
    .unwrap();
    a.connection
        .borrow_mut()
        .execute(
            "INSERT INTO tx_admission_tombstone_v1
             (namespace,signer,nonce,tx_digest,terminal_state,terminal_height,
              receipt_commitment,tombstone_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                NAMESPACE.as_slice(),
                SIGNER.as_slice(),
                nonce.to_be_bytes().as_slice(),
                digest.as_slice(),
                STATE_RELEASED_V0,
                0_u64.to_be_bytes().as_slice(),
                [0_u8; 32].as_slice(),
                checksum.as_slice(),
            ],
        )
        .unwrap();
}
struct Envelope(u64);
impl SignedEnvelopeView for Envelope {
    fn canonical_digest(&self) -> CanonicalTxDigest {
        CanonicalTxDigest::from_bytes([self.0 as u8; 32]).unwrap()
    }
    fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
        CanonicalSignerId::from_bytes(SIGNER)
            .map_err(|_| AdmissionReject::CanonicalValidationFailed)
    }
    fn canonical_body(&self) -> &[u8] {
        b"floor-test"
    }
    fn nonce(&self) -> u64 {
        self.0
    }
    fn fee_limit(&self) -> u128 {
        1
    }
    fn resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_gas: 1,
            max_bytes: 1024,
        }
    }
    fn validate_canonical(&self) -> Result<(), AdmissionReject> {
        Ok(())
    }
}
fn metadata(nonce: u64) -> SignedEnvelopeMetadata {
    TypedAdmissionGate::new(16, 0, 1024)
        .canonical_metadata_v0(&Envelope(nonce))
        .unwrap()
}
fn reserve(
    a: &mut SqlitePendingNonceAuthorityV0,
    nonce: u64,
) -> Result<SqlitePendingNonceReservationV0, TxAdmissionWalErrorV0> {
    a.reserve_record(&Envelope(nonce), &metadata(nonce))
}
fn assert_replay(a: &mut SqlitePendingNonceAuthorityV0, nonce: u64) {
    assert!(matches!(
        reserve(a, nonce),
        Err(TxAdmissionWalErrorV0::Replay)
    ));
}

#[test]
fn durable_floor_survives_purge_and_restart_and_bounds_the_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("wal.sqlite");
    let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
    for nonce in [1, 2, 3] {
        terminal(&a, nonce);
    }
    let result = a
        .purge_tombstones_with_replay_floor_v1(&floor(3, 100), 1)
        .unwrap();
    assert_eq!(result.purged(), 1);
    assert_eq!(result.retained_tombstones(), 2);
    assert_eq!(a.retained_rows().unwrap(), 3); // two tombstones and one floor
    for nonce in 1..=3 {
        assert_replay(&mut a, nonce);
    }
    assert_eq!(
        a.purge_tombstones_with_replay_floor_v1(&floor(3, 100), 16)
            .unwrap()
            .purged(),
        2
    );
    assert_eq!(a.retained_rows().unwrap(), 1);
    drop(a);
    let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
    for nonce in 1..=3 {
        assert_replay(&mut a, nonce);
    }
    let mut next = reserve(&mut a, 4).unwrap();
    next.release().unwrap();
}

#[test]
fn durable_floor_regression_or_policy_substitution_has_no_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("wal.sqlite");
    let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
    terminal(&a, 1);
    let accepted = evidence(4, 100);
    a.purge_tombstones_with_replay_floor_v1(&accepted.verify_with(&TestFloorVerifier).unwrap(), 16)
        .unwrap();
    let mut wrong_root = evidence(4, 100);
    wrong_root.state_root = [0x99; 32];
    let mut wrong_policy = evidence(5, 101);
    wrong_policy.retention_policy_digest = [0x88; 32];
    for e in [evidence(3, 101), evidence(5, 99), wrong_root, wrong_policy] {
        assert_eq!(
            a.purge_tombstones_with_replay_floor_v1(
                &e.verify_with(&TestFloorVerifier).unwrap(),
                16
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptConflict)
        );
        assert!(!a.replay_floor_recovery_required.get());
        assert_eq!(
            read_stored_replay_floor_v1(&a.connection.borrow(), NAMESPACE, SIGNER).unwrap(),
            Some(accepted)
        );
        assert_eq!(a.retained_rows().unwrap(), 1);
    }
}

#[test]
fn durable_floor_accepts_an_alternate_proof_of_the_same_finalized_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a =
        SqlitePendingNonceAuthorityV0::open(tmp.path().join("wal.sqlite"), NAMESPACE).unwrap();
    a.purge_tombstones_with_replay_floor_v1(&floor(3, 100), 16)
        .unwrap();
    let mut alternate = evidence(3, 100);
    alternate.finality_proof_digest = [0x42; 32];
    let r = a
        .purge_tombstones_with_replay_floor_v1(
            &alternate.verify_with(&TestFloorVerifier).unwrap(),
            16,
        )
        .unwrap();
    assert_eq!(r.purged(), 0);
    assert_eq!(
        read_stored_replay_floor_v1(&a.connection.borrow(), NAMESPACE, SIGNER).unwrap(),
        Some(alternate)
    );
    assert_replay(&mut a, 2);
}

#[test]
fn durable_floor_cannot_resolve_a_live_reserved_or_handed_off_nonce() {
    for handed_off in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let mut a =
            SqlitePendingNonceAuthorityV0::open(tmp.path().join("wal.sqlite"), NAMESPACE).unwrap();
        let mut reservation = reserve(&mut a, 5).unwrap();
        if handed_off {
            reservation.handoff().unwrap();
        }
        assert_eq!(
            a.purge_tombstones_with_replay_floor_v1(&floor(5, 100), 16),
            Err(TxAdmissionWalErrorV0::ReservationConflict)
        );
        assert_eq!(
            read_stored_replay_floor_v1(&a.connection.borrow(), NAMESPACE, SIGNER).unwrap(),
            None
        );
        assert!(!a.replay_floor_recovery_required.get());
    }
}

#[test]
fn durable_floor_tamper_and_malformed_fields_reject_on_reopen() {
    for mutation in [
        "UPDATE tx_admission_replay_floor_v1 SET commitment=zeroblob(32)",
        "UPDATE tx_admission_replay_floor_v1 SET reject_nonce_through=zeroblob(9)",
        "UPDATE tx_admission_replay_floor_v1 SET state_root=zeroblob(32)",
        "UPDATE tx_admission_replay_floor_v1 SET namespace=zeroblob(32)",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wal.sqlite");
        let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
        a.purge_tombstones_with_replay_floor_v1(&floor(3, 100), 16)
            .unwrap();
        drop(a);
        let c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        c.execute_batch(mutation).unwrap();
        drop(c);
        assert!(SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).is_err());
    }
}

#[test]
fn durable_floor_schema_two_is_rejected_without_in_place_migration() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("wal.sqlite");
    let a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
    terminal(&a, 1);
    drop(a);
    let c = Connection::open(&path).unwrap();
    c.execute_batch("DROP TABLE tx_admission_replay_floor_v1; PRAGMA user_version=2; UPDATE tx_admission_meta SET schema_version=2;").unwrap();
    drop(c);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE),
        Err(TxAdmissionWalErrorV0::SchemaMismatch)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn durable_floor_uncertain_cut_fences_existing_tokens_and_recovers_source_or_target() {
    for cut in ["after-floor", "after-delete", "after-commit"] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wal.sqlite");
        let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
        terminal(&a, 1);
        let mut later = reserve(&mut a, 5).unwrap();
        REPLAY_FLOOR_TEST_FAILURE_V1.with(|f| *f.borrow_mut() = Some((path.clone(), cut)));
        assert_eq!(
            a.purge_tombstones_with_replay_floor_v1(&floor(1, 100), 16),
            Err(TxAdmissionWalErrorV0::Sqlite)
        );
        assert!(a.retained_rows().is_err());
        assert_eq!(later.handoff(), Err(AdmissionReject::InconsistentState));
        assert!(reserve(&mut a, 6).is_err());
        drop(later);
        drop(a);
        let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
        assert_replay(&mut a, 1);
        let persisted =
            read_stored_replay_floor_v1(&a.connection.borrow(), NAMESPACE, SIGNER).unwrap();
        assert_eq!(persisted.is_some(), cut == "after-commit");
        assert_eq!(
            a.retained_tombstones_v1().unwrap(),
            usize::from(cut != "after-commit")
        );
        let mut retry = reserve(&mut a, 5).unwrap();
        retry.release().unwrap();
        a.purge_tombstones_with_replay_floor_v1(&floor(1, 100), 16)
            .unwrap();
        assert_replay(&mut a, 1);
    }
}

#[test]
fn durable_floor_process_child() {
    let Some(path) = std::env::var_os("TRNM_FLOOR_TEST_PATH") else {
        return;
    };
    let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
    a.purge_tombstones_with_replay_floor_v1(&floor(1, 100), 16)
        .unwrap();
    panic!("the child should exit at its explicit storage cut");
}

#[test]
fn durable_floor_real_process_crash_keeps_tombstone_or_floor() {
    for cut in ["after-floor", "after-delete", "after-commit"] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wal.sqlite");
        let a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
        terminal(&a, 1);
        drop(a);
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tx_admission_wal::replay_floor_store_tests_v1::durable_floor_process_child",
                "--nocapture",
            ])
            .env("TRNM_FLOOR_TEST_PATH", &path)
            .env("TRNM_FLOOR_TEST_CUT", cut)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(74));
        let mut a = SqlitePendingNonceAuthorityV0::open(&path, NAMESPACE).unwrap();
        assert_replay(&mut a, 1);
        assert_eq!(
            read_stored_replay_floor_v1(&a.connection.borrow(), NAMESPACE, SIGNER)
                .unwrap()
                .is_some(),
            cut == "after-commit"
        );
        a.purge_tombstones_with_replay_floor_v1(&floor(1, 100), 16)
            .unwrap();
        assert_replay(&mut a, 1);
    }
}
