use super::native_ancestry_commit_tests::{logical_rows, open};
use super::*;
use crate::account_archive_prototype::multiproof::{
    CheckedMultiproof, MultiproofProgress, MAX_ACCOUNTS,
};
use crate::{ErrorCode, ErrorKind};

#[test]
fn native_account_query_dimensions_precede_any_snapshot_or_state_read() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let requests = [
        (
            vec![[0; 32]; MAX_ACCOUNTS + 1],
            "NATIVE_ACCOUNT_PROOF:Budget",
        ),
        (vec![[0; 32]; 2], "NATIVE_ACCOUNT_PROOF:InvalidWitness"),
    ];
    // A nested read transaction would already fail. Neither invalid request may
    // reach it, or consult the deliberately unavailable retained commitment.
    node.db
        .execute_batch("BEGIN IMMEDIATE; DELETE FROM native_state_commitments;")
        .unwrap();
    for (owners, expected) in requests {
        let error = node
            .authenticated_account_multiproof_with_progress([255; 32], &owners, &|_| {
                panic!("invalid request must be rejected before progress/storage")
            })
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(!error.requires_owner_stop());
    }
    node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(logical_rows(&node.db), before);
    let legacy_dir = tempfile::tempdir().unwrap();
    let legacy = open(legacy_dir.path(), settings.clone(), false);
    assert_eq!(
        legacy
            .authenticated_account_multiproof(settings.genesis(), &vec![[0; 32]; MAX_ACCOUNTS + 1])
            .unwrap_err()
            .to_string(),
        "NATIVE_STATE_BACKEND_REQUIRED"
    );
}

#[test]
fn native_account_query_cancellation_preserves_error_snapshot_and_exact_retry_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), true);
    let mut ids = vec![settings.genesis()];
    for height in 1..=3 {
        let packet = node
            .make(
                *ids.last().unwrap(),
                vec![],
                development_public(7).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        ids.push(id);
    }
    let owners = [
        development_public(0).unwrap(),
        development_public(7).unwrap(),
        development_public(777).unwrap(),
    ];
    let before = logical_rows(&node.db);
    for id in [ids[2], ids[3]] {
        let expected = node.authenticated_account_multiproof(id, &owners).unwrap();
        let expected_bytes = expected.1.encode().unwrap();
        let trace = RefCell::new(Vec::new());
        let actual = node
            .authenticated_account_multiproof_with_progress(id, &owners, &|point| {
                trace.borrow_mut().push(point);
                Ok(())
            })
            .unwrap();
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1.encode().unwrap(), expected_bytes);
        assert_eq!(actual.2, expected.2);
        CheckedMultiproof::verify(
            crate::account_archive_prototype::Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            &actual.0,
            &actual.1,
        )
        .unwrap();
        let points = [
            NativeAccountProofProgress::BeforeRead,
            NativeAccountProofProgress::StateReplay,
            NativeAccountProofProgress::StateVerification,
            NativeAccountProofProgress::Proof(MultiproofProgress::ArchiveRead { index: 0 }),
            NativeAccountProofProgress::Proof(MultiproofProgress::BeforeVerification),
            NativeAccountProofProgress::Proof(MultiproofProgress::Account { index: 0 }),
            NativeAccountProofProgress::Proof(MultiproofProgress::BeforeOutput),
            NativeAccountProofProgress::BeforeOutput,
        ];
        for cancel_at in points {
            assert!(trace.borrow().contains(&cancel_at));
            let reached = Cell::new(false);
            let error = node
                .authenticated_account_multiproof_with_progress(id, &owners, &|point| {
                    if point == cancel_at {
                        reached.set(true);
                        Err(Error::new(ErrorCode::PublicRequestCancelled))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(reached.get());
            assert_eq!(error.code(), Some(ErrorCode::PublicRequestCancelled));
            assert_eq!(error.kind(), ErrorKind::Cancelled);
            assert!(!error.requires_owner_stop());
            assert!(node.db.is_autocommit());
            assert_eq!(logical_rows(&node.db), before);
            assert_eq!(
                node.authenticated_account_multiproof(id, &owners)
                    .unwrap()
                    .1
                    .encode()
                    .unwrap(),
                expected_bytes
            );
        }
    }
    drop(node);
    let node = open(directory.path(), settings, true);
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_account_query_reads_real_nodes_and_rolls_back_callback_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let owners = [development_public(0).unwrap()];
    let touched = Cell::new(false);
    let error = node
        .authenticated_account_multiproof_with_progress(settings.genesis(), &owners, &|point| {
            if point
                == NativeAccountProofProgress::Proof(MultiproofProgress::ArchiveRead { index: 0 })
            {
                touched.set(true);
                node.db.execute("DELETE FROM archive_nodes", [])?;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(touched.get());
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF:DataUnavailable");
    assert!(error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
    node.authenticated_account_multiproof(settings.genesis(), &owners)
        .unwrap();
}

#[test]
fn native_account_query_final_callback_write_is_rejected_and_rolled_back() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let owners = [development_public(0).unwrap()];
    let before = logical_rows(&node.db);
    let expected = node
        .authenticated_account_multiproof(settings.genesis(), &owners)
        .unwrap();
    let touched = Cell::new(false);
    let result = node.authenticated_account_multiproof_with_progress(
        settings.genesis(),
        &owners,
        &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                touched.set(true);
                node.db
                    .execute("UPDATE active SET generation=generation+1", [])?;
            }
            Ok(())
        },
    );
    assert!(touched.get());
    assert!(
        result.is_err(),
        "a read-only proof must not commit callback writes"
    );
    let error = result.unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF_WRITE");
    assert!(error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(
        node.authenticated_account_multiproof(settings.genesis(), &owners)
            .unwrap()
            .1
            .encode()
            .unwrap(),
        expected.1.encode().unwrap()
    );
    drop(node);
    let node = open(directory.path(), settings, true);
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_account_query_write_then_restore_still_has_no_commit_authority() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let error = node
        .authenticated_account_multiproof_with_progress(
            settings.genesis(),
            &[development_public(0).unwrap()],
            &|point| {
                if point == NativeAccountProofProgress::BeforeOutput {
                    node.db
                        .execute("UPDATE active SET generation=generation+1", [])?;
                    node.db
                        .execute("UPDATE active SET generation=generation-1", [])?;
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF_WRITE");
    assert!(error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_account_query_cancel_after_write_keeps_original_error_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let error = node
        .authenticated_account_multiproof_with_progress(
            settings.genesis(),
            &[development_public(0).unwrap()],
            &|point| {
                if point == NativeAccountProofProgress::BeforeOutput {
                    node.db
                        .execute("UPDATE active SET generation=generation+1", [])?;
                    return Err(Error::new(ErrorCode::PublicRequestCancelled));
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::PublicRequestCancelled));
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(!error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_nonce_batch_dimensions_precede_database_and_preserve_single_reads() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings, authenticated);
        let senders = [
            development_public(0).unwrap(),
            development_public(7).unwrap(),
            development_public(777).unwrap(),
        ];
        let expected: Vec<_> = senders
            .iter()
            .map(|sender| node.next_nonce(*sender).unwrap())
            .collect();
        let before = logical_rows(&node.db);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        node.db
            .execute_batch("BEGIN IMMEDIATE; DELETE FROM kv;")
            .unwrap();
        assert_eq!(
            node.next_nonces(&[]).unwrap_err().to_string(),
            "NONCE_QUERY_LIMIT"
        );
        assert_eq!(
            node.next_nonces(&vec![[0; 32]; 257])
                .unwrap_err()
                .to_string(),
            "NONCE_QUERY_LIMIT"
        );
        assert_eq!(
            node.next_nonces(&[senders[0], senders[0]])
                .unwrap_err()
                .to_string(),
            "DUPLICATE_NONCE_QUERY"
        );
        node.db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(logical_rows(&node.db), before);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert!(node.db.is_autocommit());
    }
}

#[test]
fn native_nonce_batch_rechecks_actual_state_and_reopens_without_a_verdict_cache() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), authenticated);
        let senders = [
            development_public(0).unwrap(),
            development_public(7).unwrap(),
        ];
        let expected = node.next_nonces(&senders).unwrap();
        let before = logical_rows(&node.db);
        let other = rusqlite::Connection::open(node.directory.join("native.sqlite")).unwrap();
        let key = format!("account:{}", hex::encode(senders[0]));
        let slot = node.slot().unwrap();
        let raw: Vec<u8> = other
            .query_row(
                "SELECT value FROM kv WHERE slot=? AND key=?",
                params![slot, &key],
                |row| row.get(0),
            )
            .unwrap();
        other
            .execute(
                "UPDATE kv SET value=X'00' WHERE slot=? AND key=?",
                params![slot, &key],
            )
            .unwrap();
        let error = node.next_nonces(&senders).unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(node.db.is_autocommit());
        other
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![raw, slot, key],
            )
            .unwrap();
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert_eq!(logical_rows(&node.db), before);
        drop(other);
        drop(node);
        let node = open(directory.path(), settings, authenticated);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert_eq!(logical_rows(&node.db), before);
    }
}

#[test]
fn native_nonce_batch_arithmetic_retains_absence_bad_nonce_and_overflow_rules() {
    let sender = development_public(0).unwrap();
    let key = format!("account:{}", hex::encode(sender));
    let mut state = State::new();
    assert_eq!(next_nonce_from_state(&state, sender).unwrap(), 1);
    for value in [
        serde_json::json!(null),
        serde_json::json!({"nonce":-1}),
        serde_json::json!({"nonce":"1"}),
    ] {
        state.insert(key.clone(), value);
        assert_eq!(
            next_nonce_from_state(&state, sender)
                .unwrap_err()
                .to_string(),
            "STATE_NONCE"
        );
    }
    state.insert(key, serde_json::json!({"nonce":u64::MAX}));
    assert_eq!(
        next_nonce_from_state(&state, sender)
            .unwrap_err()
            .to_string(),
        "NONCE_OVERFLOW"
    );
}

#[test]
fn native_nonce_batch_tracks_signed_execution_heavier_reorg_and_cold_reopen() {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let sender = development_public(0).unwrap();
        let owners = [
            sender,
            development_public(3).unwrap(),
            development_public(777).unwrap(),
        ];
        assert_eq!(node.next_nonces(&owners).unwrap(), vec![1, 1, 1]);
        let mut payload = development_public(7).unwrap().to_vec();
        payload.extend(1u64.to_le_bytes());
        let mut tx = Envelope {
            network: settings.network(),
            sender,
            nonce: 1,
            expiry: 10000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        let seed = hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]);
        let key = signing_key_from_hex(&hex::encode(seed)).unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        let packet = node
            .make(
                settings.genesis(),
                vec![tx.encode().unwrap()],
                development_public(7).unwrap(),
                11,
                4096,
            )
            .unwrap();
        let old = node.admit(&packet, 100_000).unwrap();
        node.activate(old).unwrap();
        assert_eq!(node.next_nonces(&owners).unwrap(), vec![2, 1, 1]);
        let mut parent = settings.genesis();
        for height in 1..=2 {
            let packet = node
                .make(
                    parent,
                    vec![],
                    development_public(2).unwrap(),
                    2 + height * 10,
                    4096,
                )
                .unwrap();
            parent = node.admit(&packet, 100_000).unwrap();
        }
        node.activate(parent).unwrap();
        let expected: Vec<_> = owners
            .iter()
            .map(|owner| node.next_nonce(*owner).unwrap())
            .collect();
        assert_eq!(expected, vec![1, 1, 1]);
        assert_eq!(node.next_nonces(&owners).unwrap(), expected);
        assert_ne!(node.active().unwrap().0, old);
        let rows = logical_rows(&node.db);
        drop(node);
        let node = open(directory.path(), settings, authenticated);
        assert_eq!(node.next_nonces(&owners).unwrap(), expected);
        assert_eq!(logical_rows(&node.db), rows);
    }
}

#[test]
fn native_nonce_batch_complete_call_observation_preserves_reference_results() {
    use std::time::Instant;
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings, authenticated);
        let senders: Vec<_> = (0..4).map(|i| development_public(i).unwrap()).collect();
        let expected: Vec<_> = senders
            .iter()
            .map(|sender| node.next_nonce(*sender).unwrap())
            .collect();
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        let before = logical_rows(&node.db);
        for (round, batch) in [false, true, true, false].into_iter().enumerate() {
            let started = Instant::now();
            for _ in 0..16 {
                let actual = if batch {
                    node.next_nonces(&senders).unwrap()
                } else {
                    senders
                        .iter()
                        .map(|sender| node.next_nonce(*sender).unwrap())
                        .collect::<Vec<_>>()
                };
                assert_eq!(std::hint::black_box(actual), expected);
            }
            let elapsed = started.elapsed().as_nanos();
            println!(
                "native_nonce_batch_observation_v1 {}",
                serde_json::json!({"authenticated":authenticated,"round":round,"batched":batch,"senders":4,"repetitions":16,"elapsed_ns":elapsed,"nonces":expected,"full_state_checks_preserved":true,"saturated_tps_measured":false,"independent_operator":false})
            );
            assert!(node.db.is_autocommit());
            assert_eq!(logical_rows(&node.db), before);
        }
    }
}
