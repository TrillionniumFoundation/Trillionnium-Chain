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
