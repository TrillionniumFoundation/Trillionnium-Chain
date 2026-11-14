use super::*;
use crate::account_archive_prototype::multiproof::{CheckedMultiproof, MultiproofProgress};
use crate::development_public;
use crate::store::native_ancestry_commit_tests::{logical_rows, open};
use crate::Settings;
use std::cell::RefCell;

fn owners() -> [Hash; 3] {
    [
        development_public(0).unwrap(),
        development_public(7).unwrap(),
        development_public(777).unwrap(),
    ]
}

#[test]
fn pinned_account_query_repeated_real_paths_need_no_state_or_history_tables() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), true);
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transfer = trnm_protocol::pon_wire::Envelope {
        network: settings.network(),
        sender: owners()[0],
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(crate::hash(
        b"DEV-ONLY-KEY",
        &[&0_u64.to_le_bytes()],
    )))
    .unwrap();
    transfer.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &key,
        &transfer.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let block = node
        .make(
            settings.genesis(),
            vec![transfer.encode().unwrap()],
            owners()[1],
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&block, 100_000).unwrap();
    node.activate(id).unwrap();
    let expected = node
        .authenticated_account_multiproof(id, &owners())
        .unwrap();
    let pin = node
        .pin_authenticated_account_query(id, &|_| Ok(()))
        .unwrap();
    assert_eq!(pin.checkpoint(), &expected.0);
    // Make any full-State/history dependency genuinely unavailable, rather than
    // asserting implementation text or trusting a synthetic scan counter.
    for table in ["kv", "snapshots", "deltas"] {
        node.db
            .execute_batch(&format!("ALTER TABLE {table} RENAME TO hidden_{table}"))
            .unwrap();
    }
    node.db.flush_prepared_statement_cache();
    assert!(node
        .authenticated_account_multiproof(id, &owners())
        .is_err());
    for _ in 0..3 {
        let trace = RefCell::new(Vec::new());
        let actual = node
            .authenticated_account_multiproof_at_pin(&pin, &owners(), &|point| {
                trace.borrow_mut().push(point);
                Ok(())
            })
            .unwrap();
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1.encode().unwrap(), expected.1.encode().unwrap());
        assert_eq!(actual.2, expected.2);
        assert!(actual.2.archive_point_reads > 0);
        assert!(!trace
            .borrow()
            .contains(&NativeAccountProofProgress::StateReplay));
        assert!(!trace
            .borrow()
            .contains(&NativeAccountProofProgress::StateVerification));
        let checked = CheckedMultiproof::verify(pin.context, &actual.0, &actual.1).unwrap();
        assert_eq!(checked.account(owners()[0]).unwrap().unwrap().nonce, 1);
        assert!(checked.account(owners()[2]).unwrap().is_none());
    }
    // The deliberately damaged native store must not become cold-openable just
    // because the separate historical proof reader can still use its COW tree.
    drop(node);
    assert!(Node::open_with_authenticated_state(directory.path(), settings, 1).is_err());
}

#[test]
fn pinned_account_query_rejects_current_context_record_block_and_missing_nodes() {
    for change in [
        "context",
        "record",
        "block",
        "node",
        "missing-record",
        "pin-context",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), true);
        let mut pin = node
            .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
            .unwrap();
        match change {
            "context" => {
                node.db
                    .execute(
                        "UPDATE metadata SET value=? WHERE key='parameters'",
                        [[9u8; 32].as_slice()],
                    )
                    .unwrap();
            }
            "record" => {
                node.db
                    .execute(
                        "UPDATE native_state_commitments SET data=?",
                        [b"{}".as_slice()],
                    )
                    .unwrap();
            }
            "block" => {
                node.db
                    .execute("UPDATE blocks SET chainwork=?", [[9u8; 64].as_slice()])
                    .unwrap();
            }
            "node" => {
                node.db.execute("DELETE FROM archive_nodes", []).unwrap();
            }
            "missing-record" => {
                node.db
                    .execute("DELETE FROM native_state_commitments", [])
                    .unwrap();
            }
            "pin-context" => pin.context.network[0] ^= 1,
            _ => unreachable!(),
        }
        let error = node
            .authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
            .unwrap_err();
        if change == "block" {
            assert_eq!(error.to_string(), "NATIVE_ACCOUNT_QUERY_PIN_CHANGED");
        }
        if change == "pin-context" {
            assert_eq!(error.to_string(), "NATIVE_ACCOUNT_QUERY_CONTEXT");
        }
        assert!(node.db.is_autocommit());
    }
}

#[test]
fn pinned_account_query_cancel_and_callback_write_keep_original_error_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let pin = node
        .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
        .unwrap();
    let before = logical_rows(&node.db);
    for stop in [
        NativeAccountProofProgress::BeforeRead,
        NativeAccountProofProgress::Proof(MultiproofProgress::ArchiveRead { index: 0 }),
        NativeAccountProofProgress::Proof(MultiproofProgress::Account { index: 0 }),
        NativeAccountProofProgress::BeforeOutput,
    ] {
        let error = node
            .authenticated_account_multiproof_at_pin(&pin, &owners(), &|point| {
                if point == stop {
                    Err(Error::from("original-query-cancel"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "original-query-cancel");
        assert!(node.db.is_autocommit());
        assert_eq!(logical_rows(&node.db), before);
    }
    let error = node
        .authenticated_account_multiproof_at_pin(&pin, &owners(), &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                node.db
                    .execute("UPDATE active SET generation=generation+1", [])?;
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF_WRITE");
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(
        node.authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
            .unwrap()
            .1
            .encode()
            .unwrap(),
        node.authenticated_account_multiproof(settings.genesis(), &owners())
            .unwrap()
            .1
            .encode()
            .unwrap()
    );
}

#[test]
fn pinned_account_query_is_historical_content_not_active_or_cold_open_authority() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), true);
    let pin = node
        .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
        .unwrap();
    let expected = node
        .authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
        .unwrap();
    let block = node
        .make(settings.genesis(), vec![], owners()[1], 11, 4096)
        .unwrap();
    let id = node.admit(&block, 100_000).unwrap();
    node.activate(id).unwrap();
    assert_eq!(
        node.authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
            .unwrap(),
        expected
    );
    drop(node);
    let node = open(directory.path(), settings.clone(), true);
    assert_eq!(
        node.authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
            .unwrap(),
        expected
    );
    // Corrupt live KV: the historical proof is still exactly its pinned content,
    // while the unchanged cold-open owner must reject the actual corrupt State.
    node.db
        .execute(
            "UPDATE kv SET value=? WHERE key=?",
            rusqlite::params![
                br#"{"balance":9,"nonce":9}"#.as_slice(),
                format!("account:{}", hex::encode(owners()[0]))
            ],
        )
        .unwrap();
    assert_eq!(
        node.authenticated_account_multiproof_at_pin(&pin, &owners(), &|_| Ok(()))
            .unwrap(),
        expected
    );
    drop(node);
    assert!(Node::open_with_authenticated_state(directory.path(), settings, 1).is_err());
}

#[derive(Clone, Copy, Debug)]
enum QueryScopeEntry {
    Strict,
    Pin,
    Pinned,
}

const QUERY_SCOPE_ENTRIES: [QueryScopeEntry; 3] = [
    QueryScopeEntry::Strict,
    QueryScopeEntry::Pin,
    QueryScopeEntry::Pinned,
];

fn scoped_query(
    node: &Node,
    pin: &PinnedNativeAccountQuery,
    entry: QueryScopeEntry,
    progress: &impl Fn(NativeAccountProofProgress) -> Result<()>,
) -> Result<()> {
    match entry {
        QueryScopeEntry::Strict => node
            .authenticated_account_multiproof_with_progress(
                node.settings.genesis(),
                &owners(),
                progress,
            )
            .map(|_| ()),
        QueryScopeEntry::Pin => node
            .pin_authenticated_account_query(node.settings.genesis(), progress)
            .map(|_| ()),
        QueryScopeEntry::Pinned => node
            .authenticated_account_multiproof_at_pin(pin, &owners(), progress)
            .map(|_| ()),
    }
}

fn query_inside_point(entry: QueryScopeEntry) -> NativeAccountProofProgress {
    match entry {
        QueryScopeEntry::Strict | QueryScopeEntry::Pin => NativeAccountProofProgress::StateReplay,
        QueryScopeEntry::Pinned => {
            NativeAccountProofProgress::Proof(MultiproofProgress::ArchiveRead { index: 0 })
        }
    }
}

#[test]
fn account_query_scope_rejects_commit_rollback_and_savepoint_aba() {
    for entry in QUERY_SCOPE_ENTRIES {
        for sql in [
            "ROLLBACK; BEGIN",
            "COMMIT; BEGIN",
            "SAVEPOINT query_probe; RELEASE query_probe",
            "SAVEPOINT query_probe; ROLLBACK TO query_probe; RELEASE query_probe",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(1)).unwrap();
            let node = open(directory.path(), settings.clone(), true);
            let pin = node
                .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
                .unwrap();
            let before = logical_rows(&node.db);
            let changes = node.db.total_changes();
            let reached = std::cell::Cell::new(false);
            let error = scoped_query(&node, &pin, entry, &|point| {
                if point == NativeAccountProofProgress::BeforeOutput {
                    reached.set(true);
                    assert!(!node.db.is_autocommit());
                    node.db.execute_batch(sql)?;
                    assert!(!node.db.is_autocommit());
                    assert_eq!(node.db.total_changes(), changes);
                }
                Ok(())
            })
            .expect_err("the original read transaction cannot be replaced");
            assert!(reached.get(), "{entry:?}, {sql}");
            assert!(
                error.to_string().starts_with("NATIVE_ACCOUNT_PROOF_SCOPE"),
                "{entry:?}, {sql}: {error}"
            );
            assert!(error.requires_owner_stop());
            assert!(node.db.is_autocommit());
            assert_eq!(logical_rows(&node.db), before);
            scoped_query(&node, &pin, entry, &|_| Ok(())).unwrap();
        }
    }
}

#[test]
fn account_query_scope_rejects_an_actual_new_snapshot_without_local_row_writes() {
    for entry in QUERY_SCOPE_ENTRIES {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), true);
        let pin = node
            .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
            .unwrap();
        let foreign = rusqlite::Connection::open(node.directory.join("native.sqlite")).unwrap();
        let before = logical_rows(&node.db);
        let generation = node.active().unwrap().1;
        let changes = node.db.total_changes();
        let reached = std::cell::Cell::new(false);
        let error = scoped_query(&node, &pin, entry, &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                reached.set(true);
                assert_eq!(node.active()?.1, generation);
                node.db.execute_batch("ROLLBACK")?;
                foreign.execute("UPDATE active SET generation=generation+1", [])?;
                node.db.execute_batch("BEGIN")?;
                // This read really enters the foreign commit's NEW snapshot.
                assert_eq!(node.active()?.1, generation + 1);
                assert_eq!(node.db.total_changes(), changes);
            }
            Ok(())
        })
        .expect_err("a foreign committed generation cannot replace this read snapshot");
        assert!(reached.get(), "{entry:?}");
        assert!(error.to_string().starts_with("NATIVE_ACCOUNT_PROOF_SCOPE"));
        assert!(error.requires_owner_stop());
        assert!(node.db.is_autocommit());
        // Refusal does not pretend to roll back another connection's commit.
        assert_eq!(node.active().unwrap().1, generation + 1);
        foreign
            .execute("UPDATE active SET generation=generation-1", [])
            .unwrap();
        assert_eq!(logical_rows(&node.db), before);
        scoped_query(&node, &pin, entry, &|_| Ok(())).unwrap();
    }
}

#[test]
fn account_query_scope_error_keeps_cancellation_after_early_or_final_replacement() {
    for entry in QUERY_SCOPE_ENTRIES {
        for stop in [
            query_inside_point(entry),
            NativeAccountProofProgress::BeforeOutput,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(1)).unwrap();
            let node = open(directory.path(), settings.clone(), true);
            let pin = node
                .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
                .unwrap();
            let before = logical_rows(&node.db);
            let reached = std::cell::Cell::new(false);
            let error = scoped_query(&node, &pin, entry, &|point| {
                if point == stop {
                    reached.set(true);
                    node.db.execute_batch("ROLLBACK; BEGIN")?;
                    Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(reached.get(), "{entry:?}, {stop:?}");
            assert!(error.to_string().starts_with("NATIVE_ACCOUNT_PROOF_SCOPE"));
            assert!(error.requires_owner_stop());
            let first = std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<Error>())
                .expect("the original typed cancellation remains the source");
            assert_eq!(first.code(), Some(crate::ErrorCode::PublicRequestCancelled));
            assert_eq!(first.kind(), crate::ErrorKind::Cancelled);
            assert!(!first.requires_owner_stop());
            assert!(node.db.is_autocommit());
            assert_eq!(logical_rows(&node.db), before);
        }
    }
}

#[test]
fn account_query_scope_rejects_automatic_rollback_with_unchanged_row_count() {
    for entry in QUERY_SCOPE_ENTRIES {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), true);
        let pin = node
            .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
            .unwrap();
        let before = logical_rows(&node.db);
        let changes = node.db.total_changes();
        let reached = std::cell::Cell::new(false);
        let error = scoped_query(&node, &pin, entry, &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                reached.set(true);
                assert!(!node.db.is_autocommit());
                node.db
                    .execute(
                        "INSERT OR ROLLBACK INTO metadata(key,value) VALUES('schema',X'00')",
                        [],
                    )
                    .expect_err("the existing schema key forces SQLite's implicit rollback");
                assert!(node.db.is_autocommit());
                assert_eq!(node.db.total_changes(), changes);
            }
            Ok(())
        })
        .unwrap_err();
        assert!(reached.get(), "{entry:?}");
        assert!(error.to_string().starts_with("NATIVE_ACCOUNT_PROOF_SCOPE"));
        assert!(error.requires_owner_stop());
        assert!(node.db.is_autocommit());
        assert_eq!(logical_rows(&node.db), before);
        scoped_query(&node, &pin, entry, &|_| Ok(())).unwrap();
    }
}

#[test]
fn account_query_scope_keeps_foreign_controls_and_ordinary_cancellation_separate() {
    for entry in QUERY_SCOPE_ENTRIES {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), true);
        let pin = node
            .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
            .unwrap();
        let foreign = rusqlite::Connection::open(node.directory.join("native.sqlite")).unwrap();
        let before = logical_rows(&node.db);
        let reached = std::cell::Cell::new(false);
        scoped_query(&node, &pin, entry, &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                reached.set(true);
                foreign.execute_batch("BEGIN; SAVEPOINT other; RELEASE other; ROLLBACK")?;
            }
            Ok(())
        })
        .unwrap();
        assert!(reached.get(), "{entry:?}");
        for stop in [
            query_inside_point(entry),
            NativeAccountProofProgress::BeforeOutput,
        ] {
            let error = scoped_query(&node, &pin, entry, &|point| {
                if point == stop {
                    Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.code(), Some(crate::ErrorCode::PublicRequestCancelled));
            assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
            assert!(!error.requires_owner_stop());
            assert!(node.db.is_autocommit());
            assert_eq!(logical_rows(&node.db), before);
        }
    }
}

#[test]
fn account_query_scope_cancelled_row_writes_clear_candidates_and_keep_original_error() {
    for entry in QUERY_SCOPE_ENTRIES {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), true);
        let pin = node
            .pin_authenticated_account_query(settings.genesis(), &|_| Ok(()))
            .unwrap();
        let expected = node
            .authenticated_account_multiproof(settings.genesis(), &owners())
            .unwrap()
            .1
            .encode()
            .unwrap();
        node.read_active().unwrap();
        assert!(node.derived_commitment_status().cache_root.is_some());
        let before = logical_rows(&node.db);
        let reached = std::cell::Cell::new(false);
        let error = scoped_query(&node, &pin, entry, &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                reached.set(true);
                node.db
                    .execute("UPDATE active SET generation=generation+1", [])?;
                Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(reached.get(), "{entry:?}");
        assert_eq!(error.code(), Some(crate::ErrorCode::PublicRequestCancelled));
        assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
        assert!(!error.requires_owner_stop());
        assert!(node.derived_commitment_status().cache_root.is_none());
        assert!(node.db.is_autocommit());
        assert_eq!(logical_rows(&node.db), before);
        assert_eq!(
            node.authenticated_account_multiproof(settings.genesis(), &owners())
                .unwrap()
                .1
                .encode()
                .unwrap(),
            expected
        );
    }
}
