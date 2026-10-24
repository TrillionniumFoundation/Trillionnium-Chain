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
