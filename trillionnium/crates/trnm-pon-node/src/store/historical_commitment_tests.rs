use super::*;
use crate::{ErrorCode, ErrorKind};
use serde_json::json;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_commitment::CommitmentMethod;
use trnm_protocol::pon_wire::Envelope;

const NOW: u64 = 1_000_000;

fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10_000,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn chain(path: &Path) -> (Node, Vec<Hash>) {
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(path, settings.clone(), 2).unwrap();
    let mut ids = vec![settings.genesis()];
    for height in 1..=6 {
        let packet = node
            .make(
                *ids.last().unwrap(),
                vec![transfer(&settings, height)],
                development_public(2).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, NOW).unwrap();
        node.activate(id).unwrap();
        ids.push(id);
    }
    (node, ids)
}
fn retained_status(node: &Node) -> (usize, usize, usize) {
    let cache = node.historical_commitment_cache.borrow();
    (
        cache.entries(),
        cache.payload_bytes(),
        cache.retained_charge_bytes(),
    )
}
fn assert_original_error(node: &Node, operation: impl Fn() -> Result<()>) -> String {
    assert!(retained_status(node).0 > 0);
    let warm = operation().unwrap_err();
    node.historical_commitment_cache.borrow_mut().clear();
    let original = operation().unwrap_err();
    assert_eq!(warm.to_string(), original.to_string());
    assert_eq!(warm.kind(), original.kind());
    assert_eq!(warm.requires_owner_stop(), original.requires_owner_stop());
    warm.to_string()
}

#[test]
fn historical_material_reuses_arithmetic_after_complete_replay_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path());
    let expected = node.state_at(ids[4]).unwrap();
    node.historical_commitment_cache.borrow_mut().clear();
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    let cold = node.derived_commitment_status();
    assert_eq!(retained_status(&node).0, 5);
    assert!(retained_status(&node).1 > 0);
    assert!(retained_status(&node).2 > 0);
    assert!(cold.last.unwrap().changed_keys > 0);
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    let warm = node.derived_commitment_status();
    assert_eq!(
        warm.last.as_ref().unwrap().method,
        CommitmentMethod::CheckedApply
    );
    assert_eq!(warm.last.unwrap().changed_keys, 0);
    assert_eq!(root(&expected).unwrap(), node.record(ids[4]).unwrap().root);
    let active = node.read_active().unwrap();
    let settings = node.settings.clone();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(reopened.state_at(ids[4]).unwrap(), expected);
    assert_eq!(reopened.read_active().unwrap(), active);
}

#[test]
fn actual_foreign_snapshot_delta_and_root_damage_preserve_original_failures() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path());
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let expected = node.state_at(ids[4]).unwrap();
    let genesis_raw: Vec<u8> = foreign
        .query_row(
            "SELECT state FROM snapshots WHERE block=?",
            [ids[0].as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let (key, before, after): Delta = foreign
        .query_row("SELECT key,before,after FROM deltas WHERE block=? AND before IS NOT NULL AND after IS NOT NULL ORDER BY key LIMIT 1", [ids[2].as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    for bad in [b"[".to_vec(), [genesis_raw.clone(), b" ".to_vec()].concat()] {
        node.state_at(ids[4]).unwrap();
        foreign
            .execute(
                "UPDATE snapshots SET state=? WHERE block=?",
                params![bad, ids[0].as_slice()],
            )
            .unwrap();
        let error = assert_original_error(&node, || node.state_at(ids[4]).map(|_| ()));
        assert!(error == "STATE_BYTES" || error.starts_with("JSON:"));
        foreign
            .execute(
                "UPDATE snapshots SET state=? WHERE block=?",
                params![genesis_raw, ids[0].as_slice()],
            )
            .unwrap();
        assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    }
    node.state_at(ids[4]).unwrap();
    let mut changed_genesis: State = serde_json::from_slice(&genesis_raw).unwrap();
    changed_genesis.insert("extra".into(), json!(0));
    foreign
        .execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![canonical(&changed_genesis).unwrap(), ids[0].as_slice()],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node.state_at(ids[4]).map(|_| ())),
        "ROOT"
    );
    foreign
        .execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![genesis_raw, ids[0].as_slice()],
        )
        .unwrap();
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    node.state_at(ids[4]).unwrap();
    foreign
        .execute(
            "UPDATE deltas SET before=? WHERE block=? AND key=?",
            params![b"null".as_slice(), ids[2].as_slice(), key],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node.state_at(ids[4]).map(|_| ())),
        "UNDO_ROOT"
    );
    foreign
        .execute(
            "UPDATE deltas SET before=? WHERE block=? AND key=?",
            params![before, ids[2].as_slice(), key],
        )
        .unwrap();
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    for bad in [b"[".as_slice(), b"null".as_slice()] {
        node.state_at(ids[4]).unwrap();
        foreign
            .execute(
                "UPDATE deltas SET after=? WHERE block=? AND key=?",
                params![bad, ids[2].as_slice(), key],
            )
            .unwrap();
        let error = assert_original_error(&node, || node.state_at(ids[4]).map(|_| ()));
        assert!(error == "ROOT" || error.starts_with("JSON:"));
        foreign
            .execute(
                "UPDATE deltas SET after=? WHERE block=? AND key=?",
                params![after, ids[2].as_slice(), key],
            )
            .unwrap();
        assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    }
    node.state_at(ids[4]).unwrap();
    let original_root = node.record(ids[4]).unwrap().root;
    foreign
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![[92_u8; 32].as_slice(), ids[4].as_slice()],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node.state_at(ids[4]).map(|_| ())),
        "ROOT"
    );
    assert_eq!(retained_status(&node).0, 0);
    foreign
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![original_root.as_slice(), ids[4].as_slice()],
        )
        .unwrap();
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    node.state_at(ids[4]).unwrap();
    foreign
        .execute(
            "DELETE FROM deltas WHERE block=? AND key=?",
            params![ids[2].as_slice(), key],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node.state_at(ids[4]).map(|_| ())),
        "ROOT"
    );
    foreign
        .execute(
            "INSERT INTO deltas VALUES(?,?,?,?)",
            params![ids[2].as_slice(), key, before, after],
        )
        .unwrap();
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
}

#[test]
fn original_context_parent_header_and_work_checks_keep_their_positions() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path());
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let mut packet = node
        .make(
            ids[4],
            vec![transfer(&node.settings, 5)],
            development_public(3).unwrap(),
            55,
            4096,
        )
        .unwrap();
    packet.proof[8] ^= 1;
    assert!(node
        .check_admission_context(&packet, NOW)
        .unwrap()
        .is_none());
    let original_params = node.settings.parameters();
    foreign
        .execute(
            "UPDATE metadata SET value=? WHERE key='parameters'",
            [[94_u8; 32].as_slice()],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node.check_active_before_commit()),
        "STORAGE_CONTEXT"
    );
    foreign
        .execute(
            "UPDATE metadata SET value=? WHERE key='parameters'",
            [original_params.as_slice()],
        )
        .unwrap();
    node.state_at(ids[4]).unwrap();
    foreign
        .execute(
            "UPDATE blocks SET parent=? WHERE id=?",
            params![ids[1].as_slice(), ids[4].as_slice()],
        )
        .unwrap();
    let error = assert_original_error(&node, || {
        node.check_admission_context(&packet, NOW).map(|_| ())
    });
    assert!(error == "STORAGE_PACKET" || error == "ANCESTRY_HEIGHT");
    foreign
        .execute(
            "UPDATE blocks SET parent=? WHERE id=?",
            params![ids[3].as_slice(), ids[4].as_slice()],
        )
        .unwrap();
    node.state_at(ids[4]).unwrap();
    let raw = node.packet(ids[3]).unwrap().encode().unwrap();
    let mut damaged = raw.clone();
    damaged[0] ^= 0xff;
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![damaged, ids[3].as_slice()],
        )
        .unwrap();
    assert_eq!(
        assert_original_error(&node, || node
            .check_admission_context(&packet, NOW)
            .map(|_| ())),
        "HEADER_CODEC"
    );
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![raw, ids[3].as_slice()],
        )
        .unwrap();
    node.state_at(ids[4]).unwrap();
    let original_work = node.record(ids[3]).unwrap().work.bytes();
    foreign
        .execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![[0_u8; 65].as_slice(), ids[3].as_slice()],
        )
        .unwrap();
    let error = assert_original_error(&node, || {
        node.check_observed_history(ids[4], NOW).map(|_| ())
    });
    assert!(error.starts_with("SQLITE:") || error == "STORAGE_WORK");
    foreign
        .execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![original_work.as_slice(), ids[3].as_slice()],
        )
        .unwrap();
    assert!(node
        .check_admission_context(&packet, NOW)
        .unwrap()
        .is_none());
}

#[test]
fn historical_cancel_and_cpu_budget_keep_original_progress_and_error_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path());
    let expected = node.state_at(ids[4]).unwrap();
    let mut maximum = 0;
    node.state_at_with_progress(ids[4], &mut || {
        maximum += 1;
        Ok(())
    })
    .unwrap();
    assert!(maximum > 10);
    for code in [
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicMutationCpuBudget,
        ErrorCode::UnknownParent,
    ] {
        for stop in [2, maximum / 2, maximum] {
            for warm in [true, false] {
                if warm {
                    node.state_at(ids[4]).unwrap();
                } else {
                    node.historical_commitment_cache.borrow_mut().clear();
                }
                let mut calls = 0;
                let error = node
                    .state_at_with_progress(ids[4], &mut || {
                        calls += 1;
                        if calls == stop {
                            Err(Error::new(code))
                        } else {
                            Ok(())
                        }
                    })
                    .unwrap_err();
                assert!(error.is(code));
                assert_eq!(error.kind(), Error::new(code).kind());
                assert!(!error.requires_owner_stop());
                assert_eq!(calls, stop);
            }
            assert_eq!(node.state_at(ids[4]).unwrap(), expected);
        }
    }
}

#[test]
fn cached_historical_material_cannot_hide_final_writer_damage_or_publish_failed_block() {
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path());
    let packet = node
        .make(
            ids[4],
            vec![transfer(&node.settings, 5)],
            development_public(3).unwrap(),
            55,
            4096,
        )
        .unwrap();
    let before = node.read_active().unwrap();
    let parent_state = node.state_at(ids[4]).unwrap();
    let expected = trnm_mvcc_fee::pon_executor::execute(
        &parent_state,
        &packet.transactions,
        packet.header.height,
        packet.header.miner,
        packet.header.parent,
        2,
        &node.settings.app,
    )
    .unwrap();
    assert_eq!(expected.root, packet.header.state);
    assert_eq!(
        sequence_root("receipts", &expected.receipts),
        packet.header.receipts
    );
    let count: u64 = node
        .db
        .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
        .unwrap();
    node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage_old_parent BEFORE INSERT ON blocks BEGIN UPDATE deltas SET before=X'6e756c6c' WHERE block=X'{}' AND before IS NOT NULL; END;", hex::encode(ids[2]))).unwrap();
    let error = node.admit(&packet, NOW).unwrap_err();
    assert_eq!(error.to_string(), "UNDO_ROOT");
    assert_eq!(error.kind(), ErrorKind::LocalStructure);
    assert!(error.requires_owner_stop());
    assert_eq!(
        node.db
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        count
    );
    assert_eq!(node.read_active().unwrap(), before);
    node.db
        .execute_batch("DROP TRIGGER damage_old_parent;")
        .unwrap();
    let id = node.admit(&packet, NOW).unwrap();
    assert_eq!(id, packet.id().unwrap());
    assert_eq!(node.state_at(id).unwrap(), expected.state);
}

fn material(state: &State) -> CheckedCommitment {
    pon_commitment::checked_snapshot(state, root(state).unwrap(), None, CacheLimits::default())
        .unwrap()
        .snapshot
        .unwrap()
}
#[test]
fn independent_entry_payload_and_retention_bounds_discard_without_ledger_rejection() {
    let mut cache = historical_commitment::HistoricalCommitments::default();
    let small = material(&State::from([("key".into(), json!(1))]));
    for n in 0..=8_u8 {
        cache.retain([n; 32], Some(&small));
    }
    assert_eq!(cache.entries(), 8);
    assert!(cache.candidate([0; 32], small.root()).is_none());
    assert!(cache.candidate([8; 32], small.root()).is_some());
    assert_eq!(
        cache.retained_charge_bytes(),
        8 * small.retained_charge_bytes()
    );
    assert_eq!(cache.payload_bytes(), 8 * small.payload_bytes());
    let large_state: State = (0..8000)
        .map(|n| (format!("key:{n:05}"), json!(n)))
        .collect();
    let large = material(&large_state);
    assert!(large.retained_charge_bytes() < 16 * 1024 * 1024);
    cache.clear();
    cache.retain([1; 32], Some(&large));
    cache.retain([2; 32], Some(&large));
    assert_eq!(cache.entries(), 1);
    assert!(cache.retained_charge_bytes() <= 16 * 1024 * 1024);
    let oversized_state: State = (0..12000)
        .map(|n| (format!("key:{n:05}"), json!(n)))
        .collect();
    let oversized = material(&oversized_state);
    assert!(oversized.retained_charge_bytes() > 16 * 1024 * 1024);
    cache.retain([4; 32], Some(&oversized));
    assert_eq!(cache.entries(), 1);
    assert!(cache.candidate([4; 32], oversized.root()).is_none());
    let heavy_payload: State = (0..513)
        .map(|n| (format!("payload:{n:04}"), json!("x".repeat(4094))))
        .collect();
    let heavy = material(&heavy_payload);
    assert!(heavy.payload_bytes() > 2 * 1024 * 1024);
    cache.retain([3; 32], Some(&heavy));
    assert_eq!(cache.entries(), 1);
    assert!(cache.candidate([3; 32], heavy.root()).is_none());
    cache.retain([2; 32], None);
    assert_eq!(
        (
            cache.entries(),
            cache.payload_bytes(),
            cache.retained_charge_bytes()
        ),
        (0, 0, 0)
    );
}

#[test]
fn wrong_block_material_is_only_an_index_miss_and_original_invalidation_clears_all() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path());
    let expected = node.state_at(ids[4]).unwrap();
    let wrong = material(&State::from([("unrelated".into(), json!(99))]));
    node.historical_commitment_cache
        .borrow_mut()
        .retain(ids[4], Some(&wrong));
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
    assert!(node.derived_commitment_status().last.unwrap().changed_keys > 0);
    assert!(retained_status(&node).0 > 0);
    node.invalidate_commitment();
    let status = node.derived_commitment_status();
    assert_eq!(status.cache_root, None);
    assert_eq!(
        (
            retained_status(&node).0,
            retained_status(&node).1,
            retained_status(&node).2
        ),
        (0, 0, 0)
    );
    assert_eq!(node.state_at(ids[4]).unwrap(), expected);
}
