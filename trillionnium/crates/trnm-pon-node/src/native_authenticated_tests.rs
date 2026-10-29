use super::*;
use crate::account_archive_prototype::{multiproof::CheckedMultiproof, Context};
use crate::ErrorKind;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}
fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn transaction(
    settings: &Settings,
    sender: u64,
    account_sequence: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(sender),
        nonce: account_sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn transfer(settings: &Settings, account_sequence: u64, recipient: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend((100 + recipient).to_le_bytes());
    transaction(settings, 0, account_sequence, 1, payload)
}
fn make(node: &Node, parent: Hash, transactions: Vec<Vec<u8>>) -> Packet {
    let height = node.parent_height(parent).unwrap() + 1;
    node.make_consensus_maintenance(parent, transactions, public(7), 1 + height * 10, 4096)
        .unwrap()
}
fn open(path: &Path, backend: StateBackend) -> Node {
    match backend {
        StateBackend::PqNetworkV2 => panic!("use the independently pinned PQ network fixture"),
        StateBackend::PermanentAccountGrowthV2 => {
            panic!("use the separately selected growth fixture")
        }
        StateBackend::Legacy => Node::open(path, settings(), 1).unwrap(),
        StateBackend::AuthenticatedV1 => {
            Node::open_with_authenticated_state(path, settings(), 1).unwrap()
        }
    }
}
fn logical_rows(db: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    let mut result = BTreeMap::new();
    for table in tables {
        assert!(table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        let mut stmt = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = stmt.column_count();
        let mut values: Vec<Vec<String>> = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|index| {
                        row.get::<_, rusqlite::types::Value>(index)
                            .map(|value| format!("{value:?}"))
                    })
                    .collect()
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        values.sort();
        result.insert(table, values);
    }
    result
}

#[test]
fn native_authenticated_signed_growth_branches_reopen_and_compact_queries() {
    let dir = tempfile::tempdir().unwrap();
    let native_path = dir.path().join("authenticated");
    let reference_path = dir.path().join("reference");
    let mut node = open(&native_path, StateBackend::AuthenticatedV1);
    let mut reference = open(&reference_path, StateBackend::Legacy);
    let genesis = node.settings.genesis();
    let initial = node.read_active().unwrap().2;
    let mut blocks = vec![genesis];
    let first = make(&node, genesis, vec![transfer(&node.settings, 1, 10)]);
    let first = node
        .admit(&first, 100_000)
        .and_then(|id| {
            reference.admit(&node.packet(id)?, 100_000)?;
            Ok(id)
        })
        .unwrap();
    blocks.push(first);
    node.activate(first).unwrap();
    reference.activate(first).unwrap();
    let second = make(&node, first, vec![transfer(&node.settings, 2, 11)]);
    let second_id = node.admit(&second, 100_000).unwrap();
    reference.admit(&second, 100_000).unwrap();
    blocks.push(second_id);
    node.activate(second_id).unwrap();
    reference.activate(second_id).unwrap();
    let generation_before_reorg = node.active().unwrap().1;
    let mut tip = genesis;
    for (height, recipient) in [(1, 20), (2, 21), (3, 22)] {
        let packet = make(
            &node,
            tip,
            vec![transfer(&node.settings, height, recipient)],
        );
        tip = node.admit(&packet, 100_000).unwrap();
        reference.admit(&packet, 100_000).unwrap();
        blocks.push(tip);
    }
    assert_eq!(node.activate(tip).unwrap(), tip);
    reference.activate(tip).unwrap();
    assert!(node.active().unwrap().1 > generation_before_reorg);
    assert_eq!(
        node.state_at(first).unwrap(),
        reference.state_at(first).unwrap()
    );
    assert_eq!(
        node.state_at(second_id).unwrap(),
        reference.state_at(second_id).unwrap()
    );
    // More signed account growth and enough actual empty successors to mature
    // rewards; only account deltas copy paths, unchanged roots remain shared.
    for height in 4..=34 {
        let txs = if height <= 8 {
            vec![transfer(&node.settings, height, 30 + height)]
        } else {
            Vec::new()
        };
        let packet = make(&node, tip, txs);
        tip = node.admit(&packet, 100_000).unwrap();
        reference.admit(&packet, 100_000).unwrap();
        blocks.push(tip);
        node.activate(tip).unwrap();
        reference.activate(tip).unwrap();
    }
    assert_eq!(
        node.read_active().unwrap(),
        reference.read_active().unwrap()
    );
    let before_reopen = logical_rows(&node.db);
    let active = node.active().unwrap();
    drop(node);
    let node = open(&native_path, StateBackend::AuthenticatedV1);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(logical_rows(&node.db), before_reopen);
    for &block in &blocks {
        assert_eq!(
            node.state_at(block).unwrap(),
            reference.state_at(block).unwrap()
        );
    }
    let owners = [public(0), public(20), public(999)];
    let (checkpoint, proof, observation) =
        node.authenticated_account_multiproof(tip, &owners).unwrap();
    let context = Context {
        network: node.settings.network(),
        parameters: node.settings.parameters(),
        genesis,
    };
    let checked = CheckedMultiproof::verify(context, &checkpoint, &proof).unwrap();
    assert_eq!(checked.account(public(0)).unwrap().unwrap().nonce, 8);
    assert!(checked.account(public(20)).unwrap().is_some());
    assert!(checked.account(public(999)).unwrap().is_none());
    assert!(
        proof.encode().unwrap().len()
            < owners.len() * crate::account_archive_prototype::MAX_WITNESS_BYTES
    );
    let selected_state = node.read_active().unwrap().2;
    assert!(selected_state.contains_key(&format!("account:{}", hex::encode(public(7)))));
    let record = native_authenticated::load(&node.db, tip).unwrap();
    assert_eq!(record.accounts.digest, checkpoint.account_root());
    assert_eq!(record.accounts.count, checkpoint.account_count());
    let node_rows: u64 = node
        .db
        .query_row("SELECT COUNT(*) FROM archive_nodes", [], |row| row.get(0))
        .unwrap();
    assert!(node_rows > 2 * record.accounts.count - 1);
    if let Ok(directory) = std::env::var("TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR") {
        let directory = Path::new(&directory);
        assert!(!directory.exists() && fs::symlink_metadata(directory).is_err());
        fs::create_dir(directory).unwrap();
        let exported: Vec<_> = blocks
            .iter()
            .map(|&id| json!({"id":hex::encode(id),"state":node.state_at(id).unwrap()}))
            .collect();
        let manifest = json!({
            "schema":"pon-native-authenticated-storage-native-observation-v1",
            "database":"native.sqlite", "genesis_timestamp":1,
            "context":{"network":hex::encode(context.network),"parameters":hex::encode(context.parameters),"genesis":hex::encode(genesis)},
            "initial":initial,
            "active":{"tip":hex::encode(active.0),"generation":active.1,"state_slot":node.slot().unwrap()},
            "blocks":exported, "reopened":true,
            "operations":{"signed_transfers":10,"admitted_blocks":36,"reorganizations":1,"cold_reopens":1,"reward_maturity_height":34},
            "compact_query":{"checkpoint":checkpoint,"proof":proof,"observation":observation,"encoded_bytes":proof.encode().unwrap().len(),
                "proof_hex":hex::encode(proof.encode().unwrap()),"requested_owners":owners.iter().map(hex::encode).collect::<Vec<_>>()},
            "scope":{"native_single_database":true,"cow_account_nodes":true,"complete_state_reference":true,"partial_state":false,"production_acceptance":false}
        });
        fs::write(
            directory.join("native.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        node.db
            .execute(
                "VACUUM INTO ?",
                [directory.join("native.sqlite").to_str().unwrap()],
            )
            .unwrap();
    }
}

#[test]
fn native_authenticated_namespaces_missing_nodes_and_corrupt_records_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join("legacy");
    let native_path = dir.path().join("authenticated");
    drop(open(&legacy_path, StateBackend::Legacy));
    assert_eq!(
        Node::open_with_authenticated_state(&legacy_path, settings(), 1)
            .err()
            .unwrap()
            .to_string(),
        "SCHEMA"
    );
    let node = open(&native_path, StateBackend::AuthenticatedV1);
    let genesis = node.settings.genesis();
    let before = logical_rows(&node.db);
    assert!(Node::open(&native_path, settings(), 1).is_err());
    let missing = native_authenticated::load(&node.db, genesis)
        .unwrap()
        .accounts
        .node
        .unwrap();
    node.db
        .execute("DELETE FROM archive_nodes WHERE id=?", [missing.as_slice()])
        .unwrap();
    assert_eq!(
        node.read_active().unwrap_err().kind(),
        ErrorKind::LocalStructure
    );
    assert!(node
        .authenticated_account_multiproof(genesis, &[public(0)])
        .is_err());
    drop(node);
    assert!(Node::open_with_authenticated_state(&native_path, settings(), 1).is_err());
    let clean_path = dir.path().join("record");
    let node = open(&clean_path, StateBackend::AuthenticatedV1);
    assert_eq!(logical_rows(&node.db), before);
    let mut record = native_authenticated::load(&node.db, genesis).unwrap();
    record.state.account_balance += 1;
    node.db
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            params![canonical(&record).unwrap(), genesis.as_slice()],
        )
        .unwrap();
    assert_eq!(
        node.read_active().unwrap_err().kind(),
        ErrorKind::LocalStructure
    );
    drop(node);
    assert!(Node::open_with_authenticated_state(&clean_path, settings(), 1).is_err());
}

#[test]
fn native_arithmetic_warm_cache_still_reads_external_tampering_and_matches_cold_errors() {
    for action in [
        "DELETE FROM archive_nodes",
        "UPDATE archive_nodes SET data=X'00'",
        "UPDATE native_state_commitments SET data=X'7b7d'",
        "DELETE FROM kv WHERE slot=(SELECT state_slot FROM active WHERE singleton=1)",
        "INSERT INTO kv(slot,key,value) SELECT state_slot,'account:0101010101010101010101010101010101010101010101010101010101010101',X'7b2262616c616e6365223a302c226e6f6e6365223a377d' FROM active WHERE singleton=1",
        "UPDATE kv SET value=CAST(value AS TEXT) WHERE slot=(SELECT state_slot FROM active WHERE singleton=1)",
        "UPDATE blocks SET state_root=zeroblob(32) WHERE id=(SELECT tip FROM active WHERE singleton=1)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
        let packet = make(
            &node,
            node.settings.genesis(),
            vec![transfer(&node.settings, 1, 77)],
        );
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        let expected = node.read_active().unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
        let external = Connection::open(dir.path().join("native.sqlite")).unwrap();
        external.execute_batch(action).unwrap();
        let warm = node.read_active().unwrap_err();
        node.authenticated_arithmetic = native_authenticated::ArithmeticCache::default();
        let cold = node.read_active().unwrap_err();
        assert_eq!(warm.kind(), ErrorKind::LocalStructure, "{action}");
        assert_eq!(warm.kind(), cold.kind(), "{action}");
        assert_eq!(warm.to_string(), cold.to_string(), "{action}");
        assert_eq!(
            warm.requires_owner_stop(),
            cold.requires_owner_stop(),
            "{action}"
        );
    }
}

#[test]
fn native_commit_admission_suppression_rolls_back_all_rows_in_both_backends() {
    for backend in [StateBackend::Legacy, StateBackend::AuthenticatedV1] {
        for table in [
            "blocks",
            "deltas",
            "native_state_commitments",
            "archive_nodes",
        ] {
            if backend == StateBackend::Legacy
                && ["native_state_commitments", "archive_nodes"].contains(&table)
            {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let mut node = open(dir.path(), backend);
            let packet = make(
                &node,
                node.settings.genesis(),
                vec![transfer(&node.settings, 1, 99)],
            );
            let before = logical_rows(&node.db);
            node.db.execute_batch(&format!("CREATE TEMP TRIGGER omit BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(node.admit(&packet, 100_000).is_err(), "{backend:?}/{table}");
            assert_eq!(logical_rows(&node.db), before, "{backend:?}/{table}");
            node.db.execute_batch("DROP TRIGGER omit").unwrap();
            let id = node.admit(&packet, 100_000).unwrap();
            node.activate(id).unwrap();
            assert_eq!(
                node.state_at(id).unwrap()[&format!("account:{}", hex::encode(public(0)))]["nonce"],
                1
            );
        }
    }
}

#[test]
fn native_commit_final_event_triggers_cannot_publish_bad_state_or_rewind_pointer() {
    for backend in [StateBackend::Legacy, StateBackend::AuthenticatedV1] {
        for slow in [false, true] {
            for action in [
                "DELETE FROM kv WHERE slot=(SELECT state_slot FROM active WHERE singleton=1)",
                "UPDATE active SET tip=(SELECT parent FROM blocks WHERE id=NEW.block),generation=NEW.generation-1 WHERE singleton=1",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mut node = open(dir.path(), backend);
                let packet = make(&node, node.settings.genesis(), vec![transfer(&node.settings, 1, 90)]);
                let id = node.admit(&packet, 100_000).unwrap();
                let initial = node.read_active().unwrap();
                let before = RefCell::new(logical_rows(&node.db));
                let observer = Connection::open(dir.path().join("native.sqlite")).unwrap();
                node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage AFTER INSERT ON events BEGIN {action}; END;")).unwrap();
                let result = if slow {
                    let mut hook = |point: &str| { if point == "before-publish" { *before.borrow_mut() = logical_rows(&observer); } Ok(()) };
                    node.activate_with_fault(id, Some(&mut hook))
                } else { node.activate(id) };
                assert!(result.is_err(), "{backend:?}/{slow}/{action}");
                assert_eq!(logical_rows(&node.db), *before.borrow(), "{backend:?}/{slow}/{action}");
                assert_eq!(node.read_active().unwrap(), initial);
                node.db.execute_batch("DROP TRIGGER damage").unwrap();
                assert_eq!(node.recover().unwrap(), id);
                assert_eq!(node.read_active().unwrap().0, id);
            }
        }
    }
}

#[test]
fn native_authenticated_final_write_checks_parent_and_required_nodes() {
    for action in [
        "DELETE FROM native_state_commitments WHERE block=(SELECT parent FROM blocks WHERE id=NEW.block)",
        "DELETE FROM archive_nodes",
        "DELETE FROM snapshots",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
        let packet = make(&node, node.settings.genesis(), vec![transfer(&node.settings, 1, 88)]);
        let before = logical_rows(&node.db);
        node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage AFTER INSERT ON native_state_commitments BEGIN {action}; END;")).unwrap();
        assert!(node.admit(&packet, 100_000).is_err());
        assert_eq!(logical_rows(&node.db), before);
        assert_eq!(node.read_active().unwrap().0, node.settings.genesis());
    }
}

#[test]
fn native_authenticated_cancellation_rolls_back_all_persistent_components() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
    let packet = make(
        &node,
        node.settings.genesis(),
        vec![transfer(&node.settings, 1, 77)],
    );
    let before = logical_rows(&node.db);
    let checked = WorkCheckedPacket::verify(packet.clone()).unwrap();
    let error = node
        .admit_work_checked_with_progress(checked, 100_000, &|point| {
            if matches!(point, ExecutionProgress::BeforeDurableCommit) {
                Err("PEER_POLL_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(logical_rows(&node.db), before);
    let calls = AtomicUsize::new(0);
    node.admit_work_checked_with_progress(
        WorkCheckedPacket::verify(packet).unwrap(),
        100_000,
        &|point| {
            if matches!(point, ExecutionProgress::BeforeDurableCommit) {
                calls.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(calls.load(Ordering::Relaxed) > 1);
}

#[test]
fn native_authenticated_abort_child_before_commit() {
    let Ok(directory) = std::env::var("TRNM_NATIVE_AUTH_ABORT_DIRECTORY") else {
        return;
    };
    let target: usize = std::env::var("TRNM_NATIVE_AUTH_ABORT_FENCE")
        .unwrap()
        .parse()
        .unwrap();
    let mut node = open(Path::new(&directory), StateBackend::AuthenticatedV1);
    let packet = make(
        &node,
        node.settings.genesis(),
        vec![transfer(&node.settings, 1, 76)],
    );
    let calls = AtomicUsize::new(0);
    node.admit_work_checked_with_progress(
        WorkCheckedPacket::verify(packet).unwrap(),
        100_000,
        &|point| {
            if matches!(point, ExecutionProgress::BeforeDurableCommit)
                && calls.fetch_add(1, Ordering::Relaxed) + 1 == target
            {
                std::process::exit(89);
            }
            Ok(())
        },
    )
    .unwrap();
    panic!("requested final pre-commit process exit did not execute");
}

#[test]
fn native_authenticated_process_exit_before_commit_cold_recovers_without_destructors() {
    let dir = tempfile::tempdir().unwrap();
    let mut control = open(&dir.path().join("control"), StateBackend::AuthenticatedV1);
    let packet = make(
        &control,
        control.settings.genesis(),
        vec![transfer(&control.settings, 1, 76)],
    );
    let calls = AtomicUsize::new(0);
    control
        .admit_work_checked_with_progress(
            WorkCheckedPacket::verify(packet).unwrap(),
            100_000,
            &|point| {
                if matches!(point, ExecutionProgress::BeforeDurableCommit) {
                    calls.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            },
        )
        .unwrap();
    let path = dir.path().join("crash");
    let node = open(&path, StateBackend::AuthenticatedV1);
    let before = logical_rows(&node.db);
    drop(node);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("store::native_authenticated_tests::native_authenticated_abort_child_before_commit")
        .arg("--nocapture")
        .env("TRNM_NATIVE_AUTH_ABORT_DIRECTORY", &path)
        .env(
            "TRNM_NATIVE_AUTH_ABORT_FENCE",
            calls.load(Ordering::Relaxed).to_string(),
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(89),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let node = open(&path, StateBackend::AuthenticatedV1);
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(node.active().unwrap(), (node.settings.genesis(), 0));
}

#[test]
fn native_authenticated_signed_qualified_output_is_in_final_commitment() {
    use trnm_crypto_primitives::qualified_work_task::verify_development_admission;
    use trnm_protocol::qualified_work_task::TaskPurpose;
    let dir = tempfile::tempdir().unwrap();
    let settings =
        Settings::development_with_profiles(Some(1), "legacy-first-two-v3", SIGNED_TASK_PROFILE)
            .unwrap();
    let bootstrap = settings.bootstrap_task_statement().unwrap();
    let (bootstrap_model, bootstrap_input, _, _) = settings.bootstrap_task_material().unwrap();
    let model: Vec<u8> = (0..4096u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let signed = settings
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &model,
            &input,
            1,
            100,
            2,
        )
        .unwrap();
    let mut node = Node::open_with_authenticated_state(dir.path(), settings.clone(), 1).unwrap();
    let mut parent = settings.genesis();
    let key = format!("work-output:{}", hex::encode(signed.manifest.output_meter));
    for height in 1..=3 {
        let (statement, model, input) = if height == 1 {
            (&bootstrap, &bootstrap_model, &bootstrap_input)
        } else {
            (&signed, &model, &input)
        };
        let (a, b) = derive_matrices(model, input).unwrap();
        let context = settings
            .qualified_task_context(statement.manifest.demand_id, height)
            .unwrap();
        let permit = verify_development_admission(
            &statement.encode().unwrap(),
            TaskMaterial {
                model,
                input,
                a: &a,
                b: &b,
            },
            &context,
        )
        .unwrap();
        let txs = if height == 1 {
            vec![transaction(&settings, 0, 1, 13, signed.encode().unwrap())]
        } else {
            Vec::new()
        };
        let packet = node
            .make_with_task(
                parent,
                txs,
                public(3),
                1 + height * 10,
                4096,
                &permit,
                TaskMaterial {
                    model,
                    input,
                    a: &a,
                    b: &b,
                },
            )
            .unwrap();
        let before = node.state_at(parent).unwrap();
        let m06 = trnm_mvcc_fee::pon_executor::execute(
            &before,
            &packet.transactions,
            height,
            packet.header.miner,
            parent,
            1,
            &settings.app,
        )
        .unwrap();
        parent = node.admit(&packet, 100_000).unwrap();
        node.activate(parent).unwrap();
        let state = node.read_active().unwrap().2;
        if height == 2 {
            assert!(!m06.state.contains_key(&key));
            assert!(state.contains_key(&key));
            assert_ne!(m06.root, packet.header.state);
        }
        if height >= 2 {
            assert_eq!(state[&key]["arithmetic_output_count"], 1);
        }
        let record = native_authenticated::load(&node.db, parent).unwrap();
        assert_eq!(record.state.state_root, root(&state).unwrap());
        native_authenticated::verify_state(&node.db, &settings, parent, &state, &mut || Ok(()))
            .unwrap();
    }
    let final_state = node.read_active().unwrap();
    drop(node);
    let node = Node::open_with_authenticated_state(dir.path(), settings, 1).unwrap();
    assert_eq!(node.read_active().unwrap(), final_state);
}

// Actual signed state growth through ordinary admission, not synthetic KV seeding.
fn parent_with_full_transaction_block(node: &mut Node) -> Hash {
    let txs = (1..=256)
        .map(|nonce| transfer(&node.settings, nonce, 100 + nonce))
        .collect();
    let packet = make(node, node.settings.genesis(), txs);
    let id = node.admit(&packet, 100_000).unwrap();
    node.activate(id).unwrap();
    assert!(node.read_active().unwrap().2.len() > 256);
    id
}

#[test]
fn native_successor_material_avoids_cold_readback_but_checks_all_actual_state() {
    use trnm_mvcc_fee::pon_commitment::CommitmentMethod;
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path(), StateBackend::AuthenticatedV1);
    let parent = parent_with_full_transaction_block(&mut node);
    let packet = make(&node, parent, vec![transfer(&node.settings, 257, 900)]);
    node.historical_commitment_cache.borrow_mut().clear();
    let id = node.admit(&packet, 100_000).unwrap();
    let readback = node.derived_commitment_status().last.unwrap();
    assert_eq!(readback.method, CommitmentMethod::CheckedApply);
    assert_eq!(readback.changed_keys, 0);
    let expected = node.state_at(id).unwrap();
    assert!(expected.len() > 256);
    node.historical_commitment_cache.borrow_mut().clear();
    assert_eq!(node.state_at(id).unwrap(), expected);
    let cold = node.derived_commitment_status().last.unwrap();
    assert_eq!(cold.method, CommitmentMethod::RebuiltTree);
    // With no predecessor, the rebuilt tree has no relative change-set count.
    // Its actual input count still proves that the complete State was checked.
    assert_eq!(cold.actual_keys, expected.len());
    assert_eq!(readback.actual_keys, expected.len());
    assert_eq!(root(&expected).unwrap(), packet.header.state);

    let external = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let raw = canonical(&expected).unwrap();
    let mut damaged = expected.clone();
    damaged.insert("actual-post-execution-state".into(), json!(1));
    external
        .execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![canonical(&damaged).unwrap(), id.as_slice()],
        )
        .unwrap();
    let warm = node.state_at(id).unwrap_err();
    node.historical_commitment_cache.borrow_mut().clear();
    let cold = node.state_at(id).unwrap_err();
    assert_eq!(warm.to_string(), "ROOT");
    assert_eq!(warm.to_string(), cold.to_string());
    assert_eq!(warm.kind(), cold.kind());
    assert!(warm.requires_owner_stop());
    external
        .execute(
            "UPDATE snapshots SET state=? WHERE block=?",
            params![raw, id.as_slice()],
        )
        .unwrap();
    assert_eq!(node.state_at(id).unwrap(), expected);
    node.activate(id).unwrap();
    let active = node.read_active().unwrap();
    drop(node);
    let node = open(directory.path(), StateBackend::AuthenticatedV1);
    assert_eq!(node.read_active().unwrap(), active);
}

#[test]
fn native_inactive_page_parents_use_checked_material_without_early_activation() {
    let directory = tempfile::tempdir().unwrap();
    let mut source = open(
        &directory.path().join("source"),
        StateBackend::AuthenticatedV1,
    );
    let client_path = directory.path().join("client");
    let mut client = open(&client_path, StateBackend::AuthenticatedV1);
    let seed = parent_with_full_transaction_block(&mut source);
    client
        .admit(&source.packet(seed).unwrap(), 100_000)
        .unwrap();
    client.activate(seed).unwrap();
    let mut packets = Vec::new();
    let mut tip = seed;
    for step in 0..7 {
        let packet = make(
            &source,
            tip,
            vec![transfer(&source.settings, 257 + step, 900 + step)],
        );
        tip = source.admit(&packet, 100_000).unwrap();
        source.activate(tip).unwrap();
        packets.push(packet);
    }
    let before = client.native_history_arithmetic_observation();
    let mut after = seed;
    for (index, packet) in packets.iter().enumerate() {
        let next = packet.id().unwrap();
        let page = crate::ingress::Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(client.settings.network()),
            parameters: hex::encode(client.settings.parameters()),
            genesis: hex::encode(client.settings.genesis()),
            tip: hex::encode(tip),
            after: hex::encode(after),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(next),
            complete: index == 6,
        };
        let started = std::time::Instant::now();
        let result = crate::ingress::receive_page(&mut client, page, tip, after, 100_000);
        println!(
            "{}",
            serde_json::json!({
                "schema": "history-original-honest-page-observation-v1",
                "request_index": index, "requested_packets": 1,
                "original_page_budget_seconds": 30,
                "elapsed_ns": started.elapsed().as_nanos(),
                "result": result.as_ref().map(hex::encode).map_err(ToString::to_string),
                "cpu_flow": client.remote_history_cpu_domain().unwrap().observe_actual_flow().unwrap(),
                "active_tip": hex::encode(client.active().unwrap().0),
            })
        );
        after = result.unwrap();
        assert_eq!(after, next);
        assert_eq!(
            client.active().unwrap().0,
            if index == 6 { tip } else { seed }
        );
    }
    let observed = client.native_history_arithmetic_observation();
    let count = |value: &serde_json::Value, key: &str| value["counters"][key].as_u64().unwrap();
    assert_eq!(
        count(&observed, "execution_parent_historical_candidates")
            - count(&before, "execution_parent_historical_candidates"),
        6
    );
    assert_eq!(
        count(&observed, "execution_parent_checked_apply")
            - count(&before, "execution_parent_checked_apply"),
        7
    );
    assert_eq!(
        count(&observed, "execution_parent_rebuilt_tree"),
        count(&before, "execution_parent_rebuilt_tree")
    );
    let confirmation = client
        .confirmation(
            hash(b"tx-id", &[&packets[0].transactions[0]]),
            packets[0].id().unwrap(),
            100_000,
        )
        .unwrap();
    assert!(confirmation.confirmed);
    assert_eq!(confirmation.depth, Some(6));
    assert!(!confirmation.finalized && !confirmation.execution_authority);
    let expected = client.read_active().unwrap();
    let reference = source.read_active().unwrap();
    assert_eq!(expected.0, reference.0);
    assert_eq!(expected.2, reference.2);
    // Generations count local activation operations: one final page activation
    // intentionally differs from the producer's seven individual activations.
    assert_eq!(expected.1, 2);
    assert_eq!(reference.1, 8);
    drop(client);
    let client = open(&client_path, StateBackend::AuthenticatedV1);
    assert_eq!(client.read_active().unwrap(), expected);
}

#[test]
fn native_inactive_parent_material_keeps_fresh_sql_state_and_cancellation_checks() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path(), StateBackend::AuthenticatedV1);
    let packet = make(
        &node,
        node.settings.genesis(),
        vec![transfer(&node.settings, 1, 77)],
    );
    let parent = node.admit(&packet, 100_000).unwrap();
    assert_eq!(node.active().unwrap().0, node.settings.genesis());
    let next = make(&node, parent, vec![transfer(&node.settings, 2, 78)]);
    let actual = node.state_at(parent).unwrap();
    let execute = |node: &Node, actual: &State| {
        node.execute_derived(
            actual,
            parent,
            &next.transactions,
            next.header.height,
            next.header.timestamp,
            public(7),
            1,
        )
    };
    let expected = execute(&node, &actual).unwrap().output.root;
    assert_eq!(expected, next.header.state);
    // Unrelated opaque material is an index miss, not a reason to reject valid
    // supplied bytes or return the unrelated state. Full binding still succeeds.
    let unrelated =
        pon_commitment::derive_snapshot(&node.settings.initial, None, CacheLimits::default())
            .unwrap();
    node.historical_commitment_cache
        .borrow_mut()
        .retain(parent, unrelated.snapshot.as_ref());
    assert_eq!(execute(&node, &actual).unwrap().output.root, expected);
    node.state_at(parent).unwrap();
    let mut changed = actual.clone();
    changed.insert("actual-inactive-parent-extra".into(), json!(1));
    let warm = execute(&node, &changed).unwrap_err();
    node.historical_commitment_cache.borrow_mut().clear();
    let cold = execute(&node, &changed).unwrap_err();
    assert_eq!(warm.to_string(), "ROOT");
    assert_eq!(warm.to_string(), cold.to_string());
    assert_eq!(warm.kind(), cold.kind());
    assert!(warm.requires_owner_stop());

    let external = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let original_root = node.record(parent).unwrap().root;
    for storage_class in ["zeroblob(32)", "CAST(zeroblob(32) AS TEXT)"] {
        node.state_at(parent).unwrap();
        external
            .execute(
                &format!("UPDATE blocks SET state_root={storage_class} WHERE id=?"),
                [parent.as_slice()],
            )
            .unwrap();
        let warm = execute(&node, &actual).unwrap_err();
        node.historical_commitment_cache.borrow_mut().clear();
        let cold = execute(&node, &actual).unwrap_err();
        assert_eq!(warm.to_string(), cold.to_string());
        assert_eq!(warm.kind(), cold.kind());
        assert!(warm.requires_owner_stop());
        external
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                params![original_root.as_slice(), parent.as_slice()],
            )
            .unwrap();
    }
    let account_node = native_authenticated::load(&node.db, parent)
        .unwrap()
        .accounts
        .node
        .unwrap();
    let mut damaged_state = actual.clone();
    damaged_state.insert("externally-added-history-key".into(), json!(1));
    for (table, column, key_column, key, damaged) in [
        ("blocks", "parent", "id", parent, vec![99; 32]),
        (
            "native_state_commitments",
            "data",
            "block",
            parent,
            b"{}".to_vec(),
        ),
        (
            "snapshots",
            "state",
            "block",
            parent,
            canonical(&damaged_state).unwrap(),
        ),
        ("archive_nodes", "data", "id", account_node, vec![0]),
    ] {
        // Ordinary admission must repeat the real historical SQL/graph checks
        // before it can use an execution parent's optional arithmetic.
        node.state_at(parent).unwrap();
        let original: Vec<u8> = external
            .query_row(
                &format!("SELECT {column} FROM {table} WHERE {key_column}=?"),
                [key.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let update = format!("UPDATE {table} SET {column}=? WHERE {key_column}=?");
        external
            .execute(&update, params![damaged, key.as_slice()])
            .unwrap();
        let warm = node.admit(&next, 100_000).unwrap_err();
        node.historical_commitment_cache.borrow_mut().clear();
        node.authenticated_arithmetic = native_authenticated::ArithmeticCache::default();
        let cold = node.admit(&next, 100_000).unwrap_err();
        assert_eq!(warm.to_string(), cold.to_string(), "{table}/{column}");
        assert_eq!(warm.kind(), cold.kind(), "{table}/{column}");
        assert!(warm.requires_owner_stop(), "{table}/{column}");
        external
            .execute(&update, params![original, key.as_slice()])
            .unwrap();
        assert_eq!(node.state_at(parent).unwrap(), actual);
    }
    // Both original parent-binding progress points remain fail-closed while
    // the actual historical material is warm. No durable rows are published.
    let rows = logical_rows(&node.db);
    for cut in [0, 1] {
        node.state_at(parent).unwrap();
        let calls = AtomicUsize::new(0);
        let error = node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(next.clone()).unwrap(),
                100_000,
                &|point| {
                    if point == ExecutionProgress::BeforeParentBinding
                        && calls.fetch_add(1, Ordering::SeqCst) == cut
                    {
                        Err(Error::new(crate::ErrorCode::FrameDeadline))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::FrameDeadline));
        assert!(!error.requires_owner_stop());
        assert_eq!(calls.load(Ordering::SeqCst), cut + 1);
        assert_eq!(logical_rows(&node.db), rows);
    }
    let tip = node.admit(&next, 100_000).unwrap();
    node.activate(tip).unwrap();
    let active = node.read_active().unwrap();
    drop(node);
    assert_eq!(
        open(directory.path(), StateBackend::AuthenticatedV1)
            .read_active()
            .unwrap(),
        active
    );
}

#[test]
fn controlled_parent_reconstruction_preserves_cancellation_and_complete_retry() {
    for backend in [StateBackend::Legacy, StateBackend::AuthenticatedV1] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(dir.path(), backend);
        let parent = parent_with_full_transaction_block(&mut node);
        let packet = make(&node, parent, vec![transfer(&node.settings, 257, 500)]);
        let before = logical_rows(&node.db);
        let mut total = 0;
        assert_eq!(
            node.check_admission_context_with_progress(&packet, 100_000, &mut || {
                total += 1;
                Ok(())
            })
            .unwrap(),
            None
        );
        assert!(
            total > 4,
            "actual multi-row state must reach internal checkpoints"
        );
        for cut in [0, total / 2, total - 1] {
            let mut calls = 0;
            let error = node
                .check_admission_context_with_progress(&packet, 100_000, &mut || {
                    let current = calls;
                    calls += 1;
                    if current == cut {
                        Err(Error::new(crate::ErrorCode::FrameDeadline))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(error.is(crate::ErrorCode::FrameDeadline));
            assert!(!error.requires_owner_stop());
            assert_eq!(calls, cut + 1);
            assert_eq!(logical_rows(&node.db), before);
            assert_eq!(
                node.check_admission_context(&packet, 100_000).unwrap(),
                None
            );
        }
        // A context error still precedes parent observations and cannot be hidden by cancellation.
        let mut wrong_network = packet.clone();
        wrong_network.header.network = [99; 32];
        let mut calls = 0;
        assert_eq!(
            node.check_admission_context_with_progress(&wrong_network, 100_000, &mut || {
                calls += 1;
                Err("MUST_NOT_RUN".into())
            })
            .unwrap_err()
            .to_string(),
            "NETWORK"
        );
        assert_eq!(calls, 0);
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        let after = node.read_active().unwrap();
        drop(node);
        let reopened = open(dir.path(), backend);
        assert_eq!(reopened.read_active().unwrap(), after);
    }
}

#[test]
fn controlled_final_readback_cancels_inside_transaction_without_corruption_or_partial_rows() {
    for backend in [StateBackend::Legacy, StateBackend::AuthenticatedV1] {
        let dir = tempfile::tempdir().unwrap();
        let mut reference = open(&dir.path().join("reference"), backend);
        let mut node = open(&dir.path().join("candidate"), backend);
        let parent = parent_with_full_transaction_block(&mut reference);
        node.admit(&reference.packet(parent).unwrap(), 100_000)
            .unwrap();
        node.activate(parent).unwrap();
        let packet = make(
            &reference,
            parent,
            vec![transfer(&reference.settings, 257, 500)],
        );
        let before = logical_rows(&node.db);
        let commit_calls = AtomicUsize::new(0);
        let id = reference
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(packet.clone()).unwrap(),
                100_000,
                &|point| {
                    if point == ExecutionProgress::BeforeDurableCommit {
                        commit_calls.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )
            .unwrap();
        let total = commit_calls.load(Ordering::SeqCst);
        assert!(
            total > 4,
            "final checked state/row reads must observe cancellation internally"
        );
        for cut in [0, total / 2, total - 1] {
            let calls = AtomicUsize::new(0);
            let error = node
                .admit_work_checked_with_progress(
                    WorkCheckedPacket::verify(packet.clone()).unwrap(),
                    100_000,
                    &|point| {
                        if point == ExecutionProgress::BeforeDurableCommit
                            && calls.fetch_add(1, Ordering::SeqCst) == cut
                        {
                            Err(Error::new(crate::ErrorCode::FrameDeadline))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
            assert!(error.is(crate::ErrorCode::FrameDeadline));
            assert!(!error.requires_owner_stop());
            assert_eq!(calls.load(Ordering::SeqCst), cut + 1);
            assert_eq!(logical_rows(&node.db), before);
            assert!(node.packet(id).is_err());
        }
        assert_eq!(node.admit(&packet, 100_000).unwrap(), id);
        reference.activate(id).unwrap();
        node.activate(id).unwrap();
        assert_eq!(logical_rows(&node.db), logical_rows(&reference.db));
        let after = node.read_active().unwrap();
        drop(node);
        let reopened = open(&dir.path().join("candidate"), backend);
        assert_eq!(reopened.read_active().unwrap(), after);
    }
}

#[test]
fn native_dense_snapshots_retain_64_and_reconstruct_pruned_history() {
    let dir = tempfile::tempdir().unwrap();
    let native_path = dir.path().join("dense");
    let mut node = open(&native_path, StateBackend::AuthenticatedV1);
    let mut reference = open(&dir.path().join("reference"), StateBackend::Legacy);
    let genesis = node.settings.genesis();
    let mut ids = vec![genesis];
    let mut parent = genesis;
    for height in 1..=70 {
        let packet = make(&reference, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        assert_eq!(reference.admit(&packet, 100_000).unwrap(), parent);
        node.activate(parent).unwrap();
        reference.activate(parent).unwrap();
        ids.push(parent);
        let count: u64 = node
            .db
            .query_row(
                "SELECT COUNT(*) FROM snapshots WHERE block!=?",
                [genesis.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, height.min(64));
        let legacy: u64 = reference
            .db
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(legacy, 1);
    }
    let retained: Vec<Vec<u8>> = node.db.prepare("SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block WHERE blocks.height>0 ORDER BY blocks.height,blocks.id").unwrap()
        .query_map([], |row| row.get(0)).unwrap().map(|row| row.unwrap()).collect();
    assert_eq!(
        retained,
        ids[7..].iter().map(|id| id.to_vec()).collect::<Vec<_>>()
    );
    let before = logical_rows(&node.db);
    drop(node);
    let node = open(&native_path, StateBackend::AuthenticatedV1);
    assert_eq!(logical_rows(&node.db), before);
    for index in [0, 1, 6, 7, 35, 69, 70] {
        assert_eq!(
            node.state_at(ids[index]).unwrap(),
            reference.state_at(ids[index]).unwrap()
        );
    }
    let active = node.read_active().unwrap();
    node.db
        .execute("DELETE FROM snapshots WHERE block!=?", [genesis.as_slice()])
        .unwrap();
    for index in [1, 7, 35, 69] {
        assert_eq!(
            node.state_at(ids[index]).unwrap(),
            reference.state_at(ids[index]).unwrap()
        );
    }
    assert_eq!(node.read_active().unwrap(), active);
    native_authenticated::verify_history(&node.db, &node.settings, parent, &mut || Ok(())).unwrap();
}

#[test]
fn native_dense_snapshot_insert_corruption_and_delta_omission_roll_back() {
    for trigger in [
        "CREATE TEMP TRIGGER snapshot_fault BEFORE INSERT ON snapshots BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TEMP TRIGGER snapshot_fault AFTER INSERT ON snapshots BEGIN UPDATE snapshots SET state=X'7b7d' WHERE block=NEW.block; END;",
        "CREATE TEMP TRIGGER snapshot_fault AFTER INSERT ON snapshots BEGIN DELETE FROM deltas WHERE block=NEW.block; END;",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
        let packet = make(&node, node.settings.genesis(), vec![transfer(&node.settings, 1, 811)]);
        let before = logical_rows(&node.db);
        node.db.execute_batch(trigger).unwrap();
        assert!(node.admit(&packet, 100_000).is_err(), "{trigger}");
        assert_eq!(logical_rows(&node.db), before, "{trigger}");
        node.db.execute_batch("DROP TRIGGER snapshot_fault").unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        assert_ne!(id, node.settings.genesis());
    }
}

#[test]
fn native_dense_snapshot_pruning_suppression_preserves_atomic_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
    let mut parent = node.settings.genesis();
    for _ in 0..64 {
        let packet = make(&node, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        node.activate(parent).unwrap();
    }
    let packet = make(&node, parent, vec![]);
    let before = logical_rows(&node.db);
    node.db.execute_batch("CREATE TEMP TRIGGER refuse_prune BEFORE DELETE ON snapshots BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let error = node.admit(&packet, 100_000).unwrap_err();
    assert_eq!(error.to_string(), "SNAPSHOT_LIMIT");
    assert_eq!(error.kind(), ErrorKind::LocalStructure);
    assert_eq!(logical_rows(&node.db), before);
    node.db.execute_batch("DROP TRIGGER refuse_prune").unwrap();
    node.admit(&packet, 100_000).unwrap();
    let count: u64 = node
        .db
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 65);
}

#[test]
fn native_dense_snapshot_cannot_hide_old_delta_damage_from_admission() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path(), StateBackend::AuthenticatedV1);
    let packet = make(
        &node,
        node.settings.genesis(),
        vec![transfer(&node.settings, 1, 812)],
    );
    let first = node.admit(&packet, 100_000).unwrap();
    node.activate(first).unwrap();
    let second = make(&node, first, vec![]);
    let second = node.admit(&second, 100_000).unwrap();
    node.activate(second).unwrap();
    let next = make(&node, second, vec![]);
    let before = logical_rows(&node.db);
    node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage_old_delta AFTER INSERT ON snapshots BEGIN DELETE FROM deltas WHERE block=X'{}'; END;", hex::encode(first))).unwrap();
    assert!(node.admit(&next, 100_000).is_err());
    assert_eq!(logical_rows(&node.db), before);
    node.db
        .execute_batch("DROP TRIGGER damage_old_delta")
        .unwrap();
    node.admit(&next, 100_000).unwrap();
}

#[test]
fn native_dense_snapshot_readback_cost_keeps_full_state_and_unaccelerated_reference() {
    let dir = tempfile::tempdir().unwrap();
    let mut settings = settings();
    for index in 0..1024u64 {
        settings.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(
                    b"dense-snapshot-zero-balance",
                    &[&index.to_le_bytes()]
                ))
            ),
            json!({"balance":0,"nonce":7}),
        );
    }
    settings.genesis = hash(
        b"dense-snapshot-cost-explicit-fixture",
        &[&settings.genesis, &root(&settings.initial).unwrap()],
    );
    let mut node = Node::open_with_authenticated_state(dir.path(), settings, 1).unwrap();
    let mut parent = node.settings.genesis();
    for height in 1..=8 {
        let packet = make(&node, parent, vec![]);
        parent = node.admit(&packet, 100_000).unwrap();
        if height < 8 {
            node.activate(parent).unwrap();
        }
    }
    let logical_before = logical_rows(&node.db);
    let expected = node.state_at(parent).unwrap();
    let mut observations = Vec::new();
    for pair in 0..4 {
        for accelerated in if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let tx = node.db.unchecked_transaction().unwrap();
            if !accelerated {
                tx.execute(
                    "DELETE FROM snapshots WHERE block!=?",
                    [node.settings.genesis().as_slice()],
                )
                .unwrap();
            }
            let mut callbacks = 0usize;
            let start = std::time::Instant::now();
            let state = node
                .state_at_with_progress(parent, &mut || {
                    callbacks += 1;
                    Ok(())
                })
                .unwrap();
            let elapsed_ns = start.elapsed().as_nanos();
            assert_eq!(state, expected);
            observations.push(json!({"pair":pair,"accelerated":accelerated,"height":8,"full_keys":state.len(),"elapsed_ns":elapsed_ns,"callbacks":callbacks}));
            tx.rollback().unwrap();
            assert_eq!(logical_rows(&node.db), logical_before);
        }
    }
    let native_arithmetic = node.native_history_arithmetic_observation();
    let root_arithmetic = &native_arithmetic["complete_root_arithmetic"];
    assert!(
        root_arithmetic["counters"]["material_uses"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        root_arithmetic["counters"]["derived_checked_apply"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(root_arithmetic["has_consensus_authority"], false);
    eprintln!(
        "pon_native_snapshot_readback_cost_v1 {}",
        json!({"scope":"same unmodified state_at implementation with/without optional snapshots; synthetic1024 zero-balance accounts, not full capacity or TPS","observations":observations,
            "native_history_arithmetic":native_arithmetic})
    );
}
