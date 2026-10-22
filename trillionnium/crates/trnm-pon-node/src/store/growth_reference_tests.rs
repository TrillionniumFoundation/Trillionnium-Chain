use super::*;
use crate::{development_public, Error, Node, Packet, Settings};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::growth_profile_v2 as growth;
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn settings() -> Settings {
    Settings::development_with_profiles(Some(1), "native-public-evaluation-dev-v1", growth::PROFILE)
        .unwrap()
}
fn signed(settings: &Settings, sender: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = development_public(recipient).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(sender).unwrap(),
        nonce,
        expiry: 100_000,
        fee_limit: 1_000_000,
        tag: 1,
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
fn make(node: &Node, parent: Hash, height: u64, transactions: Vec<Vec<u8>>) -> Packet {
    node.make_consensus_maintenance(
        parent,
        transactions,
        development_public(0).unwrap(),
        1 + height * 10,
        4096,
    )
    .unwrap()
}
fn mine(node: &mut Node, height: u64, transactions: Vec<Vec<u8>>) -> Hash {
    let packet = make(node, node.active().unwrap().0, height, transactions);
    let id = node.admit(&packet, 100_000).unwrap();
    node.activate(id).unwrap();
    id
}
#[test]
fn native_growth_reference_public_checked_apis_bind_actual_profile_parent() {
    use trnm_mvcc_fee::pon_commitment::{
        self, CacheLimits, CheckedExecutionParent, ExecutionRequest,
    };
    use trnm_mvcc_fee::pon_executor::{ExecutionError, ExecutionSession};
    let directory = tempfile::tempdir().unwrap();
    let cfg = settings();
    let node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    let (parent, _, actual) = node.read_active().unwrap();
    let root = cfg.state_root(&actual).unwrap();
    let request = || ExecutionRequest {
        transactions: &[],
        height: 1,
        miner: development_public(0).unwrap(),
        parent_id: parent,
        workers: 1,
    };
    let plain = pon_commitment::execute_checked(
        &actual,
        root,
        None,
        request(),
        &cfg.app,
        CacheLimits::default(),
    )
    .unwrap();
    let controlled = pon_commitment::execute_checked_with_progress(
        &actual,
        root,
        None,
        request(),
        &cfg.app,
        CacheLimits::default(),
        &|_| Ok::<(), &str>(()),
    )
    .unwrap();
    assert_eq!(plain.output.state, controlled.output.state);
    assert_eq!(
        plain.output.root,
        cfg.state_root(&plain.output.state).unwrap()
    );
    assert!(plain.commitment.snapshot.is_none());
    assert_eq!(
        pon_commitment::execute_checked_with_progress(
            &actual,
            root,
            None,
            request(),
            &cfg.app,
            CacheLimits::default(),
            &|_| Err("cancel"),
        )
        .err(),
        Some(ExecutionError::Cancelled("cancel"))
    );
    let mut wrong = root;
    wrong[0] ^= 1;
    assert_eq!(
        pon_commitment::execute_checked(
            &actual,
            wrong,
            None,
            request(),
            &cfg.app,
            CacheLimits::default(),
        )
        .err(),
        Some("COMMITMENT_ROOT")
    );
    let legacy_root = trnm_mvcc_fee::pon_executor::root(&actual).unwrap();
    let legacy_parent =
        CheckedExecutionParent::bind(&actual, legacy_root, None, CacheLimits::default()).unwrap();
    assert_eq!(
        legacy_parent.execute(request(), &cfg.app).err(),
        Some("GROWTH_REFERENCE_BINDING_REQUIRED")
    );
    assert_eq!(
        ExecutionSession::new(actual.clone(), legacy_root, cfg.app).err(),
        Some("GROWTH_REFERENCE_SESSION_UNSUPPORTED")
    );
    assert_eq!(node.read_active().unwrap().2, actual);
}
#[test]
fn native_growth_reference_signed_zero_reentry_and_cold_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("growth");
    let cfg = settings();
    let old = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    assert_ne!(cfg.network(), old.network());
    assert_ne!(cfg.parameters(), old.parameters());
    assert_ne!(cfg.genesis(), old.genesis());
    let mut node = Node::open(&path, cfg.clone(), 2).unwrap();
    let initial = node.read_active().unwrap();
    let raw = signed(&cfg, 0, 1, 4, 1000);
    let fee = cfg.app.fees[1] + raw.len() as u64 * cfg.limit("byte_fee_units").unwrap();
    mine(&mut node, 1, vec![raw]);
    mine(&mut node, 2, vec![signed(&cfg, 4, 1, 0, 1000 - fee)]);
    let key = format!("account:{}", hex::encode(development_public(4).unwrap()));
    assert_eq!(
        node.read_active().unwrap().2[&key],
        serde_json::json!({"balance":0,"nonce":1})
    );
    mine(&mut node, 3, vec![signed(&cfg, 0, 2, 4, 1)]);
    let view = node.read_active().unwrap();
    assert_eq!(view.2[&key]["nonce"], 1);
    assert_eq!(
        node.make_consensus_maintenance(
            view.0,
            vec![signed(&cfg, 4, 1, 0, 1)],
            development_public(0).unwrap(),
            41,
            4096
        )
        .unwrap_err()
        .to_string(),
        "NONCE"
    );
    let observed = node.growth_reference_observation().unwrap();
    assert_eq!(observed.permanent_accounts, 5);
    assert!(!observed.bounded_witness_qualified);
    assert!(observed.complete_state_required);
    assert!(node.derived_commitment_status().cache_root.is_none());
    drop(node);
    assert!(Node::open(&path, old, 1).is_err());
    let node = Node::open(&path, cfg.clone(), 1).unwrap();
    assert_eq!(node.read_active().unwrap(), view);
    assert_eq!(node.growth_reference_observation().unwrap(), observed);
    let wrong_backend = directory.path().join("wrong-backend");
    assert_eq!(
        Node::open_with_authenticated_state(&wrong_backend, cfg, 1)
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_REFERENCE_BACKEND"
    );
    assert!(!wrong_backend.exists());
    assert_eq!(initial.2.len() + 4, view.2.len());
}
#[test]
fn native_growth_reference_reorganization_cut_and_corruption_fail_stop() {
    let directory = tempfile::tempdir().unwrap();
    let cfg = settings();
    let mut node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    let genesis = node.active().unwrap().0;
    mine(&mut node, 1, vec![signed(&cfg, 0, 1, 4, 7)]);
    let fork = make(&node, genesis, 1, vec![signed(&cfg, 0, 1, 5, 9)]);
    let branch = node.admit(&fork, 100_000).unwrap();
    let child = make(&node, branch, 2, vec![]);
    let target = node.admit(&child, 100_000).unwrap();
    let error = node
        .activate_with_fault(
            target,
            Some(&mut |stage| {
                if stage.starts_with("attach:") {
                    Err(Error::from("GROWTH_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "GROWTH_CUT");
    drop(node);
    let node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, target);
    let state = node.read_active().unwrap().2;
    let commitment = growth::commitment(&state, &cfg.app).unwrap();
    assert_eq!(cfg.state_root(&state).unwrap(), commitment.id());
    let account_values = crate::account_archive_prototype::accounts(&state).unwrap();
    assert_eq!(
        commitment.account_root,
        crate::account_archive_prototype::account_root(&account_values).unwrap()
    );
    drop(node);
    let db = rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
    db.execute("UPDATE kv SET value=? WHERE key=? AND slot=(SELECT state_slot FROM active WHERE singleton=1)",rusqlite::params![br#"{"balance":9,"nonce":9}"#.as_slice(),format!("account:{}",hex::encode(development_public(5).unwrap()))]).unwrap();
    drop(db);
    assert!(Node::open(directory.path(), cfg, 1).is_err());
}

/// Full ordinary-genesis signed account creation; no seeded archive/State.
#[test]
#[ignore = "explicit release native-growth ordinary-genesis 65,537 signed-account gate"]
fn native_growth_reference_65537_signed_accounts_and_cold_reopen() {
    assert!(
        std::hint::black_box(!cfg!(debug_assertions)),
        "select --release for the real growth campaign"
    );
    let directory = tempfile::tempdir().unwrap();
    let cfg = settings();
    let mut node = Node::open(directory.path(), cfg.clone(), 2).unwrap();
    let mut recipient = 4u64;
    let mut nonces = [0u64; 4];
    let mut height = 0u64;
    // Stop at exactly 65,536 permanent accounts, then cross with one more
    // actual signed transfer. Every preceding account is also transaction-made.
    while recipient < 65_536 {
        let mut txs = Vec::new();
        for _ in 0..256 {
            if recipient == 65_536 {
                break;
            }
            let sender = recipient % 4;
            nonces[sender as usize] += 1;
            txs.push(signed(&cfg, sender, nonces[sender as usize], recipient, 1));
            recipient += 1;
        }
        height += 1;
        mine(&mut node, height, txs);
        if height.is_multiple_of(16) || recipient == 65_536 {
            let actual_accounts:u64=node.db.query_row("SELECT COUNT(*) FROM kv WHERE slot=(SELECT state_slot FROM active WHERE singleton=1) AND key LIKE 'account:%'",[],|row|row.get(0)).unwrap();
            eprintln!(
                "native-growth-progress {}",
                serde_json::json!({"height":height,"active_accounts":actual_accounts,"tip":hex::encode(node.active().unwrap().0)})
            );
        }
    }
    let boundary_parent = node.read_active().unwrap();
    let parent_observation = node.growth_reference_observation().unwrap();
    assert_eq!(parent_observation.permanent_accounts, 65_536);
    nonces[0] += 1;
    height += 1;
    let last = make(
        &node,
        boundary_parent.0,
        height,
        vec![signed(&cfg, 0, nonces[0], 65_536, 1)],
    );
    let target = node.admit(&last, 100_000).unwrap();
    let expected = node.state_at(target).unwrap();
    assert_eq!(
        growth::commitment(&expected, &cfg.app)
            .unwrap()
            .account_count,
        65_537
    );
    let interrupted = node
        .activate_with_fault(
            target,
            Some(&mut |stage| {
                if stage == "before-publish" {
                    Err(Error::from("GROWTH_BOUNDARY_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(interrupted.to_string(), "GROWTH_BOUNDARY_CUT");
    assert_eq!(
        node.active().unwrap(),
        (boundary_parent.0, boundary_parent.1)
    );
    drop(node);
    let node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    assert_eq!(before.0, target);
    assert_eq!(before.1, boundary_parent.1 + 1);
    assert_eq!(before.2, expected);
    let observed = node.growth_reference_observation().unwrap();
    assert_eq!(observed.permanent_accounts, 65_537);
    assert!(observed.working_keys <= growth::MAX_WORKING_KEYS as u64);
    assert_eq!(trnm_mvcc_fee::pon_executor::root(&before.2), Err("LIMIT"));
    let old = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    assert_eq!(old.state_root(&before.2).unwrap_err().to_string(), "LIMIT");
    assert_eq!(
        cfg.state_root(&before.2).unwrap(),
        growth::commitment(&before.2, &cfg.app).unwrap().id()
    );
    for sender in 0..4 {
        assert_eq!(
            node.next_nonce(development_public(sender).unwrap())
                .unwrap(),
            nonces[sender as usize] + 1
        );
    }
    drop(node);
    let node = Node::open(directory.path(), cfg, 1).unwrap();
    let recovered = node.read_active().unwrap();
    assert_eq!(recovered, before);
    assert_eq!(node.growth_reference_observation().unwrap(), observed);
    let monetary = growth::commitment(&recovered.2, &node.settings.app).unwrap();
    let metadata_schema: Vec<u8> = node
        .db
        .query_row("SELECT value FROM metadata WHERE key='schema'", [], |row| {
            row.get(0)
        })
        .unwrap();
    let git = |args: &[&str]| {
        let value = std::process::Command::new("git")
            .arg("-C")
            .arg(env!("CARGO_MANIFEST_DIR"))
            .args(args)
            .output()
            .unwrap();
        assert!(value.status.success());
        String::from_utf8(value.stdout).unwrap().trim().to_owned()
    };
    let receipt = serde_json::json!({
        "schema":"pon-native-growth-reference-readback-v2",
        "git_head_at_execution":git(&["rev-parse","HEAD"]),"git_tree_at_execution":git(&["rev-parse","HEAD^{tree}"]),
        "git_reported_clean_at_execution":git(&["status","--porcelain"]).is_empty(),
        "state_backend":"growth-complete-state-reference-v2","storage_schema":hex::encode(metadata_schema),
        "context":{"network":hex::encode(node.settings.network()),"parameters":hex::encode(node.settings.parameters()),"genesis":hex::encode(node.settings.genesis())},
        "initial_accounts":4,"created_by_signed_transfers":65_533,"active_permanent_accounts":65_537,
        "blocks":height,"before_reopen":{"tip":hex::encode(before.0),"generation":before.1,"state_root":hex::encode(node.settings.state_root(&before.2).unwrap())},
        "after_reopen":{"tip":hex::encode(recovered.0),"generation":recovered.1,"state_root":hex::encode(node.settings.state_root(&recovered.2).unwrap())},
        "boundary_fault":{"stage":"before-publish","scope":"cooperative interruption and cold recovery; not physical power loss",
            "parent_tip":hex::encode(boundary_parent.0),"parent_generation":boundary_parent.1,"parent_permanent_accounts":65_536,
            "parent_state_root":hex::encode(node.settings.state_root(&boundary_parent.2).unwrap()),
            "recovered_target":hex::encode(target),"recovered_generation":before.1,"recovered_permanent_accounts":65_537},
        "commitment":monetary,"encoded_commitment":hex::encode(monetary.encode()),"sender_nonces":nonces,
        "observation":observed,"bounded_witness_qualified":false,"production_activation":false,
        "database":"store/native.sqlite","scope":"ordinary four-account genesis; actual signed native admission and cold reopen; complete-State development reference"
    });
    assert_eq!(receipt["git_reported_clean_at_execution"], true);
    eprintln!("native-growth-reference {}", receipt);
    drop(node);
    if let Some(export) = std::env::var_os("TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY") {
        use std::os::unix::fs::PermissionsExt;
        let export = std::path::PathBuf::from(export);
        assert!(export.is_absolute() && !export.exists());
        let parent = export.parent().unwrap();
        assert_eq!(parent.canonicalize().unwrap(), parent);
        std::fs::create_dir(&export).unwrap();
        std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = directory.keep();
        std::fs::rename(&retained, export.join("store")).unwrap();
        std::fs::write(
            export.join("native.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }
}
