//! Fresh operator profile tests use explicitly disclosed deterministic test keys;
//! they do not certify real-world key generation, custody, governance or usefulness.
#[path = "support/operator_fixture.rs"]
mod fixture;
use fixture::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};
use trnm_mvcc_fee::{deployment_actors, pon_executor::Config};
use trnm_pon_node::{
    operator_deployment::{self as actors, offline},
    Node, Settings,
};
use trnm_protocol::pon_wire::hash;
#[test]
fn public_only_bootstrap_two_owners_reopen_exact_context_and_no_fixture_funding() {
    let (spec, bundle, m, i, s) = fixture();
    let d = tempfile::tempdir().unwrap();
    let n = Node::open(&d.path().join("a"), s.clone(), 2).unwrap();
    let s2 = Settings::development_with_operator_actors(&spec, &bundle, &m, &i).unwrap();
    let n2 = Node::open(&d.path().join("b"), s2.clone(), 1).unwrap();
    assert_eq!(
        n.state_at(s.genesis()).unwrap(),
        n2.state_at(s2.genesis()).unwrap()
    );
    assert_eq!(s.operator_actor_profile(), Some(actors::PROFILE));
    assert!(!n.state_at(s.genesis()).unwrap().contains_key(&format!(
        "account:{}",
        hex::encode(trnm_pon_node::development_public(0).unwrap())
    )));
    assert_eq!(n.settings().bootstrap_task_material().unwrap().0, m);
    assert_eq!(n.settings().bootstrap_task_material().unwrap().1, i);
    assert!(s
        .development_task_manifest(
            0,
            trnm_protocol::qualified_work_task::TaskPurpose::Maintenance,
            &m,
            &i,
            0,
            1000,
            1
        )
        .is_err());
    let g = s.genesis();
    drop(n);
    assert_eq!(
        Node::open(&d.path().join("a"), s, 1)
            .unwrap()
            .active()
            .unwrap(),
        (g, 0)
    );
}
#[test]
fn descriptor_canonical_bounds_and_false_acceptance_are_required() {
    let (spec, _, _, _, _) = fixture();
    let raw = spec.canonical().unwrap();
    assert_eq!(
        deployment_actors::OperatorDeploymentSpec::decode(&raw).unwrap(),
        spec
    );
    let body = String::from_utf8(raw.clone()).unwrap();
    let duplicate = format!("{{\"profile\":\"{}\",{}", actors::PROFILE, &body[1..]);
    assert_eq!(
        deployment_actors::OperatorDeploymentSpec::decode(duplicate.as_bytes()).unwrap_err(),
        "ACTOR_ENCODING"
    );
    for flag in [
        "production_activation",
        "public_network_ready",
        "independent_governance_accepted",
        "hardness_accepted",
        "demand_truth_accepted",
        "objective_model_quality",
    ] {
        let mut v = serde_json::to_value(&spec).unwrap();
        v[flag] = serde_json::json!(true);
        assert_eq!(
            deployment_actors::OperatorDeploymentSpec::decode(&actors::canonical(&v).unwrap())
                .unwrap_err(),
            "ACTOR_ACCEPTANCE"
        );
    }
    let mut value = serde_json::to_value(&spec).unwrap();
    value["hardness_accepted"] = serde_json::json!(true);
    assert!(
        deployment_actors::OperatorDeploymentSpec::decode(&actors::canonical(&value).unwrap())
            .is_err()
    );
    value["hardness_accepted"] = serde_json::json!(false);
    value["unexpected"] = serde_json::json!(0);
    assert!(
        deployment_actors::OperatorDeploymentSpec::decode(&actors::canonical(&value).unwrap())
            .is_err()
    );
    assert!(deployment_actors::OperatorDeploymentSpec::decode(
        &serde_json::to_vec_pretty(&spec).unwrap()
    )
    .is_err());
    assert!(deployment_actors::OperatorDeploymentSpec::decode(&vec![b' '; 32769]).is_err());
}
#[test]
fn duplicate_unfunded_short_roster_known_fixture_and_overflow_refused() {
    let (s, _, _, _, _) = fixture();
    let mut c = s.clone();
    c.source = hex::encode(trnm_pon_node::development_public(0).unwrap());
    assert_eq!(c.validate().unwrap_err(), "ACTOR_KNOWN_FIXTURE_KEY");
    let mut c = s.clone();
    c.evaluators[1] = c.evaluators[0].clone();
    assert!(c.validate().is_err());
    let mut c = s.clone();
    c.evaluators.truncate(2);
    assert!(c.validate().is_err());
    let mut c = s.clone();
    c.allocations.retain(|a| a.public_key != c.source);
    assert!(c.validate().is_err());
    let mut c = s.clone();
    c.allocations[0].balance = u64::MAX;
    assert!(c.validate().is_err());
    let mut c = s;
    c.source = c.requester.clone();
    assert!(c.validate().is_err());
}
#[test]
fn material_hash_field_encoding_source_and_requester_signatures_fail_closed() {
    let (s, b, m, i, _) = fixture();
    let mut wrong = m.clone();
    wrong[0] ^= 1;
    assert!(Settings::development_with_operator_actors(&s, &b, &wrong, &i).is_err());
    let mut wrong = m.clone();
    wrong[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut c = s.clone();
    c.bootstrap.model = hex::encode(hash(b"artifact", &[&wrong]));
    assert!(actors::prepare(&c, &wrong, &i).is_err());
    let mut c = b.clone();
    c.requester_approval.signature = hex::encode([0; 64]);
    assert!(Settings::development_with_operator_actors(&s, &c, &m, &i).is_err());
    let mut c = b;
    c.signed_statement
        .replace_range(c.signed_statement.len() - 128.., &hex::encode([0; 64]));
    assert!(Settings::development_with_operator_actors(&s, &c, &m, &i).is_err());
}
#[test]
fn fresh_descriptor_changes_context_and_rejects_old_certificate() {
    let (s, b, m, i, old) = fixture();
    for change in 0..8 {
        let mut c = s.clone();
        match change {
            0 => c.deployment_id = hex::encode([61; 32]),
            1 => c.genesis_timestamp += 1,
            2 => c.allocations[0].balance += 1,
            3 => c.bootstrap.source_record = hex::encode([62; 32]),
            4 => {
                c.evaluators.push(public(6));
                c.evaluators.sort();
                c.allocations.push(actors::GenesisAllocation {
                    public_key: public(6),
                    balance: 50_000_000,
                });
            }
            5 => c.bootstrap.authorization_scope = hex::encode([63; 32]),
            6 => {
                c.source = public(6);
                c.allocations.push(actors::GenesisAllocation {
                    public_key: public(6),
                    balance: 50_000_000,
                });
            }
            _ => {
                c.requester = public(7);
                c.allocations.push(actors::GenesisAllocation {
                    public_key: public(7),
                    balance: 50_000_000,
                });
            }
        }
        c.allocations
            .sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let new = actors::prepare(&c, &m, &i).unwrap();
        assert_ne!(new.network, hex::encode(old.network()));
        assert_ne!(new.parameters, hex::encode(old.parameters()));
        assert!(Settings::development_with_operator_actors(&c, &b, &m, &i).is_err());
        let source = actors::approval(
            &new,
            "source",
            hex::encode(signature(
                if change == 6 { 6 } else { 0 },
                &hex::decode(&new.source_message).unwrap(),
            )),
        )
        .unwrap();
        let requester = actors::approval(
            &new,
            "requester",
            hex::encode(signature(
                if change == 7 { 7 } else { 1 },
                &hex::decode(&new.requester_message).unwrap(),
            )),
        )
        .unwrap();
        let bundle = actors::assemble(&new, &source, &requester).unwrap();
        let actual = Settings::development_with_operator_actors(&c, &bundle, &m, &i).unwrap();
        assert_ne!(actual.genesis(), old.genesis());
    }
}
#[test]
fn offline_secret_pin_owner_mode_symlink_hardlink_and_template_checks() {
    let (s, _, m, i, _) = fixture();
    let t = actors::prepare(&s, &m, &i).unwrap();
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("source");
    fs::write(&p, secret(0)).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(offline::sign_approval_from_file(&s, &t, &m, &i, "source", &p).is_ok());
    assert!(
        offline::sign_approval_from_file(&s, &t, &m, &i, "requester", &p)
            .unwrap_err()
            .to_string()
            .contains("ACTOR_SIGNER_PIN")
    );
    let mut wrong = t.clone();
    wrong.source_message = hex::encode([1; 32]);
    assert!(offline::sign_approval_from_file(&s, &wrong, &m, &i, "source", &p).is_err());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(offline::sign_approval_from_file(&s, &t, &m, &i, "source", &p).is_err());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    let link = d.path().join("link");
    symlink(&p, &link).unwrap();
    assert!(offline::sign_approval_from_file(&s, &t, &m, &i, "source", &link).is_err());
    let hard = d.path().join("hard");
    fs::hard_link(&p, &hard).unwrap();
    assert!(offline::sign_approval_from_file(&s, &t, &m, &i, "source", &p).is_err());
}
#[test]
fn actual_native_renewal_transfer_parent_binding_reopen_and_heavier_fork() {
    use trnm_protocol::qualified_work_task::lifecycle_v4::AtomicRenewTaskV4;
    let (_, _, m, i, s) = fixture();
    let d = tempfile::tempdir().unwrap();
    let mut n = Node::open(d.path(), s.clone(), 4).unwrap();
    let old = s.bootstrap_lifecycle_task().unwrap();
    let mut lease = old.lease.clone();
    lease.revision = 2;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    let mut signed = old.signed.clone();
    signed.lease_id = lease.id().unwrap();
    signed.manifest.source_record = lease.bound_source_record().unwrap();
    signed.manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    signed.manifest.not_before = 1;
    signed.manifest.expires = 1001;
    signed.manifest.available_until = 1101;
    signed.manifest.demand_nonce = 2;
    signed.signature = signature(0, &signed.signing_message().unwrap());
    let renew = AtomicRenewTaskV4 {
        lease: lease.clone(),
        signed: signed.clone(),
    };
    let tx = transaction(&s, 1, 1, 22, renew.encode().unwrap());
    let tx2 = transfer(&s, 0, 1, 5, 77);
    let p1 = make(
        &n,
        s.genesis(),
        vec![tx, tx2],
        &old.signed,
        &old.lease,
        &m,
        &i,
    );
    let id1 = n.admit(&p1, s.genesis_time() + 10000).unwrap();
    n.activate(id1).unwrap();
    assert_eq!(n.next_nonce(key(1)).unwrap(), 2);
    assert_eq!(n.next_nonce(key(0)).unwrap(), 2);
    let p2 = make(&n, id1, vec![], &signed, &lease, &m, &i);
    let id2 = n.admit(&p2, s.genesis_time() + 10000).unwrap();
    n.activate(id2).unwrap();
    let root = n.stats().unwrap()["state_root"].clone();
    drop(n);
    let mut n = Node::open(d.path(), s.clone(), 1).unwrap();
    assert_eq!(n.active().unwrap(), (id2, 2));
    assert_eq!(n.stats().unwrap()["state_root"], root);
    let mut tip = s.genesis();
    for _ in 0..3 {
        let p = make(&n, tip, vec![], &old.signed, &old.lease, &m, &i);
        tip = n.admit(&p, s.genesis_time() + 10000).unwrap();
    }
    n.activate(tip).unwrap();
    assert_eq!(n.next_nonce(key(1)).unwrap(), 1);
    assert_eq!(n.next_nonce(key(0)).unwrap(), 1);
    assert_eq!(
        n.lifecycle_task_lease(tip, old.signed.manifest.matrix_task, 4)
            .unwrap()
            .revision,
        1
    );
}
#[test]
fn operator_roster_is_used_by_actual_native_evaluation_and_fixture_votes_are_not_authority() {
    use trnm_mvcc_fee::{pon_executor, public_evaluation as evaluation};
    let (spec, _, _, _, s) = fixture();
    let cfg = Config::installed_with_operator_actors(&spec).unwrap();
    assert!(trnm_mvcc_fee::qualified_task_lifecycle::bootstrap_state(
        &cfg,
        &s.bootstrap_task_material().unwrap().0,
        &s.bootstrap_task_material().unwrap().1
    )
    .is_err());
    let d = tempfile::tempdir().unwrap();
    let n = Node::open(d.path(), s.clone(), 2).unwrap();
    let state = n.state_at(s.genesis()).unwrap();
    let cid = hash(
        b"contribution-v3",
        &[
            &key(5),
            &cfg.family,
            &[0; 32],
            &[7; 32],
            &[8; 32],
            &0u64.to_le_bytes(),
        ],
    );
    let mut payload = Vec::new();
    for v in [cid, cfg.family, [0; 32], [7; 32]] {
        payload.extend(v);
    }
    payload.extend(1024u64.to_le_bytes());
    payload.extend([8; 32]);
    payload.extend(0u64.to_le_bytes());
    let out = pon_executor::execute(
        &state,
        &[transaction(&s, 5, 1, 6, payload)],
        1,
        key(5),
        [9; 32],
        2,
        &cfg,
    )
    .unwrap()
    .state;
    let e = &out[&format!("contribution:{}", hex::encode(cid))]["public_evaluation"];
    assert_eq!(e["plan"]["roster"], serde_json::json!(spec.evaluators));
    let round = evaluation::round(e).unwrap();
    // Fund a historical fixture key through an ordinary native transfer, so its
    // failed vote tests the frozen roster rather than an unfunded account shortcut.
    let fixture_key = trnm_pon_node::development_public(0).unwrap();
    let mut funding = fixture_key.to_vec();
    funding.extend(1_000_000u64.to_le_bytes());
    let out = pon_executor::execute(
        &out,
        &[transaction(&s, 0, 1, 1, funding)],
        2,
        key(5),
        [9; 32],
        2,
        &cfg,
    )
    .unwrap()
    .state;
    let mut bad = trnm_protocol::pon_wire::Envelope {
        network: s.network(),
        sender: fixture_key,
        nonce: 1,
        expiry: 128,
        fee_limit: 1_000_000,
        tag: 14,
        payload: vec![],
        signature: [0; 64],
    };
    bad.payload.extend(cid);
    bad.payload.extend(round);
    bad.payload.extend([81; 32]);
    let dev = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&0u64.to_le_bytes()],
    )))
    .unwrap();
    bad.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &dev,
        &bad.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let error = pon_executor::execute(&out, &[bad.encode().unwrap()], 16, key(5), [9; 32], 2, &cfg)
        .unwrap_err();
    assert_eq!(error, "PUBLIC_EVAL_AUTHORITY");
    let mut txs = vec![];
    for who in 2..5 {
        let commitment =
            evaluation::reveal_commitment(round, cid, key(who), cfg.plan, [9; 32], 0, [who; 32]);
        let mut p = cid.to_vec();
        p.extend(round);
        p.extend(commitment);
        txs.push(transaction(&s, who, 1, 14, p));
    }
    let out = pon_executor::execute(&out, &txs, 16, key(5), [9; 32], 4, &cfg)
        .unwrap()
        .state;
    let mut txs = vec![];
    for who in 2..5 {
        let mut p = cid.to_vec();
        p.extend(round);
        p.extend(cfg.plan);
        p.extend([9; 32]);
        p.extend(0u64.to_le_bytes());
        p.extend([who; 32]);
        txs.push(transaction(&s, who, 2, 15, p));
    }
    let out = pon_executor::execute(&out, &txs, 32, key(5), [9; 32], 4, &cfg)
        .unwrap()
        .state;
    let out = pon_executor::execute(&out, &[], 48, key(5), [9; 32], 4, &cfg)
        .unwrap()
        .state;
    assert_eq!(
        out[&format!("contribution:{}", hex::encode(cid))]["score"],
        0
    );
    assert_eq!(
        out[&format!("contribution:{}", hex::encode(cid))]["status"],
        "evaluated"
    );
}
#[test]
fn cli_prepare_offline_sign_finalize_public_status_and_explicit_miner() {
    use std::process::Command;
    let (s, _, m, i, _) = fixture();
    let d = tempfile::tempdir().unwrap();
    let spec = d.path().join("spec.json");
    let model = d.path().join("model");
    let input = d.path().join("input");
    let template = d.path().join("template.json");
    let source = d.path().join("source.json");
    let requester = d.path().join("requester.json");
    let bundle = d.path().join("bundle.json");
    let secretfile = d.path().join("secret");
    for (p, raw) in [
        (&spec, s.canonical().unwrap()),
        (&model, m.clone()),
        (&input, i.clone()),
    ] {
        offline::write_new_public(p, &raw).unwrap();
    }
    let run = |command: &str, extra: Vec<(&str, String)>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
        cmd.arg(command).args([
            "--development",
            "--actor-profile",
            actors::PROFILE,
            "--deployment-spec",
            spec.to_str().unwrap(),
            "--deployment-model",
            model.to_str().unwrap(),
            "--deployment-input",
            input.to_str().unwrap(),
        ]);
        for (k, v) in extra {
            cmd.arg(k).arg(v);
        }
        cmd.output().unwrap()
    };
    let out = run(
        "genesis-prepare",
        vec![("--output", template.display().to_string())],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!secretfile.exists());
    let raw = fs::read(&template).unwrap();
    let t: actors::BootstrapTemplate = actors::decode(&raw).unwrap();
    assert_eq!(t, actors::prepare(&s, &m, &i).unwrap());
    for (role, who, path) in [("source", 0, &source), ("requester", 1, &requester)] {
        fs::write(&secretfile, secret(who)).unwrap();
        fs::set_permissions(&secretfile, fs::Permissions::from_mode(0o600)).unwrap();
        let out = run(
            "genesis-sign",
            vec![
                ("--deployment-template", template.display().to_string()),
                ("--role", role.into()),
                ("--signer-secret", secretfile.display().to_string()),
                ("--output", path.display().to_string()),
            ],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains(&secret(who)));
    }
    let out = run(
        "genesis-finalize",
        vec![
            ("--deployment-template", template.display().to_string()),
            ("--source-approval", source.display().to_string()),
            ("--requester-approval", requester.display().to_string()),
            ("--output", bundle.display().to_string()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_file(&secretfile).unwrap();
    let store = d.path().join("store");
    let out = run(
        "status",
        vec![
            ("--store", store.display().to_string()),
            ("--deployment-bootstrap", bundle.display().to_string()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(
        "make",
        vec![
            ("--store", store.display().to_string()),
            ("--deployment-bootstrap", bundle.display().to_string()),
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ACTOR_EXPLICIT_MINER_REQUIRED"));
    // --task-bootstrap is a flag, so issue the actual command directly here.
    let packet = d.path().join("packet");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.arg("mine").args([
        "--development",
        "--actor-profile",
        actors::PROFILE,
        "--deployment-spec",
        spec.to_str().unwrap(),
        "--deployment-model",
        model.to_str().unwrap(),
        "--deployment-input",
        input.to_str().unwrap(),
        "--deployment-bootstrap",
        bundle.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--miner",
        &public(5),
        "--task-bootstrap",
        "--logical-now",
        "1800010000",
        "--timestamp",
        "1800000010",
        "--output",
        packet.to_str().unwrap(),
    ]);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(packet.exists());
    let b: actors::BootstrapBundle = actors::decode(&fs::read(&bundle).unwrap()).unwrap();
    let settings = Settings::development_with_operator_actors(&s, &b, &m, &i).unwrap();
    assert_eq!(
        Node::open(&store, settings, 1).unwrap().active().unwrap().1,
        1
    );
}
#[test]
fn weak_actor_key_and_cross_context_approval_refused() {
    let (s, _, m, i, _) = fixture();
    let mut weak = [0u8; 32];
    weak[0] = 1;
    assert_eq!(
        deployment_actors::operator_key(&hex::encode(weak)).unwrap_err(),
        "ACTOR_WEAK_KEY"
    );
    let t = actors::prepare(&s, &m, &i).unwrap();
    let mut c = s;
    c.deployment_id = hex::encode([99; 32]);
    let new = actors::prepare(&c, &m, &i).unwrap();
    let a = actors::approval(
        &t,
        "source",
        hex::encode(signature(0, &hex::decode(&t.source_message).unwrap())),
    )
    .unwrap();
    let r = actors::approval(
        &new,
        "requester",
        hex::encode(signature(1, &hex::decode(&new.requester_message).unwrap())),
    )
    .unwrap();
    assert!(actors::assemble(&new, &a, &r).is_err());
}
#[test]
fn manually_proved_bad_nonce_packet_is_rejected_without_durable_state_movement() {
    use trnm_crypto_primitives::pon_work::PreparedTask;
    let (_, _, m, i, s) = fixture();
    let d = tempfile::tempdir().unwrap();
    let mut n = Node::open(d.path(), s.clone(), 2).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let mut p = make(&n, s.genesis(), vec![], &boot.signed, &boot.lease, &m, &i);
    let before = n.state_at(s.genesis()).unwrap();
    p.transactions = vec![transfer(&s, 0, 7, 5, 1)];
    p.header.transactions = trnm_pon_node::sequence_root("transactions", &p.transactions);
    let (_, _, a, b) = s.bootstrap_task_material().unwrap();
    let prepared = PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        p.header.nonce = nonce;
        p.proof = prepared.prove(p.header.challenge()).unwrap();
        if hash(
            b"ticket",
            &[&p.header.challenge(), &p.proof[p.proof.len() - 32..]],
        ) <= p.header.target
        {
            break;
        }
    }
    assert!(trnm_crypto_primitives::pon_work::verify(
        p.header.challenge(),
        p.header.work_task,
        p.header.target,
        &p.proof
    )
    .is_ok());
    let error = n
        .admit(&p, s.genesis_time() + 10000)
        .unwrap_err()
        .to_string();
    assert!(error.contains("NONCE"), "{error}");
    assert_eq!(n.active().unwrap(), (s.genesis(), 0));
    assert_eq!(n.state_at(s.genesis()).unwrap(), before);
    drop(n);
    let n = Node::open(d.path(), s, 1).unwrap();
    assert_eq!(n.active().unwrap().1, 0);
    assert_eq!(n.next_nonce(key(0)).unwrap(), 1);
}
#[test]
fn actual_operator_pool_mining_and_peer_configuration_use_public_context() {
    use std::{
        sync::{atomic::AtomicBool, Arc, Mutex},
        time::Duration,
    };
    use trnm_pon_node::{
        ingress,
        mining::{run_pool_mining, MiningConfig, MiningMaterial},
        peer_polling::{PeerPollingConfig, PinnedPeer},
        PoolLimits,
    };
    let (mut spec, _, m, i, old) = fixture();
    spec.genesis_timestamp = ingress::now().unwrap() - 100;
    let t = actors::prepare(&spec, &m, &i).unwrap();
    let a = actors::approval(
        &t,
        "source",
        hex::encode(signature(0, &hex::decode(&t.source_message).unwrap())),
    )
    .unwrap();
    let r = actors::approval(
        &t,
        "requester",
        hex::encode(signature(1, &hex::decode(&t.requester_message).unwrap())),
    )
    .unwrap();
    let b = actors::assemble(&t, &a, &r).unwrap();
    let s = Settings::development_with_operator_actors(&spec, &b, &m, &i).unwrap();
    let d = tempfile::tempdir().unwrap();
    let mut n = Node::open(d.path(), s.clone(), 2).unwrap();
    let limits = PoolLimits {
        max_records: 16,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: key(5),
    };
    n.enable_local_mempool(limits).unwrap();
    let tx = transfer(&s, 0, 1, 5, 1);
    n.pool_submit(tx.clone()).unwrap();
    let owner = Arc::new(Mutex::new(n));
    let report = run_pool_mining(
        owner.clone(),
        MiningConfig {
            miner: key(5),
            material: MiningMaterial::Registered { model: m, input: i },
            max_transactions: 256,
            max_transaction_bytes: 524288,
            search_attempts: 4096,
            pace: Duration::from_secs(1),
            runtime: Duration::from_secs(4),
            max_blocks: 1,
        },
        Arc::new(AtomicBool::new(false)),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(report.activated_blocks, 1);
    assert_eq!(report.included_transactions, 1);
    assert_eq!(owner.lock().unwrap().next_nonce(key(0)).unwrap(), 2);
    let cfg = PeerPollingConfig {
        schema: "pon-native-pinned-peer-poll-config-v1".into(),
        network: hex::encode(s.network()),
        parameters: hex::encode(s.parameters()),
        genesis: hex::encode(s.genesis()),
        transport_profile: hex::encode(
            ingress::public_v3::PublicPolicy::new(8, Duration::from_secs(2))
                .unwrap()
                .id(),
        ),
        bits: 8,
        lifetime_ms: 2000,
        peers: vec![PinnedPeer {
            address: "127.0.0.1:10001".parse().unwrap(),
            server_public: public(5),
        }],
        poll_interval_ms: 100,
        runtime_ms: 1000,
        max_calls: 10,
        max_pages_per_cycle: 1,
    };
    assert!(cfg.validate(&s).is_ok());
    assert!(cfg.validate(&old).is_err());
}
