//! Synthetic codec controls and explicitly selected original-material replay.
//! All signing keys here are disclosed deterministic TEST keys, never live actors.
#[path = "support/operator_fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    process::Command,
};
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::{derive_checkpoint_tile_material_v1, PinnedTileContextV1},
    checkpoint_tile_policy_v1::{CheckpointTilePolicySpecV1, PROFILE as TASK_PROFILE},
    deployment_checkpoint_tile_v1,
    pon_executor::Config,
    qualified_task_lifecycle::{self, slot_key},
};
use trnm_pon_node::{
    operator_checkpoint_tile::{
        self as tile, CheckpointTileRuntimePaths, OperatorCheckpointTileSpecV1,
    },
    operator_deployment::{self as actors, BootstrapBundle},
    Node, Settings,
};
use trnm_protocol::{
    pon_wire::hash,
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::AtomicRenewTaskV4,
        TaskPurpose,
    },
};
const CLOCK: u64 = 1_800_010_000;
fn sha(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
struct Case {
    dir: tempfile::TempDir,
    spec: OperatorCheckpointTileSpecV1,
    bundle: BootstrapBundle,
    m: Vec<u8>,
    i: Vec<u8>,
    paths: CheckpointTileRuntimePaths,
    s: Settings,
}
fn build(
    m: Vec<u8>,
    i: Vec<u8>,
    checkpoint: PathBuf,
    activation: PathBuf,
    dir: tempfile::TempDir,
) -> Case {
    let cp = fs::read(&checkpoint).unwrap();
    let act = fs::read(&activation).unwrap();
    let mut old = fixture().0;
    old.bootstrap.model = hex::encode(hash(b"artifact", &[&m]));
    old.bootstrap.input = hex::encode(hash(b"qualified-task-input-v1", &[&i]));
    let cfg = Config::installed_with_operator_actors(&old).unwrap();
    let context = PinnedTileContextV1 {
        network: cfg.network,
        parameters: cfg.parameters,
        checkpoint_sha256: sha(&cp),
        checkpoint_bytes: cp.len() as u64,
        activation_sha256: sha(&act),
        model: hash(b"artifact", &[&m]),
        input: hash(b"qualified-task-input-v1", &[&i]),
    };
    let checked =
        derive_checkpoint_tile_material_v1(&mut Cursor::new(&cp), &act, &m, &i, &context, |_| {
            Ok(())
        })
        .unwrap();
    let spec = OperatorCheckpointTileSpecV1 {
        schema: "pon-native-operator-checkpoint-tile-spec-v1".into(),
        profile: tile::PROFILE.into(),
        task_profile: TASK_PROFILE.into(),
        actors: old,
        material_policy: CheckpointTilePolicySpecV1::from_checked(&checked).unwrap(),
    };
    let paths = CheckpointTileRuntimePaths::new(checkpoint, activation);
    let template = tile::prepare(&spec, &m, &i, &paths).unwrap();
    let source = tile::approval(
        &template,
        "source",
        hex::encode(signature(
            0,
            &hex::decode(&template.source_message).unwrap(),
        )),
    )
    .unwrap();
    let requester = tile::approval(
        &template,
        "requester",
        hex::encode(signature(
            1,
            &hex::decode(&template.requester_message).unwrap(),
        )),
    )
    .unwrap();
    let bundle = tile::assemble(&template, &source, &requester).unwrap();
    let s =
        Settings::development_with_operator_checkpoint_tile(&spec, &bundle, &m, &i, paths.clone())
            .unwrap();
    Case {
        dir,
        spec,
        bundle,
        m,
        i,
        paths,
        s,
    }
}
fn synthetic() -> Case {
    let dir = tempfile::tempdir().unwrap();
    let header=serde_json::to_vec(&json!({"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,576],"data_offsets":[0,576*576*2]}})).unwrap();
    let mut cp = (header.len() as u64).to_le_bytes().to_vec();
    cp.extend(header);
    for _ in 0..576 * 576 {
        cp.extend(0x3f80u16.to_le_bytes());
    }
    let m = (0..4096)
        .flat_map(|_| 16384u32.to_le_bytes())
        .collect::<Vec<_>>();
    let i = (0..4096)
        .flat_map(|at| {
            if at % 64 < 2 {
                16u32.to_le_bytes()
            } else {
                0u32.to_le_bytes()
            }
        })
        .collect::<Vec<_>>();
    let act = json!({"schema":"checkpoint-qproj-postnorm-activation-v1","checkpoint_sha256":hex::encode(sha(&cp)),"dtype":"F32LE","shape":[1,2,576],"token_ids":[1,2],"attention_mask":[1,1],"positions":[0,1],"hidden_hex":hex::encode((0..1152).flat_map(|_|1f32.to_bits().to_le_bytes()).collect::<Vec<_>>()),"producer_script_sha256":"01".repeat(32),"prompt_utf8_sha256":"02".repeat(32),"runtime":{"device":"cpu","python":"fixture","torch":"fixture","transformers":"fixture","safetensors":"fixture","numpy":"fixture","threads":2,"base_only":true,"training":false,"local_files_only":true,"trust_remote_code":false,"forward_calls":1,"hook_calls":1,"parameter_count":134515008,"storage_dtype":"float32","material_manifest_sha256":"03".repeat(32)},"activation_origin":"actual-layer0-q_proj-prehook-post-RMSNorm","scope":"observed CPU base-model hook; no independent full-forward proof or source authority"});
    let checkpoint = dir.path().join("model.safetensors");
    let activation = dir.path().join("activation.json");
    fs::write(&checkpoint, cp).unwrap();
    fs::write(&activation, serde_json::to_vec(&act).unwrap()).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&activation, fs::Permissions::from_mode(0o600)).unwrap();
    build(m, i, checkpoint, activation, dir)
}
fn resigned(c: &Case, lease: &DemandLeaseV2, seq: u64) -> SignedLifecycleTaskV2 {
    let mut signed = c.s.bootstrap_lifecycle_task().unwrap().signed;
    signed.lease_id = lease.id().unwrap();
    let m = &mut signed.manifest;
    m.source_record = lease.bound_source_record().unwrap();
    m.withdrawal_head = lease.withdrawal_frontier().unwrap();
    m.demand_nonce = seq;
    m.not_before = lease.not_before;
    m.expires = lease.expires;
    m.available_until = lease.available_until;
    m.output_meter = m.derived_output_meter();
    signed.signature = signature(0, &signed.signing_message().unwrap());
    signed
}
fn activate(n: &mut Node, p: &trnm_pon_node::Packet) -> [u8; 32] {
    let id = n.admit(p, CLOCK).unwrap();
    n.activate(id).unwrap();
    id
}
#[test]
fn native_revision10_replay_renew_reorg_reopen_and_original_profiles_are_distinct() {
    let c = synthetic();
    assert_eq!(c.s.task_profile(), TASK_PROFILE);
    assert_eq!(
        Config::installed_with_operator_checkpoint_tile(&c.spec)
            .unwrap()
            .params["consensus_revision"],
        10
    );
    assert_eq!(c.s.operator_actor_profile(), Some(tile::PROFILE));
    assert!(Settings::development_with_profiles(
        None,
        "native-public-evaluation-dev-v1",
        TASK_PROFILE
    )
    .is_err());
    let cfg = Config::installed_with_checkpoint_tile_policy(
        "native-public-evaluation-dev-v1",
        "linear-expert-dev-v1",
        &c.spec.material_policy,
    )
    .unwrap();
    assert_eq!(
        qualified_task_lifecycle::bootstrap_state(&cfg, &c.m, &c.i).unwrap_err(),
        "CHECKPOINT_EXPLICIT_BOOTSTRAP_REQUIRED"
    );
    let (_, old_bundle, om, oi, old) = fixture();
    assert_ne!(old.network(), c.s.network());
    assert_ne!(old.parameters(), c.s.parameters());
    assert_ne!(old.genesis(), c.s.genesis());
    assert!(
        Settings::development_with_operator_actors(&c.spec.actors, &c.bundle, &c.m, &c.i).is_err()
    );
    assert!(Settings::development_with_operator_checkpoint_tile(
        &c.spec,
        &old_bundle,
        &c.m,
        &c.i,
        c.paths.clone()
    )
    .is_err());
    let old_dir = c.dir.path().join("old");
    drop(Node::open(&old_dir, old.clone(), 1).unwrap());
    assert!(Node::open(&old_dir, c.s.clone(), 1).is_err());
    assert_eq!(
        Settings::development_with_operator_actors(&fixture().0, &old_bundle, &om, &oi)
            .unwrap()
            .genesis(),
        old.genesis()
    );
    let store = c.dir.path().join("store");
    let mut n = Node::open(&store, c.s.clone(), 2).unwrap();
    let boot = c.s.bootstrap_lifecycle_task().unwrap();
    let p = make(
        &n,
        c.s.genesis(),
        vec![transfer(&c.s, 0, 1, 5, 7)],
        &boot.signed,
        &boot.lease,
        &c.m,
        &c.i,
    );
    let first = activate(&mut n, &p);
    let mut lease = boot.lease.clone();
    lease.revision += 1;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    let next = resigned(&c, &lease, 2);
    let renew = transaction(
        &c.s,
        1,
        1,
        22,
        AtomicRenewTaskV4 {
            lease: lease.clone(),
            signed: next.clone(),
        }
        .encode()
        .unwrap(),
    );
    let p = make(
        &n,
        first,
        vec![renew],
        &boot.signed,
        &boot.lease,
        &c.m,
        &c.i,
    );
    let renewed = activate(&mut n, &p);
    let p = make(&n, renewed, vec![], &next, &lease, &c.m, &c.i);
    let current = activate(&mut n, &p);
    let state = n.read_active().unwrap().2;
    let record = &state[&slot_key(0).unwrap()];
    assert_eq!(record["source_sequence"], 2);
    assert_eq!(record["output_count"], 0);
    assert_eq!(n.next_nonce(key(0)).unwrap(), 2);
    assert_eq!(n.next_nonce(key(1)).unwrap(), 2);
    drop(n);
    let mut n = Node::open(&store, c.s.clone(), 1).unwrap();
    assert_eq!(n.active().unwrap().0, current);
    assert_eq!(n.read_active().unwrap().2, state);
    let mut branch = first;
    for _ in 0..3 {
        let p = make(&n, branch, vec![], &boot.signed, &boot.lease, &c.m, &c.i);
        branch = n.admit(&p, CLOCK).unwrap();
    }
    n.activate(branch).unwrap();
    assert_eq!(
        n.read_active().unwrap().2[&slot_key(0).unwrap()]["source_sequence"],
        1
    );
    assert_eq!(n.next_nonce(key(1)).unwrap(), 1);
    let (_, _, a, b) = c.s.bootstrap_task_material().unwrap();
    let material = || trnm_crypto_primitives::qualified_work_task::TaskMaterial {
        model: &c.m,
        input: &c.i,
        a: &a,
        b: &b,
    };
    let old_admission =
        trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_admission(
            &next.encode().unwrap(),
            material(),
            &lease,
            5,
        )
        .unwrap();
    assert!(n
        .make_with_task(
            branch,
            vec![],
            key(5),
            1_800_000_050,
            4096,
            &old_admission,
            material()
        )
        .is_err());
}
#[test]
fn policy_codec_material_purpose_source_signatures_and_full_original_reopen_fail_closed() {
    let c = synthetic();
    let raw = c.spec.canonical().unwrap();
    assert_eq!(OperatorCheckpointTileSpecV1::decode(&raw).unwrap(), c.spec);
    let mut value = serde_json::to_value(&c.spec).unwrap();
    value["material_policy"]["full_forward_verified"] = json!(true);
    assert!(OperatorCheckpointTileSpecV1::decode(&actors::canonical(&value).unwrap()).is_err());
    let duplicate = format!(
        "{{\"profile\":\"{}\",{}",
        tile::PROFILE,
        &String::from_utf8(raw).unwrap()[1..]
    );
    assert!(OperatorCheckpointTileSpecV1::decode(duplicate.as_bytes()).is_err());
    let mut manifest = c.s.bootstrap_lifecycle_task().unwrap().signed.manifest;
    manifest.purpose = TaskPurpose::InferenceContraction;
    manifest.useful_output_limit = 1;
    assert_eq!(
        c.spec.material_policy.check_manifest(&manifest),
        Err("CHECKPOINT_TASK_PURPOSE")
    );
    let mut bad = c.bundle.clone();
    bad.requester_approval.signature = hex::encode([0; 64]);
    assert!(Settings::development_with_operator_checkpoint_tile(
        &c.spec,
        &bad,
        &c.m,
        &c.i,
        c.paths.clone()
    )
    .is_err());
    let mut bad = c.bundle.clone();
    let len = bad.signed_statement.len();
    bad.signed_statement
        .replace_range(len - 128.., &hex::encode([0; 64]));
    assert!(Settings::development_with_operator_checkpoint_tile(
        &c.spec,
        &bad,
        &c.m,
        &c.i,
        c.paths.clone()
    )
    .is_err());
    let store = c.dir.path().join("unchanged");
    drop(Node::open(&store, c.s.clone(), 1).unwrap());
    let cp = c.dir.path().join("model.safetensors");
    let original = fs::read(&cp).unwrap();
    let mut corrupted = original.clone();
    let end = corrupted.len() - 1;
    corrupted[end] ^= 1;
    fs::write(&cp, &corrupted).unwrap();
    assert!(Node::open(&store, c.s.clone(), 1).is_err());
    assert!(!c.dir.path().join("uncreated").exists());
    assert!(Node::open(&c.dir.path().join("uncreated"), c.s.clone(), 1).is_err());
    assert!(!c.dir.path().join("uncreated").exists());
    fs::write(&cp, &original).unwrap();
    assert_eq!(
        Node::open(&store, c.s.clone(), 1)
            .unwrap()
            .active()
            .unwrap(),
        (c.s.genesis(), 0)
    );
    let alias = c.dir.path().join("alias");
    symlink(&cp, &alias).unwrap();
    let paths = CheckpointTileRuntimePaths::new(alias, c.dir.path().join("activation.json"));
    assert!(tile::prepare(&c.spec, &c.m, &c.i, &paths).is_err());
    let node = Node::open(&store, c.s.clone(), 1).unwrap();
    let boot = c.s.bootstrap_lifecycle_task().unwrap();
    let before = node.read_active().unwrap();
    let standalone = transaction(&c.s, 1, 1, 19, boot.lease.encode().unwrap());
    let (a, b) = trnm_crypto_primitives::qualified_work_task::derive_matrices(&c.m, &c.i).unwrap();
    let material = || trnm_crypto_primitives::qualified_work_task::TaskMaterial {
        model: &c.m,
        input: &c.i,
        a: &a,
        b: &b,
    };
    let admission =
        trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_admission(
            &boot.signed.encode().unwrap(),
            material(),
            &boot.lease,
            1,
        )
        .unwrap();
    assert!(node
        .make_with_task(
            c.s.genesis(),
            vec![standalone],
            key(5),
            1_800_000_010,
            4096,
            &admission,
            material()
        )
        .is_err());
    assert_eq!(node.read_active().unwrap(), before);
    let mut lease = boot.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let tx = transaction(&c.s, 1, 1, 18, lease.encode().unwrap());
    assert!(node
        .make_with_task(
            c.s.genesis(),
            vec![tx],
            key(5),
            1_800_000_010,
            4096,
            &admission,
            material()
        )
        .is_err());
    assert_eq!(node.read_active().unwrap(), before);
    for variant in 0..4 {
        let mut lease = boot.lease.clone();
        lease.revision += 1;
        lease.not_before = 1;
        lease.expires = 1001;
        lease.available_until = 1101;
        if variant == 0 {
            lease.not_before = 2;
            lease.expires = 1002;
            lease.available_until = 1102;
        }
        let mut signed = resigned(&c, &lease, if variant == 2 { 1 } else { 2 });
        if variant == 1 {
            signed.signature[0] ^= 1;
        }
        if variant == 3 {
            signed.manifest.model = [91; 32];
            signed.manifest.layer = trnm_protocol::qualified_work_task::QualifiedWorkTask::layer_id(
                signed.manifest.model,
            );
            signed.manifest.output_meter = signed.manifest.derived_output_meter();
            signed.signature = signature(0, &signed.signing_message().unwrap());
        }
        let raw = transaction(
            &c.s,
            1,
            1,
            22,
            AtomicRenewTaskV4 { lease, signed }.encode().unwrap(),
        );
        let error = node
            .make_with_task(
                c.s.genesis(),
                vec![raw],
                key(5),
                1_800_000_010,
                4096,
                &admission,
                material(),
            )
            .unwrap_err()
            .to_string();
        let expected = [
            "TASK_WINDOW",
            "TASK_STATEMENT",
            "TASK_SOURCE_NONCE",
            "CHECKPOINT_TASK_MATERIAL",
        ][variant];
        assert!(error.contains(expected), "{variant}: {error}");
        assert_eq!(node.read_active().unwrap(), before);
    }
    let link = c.dir.path().join("hardlink");
    fs::hard_link(&cp, &link).unwrap();
    assert!(Node::open(&c.dir.path().join("link-store"), c.s.clone(), 1).is_err());
    assert!(!c.dir.path().join("link-store").exists());
    fs::remove_file(link).unwrap();
    assert_eq!(deployment_checkpoint_tile_v1::PROFILE, tile::PROFILE);
}
#[test]
fn actual_cli_offline_prepare_sign_finalize_and_explicit_material_node_mine() {
    let c = synthetic();
    let binary = env!("CARGO_BIN_EXE_trnm-pon-node");
    let spec = c.dir.path().join("spec.json");
    let model = c.dir.path().join("A");
    let input = c.dir.path().join("B");
    fs::write(&spec, c.spec.canonical().unwrap()).unwrap();
    fs::write(&model, &c.m).unwrap();
    fs::write(&input, &c.i).unwrap();
    for p in [&spec, &model, &input] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let base = vec![
        "--development".to_string(),
        "--actor-profile".into(),
        tile::PROFILE.into(),
        "--deployment-spec".into(),
        spec.display().to_string(),
        "--deployment-model".into(),
        model.display().to_string(),
        "--deployment-input".into(),
        input.display().to_string(),
        "--deployment-checkpoint".into(),
        c.dir.path().join("model.safetensors").display().to_string(),
        "--deployment-activation".into(),
        c.dir.path().join("activation.json").display().to_string(),
    ];
    let call = |command: &str, extra: Vec<String>| {
        let output = Command::new(binary)
            .arg(command)
            .args(&base)
            .args(extra)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let template = c.dir.path().join("template.json");
    call(
        "genesis-prepare",
        vec!["--output".into(), template.display().to_string()],
    );
    let mut approvals = Vec::new();
    for (role, who) in [("source", 0), ("requester", 1)] {
        let keypath = c.dir.path().join(format!("{role}.secret"));
        fs::write(&keypath, secret(who)).unwrap();
        fs::set_permissions(&keypath, fs::Permissions::from_mode(0o600)).unwrap();
        let out = c.dir.path().join(format!("{role}.json"));
        call(
            "genesis-sign",
            vec![
                "--deployment-template".into(),
                template.display().to_string(),
                "--role".into(),
                role.into(),
                "--signer-secret".into(),
                keypath.display().to_string(),
                "--output".into(),
                out.display().to_string(),
            ],
        );
        approvals.push(out);
    }
    let bundle = c.dir.path().join("bundle.json");
    call(
        "genesis-finalize",
        vec![
            "--deployment-template".into(),
            template.display().to_string(),
            "--source-approval".into(),
            approvals[0].display().to_string(),
            "--requester-approval".into(),
            approvals[1].display().to_string(),
            "--output".into(),
            bundle.display().to_string(),
        ],
    );
    let store = c.dir.path().join("cli-store");
    let ordinary = vec![
        "--deployment-bootstrap".into(),
        bundle.display().to_string(),
        "--store".into(),
        store.display().to_string(),
        "--miner".into(),
        public(5),
        "--task-bootstrap".into(),
        "--timestamp".into(),
        "1800000010".into(),
        "--logical-now".into(),
        CLOCK.to_string(),
        "--output".into(),
        c.dir.path().join("mined.pnw1").display().to_string(),
    ];
    let value = call("mine", ordinary);
    assert!(value["result"]["admitted"].as_bool().unwrap());
    let n = Node::open(&store, c.s.clone(), 1).unwrap();
    assert_eq!(n.parent_height(n.active().unwrap().0).unwrap(), 1);
}
#[test]
#[ignore = "requires explicitly pinned existing Stage A originals; no downloads or models"]
fn actual_stage_a_complete_original_public_policy_install_and_full_native_packet() {
    let checkpoint = PathBuf::from(std::env::var("TRNM_TILE_CHECKPOINT").unwrap());
    let activation = PathBuf::from(std::env::var("TRNM_TILE_ACTIVATION").unwrap());
    let m = fs::read(std::env::var("TRNM_TILE_A").unwrap()).unwrap();
    let i = fs::read(std::env::var("TRNM_TILE_B").unwrap()).unwrap();
    assert_eq!(
        hex::encode(sha(&fs::read(&checkpoint).unwrap())),
        "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
    );
    assert_eq!(
        hex::encode(sha(&fs::read(&activation).unwrap())),
        "b4d8a0433449353f1f9b329ac63b794ab17f13b6d5c4b28605b161851757af68"
    );
    assert_eq!(
        hex::encode(sha(&m)),
        "1974c3ff10acd6d1588102c343fcf4aeac921ea3f5c2a706cf39ef3416886cbb"
    );
    assert_eq!(
        hex::encode(sha(&i)),
        "d165f6400283bd330acf9fe7c51d916e453bea417acc453fe8e9d025f4fefd85"
    );
    let c = build(m, i, checkpoint, activation, tempfile::tempdir().unwrap());
    let store = c.dir.path().join("actual");
    let mut n = Node::open(&store, c.s.clone(), 2).unwrap();
    let boot = c.s.bootstrap_lifecycle_task().unwrap();
    let packet = make(
        &n,
        c.s.genesis(),
        vec![],
        &boot.signed,
        &boot.lease,
        &c.m,
        &c.i,
    );
    let id = activate(&mut n, &packet);
    let actual_state = n.read_active().unwrap().2;
    let output = PathBuf::from(std::env::var("TRNM_TILE_CONTROL_OUTPUT").unwrap());
    fs::create_dir(&output).unwrap();
    fs::write(output.join("packet.pnw1"), packet.encode().unwrap()).unwrap();
    fs::write(
        output.join("state.json"),
        serde_json::to_vec(&actual_state).unwrap(),
    )
    .unwrap();
    fs::write(output.join("spec.json"), c.spec.canonical().unwrap()).unwrap();
    fs::write(
        output.join("bundle.json"),
        actors::canonical(&c.bundle).unwrap(),
    )
    .unwrap();
    fs::write(output.join("source.qdl2"), boot.signed.encode().unwrap()).unwrap();
    fs::write(
        output.join("descriptor.json"),
        c.paths
            .replay(
                &Config::installed_with_operator_checkpoint_tile(&c.spec).unwrap(),
                &c.m,
                &c.i,
            )
            .unwrap()
            .canonical_descriptor(),
    )
    .unwrap();
    drop(n);
    assert_eq!(
        Node::open(&store, c.s.clone(), 1)
            .unwrap()
            .active()
            .unwrap()
            .0,
        id
    );
    println!(
        "{}",
        json!({"schema":"checkpoint-tile-native-stage-a-control-v1","checkpoint_bytes":c.spec.material_policy.checkpoint_bytes,"policy":hex::encode(c.spec.material_policy.id().unwrap()),"network":hex::encode(c.s.network()),"parameters":hex::encode(c.s.parameters()),"genesis":hex::encode(c.s.genesis()),"header":hex::encode(id),"height":1,"matrix_words_each":4096,"maintenance_output_limit":0,"hardness_accepted":false,"full_forward_verified":false,"genuine_demand_verified":false,"public_network_ready":false})
    );
}
