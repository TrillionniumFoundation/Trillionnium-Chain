//! Real retained full proofs and real SQLite-backed Node owners. No verifier stub.
use std::fs;
use std::path::Path;

use trnm_pon_node::{Node, Settings, development_public};
use w1_node_adapter_research::{
    OperatorPlan, PreparedBundle, Stage, WorkStartBudget, admit, observe, verify_bundle,
};

const TIME: u64 = 1_800_000_000;
fn settings() -> Settings {
    Settings::development(Some(TIME)).unwrap()
}
fn bytes(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/node-input-v1")
            .join(name),
    )
    .unwrap()
}
fn plan() -> OperatorPlan {
    serde_json::from_slice(&bytes("operator-plan.json")).unwrap()
}
fn bundle() -> PreparedBundle {
    make(plan(), bytes("statement.bin"), bytes("sha.proof.bin"))
}
fn make(p: OperatorPlan, public: Vec<u8>, sha: Vec<u8>) -> PreparedBundle {
    PreparedBundle::new(
        p,
        bytes("packet.bin"),
        public,
        sha,
        bytes("arith.proof.bin"),
    )
    .unwrap()
}
fn node(path: &Path) -> Node {
    Node::open(path, settings(), 1).unwrap()
}

#[test]
fn complete_two_proofs_real_admission_duplicate_and_cold_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle();
    let stored = bundle.persist(&dir.path().join("archives")).unwrap();
    let receiver = dir.path().join("node");
    let mut n = node(&receiver);
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let first = admit(&mut n, verified, TIME + 100, true, |_| Ok(())).unwrap();
    assert_eq!(first["native_admitted"], true);
    assert_eq!(first["schema"], "trnm-w1-node-adapter-admission-v2");
    assert_eq!(first["native_admission_path_invoked"], true);
    assert!(first.get("native_full_replay_required").is_none());
    assert_eq!(first["native_observation"]["stored_exact"], true);
    assert_eq!(first["native_observation"]["active_chain_member"], true);
    let active = n.active().unwrap();
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let duplicate = admit(&mut n, verified, TIME + 101, true, |_| Ok(())).unwrap();
    assert_eq!(duplicate["native_admission_path_invoked"], true);
    assert!(duplicate.get("native_full_replay_required").is_none());
    assert_eq!(duplicate["native_work_policy"], first["native_work_policy"]);
    assert_eq!(
        n.active().unwrap(),
        active,
        "duplicate cannot create chainwork/generation"
    );
    drop(n);
    let n = node(&receiver);
    let reloaded = PreparedBundle::reload(&stored, plan()).unwrap();
    let current = observe(&n, &reloaded, |_| Ok(())).unwrap();
    assert_eq!(current["both_real_proofs_reverified"], true);
    assert_eq!(current["admission_performed"], false);
    assert_eq!(current["native_observation"]["active_chain_member"], true);
    assert_eq!(n.active().unwrap(), active);
}

#[test]
fn a_valid_native_packet_with_false_public_arithmetic_never_reaches_node() {
    let dir = tempfile::tempdir().unwrap();
    let mut public = bytes("statement.bin");
    let last = public.len() - 4;
    let old = u32::from_le_bytes(public[last..].try_into().unwrap());
    public[last..].copy_from_slice(&(old ^ 1).to_le_bytes());
    let bundle = make(plan(), public, bytes("sha.proof.bin"));
    let n = node(dir.path());
    let before = n.active().unwrap();
    assert!(verify_bundle(&bundle, |_| Ok(())).is_err());
    assert_eq!(
        n.exact_packet_observation(bundle.packet()).unwrap()["stored_exact"],
        false
    );
    assert_eq!(n.active().unwrap(), before);
}

#[test]
fn independent_artifact_binding_is_cryptographically_checked() {
    let mut p = plan();
    let mut artifacts = hex::decode(&p.expected_artifacts).unwrap();
    artifacts[0] ^= 1;
    p.expected_artifacts = hex::encode(artifacts);
    let bundle = make(p, bytes("statement.bin"), bytes("sha.proof.bin"));
    let mut entered = false;
    let result = verify_bundle(&bundle, |stage| {
        entered |= stage == Stage::BeforeShaVerify;
        Ok(())
    });
    assert!(entered && result.is_err());
}

#[test]
fn independently_changed_header_and_profile_fail_before_crypto() {
    let mut p = plan();
    let mut header = hex::decode(&p.expected_header).unwrap();
    let n = header.len();
    header[n - 1] ^= 1;
    p.expected_header = hex::encode(header);
    assert!(
        PreparedBundle::new(
            p,
            bytes("packet.bin"),
            bytes("statement.bin"),
            bytes("sha.proof.bin"),
            bytes("arith.proof.bin")
        )
        .is_err()
    );
    let mut p = plan();
    p.profile = "PGH2-or-production-is-not-this-profile".into();
    assert!(p.expected().is_err());
}

#[test]
fn precommit_cancellation_keeps_native_store_empty_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let receiver = dir.path().join("node");
    let bundle = bundle();
    let mut n = node(&receiver);
    let before = n.active().unwrap();
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let result = admit(&mut n, verified, TIME + 100, true, |stage| {
        if stage == Stage::BeforeNodeAdmission {
            Err("cancel".into())
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert_eq!(n.active().unwrap(), before);
    drop(n);
    let n = node(&receiver);
    assert_eq!(
        n.exact_packet_observation(bundle.packet()).unwrap()["stored_exact"],
        false
    );
}

#[test]
fn postcommit_cancellation_preserves_true_admission_without_activation() {
    let dir = tempfile::tempdir().unwrap();
    let receiver = dir.path().join("node");
    let bundle = bundle();
    let mut n = node(&receiver);
    let before = n.active().unwrap();
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let result = admit(&mut n, verified, TIME + 100, true, |stage| {
        if stage == Stage::NodeCommitted {
            Err("late cancel".into())
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(result["native_admitted"], true);
    assert_eq!(result["late_cancellation"], "late cancel");
    assert_eq!(result["native_observation"]["stored_exact"], true);
    assert_eq!(result["native_observation"]["active_chain_member"], false);
    assert_eq!(n.active().unwrap(), before);
    drop(n);
    let n = node(&receiver);
    assert_eq!(
        n.exact_packet_observation(bundle.packet()).unwrap()["stored_exact"],
        true
    );
    // Native open performs its own recovery. It can activate the committed
    // best packet even though the adapter skipped activation before closing.
    assert_eq!(n.active().unwrap().0, bundle.packet().id().unwrap());
    assert!(n.active().unwrap().1 > before.1);
}

#[test]
fn current_node_genesis_is_rebound_after_proof_verification() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle();
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let mut n = Node::open(
        dir.path(),
        Settings::development(Some(TIME + 1)).unwrap(),
        1,
    )
    .unwrap();
    let before = n.active().unwrap();
    assert!(admit(&mut n, verified, TIME + 100, true, |_| Ok(())).is_err());
    assert_eq!(n.active().unwrap(), before);
}

#[test]
fn reorg_observation_does_not_reuse_old_active_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle();
    let mut n = node(dir.path());
    let verified = verify_bundle(&bundle, |_| Ok(())).unwrap();
    let first = admit(&mut n, verified, TIME + 100, true, |_| Ok(())).unwrap();
    assert_eq!(first["native_observation"]["active_chain_member"], true);
    let sibling = n
        .make(
            settings().genesis(),
            vec![],
            development_public(4).unwrap(),
            TIME + 11,
            4096,
        )
        .unwrap();
    let sibling_id = n.admit(&sibling, TIME + 100).unwrap();
    let child = n
        .make(
            sibling_id,
            vec![],
            development_public(4).unwrap(),
            TIME + 21,
            4096,
        )
        .unwrap();
    let child_id = n.admit(&child, TIME + 100).unwrap();
    n.activate(child_id).unwrap();
    let active = n.active().unwrap();
    assert_eq!(active.0, child_id);
    let current = observe(&n, &bundle, |_| Ok(())).unwrap();
    assert_eq!(current["native_observation"]["stored_exact"], true);
    assert_eq!(current["native_observation"]["active_chain_member"], false);
    assert_eq!(
        n.active().unwrap(),
        active,
        "reopen observation has no activation effect"
    );
}

#[test]
fn archive_corruption_and_incomplete_commit_marker_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle();
    let path = bundle.persist(dir.path()).unwrap();
    let marker = fs::read(path.join("complete-v1")).unwrap();
    fs::remove_file(path.join("complete-v1")).unwrap();
    assert!(PreparedBundle::reload(&path, plan()).is_err());
    fs::write(path.join("complete-v1"), marker).unwrap();
    let mut binding: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("binding.json")).unwrap()).unwrap();
    binding["production_activation"] = true.into();
    fs::write(
        path.join("binding.json"),
        serde_json::to_vec(&binding).unwrap(),
    )
    .unwrap();
    assert!(PreparedBundle::reload(&path, plan()).is_err());
}

#[test]
fn archive_limit_counts_interrupted_operations_without_resetting_them() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..16 {
        fs::create_dir(dir.path().join(format!("interrupted-{i}"))).unwrap();
    }
    assert!(bundle().persist(dir.path()).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 16);
}

#[test]
fn failed_work_start_is_spent_and_cannot_refund_the_batch() {
    let mut budget = WorkStartBudget::new(1).unwrap();
    budget.reserve().unwrap();
    assert!(
        PreparedBundle::new(
            plan(),
            bytes("packet.bin"),
            bytes("statement.bin"),
            vec![],
            bytes("arith.proof.bin")
        )
        .is_err()
    );
    for _ in 0..16 {
        assert!(budget.reserve().is_err());
    }
    assert_eq!(budget.spent(), 1);
    assert!(WorkStartBudget::new(0).is_err());
    assert!(WorkStartBudget::new(17).is_err());
}

#[test]
fn real_cli_refusal_and_early_cancel_never_open_node() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/node-input-v1");
    for cancellation in ["BeforeProof", "none"] {
        let dir = tempfile::tempdir().unwrap();
        let inputs = dir.path().join("input");
        fs::create_dir(&inputs).unwrap();
        for name in ["operator-plan.json", "packet.bin", "statement.bin"] {
            fs::copy(fixture.join(name), inputs.join(name)).unwrap();
        }
        if cancellation == "none" {
            let mut public = fs::read(inputs.join("statement.bin")).unwrap();
            let last = public.len() - 4;
            let old = u32::from_le_bytes(public[last..].try_into().unwrap());
            public[last..].copy_from_slice(&(old ^ 1).to_le_bytes());
            fs::write(inputs.join("statement.bin"), public).unwrap();
        }
        let output = dir.path().join("exercise");
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_w1-node-adapter-research"))
            .arg("exercise")
            .arg(&inputs)
            .arg(&fixture)
            .arg(&output)
            .arg(cancellation)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("exercise.json")).unwrap()).unwrap();
        assert!(record["outcome"].is_null() && record["error"].is_string());
        assert_eq!(record["node_opened"], false);
        assert!(record["native_observation"].is_null());
        assert_eq!(record["work_starts_spent"], 1);
        assert!(!output.join("receiver-node").exists());
    }
}
