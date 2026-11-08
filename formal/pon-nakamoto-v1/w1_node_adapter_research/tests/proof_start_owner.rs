//! Real filesystem owners, separate CLI processes and retained complete proofs.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use w1_node_adapter_research::proof_start_owner::{
    ProofStartOwner, ProofStartPolicy, ProofStartPurpose,
};
use w1_node_adapter_research::{OperatorPlan, PreparedBundle, verify_reserved_bundle};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/node-input-v1")
}

fn plan() -> OperatorPlan {
    serde_json::from_slice(&fs::read(fixture().join("operator-plan.json")).unwrap()).unwrap()
}

fn policy(maximum: usize) -> ProofStartPolicy {
    ProofStartPolicy::for_plan("71".repeat(32), maximum, &plan()).unwrap()
}

fn owner_path(directory: &Path) -> PathBuf {
    fs::canonicalize(directory).unwrap().join("owner")
}

fn make_owner(directory: &Path, maximum: usize) -> (ProofStartOwner, PathBuf, PathBuf) {
    let policy = policy(maximum);
    let policy_path = directory.join("independent-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let path = owner_path(directory);
    let owner = ProofStartOwner::create(&path, policy).unwrap();
    (owner, path, policy_path)
}

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_w1-node-adapter-research"));
    command.env("RAYON_NUM_THREADS", "2");
    command
}

fn result(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .next_back()
        .unwrap();
    serde_json::from_slice::<Value>(line).unwrap()["result"].clone()
}

fn private_empty(path: &Path) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
fn cold_owner_reopen_cannot_refund_dropped_starts() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, _) = make_owner(dir.path(), 2);
    let first = owner.reserve(ProofStartPurpose::Admission).unwrap();
    assert_eq!(first.record().slot, 1);
    drop(first);
    drop(owner);
    let owner = ProofStartOwner::open(&path, policy(2)).unwrap();
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 1);
    let second = owner.reserve(ProofStartPurpose::ReopenObservation).unwrap();
    assert_eq!(second.record().slot, 2);
    drop(second);
    drop(owner);
    let owner = ProofStartOwner::open(&path, policy(2)).unwrap();
    assert!(owner.snapshot().unwrap().exhausted);
    for _ in 0..16 {
        assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    }
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 2);
    assert!(
        !owner
            .snapshot()
            .unwrap()
            .backup_rollback_protection_established
    );
    assert!(
        !owner
            .snapshot()
            .unwrap()
            .lifetime_quantum_query_bound_established
    );
    assert!(ProofStartOwner::create(&path, policy(2)).is_err());
}

#[test]
fn interrupted_slot_writes_remain_spent_without_repair() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, _) = make_owner(dir.path(), 3);
    private_empty(&path.join("starts-v1/01.start"));
    let partial = path.join("starts-v1/02.start");
    private_empty(&partial);
    fs::write(&partial, b"{\"schema\"").unwrap();
    drop(owner);
    let owner = ProofStartOwner::open(&path, policy(3)).unwrap();
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 2);
    assert_eq!(
        owner
            .reserve(ProofStartPurpose::Admission)
            .unwrap()
            .record()
            .slot,
        3
    );
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    assert!(
        fs::read(path.join("starts-v1/01.start"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read(&partial).unwrap(), b"{\"schema\"");
}

#[test]
fn independently_changed_policy_cannot_enlarge_or_rebind_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, _) = make_owner(dir.path(), 2);
    let original = policy(2);
    for field in [
        "maximum",
        "owner",
        "genesis",
        "network",
        "parameters",
        "schema",
        "profile",
    ] {
        let mut changed = original.clone();
        match field {
            "maximum" => changed.maximum_starts = 3,
            "owner" => changed.owner_id = "72".repeat(32),
            "genesis" => changed.genesis = "73".repeat(32),
            "network" => changed.network = "74".repeat(32),
            "parameters" => changed.parameters = "75".repeat(32),
            "schema" => changed.schema.push_str("-unknown"),
            "profile" => changed.profile.push_str("-unknown"),
            _ => unreachable!(),
        }
        assert!(ProofStartOwner::open(&path, changed).is_err(), "{field}");
    }
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 0);
    assert!(ProofStartPolicy::for_plan("71".repeat(32), 0, &plan()).is_err());
    assert!(ProofStartPolicy::for_plan("71".repeat(32), 17, &plan()).is_err());
}

#[test]
fn missing_or_interrupted_initialization_never_creates_a_fallback_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = owner_path(dir.path());
    assert!(ProofStartOwner::open(&path, policy(1)).is_err());
    assert!(!path.exists());
    let owner = ProofStartOwner::create(&path, policy(1)).unwrap();
    fs::remove_file(path.join("complete-v1")).unwrap();
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    assert!(ProofStartOwner::open(&path, policy(1)).is_err());
    assert!(ProofStartOwner::create(&path, policy(1)).is_err());
    assert_eq!(fs::read_dir(path.join("starts-v1")).unwrap().count(), 0);
}

#[test]
fn links_unexpected_entries_and_loose_permissions_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, _) = make_owner(dir.path(), 2);
    let alias = fs::canonicalize(dir.path()).unwrap().join("owner-alias");
    symlink(&path, &alias).unwrap();
    assert!(ProofStartOwner::open(&alias, policy(2)).is_err());
    let external = dir.path().join("external-slot");
    private_empty(&external);
    let first = path.join("starts-v1/01.start");
    symlink(&external, &first).unwrap();
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    fs::remove_file(&first).unwrap();
    fs::hard_link(&external, &first).unwrap();
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    fs::remove_file(&first).unwrap();
    private_empty(&path.join("starts-v1/unexpected"));
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    fs::remove_file(path.join("starts-v1/unexpected")).unwrap();
    fs::set_permissions(
        path.join("policy-v1.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    assert_eq!(fs::read_dir(path.join("starts-v1")).unwrap().count(), 0);
}

#[test]
fn an_open_owner_handle_refuses_replacement_at_the_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, _) = make_owner(dir.path(), 2);
    owner.reserve(ProofStartPurpose::Admission).unwrap();
    fs::rename(&path, path.with_file_name("retained-original-owner")).unwrap();
    let replacement = ProofStartOwner::create(&path, policy(2)).unwrap();
    assert!(owner.reserve(ProofStartPurpose::Admission).is_err());
    assert_eq!(replacement.snapshot().unwrap().occupied_slots, 0);
    // A new process cannot authenticate backup history. No anti-rollback claim.
    assert!(
        !replacement
            .snapshot()
            .unwrap()
            .backup_rollback_protection_established
    );
}

#[test]
fn a_reserved_permit_checks_context_before_any_crypto_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, _, _) = make_owner(dir.path(), 1);
    let reservation = owner.reserve(ProofStartPurpose::Admission).unwrap();
    let mut changed = plan();
    changed.genesis = "91".repeat(32);
    let bundle = PreparedBundle::new(
        changed,
        fs::read(fixture().join("packet.bin")).unwrap(),
        fs::read(fixture().join("statement.bin")).unwrap(),
        fs::read(fixture().join("sha.proof.bin")).unwrap(),
        fs::read(fixture().join("arith.proof.bin")).unwrap(),
    )
    .unwrap();
    let mut entered = false;
    assert!(
        verify_reserved_bundle(&bundle, reservation, |_| {
            entered = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!entered);
    assert!(owner.snapshot().unwrap().exhausted);
}

#[test]
fn cli_input_failure_consumes_a_slot_and_exhaustion_precedes_loading() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, expected) = make_owner(dir.path(), 1);
    let bad_output = dir.path().join("bad-output");
    let bad = cli()
        .arg("exercise")
        .arg(dir.path().join("absent-fixture"))
        .arg(fixture())
        .arg(&bad_output)
        .arg("none")
        .arg(&path)
        .arg(&expected)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stdout).contains("proof_start_reserved"));
    assert!(owner.snapshot().unwrap().exhausted);
    assert!(!bad_output.join("receiver-node").exists());
    let refused_output = dir.path().join("refused-output");
    let refused = cli()
        .arg("exercise")
        .arg(fixture())
        .arg(fixture())
        .arg(&refused_output)
        .arg("none")
        .arg(&path)
        .arg(&expected)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("proof-start budget exhausted"));
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("checkpoint"));
    assert!(!refused_output.exists());
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 1);
}

#[test]
fn concurrent_cli_processes_share_one_fixed_nonrefundable_quota() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, expected) = make_owner(dir.path(), 3);
    let mut children = Vec::new();
    for index in 0..8 {
        let output_path = dir.path().join(format!("process-{index}"));
        let child = cli()
            .arg("exercise")
            .arg(fixture())
            .arg(fixture())
            .arg(&output_path)
            .arg("BeforeProof")
            .arg(&path)
            .arg(&expected)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        children.push((output_path, child));
    }
    let mut slots = BTreeSet::new();
    let mut refused = 0;
    for (output_path, child) in children {
        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            let record = result(&output);
            assert_eq!(record["error"], "REQUEST_CANCELLED:BeforeProof");
            assert_eq!(record["node_opened"], false);
            assert!(slots.insert(record["proof_start"]["slot"].as_u64().unwrap()));
        } else {
            refused += 1;
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("proof-start budget exhausted")
            );
            assert!(!output_path.exists());
            assert!(!String::from_utf8_lossy(&output.stdout).contains("checkpoint"));
        }
        assert!(!output_path.join("receiver-node").exists());
    }
    assert_eq!(slots, BTreeSet::from([1, 2, 3]));
    assert_eq!(refused, 5);
    drop(owner);
    assert!(
        ProofStartOwner::open(&path, policy(3))
            .unwrap()
            .snapshot()
            .unwrap()
            .exhausted
    );
}

#[test]
fn real_proofs_native_admission_and_cold_readback_charge_the_same_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, path, expected) = make_owner(dir.path(), 2);
    let output_path = dir.path().join("admission");
    let first = result(
        &cli()
            .arg("exercise")
            .arg(fixture())
            .arg(fixture())
            .arg(&output_path)
            .arg("none")
            .arg(&path)
            .arg(&expected)
            .output()
            .unwrap(),
    );
    assert_eq!(first["schema"], "trnm-w1-node-adapter-exercise-v2");
    assert_eq!(first["outcome"]["native_admitted"], true);
    assert_eq!(first["outcome"]["both_real_proofs_verified"], true);
    assert_eq!(first["outcome"]["proof_start"]["slot"], 1);
    assert_eq!(first["outcome"]["proof_start"]["purpose"], "admission");
    let operation = first["operation_directory"].as_str().unwrap();
    let cold = result(
        &cli()
            .arg("reopen")
            .arg(fixture())
            .arg(&output_path)
            .arg(operation)
            .arg(&path)
            .arg(&expected)
            .output()
            .unwrap(),
    );
    assert_eq!(cold["both_real_proofs_reverified"], true);
    assert_eq!(cold["admission_performed"], false);
    assert_eq!(cold["native_observation"]["active_chain_member"], true);
    assert_eq!(cold["proof_start"]["slot"], 2);
    assert_eq!(cold["proof_start"]["purpose"], "reopen_observation");
    assert_eq!(
        cold["proof_start"]["policy_sha256"],
        first["proof_start"]["policy_sha256"]
    );
    let third = cli()
        .arg("reopen")
        .arg(fixture())
        .arg(&output_path)
        .arg(operation)
        .arg(&path)
        .arg(&expected)
        .output()
        .unwrap();
    assert!(!third.status.success());
    assert!(String::from_utf8_lossy(&third.stderr).contains("proof-start budget exhausted"));
    assert!(!String::from_utf8_lossy(&third.stdout).contains("proof_start_reserved"));
    assert_eq!(owner.snapshot().unwrap().occupied_slots, 2);
    assert_eq!(cold["qualification"], "HOLD_NO_GO");
    assert_eq!(cold["production_activation"], false);
}
