//! Actual local native calls and durable sidecar refusal controls.
#[path = "../examples/support/native_journal_scenario.rs"]
mod scenario;

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::native_owner_journal::{
    JournalBackend, JournalMakeRequest, JournaledNativeOwner, NativeJournalOptions,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::Hash;

fn settings() -> Settings {
    Settings::development(Some(1)).unwrap()
}
fn open(root: &Path, options: NativeJournalOptions) -> JournaledNativeOwner {
    JournaledNativeOwner::open(
        &root.join("store"),
        &root.join("journal"),
        settings(),
        options,
    )
    .unwrap()
}
fn make(owner: &mut JournaledNativeOwner) -> Packet {
    owner
        .make(
            JournalMakeRequest {
                parent: settings().genesis(),
                transactions: vec![],
                miner: development_public(0).unwrap(),
                timestamp: 11,
                max_attempts: 4096,
            },
            100,
        )
        .unwrap()
}
fn external_packet(root: &Path) -> Packet {
    Node::open(root, settings(), 1)
        .unwrap()
        .make(
            settings().genesis(),
            vec![],
            development_public(1).unwrap(),
            12,
            4096,
        )
        .unwrap()
}
fn digest(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw))
}
fn assert_refused(root: &Path, options: NativeJournalOptions, expected: &str) {
    match JournaledNativeOwner::open(
        &root.join("store"),
        &root.join("journal"),
        settings(),
        options,
    ) {
        Ok(_) => panic!("expected {expected}"),
        Err(error) => assert_eq!(error.to_string(), expected),
    }
}

#[test]
fn actual_legacy_and_authenticated_restart_preserve_unadmitted_output_identity() {
    for backend in [JournalBackend::Legacy, JournalBackend::AuthenticatedV1] {
        let root = tempfile::tempdir().unwrap();
        let options = NativeJournalOptions {
            backend,
            ..NativeJournalOptions::default()
        };
        let mut owner = open(root.path(), options.clone());
        let packet = make(&mut owner);
        let block = hex::encode(packet.id().unwrap());
        let before = owner.status().unwrap();
        assert_eq!(before["registry"][&block]["first_seen_epoch"], 1);
        assert_eq!(
            before["registry"][&block]["native_relation_rechecked_by_census"],
            false
        );
        let pin = owner.finish(100).unwrap();
        let mut owner = open(
            root.path(),
            NativeJournalOptions {
                expected_checkpoint: Some(pin),
                ..options
            },
        );
        owner.admit(&packet, 100).unwrap();
        owner.admit(&packet, 100).unwrap();
        owner.activate_observed(packet.id().unwrap(), 100).unwrap();
        let after = owner.status().unwrap();
        assert_eq!(after["registry"].as_object().unwrap().len(), 1);
        assert_eq!(
            after["registry"][&block]["first_seen_sequence"],
            before["registry"][&block]["first_seen_sequence"]
        );
        assert_eq!(
            after["registry"][&block]["origin_class"],
            "recorded_local_production"
        );
        assert_eq!(
            after["registry"][&block]["native_relation_rechecked_by_census"],
            true
        );
        assert_eq!(
            after["outside_lease_intervals"].as_array().unwrap().len(),
            1
        );
        assert_eq!(after["fresh_resource_state_attested"], false);
        assert_eq!(after["trusted_history_anchor"], false);
        owner.finish(100).unwrap();
    }
}

#[test]
fn actual_two_branch_process_cut_recovery_and_saved_checkpoint_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let report = scenario::run(&temporary.path().join("run"), |plan| {
        Ok(Command::new(&executable)
            .args([
                "--exact",
                "native_journal_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env("NATIVE_JOURNAL_CHILD_PLAN", plan)
            .output()?)
    })
    .unwrap();
    assert_eq!(report["crash_child"]["exit_code"], scenario::CRASH_EXIT);
    assert_eq!(
        report["before_hidden"]["local_view_commitment"],
        report["after_hidden"]["local_view_commitment"]
    );
    assert_eq!(
        report["stale_checkpoint_refusal"],
        "OWNER_JOURNAL_CHECKPOINT"
    );
    assert_eq!(
        report["recovered_status"]["unresolved_intents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["recovered_status"]["unresolved_intents"][0]["operation"],
        "activate_observed"
    );
    assert_eq!(
        report["invalid_same_id_packet"]["id"],
        report["bob_status"]["registry"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, value)| value["packet_sha256"]
                == report["invalid_same_id_packet"]["valid_packet_sha256"])
            .unwrap()
            .0
            .as_str()
    );
    assert_ne!(
        report["invalid_same_id_packet"]["sha256"],
        report["invalid_same_id_packet"]["valid_packet_sha256"]
    );
    assert_eq!(report["six_successor_risk_qualified"], false);
}

#[test]
#[ignore = "owned subprocess helper, actually executed by the process-cut test"]
fn native_journal_process_child() {
    let plan =
        std::env::var_os("NATIVE_JOURNAL_CHILD_PLAN").expect("explicit parent plan required");
    scenario::crash_child(Path::new(&plan)).unwrap();
    panic!("the native commit cut must terminate this child");
}

#[test]
fn dropped_pending_native_activation_blocks_reuse_and_remains_unresolved_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default());
    let packet = make(&mut owner);
    owner.admit(&packet, 100).unwrap();
    let pin = owner.checkpoint().unwrap();
    let pending = owner.begin_activation(packet.id().unwrap(), 100).unwrap();
    assert!(pending.native_succeeded());
    drop(pending);
    assert_eq!(
        owner.observe(100).unwrap_err().to_string(),
        "OWNER_JOURNAL_UNRESOLVED"
    );
    assert_eq!(
        owner.status().unwrap()["unresolved_intents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    drop(owner);
    let owner = open(
        root.path(),
        NativeJournalOptions {
            expected_checkpoint: Some(pin),
            ..NativeJournalOptions::default()
        },
    );
    let status = owner.status().unwrap();
    assert_eq!(
        status["last_census"]["active_tip"],
        hex::encode(packet.id().unwrap())
    );
    assert_eq!(status["unresolved_intents"].as_array().unwrap().len(), 1);
    assert_eq!(status["unresolved_intents"][0]["prepared"], true);
    owner.finish(100).unwrap();
}

#[test]
fn torn_tail_is_preserved_and_refused_before_reopening_native_store() {
    let root = tempfile::tempdir().unwrap();
    open(root.path(), NativeJournalOptions::default())
        .finish(100)
        .unwrap();
    let path = root.path().join("journal/journal.pnoj1");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let torn = fs::read(&path).unwrap();
    assert_refused(
        root.path(),
        NativeJournalOptions::default(),
        "OWNER_JOURNAL_TORN_TAIL",
    );
    assert_eq!(fs::read(path).unwrap(), torn);
}

#[test]
fn wrong_prior_checkpoint_refuses_without_appending_an_open_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut pin = open(root.path(), NativeJournalOptions::default())
        .finish(100)
        .unwrap();
    pin.record_hash = "ff".repeat(32);
    let path = root.path().join("journal/journal.pnoj1");
    let before = fs::read(&path).unwrap();
    assert_refused(
        root.path(),
        NativeJournalOptions {
            expected_checkpoint: Some(pin),
            ..NativeJournalOptions::default()
        },
        "OWNER_JOURNAL_CHECKPOINT",
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn sidecar_lock_is_exclusive_and_new_namespace_never_claims_fresh_resources() {
    let root = tempfile::tempdir().unwrap();
    let owner = open(root.path(), NativeJournalOptions::default());
    assert_refused(
        root.path(),
        NativeJournalOptions::default(),
        "OWNER_JOURNAL_BUSY",
    );
    let status = owner.status().unwrap();
    for field in [
        "fresh_resource_state_attested",
        "initial_resource_state_known",
        "trusted_history_anchor",
        "world_coverage_attested",
        "physical_clock_authenticated",
        "all_ever_native_api_calls_covered",
    ] {
        assert_eq!(status[field], false);
    }
    assert_eq!(status["initial_world_inventory_bound"], Value::Null);
    owner.finish(100).unwrap();
}

#[test]
fn referenced_packet_corruption_is_refused_and_never_overwritten_on_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default());
    let packet = make(&mut owner);
    owner.admit(&packet, 100).unwrap();
    let pin = owner.finish(100).unwrap();
    let path = root
        .path()
        .join("journal/packets")
        .join(format!("{}.pnp1", digest(&packet.encode().unwrap())));
    let mut corrupted = fs::read(&path).unwrap();
    corrupted[400] ^= 1;
    fs::write(&path, &corrupted).unwrap();
    assert_refused(
        root.path(),
        NativeJournalOptions {
            expected_checkpoint: Some(pin),
            ..NativeJournalOptions::default()
        },
        "OWNER_JOURNAL_ARTIFACT",
    );
    assert_eq!(fs::read(path).unwrap(), corrupted);
}

#[test]
fn terminal_budget_failure_preserves_real_native_effect_and_unresolved_debt() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(
        root.path(),
        NativeJournalOptions {
            maximum_records: 8,
            ..NativeJournalOptions::default()
        },
    );
    let packet = make(&mut owner);
    let pin = owner.checkpoint().unwrap();
    assert_eq!(
        owner.admit(&packet, 100).unwrap_err().to_string(),
        "OWNER_JOURNAL_RECORD_BUDGET"
    );
    let failed = owner.status().unwrap();
    assert_eq!(failed["blocked"], true);
    assert_eq!(failed["unresolved_intents"].as_array().unwrap().len(), 1);
    drop(owner);
    let owner = open(
        root.path(),
        NativeJournalOptions {
            expected_checkpoint: Some(pin),
            ..NativeJournalOptions::default()
        },
    );
    let recovered = owner.status().unwrap();
    assert_eq!(
        recovered["last_census"]["rows"].as_array().unwrap().len(),
        2
    );
    assert_eq!(recovered["unresolved_intents"][0]["operation"], "admit");
    assert_eq!(recovered["fresh_resource_state_attested"], false);
    owner.finish(100).unwrap();
}

#[test]
fn input_artifact_budget_refuses_before_any_native_admission_intent() {
    let root = tempfile::tempdir().unwrap();
    let producer = tempfile::tempdir().unwrap();
    let packet = external_packet(producer.path());
    let mut owner = open(
        root.path(),
        NativeJournalOptions {
            maximum_artifact_bytes: 1,
            ..NativeJournalOptions::default()
        },
    );
    let before = owner.checkpoint().unwrap();
    assert_eq!(
        owner.admit(&packet, 100).unwrap_err().to_string(),
        "OWNER_JOURNAL_ARTIFACT_BUDGET"
    );
    assert_eq!(owner.checkpoint().unwrap(), before);
    assert_eq!(
        owner.status().unwrap()["last_census"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    owner.finish(100).unwrap();
}

#[test]
fn invalid_same_id_packet_never_inherits_another_packets_valid_native_weight() {
    let root = tempfile::tempdir().unwrap();
    let producer = tempfile::tempdir().unwrap();
    let packet = external_packet(producer.path());
    let id: Hash = packet.id().unwrap();
    let mut invalid = packet.clone();
    invalid.proof[4 + 2 * pon_work::CELLS * 4] ^= 1;
    assert_eq!(invalid.id().unwrap(), id);
    let mut owner = open(root.path(), NativeJournalOptions::default());
    assert!(owner
        .admit(&invalid, 100)
        .unwrap_err()
        .to_string()
        .starts_with("WORK:"));
    assert!(owner.status().unwrap()["registry"]
        .as_object()
        .unwrap()
        .is_empty());
    owner.admit(&packet, 100).unwrap();
    let status = owner.status().unwrap();
    let registered = &status["registry"][hex::encode(id)];
    assert_eq!(
        registered["packet_sha256"],
        digest(&packet.encode().unwrap())
    );
    assert_ne!(
        registered["packet_sha256"],
        digest(&invalid.encode().unwrap())
    );
    assert_eq!(registered["native_relation_rechecked_by_census"], true);
    assert_eq!(registered["origin_class"], "external_input");
    owner.finish(100).unwrap();
}
