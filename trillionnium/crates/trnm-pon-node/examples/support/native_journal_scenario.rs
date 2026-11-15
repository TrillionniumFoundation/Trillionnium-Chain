//! Real PNP1 production, import, confirmation, restart and process-cut calls.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Output;
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_pon_node::native_owner_journal::{
    JournalCheckpoint, JournalMakeRequest, JournaledNativeOwner, NativeJournalOptions,
};
use trnm_pon_node::{development_public, Error, Packet, Result, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const CRASH_EXIT: i32 = 23;
const NOW: u64 = 100;
const FUTURE: u64 = 100_000;

#[derive(Serialize, Deserialize)]
struct CrashPlan {
    store: PathBuf,
    journal: PathBuf,
    checkpoint: JournalCheckpoint,
    packets: Vec<PathBuf>,
    target: Hash,
}

fn options(pin: Option<JournalCheckpoint>) -> NativeJournalOptions {
    NativeJournalOptions {
        observed_now: NOW,
        expected_checkpoint: pin,
        ..NativeJournalOptions::default()
    }
}
fn open(root: &Path, label: &str, pin: Option<JournalCheckpoint>) -> Result<JournaledNativeOwner> {
    JournaledNativeOwner::open(
        &root.join(format!("{label}-store")),
        &root.join(format!("{label}-journal")),
        Settings::development(Some(1))?,
        options(pin),
    )
}
fn make(
    node: &mut JournaledNativeOwner,
    parent: Hash,
    timestamp: u64,
    miner: u64,
    transactions: Vec<Vec<u8>>,
) -> Result<Packet> {
    node.make(
        JournalMakeRequest {
            parent,
            transactions,
            miner: development_public(miner)?,
            timestamp,
            max_attempts: 4096,
        },
        NOW,
    )
}
fn signed_transfer(settings: &Settings) -> Result<Vec<u8>> {
    let mut payload = development_public(1)?.to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0)?,
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
        .map_err(|e| Error::from(format!("JOURNAL_TEST_KEY:{e:?}")))?;
    transaction.signature = hex::decode(sign_hex(
        &key,
        &transaction
            .signing_digest()
            .map_err(|e| Error::from(format!("JOURNAL_TEST_SIGN:{e:?}")))?,
    ))
    .map_err(|e| Error::from(format!("JOURNAL_TEST_HEX:{e}")))?
    .try_into()
    .map_err(|_| "JOURNAL_TEST_SIGNATURE")?;
    transaction
        .encode()
        .map_err(|e| Error::from(format!("JOURNAL_TEST_TRANSACTION:{e:?}")))
}
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        } else {
            return Err("JOURNAL_TEST_COPY_SPECIAL_FILE".into());
        }
    }
    Ok(())
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Execute only in an actual child process. No terminal observation is written
/// after native activation succeeds; process exit releases the real owner lock.
pub fn crash_child(plan_path: &Path) -> Result<()> {
    let plan: CrashPlan = serde_json::from_slice(&fs::read(plan_path)?)?;
    let mut owner = JournaledNativeOwner::open(
        &plan.store,
        &plan.journal,
        Settings::development(Some(1))?,
        options(Some(plan.checkpoint)),
    )?;
    for path in &plan.packets {
        owner.admit(&Packet::decode(&fs::read(path)?)?, NOW)?;
    }
    let pending = owner.begin_activation(plan.target, NOW)?;
    if !pending.native_succeeded() {
        return Err("JOURNAL_TEST_NATIVE_ACTIVATION_FAILED".into());
    }
    println!(
        "{}",
        json!({"native_activation_returned_success":true,"intent_sequence":pending.intent_sequence(),
        "terminal_observation_written":false,"exit_after_native_commit":true})
    );
    std::io::stdout().flush()?;
    std::process::exit(CRASH_EXIT)
}

/// The caller supplies only a child launcher, never a Node reference or native
/// success claim. Every substantive success is read from the actual process.
pub fn run(root: &Path, spawn_crash: impl FnOnce(&Path) -> Result<Output>) -> Result<Value> {
    fs::create_dir(root)?;
    let root = root.canonicalize()?;
    let settings = Settings::development(Some(1))?;
    let genesis = settings.genesis();
    let transaction = signed_transfer(&settings)?;
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut alice = open(&root, "alice", None)?;
    let mut bob = open(&root, "bob", None)?;
    let mut alice_packets = Vec::new();
    let mut tip = genesis;
    for height in 1..=7 {
        let packet = make(
            &mut alice,
            tip,
            height * 10 + 1,
            0,
            if height == 1 {
                vec![transaction.clone()]
            } else {
                vec![]
            },
        )?;
        tip = alice.admit(&packet, NOW)?;
        alice.activate_observed(tip, NOW)?;
        alice_packets.push(packet);
    }
    let target_block = alice_packets[0].id()?;
    let a7 = tip;
    let confirmation = alice.confirmation(transaction_id, target_block, NOW)?;
    if !confirmation.confirmed {
        return Err("JOURNAL_TEST_SIX_SUCCESSORS".into());
    }
    let before_hidden = serde_json::to_value(alice.observe(NOW)?)?;
    let mut bob_packets = Vec::new();
    tip = genesis;
    for height in 1..=8 {
        let packet = make(&mut bob, tip, height * 10 + 2, 2, vec![])?;
        tip = bob.admit(&packet, NOW)?;
        bob.activate_observed(tip, NOW)?;
        bob_packets.push(packet);
    }
    let b8 = tip;
    let after_hidden = serde_json::to_value(alice.observe(NOW)?)?;
    if before_hidden["local_view_commitment"] != after_hidden["local_view_commitment"] {
        return Err("JOURNAL_TEST_PRIVATE_REMOTE_CHANGED_VIEW".into());
    }
    // A complete actual producer output is retained while still unadmitted,
    // then imported after the original owner is dropped and reopened.
    let a8_packet = make(&mut alice, a7, 81, 0, vec![])?;
    let before_restart = alice.status()?;
    let pin = alice.finish(NOW)?;
    write_new(&root.join("alice-before-restart-checkpoint.json"), &pin)?;
    let mut alice = open(&root, "alice", Some(pin))?;
    let after_restart = alice.status()?;
    let a8 = alice.admit(&a8_packet, NOW)?;
    // Import the exact same packet once more: no second block identity/credit.
    alice.admit(&a8_packet, NOW)?;
    let a9_packet = make(&mut alice, a8, 91, 0, vec![])?;
    let a9 = alice.admit(&a9_packet, NOW)?;
    let mut invalid = bob_packets[0].clone();
    invalid.proof[4 + 2 * pon_work::CELLS * 4] ^= 1;
    let invalid_error = alice
        .admit(&invalid, NOW)
        .expect_err("actual invalid product must be refused");
    if !invalid_error.to_string().starts_with("WORK:") {
        return Err("JOURNAL_TEST_INVALID_PRODUCT_KIND".into());
    }
    for packet in &bob_packets {
        alice.admit(packet, NOW)?;
    }
    let tie = alice.activate_observed(bob_packets[6].id()?, NOW)?;
    if tie != a7 {
        return Err("JOURNAL_TEST_TIE_REPLACED".into());
    }
    let selected = alice.activate_observed(b8, NOW)?;
    if selected != b8 {
        return Err("JOURNAL_TEST_REORG_NOT_EXECUTED".into());
    }
    let reorged = alice.confirmation(transaction_id, target_block, NOW)?;
    if !reorged.reorged {
        return Err("JOURNAL_TEST_REORG_NOT_OBSERVED".into());
    }
    let future = make(&mut alice, a9, FUTURE, 0, vec![])?;
    alice
        .admit(&future, NOW)
        .expect_err("future header must be deferred");
    let future_id = alice.admit(&future, FUTURE)?;
    let child = make(&mut alice, future_id, 105, 0, vec![])?;
    let child_id = alice.admit(&child, FUTURE)?;
    alice
        .activate_observed(child_id, NOW)
        .expect_err("future ancestor must be deferred");
    let deferred = serde_json::to_value(alice.observe(NOW)?)?;
    let mature = serde_json::to_value(alice.observe(FUTURE)?)?;
    let alice_status = alice.status()?;
    let alice_pin = alice.finish(FUTURE)?;
    let bob_status = bob.status()?;
    let bob_pin = bob.finish(NOW)?;

    // The crash receiver opens with only A1..A7, so original Node::recover
    // cannot preselect B8 before the specific activation under observation.
    let mut receiver = open(&root, "crash", None)?;
    for packet in &alice_packets {
        let id = receiver.admit(packet, NOW)?;
        receiver.activate_observed(id, NOW)?;
    }
    let crash_confirmation = receiver.confirmation(transaction_id, target_block, NOW)?;
    if !crash_confirmation.confirmed {
        return Err("JOURNAL_TEST_CRASH_REFERENCE".into());
    }
    let crash_before_pin = receiver.finish(NOW)?;
    copy_tree(&root.join("crash-store"), &root.join("old-crash-store"))?;
    copy_tree(&root.join("crash-journal"), &root.join("old-crash-journal"))?;
    let packet_paths = bob_packets
        .iter()
        .map(|packet| {
            let raw = packet.encode()?;
            let digest = crate_digest(&raw);
            Ok(root
                .join("bob-journal")
                .join("packets")
                .join(format!("{digest}.pnp1")))
        })
        .collect::<Result<Vec<_>>>()?;
    let plan_path = root.join("crash-plan.json");
    write_new(
        &plan_path,
        &CrashPlan {
            store: root.join("crash-store"),
            journal: root.join("crash-journal"),
            checkpoint: crash_before_pin.clone(),
            packets: packet_paths,
            target: b8,
        },
    )?;
    let output = spawn_crash(&plan_path)?;
    if output.status.code() != Some(CRASH_EXIT) {
        return Err(format!(
            "JOURNAL_TEST_CHILD_EXIT:{:?}:{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let child_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !child_stdout.contains("\"native_activation_returned_success\":true") {
        return Err("JOURNAL_TEST_CHILD_NATIVE_RESULT".into());
    }
    let mut receiver = open(&root, "crash", Some(crash_before_pin))?;
    let recovered = receiver.status()?;
    if recovered["unresolved_intents"]
        .as_array()
        .is_none_or(Vec::is_empty)
        || recovered["last_census"]["active_tip"] != hex::encode(b8)
    {
        return Err("JOURNAL_TEST_GAP_WAS_ERASED".into());
    }
    let crash_reorged = receiver.confirmation(transaction_id, target_block, NOW)?;
    if !crash_reorged.reorged {
        return Err("JOURNAL_TEST_CRASH_REORG".into());
    }
    let recovered_pin = receiver.finish(NOW)?;
    write_new(
        &root.join("crash-recovered-checkpoint.json"),
        &recovered_pin,
    )?;

    // Preserve the newest real files, restore an actual earlier DB+sidecar
    // snapshot, and prove the saved external checkpoint refuses that prefix.
    fs::rename(root.join("crash-store"), root.join("recovered-crash-store"))?;
    fs::rename(
        root.join("crash-journal"),
        root.join("recovered-crash-journal"),
    )?;
    copy_tree(&root.join("old-crash-store"), &root.join("crash-store"))?;
    copy_tree(&root.join("old-crash-journal"), &root.join("crash-journal"))?;
    let stale = open(&root, "crash", Some(recovered_pin.clone()));
    let stale_error = match stale {
        Ok(_) => return Err("JOURNAL_TEST_ROLLBACK_PIN_ACCEPTED".into()),
        Err(error) => error.to_string(),
    };
    if stale_error != "OWNER_JOURNAL_CHECKPOINT" {
        return Err(format!("JOURNAL_TEST_WRONG_PIN_REFUSAL:{stale_error}").into());
    }
    // With no external pin, an internally consistent old world can be opened.
    // It still has no fresh-state, history-authentication or security authority.
    let unpinned = open(&root, "crash", None)?;
    let unpinned_status = unpinned.status()?;
    if unpinned_status["fresh_resource_state_attested"] != false
        || unpinned_status["trusted_history_anchor"] != false
    {
        return Err("JOURNAL_TEST_UNPINNED_ESCALATION".into());
    }
    let unpinned_checkpoint = unpinned.finish(NOW)?;
    // A real producer finishes, its exact packet bytes reach the sidecar, but
    // the terminal record budget is exhausted. Reopen inventories the orphan
    // without pretending there was a complete production observation.
    let mut orphan = JournaledNativeOwner::open(
        &root.join("orphan-store"),
        &root.join("orphan-journal"),
        settings.clone(),
        NativeJournalOptions {
            maximum_records: 5,
            ..options(None)
        },
    )?;
    let orphan_before_pin = orphan.checkpoint()?;
    let orphan_error = make(&mut orphan, genesis, 13, 3, vec![])
        .expect_err("terminal budget must refuse a completed production observation");
    if orphan_error.to_string() != "OWNER_JOURNAL_RECORD_BUDGET" {
        return Err("JOURNAL_TEST_ORPHAN_BUDGET".into());
    }
    drop(orphan);
    let mut orphan = open(&root, "orphan", Some(orphan_before_pin))?;
    let orphan_before_admit = orphan.status()?;
    let orphan_artifacts = orphan_before_admit["orphan_artifacts_at_open"]
        .as_array()
        .ok_or("JOURNAL_TEST_ORPHAN")?;
    if orphan_artifacts.len() != 1
        || !orphan_before_admit["registry"]
            .as_object()
            .ok_or("JOURNAL_TEST_ORPHAN")?
            .is_empty()
    {
        return Err("JOURNAL_TEST_ORPHAN_INVENTORY".into());
    }
    let orphan_path = root.join("orphan-journal").join(
        orphan_artifacts[0]["path"]
            .as_str()
            .ok_or("JOURNAL_TEST_ORPHAN")?,
    );
    let orphan_packet = Packet::decode(&fs::read(orphan_path)?)?;
    let orphan_id = orphan.admit(&orphan_packet, NOW)?;
    let orphan_after_admit = orphan.status()?;
    if orphan_after_admit["registry"][hex::encode(orphan_id)]["origin_class"]
        != "gap_or_recovery_discovery"
    {
        return Err("JOURNAL_TEST_ORPHAN_LAUNDERED".into());
    }
    let orphan_checkpoint = orphan.finish(NOW)?;
    let report = json!({"schema":"pon-native-owner-journal-run-v1",
        "starting_source_commit":"88bce414d7ba7f7f6a60dba03943ee20dc501ed7","native_execution_exercised":true,
        "execution_scope":"actual opt-in owner leases; ordinary PNP1 work, controlled validation clocks; no world-time attestation",
        "journals":[
            {"name":"alice","path":"alice-journal","checkpoint":alice_pin},
            {"name":"bob","path":"bob-journal","checkpoint":bob_pin},
            {"name":"crash_recovered","path":"recovered-crash-journal","checkpoint":recovered_pin},
            {"name":"old_snapshot","path":"old-crash-journal","checkpoint":crash_before_pin_from_plan(&plan_path)?},
            {"name":"restored_without_pin","path":"crash-journal","checkpoint":unpinned_checkpoint},
            {"name":"orphan_recovered","path":"orphan-journal","checkpoint":orphan_checkpoint}],
        "references":{"target_block":hex::encode(target_block),"target_transaction":hex::encode(transaction_id),
            "a7":hex::encode(a7),"a8_before_restart":hex::encode(a8),"a9":hex::encode(a9),
            "b8":hex::encode(b8),"future":hex::encode(future_id),"future_child":hex::encode(child_id)},
        "before_hidden":before_hidden,"after_hidden":after_hidden,
        "before_restart":before_restart,"after_restart":after_restart,
        "deferred":deferred,"mature":mature,"alice_status":alice_status,"bob_status":bob_status,
        "crash_child":{"exit_code":output.status.code(),"stdout":child_stdout,
            "stderr":String::from_utf8_lossy(&output.stderr),"native_result_before_terminal_exit":true},
        "recovered_status":recovered,"unpinned_status":unpinned_status,"stale_checkpoint_refusal":stale_error,
        "orphan_before_admit":orphan_before_admit,"orphan_after_admit":orphan_after_admit,
        "orphan_production_terminal_refusal":orphan_error.to_string(),
        "actual_confirmations":[confirmation,reorged,crash_confirmation,crash_reorged],
        "invalid_same_id_packet":{"id":hex::encode(invalid.id()?),"sha256":crate_digest(&invalid.encode()?),
            "valid_packet_sha256":crate_digest(&bob_packets[0].encode()?),"native_refusal":invalid_error.to_string()},
        "native_runtime_attested":false,"trusted_history_anchor":false,"world_coverage_attested":false,
        "fresh_resource_state_attested":false,"physical_clock_authenticated":false,
        "probabilistic_environment_bound":false,"six_successor_risk_qualified":false,"probability_bound":null});
    write_new(&root.join("run.json"), &report)?;
    Ok(report)
}
fn crate_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
fn crash_before_pin_from_plan(path: &Path) -> Result<JournalCheckpoint> {
    Ok(serde_json::from_slice::<CrashPlan>(&fs::read(path)?)?.checkpoint)
}
