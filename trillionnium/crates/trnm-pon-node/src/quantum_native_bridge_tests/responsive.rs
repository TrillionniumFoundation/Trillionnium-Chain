//! Source-bound responsive CPU execution with explicitly conditional event clocks.
//! Eager scalar proofs are observer work; their outcomes remain hidden until due.
use super::{
    assert_python_source_snapshot, digest, initialize_history, json_new, native_sources,
    native_verify, packet_record, read_bridge_input, read_packet, root, work, write_new,
    CLOCK_ORIGIN, GENESIS_TIME,
};
use crate::{consensus, development_public, maintenance, Node, Packet, Settings};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::Hash;

const SCHEMA: &str = "trnm-w1-native-responsive-execution-v1";
const HORIZON: u64 = 16;

fn hash(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn work_value(value: &Value) -> consensus::Work {
    consensus::Work::from_bytes(
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn uint(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap()
}

#[cfg(unix)]
fn cpu_ns() -> u128 {
    // Safe wrapper from the already pinned rustix dependency. Includes this
    // process's threads; spawned children are retained by the outer observer.
    let value = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    assert!(value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec));
    value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128
}

#[cfg(not(unix))]
fn cpu_ns() -> u128 {
    panic!("responsive research requires a process CPU clock")
}

fn nonce(owner: &str, seed: u64, index: u64, parent: Hash) -> u64 {
    let domain = format!("trnm-w1-native-responsive-{owner}-nonce-v1");
    let mut state = Sha256::new();
    state.update(domain.as_bytes());
    state.update([0]);
    state.update(seed.to_le_bytes());
    state.update(index.to_le_bytes());
    state.update(parent);
    u64::from_le_bytes(state.finalize()[..8].try_into().unwrap()) % 8
}

fn now(tick: u64) -> u64 {
    CLOCK_ORIGIN + tick / 4 + 1
}

struct Events {
    rows: Vec<Value>,
    journal: fs::File,
}
impl Events {
    fn push(&mut self, tick: u64, kind: &str, mut row: Value) {
        row["event_index"] = json!(self.rows.len());
        row["tick"] = json!(tick);
        row["kind"] = json!(kind);
        self.journal
            .write_all(&serde_json::to_vec(&row).unwrap())
            .unwrap();
        self.journal.write_all(b"\n").unwrap();
        self.journal.sync_data().unwrap();
        self.rows.push(row);
    }
}

struct Attempt {
    id: String,
    owner: &'static str,
    start: u64,
    due: u64,
    parent: Hash,
    nonce: Option<u64>,
    packet: Option<Packet>,
    row: Option<Value>,
    winner: Option<bool>,
    proof_stage: bool,
    inventory: Value,
}

struct AttemptSpec {
    owner: &'static str,
    seed: u64,
    index: u64,
    parent: Hash,
    start: u64,
    duration: u64,
    advised: bool,
    opaque: bool,
}

fn begin_attempt(
    node: &mut Node,
    base: &Value,
    directory: &Path,
    spec: AttemptSpec,
    block_work: &BTreeMap<Hash, consensus::Work>,
) -> Attempt {
    let AttemptSpec {
        owner,
        seed,
        index,
        parent,
        start,
        duration,
        advised,
        opaque,
    } = spec;
    assert!(duration > 0);
    let id = format!("{owner}-{index}");
    let due = start.checked_add(duration).unwrap();
    if opaque {
        assert!(due > HORIZON, "QUANTUM_SAMPLER_UNIMPLEMENTED");
        return Attempt {
            id: id.clone(),
            owner,
            start,
            due,
            parent,
            nonce: None,
            packet: None,
            row: None,
            winner: None,
            proof_stage: false,
            inventory: json!({"attempt_id":id,"owner":owner,"observer_candidate_generated":false,
                "reason":"candidate check cannot complete within the declared horizon",
                "preparation_elapsed_ns":0,"proof_elapsed_ns":0,"verification_elapsed_ns":0,
                "preparation_cpu_ns":0,"proof_cpu_ns":0,"verification_cpu_ns":0}),
        };
    }
    let mut chosen = nonce(owner, seed, index, parent);
    if advised {
        assert_eq!(owner, "private");
        let context = base["contexts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| hash(&x["parent_id"]) == parent)
            .unwrap();
        if let Some(first) = context["winner_children"].as_array().unwrap().first() {
            chosen = uint(first, "nonce");
        }
    }
    let preparation = Instant::now();
    let preparation_cpu = cpu_ns();
    let parent_header = node.packet(parent).unwrap().header;
    let timestamp = if owner == "private" {
        GENESIS_TIME + parent_header.height + 1
    } else {
        (parent_header.timestamp + 1).max(now(start))
    };
    let (a, b) = maintenance();
    let candidate = node
        .prepare_from_matrices(
            parent,
            vec![],
            development_public(if owner == "private" { 1 } else { 0 }).unwrap(),
            timestamp,
            &a,
            &b,
        )
        .unwrap();
    assert_eq!(
        candidate.header.target,
        node.expected_target(parent).unwrap()
    );
    let preparation_elapsed_ns = preparation.elapsed().as_nanos();
    let preparation_cpu_ns = cpu_ns() - preparation_cpu;
    let mut header = candidate.header;
    header.nonce = chosen;
    let proof = Instant::now();
    let proof_cpu = cpu_ns();
    let packet = Packet {
        proof: candidate.prepared.prove(header.challenge()).unwrap(),
        header,
        transactions: candidate.transactions,
    };
    let proof_elapsed_ns = proof.elapsed().as_nanos();
    let proof_cpu_ns = cpu_ns() - proof_cpu;
    let verification = Instant::now();
    let verification_cpu = cpu_ns();
    let verdict = native_verify(&packet);
    let winner = verdict.is_ok();
    if let Err(ref error) = verdict {
        assert_eq!(*error, pon_work::WorkError::Target);
    }
    let verification_elapsed_ns = verification.elapsed().as_nanos();
    let verification_cpu_ns = cpu_ns() - verification_cpu;
    let credit = block_work[&parent]
        .checked_add(consensus::required_work(packet.header.target).unwrap())
        .unwrap();
    let mut row = packet_record(&packet, credit, directory);
    row["complete_native_proof_generated"] = json!(true);
    row["native_winner"] = json!(winner);
    row["native_verifier_error"] = json!(verdict.err().map(|e| format!("{e:?}")));
    let inventory = json!({"attempt_id":id,"owner":owner,"observer_candidate_generated":true,"packet":row,
        "preparation_elapsed_ns":preparation_elapsed_ns,"proof_elapsed_ns":proof_elapsed_ns,
        "verification_elapsed_ns":verification_elapsed_ns,"preparation_cpu_ns":preparation_cpu_ns,
        "proof_cpu_ns":proof_cpu_ns,"verification_cpu_ns":verification_cpu_ns,
        "outcome_hidden_until_candidate_due":true,"observer_advice":advised});
    Attempt {
        id,
        owner,
        start,
        due,
        parent,
        nonce: Some(chosen),
        packet: Some(packet),
        row: Some(row),
        winner: Some(winner),
        proof_stage: false,
        inventory,
    }
}

fn start_event(events: &mut Events, attempt: &Attempt) {
    events.push(attempt.start, if attempt.owner == "honest" {"honest-start"} else {"private-start"},
        json!({"attempt_id":attempt.id,"owner":attempt.owner,"parent_id":hex::encode(attempt.parent),
            "nonce":attempt.nonce,"start_tick":attempt.start,"due_tick":attempt.due,
            "observer_candidate_generated":attempt.packet.is_some()}));
}

fn completion_event(events: &mut Events, attempt: &Attempt, tick: u64, kind: &str) {
    events.push(
        tick,
        kind,
        json!({"attempt_id":attempt.id,"owner":attempt.owner,"packet":attempt.row,
        "native_winner":attempt.winner,"proof_elapsed_ns":attempt.inventory["proof_elapsed_ns"],
        "verification_elapsed_ns":attempt.inventory["verification_elapsed_ns"],
        "actual_cost_reference":attempt.id,"actual_cost_counted_once_in_attempt_inventory":true}),
    );
}

struct Delivery {
    due: u64,
    owner: &'static str,
    packet: Packet,
    row: Value,
    sequence: u64,
}
struct Notification {
    due: u64,
    generation: u64,
    tip: Hash,
    visible_count: usize,
}

fn ancestry(node: &Node, genesis: Hash) -> Vec<String> {
    let mut id = node.read_active().unwrap().0;
    let mut result = Vec::new();
    for _ in 0..128 {
        result.push(hex::encode(id));
        if id == genesis {
            return result;
        }
        id = node.packet(id).unwrap().header.parent;
    }
    panic!("bounded responsive ancestry exhausted");
}

fn endpoint_metrics(
    ever_replacement: bool,
    private_ids: &BTreeSet<String>,
    final_path: &[String],
    initial_tip: &str,
) -> Value {
    assert!(!final_path.is_empty());
    json!({"ever_private_replacement":ever_replacement,
        "private_tip_at_horizon":private_ids.contains(&final_path[0]),
        "private_ancestor_at_horizon":final_path.iter().any(|id|private_ids.contains(id)),
        "ancestor_includes_tip":true,
        "initial_public_block_orphaned_at_horizon":!final_path.iter().any(|id|id==initial_tip)})
}

fn run_one(
    directory: &Path,
    base: &Value,
    plan: &Value,
    config: &Value,
    run_index: usize,
) -> Value {
    let wall = Instant::now();
    let cpu = cpu_ns();
    let temporary = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
    let genesis = settings.genesis();
    let receiver_path = temporary.path().join("receiver");
    let mut receiver =
        Node::open_with_authenticated_state(&receiver_path, settings.clone(), 1).unwrap();
    let mut honest =
        Node::open_with_authenticated_state(&temporary.path().join("honest"), settings.clone(), 1)
            .unwrap();
    let mut private =
        Node::open_with_authenticated_state(&temporary.path().join("private"), settings.clone(), 1)
            .unwrap();
    let history_times = json!({"receiver_elapsed_ns":initialize_history(&mut receiver,directory,base),
        "honest_elapsed_ns":initialize_history(&mut honest,directory,base),
        "private_elapsed_ns":initialize_history(&mut private,directory,base)});
    let initial_tip = receiver.read_active().unwrap().0;
    let mut block_work = BTreeMap::new();
    block_work.insert(genesis, consensus::Work::default());
    for row in base["prefix"]["packets"]
        .as_array()
        .unwrap()
        .iter()
        .chain(std::iter::once(&base["public_tip"]))
    {
        block_work.insert(hash(&row["block_id"]), work_value(&row["chainwork_hex"]));
    }
    let mut private_parent = hash(&base["prefix"]["tip_id"]);
    let journal_name = format!("responsive-run-{run_index}.jsonl");
    let mut events = Events {
        rows: Vec::new(),
        journal: fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(&journal_name))
            .unwrap(),
    };
    let mut honest_pending: Option<Attempt> = None;
    let mut private_pending: Option<Attempt> = None;
    let mut inventory = Vec::new();
    let mut honest_started = 0;
    let mut private_started = 0;
    let mut deliveries: Vec<Delivery> = Vec::new();
    let mut notifications: Vec<Notification> = Vec::new();
    let mut visible_packets: Vec<Packet> = Vec::new();
    let mut honest_visible = 0;
    let mut generation = 0;
    let mut delivery_sequence = 0;
    let mut held = Vec::new();
    let mut published = false;
    let mut private_ids = BTreeSet::new();
    let mut ever_replacement = false;
    let seed = uint(config, "seed");
    let clock = &config["private_clock"];
    let advised = config["policy"] == "observer-advice-private-winning-path-v1";
    let quantum = config["execution_kind"] == "constructed-quantum";
    let q = uint(config, "iterations");
    let candidate_ticks = uint(clock, "candidate_check_ticks");
    let proof_ticks = uint(clock, "winner_proof_ticks");
    let propagation_ticks = uint(clock, "per_block_propagation_ticks");
    assert!(candidate_ticks > 0 && proof_ticks > 0 && propagation_ticks > 0);
    if quantum && q > 0 {
        assert!(candidate_ticks > HORIZON, "QUANTUM_SAMPLER_UNIMPLEMENTED");
    }
    for tick in 0..=HORIZON {
        if honest_pending.as_ref().is_some_and(|x| x.due == tick) {
            let attempt = honest_pending.take().unwrap();
            completion_event(&mut events, &attempt, tick, "honest-complete");
            if attempt.winner == Some(true) {
                delivery_sequence += 1;
                let due = tick + uint(plan, "honest_delivery_ticks");
                events.push(tick,"delivery-queued",json!({"owner":"honest","attempt_id":attempt.id,"block_id":attempt.row.as_ref().unwrap()["block_id"],"due_tick":due}));
                deliveries.push(Delivery {
                    due,
                    owner: "honest",
                    packet: attempt.packet.unwrap(),
                    row: attempt.row.unwrap(),
                    sequence: delivery_sequence,
                });
            }
        }
        deliveries.sort_by_key(|x| (x.due, usize::from(x.owner != "honest"), x.sequence));
        while deliveries.first().is_some_and(|x| x.due == tick) {
            let delivery = deliveries.remove(0);
            let selected_before = receiver.read_active().unwrap().0;
            let work_before = work(&receiver);
            let stage = Instant::now();
            let stage_cpu = cpu_ns();
            let id = receiver.admit(&delivery.packet, now(tick)).unwrap();
            let selected_after = receiver.activate_observed(id, now(tick)).unwrap();
            let credit = work_value(&delivery.row["chainwork_hex"]);
            block_work.insert(id, credit);
            let replacement = delivery.owner == "private"
                && selected_after == id
                && !private_ids.contains(&hex::encode(selected_before));
            ever_replacement |= replacement;
            events.push(tick,"receiver-admit",json!({"owner":delivery.owner,"packet":delivery.row,
                "selected_before":hex::encode(selected_before),"selected_after":hex::encode(selected_after),
                "selected_work_before_hex":hex::encode(work_before.bytes()),"selected_work_after_hex":hex::encode(work(&receiver).bytes()),
                "private_replacement":replacement,"admit_activate_elapsed_ns":stage.elapsed().as_nanos(),
                "admit_activate_cpu_ns":cpu_ns()-stage_cpu,"logical_observed_now":now(tick)}));
            visible_packets.push(delivery.packet);
            if selected_before != selected_after {
                generation += 1;
                let due = tick + uint(plan, "honest_tip_notification_ticks");
                notifications.push(Notification {
                    due,
                    generation,
                    tip: selected_after,
                    visible_count: visible_packets.len(),
                });
                events.push(tick,"honest-notification-queued",json!({"generation":generation,"selected_tip":hex::encode(selected_after),"due_tick":due,"visible_packet_count":visible_packets.len()}));
            }
        }
        while notifications.first().is_some_and(|x| x.due == tick) {
            let notification = notifications.remove(0);
            let old = honest.read_active().unwrap().0;
            let stage = Instant::now();
            let stage_cpu = cpu_ns();
            let mut delivered = Vec::new();
            for packet in &visible_packets[honest_visible..notification.visible_count] {
                let id = honest.admit(packet, now(tick)).unwrap();
                honest.activate_observed(id, now(tick)).unwrap();
                delivered.push(hex::encode(id));
            }
            honest_visible = notification.visible_count;
            let new = honest.read_active().unwrap().0;
            assert_eq!(new, notification.tip);
            events.push(tick,"honest-notify",json!({"generation":notification.generation,"selected_tip":hex::encode(notification.tip),
                "old_view_tip":hex::encode(old),"new_view_tip":hex::encode(new),"delivered_packet_ids":delivered,
                "admit_activate_elapsed_ns":stage.elapsed().as_nanos(),"admit_activate_cpu_ns":cpu_ns()-stage_cpu}));
            if honest_pending.as_ref().is_some_and(|x| x.parent != new) {
                let attempt = honest_pending.take().unwrap();
                events.push(tick,"honest-cancel",json!({"attempt_id":attempt.id,"owner":"honest","old_parent_id":hex::encode(attempt.parent),
                    "new_parent_id":hex::encode(new),"start_tick":attempt.start,"cancel_tick":tick,"due_tick":attempt.due,
                    "charged_elapsed_ticks":tick-attempt.start,"reserved_ticks":attempt.due-attempt.start,"packet":attempt.row,
                    "proof_elapsed_ns":attempt.inventory["proof_elapsed_ns"],"verification_elapsed_ns":attempt.inventory["verification_elapsed_ns"],
                    "actual_cost_reference":attempt.id,"actual_eager_cost_charged_in_full":true}));
            }
        }
        if private_pending.as_ref().is_some_and(|x| x.due == tick) {
            let mut attempt = private_pending.take().unwrap();
            if !attempt.proof_stage {
                completion_event(&mut events, &attempt, tick, "private-check");
                if attempt.winner == Some(true) {
                    attempt.proof_stage = true;
                    attempt.due = tick + proof_ticks;
                    events.push(tick,"private-proof-start",json!({"owner":"private","attempt_id":attempt.id,"start_tick":tick,"due_tick":attempt.due,"model_phase_only":true}));
                    private_pending = Some(attempt);
                }
            } else {
                completion_event(&mut events, &attempt, tick, "private-complete");
                let packet = attempt.packet.unwrap();
                let row = attempt.row.unwrap();
                let start = Instant::now();
                let cost = cpu_ns();
                let id = private.admit(&packet, now(tick)).unwrap();
                private.activate_observed(id, now(tick)).unwrap();
                private_parent = id;
                private_ids.insert(hex::encode(id));
                block_work.insert(id, work_value(&row["chainwork_hex"]));
                events.push(tick,"private-producer-admit",json!({"owner":"private","block_id":hex::encode(id),"admit_activate_elapsed_ns":start.elapsed().as_nanos(),"admit_activate_cpu_ns":cpu_ns()-cost}));
                held.push((packet, row));
            }
        }
        if private_pending.is_none() && private_started == 2 && !published {
            published = true;
            for (index, (packet, row)) in held.drain(..).enumerate() {
                let due = tick + propagation_ticks * (index as u64 + 1);
                delivery_sequence += 1;
                events.push(tick,"delivery-queued",json!({"owner":"private","block_id":row["block_id"],"due_tick":due,"publication_policy":"after-two-attempts-parent-first"}));
                deliveries.push(Delivery {
                    due,
                    owner: "private",
                    packet,
                    row,
                    sequence: delivery_sequence,
                });
            }
        }
        if tick == HORIZON {
            break;
        }
        if private_pending.is_none() && private_started < 2 {
            let opaque = candidate_ticks > HORIZON - tick;
            let attempt = begin_attempt(
                &mut private,
                base,
                directory,
                AttemptSpec {
                    owner: "private",
                    seed,
                    index: private_started,
                    parent: private_parent,
                    start: tick,
                    duration: candidate_ticks,
                    advised,
                    opaque,
                },
                &block_work,
            );
            start_event(&mut events, &attempt);
            inventory.push(attempt.inventory.clone());
            private_started += 1;
            private_pending = Some(attempt);
        }
        if honest_pending.is_none() && honest_started < uint(plan, "max_honest_attempts") {
            let parent = honest.read_active().unwrap().0;
            let attempt = begin_attempt(
                &mut honest,
                base,
                directory,
                AttemptSpec {
                    owner: "honest",
                    seed,
                    index: honest_started,
                    parent,
                    start: tick,
                    duration: uint(plan, "honest_attempt_ticks"),
                    advised: false,
                    opaque: false,
                },
                &block_work,
            );
            start_event(&mut events, &attempt);
            inventory.push(attempt.inventory.clone());
            honest_started += 1;
            honest_pending = Some(attempt);
        }
    }
    for attempt in [honest_pending, private_pending].into_iter().flatten() {
        events.push(HORIZON,"attempt-censored",json!({"owner":attempt.owner,"attempt_id":attempt.id,"start_tick":attempt.start,
            "due_tick":attempt.due,"phase":if attempt.proof_stage {"winner-proof"} else {"candidate"},
            "charged_elapsed_ticks":HORIZON-attempt.start,"packet":attempt.row,
            "actual_cost_reference":attempt.id,"all_observed_cpu_costs_retained":true}));
    }
    let final_tip = receiver.read_active().unwrap().0;
    let final_work = work(&receiver);
    let final_path = ancestry(&receiver, genesis);
    let final_stats = receiver.stats().unwrap();
    drop(receiver);
    let reopened = Node::open_with_authenticated_state(&receiver_path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap().0, final_tip);
    assert_eq!(work(&reopened), final_work);
    assert_eq!(ancestry(&reopened, genesis), final_path);
    let pending_deliveries: Vec<_> = deliveries
        .iter()
        .map(|x| json!({"owner":x.owner,"due_tick":x.due,"packet":x.row}))
        .collect();
    let pending_notifications: Vec<_> = notifications.iter().map(|x|json!({"generation":x.generation,"due_tick":x.due,"selected_tip":hex::encode(x.tip),"visible_packet_count":x.visible_count})).collect();
    let metrics = endpoint_metrics(
        ever_replacement,
        &private_ids,
        &final_path,
        &hex::encode(initial_tip),
    );
    drop(events.journal);
    let journal = read_bridge_input(&directory.join(&journal_name));
    json!({"run_id":config["run_id"],"policy":config["policy"],"seed":seed,"configuration":config,
        "events":events.rows,"attempt_inventory":inventory,"initial_tip":hex::encode(initial_tip),
        "initial_public_block_id":hex::encode(initial_tip),"final_tip":hex::encode(final_tip),"reopened_tip":hex::encode(reopened.read_active().unwrap().0),
        "final_chainwork_hex":hex::encode(final_work.bytes()),"final_ancestry_ids":final_path,"reopened_ancestry_ids":ancestry(&reopened,genesis),
        "private_winning_block_ids":private_ids,"metrics":metrics,"final_stats":final_stats,
        "honest_attempts_started":honest_started,"private_attempts_started":private_started,
        "pending_deliveries":pending_deliveries,"pending_notifications":pending_notifications,
        "event_journal_file":journal_name,"event_journal_sha256":digest(&journal),"event_journal_bytes":journal.len(),
        "history_replay":history_times,"cpu_receipt":{"process_cpu_ns":cpu_ns()-cpu,"wall_ns":wall.elapsed().as_nanos(),
            "scope":"three actual Nodes, all eager scalar proofs including canceled work, event ledger, delivery, notify and reopen; excludes outer source census and later report serialization; process clock excludes children",
            "eager_observer_work_is_literal_interrupted_miner":false,"exclusive_machine_calibration":false}})
}

fn python_receipt(directory: &Path, argument: &str, stem: &str) -> Value {
    let python = std::env::var_os("TRNM_RESEARCH_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(python)
        .arg(root().join("formal/pon-nakamoto-v1/experiments/w1_native_responsive.py"))
        .arg(argument)
        .arg(directory)
        .output()
        .unwrap();
    write_new(&directory.join(format!("{stem}.stdout")), &output.stdout);
    write_new(&directory.join(format!("{stem}.stderr")), &output.stderr);
    assert!(
        output.status.success(),
        "responsive reader refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn responsive_nonce_domains_and_ancestry_metrics_are_distinct() {
    let parent = [7; 32];
    assert_eq!(nonce("honest", 9, 0, parent), 4);
    assert_eq!(nonce("private", 9, 0, parent), 1);
    let private = BTreeSet::from(["private-parent".to_string()]);
    let path = [
        "honest-child".to_string(),
        "private-parent".to_string(),
        "genesis".to_string(),
    ];
    let result = endpoint_metrics(true, &private, &path, "original-public");
    assert_eq!(result["private_tip_at_horizon"], false);
    assert_eq!(result["private_ancestor_at_horizon"], true);
    assert_eq!(result["initial_public_block_orphaned_at_horizon"], true);
    let recovered = [
        "honest-child".to_string(),
        "original-public".to_string(),
        "genesis".to_string(),
    ];
    let result = endpoint_metrics(true, &private, &recovered, "original-public");
    assert_eq!(result["ever_private_replacement"], true);
    assert_eq!(result["private_ancestor_at_horizon"], false);
    assert_eq!(result["initial_public_block_orphaned_at_horizon"], false);
}

#[test]
#[ignore = "explicit source-bound live-response native miner research with conditional clocks"]
fn execute_source_bound_native_responsive_miners() {
    let directory = PathBuf::from(std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR").unwrap());
    let source = native_sources();
    let base_raw = read_bridge_input(&directory.join("native-fixture.json"));
    let base: Value = serde_json::from_slice(&base_raw).unwrap();
    assert_eq!(base["native_source"], source);
    let plan_raw = read_bridge_input(&directory.join("responsive-plan.json"));
    let plan: Value = serde_json::from_slice(&plan_raw).unwrap();
    assert_eq!(plan["schema"], "trnm-w1-native-responsive-plan-v1");
    assert_eq!(uint(&plan, "horizon_ticks"), HORIZON);
    assert_eq!(plan["tick_seconds"], json!({"numerator":1,"denominator":4}));
    let verification = python_receipt(
        &directory,
        "--verify-plan",
        "native-responsive-plan-verifier",
    );
    assert_eq!(verification["status"], "VERIFIED");
    assert_eq!(
        verification["verified_inputs"]["responsive-plan.json"],
        digest(&plan_raw)
    );
    assert_eq!(
        verification["verified_inputs"]["native-fixture.json"],
        digest(&base_raw)
    );
    assert_python_source_snapshot(&verification["source_snapshot"], &source["git_head"]);
    let mut runs = Vec::new();
    for (index, config) in plan["runs"].as_array().unwrap().iter().enumerate() {
        runs.push(run_one(&directory, &base, &plan, config, index));
    }
    assert_eq!(source, native_sources());
    assert_eq!(
        plan_raw,
        read_bridge_input(&directory.join("responsive-plan.json"))
    );
    assert_eq!(
        base_raw,
        read_bridge_input(&directory.join("native-fixture.json"))
    );
    let report = json!({"schema":SCHEMA,"plan":plan,"plan_sha256":digest(&plan_raw),"native_source":source,
        "base_fixture_file_sha256":digest(&base_raw),"runs":runs,
        "claims":{"responsive_honest_view_executed":true,"complete_native_candidate_proofs":true,
            "all_canceled_observer_cpu_costs_retained":true,"native_daa_timestamps_work_and_reopen_checked":true,
            "model_time_is_physical_time":false,"live_public_network_executed":false,"physical_hardware_calibrated":false,
            "native_probabilities_certified_by_reduced_model":false,"quantum_hardware_executed":false,
            "quantum_mining_qualified":false,"production_activation":false}});
    json_new(&directory.join("native-responsive-execution.json"), &report);
    eprintln!(
        "native_responsive_execution {}",
        json!({"runs":report["runs"].as_array().unwrap().len(),"quantum_hardware_executed":false})
    );
}

#[test]
#[ignore = "independent fresh receiver replay after scalar responsive event and proof verification"]
fn replay_source_bound_native_responsive_miners() {
    let directory = PathBuf::from(std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR").unwrap());
    let source = native_sources();
    let base_raw = read_bridge_input(&directory.join("native-fixture.json"));
    let report_raw = read_bridge_input(&directory.join("native-responsive-execution.json"));
    let base: Value = serde_json::from_slice(&base_raw).unwrap();
    let report: Value = serde_json::from_slice(&report_raw).unwrap();
    assert_eq!(report["schema"], SCHEMA);
    assert_eq!(report["native_source"], source);
    let verification = python_receipt(
        &directory,
        "--verify",
        "native-responsive-independent-verifier",
    );
    assert_eq!(verification["status"], "VERIFIED");
    assert_eq!(
        verification["verified_inputs"]["native-responsive-execution.json"],
        digest(&report_raw)
    );
    assert_eq!(
        verification["verified_inputs"]["native-fixture.json"],
        digest(&base_raw)
    );
    assert_python_source_snapshot(&verification["source_snapshot"], &source["git_head"]);
    let mut results = Vec::new();
    for run in report["runs"].as_array().unwrap() {
        let temporary = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
        let path = temporary.path().join("receiver");
        let mut receiver = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
        initialize_history(&mut receiver, &directory, &base);
        let mut admitted = 0;
        for event in run["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["kind"] == "receiver-admit")
        {
            assert_eq!(
                hex::encode(receiver.read_active().unwrap().0),
                event["selected_before"]
            );
            assert_eq!(
                hex::encode(work(&receiver).bytes()),
                event["selected_work_before_hex"]
            );
            let packet = read_packet(&directory, &event["packet"]);
            native_verify(&packet).unwrap();
            let tick = uint(event, "tick");
            let id = receiver.admit(&packet, now(tick)).unwrap();
            let selected = receiver.activate_observed(id, now(tick)).unwrap();
            assert_eq!(hex::encode(selected), event["selected_after"]);
            assert_eq!(
                hex::encode(work(&receiver).bytes()),
                event["selected_work_after_hex"]
            );
            admitted += 1;
        }
        assert_eq!(
            hex::encode(receiver.read_active().unwrap().0),
            run["final_tip"]
        );
        assert_eq!(
            json!(ancestry(&receiver, settings.genesis())),
            run["final_ancestry_ids"]
        );
        drop(receiver);
        let reopened = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
        assert_eq!(
            hex::encode(reopened.read_active().unwrap().0),
            run["reopened_tip"]
        );
        assert_eq!(
            json!(ancestry(&reopened, settings.genesis())),
            run["reopened_ancestry_ids"]
        );
        results.push(json!({"run_id":run["run_id"],"native_packets_admitted":admitted,"reopen_equal":true,"metrics":run["metrics"]}));
    }
    assert_eq!(source, native_sources());
    assert_eq!(
        report_raw,
        read_bridge_input(&directory.join("native-responsive-execution.json"))
    );
    json_new(
        &directory.join("native-responsive-replay.json"),
        &json!({"schema":"trnm-w1-native-responsive-replay-v1",
        "native_source":source,"verified_execution_sha256":digest(&report_raw),"python_verifier":verification,"runs":results,
        "quantum_hardware_executed":false,"production_activation":false}),
    );
}
