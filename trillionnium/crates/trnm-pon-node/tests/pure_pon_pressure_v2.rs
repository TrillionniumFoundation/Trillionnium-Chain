//! Separate finite pure-PoN v2 qualification. The historical r13 campaign and
//! its failures remain intact. Passing this workload is not unlimited-Sybil
//! fairness, W1 hardness, useful model work, WAN or production qualification.
#[path = "support/pure_receiver_owner_v1.rs"]
mod receiver_owner;
#[path = "support/pure_pressure_v2.rs"]
mod support;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use support::{ATTACKERS, CALL_CAP, ROUNDS, WINDOW_NS};
use trnm_crypto_primitives::pon_work::{self, PreparedTask};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicRequestObserver, PublicServer, Request},
    },
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Header};

const SCHEMA: &str = "pon-pure-pressure-v3";

#[test]
#[ignore = "exact subprocess fixture for the wait4 owner control"]
fn pure_pressure_process_cost_child_entry() {
    let mode = std::env::var("TRNM_PROCESS_COST_CONTROL").unwrap();
    if mode == "wait" {
        thread::sleep(Duration::from_secs(30));
        return;
    }
    if mode == "failure" {
        std::process::exit(7);
    }
    assert_eq!(mode, "complete");
    // Actual child threads and final publication are outside an actor's old
    // entry-to-loop thread interval, but inside its parent's wait4 observation.
    let workers: Vec<_> = (0..2_u64)
        .map(|seed| {
            thread::spawn(move || {
                let mut value = seed;
                for _ in 0..200_000 {
                    value = std::hint::black_box(
                        value.wrapping_mul(6364136223846793005).wrapping_add(1),
                    );
                }
                value
            })
        })
        .collect();
    for worker in workers {
        std::hint::black_box(worker.join().unwrap());
    }
    fs::write(
        std::env::var_os("TRNM_PROCESS_COST_CONTROL_OUTPUT").unwrap(),
        b"final child publication\n",
    )
    .unwrap();
}

#[test]
fn native_actor_wait4_preserves_whole_lifetime_and_single_reap() {
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    for mode in ["complete", "failure", "wait"] {
        let path = temp.path().join(mode);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "pure_pressure_process_cost_child_entry",
                "--ignored",
                "--test-threads=1",
            ])
            .env("TRNM_PROCESS_COST_CONTROL", mode)
            .env("TRNM_PROCESS_COST_CONTROL_OUTPUT", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = support::process_cost::ObservedChild::spawn(&mut command).unwrap();
        let original_pid = child.id();
        let duration = if mode == "wait" {
            Duration::from_millis(20)
        } else {
            Duration::from_secs(5)
        };
        let cost = child.finish(Instant::now() + duration);
        assert_eq!(cost["pid"], original_pid);
        assert_eq!(cost["successful_reaps"], 1);
        assert!(cost["error"].is_null());
        assert!(cost["rusage"]["total_cpu_ns"].is_u64());
        assert_eq!(cost["exit_success"], mode == "complete");
        assert_eq!(cost["parent_forced_kill"], mode == "wait");
        if mode == "complete" {
            assert!(cost["rusage"]["total_cpu_ns"].as_u64().unwrap() > 0);
            assert_eq!(fs::read(path).unwrap(), b"final child publication\n");
        }
        if mode == "failure" {
            assert_eq!(cost["raw_wait_status"], 7 << 8);
        }
        if mode == "wait" {
            assert_eq!(cost["raw_wait_status"].as_i64().unwrap() & 0x7f, 9);
        }
        let duplicate = child.finish(Instant::now());
        assert_eq!(duplicate["successful_reaps"], 0);
        assert!(duplicate["rusage"].is_null());
        assert_eq!(duplicate["error"], "PROCESS_ALREADY_REAPED");
    }
}

#[test]
fn native_child_ownership_probe_distinguishes_live_zombie_and_reaped() {
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let output = std::env::var_os("TRNM_CHILD_OWNERSHIP_CONTROL_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.path().join("ownership-control.json"));
    let mut observations = Vec::new();
    let probe = support::process_cost::child_ownership_probe();
    observations.push(json!({"stage":"initial","probe":probe}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            probe["no_eligible_children_at_probe"], true,
            "initial owner observation: {probe}"
        );
        for mode in ["wait", "failure"] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "pure_pressure_process_cost_child_entry",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env("TRNM_PROCESS_COST_CONTROL", mode)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = support::process_cost::ObservedChild::spawn(&mut command).unwrap();
            if mode == "wait" {
                let live = support::process_cost::child_ownership_probe();
                observations.push(json!({"stage":"live","child_pid":child.id(),"probe":live}));
                assert_eq!(
                    live["waitid_return"], 0,
                    "actual live child must not produce ECHILD: {live}"
                );
                assert_eq!(live["event"]["pid"], 0);
                assert_eq!(live["no_eligible_children_at_probe"], false);
            } else {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let zombie = support::process_cost::child_ownership_probe();
                    observations.push(
                        json!({"stage":"await-zombie","child_pid":child.id(),"probe":zombie}),
                    );
                    assert_eq!(
                        zombie["waitid_return"], 0,
                        "eligible child disappeared before owner reap: {zombie}"
                    );
                    if zombie["event"]["pid"] == child.id() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "child did not produce a retained terminal event"
                    );
                    support::pause();
                }
                let still_zombie = support::process_cost::child_ownership_probe();
                observations.push(json!({"stage":"zombie-still-owned","child_pid":child.id(),"probe":still_zombie}));
                assert_eq!(
                    still_zombie["event"]["pid"],
                    child.id(),
                    "WNOWAIT must not reap the terminal"
                );
                assert_eq!(still_zombie["successful_reaps"], 0);
            }
            let cost = child.finish(if mode == "wait" {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(5)
            });
            observations.push(json!({"stage":"actual-single-wait4","mode":mode,"cost":cost}));
            assert_eq!(cost["successful_reaps"], 1);
            assert!(cost["rusage"]["total_cpu_ns"].is_u64());
            if mode == "failure" {
                assert_eq!(cost["raw_wait_status"], 7 << 8);
            }
            let after = support::process_cost::child_ownership_probe();
            observations.push(json!({"stage":"after-reap","mode":mode,"probe":after}));
            assert_eq!(after["waitid_echild_observed"], true);
            assert_eq!(after["no_eligible_children_at_probe"], true);
        }
    }));
    support::write_new(
        &output,
        &json!({"schema":"pon-child-ownership-native-control-v1","observations":observations,
        "passed":result.is_ok(),"physical_authentication":false,
        "scope":"Actual same-environment live and unreaped-zombie controls prevent treating a fixed ECHILD interception as demonstrated kernel behavior; finite observations are not hostile-host authentication."}),
    );
    assert!(
        result.is_ok(),
        "child ownership control failed; complete observations retained at {}",
        output.display()
    );
}

fn replay(node: &mut Node, packets: &[Packet]) {
    for packet in packets {
        let id = node.admit(packet, support::now()).unwrap();
        node.activate_observed(id, support::now()).unwrap();
    }
}

fn active_position(node: &Node) -> ([u8; 32], u64, u64) {
    // read_active() returns (tip, activation generation, State). A History
    // page can activate several admitted blocks at once, so generation is not
    // block height. Preserve the full state check and query that tip's record.
    let (tip, generation, _) = node.read_active().unwrap();
    (tip, node.parent_height(tip).unwrap(), generation)
}

#[test]
fn native_active_position_keeps_block_height_distinct_from_generation() {
    let temp = tempfile::tempdir().unwrap();
    let settings = support::settings();
    let mut producer =
        Node::open_with_authenticated_state(&temp.path().join("producer"), settings.clone(), 1)
            .unwrap();
    let mut receiver =
        Node::open_with_authenticated_state(&temp.path().join("receiver"), settings.clone(), 1)
            .unwrap();
    let mut tip = producer.active().unwrap().0;
    for height in 1..=3_u64 {
        let packet = producer
            .make_consensus_maintenance(
                tip,
                vec![],
                development_public(0).unwrap(),
                settings.genesis_time() + height * 10,
                4096,
            )
            .unwrap();
        tip = producer.admit(&packet, support::now()).unwrap();
        producer.activate_observed(tip, support::now()).unwrap();
        assert_eq!(receiver.admit(&packet, support::now()).unwrap(), tip);
    }
    // Three real complete blocks, one activation. The former tuple-index
    // shortcut would incorrectly report height one for this receiver.
    receiver.activate_observed(tip, support::now()).unwrap();
    assert_eq!(active_position(&producer), (tip, 3, 3));
    assert_eq!(active_position(&receiver), (tip, 3, 1));
}

#[test]
fn native_call_window_refuses_late_entry_without_extending_deadlines() {
    let epoch = 1_000_000_000;
    let anchor = Instant::now();
    let issued = std::cell::Cell::new(0);
    // Includes the actual failed ARM observation's 102720 ns late entry.
    for started in [
        epoch - 1,
        epoch + WINDOW_NS,
        epoch + WINDOW_NS + 1,
        epoch + WINDOW_NS + 102_720,
    ] {
        assert!(support::phase_entry_ns(epoch, started).is_none());
        let outcome = support::within_call_window(epoch, anchor, started, |_, _, _| {
            issued.set(issued.get() + 1);
        });
        assert!(outcome.is_none());
    }
    assert_eq!(
        issued.get(),
        0,
        "closed windows must not issue the client call"
    );
    for (relative_start, allowance) in [
        (1_000_000_000, 2_000_000_000),
        (WINDOW_NS - 1_000_000_000, 1_000_000_000),
        (WINDOW_NS - 1, 1),
    ] {
        // A later construction or scheduling observation cannot move this
        // deadline. Late outcomes are still returned, never filtered away.
        let later = anchor + Duration::from_secs(3);
        let retained = support::within_call_window(
            epoch,
            anchor,
            epoch + relative_start,
            |deadline, started_ns, deadline_ns| {
                issued.set(issued.get() + 1);
                assert_eq!(deadline, anchor + Duration::from_nanos(allowance));
                assert_eq!(started_ns, relative_start);
                assert_eq!(deadline_ns, relative_start + allowance);
                assert!(deadline < later);
                Err::<(), _>("late client outcome retained")
            },
        );
        assert_eq!(retained, Some(Err("late client outcome retained")));
    }
    assert_eq!(issued.get(), 3);
    // A valid entry may be descheduled until its original allowance is gone.
    // Exercise the real client with that elapsed absolute deadline, without
    // sleeping or needing a peer. The issued failure must remain Some.
    let delayed_anchor = Instant::now().checked_sub(Duration::from_secs(3)).unwrap();
    let (reply, metrics) = support::within_call_window(
        epoch,
        delayed_anchor,
        epoch + 1_000_000_000,
        |deadline, _, _| {
            public_v3::call_public_pure_pon_v2(
                "127.0.0.1:0".parse().unwrap(),
                &Request::Submit {
                    packet: String::new(),
                },
                &support::settings(),
                support::identity(71).public_key(),
                &support::identity(73),
                support::policy(),
                Some(deadline),
            )
        },
    )
    .expect("an issued late error must stay visible");
    assert_eq!(reply.unwrap_err().to_string(), "PUBLIC_CLIENT_DEADLINE");
    assert_eq!(
        metrics.failed_stage,
        Some(public_v3::PublicClientStage::Construction)
    );
    assert_eq!(metrics.challenge_ns, 0);
    assert_eq!(metrics.solution_trials, 0);
    // Exercise the actual wrapper's refusal route as well. Its API is never
    // invoked, so no socket or peer is required for an already closed phase.
    let expired_epoch = support::monotonic().checked_sub(WINDOW_NS).unwrap();
    assert!(support::call(
        "127.0.0.1:0".parse().unwrap(),
        &support::settings(),
        Request::Submit {
            packet: String::new()
        },
        73,
        expired_epoch,
    )
    .is_none());
}

fn prepare(root: &Path, settings: &Settings) -> (Vec<Packet>, Vec<Packet>) {
    let started = Instant::now();
    let cpu = support::thread_cpu();
    let mut miner =
        Node::open_with_authenticated_state(&root.join("miner"), settings.clone(), 1).unwrap();
    let mut seed = Vec::new();
    for block in 0..4_u64 {
        let transactions = (0..256_u64)
            .map(|slot| {
                let nonce = block * 256 + slot + 1;
                support::signed_transfer(
                    settings,
                    nonce,
                    hash(b"pure-pressure-funded-account-v2", &[&nonce.to_le_bytes()]),
                )
            })
            .collect();
        let packet = miner
            .make_consensus_maintenance(
                miner.active().unwrap().0,
                transactions,
                development_public(0).unwrap(),
                settings.genesis_time() + (block + 1) * 10,
                4096,
            )
            .unwrap();
        replay(&mut miner, std::slice::from_ref(&packet));
        seed.push(packet);
    }
    let mut business = Vec::new();
    for index in 0..ROUNDS * 7 {
        let transactions = if index % 7 == 0 {
            vec![support::signed_transfer(
                settings,
                1025 + (index / 7) as u64,
                development_public(1).unwrap(),
            )]
        } else {
            vec![]
        };
        let packet = miner
            .make_consensus_maintenance(
                miner.active().unwrap().0,
                transactions,
                development_public(0).unwrap(),
                settings.genesis_time() + (5 + index as u64) * 10,
                4096,
            )
            .unwrap();
        replay(&mut miner, std::slice::from_ref(&packet));
        business.push(packet);
    }
    support::write_new(
        &root.join("preparation.json"),
        &json!({"schema":SCHEMA,
        "seed_transfers":1024,"seed_blocks":4,"business_blocks":21,
        "thread_cpu_ns":support::cpu_delta(cpu),"wall_ns":started.elapsed().as_nanos(),
        "seed":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "business":business.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>()}),
    );
    (seed, business)
}

fn attack(job: &Value, path: &Path) -> Value {
    let entry_cost = support::ThreadCostBoundary::capture();
    assert_eq!(job["policy"], support::policy_observation());
    let actor = job["actor"].as_u64().unwrap();
    let mode = job["mode"].as_str().unwrap();
    assert!(matches!(mode, "from-zero" | "correct-product-false-trace"));
    let template = Header::decode(&hex::decode(job["header"].as_str().unwrap()).unwrap()).unwrap();
    let transactions: Vec<Vec<u8>> = job["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect();
    let address: SocketAddr = job["address"].as_str().unwrap().parse().unwrap();
    let acquired = Instant::now();
    let acquired_cpu = support::thread_cpu();
    let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
    let prefix = if mode == "from-zero" {
        let mut prefix = b"PNW1".to_vec();
        for matrix in [&a, &b] {
            for value in matrix {
                prefix.extend(value.to_le_bytes());
            }
        }
        prefix.resize(pon_work::PROOF_BYTES - 32, 0);
        prefix
    } else {
        let prepared = PreparedTask::new(&a, &b).unwrap();
        let mut proof = prepared.prove(template.challenge()).unwrap();
        proof.truncate(pon_work::PROOF_BYTES - 32);
        proof
    };
    let acquisition = json!({"thread_cpu_ns":support::cpu_delta(acquired_cpu),
        "wall_ns":acquired.elapsed().as_nanos(),"correct_product_acquired_once":mode!="from-zero",
        "proof_prefix":hex::encode(&prefix)});
    // Preparation and one complete rejection diagnostic happen BEFORE the
    // parent constructs the cold CPU epoch, and are reported separately.
    let mut diagnostic_header = template.clone();
    diagnostic_header.nonce = 10_000_000 + actor * 1_000_000;
    let (diagnostic, diagnostic_generation_trials) =
        support::false_proof(&prefix, &diagnostic_header, 0);
    let diagnostic_cpu = support::thread_cpu();
    let rejection = pon_work::verify(
        diagnostic_header.challenge(),
        diagnostic_header.work_task,
        diagnostic_header.target,
        &diagnostic,
    )
    .unwrap_err();
    let diagnostic_cpu_ns = support::cpu_delta(diagnostic_cpu);
    support::write_new(
        &path.join("ready.json"),
        &json!({"actor":actor,"pid":std::process::id()}),
    );
    let start_path = PathBuf::from(job["start_path"].as_str().unwrap());
    let ready_deadline = Instant::now() + Duration::from_secs(180);
    while !start_path.is_file() {
        assert!(
            Instant::now() < ready_deadline,
            "missing parent start marker"
        );
        support::pause();
    }
    let marker: Value = serde_json::from_slice(&fs::read(start_path).unwrap()).unwrap();
    let epoch = marker["epoch_monotonic_ns"].as_u64().unwrap();
    let settings = support::settings();
    let mut calls = Vec::new();
    let mut cost_ledger = support::AttackerCostLedger::new();
    let loop_entry_cost = support::ThreadCostBoundary::capture();
    let loop_terminal = loop {
        let iteration_gate = support::monotonic();
        if iteration_gate >= epoch + WINDOW_NS || calls.len() >= CALL_CAP {
            break json!({"reason":if iteration_gate>=epoch+WINDOW_NS {
                    "phase_closed_before_preparation"} else {"call_cap"},
                "sequence":calls.len(),"observed_monotonic_ns":iteration_gate});
        }
        let sequence = calls.len() as u64;
        let preparation_begin = support::ThreadCostBoundary::capture();
        let mut header = template.clone();
        header.nonce =
            10_000_000 + actor * 1_000_000 + if mode == "from-zero" { 0 } else { sequence };
        let prepare_start = support::thread_cpu();
        let (proof, trials) = support::false_proof(&prefix, &header, sequence);
        let trace = hex::encode(&proof[proof.len() - 32..]);
        let packet = Packet {
            header: header.clone(),
            transactions: transactions.clone(),
            proof,
        };
        let raw = packet.encode().unwrap();
        let preparation_cpu_ns = support::cpu_delta(prepare_start);
        let preparation_end = support::ThreadCostBoundary::capture();
        let phase_gate = support::monotonic();
        let (call, call_entry) = if phase_gate >= epoch + WINDOW_NS {
            (None, None)
        } else {
            let (call, entry) = support::call_with_entry_observation(
                address,
                &settings,
                Request::Submit {
                    packet: hex::encode(&raw),
                },
                80 + ((actor * 37 + sequence) % 150) as u8,
                epoch,
            );
            (call, Some(entry))
        };
        // Retain the final preparation even if either original phase gate
        // refused to issue its call. This metadata is built after the original
        // call decision, and cannot buy another attempt or a longer deadline.
        let header_hex = hex::encode(header.encode());
        let packet_sha256 = hex::encode(Sha256::digest(&raw));
        cost_ledger.retain(
            json!({"sequence":sequence,"iteration_gate_monotonic_ns":iteration_gate,
                "begin":preparation_begin,"end":preparation_end,
                "phase_gate_monotonic_ns":phase_gate,
                "preparation_thread_cpu_ns":support::thread_cpu_between(preparation_begin,preparation_end),
                "inner_preparation_thread_cpu_ns":preparation_cpu_ns,
                "generation_trials":trials,"header":header_hex,"trace":trace,
                "packet_sha256":packet_sha256}),
            call_entry,
            call.as_ref(),
        );
        let Some(mut row) = call else {
            break json!({"reason":if call_entry.is_some() {
                    "phase_closed_at_call_entry"} else {"phase_closed_after_preparation"},
                "sequence":sequence,"observed_monotonic_ns":call_entry.unwrap_or(phase_gate)});
        };
        row["sequence"] = json!(sequence);
        row["header"] = json!(header_hex);
        row["trace"] = json!(trace);
        row["generation_trials"] = json!(trials);
        row["preparation_thread_cpu_ns"] = json!(preparation_cpu_ns);
        row["packet_sha256"] = json!(packet_sha256);
        calls.push(row);
    };
    let loop_exit_cost = support::ThreadCostBoundary::capture();
    let result = json!({"actor":actor,"pid":std::process::id(),"mode":mode,"acquisition":acquisition,
        "diagnostic_rejection":format!("{rejection:?}"),"diagnostic_thread_cpu_ns":diagnostic_cpu_ns,
        "policy":support::policy_observation(),"calls":calls,"attempt_cap_reached":calls.len()==CALL_CAP,
        "finished_ns":support::monotonic().saturating_sub(epoch)});
    let mut cost = cost_ledger.into_value();
    cost["actor"] = json!(actor);
    cost["pid"] = json!(std::process::id());
    cost["owner_thread"] = json!(format!("{:?}", thread::current().id()));
    cost["mode"] = json!(mode);
    cost["policy"] = support::policy_observation();
    cost["epoch_monotonic_ns"] = json!(epoch);
    cost["window_ns"] = json!(WINDOW_NS);
    cost["actor_call_cap"] = json!(CALL_CAP);
    cost["entry"] = json!(entry_cost);
    cost["loop_entry"] = json!(loop_entry_cost);
    cost["loop_exit"] = json!(loop_exit_cost);
    cost["loop_terminal"] = loop_terminal;
    cost["diagnostic_generation_trials"] = json!(diagnostic_generation_trials);
    cost["template_acquisition_search_trials"] = Value::Null;
    cost["template_acquisition_search_trials_observed"] = json!(false);
    cost["cpu_wall_bracket_tolerance_ns"] = json!(support::COST_CPU_WALL_TOLERANCE_NS);
    cost["physical_cpu_authentication"] = json!(false);
    cost["scope"] = json!("Observed actor test-thread CPU from attack entry through loop exit, including setup, diagnostic generation/rejection, waiting, all preparations, calls and in-loop evidence work. Nested preparation/call observations are not additional CPU. Excludes process startup, job loading, other threads and final evidence serialization/writes; not whole-process or receiver-owner CPU.");
    cost["public_fairness_qualified"] = json!(false);
    cost["work_hardness_qualified"] = json!(false);
    cost["production_qualified"] = json!(false);
    support::write_new(&path.join("attacker-cost-v1.json"), &cost);
    result
}

#[test]
fn native_attacker_cost_retains_unissued_preparations_and_unknown_cpu() {
    let mut ledger = support::AttackerCostLedger::new();
    let issued = json!({"body_digest":"11".repeat(32)});
    ledger.retain(
        json!({"sequence":0,"generation_trials":3,"preparation_thread_cpu_ns":7}),
        Some(10),
        Some(&issued),
    );
    // Preparation crossed the original phase gate: no fabricated call row.
    ledger.retain(
        json!({"sequence":1,"generation_trials":5,"preparation_thread_cpu_ns":null}),
        None,
        None,
    );
    let evidence = ledger.into_value();
    assert_eq!(evidence["summary"]["prepared_attempts"], 2);
    assert_eq!(evidence["summary"]["issued_calls"], 1);
    assert_eq!(evidence["summary"]["unissued_preparations"], 1);
    assert_eq!(evidence["summary"]["loop_generation_trials"], 8);
    assert_eq!(evidence["summary"]["known_preparation_thread_cpu_ns"], 7);
    assert_eq!(evidence["summary"]["unknown_preparation_cpu_count"], 1);
    assert!(evidence["summary"]["preparation_thread_cpu_ns"].is_null());
    assert_eq!(evidence["preparations"][0]["call_index"], 0);
    assert!(evidence["preparations"][1]["call_index"].is_null());
    assert_eq!(
        evidence["preparations"][1]["disposition"],
        "phase_closed_after_preparation"
    );
    // Preparation was timely, but request construction/scheduling crossed the
    // second original entry gate. Retention still does not create a call.
    let mut late_entry = support::AttackerCostLedger::new();
    late_entry.retain(
        json!({"sequence":0,"generation_trials":2,"preparation_thread_cpu_ns":4}),
        Some(WINDOW_NS),
        None,
    );
    let evidence = late_entry.into_value();
    assert_eq!(evidence["summary"]["issued_calls"], 0);
    assert_eq!(evidence["summary"]["preparation_thread_cpu_ns"], 4);
    assert_eq!(
        evidence["preparations"][0]["disposition"],
        "phase_closed_at_call_entry"
    );
    let start = support::ThreadCostBoundary {
        started_monotonic_ns: 1,
        ended_monotonic_ns: 2,
        thread_cpu_ns: Some(10),
    };
    let mut end = support::ThreadCostBoundary {
        started_monotonic_ns: 3,
        ended_monotonic_ns: 4,
        thread_cpu_ns: Some(15),
    };
    assert_eq!(support::thread_cpu_between(start, end), Some(5));
    end.thread_cpu_ns = None;
    assert_eq!(support::thread_cpu_between(start, end), None);
    end.thread_cpu_ns = Some(9);
    assert_eq!(support::thread_cpu_between(start, end), None);

    // Synthetic file observations exercise the real parent capture, not actor
    // execution or service qualification. One actor is intentionally incomplete
    // as a 24-actor phase, while its exact-byte capture remains inspectable.
    let temp = tempfile::tempdir().unwrap();
    let phase = temp.path().join("phase");
    let actor_path = phase.join("actor-0");
    fs::create_dir_all(&actor_path).unwrap();
    let actor_report = json!({"error":null,"result":{"actor":0,"pid":123,
        "calls":[],"finished_ns":WINDOW_NS}});
    let phase_report = json!({"phase":"from-zero","actors":[{"pid":123,
        "exit_success":true,"parent_forced_kill":false,"report":actor_report}]});
    let cost = json!({"schema":support::ATTACKER_COST_SCHEMA,"actor":0,"pid":123,
        "summary":{"prepared_attempts":1,"issued_calls":0},
        "loop_terminal":{"reason":"phase_closed_after_preparation","sequence":0}});
    support::write_new(&actor_path.join("report.json"), &actor_report);
    support::write_new(&actor_path.join("attacker-cost-v1.json"), &cost);
    support::capture_attacker_cost_bindings(&phase, &phase_report).unwrap();
    let binding_bytes = fs::read(phase.join(support::COST_BINDING_FILE)).unwrap();
    let binding: Value = serde_json::from_slice(&binding_bytes).unwrap();
    assert_eq!(binding["schema"], support::COST_BINDING_SCHEMA);
    assert_eq!(binding["physical_authentication"], false);
    assert_eq!(binding["capture_complete"], false);
    assert_eq!(binding["actors"][0]["capture_complete"], true);
    let raw = fs::read(actor_path.join("attacker-cost-v1.json")).unwrap();
    assert_eq!(
        binding["actors"][0]["files"]["attacker-cost-v1.json"]["sha256"],
        hex::encode(Sha256::digest(&raw))
    );
    // A later edit cannot silently refresh a create-only parent manifest.
    fs::write(actor_path.join("attacker-cost-v1.json"), b"{}\n").unwrap();
    assert!(support::capture_attacker_cost_bindings(&phase, &phase_report).is_err());
    assert_eq!(
        fs::read(phase.join(support::COST_BINDING_FILE)).unwrap(),
        binding_bytes
    );
    for directory_link in [false, true] {
        let linked = temp.path().join(if directory_link {
            "directory-link"
        } else {
            "file-link"
        });
        fs::create_dir(&linked).unwrap();
        if directory_link {
            std::os::unix::fs::symlink(&actor_path, linked.join("actor-0")).unwrap();
        } else {
            fs::create_dir(linked.join("actor-0")).unwrap();
            support::write_new(&linked.join("actor-0/report.json"), &actor_report);
            std::os::unix::fs::symlink(
                actor_path.join("attacker-cost-v1.json"),
                linked.join("actor-0/attacker-cost-v1.json"),
            )
            .unwrap();
        }
        support::capture_attacker_cost_bindings(&linked, &phase_report).unwrap();
        let binding: Value =
            serde_json::from_slice(&fs::read(linked.join(support::COST_BINDING_FILE)).unwrap())
                .unwrap();
        assert_eq!(binding["actors"][0]["capture_complete"], false);
        let file = &binding["actors"][0]["files"]["attacker-cost-v1.json"];
        assert!(file["sha256"].is_null() && file["bytes"].is_null() && file["error"].is_string());
    }
}

#[test]
#[ignore = "subprocess entry; immutable job supplied by the named parent campaign"]
fn pure_pressure_v2_actor_entry() {
    let path = PathBuf::from(std::env::var_os("TRNM_PURE_PRESSURE_V2_JOB").expect("actor job"));
    let job: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let result = std::panic::catch_unwind(|| attack(&job, path.parent().unwrap()));
    let (value, error) = match result {
        Ok(value) => (Some(value), None),
        Err(error) => (
            None,
            Some(
                error
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "non-string panic".to_owned()),
            ),
        ),
    };
    support::write_new(
        &path.parent().unwrap().join("report.json"),
        &json!({"schema":SCHEMA,"result":value,"error":error}),
    );
    support::write_new(
        &path
            .parent()
            .unwrap()
            .join("actor-family-observation-v1.json"),
        &support::process_cost::family_observation(),
    );
    support::write_new(
        &path.parent().unwrap().join("actor-child-ownership-v1.json"),
        &support::process_cost::child_ownership_probe(),
    );
    assert!(error.is_none(), "actor failure is retained");
}

fn hostile_snapshot(
    observers: &[PublicRequestObserver],
    honest: &BTreeSet<[u8; 32]>,
    epoch: u64,
) -> Value {
    let started = support::monotonic().saturating_sub(epoch);
    let mut rows = Vec::new();
    for (listener, observer) in observers.iter().enumerate() {
        for row in observer.snapshot().records {
            if row.operation == Some(1)
                && row
                    .body_digest
                    .is_some_and(|digest| !honest.contains(&digest))
                && row.dispatch_accepted == Some(false)
            {
                rows.push(
                    json!({"listener":listener,"connection_id":row.connection_id,
                    "body_digest":row.body_digest.map(hex::encode),
                    "dispatch_thread_cpu_ns":row.dispatch_thread_cpu_ns}),
                );
            }
        }
    }
    json!({"started_ns":started,"ended_ns":support::monotonic().saturating_sub(epoch),"rejections":rows})
}

fn is_depleted(sample: &Value) -> bool {
    let freshness = &sample["credit_freshness"];
    let f = &freshness["actual_flow"];
    // The original owner may not have booked time-based refill yet. Its
    // same-lock projection plus the entire sampling interval is a conservative
    // upper bound at sample end; observing it does not credit or consume CPU.
    let credit_upper_bound = sample["ended_ns"]
        .as_u64()
        .zip(sample["started_ns"].as_u64())
        .and_then(|(end, start)| end.checked_sub(start))
        .zip(freshness["projected_paid_credit_ns"].as_i64())
        .map(|(elapsed, paid)| {
            let refill = (u128::from(elapsed) * 250_000_000).div_ceil(1_000_000_000);
            i128::from(paid) + i128::try_from(refill).unwrap()
        });
    sample["clock_failures"] == 0
        && sample["budget"]["accounting_unavailable"] == false
        && f["balance_identity_verified"] == true
        && f["initial_credit_ns"] == 0
        && credit_upper_bound.is_some_and(|n| n < 100_000_000)
        && f["paid_cpu_debit_ns"]
            .as_u64()
            .is_some_and(|n| n > 1_900_000_000)
}

fn phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: &str,
) -> Value {
    fs::create_dir(path).unwrap();
    let mut receiver =
        Node::open_with_authenticated_state(&path.join("receiver"), settings.clone(), 1).unwrap();
    replay(&mut receiver, seed);
    receiver
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
    let mut verifier =
        Node::open_with_authenticated_state(&path.join("independent-client"), settings.clone(), 1)
            .unwrap();
    replay(&mut verifier, seed);
    let initial = receiver.read_active().unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    let mut actors = Vec::new();
    if mode != "baseline" {
        for actor in 0..ATTACKERS {
            actors.push(support::Actor::spawn(
                &path.join(format!("actor-{actor}")),
                json!({
                "actor":actor,"mode":mode,"address":addresses[actor%2].to_string(),
                "header":hex::encode(business[0].header.encode()),
                "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>(),
                "start_path":path.join("start.json"),"policy":support::policy_observation()}),
            ));
        }
    }
    let ready_deadline = Instant::now() + Duration::from_secs(180);
    while !actors.iter().all(support::Actor::ready) {
        assert!(
            Instant::now() < ready_deadline,
            "attacker preparation did not complete"
        );
        support::pause();
    }
    // All actor setup is finished. Create the zero-credit domain only now;
    // startup does not covertly gain a warm burst while actors prepare.
    let first = PublicServer::new_process_cold(support::identity(71), support::policy())
        .unwrap()
        .with_pure_admission_v2()
        .unwrap();
    let domain = first.mutation_cpu_domain();
    let second =
        PublicServer::with_continuous_domain(support::identity(71), support::policy(), &domain)
            .unwrap()
            .with_pure_admission_v2()
            .unwrap();
    let shared = domain.shares_domain_with(&second.mutation_cpu_domain());
    let initial_budget = domain.observe().unwrap();
    let initial_flow = domain.observe_actual_flow().unwrap().unwrap();
    let initial_admission = domain.observe_pure_admission().unwrap().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    let mut observers = Vec::new();
    let mut metrics = Vec::new();
    let epoch = support::monotonic();
    for (listener, server) in listeners.into_iter().zip([first, second]) {
        assert_eq!(
            server.resource_profile(),
            support::policy().pure_admission_v2_id()
        );
        let observer = PublicRequestObserver::new(16_384).unwrap();
        let meter = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
        observers.push(observer.clone());
        metrics.push(meter.clone());
        let owner = owner.clone();
        let stop = stop.clone();
        workers.push(thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(240),
                stop,
                server,
                meter,
                observer,
            )
            .map_err(|e| e.to_string())
        }));
    }
    support::write_new(
        &path.join("start.tmp"),
        &json!({"epoch_monotonic_ns":epoch}),
    );
    fs::rename(path.join("start.tmp"), path.join("start.json")).unwrap();
    let sampled = Arc::new(Mutex::new(Vec::new()));
    let sampler_domain = domain.clone();
    let sampler_metrics = metrics.clone();
    let sample_out = sampled.clone();
    let sampler = thread::spawn(move || {
        // Use the same captured start for the gate and the observation;
        // a separate while-clock check can cross the original cutoff.
        while let Some(started) = support::phase_entry_ns(epoch, support::monotonic()) {
            let budget = sampler_domain.observe().unwrap();
            let flow = sampler_domain.observe_actual_flow().unwrap();
            let credit_freshness = sampler_domain.observe_credit_freshness().unwrap();
            let admission = sampler_domain.observe_pure_admission().unwrap();
            let clock_failures: u64 = sampler_metrics
                .iter()
                .map(|m| m.lock().unwrap().mutation_cpu_clock_failures)
                .sum();
            let mut sample = json!({"started_ns":started,"ended_ns":support::monotonic().saturating_sub(epoch),
                "budget":budget,"flow":flow,"credit_freshness":credit_freshness,
                "admission":admission,"clock_failures":clock_failures});
            sample["depleted"] = json!(is_depleted(&sample));
            sample_out.lock().unwrap().push(sample);
            thread::sleep(Duration::from_millis(50));
        }
    });
    let requests: Vec<_> = business
        .iter()
        .map(|p| Request::Submit {
            packet: hex::encode(p.encode().unwrap()),
        })
        .collect();
    let honest: BTreeSet<_> = requests.iter().map(support::body_digest).collect();
    let mut submissions = Vec::new();
    let mut histories = Vec::new();
    let mut rounds = Vec::new();
    let mut errors = Vec::new();
    let mut next = 0;
    let mut after = initial.0;
    for round in 0..ROUNDS {
        let scheduled = 1_000_000_000 + round as u64 * 4_000_000_000;
        while support::monotonic() < epoch + scheduled {
            support::pause();
        }
        let started = support::monotonic().saturating_sub(epoch);
        let before = hostile_snapshot(&observers, &honest, epoch);
        let final_index = (round + 1) * 7;
        while next < final_index
            && support::monotonic() < epoch + WINDOW_NS
            && submissions.len() < 128
        {
            let Some(mut row) = support::call(
                addresses[next % 2],
                settings,
                requests[next].clone(),
                73,
                epoch,
            ) else {
                break;
            };
            row["packet_index"] = json!(next);
            row["listener"] = json!(next % 2);
            if support::on_time(&row) {
                next += 1;
            }
            submissions.push(row);
        }
        let tip = business[final_index - 1].id().unwrap();
        let included = business[round * 7].id().unwrap();
        let transaction = hash(b"tx-id", &[&business[round * 7].transactions[0]]);
        let mut observation = None;
        while next == final_index
            && support::monotonic() < epoch + WINDOW_NS
            && histories.len() < 64
        {
            let request = Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            };
            let Some(mut row) =
                support::call(addresses[round % 2], settings, request.clone(), 74, epoch)
            else {
                break;
            };
            row["request"] = serde_json::to_value(request).unwrap();
            row["listener"] = json!(round % 2);
            if support::on_time(&row) {
                let started = support::monotonic().saturating_sub(epoch);
                let cpu = support::thread_cpu();
                let imported =
                    serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                        .map_err(|e| e.to_string())
                        .and_then(|page| {
                            ingress::receive_page(&mut verifier, page, tip, after, support::now())
                                .map_err(|e| e.to_string())
                        });
                row["client_import"] = json!({"started_ns":started,"ended_ns":support::monotonic().saturating_sub(epoch),
                    "thread_cpu_ns":support::cpu_delta(cpu),"succeeded":imported.is_ok()});
                match imported {
                    Ok(value) => after = value,
                    Err(error) => errors.push(error),
                }
                if after == tip {
                    let started = support::monotonic().saturating_sub(epoch);
                    let value = verifier.confirmation(transaction, included, support::now());
                    row["client_confirmation"] = json!({"started_ns":started,
                        "ended_ns":support::monotonic().saturating_sub(epoch),"succeeded":value.is_ok()});
                    match value {
                        Ok(value) => observation = Some(value),
                        Err(error) => errors.push(error.to_string()),
                    }
                }
            }
            histories.push(row);
            if observation.is_some() {
                break;
            }
        }
        let after_snapshot = hostile_snapshot(&observers, &honest, epoch);
        let ended = support::monotonic().saturating_sub(epoch);
        let confirmed = observation.as_ref().is_some_and(|v| {
            v.confirmed && !v.finalized && !v.execution_authority && v.depth == Some(6)
        }) && ended < WINDOW_NS;
        rounds.push(json!({"round":round,"scheduled_ns":scheduled,"started_ns":started,"ended_ns":ended,
            "confirmed_inside_pressure_window":confirmed,"observation":observation,
            "transaction":hex::encode(transaction),"included_block":hex::encode(included),"tip":hex::encode(tip),
            "hostile_before":before,"hostile_after":after_snapshot}));
        if !confirmed {
            break;
        }
    }
    // The original fixed window runs to completion. Cleanup may join cancelled
    // tasks, but it never counts recovery as an on-time business confirmation.
    let cleanup = Instant::now()
        + Duration::from_nanos((epoch + WINDOW_NS).saturating_sub(support::monotonic()))
        + Duration::from_secs(5);
    let (actors, actor_process_costs): (Vec<_>, Vec<_>) = actors
        .into_iter()
        .map(|a| a.finish_with_process_cost(cleanup))
        .unzip();
    sampler.join().unwrap();
    stop.store(true, Ordering::Release);
    let services: Vec<_> = workers
        .into_iter()
        .map(|w| serde_json::to_value(w.join().unwrap()).unwrap())
        .collect();
    let capture: Vec<_> = observers
        .iter()
        .map(|o| {
            let s = o.snapshot();
            json!({"coverage_complete":s.coverage_complete(),"snapshot":s})
        })
        .collect();
    let samples = sampled.lock().unwrap().clone();
    for round in &mut rounds {
        let a = round["started_ns"].as_u64().unwrap();
        let b = round["ended_ns"].as_u64().unwrap();
        round["depletion_observed_during_round"] = json!(samples.iter().any(|s| s["started_ns"]
            .as_u64()
            .zip(s["ended_ns"].as_u64())
            .is_some_and(|(x, y)| a <= x && x <= y && y <= b)
            && is_depleted(s)));
        round["overlapping_attack_calls"] = json!(actors
            .iter()
            .filter_map(|a| a["report"]["result"]["calls"].as_array())
            .flatten()
            .filter(|c| c["started_ns"]
                .as_u64()
                .zip(c["ended_ns"].as_u64())
                .zip(c["deadline_ns"].as_u64())
                .is_some_and(|((x, y), deadline)| x < b && y.min(deadline) > a))
            .count());
    }
    let (receiver_tip, receiver_height, receiver_generation) =
        active_position(&owner.lock().unwrap());
    let (client_tip, client_height, client_generation) = active_position(&verifier);
    let report = json!({"schema":SCHEMA,"phase":mode,"epoch_monotonic_ns":epoch,"window_ns":WINDOW_NS,
        "policy":support::policy_observation(),"listeners":2,"shared_cpu_domain":shared,
        "ready_actors":if mode=="baseline" {0}else{ATTACKERS},
        "initial_budget":initial_budget,"initial_flow":initial_flow,"initial_admission":initial_admission,
        "final_budget":domain.observe().unwrap(),"final_flow":domain.observe_actual_flow().unwrap(),
        "final_admission":domain.observe_pure_admission().unwrap(),"services":services,
        "actors":actors,"submissions":submissions,"history":histories,"rounds":rounds,
        "samples":samples,"observations":capture,"receiver_tip":hex::encode(receiver_tip),
        "client_tip":hex::encode(client_tip),"receiver_height":receiver_height,"client_height":client_height,
        "receiver_generation":receiver_generation,"client_generation":client_generation,
        "errors":errors,"public_fairness_qualified":false,"production_qualified":false,
        "work_hardness_qualified":false,"installation_authorized":false});
    // Height comes from the active block record, not its activation generation.
    assert!(report["receiver_height"].is_u64() && report["client_height"].is_u64());
    // Parent-only observation follows all original joins, stop and verdict
    // construction. Its separate file cannot extend a call/actor deadline or
    // alter the historical v3 report and service qualification predicates.
    if let Err(error) = support::capture_attacker_cost_bindings(path, &report) {
        eprintln!("attacker cost binding capture unavailable: {error}");
    }
    if let Err(error) = support::capture_actor_process_costs(path, &report, &actor_process_costs) {
        eprintln!("attacker whole-process cost capture unavailable: {error}");
    }
    if let Err(error) = support::capture_child_ownership_binding(path, &report, false) {
        eprintln!("actor child-ownership binding capture unavailable: {error}");
    }
    report
}

#[test]
#[ignore = "90-second separate-process pure-PoN pressure campaign; retains failed observations"]
fn pure_pon_cold_shared_domain_pressure_v2() {
    let output = PathBuf::from(
        std::env::var_os("TRNM_PURE_PRESSURE_V2_OUT").expect("create-only output path"),
    );
    fs::create_dir(&output).unwrap();
    let settings = support::settings();
    let (seed, business) = prepare(&output, &settings);
    let mut summaries = Vec::new();
    for mode in ["baseline", "from-zero", "correct-product-false-trace"] {
        eprintln!("pure-PoN v2: {mode}, fixed 30s, cold shared CPU epoch, two listeners");
        let report = phase(&output.join(mode), &settings, &seed, &business, mode);
        support::write_new(&output.join(format!("{mode}.json")), &report);
        summaries.push(json!({"phase":mode,"file":format!("{mode}.json"),
            "all_rounds_confirmed":report["rounds"].as_array().is_some_and(|r|r.len()==ROUNDS
                && r.iter().all(|r|r["confirmed_inside_pressure_window"]==true))}));
    }
    support::write_new(
        &output.join("campaign.json"),
        &json!({"schema":SCHEMA,
        "window_ns":WINDOW_NS,"attackers":ATTACKERS,"actor_call_cap":CALL_CAP,"rounds":ROUNDS,
        "policy":support::policy_observation(),"phases":summaries,
        "scope":"finite same-host separate processes; independent History replay and signed 6-depth confirmation; diagnostic observations are not CPU authenticity or arbitrary-Sybil fairness",
        "public_fairness_qualified":false,"production_qualified":false,"work_hardness_qualified":false,
        "installation_authorized":false}),
    );
    assert!(summaries.iter().all(|s|s["all_rounds_confirmed"]==true),
        "finite service failed; complete evidence retained; independent reader checks pressure/depletion/overlap");
}
