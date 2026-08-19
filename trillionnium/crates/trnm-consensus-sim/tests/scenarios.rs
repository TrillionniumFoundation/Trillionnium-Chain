use trnm_consensus_sim::{MessageKind, ScriptedValidationOutcome, SimConfig, Simulator};
use trnm_consensus_types::{BlockId, Height, View};

fn simulator(nodes: usize, seed: u64) -> Simulator {
    let config = SimConfig::new(nodes, seed)
        .expect("valid fixture config")
        .with_maximum_network_delay(2)
        .expect("positive delay")
        .with_timeout_ticks(16)
        .expect("valid timeout");
    Simulator::new(config).expect("valid simulator")
}

fn reaches_height(simulator: &mut Simulator, height: u64, maximum: usize) -> bool {
    simulator
        .run_until(maximum, |simulator| {
            simulator.all_applied_and_durable(Height::new(height), true)
        })
        .expect("simulation remains valid")
}

fn trace_count(simulator: &Simulator, code: &str, detail: &str) -> usize {
    simulator
        .trace()
        .entries()
        .iter()
        .filter(|entry| entry.code() == code && entry.detail().contains(detail))
        .count()
}

fn trace_field<'a>(detail: &'a str, key: &str) -> Option<&'a str> {
    detail.split_whitespace().find_map(|field| {
        let (name, value) = field.split_once('=')?;
        (name == key).then_some(value)
    })
}

#[test]
fn short_epoch_stalls_before_checkpoint_without_boundary_votes_or_qcs() {
    let config = SimConfig::new(4, 0xE0_00_04)
        .expect("valid fixture config")
        .with_maximum_network_delay(2)
        .expect("positive delay")
        .with_timeout_ticks(16)
        .expect("valid timeout")
        .with_epoch_layout(6, 3)
        .expect("valid short epoch geometry");
    let mut simulator = Simulator::new(config).expect("valid short-epoch simulator");
    simulator.start();
    assert!(simulator
        .run_until(20_000, |simulator| {
            simulator.trace().entries().iter().any(|entry| {
                entry.code() == "net-reject"
                    && entry.detail().contains(
                        "height 4 reaches active epoch checkpoint 4; epoch-transition signing is unsupported",
                    )
                    && entry.detail().contains("message=proposal:")
            })
        })
        .expect("the fail-closed boundary remains a valid simulation state"));
    simulator
        .run_events(2_000)
        .expect("post-rejection scheduling remains safe and bounded");

    assert_eq!(simulator.latest_qc().height(), Height::new(3));
    assert!(!simulator.has_conflicting_finality());
    assert!(simulator.trace().entries().iter().any(|entry| {
        entry.code() == "net-reject"
            && entry.detail().contains(
                "height 4 reaches active epoch checkpoint 4; epoch-transition signing is unsupported",
            )
            && entry.detail().contains("message=proposal:")
    }));
    assert!(!simulator.trace().entries().iter().any(|entry| {
        (entry.code() == "net-deliver"
            && entry.detail().contains("message=vote:")
            && entry.detail().contains(":height=4:"))
            || (entry.code() == "qc-formed" && entry.detail().contains("height=4"))
    }));
}

fn message_field<'a>(detail: &'a str, key: &str) -> Option<&'a str> {
    trace_field(detail, "message")?
        .split(':')
        .find_map(|field| {
            let (name, value) = field.split_once('=')?;
            (name == key).then_some(value)
        })
}

#[test]
fn four_nodes_one_crash_then_heal_continue_finality() {
    let mut simulator = simulator(4, 0x4C_A5_01);
    simulator.crash(1).expect("node exists");
    simulator.start();

    assert!(reaches_height(&mut simulator, 2, 80_000));
    assert!(!simulator.has_conflicting_finality());

    simulator.recover(1).expect("durable recovery succeeds");
    simulator.heal();
    assert!(simulator
        .run_until(120_000, |simulator| {
            simulator.all_applied_and_durable(Height::new(3), false)
        })
        .expect("recovered simulation remains valid"));
    assert!(simulator.node_snapshot(1).expect("node exists").online);
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn four_node_equivocation_emits_evidence_and_conflicting_qc_halts_safely() {
    let mut simulator = simulator(4, 0x4E_01_70_CA);
    simulator.start();
    assert!(reaches_height(&mut simulator, 1, 60_000));

    let targets = [0, 1, 2, 3];
    simulator
        .inject_equivocating_votes(
            0,
            View::new(90),
            Height::new(90),
            BlockId::new([0xE1; 32]),
            BlockId::new([0xE2; 32]),
            &targets,
        )
        .expect("equivocation fixture is shape-valid");
    assert!(simulator
        .run_until(20_000, |simulator| simulator.evidence_count() > 0)
        .expect("evidence delivery remains valid"));

    let base = simulator.latest_qc().clone();
    simulator
        .inject_conflicting_qc(&base, BlockId::new([0xCF; 32]), &targets)
        .expect("adversarial quorum fixture is shape-valid");
    assert!(simulator
        .run_until(40_000, |simulator| simulator.halted_count() > 0)
        .expect("halt delivery remains valid"));
    let halted_node = (0..4)
        .find(|&node| simulator.node_snapshot(node).expect("node exists").halted)
        .expect("at least one node halted");
    assert!(
        simulator
            .node_snapshot(halted_node)
            .expect("halted node exists")
            .durable_halted
    );
    let trace_start = simulator.trace().entries().len();
    simulator.crash(halted_node).expect("halted node crashes");
    simulator
        .recover(halted_node)
        .expect("durable halt state recovers");
    assert!(simulator
        .run_until(1_000, |simulator| {
            simulator.trace().entries()[trace_start..]
                .iter()
                .any(|entry| {
                    entry.code() == "safety-halt"
                        && entry.detail().contains(&format!("node={halted_node}"))
                })
        })
        .expect("halt recovery remains valid"));
    let recovered = simulator
        .node_snapshot(halted_node)
        .expect("halted node exists");
    assert!(recovered.online);
    assert!(recovered.halted);
    assert!(recovered.durable_halted);
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn seven_nodes_tolerate_two_offline_and_recover() {
    let mut simulator = simulator(7, 0x7A_02_FF);
    simulator.crash(1).expect("node exists");
    simulator.crash(3).expect("node exists");
    simulator.start();

    assert!(reaches_height(&mut simulator, 2, 120_000));
    assert_eq!(
        simulator
            .node_snapshot(1)
            .expect("offline node exists")
            .applied_height,
        Height::new(0)
    );
    assert_eq!(
        simulator
            .node_snapshot(3)
            .expect("offline node exists")
            .applied_height,
        Height::new(0)
    );
    assert!(!simulator.has_conflicting_finality());

    simulator.recover(1).expect("first node recovers");
    simulator.recover(3).expect("second node recovers");
    simulator.heal();
    assert!(simulator
        .run_until(180_000, |simulator| {
            simulator.all_applied_and_durable(Height::new(3), false)
        })
        .expect("seven-node recovery remains valid"));
    assert!(simulator
        .trace()
        .entries()
        .iter()
        .any(|entry| entry.code() == "stale-sync-validation-callback"));
    assert!(simulator
        .trace()
        .entries()
        .iter()
        .any(|entry| entry.code() == "rebind-sync-validation-callback"));
    assert!(simulator
        .run_until(20_000, |simulator| {
            simulator
                .trace()
                .entries()
                .iter()
                .any(|entry| entry.code() == "replay-complete")
        })
        .expect("the rebound recovery replay completes"));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn seven_nodes_stall_with_three_offline_then_progress_with_two_offline() {
    let mut simulator = simulator(7, 0x7A_03_FF);
    simulator.crash(1).expect("node exists");
    simulator.crash(3).expect("node exists");
    simulator.crash(5).expect("node exists");
    simulator.start();
    simulator
        .run_events(60_000)
        .expect("sub-quorum scheduler remains valid");
    assert_eq!(simulator.maximum_applied_height(true), Height::new(0));

    simulator.recover(5).expect("restored fifth validator");
    simulator.heal();
    assert!(reaches_height(&mut simulator, 1, 120_000));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn crash_discards_an_unacknowledged_persistence_effect() {
    let mut simulator = simulator(4, 0xACC0_0001);
    simulator.start();
    let mut saw_node_zero_persist = false;
    for _ in 0..200 {
        simulator.run_events(1).expect("single event remains valid");
        saw_node_zero_persist = simulator.trace().entries().iter().any(|entry| {
            entry.code() == "persist-request" && entry.detail().starts_with("node=0 ")
        });
        if saw_node_zero_persist {
            break;
        }
    }
    assert!(saw_node_zero_persist);
    assert_eq!(trace_count(&simulator, "persist-ack", "node=0 "), 0);
    assert_eq!(trace_count(&simulator, "signature-ready", "node=0 "), 0);
    assert_eq!(
        simulator
            .node_snapshot(0)
            .expect("node exists")
            .durable_revision,
        0
    );

    simulator.crash(0).expect("node crashes");
    simulator.recover(0).expect("node recovers from last ack");
    assert_eq!(
        simulator
            .node_snapshot(0)
            .expect("node exists")
            .durable_revision,
        0
    );
    simulator.heal();
    assert!(reaches_height(&mut simulator, 1, 100_000));
    assert!(trace_count(&simulator, "local-drop", "stale-persist node=0") > 0);
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn two_plus_two_partition_cannot_finalize_and_heal_restores_progress() {
    let mut simulator = simulator(4, 0x22_22_04);
    simulator
        .partition(&[vec![0, 1], vec![2, 3]])
        .expect("valid disjoint partition");
    simulator.start();
    simulator
        .run_events(40_000)
        .expect("partitioned scheduler remains valid");

    assert_eq!(simulator.maximum_applied_height(false), Height::new(0));
    assert!(!simulator.has_conflicting_finality());

    simulator.heal();
    assert!(reaches_height(&mut simulator, 1, 10_000));
    assert!(!simulator.has_conflicting_finality());
}

fn seeded_fault_trace(seed: u64) -> Simulator {
    let mut simulator = simulator(4, seed);
    simulator.drop_next(MessageKind::Proposal, Some(0), Some(3), 1);
    simulator.duplicate_next(MessageKind::Vote, None, Some(2), 3, 1);
    simulator.delay_next(MessageKind::QuorumCertificate, None, Some(1), 2, 7);
    simulator.start();
    simulator
        .run_events(4)
        .expect("initial deterministic events run");
    assert!(simulator.reorder_next_two_messages());
    simulator.heal();
    assert!(reaches_height(&mut simulator, 1, 10_000));
    assert_eq!(simulator.pending_fault_matches(), 0);
    assert_eq!(
        trace_count(&simulator, "fault-drop", "message=proposal:"),
        1
    );
    assert_eq!(trace_count(&simulator, "fault-shape", "copies=1"), 3);
    assert_eq!(trace_count(&simulator, "fault-shape", "delay=7"), 2);
    assert_eq!(
        trace_count(&simulator, "fault-reorder", "first-message="),
        1
    );
    simulator
}

#[test]
fn seeded_drop_duplicate_reorder_delay_trace_is_replay_stable() {
    let first = seeded_fault_trace(0x5EED_2026);
    let second = seeded_fault_trace(0x5EED_2026);
    assert_eq!(first.trace(), second.trace());
    assert_eq!(first.trace_digest(), second.trace_digest());
    assert_ne!(first.trace_digest().as_bytes(), &[0u8; 32]);
}

#[test]
fn running_crash_recovers_nonzero_durable_state_through_safety_replay() {
    let mut simulator = simulator(4, 0xC2A5_4E50);
    simulator.start();
    assert!(reaches_height(&mut simulator, 1, 100_000));

    let before = simulator.node_snapshot(0).expect("node exists");
    assert!(before.durable_revision > 0);
    assert!(before.durably_applied_height >= Height::new(1));
    let trace_start = simulator.trace().entries().len();

    simulator.crash(0).expect("running node crashes");
    simulator
        .recover(0)
        .expect("nonzero durable state recovers");
    assert!(simulator
        .run_until(120_000, |simulator| {
            simulator.trace().entries()[trace_start..]
                .iter()
                .any(|entry| entry.code() == "replay-complete" && entry.detail().contains("node=0"))
        })
        .expect("safety replay remains valid"));

    let replay_trace = &simulator.trace().entries()[trace_start..];
    assert!(replay_trace
        .iter()
        .any(|entry| { entry.code() == "replay-request" && entry.detail().contains("node=0") }));
    assert!(replay_trace
        .iter()
        .any(|entry| { entry.code() == "sync-validated" && entry.detail().contains("node=0") }));
    assert!(replay_trace
        .iter()
        .any(|entry| { entry.code() == "replay-complete" && entry.detail().contains("node=0") }));
    let recovered = simulator.node_snapshot(0).expect("node exists");
    assert!(recovered.online);
    assert!(recovered.durable_revision > before.durable_revision);
    assert!(reaches_height(&mut simulator, 2, 140_000));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn standalone_qc_before_proposal_catch_up_survives_crash_recovery() {
    const TARGET: usize = 3;

    let mut simulator = simulator(4, 0x51A0_DA10);
    simulator.drop_next(MessageKind::Proposal, Some(0), Some(TARGET), 1);
    simulator.start();

    assert!(simulator
        .run_until(80_000, |simulator| {
            simulator
                .node_snapshot(TARGET)
                .is_ok_and(|snapshot| snapshot.durable_pending_standalone_qc_sync)
        })
        .expect("the proposal-less node durably records the standalone QC"));
    let before_crash = simulator.node_snapshot(TARGET).expect("target node exists");
    assert!(before_crash.online);
    assert!(before_crash.durable_pending_standalone_qc_sync);
    let initial_entries = simulator.trace().entries();
    let initial_request_index = initial_entries
        .iter()
        .position(|entry| {
            entry.code() == "standalone-qc-sync-request"
                && entry.detail().contains(&format!("node={TARGET} "))
        })
        .expect("the first standalone QC request is traced");
    let initial_request = &initial_entries[initial_request_index];
    let initial_qc = trace_field(initial_request.detail(), "qc")
        .expect("the first exact standalone QC id is traced")
        .to_owned();
    let initial_target = trace_field(initial_request.detail(), "target")
        .expect("the first exact standalone QC target is traced")
        .to_owned();
    assert!(initial_entries[..initial_request_index]
        .iter()
        .any(|entry| {
            entry.code() == "persist-ack"
                && entry.detail().contains(&format!("node={TARGET} "))
                && entry.detail().contains("standalone-pending=true")
        }));

    simulator
        .crash(TARGET)
        .expect("target crashes before catch-up");
    let crashed = simulator.node_snapshot(TARGET).expect("target node exists");
    assert!(!crashed.online);
    assert!(crashed.durable_pending_standalone_qc_sync);

    let recovery_trace_start = simulator.trace().entries().len();
    simulator
        .recover(TARGET)
        .expect("the durable standalone QC obligation recovers");
    assert!(simulator
        .run_until(120_000, |simulator| {
            let recovered = simulator.node_snapshot(TARGET).expect("target node exists");
            !recovered.durable_pending_standalone_qc_sync
                && recovered.durable_revision > before_crash.durable_revision
                && simulator.trace().entries()[recovery_trace_start..]
                    .iter()
                    .any(|entry| {
                        entry.code() == "replay-complete"
                            && entry.detail().contains(&format!("node={TARGET}"))
                    })
        })
        .expect("recovery reissues and completes the standalone QC catch-up"));

    let recovery_trace = &simulator.trace().entries()[recovery_trace_start..];
    let request_index = recovery_trace
        .iter()
        .position(|entry| {
            entry.code() == "standalone-qc-sync-request"
                && entry.detail().contains(&format!("node={TARGET} "))
        })
        .expect("recovery reissues the standalone QC request");
    let recovered_request = &recovery_trace[request_index];
    let recovered_qc = trace_field(recovered_request.detail(), "qc")
        .expect("recovery reissues an exact standalone QC id");
    let recovered_target = trace_field(recovered_request.detail(), "target")
        .expect("recovery reissues an exact standalone QC target");
    assert_eq!(recovered_qc, initial_qc);
    assert_eq!(recovered_target, initial_target);
    let sync_index = recovery_trace
        .iter()
        .enumerate()
        .skip(request_index + 1)
        .find_map(|(index, entry)| {
            (entry.code() == "sync-validated"
                && entry.detail().contains(&format!("node={TARGET} "))
                && trace_field(entry.detail(), "block") == Some(recovered_target)
                && trace_field(entry.detail(), "result") == Some("valid"))
            .then_some(index)
        })
        .expect("the exact standalone target validates after its request");
    let durable_clear_index = recovery_trace
        .iter()
        .enumerate()
        .skip(sync_index + 1)
        .find_map(|(index, entry)| {
            (entry.code() == "persist-ack"
                && entry.detail().contains(&format!("node={TARGET} "))
                && entry.detail().contains("standalone-pending=false"))
            .then_some(index)
        })
        .expect("clearing the standalone obligation becomes durable after validation");
    assert!(recovery_trace[durable_clear_index + 1..]
        .iter()
        .any(|entry| {
            entry.code() == "replay-complete" && entry.detail().contains(&format!("node={TARGET}"))
        }));
    let recovered = simulator.node_snapshot(TARGET).expect("target node exists");
    assert!(recovered.online);
    assert!(!recovered.durable_pending_standalone_qc_sync);
    assert!(reaches_height(&mut simulator, 2, 140_000));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn proposal_carried_missing_justify_qc_survives_crash_recovery() {
    const TARGET: usize = 3;

    let mut simulator = simulator(4, 0xCA22_1E20);
    simulator.drop_next(MessageKind::Proposal, Some(0), Some(TARGET), 1);
    simulator.drop_next(MessageKind::QuorumCertificate, None, Some(TARGET), 1);
    simulator.start();

    assert!(simulator
        .run_until(80_000, |simulator| {
            simulator
                .node_snapshot(TARGET)
                .is_ok_and(|snapshot| snapshot.durable_pending_standalone_qc_sync)
        })
        .expect("the proposal carrier creates a durable exact-QC obligation"));
    let before_crash = simulator.node_snapshot(TARGET).expect("target node exists");
    assert!(before_crash.online);
    assert!(before_crash.durable_pending_standalone_qc_sync);

    let initial_trace = simulator.trace().entries();
    let request_index = initial_trace
        .iter()
        .position(|entry| {
            entry.code() == "standalone-qc-sync-request"
                && entry.detail().contains(&format!("node={TARGET} "))
        })
        .expect("the carrier's exact justify QC is requested");
    let request = &initial_trace[request_index];
    let exact_qc = trace_field(request.detail(), "qc")
        .expect("the carrier request traces an exact QC id")
        .to_owned();
    let exact_target = trace_field(request.detail(), "target")
        .expect("the carrier request traces its exact missing parent")
        .to_owned();

    let dropped_parent = initial_trace[..request_index]
        .iter()
        .find(|entry| {
            entry.code() == "fault-drop"
                && entry.detail().contains(&format!("from=0 to={TARGET} "))
                && trace_field(entry.detail(), "message")
                    .is_some_and(|message| message.starts_with("proposal:"))
        })
        .expect("the parent proposal is absent at the target");
    assert_eq!(
        message_field(dropped_parent.detail(), "block"),
        Some(exact_target.as_str())
    );

    let carrier_index = initial_trace[..request_index]
        .iter()
        .position(|entry| {
            entry.code() == "net-deliver"
                && entry.detail().contains(&format!("to={TARGET} "))
                && trace_field(entry.detail(), "message")
                    .is_some_and(|message| message.starts_with("proposal:"))
                && message_field(entry.detail(), "justify") == Some(exact_qc.as_str())
        })
        .expect("a later proposal is the first carrier of the missing justify QC");
    assert!(initial_trace[..carrier_index].iter().any(|entry| {
        entry.code() == "fault-drop"
            && entry.detail().contains(&format!("to={TARGET} "))
            && message_field(entry.detail(), "id") == Some(exact_qc.as_str())
    }));
    assert!(!initial_trace[..carrier_index].iter().any(|entry| {
        entry.code() == "net-deliver"
            && entry.detail().contains(&format!("to={TARGET} "))
            && message_field(entry.detail(), "id") == Some(exact_qc.as_str())
    }));
    assert!(initial_trace[carrier_index + 1..request_index]
        .iter()
        .any(|entry| {
            entry.code() == "persist-ack"
                && entry.detail().contains(&format!("node={TARGET} "))
                && entry.detail().contains("standalone-pending=true")
        }));

    simulator
        .crash(TARGET)
        .expect("the target crashes after the durable acknowledgement");
    assert!(
        simulator
            .node_snapshot(TARGET)
            .expect("target node exists")
            .durable_pending_standalone_qc_sync
    );
    let recovery_trace_start = simulator.trace().entries().len();
    simulator
        .recover(TARGET)
        .expect("the proposal-carried obligation recovers");
    assert!(simulator
        .run_until(120_000, |simulator| {
            let snapshot = simulator.node_snapshot(TARGET).expect("target node exists");
            !snapshot.durable_pending_standalone_qc_sync
                && snapshot.durable_revision > before_crash.durable_revision
                && simulator.trace().entries()[recovery_trace_start..]
                    .iter()
                    .any(|entry| {
                        entry.code() == "replay-complete"
                            && entry.detail().contains(&format!("node={TARGET}"))
                    })
        })
        .expect("recovery completes the exact proposal-carried catch-up"));

    let recovery_trace = &simulator.trace().entries()[recovery_trace_start..];
    let recovered_request_index = recovery_trace
        .iter()
        .position(|entry| {
            entry.code() == "standalone-qc-sync-request"
                && entry.detail().contains(&format!("node={TARGET} "))
        })
        .expect("recovery reissues the proposal-carried request");
    let recovered_request = &recovery_trace[recovered_request_index];
    assert_eq!(
        trace_field(recovered_request.detail(), "qc"),
        Some(exact_qc.as_str())
    );
    assert_eq!(
        trace_field(recovered_request.detail(), "target"),
        Some(exact_target.as_str())
    );
    let synced_index = recovery_trace
        .iter()
        .enumerate()
        .skip(recovered_request_index + 1)
        .find_map(|(index, entry)| {
            (entry.code() == "sync-validated"
                && entry.detail().contains(&format!("node={TARGET} "))
                && trace_field(entry.detail(), "block") == Some(exact_target.as_str())
                && trace_field(entry.detail(), "result") == Some("valid"))
            .then_some(index)
        })
        .expect("the exact carried target validates after recovery");
    let cleared_index = recovery_trace
        .iter()
        .enumerate()
        .skip(synced_index + 1)
        .find_map(|(index, entry)| {
            (entry.code() == "persist-ack"
                && entry.detail().contains(&format!("node={TARGET} "))
                && entry.detail().contains("standalone-pending=false"))
            .then_some(index)
        })
        .expect("the proposal-carried obligation clears durably");
    assert!(recovery_trace[cleared_index + 1..].iter().any(|entry| {
        entry.code() == "replay-complete" && entry.detail().contains(&format!("node={TARGET}"))
    }));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn finalized_height_competing_qc_policy_is_deterministic() {
    const TARGET: usize = 0;

    let config = SimConfig::new(4, 0x57A1_E0C0)
        .expect("valid fixture config")
        .with_maximum_network_delay(1)
        .expect("positive delay")
        .with_timeout_ticks(10_000)
        .expect("valid timeout");
    let mut simulator = Simulator::new(config).expect("valid simulator");
    simulator.start();
    assert!(reaches_height(&mut simulator, 1, 80_000));
    simulator
        .partition(&[vec![TARGET], vec![1, 2, 3]])
        .expect("isolate the target from unrelated post-finality traffic");

    let before = simulator.node_snapshot(TARGET).expect("target node exists");
    let finalized_qc = simulator
        .quorum_certificate_for_block(before.finalized_block)
        .expect("the finalized ordinary block retains its QC")
        .clone();
    assert_eq!(finalized_qc.height(), before.finalized_height);
    let competing_view = View::new(
        finalized_qc
            .view()
            .get()
            .checked_add(10_000)
            .expect("fixture view remains bounded"),
    );
    let historical_trace_start = simulator.trace().entries().len();
    simulator
        .inject_historical_competing_qc(
            &finalized_qc,
            competing_view,
            BlockId::new([0x51; 32]),
            &[TARGET],
        )
        .expect("different-view historical competition is shape-valid");
    assert!(simulator
        .run_until(2_000, |simulator| {
            simulator.trace().entries()[historical_trace_start..]
                .iter()
                .any(|entry| {
                    entry.code() == "net-deliver"
                        && entry.detail().contains(&format!("to={TARGET} "))
                        && message_field(entry.detail(), "view")
                            .and_then(|view| view.parse::<u64>().ok())
                            == Some(competing_view.get())
                })
        })
        .expect("historical QC delivery remains safe while prior work drains"));
    let historical_delivery_index = simulator.trace().entries()[historical_trace_start..]
        .iter()
        .position(|entry| {
            entry.code() == "net-deliver"
                && entry.detail().contains(&format!("to={TARGET} "))
                && message_field(entry.detail(), "view").and_then(|view| view.parse::<u64>().ok())
                    == Some(competing_view.get())
        })
        .map(|index| historical_trace_start + index)
        .expect("historical QC has an exact delivery trace");
    let after_historical = simulator.node_snapshot(TARGET).expect("target node exists");
    assert_eq!(after_historical.current_view, before.current_view);
    assert_eq!(after_historical.finalized_height, before.finalized_height);
    assert_eq!(after_historical.finalized_block, before.finalized_block);
    assert!(!after_historical.durable_pending_standalone_qc_sync);
    assert!(!after_historical.halted);
    assert!(
        !simulator.trace().entries()[historical_delivery_index + 1..]
            .iter()
            .any(|entry| {
                entry.code() == "persist-request"
                    && entry.detail().contains(&format!("node={TARGET} "))
            })
    );
    assert!(!simulator.trace().entries()[historical_trace_start..]
        .iter()
        .any(|entry| {
            matches!(
                entry.code(),
                "standalone-qc-sync-request" | "tc-high-qc-sync-request" | "replay-request"
            ) && entry.detail().contains(&format!("node={TARGET} "))
        }));

    let same_view_trace_start = simulator.trace().entries().len();
    simulator
        .inject_conflicting_qc(&finalized_qc, BlockId::new([0x52; 32]), &[TARGET])
        .expect("same-view conflicting QC is shape-valid");
    assert!(simulator
        .run_until(2_000, |simulator| {
            simulator
                .node_snapshot(TARGET)
                .is_ok_and(|snapshot| snapshot.halted && snapshot.durable_halted)
        })
        .expect("same-view conflict becomes a durable halt"));
    assert!(simulator.trace().entries()[same_view_trace_start..]
        .iter()
        .any(|entry| {
            entry.code() == "safety-halt"
                && entry.detail().contains(&format!("node={TARGET} "))
                && entry.detail().contains("reason=conflicting-qcs:")
        }));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn unavailable_payload_retries_the_same_block_under_a_new_generation() {
    let mut simulator = simulator(4, 0xA11A_1AB1);
    simulator
        .queue_payload_validation_results(
            0,
            [
                ScriptedValidationOutcome::Unavailable,
                ScriptedValidationOutcome::Valid,
            ],
        )
        .expect("node exists");
    simulator.start();

    assert!(simulator
        .run_until(40_000, |simulator| {
            trace_count(simulator, "payload-validated", "node=0 ") >= 2
        })
        .expect("scripted validation remains valid"));
    let validations: Vec<_> = simulator
        .trace()
        .entries()
        .iter()
        .filter(|entry| entry.code() == "payload-validated" && entry.detail().contains("node=0 "))
        .take(2)
        .collect();
    assert_eq!(validations.len(), 2);
    assert_eq!(
        trace_field(validations[0].detail(), "result"),
        Some("unavailable")
    );
    assert_eq!(
        trace_field(validations[1].detail(), "result"),
        Some("valid")
    );
    assert_eq!(
        trace_field(validations[0].detail(), "block"),
        trace_field(validations[1].detail(), "block")
    );
    let first_generation = trace_field(validations[0].detail(), "generation")
        .expect("generation is traced")
        .parse::<u64>()
        .expect("generation is numeric");
    let second_generation = trace_field(validations[1].detail(), "generation")
        .expect("generation is traced")
        .parse::<u64>()
        .expect("generation is numeric");
    assert!(second_generation > first_generation);
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn mismatched_valid_candidate_is_rejected_before_seal_and_retried_fresh() {
    let mut simulator = simulator(4, 0xB2D0_CAFE);
    simulator
        .queue_payload_validation_results(
            0,
            [
                ScriptedValidationOutcome::MismatchedValid,
                ScriptedValidationOutcome::Valid,
            ],
        )
        .expect("node exists");
    simulator.start();

    assert!(simulator
        .run_until(40_000, |simulator| {
            simulator.trace().entries().iter().any(|entry| {
                entry.code() == "validation-preseal-reject" && entry.detail().contains("node=0 ")
            }) && simulator.trace().entries().iter().any(|entry| {
                entry.code() == "payload-validated"
                    && entry.detail().contains("node=0 ")
                    && entry.detail().contains("result=valid")
            })
        })
        .expect("mismatched local capability remains a recoverable driver fault"));

    let rejected = simulator
        .trace()
        .entries()
        .iter()
        .find(|entry| {
            entry.code() == "validation-preseal-reject" && entry.detail().contains("node=0 ")
        })
        .expect("the wrong-block application candidate is rejected before sealing");
    let unavailable = simulator
        .trace()
        .entries()
        .iter()
        .find(|entry| {
            entry.code() == "payload-validated"
                && entry.detail().contains("node=0 ")
                && entry.detail().contains("result=unavailable")
        })
        .expect("the rejected candidate consumes the old generation as unavailable");
    let accepted = simulator
        .trace()
        .entries()
        .iter()
        .find(|entry| {
            entry.code() == "payload-validated"
                && entry.detail().contains("node=0 ")
                && entry.detail().contains("result=valid")
        })
        .expect("the exact capability is accepted afterward");
    assert_eq!(
        trace_field(rejected.detail(), "generation"),
        trace_field(unavailable.detail(), "generation")
    );
    assert_eq!(
        trace_field(rejected.detail(), "block"),
        trace_field(unavailable.detail(), "block")
    );
    assert_eq!(
        trace_field(unavailable.detail(), "block"),
        trace_field(accepted.detail(), "block")
    );
    let rejected_generation = trace_field(rejected.detail(), "generation")
        .expect("the rejected generation is traced")
        .parse::<u64>()
        .expect("the rejected generation is numeric");
    let accepted_generation = trace_field(accepted.detail(), "generation")
        .expect("the accepted generation is traced")
        .parse::<u64>()
        .expect("the accepted generation is numeric");
    assert!(accepted_generation > rejected_generation);
    assert!(reaches_height(&mut simulator, 1, 100_000));
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn deterministically_invalid_certified_payload_halt_survives_recovery() {
    let mut simulator = simulator(4, 0x1A11_DA7A);
    simulator
        .queue_payload_validation_results(0, [ScriptedValidationOutcome::DeterministicallyInvalid])
        .expect("node exists");
    simulator.start();

    assert!(simulator
        .run_until(80_000, |simulator| {
            simulator
                .node_snapshot(0)
                .is_ok_and(|snapshot| snapshot.halted && snapshot.durable_halted)
        })
        .expect("the remaining quorum can certify the invalid block"));
    assert!(simulator.trace().entries().iter().any(|entry| {
        entry.code() == "payload-validated"
            && entry.detail().contains("node=0 ")
            && entry.detail().contains("result=deterministically-invalid")
    }));

    let trace_start = simulator.trace().entries().len();
    simulator.crash(0).expect("halted node crashes");
    simulator.recover(0).expect("durable halt recovers");
    assert!(simulator
        .run_until(2_000, |simulator| {
            simulator.trace().entries()[trace_start..]
                .iter()
                .any(|entry| {
                    entry.code() == "safety-halt"
                        && entry.detail().contains("node=0 ")
                        && entry
                            .detail()
                            .contains("reason=deterministically-invalid-payload")
                })
        })
        .expect("halt recovery remains valid"));
    let recovered = simulator.node_snapshot(0).expect("node exists");
    assert!(recovered.online);
    assert!(recovered.halted);
    assert!(recovered.durable_halted);
    assert!(!simulator.has_conflicting_finality());
}

#[test]
fn replay_unavailable_waits_for_valid_before_completing() {
    let mut simulator = simulator(4, 0xC2A5_4E50);
    simulator.start();
    assert!(reaches_height(&mut simulator, 1, 100_000));
    simulator
        .queue_payload_validation_results(
            0,
            [
                ScriptedValidationOutcome::Unavailable,
                ScriptedValidationOutcome::Valid,
            ],
        )
        .expect("node exists");

    let trace_start = simulator.trace().entries().len();
    simulator.crash(0).expect("running node crashes");
    simulator.recover(0).expect("durable state recovers");
    assert!(simulator
        .run_until(120_000, |simulator| {
            simulator.trace().entries()[trace_start..]
                .iter()
                .any(|entry| entry.code() == "replay-complete" && entry.detail().contains("node=0"))
        })
        .expect("scripted replay remains valid"));

    let replay_trace = &simulator.trace().entries()[trace_start..];
    let unavailable = replay_trace
        .iter()
        .position(|entry| {
            entry.code() == "sync-validated"
                && entry.detail().contains("node=0 ")
                && entry.detail().contains("result=unavailable")
        })
        .expect("replay observes the scripted unavailable result");
    let valid = replay_trace
        .iter()
        .position(|entry| {
            entry.code() == "sync-validated"
                && entry.detail().contains("node=0 ")
                && entry.detail().contains("result=valid")
        })
        .expect("the same replay item is retried successfully");
    let complete = replay_trace
        .iter()
        .position(|entry| entry.code() == "replay-complete" && entry.detail().contains("node=0"))
        .expect("replay eventually completes");
    assert!(unavailable < valid);
    assert!(valid < complete);
    assert!(!simulator.has_conflicting_finality());
}
