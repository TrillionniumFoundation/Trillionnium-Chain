use trnm_consensus_sim::{MessageKind, SimConfig, Simulator};
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
