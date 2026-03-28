use trnm_state::*;
use trnm_types::*;

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_challenge_deadline() {
    let mut state = StateStore::new();

    state.restore_task(
        40801,
        Some(TaskObject {
            task_id: 40801,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(0),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40801).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata zeroes the challenge deadline that bounds sponsor-funded proof retention"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_system_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40802,
        Some(TaskObject {
            task_id: 40802,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("cd".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x44; 32]),
            result_hash: Some([0x55; 32]),
            reveal_salt: Some([0x66; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("System".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40802).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved system authority, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_challenge_escrow_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40820,
        Some(TaskObject {
            task_id: 40820,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ce".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x45; 32]),
            result_hash: Some([0x56; 32]),
            reveal_salt: Some([0x67; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("treasury.challenge_escrow".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40820).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved challenge escrow identity"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_forfeit_treasury_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40803,
        Some(TaskObject {
            task_id: 40803,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ef".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x77; 32]),
            result_hash: Some([0x88; 32]),
            reveal_salt: Some([0x99; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("Treasury.Challenge_Forfeits".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40803).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved challenge-forfeits treasury, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_worker_slash_treasury_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40804,
        Some(TaskObject {
            task_id: 40804,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("12".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0xaa; 32]),
            result_hash: Some([0xbb; 32]),
            reveal_salt: Some([0xcc; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("TREASURY.WORKER_SLASHES".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40804).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved worker-slash treasury, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_pause_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40805,
        Some(TaskObject {
            task_id: 40805,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("34".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0xdd; 32]),
            result_hash: Some([0xee; 32]),
            reveal_salt: Some([0xff; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("Governance.Emergency_Pause".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40805).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved emergency-pause authority, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_resolve_authority_placeholder() {
    let mut state = StateStore::new();

    state.restore_task(
        40806,
        Some(TaskObject {
            task_id: 40806,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("56".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x10; 32]),
            result_hash: Some([0x20; 32]),
            reveal_salt: Some([0x30; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("Governance.Resolve_Authority".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40806).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved governance.resolve_authority placeholder, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_pause_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40807,
        Some(TaskObject {
            task_id: 40807,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("78".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x40; 32]),
            result_hash: Some([0x50; 32]),
            reveal_salt: Some([0x60; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("Emergency_Pause".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40807).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved emergency_pause shortcut, even through mixed-case input"
    );
}
