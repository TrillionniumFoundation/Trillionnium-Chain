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
fn restore_task_rejects_terminal_collateral_retention_without_forfeit_outcome() {
    let mut state = StateStore::new();

    state.restore_task(
        40808,
        Some(TaskObject {
            task_id: 40808,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ac".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x13; 32]),
            result_hash: Some([0x24; 32]),
            reveal_salt: Some([0x35; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40808).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata keeps sponsor-funded challenge bond state but omits the final refund-vs-forfeit outcome bit"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_forfeit_outcome_but_no_bond() {
    let mut state = StateStore::new();

    state.restore_task(
        408081,
        Some(TaskObject {
            task_id: 408081,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ac".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x14; 32]),
            result_hash: Some([0x25; 32]),
            reveal_salt: Some([0x36; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(408081).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata keeps the refund-vs-forfeit outcome bit after dropping the sponsor-funded challenge bond itself"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_embedded_control_in_challenger_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40809,
        Some(TaskObject {
            task_id: 40809,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ad".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x36; 32]),
            result_hash: Some([0x47; 32]),
            reveal_salt: Some([0x58; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob\nops".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40809).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata carries a challenger identity with embedded control/whitespace, so sponsor-funded audit trails cannot smuggle a non-canonical actor id"
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

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_window_snapshot() {
    let mut state = StateStore::new();

    state.restore_task(
        40830,
        Some(TaskObject {
            task_id: 40830,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("8f".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x70; 32]),
            result_hash: Some([0x71; 32]),
            reveal_salt: Some([0x72; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(0),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40830).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata zeroes the retained challenge-window snapshot needed to audit sponsor-funded challenge retention"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_stale_challenge_start() {
    let mut state = StateStore::new();

    state.restore_task(
        40831,
        Some(TaskObject {
            task_id: 40831,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("90".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x73; 32]),
            result_hash: Some([0x74; 32]),
            reveal_salt: Some([0x75; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40831).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata keeps a stale challenge start without live collateral context"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_stale_resolve_deadline() {
    let mut state = StateStore::new();

    state.restore_task(
        40832,
        Some(TaskObject {
            task_id: 40832,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("91".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x76; 32]),
            result_hash: Some([0x77; 32]),
            reveal_salt: Some([0x78; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(41),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40832).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata keeps a stale resolve deadline without live collateral context"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_challenge_start() {
    let mut state = StateStore::new();

    state.restore_task(
        40810,
        Some(TaskObject {
            task_id: 40810,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("9a".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x70; 32]),
            result_hash: Some([0x80; 32]),
            reveal_salt: Some([0x90; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(0),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40810).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata zeroes the challenge start that anchored sponsor-funded proof retention"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_stale_challenger_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40833,
        Some(TaskObject {
            task_id: 40833,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("92".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x79; 32]),
            result_hash: Some([0x7a; 32]),
            reveal_salt: Some([0x7b; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40833).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata keeps a stale challenger identity without live collateral context"
    );
}
