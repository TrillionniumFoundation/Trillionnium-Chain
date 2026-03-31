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
fn restore_task_rejects_slashed_collateral_retention_without_forfeit_outcome() {
    let mut state = StateStore::new();

    state.restore_task(
        408082,
        Some(TaskObject {
            task_id: 408082,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ad".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x15; 32]),
            result_hash: Some([0x26; 32]),
            reveal_salt: Some([0x37; 32]),
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
        state.get_task(408082).is_none(),
        "restore_task must fail closed when slashed collateral-retention metadata keeps sponsor-funded challenge bond state but omits the final refund-vs-forfeit outcome bit"
    );
}

#[test]
fn restore_task_rejects_slashed_collateral_retention_with_refund_outcome() {
    let mut state = StateStore::new();

    state.restore_task(
        4080821,
        Some(TaskObject {
            task_id: 4080821,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ae".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x16; 32]),
            result_hash: Some([0x27; 32]),
            reveal_salt: Some([0x38; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
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
        state.get_task(4080821).is_none(),
        "restore_task must fail closed when slashed collateral-retention metadata marks the sponsor-funded challenge bond as refunded instead of forfeited"
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
fn restore_task_rejects_terminal_collateral_retention_with_overlong_challenger_identity() {
    let mut state = StateStore::new();
    let overlong_challenger = "b".repeat(129);

    state.restore_task(
        408095,
        Some(TaskObject {
            task_id: 408095,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ae".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x39; 32]),
            result_hash: Some([0x4a; 32]),
            reveal_salt: Some([0x5b; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some(overlong_challenger),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(408095).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata carries a challenger identity longer than the canonical actor-id limit, so sponsor-funded audit trails cannot persist non-canonical actor material"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_mixed_case_challenger_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        408096,
        Some(TaskObject {
            task_id: 408096,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("af".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x3a; 32]),
            result_hash: Some([0x4b; 32]),
            reveal_salt: Some([0x5c; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("BobSmith".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(408096).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata keeps a mixed-case challenger identity instead of a lowercase canonical actor id for sponsor-funded retention audits"
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
fn restore_task_rejects_terminal_collateral_retention_with_exact_reserved_worker_slashes_treasury_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        408041,
        Some(TaskObject {
            task_id: 408041,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("21".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0xab; 32]),
            result_hash: Some([0xbc; 32]),
            reveal_salt: Some([0xcd; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("treasury.worker_slashes".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(408041).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the exact reserved worker-slashes treasury account"
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

#[test]
fn restore_task_rejects_slashed_retention_with_blank_challenger_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40835,
        Some(TaskObject {
            task_id: 40835,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("94".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x80; 32]),
            result_hash: Some([0x81; 32]),
            reveal_salt: Some([0x82; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("   ".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40835).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata keeps a blank challenger identity without live collateral context"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_overlong_challenger_identity() {
    let mut state = StateStore::new();
    let overlong_challenger = "b".repeat(129);

    state.restore_task(
        408351,
        Some(TaskObject {
            task_id: 408351,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("941".chars().cycle().take(64).collect()),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x80; 32]),
            result_hash: Some([0x81; 32]),
            reveal_salt: Some([0x82; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some(overlong_challenger),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(408351).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata keeps a challenger identity longer than the canonical actor-id limit, so sponsor-funded slash audit trails cannot persist non-canonical actor material"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_system_identity() {
    let mut state = StateStore::new();

    state.restore_task(
        40837,
        Some(TaskObject {
            task_id: 40837,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("96".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x87; 32]),
            result_hash: Some([0x88; 32]),
            reveal_salt: Some([0x89; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("System".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40837).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved system authority, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_challenge_escrow_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40835,
        Some(TaskObject {
            task_id: 40835,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("94".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x81; 32]),
            result_hash: Some([0x82; 32]),
            reveal_salt: Some([0x83; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Treasury.Challenge_Escrow".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40835).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved challenge escrow identity, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_resolve_authority_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40834,
        Some(TaskObject {
            task_id: 40834,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("93".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x7c; 32]),
            result_hash: Some([0x7d; 32]),
            reveal_salt: Some([0x7e; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Governance.Resolve_Authority".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40834).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved governance.resolve_authority placeholder, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_pause_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40836,
        Some(TaskObject {
            task_id: 40836,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("95".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x84; 32]),
            result_hash: Some([0x85; 32]),
            reveal_salt: Some([0x86; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Emergency_Pause".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40836).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved emergency_pause identity, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_forfeit_treasury_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40838,
        Some(TaskObject {
            task_id: 40838,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("97".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x8a; 32]),
            result_hash: Some([0x8b; 32]),
            reveal_salt: Some([0x8c; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Treasury.Challenge_Forfeits".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40838).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved challenge-forfeits treasury, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_exact_reserved_forfeit_treasury_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        408381,
        Some(TaskObject {
            task_id: 408381,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("971".chars().cycle().take(64).collect()),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x8d; 32]),
            result_hash: Some([0x8e; 32]),
            reveal_salt: Some([0x8f; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("treasury.challenge_forfeits".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(408381).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the exact reserved challenge-forfeits treasury account"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_reserved_worker_slash_treasury_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40839,
        Some(TaskObject {
            task_id: 40839,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("98".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x8d; 32]),
            result_hash: Some([0x8e; 32]),
            reveal_salt: Some([0x8f; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Treasury.Worker_Slash".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40839).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the reserved worker-slash treasury, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_slashed_retention_with_exact_reserved_worker_slashes_treasury_alias() {
    let mut state = StateStore::new();

    state.restore_task(
        40840,
        Some(TaskObject {
            task_id: 40840,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Slashed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained slash trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("99".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x90; 32]),
            result_hash: Some([0x91; 32]),
            reveal_salt: Some([0x92; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("Treasury.Worker_Slashes".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        state.get_task(40840).is_none(),
        "restore_task must fail closed when slashed proof-retention metadata aliases the challenger to the exact reserved worker-slashes treasury account, even through mixed-case input"
    );
}
