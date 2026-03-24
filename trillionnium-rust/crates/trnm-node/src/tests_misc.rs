use super::*;

#[path = "tests_misc/backoff.rs"]
mod backoff;
#[path = "tests_misc/emergency_pause.rs"]
mod emergency_pause;
#[path = "tests_misc/proposer_selection.rs"]
mod proposer_selection;
#[path = "tests_misc/formatting.rs"]
mod formatting;
#[path = "tests_misc/risk_gate.rs"]
mod risk_gate;

fn expected_high_risk_tx_exhaustive(tx: &MockTx) -> bool {
    // Exhaustive match intentionally used as a merge-gate guard:
    // if a new tx variant is introduced, this test must be reviewed.
    match tx {
        MockTx::CreateTask { .. }
        | MockTx::AcceptTask { .. }
        | MockTx::Commit { .. }
        | MockTx::Reveal { .. }
        | MockTx::Challenge { .. } => true,
        // Resolve performs terminal challenged escrow settlement and must stay
        // frozen while emergency pause is active.
        MockTx::Resolve { .. } => true,
    }
}
