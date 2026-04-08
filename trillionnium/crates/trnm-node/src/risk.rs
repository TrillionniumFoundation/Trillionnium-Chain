use crate::types::MockTx;

pub(crate) fn is_high_risk_tx(tx: &MockTx) -> bool {
    // Exhaustive merge-gate guard: introducing a new tx variant now requires
    // an explicit pause-risk decision here at compile time.
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

pub(crate) fn is_rejected_by_emergency_pause(is_paused: bool, tx: &MockTx) -> bool {
    is_paused && is_high_risk_tx(tx)
}
