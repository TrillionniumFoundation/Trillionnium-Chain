//! Atomic process-local routing of one complete, already resident CTS1.
//!
//! This uses the existing immutable version/tensor admission and the pool's
//! single selection slot. It does not persist CURRENT, authorize execution,
//! renew a task, discover a provider, or grant retention/FinalUse authority.

use std::{sync::atomic::AtomicBool, time::Instant};

use super::{checkpoint, CellLocalSelectionV1, CellResidencyConfigV1, CellResidencyV1};
use crate::cell::{
    require, CellDigestV1, CellErrorV1, CellReleaseSnapshotCommitmentV1,
    CellReleaseSnapshotLoaderContextV1, CellReleaseSnapshotV1, CellResidentReleaseSnapshotV1,
    CellResultV1, CellVersionCommitmentV1,
};

/// One manager's complete-release CAS ticket. All fields are private; matching
/// public content and revision in another manager cannot create this ticket.
/// It is a local byte-routing observation, never a durable authority receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellLocalReleaseSelectionV1 {
    owner: u64,
    revision: u64,
    snapshot: CellReleaseSnapshotCommitmentV1,
    version: CellVersionCommitmentV1,
    model_closure: CellDigestV1,
    environment_closure: CellDigestV1,
    composition_profile: CellDigestV1,
}

impl CellLocalReleaseSelectionV1 {
    pub fn revision(self) -> u64 {
        self.revision
    }

    pub fn snapshot(self) -> CellReleaseSnapshotCommitmentV1 {
        self.snapshot
    }

    pub fn version(self) -> CellVersionCommitmentV1 {
        self.version
    }

    pub fn model_closure(self) -> CellDigestV1 {
        self.model_closure
    }

    pub fn environment_closure(self) -> CellDigestV1 {
        self.environment_closure
    }
}

/// The pool has exactly one selection, never independently selected model and
/// environment pointers. An explicit complete-release CAS may upgrade Closure
/// to Release. Legacy single-closure selection/selected reads refuse Release;
/// there is no implicit downgrade or second current pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellLocalSelectionStateV1 {
    Closure(CellLocalSelectionV1),
    Release(CellLocalReleaseSelectionV1),
}

impl CellLocalSelectionStateV1 {
    pub fn revision(self) -> u64 {
        match self {
            Self::Closure(selected) => selected.revision,
            Self::Release(selected) => selected.revision,
        }
    }

    pub(super) fn protects(self, closure: CellDigestV1) -> bool {
        match self {
            Self::Closure(selected) => selected.closure_id == closure,
            Self::Release(selected) => {
                selected.model_closure == closure || selected.environment_closure == closure
            }
        }
    }
}

impl CellResidencyV1 {
    /// Inspect the one local selection without hiding its profile. Restarted
    /// pools start empty; restoring cached bytes does not restore this state.
    pub fn local_selection(&self) -> Option<CellLocalSelectionStateV1> {
        self.selection
    }

    pub fn release_selection(&self) -> Option<CellLocalReleaseSelectionV1> {
        match self.selection {
            Some(CellLocalSelectionStateV1::Release(selected)) => Some(selected),
            _ => None,
        }
    }

    /// Validate complete resident bytes, tensor schema and both owner contexts
    /// under the supplied task's original limits before one atomic assignment.
    /// Failed staging, stale/foreign/ABA tickets, cancellation and expiry leave
    /// both the previous selection and all resident allocations unchanged.
    ///
    /// `expected_previous` explicitly identifies an empty pool, a legacy
    /// closure selection to upgrade, or the previous complete-release ticket.
    /// No slow operation, allocation or caller callback follows the final
    /// checkpoint. The caller separately owns current publisher/revocation,
    /// execution-resource and FinalUse guards; selection grants none of them.
    #[allow(clippy::too_many_arguments)]
    pub fn select_local_release_snapshot(
        &mut self,
        expected_previous: Option<CellLocalSelectionStateV1>,
        task: CellDigestV1,
        snapshot: &CellReleaseSnapshotV1,
        expected: &CellReleaseSnapshotLoaderContextV1<'_>,
        limits: CellResidencyConfigV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellLocalReleaseSelectionV1> {
        checkpoint(deadline, cancelled)?;
        require(
            self.selection == expected_previous,
            "resident release selection conflict",
        )?;
        let revision = self
            .selection
            .map_or(0, CellLocalSelectionStateV1::revision)
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid(
                "resident selection revision exhausted",
            ))?;
        {
            let ready = self.admit_local_release_snapshot(
                task, snapshot, expected, limits, deadline, cancelled,
            )?;
            ready.with_local(task, expected, |_| ())?;
        }
        let selected = CellLocalReleaseSelectionV1 {
            owner: self.owner,
            revision,
            snapshot: expected.snapshot,
            version: expected.version.commitment,
            model_closure: expected.version.model.closure_id,
            environment_closure: expected.version.environment.closure_id,
            composition_profile: expected.composition_profile,
        };
        checkpoint(deadline, cancelled)?;
        self.selection = Some(CellLocalSelectionStateV1::Release(selected));
        Ok(selected)
    }

    /// Admit a new task only from the exact current complete selection. The
    /// returned existing CTS1 handle borrows the pool and keeps both closures,
    /// typed tensors and rules together. Safe Rust cannot switch or evict the
    /// pool while the task or any borrowed view remains live.
    ///
    /// The original task deadlines/cancellation and current owner contexts are
    /// still checked by the handle. This performs no cache/network fallback and
    /// neither inherits nor renews the task used to validate a prior switch.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_selected_local_release_snapshot<'a>(
        &'a self,
        selected: CellLocalReleaseSelectionV1,
        task: CellDigestV1,
        snapshot: &'a CellReleaseSnapshotV1,
        current: &CellReleaseSnapshotLoaderContextV1<'_>,
        limits: CellResidencyConfigV1,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> CellResultV1<CellResidentReleaseSnapshotV1<'a>> {
        checkpoint(deadline, cancelled)?;
        require(
            self.selection == Some(CellLocalSelectionStateV1::Release(selected)),
            "resident release selection mismatch",
        )?;
        require(
            selected.snapshot == current.snapshot
                && selected.version == current.version.commitment
                && selected.model_closure == current.version.model.closure_id
                && selected.environment_closure == current.version.environment.closure_id
                && selected.composition_profile == current.composition_profile,
            "resident selected release context",
        )?;
        self.admit_local_release_snapshot(task, snapshot, current, limits, deadline, cancelled)
    }
}

#[cfg(test)]
mod tests;
