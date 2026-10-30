//! Explicit native storage checkpoints. The legacy closure adapter keeps every
//! original callback; only the sealed account verifier can emit graph points.
//! This channel carries no consensus, task, CPU-credit or cached resource verdict.
use crate::account_archive_prototype::native_store::{AccountGraphKind, AccountGraphPoint};
use crate::Result;

pub(crate) enum NativeProgressPoint {
    Boundary,
    BeforeCommit,
    AccountGraph(AccountGraphPoint),
}

pub(crate) trait NativeProgress {
    fn checkpoint(&mut self) -> Result<()>;

    fn before_commit(&mut self) -> Result<()> {
        self.checkpoint()
    }

    fn account_graph(&mut self, point: AccountGraphPoint) -> Result<()> {
        // Enter/final/exit are new typed notifications. Legacy callers retain
        // their exact original callback placement, including EVERY node.
        match point.kind() {
            AccountGraphKind::BeforeNode { .. } => self.checkpoint(),
            AccountGraphKind::Enter
            | AccountGraphKind::BeforeFinalRelation { .. }
            | AccountGraphKind::Exit { .. } => Ok(()),
        }
    }
}

impl<F: FnMut() -> Result<()> + ?Sized> NativeProgress for F {
    fn checkpoint(&mut self) -> Result<()> {
        self()
    }
}

/// Explicit bridge for typed Node-owned storage work. It is never installed in
/// thread-local state or carried into an unrelated executor worker.
pub(crate) struct TypedNativeProgress<F>(pub(crate) F);

impl<F: FnMut(NativeProgressPoint) -> Result<()>> NativeProgress for TypedNativeProgress<F> {
    fn checkpoint(&mut self) -> Result<()> {
        (self.0)(NativeProgressPoint::Boundary)
    }

    fn before_commit(&mut self) -> Result<()> {
        (self.0)(NativeProgressPoint::BeforeCommit)
    }

    fn account_graph(&mut self, point: AccountGraphPoint) -> Result<()> {
        (self.0)(NativeProgressPoint::AccountGraph(point))
    }
}

/// Preserve an old execution-stage callback without erasing graph categories
/// on the new typed path. Synthetic graph edges have no old callback.
pub(crate) fn legacy_checkpoint(point: &NativeProgressPoint) -> bool {
    match point {
        NativeProgressPoint::Boundary | NativeProgressPoint::BeforeCommit => true,
        NativeProgressPoint::AccountGraph(point) => {
            matches!(point.kind(), AccountGraphKind::BeforeNode { .. })
        }
    }
}

pub(crate) fn dispatch(
    progress: &mut dyn NativeProgress,
    point: NativeProgressPoint,
) -> Result<()> {
    match point {
        NativeProgressPoint::Boundary => progress.checkpoint(),
        NativeProgressPoint::BeforeCommit => progress.before_commit(),
        NativeProgressPoint::AccountGraph(point) => progress.account_graph(point),
    }
}
