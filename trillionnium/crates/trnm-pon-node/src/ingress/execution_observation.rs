//! Diagnostic spans over existing M06 progress boundaries. No new checkpoint,
//! different error, worker accounting, deadline or authorization is introduced.
use super::public_v3::{
    request_observation::{SubmitPhaseGuard, TaskObservation},
    SubmitPhase,
};
use crate::{Error, Result};
use std::sync::Mutex;
use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionProgress};

struct Spans<'a> {
    prepare: Option<SubmitPhaseGuard<'a>>,
    execute: Option<SubmitPhaseGuard<'a>>,
    root: Option<SubmitPhaseGuard<'a>>,
    commit: Option<SubmitPhaseGuard<'a>>,
    execution_entered: bool,
    root_entered: bool,
    commit_entered: bool,
}
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Held,
    PreparedHeld,
    DetachedExecution,
}
impl Spans<'_> {
    fn finish<T>(&mut self, result: &Result<T>) {
        for guard in [
            &mut self.root,
            &mut self.execute,
            &mut self.prepare,
            &mut self.commit,
        ] {
            if let Some(guard) = guard.take() {
                guard.finish_result(result);
            }
        }
    }
}

/// `held_admission` splits the existing exclusive/held owner path at its real
/// M06 and persistence boundaries. The detached path already times those calls
/// separately, so it selects root-only child observation here. Binding/witness
/// reads before BeforeStateClone belong to prepare, final output comparison to
/// execution, and all persistence/readback/publication fences belong to commit.
pub(super) fn run<T>(
    observation: Option<&TaskObservation>,
    control: &ExecutionControl<'_, Error>,
    scope: Scope,
    action: impl FnOnce(&ExecutionControl<'_, Error>) -> Result<T>,
) -> Result<T> {
    let Some(observation) = observation else {
        return action(control);
    };
    let held_admission = !matches!(scope, Scope::DetachedExecution);
    let spans = Mutex::new(Spans {
        prepare: matches!(scope, Scope::Held)
            .then(|| observation.phase(SubmitPhase::AdmissionPrepare)),
        execute: None,
        root: None,
        commit: None,
        execution_entered: false,
        root_entered: false,
        commit_entered: false,
    });
    let progress = |point| {
        // Invoke the ORIGINAL hook exactly once and preserve its exact result.
        let result = (control.progress)(point);
        // Preparation hooks can run on scoped workers. They must not close a
        // caller-owned span or sample its CPU on another thread; the original
        // action joins those workers and returns its error to this caller.
        // Only the four actual stage markers need optional observer access.
        if result.is_ok()
            && matches!(
                point,
                ExecutionProgress::BeforeStateClone
                    | ExecutionProgress::BeforeCommitment
                    | ExecutionProgress::AfterCommitment
                    | ExecutionProgress::BeforePersistence
            )
        {
            if let Ok(mut spans) = spans.try_lock() {
                match point {
                    ExecutionProgress::BeforeStateClone
                        if held_admission && !spans.execution_entered =>
                    {
                        if let Some(guard) = spans.prepare.take() {
                            guard.finish(true);
                        }
                        spans.execution_entered = true;
                        spans.execute = Some(observation.phase(SubmitPhase::Execution));
                    }
                    ExecutionProgress::BeforeCommitment if !spans.root_entered => {
                        spans.root_entered = true;
                        spans.root = Some(observation.phase(SubmitPhase::RootCommitment));
                    }
                    ExecutionProgress::AfterCommitment => {
                        if let Some(guard) = spans.root.take() {
                            guard.finish(true);
                        }
                    }
                    ExecutionProgress::BeforePersistence
                        if held_admission && !spans.commit_entered =>
                    {
                        if let Some(guard) = spans.execute.take() {
                            guard.finish(true);
                        }
                        if let Some(guard) = spans.prepare.take() {
                            guard.finish(true);
                        }
                        spans.commit_entered = true;
                        spans.commit = Some(observation.phase(SubmitPhase::Commit));
                    }
                    _ => {}
                }
            } else {
                observation.measurement_failed();
            }
        }
        result
    };
    let result = action(&ExecutionControl::new(&progress, control.worker_accounting));
    if let Ok(mut spans) = spans.try_lock() {
        spans.finish(&result);
    } else {
        observation.measurement_failed();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    #[test]
    fn rejection_and_cancellation_keep_original_hook_and_failed_root_span() {
        for cancelled in [false, true] {
            let observation = TaskObservation::local(Instant::now());
            let calls = AtomicUsize::new(0);
            let progress = |point| {
                calls.fetch_add(1, Ordering::Relaxed);
                if cancelled && point == ExecutionProgress::AfterCommitment {
                    Err("PUBLIC_REQUEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            };
            let result: Result<()> = run(
                Some(&observation),
                &ExecutionControl::new(&progress, &()),
                Scope::Held,
                |control| {
                    (control.progress)(ExecutionProgress::BeforeStateClone)?;
                    (control.progress)(ExecutionProgress::BeforeCommitment)?;
                    if cancelled {
                        (control.progress)(ExecutionProgress::AfterCommitment)?;
                    }
                    Err("ROOT".into())
                },
            );
            assert_eq!(calls.load(Ordering::Relaxed), if cancelled { 3 } else { 2 });
            assert_eq!(
                result.unwrap_err().to_string(),
                if cancelled {
                    "PUBLIC_REQUEST_CANCELLED"
                } else {
                    "ROOT"
                }
            );
            let (phases, failures) = observation.phase_snapshot();
            assert_eq!(failures, 0);
            for phase in [SubmitPhase::Execution, SubmitPhase::RootCommitment] {
                let phase = phases[phase as usize];
                assert!(phase.started && phase.completed);
                assert_eq!(phase.accepted, Some(false));
                assert!(phase.started_ns.is_some() && phase.ended_ns.is_some());
            }
            assert!(!phases[SubmitPhase::Commit as usize].started);
        }
    }

    #[test]
    fn worker_cancellation_keeps_caller_span_open_through_the_actual_join() {
        let epoch = Instant::now();
        let observation = TaskObservation::local(epoch);
        let calls = AtomicUsize::new(0);
        let joined_ns = std::cell::Cell::new(None);
        let progress = |point| {
            calls.fetch_add(1, Ordering::Relaxed);
            if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                Err("PUBLIC_REQUEST_CANCELLED".into())
            } else {
                Ok(())
            }
        };
        let result: Result<()> = run(
            Some(&observation),
            &ExecutionControl::new(&progress, &()),
            Scope::Held,
            |control| {
                (control.progress)(ExecutionProgress::BeforeStateClone)?;
                let error = std::thread::scope(|scope| {
                    let worker = scope.spawn(|| {
                        let error =
                            (control.progress)(ExecutionProgress::BeforePrepare { index: 0 })
                                .unwrap_err();
                        let (phases, failures) = observation.phase_snapshot();
                        let execution = phases[SubmitPhase::Execution as usize];
                        assert_eq!(failures, 0);
                        assert!(execution.started && !execution.completed);
                        assert_eq!(execution.ended_ns, None);
                        error
                    });
                    worker.join().unwrap()
                });
                joined_ns.set(Some(u64::try_from(epoch.elapsed().as_nanos()).unwrap()));
                Err(error)
            },
        );
        assert!(result
            .unwrap_err()
            .is(crate::ErrorCode::PublicRequestCancelled));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let (phases, failures) = observation.phase_snapshot();
        assert_eq!(failures, 0);
        let execution = phases[SubmitPhase::Execution as usize];
        assert!(execution.completed);
        assert_eq!(execution.accepted, Some(false));
        assert_eq!(execution.error_code, Some("PUBLIC_REQUEST_CANCELLED"));
        assert!(execution.ended_ns.unwrap() >= joined_ns.get().unwrap());
        #[cfg(target_os = "linux")]
        assert!(execution.thread_cpu_ns.is_some());
    }
}
