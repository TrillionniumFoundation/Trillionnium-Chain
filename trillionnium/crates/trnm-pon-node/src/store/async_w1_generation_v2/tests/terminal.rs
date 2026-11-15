//! Accounting/runtime values here are explicit boundary fixtures. NativeTask
//! reserve/cancel, persisted journals and branch changes use the actual Node.
//! These controls do not certify process ownership, GPU isolation or a proof.
use super::*;
use trnm_service_settlement::native_generation_budget_v2::{FailureKindV2, FailureV2};

struct TerminalFixture {
    observed: Option<OwnedTerminalExecutionV3>,
    now: ClockCheckpointV2,
    calls: usize,
}
impl TerminalFixture {
    fn new(s: &GenerationStatementV2, reason: TerminalReasonV3) -> Self {
        Self {
            observed: Some(OwnedTerminalExecutionV3 {
                job: job(s),
                execution_source_commitment: s.execution_source_commitment,
                evidence_digest: sha256(b"EXPLICIT-TERMINAL-BOUNDARY-FIXTURE"),
                reason,
                resources: None,
                controller_observed: ClockCheckpointV2 {
                    clock_domain: s.original_deadline.clock_domain,
                    now_ns: 200,
                },
            }),
            now: ClockCheckpointV2 {
                clock_domain: s.original_deadline.clock_domain,
                now_ns: 200,
            },
            calls: 0,
        }
    }
}
impl OwnedGenerationRuntimeV2 for TerminalFixture {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(self.now.clone())
    }
    fn reconcile_fresh_execution(
        &mut self,
        _: &GenerationStatementV2,
        _: &ProviderJobV2,
        _: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        Err(error("TERMINAL_CONTROL_NEVER_VERIFIES_A_PROOF"))
    }
    fn run_independent_verifier(
        &mut self,
        _: &GenerationStatementV2,
        _: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        Err(error("TERMINAL_CONTROL_NEVER_RUNS_A_VERIFIER"))
    }
}
impl OwnedTerminalGenerationRuntimeV3 for TerminalFixture {
    fn reconcile_terminal_execution(
        &mut self,
        _: &GenerationStatementV2,
        _: &ProviderJobV2,
    ) -> Result<OwnedTerminalExecutionV3> {
        self.calls += 1;
        self.observed
            .take()
            .ok_or(error("TERMINAL_CONTROL_RUNTIME_MUST_NOT_REPLAY"))
    }
}
fn start(
    n: &mut Node,
    store: &mut NativeGenerationStoreV2,
    s: &GenerationStatementV2,
    runtime: &mut TerminalFixture,
) -> Hash {
    let mut owner = NodeGenerationOwnerV2::new(n, runtime).unwrap();
    let id = store.prepare(&mut owner, s.clone()).unwrap();
    assert!(matches!(
        store.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::New
    ));
    store.bind_job(id, job(s)).unwrap();
    id
}

#[test]
fn terminal_unknown_closes_dispatch_once_and_preserves_native_funding_and_cap() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("node");
    let journal = d.path().join("m12.sqlite");
    let mut n = open(&path, StateBackend::PermanentAccountGrowthV2);
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let cfg = configuration(&n);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg.clone()).unwrap();
    let mut runtime = TerminalFixture::new(&s, TerminalReasonV3::Failed);
    let id = start(&mut n, &mut store, &s, &mut runtime);
    let funding = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap();
    let failure = {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        owner.reconcile_terminal_failure(&mut store, id).unwrap()
    };
    assert_eq!(failure.kind, FailureKindV2::Unknown);
    assert!(failure.consumed.is_none());
    let prior = store.readback(id).unwrap();
    assert_eq!(prior.resource_charge, s.resource_cap);
    assert!(
        prior.verified.is_none()
            && prior.cancellation.is_none()
            && prior.settlement.is_none()
            && prior.historical_payment.is_none()
    );
    drop(store);
    drop(n);
    let mut n = open(&path, StateBackend::PermanentAccountGrowthV2);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg).unwrap();
    // Expiry and native currentness cannot redispatch or change the stored charge.
    runtime.now.now_ns = s.original_deadline.deadline_ns + 100;
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert_eq!(
            owner.reconcile_terminal_failure(&mut store, id).unwrap(),
            failure
        );
        assert!(matches!(
            store.begin(&mut owner, id).unwrap(),
            DispatchDecisionV2::Done
        ));
        assert!(store.prepare_settlement(&mut owner, id, vec![1]).is_err());
    }
    assert_eq!(runtime.calls, 1);
    assert_eq!(store.readback(id).unwrap(), prior);
    let now = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap();
    assert_eq!(now.row, funding.row);
}

#[test]
fn qualified_terminal_cost_is_recorded_once_and_overruns_are_never_clipped() {
    for overrun in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut n = open(
            &d.path().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        );
        let (task, wire) = reserve(&n.settings);
        let genesis = n.settings.genesis();
        mine(&mut n, genesis, vec![wire]);
        let s = statement(task);
        let mut store =
            NativeGenerationStoreV2::open(&d.path().join("m12.sqlite"), configuration(&n)).unwrap();
        let mut runtime = TerminalFixture::new(&s, TerminalReasonV3::Failed);
        let used = GenerationResourcesV2 {
            cpu_ns: if overrun {
                s.resource_cap.cpu_ns + 1
            } else {
                123
            },
            gpu_ns: 7,
            memory_peak_upper_bound_bytes: 2048,
            receipt_bytes: 0,
        };
        runtime.observed.as_mut().unwrap().resources = Some(used.clone());
        let id = start(&mut n, &mut store, &s, &mut runtime);
        let failure = {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            owner.reconcile_terminal_failure(&mut store, id).unwrap()
        };
        assert_eq!(
            failure.kind,
            if overrun {
                FailureKindV2::ResourceOverrun
            } else {
                FailureKindV2::Failed
            }
        );
        assert_eq!(store.readback(id).unwrap().resource_charge, used);
        let mut changed: FailureV2 = failure.clone();
        changed.consumed.as_mut().unwrap().cpu_ns -= 1;
        assert!(store.fail(id, changed).is_err());
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            assert_eq!(
                owner.reconcile_terminal_failure(&mut store, id).unwrap(),
                failure
            );
        }
        assert_eq!(runtime.calls, 1);
        assert_eq!(store.readback(id).unwrap().resource_charge, used);
    }
}

#[test]
fn timeout_requires_original_deadline_and_retains_complete_identity_after_expiry() {
    for early in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut n = open(
            &d.path().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        );
        let (task, wire) = reserve(&n.settings);
        let genesis = n.settings.genesis();
        mine(&mut n, genesis, vec![wire]);
        let s = statement(task);
        let mut store =
            NativeGenerationStoreV2::open(&d.path().join("m12.sqlite"), configuration(&n)).unwrap();
        let mut runtime = TerminalFixture::new(&s, TerminalReasonV3::TimedOut);
        let id = start(&mut n, &mut store, &s, &mut runtime);
        let prior = store.readback(id).unwrap();
        runtime
            .observed
            .as_mut()
            .unwrap()
            .controller_observed
            .now_ns = s.original_deadline.deadline_ns - u64::from(early);
        runtime.now.now_ns = s.original_deadline.deadline_ns + 1;
        let result = {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            owner.reconcile_terminal_failure(&mut store, id)
        };
        if early {
            assert!(result.is_err());
            assert_eq!(store.readback(id).unwrap(), prior);
        } else {
            assert_eq!(result.unwrap().kind, FailureKindV2::Unknown);
            let after = store.readback(id).unwrap();
            assert_eq!(after.statement, s);
            assert_eq!(after.job, prior.job);
            assert_eq!(after.resource_charge, s.resource_cap);
        }
    }
}

#[test]
fn terminal_reconciliation_rejects_job_source_clock_and_cancel_authority_changes() {
    for mutation in 0..7 {
        let d = tempfile::tempdir().unwrap();
        let mut n = open(
            &d.path().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        );
        let (task, wire) = reserve(&n.settings);
        let genesis = n.settings.genesis();
        mine(&mut n, genesis, vec![wire]);
        let s = statement(task);
        let mut store =
            NativeGenerationStoreV2::open(&d.path().join("m12.sqlite"), configuration(&n)).unwrap();
        let mut runtime = TerminalFixture::new(&s, TerminalReasonV3::Failed);
        let id = start(&mut n, &mut store, &s, &mut runtime);
        let prior = store.readback(id).unwrap();
        let observed = runtime.observed.as_mut().unwrap();
        match mutation {
            0 => observed.job.job_id.push('x'),
            1 => observed.job.operation = [91; 32],
            2 => observed.execution_source_commitment = [92; 32],
            3 => observed.evidence_digest = [0; 32],
            4 => observed.controller_observed.clock_domain = [93; 32],
            5 => observed.controller_observed.now_ns += 1,
            6 => observed.reason = TerminalReasonV3::Cancelled,
            _ => unreachable!(),
        }
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            assert!(owner.reconcile_terminal_failure(&mut store, id).is_err());
        }
        assert_eq!(store.readback(id).unwrap(), prior);
    }
}

#[test]
fn real_native_reorg_preserves_terminal_cost_and_local_owner_cancel_without_replay() {
    let d = tempfile::tempdir().unwrap();
    let node_path = d.path().join("node");
    let journal = d.path().join("m12.sqlite");
    let mut n = open(&node_path, StateBackend::PermanentAccountGrowthV2);
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    let reserved = mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let cfg = configuration(&n);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg.clone()).unwrap();
    let mut runtime = TerminalFixture::new(&s, TerminalReasonV3::Cancelled);
    let id = start(&mut n, &mut store, &s, &mut runtime);
    store.cancel(id, [41; 32]).unwrap();
    let cancel_wire = signed(&n.settings, 0, 2, 3, task.to_vec());
    let cancelled = mine(&mut n, reserved, vec![cancel_wire]);
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        owner.reconcile_terminal_failure(&mut store, id).unwrap();
    }
    let prior = store.readback(id).unwrap();
    assert_eq!(prior.resource_charge, s.resource_cap);
    let alt2 = mine(&mut n, reserved, vec![]);
    let alt3 = mine(&mut n, alt2, vec![]);
    assert_eq!(n.active().unwrap().0, alt3);
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "reserved");
    assert_eq!(row["remaining"], 1000);
    drop(store);
    drop(n);
    let mut n = open(&node_path, StateBackend::PermanentAccountGrowthV2);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg).unwrap();
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        owner.reconcile_terminal_failure(&mut store, id).unwrap();
        assert!(matches!(
            store.begin(&mut owner, id).unwrap(),
            DispatchDecisionV2::Done
        ));
    }
    assert_eq!(runtime.calls, 1);
    assert_eq!(store.readback(id).unwrap(), prior);
    let restored3 = mine(&mut n, cancelled, vec![]);
    let restored4 = mine(&mut n, restored3, vec![]);
    assert_eq!(n.active().unwrap().0, restored4);
    assert_eq!(store.readback(id).unwrap(), prior);
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "cancelled");
    assert_eq!(row["remaining"], 0);
}
