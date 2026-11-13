//! Unit-test fixtures. MockOwner is a TRUSTED-BOUNDARY TEST DOUBLE.
//! These tests establish no cryptographic proof, provider freshness or real payment.
use super::*;
use crate::native_budget::{NativeBudgetConfigV1, NativeBudgetStoreV1, NativeFundingObservationV1};
use serde_json::json;
use std::path::PathBuf;

fn hex(v: Hash) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn cfg() -> ConfigurationV2 {
    ConfigurationV2 {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        max_records: 16,
    }
}

#[cfg(unix)]
#[test]
fn generation_regular_wal_reopen_keeps_original_identity_and_pending_dispatch() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(OsString::from_vec(b"generation-\xff.sqlite".to_vec()));
    let statement = statement();
    let mut owner = MockOwner::new(&statement);
    let mut first = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
    let id = first.prepare(&mut owner, statement.clone()).unwrap();
    assert!(matches!(
        first.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::New
    ));
    let identity = first.journal_identity();
    let before = first.readback(id).unwrap();
    let mut second = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
    assert_eq!(second.journal_identity(), identity);
    assert_eq!(second.readback(id).unwrap(), before);
    assert!(matches!(
        second.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    drop(first);
    drop(second);
    let mut cold = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
    assert_eq!(cold.journal_identity(), identity);
    assert!(matches!(
        cold.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    assert_eq!(cold.readback(id).unwrap(), before);
    assert_eq!(before.resource_charge, statement.resource_cap);
}
fn statement() -> GenerationStatementV2 {
    GenerationStatementV2 {
        lane: GenerationLaneV2::FullW1ProofGeneration,
        task: [4; 32],
        owner: [5; 32],
        provider: [6; 32],
        input_sha256: [7; 32],
        header_sha256: sha256(b"header"),
        expected_artifacts_sha256: sha256(&[7; 64]),
        expected_journal_sha256: [9; 32],
        expected_work_id: [10; 32],
        image_id: [11; 8],
        guest_sha256: [12; 32],
        verifier_binary_sha256: [13; 32],
        execution_source_commitment: [14; 32],
        original_deadline: OriginalDeadlineV2 {
            clock_domain: [15; 32],
            winner_ns: 100,
            deadline_ns: 1000,
        },
        chain_deadline: 20,
        provider_namespace: [16; 32],
        provider_operation: [17; 32],
        request_digest: [18; 32],
        resource_cap: GenerationResourcesV2 {
            cpu_ns: 500,
            gpu_ns: 500,
            memory_peak_upper_bound_bytes: 1000,
            receipt_bytes: 1000,
        },
    }
}
fn job(s: &GenerationStatementV2) -> ProviderJobV2 {
    ProviderJobV2 {
        provider_namespace: s.provider_namespace,
        operation: s.provider_operation,
        request_digest: s.request_digest,
        job_id: "ACTUAL-TEST-TARGET-JOB-1".into(),
    }
}
fn evidence() -> GenerationEvidenceV2<'static> {
    GenerationEvidenceV2 {
        receipt: b"TEST-ONLY-NOT-A-CRYPTOGRAPHIC-PROOF",
        header: b"header",
        expected_artifacts: &[7; 64],
        owned_execution_evidence: [21; 32],
    }
}
struct MockOwner {
    row: Option<serde_json::Value>,
    anchor: NativeBudgetAnchorV1,
    clock: ClockCheckpointV2,
    reject_verifier: bool,
    paid: bool,
    verify_calls: usize,
    payment_observations: usize,
    claim_calls: usize,
    cancel_during_verify: Option<(PathBuf, Hash)>,
    task_owners: BTreeMap<Hash, (Hash, Hash)>,
}
impl MockOwner {
    fn new(s: &GenerationStatementV2) -> Self {
        Self {
            row: Some(
                json!({"owner":hex(s.owner),"provider":hex(s.provider),"remaining":100,
            "deadline":s.chain_deadline,"status":"reserved","output":null}),
            ),
            anchor: NativeBudgetAnchorV1 {
                network: [1; 32],
                parameters: [2; 32],
                genesis: [3; 32],
                block: [30; 32],
                state_root: [31; 32],
                height: 1,
                generation: 1,
            },
            clock: ClockCheckpointV2 {
                clock_domain: s.original_deadline.clock_domain,
                now_ns: 200,
            },
            reject_verifier: false,
            paid: false,
            verify_calls: 0,
            payment_observations: 0,
            claim_calls: 0,
            cancel_during_verify: None,
            task_owners: BTreeMap::new(),
        }
    }
    fn receipt(&mut self, s: &GenerationStatementV2) {
        self.row.as_mut().unwrap()["status"] = json!("receipt");
        self.row.as_mut().unwrap()["output"] = json!(hex(s.id().unwrap()));
        self.anchor.generation += 1;
        self.anchor.height += 1;
        self.anchor.block[0] += 1;
    }
}
impl NativeFundingOwnerV1 for MockOwner {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> Result<NativeFundingObservationV1> {
        Ok(NativeFundingObservationV1 {
            anchor: self.anchor,
            source,
            row: self.row.clone(),
        })
    }
    fn observe_payment(&mut self, q: &NativePaymentQueryV1) -> Result<NativePaymentObservationV1> {
        self.payment_observations += 1;
        require(self.paid, "UNIT_TEST_NO_CANONICAL_PAYMENT")?;
        Ok(NativePaymentObservationV1 {
            anchor: self.anchor,
            source: q.source,
            subject: q.subject,
            beneficiary: q.beneficiary,
            operation: q.operation,
            gross_escrow_debit: 100,
            beneficiary_credit: 100,
        })
    }
}
impl NativeGenerationOwnerV2 for MockOwner {
    fn claim_generation_task(&mut self, s: &GenerationStatementV2, journal: Hash) -> Result<()> {
        self.claim_calls += 1;
        let expected = (s.id()?, journal);
        if let Some(old) = self.task_owners.get(&s.task) {
            require(old == &expected, "UNIT_TEST_TASK_OWNED_BY_ANOTHER_JOURNAL")?;
        } else {
            self.task_owners.insert(s.task, expected);
        }
        Ok(())
    }
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(self.clock.clone())
    }
    fn verify_full_generation(
        &mut self,
        s: &GenerationStatementV2,
        _job: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<IndependentFullVerdictV2> {
        self.verify_calls += 1;
        if let Some((path, id)) = &self.cancel_during_verify {
            NativeGenerationStoreV2::open(path, cfg())?.cancel(*id, [99; 32])?;
        }
        require(
            !self.reject_verifier,
            "UNIT_TEST_INDEPENDENT_VERIFIER_REJECT",
        )?;
        Ok(IndependentFullVerdictV2 {
            receipt_sha256: sha256(e.receipt),
            header_sha256: s.header_sha256,
            expected_artifacts_sha256: s.expected_artifacts_sha256,
            journal_sha256: s.expected_journal_sha256,
            work_id: s.expected_work_id,
            image_id: s.image_id,
            profile_id: PROFILE.into(),
            sdk: "3.0.6".into(),
            verifier_binary_sha256: s.verifier_binary_sha256,
            owned_execution_evidence: e.owned_execution_evidence,
            consumed: GenerationResourcesV2 {
                cpu_ns: 10,
                gpu_ns: 20,
                memory_peak_upper_bound_bytes: 30,
                receipt_bytes: e.receipt.len() as u64,
            },
        })
    }
    fn check_settlement_wire(
        &mut self,
        s: &GenerationStatementV2,
        wire: &[u8],
    ) -> Result<NativePaymentQueryV1> {
        Ok(NativePaymentQueryV1 {
            source: NativeFundingSourceV1::Task(s.task),
            subject: s.id()?,
            beneficiary: s.provider,
            operation: sha256(wire),
            maximum_gross_units: 100,
        })
    }
}
fn started(
    path: &Path,
    s: &GenerationStatementV2,
    o: &mut MockOwner,
) -> (NativeGenerationStoreV2, Hash) {
    let mut store = NativeGenerationStoreV2::open(path, cfg()).unwrap();
    let id = store.prepare(o, s.clone()).unwrap();
    assert!(matches!(
        store.begin(o, id).unwrap(),
        DispatchDecisionV2::New
    ));
    store.bind_job(id, job(s)).unwrap();
    (store, id)
}

#[test]
fn generation_namespace_refuses_v1_without_migration_or_writes() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("v1.sqlite");
    let old = NativeBudgetStoreV1::open(
        &p,
        NativeBudgetConfigV1 {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            max_records: 16,
        },
    )
    .unwrap();
    let old_report = old.report().unwrap();
    assert!(NativeGenerationStoreV2::open(&p, cfg()).is_err());
    assert_eq!(old.report().unwrap(), old_report);
    assert_ne!(NAMESPACE, crate::native_budget::NATIVE_BUDGET_NAMESPACE_V1);
}
#[test]
fn a_second_generation_journal_cannot_claim_the_same_task_or_reset_its_deadline() {
    let d = tempfile::tempdir().unwrap();
    let s = statement();
    let mut o = MockOwner::new(&s);
    let mut a = NativeGenerationStoreV2::open(&d.path().join("a.sqlite"), cfg()).unwrap();
    let mut b = NativeGenerationStoreV2::open(&d.path().join("b.sqlite"), cfg()).unwrap();
    let id = a.prepare(&mut o, s.clone()).unwrap();
    assert_ne!(a.journal_identity(), b.journal_identity());
    assert!(b.prepare(&mut o, s.clone()).is_err());
    let mut changed = s;
    changed.original_deadline.deadline_ns += 100;
    assert!(b.prepare(&mut o, changed).is_err());
    assert!(!a.readback(id).unwrap().dispatch_intent);
    assert!(b.readback(id).is_err());
}
#[test]
fn committed_intent_after_cold_restart_never_reissues_new_even_without_funding() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (store, id) = started(&p, &s, &mut o);
    let prior = store.readback(id).unwrap();
    drop(store);
    o.row = None;
    let mut store = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    assert!(matches!(
        store.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    assert_eq!(store.readback(id).unwrap(), prior);
    let mut changed = job(&s);
    changed.job_id.push('2');
    assert!(store.bind_job(id, changed).is_err());
    let mut changed = s.clone();
    changed.original_deadline.deadline_ns += 1;
    assert!(store.prepare(&mut o, changed).is_err());
    assert_eq!(store.readback(id).unwrap(), prior);
}
#[test]
fn one_of_two_handles_gets_new_and_unknown_consumes_the_original_reservation() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let mut a = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    let id = a.prepare(&mut o, s.clone()).unwrap();
    let mut b = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    assert!(matches!(
        a.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::New
    ));
    assert!(matches!(
        b.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    a.fail(
        id,
        FailureV2 {
            kind: FailureKindV2::Unknown,
            evidence_digest: [44; 32],
            consumed: None,
        },
    )
    .unwrap();
    assert_eq!(b.readback(id).unwrap().resource_charge, s.resource_cap);
    assert!(matches!(
        b.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::Done
    ));
}
#[test]
fn original_deadline_and_clock_domain_never_renew_on_replay() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let mut a = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    let id = a.prepare(&mut o, s.clone()).unwrap();
    let original = a.readback(id).unwrap();
    o.clock.now_ns = s.original_deadline.deadline_ns;
    assert!(a.begin(&mut o, id).is_err());
    assert_eq!(a.readback(id).unwrap(), original);
    o.clock.now_ns = 200;
    o.clock.clock_domain = [77; 32];
    assert!(a.begin(&mut o, id).is_err());
    assert_eq!(a.readback(id).unwrap(), original);
    let mut renewed = s;
    renewed.original_deadline.clock_domain = [77; 32];
    renewed.original_deadline.deadline_ns = 2000;
    assert!(a.prepare(&mut o, renewed).is_err());
}
#[test]
fn provider_identity_and_ack_never_substitute_for_full_verifier() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (mut a, id) = started(&p, &s, &mut o);
    o.reject_verifier = true;
    let prior = a.readback(id).unwrap();
    assert!(a.verify(&mut o, id, &evidence()).is_err());
    assert_eq!(a.readback(id).unwrap(), prior);
    assert_eq!(o.verify_calls, 1);
    o.receipt(&s);
    assert!(a
        .prepare_settlement(&mut o, id, b"UNIT-TEST-WIRE".to_vec())
        .is_err());
    assert!(a.record_payment(&mut o, id).is_err());
}
#[test]
fn cancellation_committed_while_verifier_runs_is_sticky_and_blocks_settlement() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (mut a, id) = started(&p, &s, &mut o);
    o.cancel_during_verify = Some((p.clone(), id));
    assert!(a.verify(&mut o, id, &evidence()).is_err());
    let prior = a.readback(id).unwrap();
    assert_eq!(prior.cancellation, Some([99; 32]));
    assert!(prior.verified.is_none());
    drop(a);
    let mut a = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    o.cancel_during_verify = None;
    o.receipt(&s);
    assert!(a.verify(&mut o, id, &evidence()).is_err());
    assert!(a
        .prepare_settlement(&mut o, id, b"UNIT-TEST-WIRE".to_vec())
        .is_err());
    assert!(matches!(
        a.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::Done
    ));
    assert_eq!(a.readback(id).unwrap(), prior);
}
#[test]
fn cancel_after_verified_preserves_cost_and_cancel_after_settlement_intent_is_too_late() {
    let d = tempfile::tempdir().unwrap();
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (mut a, id) = started(&d.path().join("cancel-before.sqlite"), &s, &mut o);
    a.verify(&mut o, id, &evidence()).unwrap();
    let cost = a.readback(id).unwrap().resource_charge;
    a.cancel(id, [80; 32]).unwrap();
    o.receipt(&s);
    assert!(a.prepare_settlement(&mut o, id, b"wire".to_vec()).is_err());
    assert_eq!(a.readback(id).unwrap().resource_charge, cost);
    let mut o = MockOwner::new(&s);
    let (mut b, id) = started(&d.path().join("intent-first.sqlite"), &s, &mut o);
    b.verify(&mut o, id, &evidence()).unwrap();
    o.receipt(&s);
    assert!(matches!(
        b.prepare_settlement(&mut o, id, b"wire".to_vec()).unwrap(),
        DispatchDecisionV2::New
    ));
    let prior = b.readback(id).unwrap();
    assert!(b.cancel(id, [81; 32]).is_err());
    assert_eq!(b.readback(id).unwrap(), prior);
    assert!(matches!(
        b.prepare_settlement(&mut o, id, b"wire".to_vec()).unwrap(),
        DispatchDecisionV2::Pending
    ));
    assert!(b
        .prepare_settlement(&mut o, id, b"different wire".to_vec())
        .is_err());
}
#[test]
fn historical_payment_survives_reorg_and_reobservation_never_mints_a_replacement() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (mut a, id) = started(&p, &s, &mut o);
    a.verify(&mut o, id, &evidence()).unwrap();
    o.receipt(&s);
    a.prepare_settlement(&mut o, id, b"original wire".to_vec())
        .unwrap();
    assert!(a.record_payment(&mut o, id).is_err());
    o.paid = true;
    a.record_payment(&mut o, id).unwrap();
    let count = o.payment_observations;
    a.record_payment(&mut o, id).unwrap();
    assert_eq!(o.payment_observations, count);
    let historical = a.readback(id).unwrap();
    drop(a);
    o.paid = false;
    o.anchor.generation += 1;
    let mut a = NativeGenerationStoreV2::open(&p, cfg()).unwrap();
    assert!(a.reobserve_payment(&mut o, id).is_err());
    assert_eq!(a.readback(id).unwrap(), historical);
    assert!(matches!(
        a.prepare_settlement(&mut o, id, b"original wire".to_vec())
            .unwrap(),
        DispatchDecisionV2::Done
    ));
    o.paid = true;
    o.anchor.generation += 1;
    let current = a.reobserve_payment(&mut o, id).unwrap();
    assert_eq!(
        current.operation,
        historical.historical_payment.as_ref().unwrap().operation
    );
    assert_eq!(a.readback(id).unwrap(), historical);
}
#[test]
fn actual_resource_overrun_is_retained_without_clipping_or_positive() {
    let d = tempfile::tempdir().unwrap();
    let s = statement();
    let mut o = MockOwner::new(&s);
    let (mut a, id) = started(&d.path().join("generation.sqlite"), &s, &mut o);
    let mut actual = s.resource_cap.clone();
    actual.cpu_ns += 999;
    a.fail(
        id,
        FailureV2 {
            kind: FailureKindV2::ResourceOverrun,
            evidence_digest: [88; 32],
            consumed: Some(actual.clone()),
        },
    )
    .unwrap();
    assert_eq!(a.readback(id).unwrap().resource_charge, actual);
    assert!(a.readback(id).unwrap().verified.is_none());
}

#[test]
fn cancel_before_dispatch_is_terminal_after_cold_reopen_without_repinning_funds() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("generation.sqlite");
    let s = statement();
    let mut o = MockOwner::new(&s);
    let mut store = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
    let id = store.prepare(&mut o, s.clone()).unwrap();
    store.cancel(id, [84; 32]).unwrap();
    let prior = store.readback(id).unwrap();
    assert!(!prior.dispatch_intent);
    assert_eq!(prior.resource_charge, s.resource_cap);
    drop(store);
    o.row = None;
    o.clock.clock_domain = [85; 32];
    let mut store = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
    assert!(matches!(
        store.begin(&mut o, id).unwrap(),
        DispatchDecisionV2::Done
    ));
    assert_eq!(store.readback(id).unwrap(), prior);
    assert!(store.bind_job(id, job(&s)).is_err());
}

#[test]
fn restored_fixed_size_blobs_refuse_before_owner_callbacks_and_cold_reopen() {
    for (table, field, expected) in [
        (
            "native_generation_meta_v2",
            "journal",
            "GENERATION_JOURNAL_IDENTITY",
        ),
        (
            "native_generation_meta_v2",
            "root",
            "GENERATION_JOURNAL_ROOT_SIZE",
        ),
        (
            "native_generation_events_v2",
            "root",
            "GENERATION_JOURNAL_ROOT_SIZE",
        ),
    ] {
        for bytes in [0, 31, 33, 16 * 1024 * 1024] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("restored.sqlite");
            let s = statement();
            let mut o = MockOwner::new(&s);
            let mut store = NativeGenerationStoreV2::open(&path, cfg()).unwrap();
            let id = store.prepare(&mut o, s).unwrap();
            let claims = o.claim_calls;
            let corrupt = Connection::open(&path).unwrap();
            // A copied SQLite file need not have honored its stored CHECKs.
            corrupt
                .pragma_update(None, "ignore_check_constraints", true)
                .unwrap();
            corrupt
                .execute(&format!("UPDATE {table} SET {field}=zeroblob(?1)"), [bytes])
                .unwrap();
            drop(corrupt);
            assert!(store
                .recovery_checkpoint_v3()
                .unwrap_err()
                .to_string()
                .contains(expected));
            assert!(store
                .begin(&mut o, id)
                .err()
                .unwrap()
                .to_string()
                .contains(expected));
            assert_eq!(o.claim_calls, claims);
            drop(store);
            assert!(NativeGenerationStoreV2::open(&path, cfg())
                .err()
                .unwrap()
                .to_string()
                .contains(expected));
        }
    }
}
