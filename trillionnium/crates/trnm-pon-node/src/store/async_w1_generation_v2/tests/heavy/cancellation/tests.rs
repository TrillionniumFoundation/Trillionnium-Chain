//! Real signed research Node/M12 controls. No successful verifier fixture or
//! subprocess proof is used; the runtime rejects every verification request.
use super::super::super::{reserve, statement as binding_fixture};
use super::*;
use trnm_service_settlement::native_generation_budget_v2::{
    FailureKindV2, FailureV2, SettlementIntentV2,
};

struct NoProofRuntime;
impl OwnedGenerationRuntimeV2 for NoProofRuntime {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(ClockCheckpointV2 {
            clock_domain: [9; 32],
            now_ns: 200,
        })
    }
    fn reconcile_fresh_execution(
        &mut self,
        _: &GenerationStatementV2,
        _: &ProviderJobV2,
        _: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        Err(error("NO_GENERATION_EXECUTED_IN_OWNER_CANCEL_CONTROL"))
    }
    fn run_independent_verifier(
        &mut self,
        _: &GenerationStatementV2,
        _: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        Err(error("NO_VERIFIER_SUCCESS_IN_OWNER_CANCEL_CONTROL"))
    }
}

fn begin(n: &mut Node, store: &mut NativeGenerationStoreV2, s: &GenerationStatementV2) -> Hash {
    let mut runtime = NoProofRuntime;
    let mut owner = NodeGenerationOwnerV2::new(n, &mut runtime).unwrap();
    let id = store.prepare(&mut owner, s.clone()).unwrap();
    assert!(matches!(
        store.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::New
    ));
    id
}

#[test]
fn actual_owner_cancel_cold_reopen_and_reorg_preserve_veto_and_full_cap() {
    let d = tempfile::tempdir().unwrap();
    let node_path = d.path().join("node");
    let journal = d.path().join("generation.sqlite");
    let out = d.path().join("cancel");
    fs::create_dir(&out).unwrap();
    let mut n = open(&node_path, StateBackend::PermanentAccountGrowthV2);
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    let reserved = mine(&mut n, genesis, vec![wire]);
    let s = binding_fixture(task);
    let cfg = configuration(&n);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg.clone()).unwrap();
    let id = begin(&mut n, &mut store, &s);
    assert_eq!(
        commit_owner_veto(&mut store, id, public(2), s.provider_operation, [21; 32]).unwrap()
            ["accepted_observed"],
        false
    );
    assert!(store.readback(id).unwrap().cancellation.is_none());
    let accepted =
        commit_owner_veto(&mut store, id, s.owner, s.provider_operation, [22; 32]).unwrap();
    assert_eq!(accepted["accepted_observed"], true);
    assert_eq!(accepted["resource_reservation_released"], false);
    let replay =
        commit_owner_veto(&mut store, id, s.owner, s.provider_operation, [23; 32]).unwrap();
    assert_eq!(replay["decision"], "PriorCancellationReconcileOnly");
    assert_eq!(replay["target_cancel_authorized"], false);
    assert_eq!(store.readback(id).unwrap().cancellation, Some([22; 32]));
    let provider_before = balance(&n, public(1));
    let cancelled_tip = native_cancel(&mut n, &out, task, id, reserved, 1).unwrap();
    assert_eq!(
        observe_native(&n, &out, task).unwrap()["canonical_cancel_observed"],
        true
    );
    let before = store.readback(id).unwrap();
    assert_eq!(before.resource_charge, s.resource_cap);
    assert!(
        before.verified.is_none()
            && before.settlement.is_none()
            && before.historical_payment.is_none()
    );
    drop(store);
    drop(n);
    let mut n = open(&node_path, StateBackend::PermanentAccountGrowthV2);
    let mut store = NativeGenerationStoreV2::open(&journal, cfg).unwrap();
    let mut runtime = NoProofRuntime;
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(matches!(
            store.begin(&mut owner, id).unwrap(),
            DispatchDecisionV2::Done
        ));
    }
    assert_eq!(store.readback(id).unwrap(), before);
    assert_eq!(balance(&n, public(1)), provider_before);
    // An old ancestor is not a higher-ranked fork. Build a real longer branch
    // without the cancel transaction, using the Node's ordinary fork choice.
    let alternate_two = mine(&mut n, reserved, vec![]);
    let alternate_three = mine(&mut n, alternate_two, vec![]);
    assert_eq!(n.active().unwrap().0, alternate_three);
    let reorg = observe_native(&n, &out, task).unwrap();
    assert_eq!(reorg["canonical_cancel_observed"], false);
    assert_eq!(reorg["refund_claim"], false);
    assert_eq!(reorg["funding_row"]["status"], "reserved");
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(matches!(
            store.begin(&mut owner, id).unwrap(),
            DispatchDecisionV2::Done
        ));
    }
    assert_eq!(store.readback(id).unwrap(), before);
    // Restore the original cancel's ancestry without signing or submitting a
    // second TaskCancel. Its canonical observation can return; the M12 veto and
    // retained full resource cap never rolled back along with the native fork.
    let restored_three = mine(&mut n, cancelled_tip, vec![]);
    let restored_four = mine(&mut n, restored_three, vec![]);
    assert_eq!(n.active().unwrap().0, restored_four);
    assert_eq!(
        observe_native(&n, &out, task).unwrap()["canonical_cancel_observed"],
        true
    );
    assert_eq!(store.readback(id).unwrap(), before);
    assert_eq!(balance(&n, public(1)), provider_before);
}

#[test]
fn provider_unknown_is_not_owner_cancel_and_no_resource_refund() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(
        &d.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    mine(&mut n, genesis, vec![wire]);
    let s = binding_fixture(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("m12.sqlite"), configuration(&n)).unwrap();
    let id = begin(&mut n, &mut store, &s);
    store
        .fail(
            id,
            FailureV2 {
                kind: FailureKindV2::Unknown,
                evidence_digest: [25; 32],
                consumed: None,
            },
        )
        .unwrap();
    let retained = store.readback(id).unwrap();
    assert!(
        retained.cancellation.is_none()
            && retained.verified.is_none()
            && retained.settlement.is_none()
    );
    assert_eq!(retained.resource_charge, s.resource_cap);
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "reserved");
    assert_eq!(row["remaining"], 1000);
}

#[test]
fn actual_native_receipt_refuses_new_owner_cancel_without_writing_intent() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(
        &d.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (task, wire) = reserve(&n.settings);
    let settings = n.settings.clone();
    let reserved = mine(&mut n, settings.genesis(), vec![wire]);
    let mut payload = task.to_vec();
    payload.extend([31; 32]);
    let receipt = mine(&mut n, reserved, vec![signed(&settings, 1, 1, 4, payload)]);
    let out = d.path().join("cancel");
    fs::create_dir(&out).unwrap();
    assert!(native_cancel(&mut n, &out, task, [31; 32], receipt, 1).is_err());
    assert!(!out.join("native-cancel-dispatch-intent.json").exists());
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "receipt");
    assert_eq!(row["remaining"], 1000);
}

#[test]
fn requested_policy_too_late_and_plan_are_conservative() {
    let s = binding_fixture([35; 32]);
    // Pure reader-policy input only. This is not an inserted durable settlement
    // or a verifier result; actual settle races remain guarded by M12.cancel.
    let before = GenerationReadbackV2 {
        statement: s.clone(),
        dispatch_intent: true,
        job: None,
        verified: None,
        failure: None,
        cancellation: None,
        settlement: Some(SettlementIntentV2 {
            operation: [36; 32],
            exact_wire: vec![0],
        }),
        historical_payment: None,
        resource_charge: s.resource_cap.clone(),
    };
    assert_eq!(
        requested_decision(&before, s.owner, s.provider_operation),
        "TooLate"
    );
    let c = json!({"owner_cancellation":{"schema":"TRNM-W1-OWNER-CANCEL-PLAN1",
        "authority":"development-owner-0","trigger":"live-first-prove-r0vm",
        "reason_sha256":hex::encode([37;32]),"native_task_action":"cancel-reserved"}});
    assert!(Plan::parse(&c).unwrap().cancel_native);
    let mut changed = c;
    changed["owner_cancellation"]["native_task_action"] = json!("refund-on-provider-error");
    assert!(Plan::parse(&changed).is_err());
    assert!(Plan::parse(&json!({"provider_error":"failed"})).is_err());
}

#[test]
fn actual_two_handle_same_reason_replay_never_claims_new_event() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(
        &d.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    mine(&mut n, genesis, vec![wire]);
    let s = binding_fixture(task);
    let path = d.path().join("m12.sqlite");
    let cfg = configuration(&n);
    let mut first = NativeGenerationStoreV2::open(&path, cfg.clone()).unwrap();
    let id = begin(&mut n, &mut first, &s);
    let before = first.readback(id).unwrap();
    assert_eq!(
        requested_decision(&before, s.owner, s.provider_operation),
        "MayRequest"
    );
    // Reproduce the precise interleaving: the first caller has read None,
    // another real handle appends the same reason, then the first gets Replay.
    let mut second = NativeGenerationStoreV2::open(&path, cfg).unwrap();
    second.cancel(id, [41; 32]).unwrap();
    first.cancel(id, [41; 32]).unwrap();
    let after = first.readback(id).unwrap();
    let observed = observed_veto(&before, &after, [41; 32]).unwrap();
    assert_eq!(observed["decision"], "CancellationObserved");
    assert_eq!(observed["accepted_observed"], true);
    assert_eq!(observed["new_event_proven"], false);
    assert!(observed["journal_event_new"].is_null());
    assert!(observed_veto(&before, &after, [42; 32]).is_err());
}

#[test]
fn prepared_only_cold_reader_refuses_before_begin_without_mutation() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(
        &d.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (task, wire) = reserve(&n.settings);
    let genesis = n.settings.genesis();
    mine(&mut n, genesis, vec![wire]);
    let s = binding_fixture(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("m12.sqlite"), configuration(&n)).unwrap();
    let mut runtime = NoProofRuntime;
    let id = {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        store.prepare(&mut owner, s).unwrap()
    };
    let original = store.readback(id).unwrap();
    assert!(!original.dispatch_intent);
    assert!(require_existing_dispatch(&original).is_err());
    assert_eq!(store.readback(id).unwrap(), original);
}
