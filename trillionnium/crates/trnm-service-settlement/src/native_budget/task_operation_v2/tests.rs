//! Adversarial tests of the actual SQLite journal. Callback observations below
//! are controlled fixtures; the Node integration suite supplies real signatures,
//! canonical replay and persistent cross-version/operation fences.
use super::*;
use crate::native_budget::{NativeBudgetStoreV1, NativeFundingObservationV1};

fn config() -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        max_records: 8,
    }
}

#[cfg(unix)]
#[test]
fn task_operation_regular_wal_reopen_keeps_checkpoint_and_one_time_begin() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(OsString::from_vec(b"task-\xff.sqlite".to_vec()));
    let mut first = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    first.reserve(&mut owner, binding.clone()).unwrap();
    assert_eq!(
        first.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::New
    );
    let checkpoint = first.checkpoint().unwrap();
    let snapshot = first.snapshot(binding.claim).unwrap();
    let mut second = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    assert_eq!(second.checkpoint().unwrap(), checkpoint);
    assert_eq!(second.snapshot(binding.claim).unwrap(), snapshot);
    assert_eq!(
        second.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    drop(first);
    drop(second);
    let mut cold = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    assert_eq!(cold.checkpoint().unwrap(), checkpoint);
    assert_eq!(
        cold.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(owner.starts, 1);
    assert_eq!(cold.snapshot(binding.claim).unwrap(), snapshot);
}
fn binding() -> NativeTaskOperationBindingV2 {
    NativeTaskOperationBindingV2 {
        claim: [10; 32],
        task: [11; 32],
        contract_digest: [12; 32],
        operation: [13; 32],
        beneficiary: [14; 32],
        target_scope: [15; 32],
        resource_cap: NativeBudgetResourcesV1::Contribution {
            training_cpu_ns: 10,
            parameter_bytes: 100,
        },
    }
}
fn costs() -> NativeTaskCostBreakdownV2 {
    NativeTaskCostBreakdownV2 {
        training_units: 7,
        evaluation_units: 2,
        storage_units: 1,
        serving_units: 0,
        unit: [31; 32],
        measurement_receipt: [32; 32],
    }
}
fn consumed() -> NativeBudgetResourcesV1 {
    NativeBudgetResourcesV1::Contribution {
        training_cpu_ns: 7,
        parameter_bytes: 90,
    }
}

struct Owner {
    observed: NativeTaskContractObservationV2,
    pinned: Option<NativeTaskOperationBindingV2>,
    started: bool,
    starts: u64,
    fail_after_start: bool,
    payment: Option<NativePaymentObservationV1>,
    payment_read_hook: Option<Box<dyn FnOnce() -> Result<()>>>,
}
impl Owner {
    fn new() -> Self {
        let binding = binding();
        let cfg = config();
        Self {
            observed: NativeTaskContractObservationV2 {
                anchor: NativeBudgetAnchorV1 {
                    network: cfg.network,
                    parameters: cfg.parameters,
                    genesis: cfg.genesis,
                    block: [21; 32],
                    state_root: [22; 32],
                    height: 1,
                    generation: 1,
                },
                task: binding.task,
                contract_digest: binding.contract_digest,
                payer: [16; 32],
                provider: binding.beneficiary,
                request: [17; 32],
                model: [18; 32],
                input: [19; 32],
                output_spec: [20; 32],
                amount: 2_000,
                delivery_deadline: 10,
                dispute_deadline: 20,
                remaining: 2_000,
                status: NativeTaskStatusV2::Reserved,
                output: None,
                receipt_height: None,
            },
            pinned: None,
            started: false,
            starts: 0,
            fail_after_start: false,
            payment: None,
            payment_read_hook: None,
        }
    }
    fn deliver(&mut self, output: Hash) {
        self.observed.anchor.generation = 2;
        self.observed.anchor.height = 2;
        self.observed.anchor.block = [23; 32];
        self.observed.anchor.state_root = [24; 32];
        self.observed.status = NativeTaskStatusV2::Receipt;
        self.observed.output = Some(output);
        self.observed.receipt_height = Some(2);
    }
    fn pay(&mut self, operation: Hash) {
        self.observed.anchor.generation = 3;
        self.observed.anchor.height = 3;
        self.observed.anchor.block = [25; 32];
        self.observed.anchor.state_root = [26; 32];
        self.observed.status = NativeTaskStatusV2::Settled;
        self.observed.remaining = 0;
        self.payment = Some(NativePaymentObservationV1 {
            anchor: self.observed.anchor,
            source: NativeFundingSourceV1::Task(self.observed.task),
            subject: self.observed.output.unwrap(),
            beneficiary: self.observed.provider,
            operation,
            gross_escrow_debit: self.observed.amount,
            beneficiary_credit: self.observed.amount,
        });
    }
    fn check(&self, binding: &NativeTaskOperationBindingV2) -> Result<()> {
        require(self.pinned.as_ref() == Some(binding), "FIXTURE_BINDING")
    }
}
impl NativeFundingOwnerV1 for Owner {
    fn observe_funding(&mut self, _: NativeFundingSourceV1) -> Result<NativeFundingObservationV1> {
        Err(NativeBudgetErrorV1::Invalid("V2_MUST_NOT_USE_V1_FUNDING"))
    }
    fn observe_payment(
        &mut self,
        query: &NativePaymentQueryV1,
    ) -> Result<NativePaymentObservationV1> {
        if let Some(hook) = self.payment_read_hook.take() {
            hook()?;
        }
        let observed = self
            .payment
            .as_ref()
            .ok_or(NativeBudgetErrorV1::Invalid("FIXTURE_NO_PAYMENT"))?;
        require(
            observed.source == query.source
                && observed.subject == query.subject
                && observed.beneficiary == query.beneficiary
                && observed.operation == query.operation
                && observed.gross_escrow_debit <= query.maximum_gross_units,
            "FIXTURE_PAYMENT",
        )?;
        Ok(observed.clone())
    }
}
impl NativeTaskOperationOwnerV2 for Owner {
    fn reserve_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskContractObservationV2> {
        if self.pinned.is_some() {
            self.check(binding)?;
        } else {
            self.pinned = Some(binding.clone());
        }
        Ok(self.observed.clone())
    }
    fn begin_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskBeginObservationV2> {
        self.check(binding)?;
        let new_execution = !self.started;
        self.started = true;
        if new_execution {
            self.starts += 1;
        }
        if self.fail_after_start {
            self.fail_after_start = false;
            return Err(NativeBudgetErrorV1::Owner(
                "fixture lost acknowledgement after durable owner begin".into(),
            ));
        }
        Ok(NativeTaskBeginObservationV2 {
            contract: self.observed.clone(),
            new_execution,
        })
    }
    fn observe_task_delivery_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskDeliveryObservationV2> {
        self.check(binding)?;
        require(self.observed.output.is_some(), "FIXTURE_NO_DELIVERY")?;
        let mut receipt_anchor = self.observed.anchor;
        receipt_anchor.height = self.observed.receipt_height.unwrap();
        receipt_anchor.block = [23; 32];
        receipt_anchor.state_root = [24; 32];
        Ok(NativeTaskDeliveryObservationV2 {
            contract: self.observed.clone(),
            receipt_operation: [40; 32],
            receipt_anchor,
        })
    }
}

fn complete(
    store: &mut NativeTaskOperationStoreV2,
    binding: &NativeTaskOperationBindingV2,
    output: Hash,
) {
    store
        .record_costs(
            binding.claim,
            NativeResourceOutcomeV1::NoGain,
            consumed(),
            costs(),
        )
        .unwrap();
    store
        .complete(binding.claim, binding.operation, output, [42; 32])
        .unwrap();
}

#[test]
fn exact_binding_and_fresh_namespace_reject_old_journals() {
    let binding = binding();
    assert_eq!(binding.encode().unwrap().len(), 209);
    assert_eq!(
        hex_string(&binding.id().unwrap()),
        "0e4734397c7e7aedf4e85a8c7d54f43d0ef9253cb18d235c63c4392ec6ec2bbf"
    );
    assert_eq!(
        NativeTaskOperationBindingV2::decode(&binding.encode().unwrap()).unwrap(),
        binding
    );
    let mut bad = binding.encode().unwrap();
    bad.push(0);
    assert!(NativeTaskOperationBindingV2::decode(&bad).is_err());
    let directory = tempfile::tempdir().unwrap();
    let old = directory.path().join("v1.sqlite");
    drop(NativeBudgetStoreV1::open(&old, config()).unwrap());
    assert!(NativeTaskOperationStoreV2::open(&old, config()).is_err());
    let fresh = directory.path().join("v2.sqlite");
    drop(NativeTaskOperationStoreV2::open(&fresh, config()).unwrap());
    assert!(NativeBudgetStoreV1::open(&fresh, config()).is_err());
}

#[test]
fn unknown_output_is_bound_once_after_durable_intent_costs_and_actual_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operations.sqlite");
    let mut store = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    let output = [41; 32];
    assert_eq!(
        store.reserve(&mut owner, binding.clone()).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(store.snapshot(binding.claim).unwrap().reserved.output, None);
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(owner.starts, 1);
    assert!(store.bind_delivery(&mut owner, binding.claim).is_err());
    assert!(store
        .complete(binding.claim, binding.operation, output, [42; 32])
        .is_err());
    complete(&mut store, &binding, output);
    let completed = store.checkpoint().unwrap();
    owner.deliver([43; 32]);
    assert_eq!(
        store
            .bind_delivery(&mut owner, binding.claim)
            .unwrap_err()
            .to_string(),
        "TASK_OPERATION_DELIVERY_V2"
    );
    assert_eq!(store.checkpoint().unwrap(), completed);
    owner.deliver(output);
    assert_eq!(
        store.bind_delivery(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store.bind_delivery(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert!(store
        .complete(binding.claim, binding.operation, [43; 32], [42; 32])
        .is_err());
    assert!(store
        .record_costs(
            binding.claim,
            NativeResourceOutcomeV1::Positive,
            consumed(),
            costs()
        )
        .is_err());
    let payment_operation = [51; 32];
    owner.pay(payment_operation);
    assert_eq!(
        store
            .record_native_payment(&mut owner, binding.claim, payment_operation)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store
            .record_native_payment(&mut owner, binding.claim, payment_operation)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    let report = store.report().unwrap();
    let checkpoint = store.checkpoint().unwrap();
    assert_eq!(checkpoint.sequence, 6);
    assert_eq!(
        report["claims"][0]["historically_observed_native_payment"],
        2_000
    );
    assert_eq!(report["claims"][0]["learning_improvement_bonus"], false);
    drop(store);
    let mut store = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    assert_eq!(store.report().unwrap(), report);
    assert_eq!(store.verify_checkpoint(&checkpoint).unwrap(), checkpoint);
    let (snapshot, observed_checkpoint) = store
        .snapshot_after_checkpoint(binding.claim, Some(&completed))
        .unwrap();
    assert_eq!(observed_checkpoint, checkpoint);
    assert_eq!(snapshot, store.snapshot(binding.claim).unwrap());
    assert_eq!(
        store
            .reobserve_native_payment(&mut owner, binding.claim)
            .unwrap()
            .historical
            .gross_escrow_debit,
        2_000
    );
    owner.payment = None;
    owner.observed.anchor.generation = 4;
    assert!(store
        .reobserve_native_payment(&mut owner, binding.claim)
        .is_err());
    assert_eq!(store.report().unwrap(), report);
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(owner.starts, 1);
    let mut duplicate = binding;
    duplicate.claim = [61; 32];
    duplicate.operation = [62; 32];
    assert!(store.reserve(&mut owner, duplicate).is_err());
    assert_eq!(store.report().unwrap(), report);
}

#[test]
fn second_journal_and_lost_owner_acknowledgement_never_receive_a_second_new() {
    let directory = tempfile::tempdir().unwrap();
    let mut first =
        NativeTaskOperationStoreV2::open(&directory.path().join("first.sqlite"), config()).unwrap();
    let mut second =
        NativeTaskOperationStoreV2::open(&directory.path().join("second.sqlite"), config())
            .unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    first.reserve(&mut owner, binding.clone()).unwrap();
    let reserved = first.checkpoint().unwrap();
    owner.fail_after_start = true;
    assert!(first.begin(&mut owner, binding.claim).is_err());
    assert_eq!(first.checkpoint().unwrap(), reserved);
    assert_eq!(owner.starts, 1);
    assert_eq!(
        first.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    second.reserve(&mut owner, binding.clone()).unwrap();
    assert_eq!(
        second.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert!(
        !second
            .snapshot(binding.claim)
            .unwrap()
            .begun
            .unwrap()
            .new_execution
    );
    let output = [41; 32];
    // A reconciled target receipt can complete a Pending operation. Nothing in
    // this recovery path grants another dispatch or an improved-model reward.
    complete(&mut second, &binding, output);
    owner.deliver(output);
    second.bind_delivery(&mut owner, binding.claim).unwrap();
    assert_eq!(
        second.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(owner.starts, 1);
    let mut changed = binding;
    changed.claim = [70; 32];
    changed.target_scope = [71; 32];
    let mut third =
        NativeTaskOperationStoreV2::open(&directory.path().join("third.sqlite"), config()).unwrap();
    assert!(third.reserve(&mut owner, changed).is_err());
    assert_eq!(third.checkpoint().unwrap().sequence, 0);
}

#[test]
fn checkpoints_detect_local_rollback_and_owner_fence_still_blocks_redispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("current.sqlite");
    let saved = directory.path().join("saved.sqlite");
    let mut store = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    store.reserve(&mut owner, binding.clone()).unwrap();
    drop(store);
    std::fs::copy(&path, &saved).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::New
    );
    let begun = store.checkpoint().unwrap();
    drop(store);
    std::fs::copy(&saved, &path).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    assert_eq!(
        store.verify_checkpoint(&begun).unwrap_err().to_string(),
        "TASK_OPERATION_CHECKPOINT_ROLLBACK_V2"
    );
    assert!(store
        .snapshot_after_checkpoint(binding.claim, Some(&begun))
        .is_err());
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(owner.starts, 1);
    let checkpoint = store.checkpoint().unwrap();
    let mut wrong = checkpoint.clone();
    wrong.root[0] ^= 1;
    assert!(store.verify_checkpoint(&wrong).is_err());
    assert!(store
        .snapshot_after_checkpoint(binding.claim, Some(&wrong))
        .is_err());
    store
        .connection
        .execute(
            "UPDATE task_operation_events_v2 SET root=zeroblob(32) WHERE sequence=2",
            [],
        )
        .unwrap();
    assert!(store.checkpoint().is_err());
    drop(store);
    assert!(NativeTaskOperationStoreV2::open(&path, config()).is_err());
}

#[test]
fn stale_native_anchor_capacity_and_resource_overrun_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.max_records = 1;
    let mut store =
        NativeTaskOperationStoreV2::open(&directory.path().join("operations.sqlite"), cfg).unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    store.reserve(&mut owner, binding.clone()).unwrap();
    let initial_anchor = owner.observed.anchor;
    owner.observed.anchor.generation = 0;
    assert_eq!(
        store
            .begin(&mut owner, binding.claim)
            .unwrap_err()
            .to_string(),
        "TASK_OPERATION_ANCHOR_ROLLBACK_V2"
    );
    owner.observed.anchor = initial_anchor;
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(owner.starts, 1);
    let too_much = NativeBudgetResourcesV1::Contribution {
        training_cpu_ns: 11,
        parameter_bytes: 90,
    };
    assert!(store
        .record_costs(
            binding.claim,
            NativeResourceOutcomeV1::NoGain,
            too_much,
            costs()
        )
        .is_err());
    assert!(store
        .record_costs(
            binding.claim,
            NativeResourceOutcomeV1::Unknown,
            consumed(),
            costs()
        )
        .is_err());
    let before = store.checkpoint().unwrap();
    let mut other = Owner::new();
    other.observed.task = [80; 32];
    let mut second = binding.clone();
    second.claim = [81; 32];
    second.task = [80; 32];
    second.operation = [82; 32];
    assert!(store.reserve(&mut other, second).is_err());
    assert!(other.pinned.is_none()); // Capacity is checked before consuming a Node pin.
    assert_eq!(store.checkpoint().unwrap(), before);
    store
        .record_costs(
            binding.claim,
            NativeResourceOutcomeV1::Unknown,
            binding.resource_cap.clone(),
            costs(),
        )
        .unwrap();
    store
        .complete(binding.claim, binding.operation, [41; 32], [42; 32])
        .unwrap();
    owner.deliver([41; 32]);
    store.bind_delivery(&mut owner, binding.claim).unwrap();
    owner.pay([51; 32]);
    assert!(store
        .record_native_payment(&mut owner, binding.claim, [51; 32])
        .is_err());
    assert_eq!(
        store.report().unwrap()["claims"][0]["resource_charge"],
        json!([10, 100, 0, 0])
    );
}

fn paid_no_gain_operation(
    path: &Path,
) -> (
    NativeTaskOperationStoreV2,
    Owner,
    NativeTaskOperationBindingV2,
) {
    let mut store = NativeTaskOperationStoreV2::open(path, config()).unwrap();
    let mut owner = Owner::new();
    let binding = binding();
    store.reserve(&mut owner, binding.clone()).unwrap();
    store.begin(&mut owner, binding.claim).unwrap();
    complete(&mut store, &binding, [41; 32]);
    owner.deliver([41; 32]);
    store.bind_delivery(&mut owner, binding.claim).unwrap();
    owner.pay([51; 32]);
    store
        .record_native_payment(&mut owner, binding.claim, [51; 32])
        .unwrap();
    (store, owner, binding)
}

fn later_task(anchor: NativeBudgetAnchorV1) -> (Owner, NativeTaskOperationBindingV2) {
    let mut other = Owner::new();
    let mut binding = binding();
    binding.claim = [71; 32];
    binding.task = [72; 32];
    binding.operation = [73; 32];
    other.observed.task = binding.task;
    other.observed.anchor = anchor;
    (other, binding)
}

#[test]
fn payment_readback_rejects_same_generation_anchor_changes_without_rewriting_no_gain_fee() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operations.sqlite");
    let (mut store, mut owner, binding) = paid_no_gain_operation(&path);
    let original = owner.payment.as_ref().unwrap().clone();
    let checkpoint = store.checkpoint().unwrap();
    let report = store.report().unwrap();
    assert_eq!(report["claims"][0]["declared_costs"]["outcome"], "NoGain");
    assert_eq!(
        report["claims"][0]["historically_observed_native_payment"],
        2_000
    );
    assert_eq!(report["claims"][0]["learning_improvement_bonus"], false);

    let mut changed_block = original.anchor;
    changed_block.block = [81; 32];
    let mut changed_root = original.anchor;
    changed_root.state_root = [82; 32];
    let mut changed_height = original.anchor;
    changed_height.height += 1;
    for changed in [changed_block, changed_root, changed_height] {
        owner.payment.as_mut().unwrap().anchor = changed;
        assert_eq!(
            store
                .reobserve_native_payment(&mut owner, binding.claim)
                .unwrap_err()
                .to_string(),
            "TASK_OPERATION_ANCHOR_ROLLBACK_V2"
        );
        assert_eq!(store.checkpoint().unwrap(), checkpoint);
        assert_eq!(store.report().unwrap(), report);
    }

    // A genuinely newer owner generation may observe the same payment on a
    // different branch. Its height need not increase; no history is rewritten.
    let mut newer = original.anchor;
    newer.generation += 1;
    newer.height -= 1;
    newer.block = [83; 32];
    newer.state_root = [84; 32];
    owner.payment.as_mut().unwrap().anchor = newer;
    let readback = store
        .reobserve_native_payment(&mut owner, binding.claim)
        .unwrap();
    assert_eq!(readback.historical, original);
    assert_eq!(readback.observed.anchor, newer);
    assert_eq!(readback.observed.beneficiary_credit, 2_000);
    assert_eq!(store.checkpoint().unwrap(), checkpoint);
    assert_eq!(store.report().unwrap(), report);
    assert_eq!(
        store.begin(&mut owner, binding.claim).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(owner.starts, 1);
}

#[test]
fn payment_readback_enforces_the_latest_persisted_anchor_across_tasks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operations.sqlite");
    let (mut store, mut owner, binding) = paid_no_gain_operation(&path);
    let original = owner.payment.as_ref().unwrap().clone();
    let mut latest = original.anchor;
    latest.generation = 5;
    latest.height = 5;
    latest.block = [85; 32];
    latest.state_root = [86; 32];
    let (mut other, other_binding) = later_task(latest);
    store.reserve(&mut other, other_binding).unwrap();
    let checkpoint = store.checkpoint().unwrap();

    // This is newer than the original payment (generation 3), but older than
    // a native fact already retained by the same journal (generation 5).
    owner.payment.as_mut().unwrap().anchor.generation = 4;
    assert_eq!(
        store
            .reobserve_native_payment(&mut owner, binding.claim)
            .unwrap_err()
            .to_string(),
        "TASK_OPERATION_ANCHOR_ROLLBACK_V2"
    );
    assert_eq!(store.checkpoint().unwrap(), checkpoint);
    owner.payment.as_mut().unwrap().anchor = latest;
    let readback = store
        .reobserve_native_payment(&mut owner, binding.claim)
        .unwrap();
    assert_eq!(readback.historical, original);
    assert_eq!(readback.observed.anchor, latest);
    assert_eq!(store.checkpoint().unwrap(), checkpoint);
}

#[test]
fn payment_readback_refuses_a_concurrent_journal_append_during_owner_observation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operations.sqlite");
    let (store, mut owner, binding) = paid_no_gain_operation(&path);
    let original = owner.payment.as_ref().unwrap().clone();
    let before = store.checkpoint().unwrap();
    let mut later = original.anchor;
    later.generation += 1;
    later.height += 1;
    later.block = [87; 32];
    later.state_root = [88; 32];
    let (mut other, other_binding) = later_task(later);
    // Exercise a real WAL commit through a second connection between the
    // journal snapshot and payment callback return, without timing or sleeps.
    let mut writer = NativeTaskOperationStoreV2::open(&path, config()).unwrap();
    owner.payment_read_hook = Some(Box::new(move || {
        writer.reserve(&mut other, other_binding)?;
        Ok(())
    }));
    assert_eq!(
        store
            .reobserve_native_payment(&mut owner, binding.claim)
            .unwrap_err()
            .to_string(),
        "TASK_OPERATION_PAYMENT_JOURNAL_CHANGED_V2"
    );
    let after = store.checkpoint().unwrap();
    assert_eq!(after.sequence, before.sequence + 1);
    assert_eq!(store.verify_checkpoint(&before).unwrap(), after);
    assert_eq!(
        store.snapshot(binding.claim).unwrap().payment,
        Some(original)
    );
    owner.payment.as_mut().unwrap().anchor = later;
    assert!(store
        .reobserve_native_payment(&mut owner, binding.claim)
        .is_ok());
    assert_eq!(store.checkpoint().unwrap(), after);
    assert_eq!(owner.starts, 1);
}
