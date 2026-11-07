//! Unknown output admission through the actual Node owner, then actual tag4
//! delivery and arbitration payment. Keys, resource values and evaluation
//! outcome are controlled fixtures, not independent customer or meter evidence.
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::task_operation_v2::*;
use trnm_service_settlement::native_budget::*;

const AMOUNT: u64 = 2_000;
const CLAIM: Hash = [31; 32];
const OPERATION: Hash = [32; 32];
const CLOCK: u64 = 100_000;

#[derive(Clone, Copy)]
enum Backend {
    Legacy,
    Authenticated,
}
fn public(index: u64) -> Hash {
    development_public(index).unwrap()
}
fn settings() -> Settings {
    Settings::development_with_funded_service_contract_v1(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}
fn open(path: &Path, backend: Backend) -> trnm_pon_node::Result<Node> {
    match backend {
        Backend::Legacy => Node::open(path, settings(), 1),
        Backend::Authenticated => Node::open_with_authenticated_state(path, settings(), 1),
    }
}
fn signed(settings: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut transaction = Envelope {
        network: settings.network(),
        sender: public(sender),
        nonce,
        expiry: 2_000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}
fn mine(node: &mut Node, parent: Hash, transactions: Vec<Vec<u8>>) -> Hash {
    let timestamp = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
    let packet = node
        .make_consensus_maintenance(parent, transactions, public(3), timestamp, 4096)
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}
fn contract(nonce: u64) -> (FundedServiceContractV1, Hash, Hash) {
    let cfg = settings();
    let contract = FundedServiceContractV1 {
        request: hash(b"unknown-output-request-v2", &[&nonce.to_le_bytes()]),
        provider: public(1),
        model: [81; 32],
        input: [82; 32],
        output_spec: [83; 32],
        qualified_work: [84; 32],
        evaluation_protocol: [85; 32],
        fee_schedule: [86; 32],
        dispute_policy: [87; 32],
        arbitrator: public(2),
        budget: AMOUNT,
        delivery_deadline: 12,
        dispute_deadline: 24,
    };
    let task = contract.task_id(cfg.network(), cfg.parameters(), public(0), nonce);
    let digest = contract.digest(cfg.network(), cfg.parameters(), public(0));
    (contract, task, digest)
}
fn resources(amount: u64) -> NativeBudgetResourcesV1 {
    NativeBudgetResourcesV1::Contribution {
        training_cpu_ns: amount,
        parameter_bytes: amount,
    }
}
fn binding(
    task: Hash,
    contract_digest: Hash,
    claim: Hash,
    operation: Hash,
) -> NativeTaskOperationBindingV2 {
    NativeTaskOperationBindingV2 {
        claim,
        task,
        contract_digest,
        operation,
        beneficiary: public(1),
        target_scope: [41; 32],
        resource_cap: resources(10),
    }
}
fn configuration(cfg: &Settings) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: cfg.network(),
        parameters: cfg.parameters(),
        genesis: cfg.genesis(),
        max_records: 32,
    }
}
fn v1_policy(task: Hash, budget: Hash) -> NativeBudgetPolicyV1 {
    NativeBudgetPolicyV1 {
        budget,
        source: NativeFundingSourceV1::Task(task),
        monetary_cap: AMOUNT,
        deadline: 23,
        resource_cap: resources(10),
        max_inflight: 1,
    }
}

/// Real Node commits its once-only fence; the bridge loses the reply before M12
/// can append Begin. This is an explicit failure, not a simulated success.
struct LoseBeginReply<'a>(&'a mut Node);
impl NativeFundingOwnerV1 for LoseBeginReply<'_> {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        NativeFundingOwnerV1::observe_funding(self.0, source)
    }
    fn observe_payment(
        &mut self,
        query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        NativeFundingOwnerV1::observe_payment(self.0, query)
    }
}
impl NativeTaskOperationOwnerV2 for LoseBeginReply<'_> {
    fn reserve_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskContractObservationV2> {
        self.0.reserve_task_operation_v2(binding)
    }
    fn begin_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskBeginObservationV2> {
        let result = self.0.begin_task_operation_v2(binding)?;
        assert!(result.new_execution);
        Err(NativeBudgetErrorV1::Owner(
            "controlled lost reply after durable Node begin".into(),
        ))
    }
    fn observe_task_delivery_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskDeliveryObservationV2> {
        self.0.observe_task_delivery_v2(binding)
    }
}

fn scenario(backend: Backend) {
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let journal_path = directory.path().join("operation.sqlite");
    let lost_path = directory.path().join("lost-reply.sqlite");
    let before_begin_path = directory.path().join("before-begin.sqlite");
    let before_costs_path = directory.path().join("before-costs.sqlite");
    let mut node = open(&node_path, backend).unwrap();
    let cfg = node.settings().clone();
    let mut transactions = Vec::new();
    let mut tasks = Vec::new();
    for nonce in 1..=3 {
        let (terms, task, digest) = contract(nonce);
        transactions.push(signed(
            &cfg,
            0,
            nonce,
            2,
            FundedServiceReservationV1 {
                task,
                contract: terms,
            }
            .encode()
            .unwrap(),
        ));
        tasks.push((task, digest));
    }
    let reserved = mine(&mut node, cfg.genesis(), transactions);
    let (task, digest) = tasks[0];
    let bind = binding(task, digest, CLAIM, OPERATION);
    let mut store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();
    assert_eq!(
        store.reserve(&mut node, bind.clone()).unwrap(),
        NativeBudgetReplayV1::New
    );
    let before = store.snapshot(CLAIM).unwrap();
    assert_eq!(before.reserved.status, NativeTaskStatusV2::Reserved);
    assert_eq!(before.reserved.output, None);
    assert!(before.completion.is_none());
    assert!(before.delivery.is_none());
    assert!(node
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap()["output"]
        .is_null());
    let mut v1 =
        NativeBudgetStoreV1::open(&directory.path().join("v1.sqlite"), configuration(&cfg))
            .unwrap();
    assert!(v1
        .open_budget(&mut node, v1_policy(task, [42; 32]))
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_VERSION_CONFLICT"));
    drop(store);
    std::fs::copy(&journal_path, &before_begin_path).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();
    assert_eq!(
        store.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::Pending
    );

    drop(store);
    std::fs::copy(&journal_path, &before_costs_path).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();

    // Another journal cannot reissue the same Node's first execution decision.
    let mut second = NativeTaskOperationStoreV2::open(
        &directory.path().join("second.sqlite"),
        configuration(&cfg),
    )
    .unwrap();
    assert_eq!(
        second.reserve(&mut node, bind.clone()).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        second.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert!(!second.snapshot(CLAIM).unwrap().begun.unwrap().new_execution);
    let mut changed = bind.clone();
    changed.target_scope = [43; 32];
    let mut other = NativeTaskOperationStoreV2::open(
        &directory.path().join("changed.sqlite"),
        configuration(&cfg),
    )
    .unwrap();
    assert!(other
        .reserve(&mut node, changed)
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_REBIND"));
    let (task2, digest2) = tasks[1];
    assert!(other
        .reserve(&mut node, binding(task2, digest2, [44; 32], OPERATION))
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_DUPLICATE_OPERATION"));

    // The reverse version direction is fenced by a real V1 owner authorization.
    let (task3, digest3) = tasks[2];
    v1.open_budget(&mut node, v1_policy(task3, [45; 32]))
        .unwrap();
    assert!(other
        .reserve(&mut node, binding(task3, digest3, [46; 32], [47; 32]))
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_VERSION_CONFLICT"));
    assert_eq!(
        node.native_funding_observation(NativeFundingSourceV1::Task(task3))
            .unwrap()
            .row
            .unwrap()["remaining"],
        AMOUNT
    );

    let lost_binding = binding(task2, digest2, [48; 32], [49; 32]);
    let mut lost = NativeTaskOperationStoreV2::open(&lost_path, configuration(&cfg)).unwrap();
    lost.reserve(&mut node, lost_binding.clone()).unwrap();
    assert!(lost
        .begin(&mut LoseBeginReply(&mut node), lost_binding.claim)
        .is_err());
    assert!(lost.snapshot(lost_binding.claim).unwrap().begun.is_none());
    drop(lost);
    drop(node);
    let mut node = open(&node_path, backend).unwrap();
    let mut lost = NativeTaskOperationStoreV2::open(&lost_path, configuration(&cfg)).unwrap();
    assert_eq!(
        lost.begin(&mut node, lost_binding.claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert!(
        !lost
            .snapshot(lost_binding.claim)
            .unwrap()
            .begun
            .unwrap()
            .new_execution
    );
    assert_eq!(
        store.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::Pending
    );

    // Only now is an actual result produced. The reserved request never carried
    // this digest; these small fixture bytes do not stand in for a trained model.
    let values: Vec<u8> = (0_u64..16)
        .flat_map(|value| (value * value + 3 * value + 7).to_le_bytes())
        .collect();
    let output = hash(b"actual-post-begin-fixture-output-v2", &[&values]);
    let costs = NativeTaskCostBreakdownV2 {
        training_units: 4,
        evaluation_units: 3,
        storage_units: 2,
        serving_units: 1,
        unit: [50; 32],
        measurement_receipt: [51; 32],
    };
    assert!(store.complete(CLAIM, OPERATION, output, [52; 32]).is_err());
    store
        .record_costs(CLAIM, NativeResourceOutcomeV1::NoGain, resources(3), costs)
        .unwrap();
    assert!(store.complete(CLAIM, [53; 32], output, [52; 32]).is_err());
    store.complete(CLAIM, OPERATION, output, [52; 32]).unwrap();
    assert!(store.bind_delivery(&mut node, CLAIM).is_err());
    let mut payload = task.to_vec();
    payload.extend(output);
    let receipt = signed(&cfg, 1, 1, 4, payload);
    let receipt_operation = Envelope::decode(&receipt).unwrap().id().unwrap();
    let receipted = mine(&mut node, reserved, vec![receipt]);
    let native_delivery = node.observe_task_delivery_v2(&bind).unwrap();
    assert_eq!(native_delivery.receipt_operation, receipt_operation);
    assert_eq!(native_delivery.receipt_anchor.block, receipted);
    assert_eq!(native_delivery.contract.output, Some(output));
    assert_eq!(
        store.bind_delivery(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store.bind_delivery(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert!(store
        .record_native_payment(&mut node, CLAIM, [54; 32])
        .is_err());
    let accept = signed(
        &cfg,
        2,
        1,
        5,
        FundedServiceDecisionV1 {
            task,
            contract_digest: digest,
            output,
            evidence: [55; 32],
            verdict: FundedServiceVerdictV1::PayProvider,
        }
        .encode()
        .unwrap(),
    );
    let payment_operation = Envelope::decode(&accept).unwrap().id().unwrap();
    let settled = mine(&mut node, receipted, vec![accept]);
    assert_eq!(
        store
            .record_native_payment(&mut node, CLAIM, payment_operation)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let paid = store.snapshot(CLAIM).unwrap();
    assert_eq!(paid.payment.as_ref().unwrap().beneficiary_credit, AMOUNT);
    assert_eq!(
        paid.delivery.as_ref().unwrap().contract.output,
        Some(output)
    );
    assert_eq!(
        store.report().unwrap()["claims"][0]["learning_improvement_bonus"],
        false
    );
    assert_eq!(
        store.report().unwrap()["physical_costs_verified_by_this_journal"],
        false
    );
    let reconciled = node
        .reconcile_native_task_operation_v2(&store, CLAIM, 7)
        .unwrap();
    assert_eq!(reconciled["native_delivery_verified"], true);
    assert_eq!(reconciled["historical_native_payment_verified"], true);
    assert_eq!(reconciled["declared_costs"]["training_units"], 4);
    assert_eq!(reconciled["physical_costs_verified"], false);
    assert_eq!(
        node.reconcile_native_task_operation_v2(&store, CLAIM, 7)
            .unwrap(),
        reconciled
    );
    drop(store);
    drop(node);

    let mut node = open(&node_path, backend).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();
    assert_eq!(node.active().unwrap().0, settled);
    assert_eq!(store.snapshot(CLAIM).unwrap(), paid);
    let history = node
        .native_task_operation_reconciliation_history_v2()
        .unwrap();
    assert_eq!(history["live_m12_journal_rechecked"], false);
    for old_path in [&before_begin_path, &before_costs_path] {
        let mut old = NativeTaskOperationStoreV2::open(old_path, configuration(&cfg)).unwrap();
        assert!(node
            .reconcile_native_task_operation_v2(&old, CLAIM, 99)
            .is_err());
        assert_eq!(
            old.begin(&mut node, CLAIM).unwrap(),
            NativeBudgetReplayV1::Pending
        );
        assert_eq!(
            node.native_task_operation_reconciliation_history_v2()
                .unwrap(),
            history
        );
    }
    let fork_path = directory.path().join("forked-costs.sqlite");
    std::fs::copy(&before_costs_path, &fork_path).unwrap();
    let mut fork = NativeTaskOperationStoreV2::open(&fork_path, configuration(&cfg)).unwrap();
    fork.record_costs(
        CLAIM,
        NativeResourceOutcomeV1::NoGain,
        resources(2),
        NativeTaskCostBreakdownV2 {
            training_units: 5,
            evaluation_units: 3,
            storage_units: 2,
            serving_units: 1,
            unit: [50; 32],
            measurement_receipt: [51; 32],
        },
    )
    .unwrap();
    fork.complete(CLAIM, OPERATION, output, [52; 32]).unwrap();
    fork.bind_delivery(&mut node, CLAIM).unwrap();
    fork.record_native_payment(&mut node, CLAIM, payment_operation)
        .unwrap();
    assert!(node
        .reconcile_native_task_operation_v2(&fork, CLAIM, 99)
        .is_err());
    assert_eq!(
        node.native_task_operation_reconciliation_history_v2()
            .unwrap(),
        history
    );
    assert_eq!(
        node.reconcile_native_task_operation_v2(&store, CLAIM, 8)
            .unwrap()["sequence"],
        2
    );
    assert!(node
        .reconcile_native_task_operation_v2(&store, CLAIM, 7)
        .is_err());
    assert_eq!(
        store
            .reobserve_native_payment(&mut node, CLAIM)
            .unwrap()
            .historical
            .beneficiary_credit,
        AMOUNT
    );
    let branch3 = mine(&mut node, receipted, vec![]);
    let branch4 = mine(&mut node, branch3, vec![]);
    assert_eq!(node.active().unwrap().0, branch4);
    assert!(store.reobserve_native_payment(&mut node, CLAIM).is_err());
    assert_eq!(store.snapshot(CLAIM).unwrap(), paid);
    assert_eq!(
        store.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert!(!node.begin_task_operation_v2(&bind).unwrap().new_execution);
    assert!(v1
        .open_budget(&mut node, v1_policy(task, [56; 32]))
        .is_err());
    assert_eq!(
        node.reconcile_native_task_operation_v2(&store, CLAIM, 8)
            .unwrap()["historical_native_payment_verified"],
        true
    );

    // A real reorg can expose a different signed output for the same native
    // Task. It cannot change the first result of this already-started operation.
    let mut replacement = task.to_vec();
    replacement.extend([62; 32]);
    let mut branch = mine(
        &mut node,
        reserved,
        vec![signed(&cfg, 1, 1, 4, replacement)],
    );
    for _ in 0..3 {
        branch = mine(&mut node, branch, vec![]);
    }
    assert_eq!(node.active().unwrap().0, branch);
    assert!(node
        .observe_task_delivery_v2(&bind)
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_OUTPUT_REBIND"));
    assert!(!node.begin_task_operation_v2(&bind).unwrap().new_execution);

    // Even the same output with a different signed receipt cannot replace the
    // original receipt identity. Retain and verify the original historical one.
    let mut payload = task.to_vec();
    payload.extend(output);
    let mut replacement = Envelope::decode(&signed(&cfg, 1, 1, 4, payload)).unwrap();
    replacement.expiry -= 1;
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&1_u64.to_le_bytes()]))).unwrap();
    replacement.signature = hex::decode(sign_hex(&key, &replacement.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let mut branch = mine(&mut node, reserved, vec![replacement.encode().unwrap()]);
    for _ in 0..4 {
        branch = mine(&mut node, branch, vec![]);
    }
    assert_eq!(node.active().unwrap().0, branch);
    assert!(node
        .observe_task_delivery_v2(&bind)
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_RECEIPT_REBIND"));
    assert_eq!(store.snapshot(CLAIM).unwrap(), paid);
    assert_eq!(
        node.native_task_operation_pins_v1().unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    drop(node);
    let node = open(&node_path, backend).unwrap();
    assert_eq!(
        node.native_task_operation_pins_v1().unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    drop(node);
    let floor_key = "pon-native-task-operation-reconciliation-v2:event:0000000000000001";
    let corrupt = rusqlite::Connection::open(node_path.join("native.sqlite")).unwrap();
    let original: Vec<u8> = corrupt
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [floor_key],
            |row| row.get(0),
        )
        .unwrap();
    corrupt
        .execute("DELETE FROM metadata WHERE key=?1", [floor_key])
        .unwrap();
    drop(corrupt);
    let error = match open(&node_path, backend) {
        Ok(_) => panic!("missing reconciliation prefix accepted"),
        Err(error) => error,
    };
    assert!(error.requires_owner_stop());
    // Restore the exact test fixture to test an independent pin deletion. There
    // is deliberately no runtime API that repairs, prunes or resets either log.
    let corrupt = rusqlite::Connection::open(node_path.join("native.sqlite")).unwrap();
    corrupt
        .execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            rusqlite::params![floor_key, original],
        )
        .unwrap();
    corrupt
        .execute(
            "DELETE FROM metadata WHERE key=?1",
            [format!(
                "pon-native-task-operation-pin-v1:task:{}",
                hex::encode(task)
            )],
        )
        .unwrap();
    drop(corrupt);
    let error = match open(&node_path, backend) {
        Ok(_) => panic!("missing operation fence accepted"),
        Err(error) => error,
    };
    assert!(error.requires_owner_stop());
}

#[test]
fn unknown_output_uses_native_once_fence_and_real_delivery_on_both_backends() {
    scenario(Backend::Legacy);
    scenario(Backend::Authenticated);
}

#[test]
fn ordinary_task_cannot_claim_full_contract_v2_admission() {
    let directory = tempfile::tempdir().unwrap();
    let cfg = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(&directory.path().join("node"), cfg.clone(), 1).unwrap();
    let task = hash(
        b"task-instance-v3",
        &[
            &cfg.network(),
            &cfg.parameters(),
            &public(0),
            &1_u64.to_le_bytes(),
            &public(1),
            &AMOUNT.to_le_bytes(),
            &24_u64.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(AMOUNT.to_le_bytes());
    payload.extend(24_u64.to_le_bytes());
    mine(
        &mut node,
        cfg.genesis(),
        vec![signed(&cfg, 0, 1, 2, payload)],
    );
    let mut store = NativeTaskOperationStoreV2::open(
        &directory.path().join("budget.sqlite"),
        configuration(&cfg),
    )
    .unwrap();
    assert!(store
        .reserve(&mut node, binding(task, [61; 32], CLAIM, OPERATION))
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_PROFILE"));
    assert_eq!(
        node.native_task_operation_pins_v1().unwrap()["records"],
        serde_json::json!([])
    );
}

struct ReorderedOwner {
    reserved: NativeTaskContractObservationV2,
    begun: NativeTaskBeginObservationV2,
}
impl NativeFundingOwnerV1 for ReorderedOwner {
    fn observe_funding(
        &mut self,
        _source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        Err(NativeBudgetErrorV1::Invalid("UNUSED_FIXTURE_OWNER"))
    }
}
impl NativeTaskOperationOwnerV2 for ReorderedOwner {
    fn reserve_task_operation_v2(
        &mut self,
        _binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskContractObservationV2> {
        Ok(self.reserved.clone())
    }
    fn begin_task_operation_v2(
        &mut self,
        _binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskBeginObservationV2> {
        Ok(self.begun.clone())
    }
    fn observe_task_delivery_v2(
        &mut self,
        _binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskDeliveryObservationV2> {
        Err(NativeBudgetErrorV1::Invalid("UNUSED_FIXTURE_OWNER"))
    }
}

#[test]
fn real_old_funding_rows_cannot_backfill_a_later_native_begin_or_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(&directory.path().join("node"), Backend::Legacy).unwrap();
    let cfg = node.settings().clone();
    let (terms1, task1, digest1) = contract(1);
    let (terms2, task2, digest2) = contract(2);
    let reserved = mine(
        &mut node,
        cfg.genesis(),
        vec![
            signed(
                &cfg,
                0,
                1,
                2,
                FundedServiceReservationV1 {
                    task: task1,
                    contract: terms1,
                }
                .encode()
                .unwrap(),
            ),
            signed(
                &cfg,
                0,
                2,
                2,
                FundedServiceReservationV1 {
                    task: task2,
                    contract: terms2.clone(),
                }
                .encode()
                .unwrap(),
            ),
        ],
    );
    let bind1 = binding(task1, digest1, [71; 32], [72; 32]);
    let actual_reserve = node.reserve_task_operation_v2(&bind1).unwrap();
    // This second observation quotes real retained funding fields, but there
    // was deliberately no native V2 reservation for Task2 at this generation.
    let old_anchor = node
        .native_funding_observation(NativeFundingSourceV1::Task(task2))
        .unwrap()
        .anchor;
    let old_reserve2 = NativeTaskContractObservationV2 {
        anchor: old_anchor,
        task: task2,
        contract_digest: digest2,
        payer: public(0),
        provider: public(1),
        request: terms2.request,
        model: terms2.model,
        input: terms2.input,
        output_spec: terms2.output_spec,
        amount: AMOUNT,
        delivery_deadline: terms2.delivery_deadline,
        dispute_deadline: terms2.dispute_deadline,
        remaining: AMOUNT,
        status: NativeTaskStatusV2::Reserved,
        output: None,
        receipt_height: None,
    };
    mine(&mut node, reserved, vec![]);
    let actual_begin = node.begin_task_operation_v2(&bind1).unwrap();
    assert!(actual_begin.contract.anchor.generation > actual_reserve.anchor.generation);
    assert!(actual_begin.new_execution);
    for new_execution in [true, false] {
        let mut quoted = ReorderedOwner {
            reserved: actual_reserve.clone(),
            begun: NativeTaskBeginObservationV2 {
                contract: actual_reserve.clone(),
                new_execution,
            },
        };
        let path = directory
            .path()
            .join(format!("backdated-begin-{new_execution}.sqlite"));
        let mut store = NativeTaskOperationStoreV2::open(&path, configuration(&cfg)).unwrap();
        store.reserve(&mut quoted, bind1.clone()).unwrap();
        store.begin(&mut quoted, bind1.claim).unwrap();
        assert!(node
            .reconcile_native_task_operation_v2(&store, bind1.claim, 1)
            .unwrap_err()
            .to_string()
            .contains("TASK_OPERATION_RECONCILIATION_BEGIN"));
    }
    let bind2 = binding(task2, digest2, [73; 32], [74; 32]);
    let new_reserve2 = node.reserve_task_operation_v2(&bind2).unwrap();
    let new_begin2 = node.begin_task_operation_v2(&bind2).unwrap();
    assert!(new_reserve2.anchor.generation > old_reserve2.anchor.generation);
    let mut quoted = ReorderedOwner {
        reserved: old_reserve2,
        begun: new_begin2,
    };
    let mut store = NativeTaskOperationStoreV2::open(
        &directory.path().join("backdated-reserve.sqlite"),
        configuration(&cfg),
    )
    .unwrap();
    store.reserve(&mut quoted, bind2.clone()).unwrap();
    store.begin(&mut quoted, bind2.claim).unwrap();
    assert!(node
        .reconcile_native_task_operation_v2(&store, bind2.claim, 1)
        .unwrap_err()
        .to_string()
        .contains("TASK_OPERATION_RECONCILIATION_SOURCE"));
    assert_eq!(
        node.native_task_operation_reconciliation_history_v2()
            .unwrap()["records"],
        serde_json::json!([])
    );
}
