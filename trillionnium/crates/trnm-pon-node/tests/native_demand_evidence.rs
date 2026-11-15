//! Actual Node escrow, signed delivery/payment and M12 reconciliation fixtures.
//! Controlled development keys, fixed outputs and resource numbers do not
//! establish external customers, physical training or independent evaluation.
use serde_json::json;
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, NativeTaskEvidenceRequestV1, Node, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::*;

const AMOUNT: u64 = 2_000;
const CLAIM: Hash = [73; 32];
const EFFECT: Hash = [74; 32];
const RECEIPT: Hash = [76; 32];
const CLOCK: u64 = 100_000;

#[derive(Clone, Copy)]
enum Backend {
    LegacyContract,
    AuthenticatedContract,
    GrowthOrdinaryTask,
}
fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn settings(backend: Backend) -> Settings {
    if matches!(backend, Backend::GrowthOrdinaryTask) {
        Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap()
        .with_permanent_account_growth_v2("native-demand-evidence-v1")
        .unwrap()
    } else {
        Settings::development_with_funded_service_contract_v1(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap()
    }
}
fn try_open(path: &Path, backend: Backend) -> trnm_pon_node::Result<Node> {
    let settings = settings(backend);
    match backend {
        Backend::LegacyContract => Node::open(path, settings, 1),
        Backend::AuthenticatedContract => Node::open_with_authenticated_state(path, settings, 1),
        Backend::GrowthOrdinaryTask => Node::open_with_permanent_account_growth_v2(path, settings),
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
fn mine(node: &mut Node, backend: Backend, parent: Hash, transactions: Vec<Vec<u8>>) -> Hash {
    let time = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
    let id = if matches!(backend, Backend::GrowthOrdinaryTask) {
        let packet = node
            .make_growth_consensus_maintenance(parent, transactions, public(3), time, 4096)
            .unwrap();
        node.admit_growth(&packet, CLOCK).unwrap()
    } else {
        let packet = node
            .make_consensus_maintenance(parent, transactions, public(3), time, 4096)
            .unwrap();
        node.admit(&packet, CLOCK).unwrap()
    };
    node.activate(id).unwrap();
    id
}
fn resources(amount: u64) -> NativeBudgetResourcesV1 {
    NativeBudgetResourcesV1::Evaluation {
        evaluation_cpu_ns: amount,
        evaluated_examples: amount,
    }
}
fn request(contract: Option<Hash>, epoch: u64) -> NativeTaskEvidenceRequestV1 {
    NativeTaskEvidenceRequestV1 {
        claim: CLAIM,
        consumer_epoch: epoch,
        expected_contract_digest: contract,
    }
}

struct ClaimedOwner {
    funding: NativeFundingObservationV1,
    payment: Option<NativePaymentObservationV1>,
}
impl NativeFundingOwnerV1 for ClaimedOwner {
    fn observe_funding(
        &mut self,
        _source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        Ok(self.funding.clone())
    }
    fn observe_payment(
        &mut self,
        _query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        self.payment
            .clone()
            .ok_or(NativeBudgetErrorV1::Invalid("NO_TEST_PAYMENT"))
    }
}
fn start_budget(
    store: &mut NativeBudgetStoreV1,
    owner: &mut impl NativeFundingOwnerV1,
    source: NativeFundingSourceV1,
    output: Hash,
    amount: u64,
) {
    let policy = NativeBudgetPolicyV1 {
        budget: [72; 32],
        source,
        monetary_cap: amount,
        deadline: 23,
        resource_cap: resources(10),
        max_inflight: 1,
    };
    let claim = NativeBudgetClaimV1 {
        claim: CLAIM,
        budget: policy.budget,
        subject: output,
        beneficiary: public(1),
        monetary_reservation: amount,
        resource_reservation: resources(4),
    };
    store.open_budget(owner, policy).unwrap();
    store.reserve(owner, claim).unwrap();
    store.begin_effect(owner, CLAIM, EFFECT, output).unwrap();
}

fn scenario(backend: Backend) {
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let journal_path = directory.path().join("budget.sqlite");
    let rollback_path = directory.path().join("budget-before-completion.sqlite");
    let mut node = try_open(&node_path, backend).unwrap();
    let cfg = node.settings().clone();
    let contract = FundedServiceContractV1 {
        request: [81; 32],
        provider: public(1),
        model: [82; 32],
        input: [83; 32],
        output_spec: [84; 32],
        qualified_work: [85; 32],
        evaluation_protocol: [86; 32],
        fee_schedule: [87; 32],
        dispute_policy: [88; 32],
        arbitrator: public(2),
        budget: AMOUNT,
        delivery_deadline: 12,
        dispute_deadline: 24,
    };
    let (task, reserve_payload, contract_digest) = if matches!(backend, Backend::GrowthOrdinaryTask)
    {
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
        (task, payload, None)
    } else {
        let task = contract.task_id(cfg.network(), cfg.parameters(), public(0), 1);
        let digest = contract.digest(cfg.network(), cfg.parameters(), public(0));
        (
            task,
            FundedServiceReservationV1 { task, contract }
                .encode()
                .unwrap(),
            Some(digest),
        )
    };
    let reserved = mine(
        &mut node,
        backend,
        cfg.genesis(),
        vec![signed(&cfg, 0, 1, 2, reserve_payload)],
    );
    let source = NativeFundingSourceV1::Task(task);
    let output = hash(b"native-demand-fixed-fixture-output-v1", &[&task]);
    let native = node.native_funding_observation(source).unwrap();
    let configuration = NativeBudgetConfigV1 {
        network: cfg.network(),
        parameters: cfg.parameters(),
        genesis: cfg.genesis(),
        max_records: 32,
    };

    // A perfectly valid M12 hash chain fed a false JSON owner is not native evidence.
    let mut claimed = native.clone();
    claimed.row.as_mut().unwrap()["remaining"] = json!(AMOUNT + 1);
    let mut owner = ClaimedOwner {
        funding: claimed,
        payment: None,
    };
    let mut invented = NativeBudgetStoreV1::open(
        &directory.path().join("invented-funds.sqlite"),
        configuration.clone(),
    )
    .unwrap();
    start_budget(&mut invented, &mut owner, source, output, AMOUNT + 1);
    let refused = node
        .reconcile_native_task_evidence_v1(&invented, request(contract_digest, 1))
        .unwrap_err();
    assert!(refused
        .to_string()
        .contains("BUDGET_EVIDENCE_NATIVE_FUNDING"));
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"],
        json!([])
    );

    let mut owner = ClaimedOwner {
        funding: native.clone(),
        payment: Some(NativePaymentObservationV1 {
            anchor: native.anchor,
            source,
            subject: output,
            beneficiary: public(1),
            operation: [99; 32],
            gross_escrow_debit: AMOUNT,
            beneficiary_credit: AMOUNT,
        }),
    };
    let mut invented = NativeBudgetStoreV1::open(
        &directory.path().join("invented-payment.sqlite"),
        configuration.clone(),
    )
    .unwrap();
    start_budget(&mut invented, &mut owner, source, output, AMOUNT);
    invented
        .record_resources(CLAIM, NativeResourceOutcomeV1::NoGain, Some(resources(3)))
        .unwrap();
    invented.complete_effect(CLAIM, EFFECT, RECEIPT).unwrap();
    invented
        .record_native_payment(&mut owner, CLAIM, [99; 32])
        .unwrap();
    assert!(node
        .reconcile_native_task_evidence_v1(&invented, request(contract_digest, 1))
        .is_err());
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"],
        json!([])
    );

    let mut budgets = NativeBudgetStoreV1::open(&journal_path, configuration.clone()).unwrap();
    start_budget(&mut budgets, &mut node, source, output, AMOUNT);
    let first = node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 1))
        .unwrap();
    assert_eq!(first.sequence(), 1);
    assert!(!first.current_payment_confirmed());
    assert_eq!(
        first.report().unwrap()["complete_contract_bound"],
        contract_digest.is_some()
    );
    assert_eq!(
        first.report().unwrap()["prospective_training_admission"],
        false
    );
    let replay = node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 1))
        .unwrap();
    assert_eq!(
        (replay.sequence(), replay.root()),
        (first.sequence(), first.root())
    );
    assert!(node
        .reconcile_native_task_evidence_v1(&budgets, request(Some([90; 32]), 1))
        .is_err());
    assert!(node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 0))
        .is_err());
    drop(budgets);
    std::fs::copy(&journal_path, &rollback_path).unwrap();
    let mut budgets = NativeBudgetStoreV1::open(&journal_path, configuration.clone()).unwrap();
    budgets
        .record_resources(CLAIM, NativeResourceOutcomeV1::NoGain, Some(resources(3)))
        .unwrap();
    budgets.complete_effect(CLAIM, EFFECT, RECEIPT).unwrap();
    let mut delivery = task.to_vec();
    delivery.extend(output);
    let receipted = mine(
        &mut node,
        backend,
        reserved,
        vec![signed(&cfg, 1, 1, 4, delivery.clone())],
    );
    let accept = if let Some(digest) = contract_digest {
        signed(
            &cfg,
            2,
            1,
            5,
            FundedServiceDecisionV1 {
                task,
                contract_digest: digest,
                output,
                evidence: [91; 32],
                verdict: FundedServiceVerdictV1::PayProvider,
            }
            .encode()
            .unwrap(),
        )
    } else {
        signed(&cfg, 0, 2, 5, delivery)
    };
    let operation = Envelope::decode(&accept).unwrap().id().unwrap();
    let settled = mine(&mut node, backend, receipted, vec![accept]);
    budgets
        .record_native_payment(&mut node, CLAIM, operation)
        .unwrap();
    let paid = node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 1))
        .unwrap();
    assert!(paid.current_payment_confirmed());
    assert_eq!(paid.sequence(), 2);
    let report = paid.report().unwrap();
    assert_eq!(report["historical_payment"]["beneficiary_credit"], AMOUNT);
    assert_eq!(report["current_delivery_matches_claim"], true);
    assert_eq!(report["m12"]["outcome"], "NoGain");
    assert_eq!(report["learning_bonus_authorized"], false);
    assert_eq!(report["external_demand_verified"], false);
    let paid_successor = mine(&mut node, backend, settled, vec![]);
    assert_eq!(
        node.reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 1))
            .unwrap()
            .sequence(),
        3
    );
    drop(budgets);
    drop(node);

    let mut node = try_open(&node_path, backend).unwrap();
    let budgets = NativeBudgetStoreV1::open(&journal_path, configuration.clone()).unwrap();
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        node.reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 2))
            .unwrap()
            .sequence(),
        4
    );
    assert_eq!(node.active().unwrap().0, paid_successor);
    let before = node.native_task_evidence_history_v1().unwrap();

    // A consumer restart/epoch cannot make an older valid journal current.
    let rollback = NativeBudgetStoreV1::open(&rollback_path, configuration.clone()).unwrap();
    assert!(node
        .reconcile_native_task_evidence_v1(&rollback, request(contract_digest, 3))
        .unwrap_err()
        .to_string()
        .contains("BUDGET_EVIDENCE_ROLLBACK"));
    drop(rollback);
    let fork_path = directory.path().join("budget-fork.sqlite");
    std::fs::copy(&rollback_path, &fork_path).unwrap();
    let mut fork = NativeBudgetStoreV1::open(&fork_path, configuration.clone()).unwrap();
    fork.record_resources(CLAIM, NativeResourceOutcomeV1::NoGain, Some(resources(2)))
        .unwrap();
    fork.complete_effect(CLAIM, EFFECT, RECEIPT).unwrap();
    fork.record_native_payment(&mut node, CLAIM, operation)
        .unwrap();
    assert!(node
        .reconcile_native_task_evidence_v1(&fork, request(contract_digest, 3))
        .unwrap_err()
        .to_string()
        .contains("BUDGET_EVIDENCE_FORK"));
    assert_eq!(node.native_task_evidence_history_v1().unwrap(), before);

    // Historical replay works on the orphan, while current branch membership is false.
    let branch3 = mine(&mut node, backend, receipted, vec![]);
    let branch4 = mine(&mut node, backend, branch3, vec![]);
    let branch5 = mine(&mut node, backend, branch4, vec![]);
    assert_eq!(node.active().unwrap().0, branch5);
    let reorganized = node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 2))
        .unwrap();
    assert_eq!(reorganized.sequence(), 5);
    assert!(!reorganized.current_payment_confirmed());
    let report = reorganized.report().unwrap();
    assert_eq!(report["historical_payment_verified"], true);
    assert_eq!(report["current_task"]["status"], "receipt");
    assert_eq!(report["historical_payment"]["beneficiary_credit"], AMOUNT);
    drop(node);
    drop(budgets);
    let mut node = try_open(&node_path, backend).unwrap();
    let budgets = NativeBudgetStoreV1::open(&journal_path, configuration).unwrap();
    let replay = node
        .reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 2))
        .unwrap();
    assert_eq!(
        (replay.sequence(), replay.root()),
        (reorganized.sequence(), reorganized.root())
    );
    assert_eq!(
        node.reconcile_native_task_evidence_v1(&budgets, request(contract_digest, 3))
            .unwrap()
            .sequence(),
        6
    );
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    drop(node);

    // Namespace corruption is owner-stopping on reopen, never an empty history.
    let db = rusqlite::Connection::open(node_path.join("native.sqlite")).unwrap();
    db.execute(
        "DELETE FROM metadata WHERE key='pon-native-demand-evidence-v1:event:0000000000000001'",
        [],
    )
    .unwrap();
    drop(db);
    let error = match try_open(&node_path, backend) {
        Ok(_) => panic!("corrupt history accepted"),
        Err(error) => error,
    };
    assert!(error.requires_owner_stop());
}

#[test]
fn complete_contract_real_arbitration_reconciles_after_restart_reorg_and_epoch() {
    scenario(Backend::LegacyContract);
    scenario(Backend::AuthenticatedContract);
}

#[test]
fn ordinary_growth_task_keeps_native_evidence_without_claiming_full_contract() {
    scenario(Backend::GrowthOrdinaryTask);
}
