//! A valid retained branch is not proof that it was the active tip in a claimed
//! generation. These tests deliberately feed false owner observations into a
//! valid M12 journal; the actual Node evidence owner must refuse them.
use serde_json::json;
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, ErrorCode, NativeTaskEvidenceRequestV1, Node, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::*;

const AMOUNT: u64 = 2_000;
const CLAIM: Hash = [73; 32];
const EFFECT: Hash = [74; 32];
const OUTPUT: Hash = [75; 32];

#[derive(Clone, Copy)]
enum Backend {
    Legacy,
    Authenticated,
}
fn open(path: &Path, backend: Backend, settings: Settings) -> Node {
    match backend {
        Backend::Legacy => Node::open(path, settings, 1),
        Backend::Authenticated => Node::open_with_authenticated_state(path, settings, 1),
    }
    .unwrap()
}
fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn signed(settings: &Settings, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(who),
        nonce,
        expiry: 100,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn packet(
    node: &mut Node,
    parent: Hash,
    transactions: Vec<Vec<u8>>,
    time_offset: u64,
    activate: bool,
) -> (Hash, Hash, u64) {
    let height = node.parent_height(parent).unwrap() + 1;
    let packet = node
        .make_consensus_maintenance(
            parent,
            transactions,
            public(3),
            1 + 10 * height + time_offset,
            4096,
        )
        .unwrap();
    let root = packet.header.state;
    let block = node.admit(&packet, 100_000).unwrap();
    if activate {
        node.activate(block).unwrap();
    }
    (block, root, height)
}
fn resources(amount: u64) -> NativeBudgetResourcesV1 {
    NativeBudgetResourcesV1::Evaluation {
        evaluation_cpu_ns: amount,
        evaluated_examples: amount,
    }
}
fn start(store: &mut NativeBudgetStoreV1, owner: &mut impl NativeFundingOwnerV1, task: Hash) {
    store
        .open_budget(
            owner,
            NativeBudgetPolicyV1 {
                budget: [72; 32],
                source: NativeFundingSourceV1::Task(task),
                monetary_cap: AMOUNT,
                deadline: 23,
                resource_cap: resources(10),
                max_inflight: 1,
            },
        )
        .unwrap();
    store
        .reserve(
            owner,
            NativeBudgetClaimV1 {
                claim: CLAIM,
                budget: [72; 32],
                subject: OUTPUT,
                beneficiary: public(1),
                monetary_reservation: AMOUNT,
                resource_reservation: resources(4),
            },
        )
        .unwrap();
    store.begin_effect(owner, CLAIM, EFFECT, OUTPUT).unwrap();
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

fn scenario(backend: Backend, invented_payment: bool) {
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let settings = Settings::development_with_funded_service_contract_v1(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = open(&node_path, backend, settings.clone());
    let contract = FundedServiceContractV1 {
        request: [1; 32],
        provider: public(1),
        model: [3; 32],
        input: [4; 32],
        output_spec: [5; 32],
        qualified_work: [6; 32],
        evaluation_protocol: [7; 32],
        fee_schedule: [8; 32],
        dispute_policy: [9; 32],
        arbitrator: public(2),
        budget: AMOUNT,
        delivery_deadline: 12,
        dispute_deadline: 24,
    };
    let task = contract.task_id(settings.network(), settings.parameters(), public(0), 1);
    let contract_digest = contract.digest(settings.network(), settings.parameters(), public(0));
    let reserve = signed(
        &settings,
        0,
        1,
        2,
        FundedServiceReservationV1 { task, contract }
            .encode()
            .unwrap(),
    );
    let (reserved, _, _) = packet(
        &mut node,
        settings.genesis(),
        vec![reserve.clone()],
        0,
        true,
    );
    // An actual owner access pins V1. Rejection must concern the false active
    // history, not a missing V1 protocol pin or an invented monetary amount.
    let native =
        NativeFundingOwnerV1::observe_funding(&mut node, NativeFundingSourceV1::Task(task))
            .unwrap();
    let mut store = NativeBudgetStoreV1::open(
        &directory.path().join("journal.sqlite"),
        NativeBudgetConfigV1 {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
            max_records: 8,
        },
    )
    .unwrap();
    if invented_payment {
        start(&mut store, &mut node, task);
        let receipt = signed(
            &settings,
            1,
            1,
            4,
            [task.as_slice(), OUTPUT.as_slice()].concat(),
        );
        let (delivered, _, _) = packet(&mut node, reserved, vec![receipt], 0, true);
        let (main, _, _) = packet(&mut node, delivered, vec![], 0, true);
        let active = node.active().unwrap();
        assert_eq!(active.0, main);
        let pay = signed(
            &settings,
            2,
            1,
            5,
            FundedServiceDecisionV1 {
                task,
                contract_digest,
                output: OUTPUT,
                evidence: [77; 32],
                verdict: FundedServiceVerdictV1::PayProvider,
            }
            .encode()
            .unwrap(),
        );
        let operation = Envelope::decode(&pay).unwrap().id().unwrap();
        let (side, root, height) = packet(&mut node, delivered, vec![pay], 1, false);
        assert_ne!(side, main);
        assert_eq!(node.active().unwrap(), active);
        let mut false_anchor = native.anchor;
        false_anchor.block = side;
        false_anchor.state_root = root;
        false_anchor.height = height;
        false_anchor.generation = active.1;
        let mut owner = ClaimedOwner {
            funding: native,
            payment: Some(NativePaymentObservationV1 {
                anchor: false_anchor,
                source: NativeFundingSourceV1::Task(task),
                subject: OUTPUT,
                beneficiary: public(1),
                operation,
                gross_escrow_debit: AMOUNT,
                beneficiary_credit: AMOUNT,
            }),
        };
        store
            .record_resources(CLAIM, NativeResourceOutcomeV1::NoGain, Some(resources(3)))
            .unwrap();
        store.complete_effect(CLAIM, EFFECT, [78; 32]).unwrap();
        store
            .record_native_payment(&mut owner, CLAIM, operation)
            .unwrap();
        assert_eq!(
            store.report().unwrap()["budgets"][0]["historically_observed_native_gross_debit"],
            AMOUNT
        );
    } else {
        let active = node.active().unwrap();
        let (side, root, height) = packet(&mut node, settings.genesis(), vec![reserve], 1, false);
        assert_ne!(side, reserved);
        assert_eq!(node.active().unwrap(), active);
        let mut false_funding = native;
        false_funding.anchor.block = side;
        false_funding.anchor.state_root = root;
        false_funding.anchor.height = height;
        false_funding.anchor.generation = active.1;
        let mut owner = ClaimedOwner {
            funding: false_funding,
            payment: None,
        };
        start(&mut store, &mut owner, task);
    }
    let request = NativeTaskEvidenceRequestV1 {
        claim: CLAIM,
        consumer_epoch: 1,
        expected_contract_digest: Some(contract_digest),
    };
    let error = node
        .reconcile_native_task_evidence_v1(&store, request.clone())
        .unwrap_err();
    assert!(error.is(ErrorCode::NativeActiveAnchorHistory), "{error}");
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"],
        json!([])
    );
    drop(node);
    let mut node = open(&node_path, backend, settings);
    let error = node
        .reconcile_native_task_evidence_v1(&store, request)
        .unwrap_err();
    assert!(error.is(ErrorCode::NativeActiveAnchorHistory), "{error}");
    assert_eq!(
        node.native_task_evidence_history_v1().unwrap()["records"],
        json!([])
    );
}

#[test]
fn retained_never_active_payment_cannot_be_reported_as_historical_active_payment() {
    for backend in [Backend::Legacy, Backend::Authenticated] {
        scenario(backend, true);
    }
}

#[test]
fn retained_never_active_funding_cannot_borrow_an_actual_generation_number() {
    for backend in [Backend::Legacy, Backend::Authenticated] {
        scenario(backend, false);
    }
}
