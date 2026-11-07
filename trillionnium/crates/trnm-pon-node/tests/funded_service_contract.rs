//! Real signed native contracts on durable Node instances, including branch
//! changes. Public development keys and output hashes are controlled fixtures;
//! these tests do not attest independent actors or actual model improvement.
use serde_json::Value;
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_mvcc_fee::pon_executor::funded_service_v1::{
    ServiceContractRecordV1, ServiceResolutionKindV1, RECORD_FIELD,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::{NativeFundingSourceV1, NativePaymentQueryV1};

const BUDGET: u64 = 2_000;
const CLOCK: u64 = 100_000;

#[derive(Clone, Copy, Debug)]
enum Backend {
    Legacy,
    Authenticated,
}

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}

fn settings() -> Settings {
    Settings::development_with_funded_service_contract_v1(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}

fn open(path: &Path, backend: Backend) -> Node {
    match backend {
        Backend::Legacy => Node::open(path, settings(), 1),
        Backend::Authenticated => Node::open_with_authenticated_state(path, settings(), 1),
    }
    .unwrap()
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

fn mine(node: &mut Node, parent: Hash, txs: Vec<Vec<u8>>) -> Hash {
    let timestamp = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
    let packet = node
        .make_consensus_maintenance(parent, txs, public(3), timestamp, 4096)
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}

fn refused(node: &mut Node, parent: Hash, tx: Vec<u8>) {
    let active = node.active().unwrap();
    let timestamp = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
    assert!(node
        .make_consensus_maintenance(parent, vec![tx], public(3), timestamp, 4096)
        .is_err());
    assert_eq!(node.active().unwrap(), active);
}

fn balance(node: &Node, who: u64) -> u64 {
    node.read_active().unwrap().2[&format!("account:{}", hex::encode(public(who)))]["balance"]
        .as_u64()
        .unwrap()
}

fn row(node: &Node, task: Hash) -> Value {
    node.native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap()
}

fn record(node: &Node, task: Hash) -> ServiceContractRecordV1 {
    serde_json::from_value(row(node, task)[RECORD_FIELD].clone()).unwrap()
}

fn contract() -> FundedServiceContractV1 {
    FundedServiceContractV1 {
        request: hash(
            b"service-contract-fixture-request",
            &[b"commissioned evaluation"],
        ),
        provider: public(1),
        model: [3; 32],
        input: [4; 32],
        output_spec: [5; 32],
        qualified_work: [6; 32],
        evaluation_protocol: [7; 32],
        fee_schedule: [8; 32],
        dispute_policy: [9; 32],
        arbitrator: public(2),
        budget: BUDGET,
        delivery_deadline: 3,
        dispute_deadline: 6,
    }
}

fn reserve(node: &mut Node, terms: &FundedServiceContractV1) -> (Hash, Hash) {
    let settings = node.settings().clone();
    let task = terms.task_id(settings.network(), settings.parameters(), public(0), 1);
    let payload = FundedServiceReservationV1 {
        task,
        contract: terms.clone(),
    }
    .encode()
    .unwrap();
    let tx = signed(&settings, 0, 1, 2, payload);
    let block = mine(node, settings.genesis(), vec![tx]);
    (task, block)
}

fn verdict(
    settings: &Settings,
    terms: &FundedServiceContractV1,
    task: Hash,
    output: Hash,
    verdict: FundedServiceVerdictV1,
    nonce: u64,
) -> Vec<u8> {
    signed(
        settings,
        2,
        nonce,
        5,
        FundedServiceDecisionV1 {
            task,
            contract_digest: terms.digest(settings.network(), settings.parameters(), public(0)),
            output,
            evidence: [44; 32],
            verdict,
        }
        .encode()
        .unwrap(),
    )
}

fn query(task: Hash, output: Hash, tx: &[u8]) -> NativePaymentQueryV1 {
    NativePaymentQueryV1 {
        source: NativeFundingSourceV1::Task(task),
        subject: output,
        beneficiary: public(1),
        operation: Envelope::decode(tx).unwrap().id().unwrap(),
        maximum_gross_units: BUDGET,
    }
}

#[test]
fn permanent_account_growth_refuses_the_unmigrated_contract_profile_explicitly() {
    let error = settings()
        .with_permanent_account_growth_v2("unsupported-funded-service-combination")
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "GROWTH_SERVICE_CONTRACT_UNSUPPORTED");
}

#[test]
fn actual_arbitrator_payment_reopens_and_reorg_refund_cannot_claim_service_payment() {
    for backend in [Backend::Legacy, Backend::Authenticated] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path(), backend);
        let settings = node.settings().clone();
        let terms = contract();
        let (task, reserved) = reserve(&mut node, &terms);
        let original = record(&node, task);
        assert_eq!(original.terms, terms);
        assert_eq!(original.delivered_output, None);
        assert_eq!(original.receipt_height, None);
        let reserved_payer_balance = balance(&node, 0);
        let cancel = signed(&settings, 0, 2, 3, task.to_vec());
        refused(&mut node, reserved, cancel);
        let output = [40; 32];
        let receipt = signed(
            &settings,
            1,
            1,
            4,
            [task.as_slice(), output.as_slice()].concat(),
        );
        let delivered = mine(&mut node, reserved, vec![receipt]);
        let provider_before = balance(&node, 1);
        let pay = verdict(
            &settings,
            &terms,
            task,
            output,
            FundedServiceVerdictV1::PayProvider,
            1,
        );
        let payment_query = query(task, output, &pay);
        assert!(node.native_payment_observation(&payment_query).is_err());
        let paid = mine(&mut node, delivered, vec![pay]);
        assert_eq!(balance(&node, 1), provider_before + BUDGET);
        assert_eq!(balance(&node, 0), reserved_payer_balance);
        let payment = node.native_payment_observation(&payment_query).unwrap();
        assert_eq!(payment.anchor.block, paid);
        assert_eq!(payment.gross_escrow_debit, BUDGET);
        assert_eq!(payment.beneficiary_credit, BUDGET);
        assert_eq!(
            record(&node, task).resolution.unwrap().kind,
            ServiceResolutionKindV1::ArbitratorPaid
        );
        refused(
            &mut node,
            paid,
            verdict(
                &settings,
                &terms,
                task,
                output,
                FundedServiceVerdictV1::PayProvider,
                2,
            ),
        );
        drop(node);

        let mut node = open(directory.path(), backend);
        assert_eq!(
            node.native_payment_observation(&payment_query).unwrap(),
            payment
        );
        assert_eq!(balance(&node, 1), provider_before + BUDGET);
        assert_eq!(
            record(&node, task).contract_digest,
            original.contract_digest
        );
        let sibling = mine(&mut node, delivered, vec![]);
        // Equal-work siblings remain retained without displacing the old tip.
        // A real extra block makes this branch the canonical successor.
        let fork = mine(&mut node, sibling, vec![]);
        assert_eq!(node.active().unwrap().0, fork);
        assert!(node.native_payment_observation(&payment_query).is_err());
        assert_eq!(balance(&node, 1), provider_before);
        assert_eq!(row(&node, task)["status"], "receipt");
        let refund = verdict(
            &settings,
            &terms,
            task,
            output,
            FundedServiceVerdictV1::RefundPayer,
            1,
        );
        let refund_query = query(task, output, &refund);
        let refunded = mine(&mut node, fork, vec![refund]);
        assert_eq!(balance(&node, 0), reserved_payer_balance + BUDGET);
        assert_eq!(balance(&node, 1), provider_before);
        assert_eq!(row(&node, task)["status"], "refunded");
        assert_eq!(row(&node, task)["remaining"], 0);
        assert_eq!(
            record(&node, task).resolution.unwrap().kind,
            ServiceResolutionKindV1::ArbitratorRefunded
        );
        assert!(node.native_payment_observation(&refund_query).is_err());
        let mut refund_to_payer = refund_query.clone();
        refund_to_payer.beneficiary = public(0);
        assert!(node.native_payment_observation(&refund_to_payer).is_err());
        assert!(node.native_payment_observation(&payment_query).is_err());
        refused(
            &mut node,
            refunded,
            verdict(
                &settings,
                &terms,
                task,
                output,
                FundedServiceVerdictV1::PayProvider,
                2,
            ),
        );
        drop(node);

        let node = open(directory.path(), backend);
        assert_eq!(node.active().unwrap().0, refunded);
        assert_eq!(row(&node, task)["status"], "refunded");
        assert_eq!(
            record(&node, task).contract_digest,
            original.contract_digest
        );
        assert_eq!(balance(&node, 0), reserved_payer_balance + BUDGET);
        assert_eq!(balance(&node, 1), provider_before);
        assert!(node.native_payment_observation(&payment_query).is_err());
        eprintln!("native contract arbitration: backend={backend:?}, exact_pay_and_refund={BUDGET}, reopens=2, reorg=true");
    }
}

#[test]
fn ordinary_customer_acceptance_uses_the_frozen_contract_and_same_payment_owner() {
    for backend in [Backend::Legacy, Backend::Authenticated] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path(), backend);
        let settings = node.settings().clone();
        let terms = contract();
        let (task, reserved) = reserve(&mut node, &terms);
        let output = [40; 32];
        let result_payload = [task.as_slice(), output.as_slice()].concat();
        let receipt = signed(&settings, 1, 1, 4, result_payload.clone());
        let delivered = mine(&mut node, reserved, vec![receipt]);
        let before = balance(&node, 1);
        let acceptance = signed(&settings, 0, 2, 5, result_payload);
        let payment_query = query(task, output, &acceptance);
        let accepted = mine(&mut node, delivered, vec![acceptance]);
        assert_eq!(balance(&node, 1), before + BUDGET);
        assert_eq!(
            record(&node, task).resolution.unwrap().kind,
            ServiceResolutionKindV1::CustomerAccepted
        );
        assert_eq!(
            node.native_payment_observation(&payment_query)
                .unwrap()
                .beneficiary_credit,
            BUDGET
        );
        refused(
            &mut node,
            accepted,
            verdict(
                &settings,
                &terms,
                task,
                output,
                FundedServiceVerdictV1::RefundPayer,
                1,
            ),
        );
    }
}

#[test]
fn unresolved_native_contract_expiry_refunds_payer_and_is_not_a_service_payment() {
    for backend in [Backend::Legacy, Backend::Authenticated] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path(), backend);
        let settings = node.settings().clone();
        let terms = contract();
        let (task, reserved) = reserve(&mut node, &terms);
        let payer = balance(&node, 0);
        let output = [40; 32];
        let receipt = signed(
            &settings,
            1,
            1,
            4,
            [task.as_slice(), output.as_slice()].concat(),
        );
        let mut current = mine(&mut node, reserved, vec![receipt]);
        let provider = balance(&node, 1);
        while node.parent_height(current).unwrap() < terms.dispute_deadline {
            current = mine(&mut node, current, vec![]);
        }
        assert_eq!(row(&node, task)["status"], "expired");
        assert_eq!(row(&node, task)["remaining"], 0);
        assert_eq!(balance(&node, 0), payer + BUDGET);
        assert_eq!(balance(&node, 1), provider);
        assert_eq!(record(&node, task).delivered_output, Some(output));
        assert!(record(&node, task).resolution.is_none());
        let pay = verdict(
            &settings,
            &terms,
            task,
            output,
            FundedServiceVerdictV1::PayProvider,
            1,
        );
        assert!(node
            .native_payment_observation(&query(task, output, &pay))
            .is_err());
        drop(node);
        let node = open(directory.path(), backend);
        assert_eq!(row(&node, task)["status"], "expired");
        assert_eq!(balance(&node, 0), payer + BUDGET);
        assert_eq!(balance(&node, 1), provider);
    }
}
