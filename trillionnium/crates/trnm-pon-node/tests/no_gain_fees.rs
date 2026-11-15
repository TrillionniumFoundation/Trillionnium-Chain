//! Real signed Task settlement through the public Node owner and M12 adapter.
//!
//! The resource figures, output digest and NoGain outcome are controlled inputs.
//! This executes funding, payment and durable readback; it does not run training,
//! authenticate independent evaluation or establish physical resource metering.
use serde_json::{json, Value};
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::*;

const AMOUNT: u64 = 2_000;
const CLOCK: u64 = 100_000;

#[derive(Clone, Copy, Debug)]
enum Backend {
    Legacy,
    Authenticated,
    Growth,
}

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}

fn open(path: &Path, backend: Backend) -> Node {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    match backend {
        Backend::Legacy => Node::open(path, settings, 1),
        Backend::Authenticated => Node::open_with_authenticated_state(path, settings, 1),
        Backend::Growth => Node::open_with_permanent_account_growth_v2(
            path,
            settings
                .with_permanent_account_growth_v2("no-gain-native-fee-v1")
                .unwrap(),
        ),
    }
    .unwrap()
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
    let timestamp = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
    let id = match backend {
        Backend::Growth => {
            let packet = node
                .make_growth_consensus_maintenance(parent, transactions, public(3), timestamp, 4096)
                .unwrap();
            node.admit_growth(&packet, CLOCK).unwrap()
        }
        _ => {
            let packet = node
                .make_consensus_maintenance(parent, transactions, public(3), timestamp, 4096)
                .unwrap();
            node.admit(&packet, CLOCK).unwrap()
        }
    };
    // An equal-work sibling is stored but does not displace the current tip.
    node.activate(id).unwrap();
    id
}

fn balance(node: &Node, backend: Backend, owner: Hash) -> u64 {
    match backend {
        Backend::Growth => {
            node.growth_account(node.active().unwrap().0, owner)
                .unwrap()
                .unwrap()
                .balance
        }
        _ => node.read_active().unwrap().2[&format!("account:{}", hex::encode(owner))]["balance"]
            .as_u64()
            .unwrap(),
    }
}

fn model_state(node: &Node, backend: Backend) -> Vec<(String, Value)> {
    let state = match backend {
        Backend::Growth => node.growth_current_working().unwrap().working,
        _ => node.read_active().unwrap().2,
    };
    state
        .into_iter()
        .filter(|(key, _)| {
            key == "model:current"
                || key.starts_with("release:")
                || key.starts_with("contribution:")
        })
        .collect()
}

fn resources(lane: NativeBudgetLaneV1, amount: u64) -> NativeBudgetResourcesV1 {
    match lane {
        NativeBudgetLaneV1::Contribution => NativeBudgetResourcesV1::Contribution {
            training_cpu_ns: amount,
            parameter_bytes: amount,
        },
        NativeBudgetLaneV1::Evaluation => NativeBudgetResourcesV1::Evaluation {
            evaluation_cpu_ns: amount,
            evaluated_examples: amount,
        },
        _ => panic!("this suite covers commissioned training and evaluation"),
    }
}

fn scenario(lane: NativeBudgetLaneV1, backend: Backend) {
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let journal = directory.path().join("budgets.sqlite");
    let mut node = open(&node_path, backend);
    let settings = node.settings().clone();
    let original_model_state = model_state(&node, backend);
    let original_owner_balance = balance(&node, backend, public(0));
    let original_provider_balance = balance(&node, backend, public(1));
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &1_u64.to_le_bytes(),
            &public(1),
            &AMOUNT.to_le_bytes(),
            &20_u64.to_le_bytes(),
        ],
    );
    let output = hash(b"no-gain-native-fee-fixture-output-v1", &[&task]);
    let mut reserve_payload = task.to_vec();
    reserve_payload.extend(public(1));
    reserve_payload.extend(AMOUNT.to_le_bytes());
    reserve_payload.extend(20_u64.to_le_bytes());
    let reserve = signed(&settings, 0, 1, 2, reserve_payload);
    let reserved = mine(&mut node, backend, settings.genesis(), vec![reserve]);
    assert!(balance(&node, backend, public(0)) < original_owner_balance - AMOUNT);
    assert_eq!(
        balance(&node, backend, public(1)),
        original_provider_balance
    );
    let source = NativeFundingSourceV1::Task(task);
    let funding = node.native_funding_observation(source).unwrap();
    assert_eq!(funding.anchor.block, reserved);
    assert_eq!(funding.row.as_ref().unwrap()["remaining"], AMOUNT);
    assert_eq!(funding.row.as_ref().unwrap()["status"], "reserved");
    let configuration = NativeBudgetConfigV1 {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
        max_records: 32,
    };
    let mut budgets = NativeBudgetStoreV1::open(&journal, configuration.clone()).unwrap();
    let policy = NativeBudgetPolicyV1 {
        budget: [72; 32],
        source,
        monetary_cap: AMOUNT,
        deadline: 19,
        resource_cap: resources(lane, 10),
        max_inflight: 1,
    };
    let claim = NativeBudgetClaimV1 {
        claim: [73; 32],
        budget: policy.budget,
        subject: output,
        beneficiary: public(1),
        monetary_reservation: AMOUNT,
        resource_reservation: resources(lane, 4),
    };
    budgets.open_budget(&mut node, policy).unwrap();
    budgets.reserve(&mut node, claim.clone()).unwrap();
    assert_eq!(
        budgets
            .begin_effect(&mut node, claim.claim, [74; 32], output)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    budgets
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::NoGain,
            Some(resources(lane, 3)),
        )
        .unwrap();

    let mut result_payload = task.to_vec();
    result_payload.extend(output);
    let receipt = signed(&settings, 1, 1, 4, result_payload.clone());
    let accept = signed(&settings, 0, 2, 5, result_payload.clone());
    let operation = Envelope::decode(&accept).unwrap().id().unwrap();
    let query = NativePaymentQueryV1 {
        source,
        subject: output,
        beneficiary: public(1),
        operation,
        maximum_gross_units: AMOUNT,
    };
    let receipted = mine(&mut node, backend, reserved, vec![receipt]);
    let after_receipt_balance = balance(&node, backend, public(1));
    assert!(after_receipt_balance < original_provider_balance);
    assert!(node.native_payment_observation(&query).is_err());
    let before_unexecuted = budgets.report().unwrap();
    assert!(budgets
        .record_native_payment(&mut node, claim.claim, operation)
        .is_err());
    assert_eq!(budgets.report().unwrap(), before_unexecuted);

    let settled = mine(&mut node, backend, receipted, vec![accept]);
    assert_eq!(
        balance(&node, backend, public(1)),
        after_receipt_balance + AMOUNT
    );
    let payment = node.native_payment_observation(&query).unwrap();
    assert_eq!(payment.anchor.block, settled);
    assert_eq!(payment.gross_escrow_debit, AMOUNT);
    assert_eq!(payment.beneficiary_credit, AMOUNT);
    let paid_funding = node.native_funding_observation(source).unwrap();
    assert_eq!(paid_funding.row.as_ref().unwrap()["remaining"], 0);
    assert_eq!(paid_funding.row.as_ref().unwrap()["status"], "settled");
    // Real native payment alone cannot stand in for completed local work.
    assert!(budgets
        .record_native_payment(&mut node, claim.claim, operation)
        .is_err());
    assert_eq!(budgets.report().unwrap(), before_unexecuted);
    budgets
        .complete_effect(claim.claim, [74; 32], [76; 32])
        .unwrap();
    assert_eq!(
        budgets
            .record_native_payment(&mut node, claim.claim, operation)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let report = budgets.report().unwrap();
    assert_eq!(
        report["budgets"][0]["historically_observed_native_gross_debit"],
        AMOUNT
    );
    assert_eq!(
        report["budgets"][0]["historically_observed_beneficiary_credit"],
        AMOUNT
    );
    assert_eq!(report["budgets"][0]["resource_charge"], json!([3, 3, 0, 0]));
    assert_eq!(report["authorizes_native_payment"], false);
    assert_eq!(report["production_activation"], false);
    assert_eq!(model_state(&node, backend), original_model_state);
    assert_eq!(
        budgets
            .record_native_payment(&mut node, claim.claim, operation)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert!(budgets
        .record_native_payment(&mut node, claim.claim, [77; 32])
        .is_err());
    let relabel = budgets
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(lane, 3)),
        )
        .unwrap_err();
    assert_eq!(relabel.to_string(), "BUDGET_RESOURCE_REPLAY_MISMATCH");
    assert_eq!(budgets.report().unwrap(), report);

    // A fresh account nonce cannot pay an already settled Task a second time.
    let second_accept = signed(&settings, 0, 3, 5, result_payload);
    let next_timestamp = 1 + 10 * (node.parent_height(settled).unwrap() + 1);
    let refused = match backend {
        Backend::Growth => node
            .make_growth_consensus_maintenance(
                settled,
                vec![second_accept],
                public(3),
                next_timestamp,
                4096,
            )
            .is_err(),
        _ => node
            .make_consensus_maintenance(
                settled,
                vec![second_accept],
                public(3),
                next_timestamp,
                4096,
            )
            .is_err(),
    };
    assert!(refused);
    assert_eq!(node.active().unwrap().0, settled);
    assert_eq!(
        balance(&node, backend, public(1)),
        after_receipt_balance + AMOUNT
    );
    drop(budgets);
    drop(node);

    let mut node = open(&node_path, backend);
    let mut budgets = NativeBudgetStoreV1::open(&journal, configuration.clone()).unwrap();
    assert_eq!(budgets.report().unwrap(), report);
    let readback = budgets
        .reobserve_native_payment(&mut node, claim.claim)
        .unwrap();
    assert_eq!(readback.historical, payment);
    assert_eq!(
        readback.observed,
        node.native_payment_observation(&query).unwrap()
    );
    assert_eq!(
        budgets
            .record_native_payment(&mut node, claim.claim, operation)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(budgets.report().unwrap(), report);
    assert_eq!(
        balance(&node, backend, public(1)),
        after_receipt_balance + AMOUNT
    );

    // Reorganization removes current monetary membership, never the historical
    // local cost/payment or the completed effect's no-redispatch identity.
    let sibling = mine(&mut node, backend, receipted, vec![]);
    let fork = mine(&mut node, backend, sibling, vec![]);
    assert_eq!(node.active().unwrap().0, fork);
    assert!(node.native_payment_observation(&query).is_err());
    assert!(budgets
        .reobserve_native_payment(&mut node, claim.claim)
        .is_err());
    assert_eq!(balance(&node, backend, public(1)), after_receipt_balance);
    assert_eq!(budgets.report().unwrap(), report);
    assert_eq!(
        budgets
            .begin_effect(&mut node, claim.claim, [74; 32], output)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    let mut duplicate = claim.clone();
    duplicate.claim = [78; 32];
    assert!(budgets.reserve(&mut node, duplicate).is_err());
    assert_eq!(budgets.report().unwrap(), report);
    drop(budgets);
    drop(node);
    let mut node = open(&node_path, backend);
    let mut budgets = NativeBudgetStoreV1::open(&journal, configuration).unwrap();
    assert!(budgets
        .reobserve_native_payment(&mut node, claim.claim)
        .is_err());
    assert_eq!(budgets.report().unwrap(), report);
    assert_eq!(
        budgets
            .begin_effect(&mut node, claim.claim, [74; 32], output)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(balance(&node, backend, public(1)), after_receipt_balance);
    assert_eq!(model_state(&node, backend), original_model_state);
    eprintln!(
        "native NoGain fee: lane={lane:?}, backend={backend:?}, exact_credit={AMOUNT}, reopens=2, reorg=true, model_release_created=false"
    );
}

#[test]
fn native_no_gain_training_task_fee_survives_reopen_and_reorg_without_double_payment() {
    for backend in [Backend::Legacy, Backend::Authenticated, Backend::Growth] {
        scenario(NativeBudgetLaneV1::Contribution, backend);
    }
}

#[test]
fn native_no_gain_evaluation_task_fee_survives_reopen_and_reorg_without_double_payment() {
    for backend in [Backend::Legacy, Backend::Authenticated, Backend::Growth] {
        scenario(NativeBudgetLaneV1::Evaluation, backend);
    }
}
