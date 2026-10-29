//! Real signed native funding with a separately durable M12 resource/effect
//! journal. Branch changes never restore local physical budgets or dispatch rights.
use super::*;
use crate::{consensus, development_public};
use serde_json::json;
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::*;

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn settings(backend: StateBackend) -> crate::Settings {
    let base = crate::Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    if backend == StateBackend::PermanentAccountGrowthV2 {
        base.with_permanent_account_growth_v2("native-budget-bridge-v2")
            .unwrap()
    } else {
        base
    }
}
fn open(path: &Path, backend: StateBackend) -> Node {
    match backend {
        StateBackend::PqNetworkV2 => panic!("use the independently pinned PQ network fixture"),
        StateBackend::Legacy => Node::open(path, settings(backend), 1).unwrap(),
        StateBackend::AuthenticatedV1 => {
            Node::open_with_authenticated_state(path, settings(backend), 1).unwrap()
        }
        StateBackend::PermanentAccountGrowthV2 => {
            Node::open_with_permanent_account_growth_v2(path, settings(backend)).unwrap()
        }
    }
}
fn signed(
    settings: &crate::Settings,
    sender: u64,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(sender),
        nonce,
        expiry: 2000,
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
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn mine(node: &mut Node, parent: Hash, transactions: Vec<Vec<u8>>) -> Hash {
    let height = node.record(parent).unwrap().height + 1;
    let id = if node.state_backend == StateBackend::PermanentAccountGrowthV2 {
        let packet = node
            .make_growth_consensus_maintenance(
                parent,
                transactions,
                public(3),
                1 + height * 10,
                4096,
            )
            .unwrap();
        node.admit_growth(&packet, 100_000).unwrap()
    } else {
        let packet = node
            .make_consensus_maintenance(parent, transactions, public(3), 1 + height * 10, 4096)
            .unwrap();
        node.admit(&packet, 100_000).unwrap()
    };
    node.activate(id).unwrap();
    id
}
fn reserve_task(
    settings: &crate::Settings,
    nonce: u64,
    amount: u64,
    deadline: u64,
) -> (Hash, Vec<u8>) {
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &public(1),
            &amount.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(amount.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    (task, signed(settings, 0, nonce, 2, payload))
}
fn configuration(node: &Node) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: node.settings.network(),
        parameters: node.settings.parameters(),
        genesis: node.settings.genesis(),
        max_records: 32,
    }
}
fn balance(node: &Node, owner: Hash) -> u64 {
    if node.state_backend == StateBackend::PermanentAccountGrowthV2 {
        node.growth_account(node.active().unwrap().0, owner)
            .unwrap()
            .unwrap()
            .balance
    } else {
        node.read_active().unwrap().2[&format!("account:{}", hex::encode(owner))]["balance"]
            .as_u64()
            .unwrap()
    }
}

#[test]
fn native_budget_bridge_signed_escrow_anchor_reorg_and_unknown_effect_replay() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node");
        let journal = dir.path().join("budgets.sqlite");
        let mut node = open(&path, backend);
        let settings = node.settings.clone();
        let genesis = settings.genesis();
        let original_balance = balance(&node, public(0));
        let (task, tx) = reserve_task(&settings, 1, 1_000, 20);
        let tip = mine(&mut node, genesis, vec![tx]);
        assert!(balance(&node, public(0)) < original_balance - 1_000);
        let source = NativeFundingSourceV1::Task(task);
        let observed = node.observe_funding(source).unwrap();
        assert_eq!(observed.anchor.block, tip);
        assert_eq!(observed.anchor.height, 1);
        assert_eq!(observed.anchor.state_root, node.record(tip).unwrap().root);
        assert_eq!(observed.row.as_ref().unwrap()["remaining"], 1_000);
        assert!(node
            .observe_funding(NativeFundingSourceV1::Task([255; 32]))
            .unwrap()
            .row
            .is_none());
        let mut budgets = NativeBudgetStoreV1::open(&journal, configuration(&node)).unwrap();
        let policy = NativeBudgetPolicyV1 {
            budget: [50; 32],
            source,
            monetary_cap: 1_000,
            deadline: 19,
            resource_cap: NativeBudgetResourcesV1::Storage {
                retained_bytes: 100,
                retained_byte_blocks: 1_000,
            },
            max_inflight: 1,
        };
        budgets.open_budget(&mut node, policy.clone()).unwrap();
        let claim = NativeBudgetClaimV1 {
            claim: [51; 32],
            budget: policy.budget,
            subject: [52; 32],
            beneficiary: public(1),
            monetary_reservation: 1_000,
            resource_reservation: NativeBudgetResourcesV1::Storage {
                retained_bytes: 40,
                retained_byte_blocks: 400,
            },
        };
        budgets.reserve(&mut node, claim.clone()).unwrap();
        assert_eq!(
            budgets
                .begin_effect(&mut node, claim.claim, [53; 32], [54; 32])
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        budgets
            .record_resources(claim.claim, NativeResourceOutcomeV1::Unknown, None)
            .unwrap();
        let local = budgets.report().unwrap();
        assert_eq!(
            local["budgets"][0]["resource_charge"],
            json!([40, 400, 0, 0])
        );
        let first = mine(&mut node, genesis, vec![]);
        let fork = mine(&mut node, first, vec![]);
        assert_eq!(node.active().unwrap().0, fork);
        assert!(node.observe_funding(source).unwrap().row.is_none());
        assert_eq!(balance(&node, public(0)), original_balance);
        let config = configuration(&node);
        drop(budgets);
        drop(node);
        let mut node = open(&path, backend);
        let mut budgets = NativeBudgetStoreV1::open(&journal, config).unwrap();
        assert_eq!(budgets.report().unwrap(), local);
        assert_eq!(
            budgets
                .begin_effect(&mut node, claim.claim, [53; 32], [54; 32])
                .unwrap(),
            NativeBudgetReplayV1::Pending
        );
        assert!(budgets
            .begin_effect(&mut node, claim.claim, [53; 32], [99; 32])
            .is_err());
        let mut second = claim.clone();
        second.claim = [61; 32];
        second.subject = [62; 32];
        assert!(budgets.reserve(&mut node, second).is_err());
        assert_eq!(budgets.report().unwrap(), local);
        assert_eq!(
            node.record(fork).unwrap().work,
            consensus::required_work(node.settings.target("initial_target_hex").unwrap())
                .unwrap()
                .checked_add(
                    consensus::required_work(node.settings.target("initial_target_hex").unwrap())
                        .unwrap()
                )
                .unwrap()
        );
    }
}

fn transaction_id(raw: &[u8]) -> Hash {
    Envelope::decode(raw).unwrap().id().unwrap()
}
fn transfer(
    settings: &crate::Settings,
    sender: u64,
    nonce: u64,
    recipient: u64,
    amount: u64,
) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    signed(settings, sender, nonce, 1, payload)
}
fn exact_fee(settings: &crate::Settings, raw: &[u8]) -> u64 {
    let tag = Envelope::decode(raw).unwrap().tag;
    settings.app.fees[tag as usize] + (raw.len() as u64) * settings.limit("byte_fee_units").unwrap()
}
fn working(node: &Node) -> trnm_mvcc_fee::pon_executor::State {
    if node.state_backend == StateBackend::PermanentAccountGrowthV2 {
        node.growth_current_working().unwrap().working
    } else {
        node.read_active().unwrap().2
    }
}

#[test]
fn native_payment_bridge_task_exact_signed_transition_net_balance_and_reorg() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node_path = dir.path().join("node");
        let journal = dir.path().join("budgets.sqlite");
        let mut node = open(&node_path, backend);
        let settings = node.settings.clone();
        let (task, reserve) = reserve_task(&settings, 1, 2_000, 20);
        let genesis = settings.genesis();
        let first = mine(&mut node, genesis, vec![reserve]);
        let source = NativeFundingSourceV1::Task(task);
        let output = [71; 32];
        let mut payload = task.to_vec();
        payload.extend(output);
        let receipt = signed(&settings, 1, 1, 4, payload.clone());
        let settle = signed(&settings, 0, 2, 5, payload);
        let operation = transaction_id(&settle);
        let spend = transfer(&settings, 1, 2, 2, 300);
        let provider_before = balance(&node, public(1));
        let mut budgets = NativeBudgetStoreV1::open(&journal, configuration(&node)).unwrap();
        let policy = NativeBudgetPolicyV1 {
            budget: [72; 32],
            source,
            monetary_cap: 2_000,
            deadline: 19,
            resource_cap: NativeBudgetResourcesV1::Storage {
                retained_bytes: 100,
                retained_byte_blocks: 1_000,
            },
            max_inflight: 1,
        };
        budgets.open_budget(&mut node, policy.clone()).unwrap();
        let claim = NativeBudgetClaimV1 {
            claim: [73; 32],
            budget: policy.budget,
            subject: output,
            beneficiary: public(1),
            monetary_reservation: 2_000,
            resource_reservation: NativeBudgetResourcesV1::Storage {
                retained_bytes: 40,
                retained_byte_blocks: 400,
            },
        };
        budgets.reserve(&mut node, claim.clone()).unwrap();
        assert_eq!(
            budgets
                .begin_effect(&mut node, claim.claim, [74; 32], [75; 32])
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        budgets
            .complete_effect(claim.claim, [74; 32], [76; 32])
            .unwrap();
        budgets
            .record_resources(
                claim.claim,
                NativeResourceOutcomeV1::Positive,
                Some(claim.resource_reservation.clone()),
            )
            .unwrap();
        let query = NativePaymentQueryV1 {
            source,
            subject: output,
            beneficiary: public(1),
            operation,
            maximum_gross_units: 2_000,
        };
        assert!(
            node.observe_payment(&query).is_err(),
            "a signed but unconfirmed transaction is not payment"
        );
        assert!(budgets
            .record_native_payment(&mut node, claim.claim, operation)
            .is_err());
        let actual_fees = exact_fee(&settings, &receipt) + exact_fee(&settings, &spend);
        let settled = mine(&mut node, first, vec![receipt, settle, spend]);
        assert_eq!(
            balance(&node, public(1)),
            provider_before + 2_000 - 300 - actual_fees
        );
        let observed = node.observe_payment(&query).unwrap();
        assert_eq!(observed.anchor.block, settled);
        assert_eq!(observed.gross_escrow_debit, 2_000);
        assert_eq!(
            observed.beneficiary_credit, 2_000,
            "the exact credit differs from the account net change"
        );
        let mut wrong = query.clone();
        wrong.subject = [77; 32];
        assert!(node.observe_payment(&wrong).is_err());
        wrong = query.clone();
        wrong.beneficiary = public(2);
        assert!(node.observe_payment(&wrong).is_err());
        wrong = query.clone();
        wrong.maximum_gross_units = 1_999;
        assert!(node.observe_payment(&wrong).is_err());
        wrong = query.clone();
        wrong.operation = [78; 32];
        assert!(node.observe_payment(&wrong).is_err());
        assert_eq!(
            budgets
                .record_native_payment(&mut node, claim.claim, operation)
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        assert_eq!(
            budgets
                .record_native_payment(&mut node, claim.claim, operation)
                .unwrap(),
            NativeBudgetReplayV1::Done
        );
        let report = budgets.report().unwrap();
        assert_eq!(
            report["budgets"][0]["historically_observed_native_gross_debit"],
            2_000
        );
        let readback = budgets
            .reobserve_native_payment(&mut node, claim.claim)
            .unwrap();
        assert_eq!(readback.historical, observed);
        assert_eq!(readback.observed, observed);
        assert_eq!(budgets.report().unwrap(), report);
        let fork_a = mine(&mut node, first, vec![]);
        let fork = mine(&mut node, fork_a, vec![]);
        assert_eq!(node.active().unwrap().0, fork);
        assert!(node.observe_payment(&query).is_err());
        assert!(budgets
            .reobserve_native_payment(&mut node, claim.claim)
            .is_err());
        assert_eq!(budgets.report().unwrap(), report);
        assert_eq!(
            node.observe_funding(source).unwrap().row.unwrap()["remaining"],
            2_000
        );
        assert_eq!(balance(&node, public(1)), provider_before);
        let config = configuration(&node);
        drop(budgets);
        drop(node);
        let mut node = open(&node_path, backend);
        let mut budgets = NativeBudgetStoreV1::open(&journal, config).unwrap();
        assert!(node.observe_payment(&query).is_err());
        assert!(budgets
            .reobserve_native_payment(&mut node, claim.claim)
            .is_err());
        assert_eq!(budgets.report().unwrap(), report);
        assert_eq!(
            budgets
                .begin_effect(&mut node, claim.claim, [74; 32], [75; 32])
                .unwrap(),
            NativeBudgetReplayV1::Done
        );
        assert_eq!(
            budgets
                .record_native_payment(&mut node, claim.claim, operation)
                .unwrap(),
            NativeBudgetReplayV1::Done
        );
        assert_eq!(
            balance(&node, public(1)),
            provider_before,
            "historical replay issues no replacement payment"
        );
        // The same signed payment may reappear on a heavier branch. This
        // reobservation updates only the returned anchor: no new claim, credit,
        // physical effect or historical journal event is created.
        let restored_a = mine(&mut node, settled, vec![]);
        let restored = mine(&mut node, restored_a, vec![]);
        assert_eq!(node.active().unwrap().0, restored);
        let readback = budgets
            .reobserve_native_payment(&mut node, claim.claim)
            .unwrap();
        assert_eq!(readback.historical, observed);
        assert_eq!(readback.observed.anchor.block, restored);
        assert!(readback.observed.anchor.generation > observed.anchor.generation);
        assert_eq!(readback.observed.operation, operation);
        assert_eq!(readback.observed.gross_escrow_debit, 2_000);
        assert_eq!(readback.observed.beneficiary_credit, 2_000);
        assert_eq!(budgets.report().unwrap(), report);
        assert_eq!(
            balance(&node, public(1)),
            provider_before + 2_000 - 300 - actual_fees
        );
        let mut duplicate = claim;
        duplicate.claim = [79; 32];
        assert!(budgets.reserve(&mut node, duplicate).is_err());
    }
}

fn reserve_quota(settings: &crate::Settings, units: u64, deadline: u64) -> (Hash, Vec<u8>) {
    let quota = hash(
        b"quota-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &1u64.to_le_bytes(),
            &public(2),
            &public(1),
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = quota.to_vec();
    payload.extend(public(2));
    payload.extend(public(1));
    payload.extend(units.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    (quota, signed(settings, 0, 1, 10, payload))
}
fn use_quota(
    settings: &crate::Settings,
    quota: Hash,
    nonce: u64,
    units: u64,
    result: Hash,
) -> Vec<u8> {
    let digest = hash(
        b"use",
        &[
            &settings.network(),
            &settings.parameters(),
            &quota,
            &public(1),
            &nonce.to_le_bytes(),
            &units.to_le_bytes(),
            &result,
        ],
    );
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&2u64.to_le_bytes()]))).unwrap();
    let mut payload = quota.to_vec();
    payload.extend(units.to_le_bytes());
    payload.extend(result);
    payload.extend(hex::decode(sign_hex(&key, &digest)).unwrap());
    signed(settings, 1, nonce, 11, payload)
}
#[test]
fn native_payment_bridge_quota_exact_consumer_authorized_operations_and_native_fees() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open(&dir.path().join("node"), backend);
        let settings = node.settings.clone();
        let (quota, reservation) = reserve_quota(&settings, 3, 20);
        let genesis = settings.genesis();
        let first = mine(&mut node, genesis, vec![reservation]);
        let source = NativeFundingSourceV1::Quota(quota);
        let unit_price = settings.limit("quota_unit_price").unwrap();
        let a = use_quota(&settings, quota, 1, 1, [81; 32]);
        let b = use_quota(&settings, quota, 2, 1, [82; 32]);
        let operation = transaction_id(&a);
        let operation_b = transaction_id(&b);
        let fee_a = exact_fee(&settings, &a);
        let fee_b = exact_fee(&settings, &b);
        let before = balance(&node, public(1));
        let spend = transfer(&settings, 1, 3, 0, 100);
        let spend_fee = exact_fee(&settings, &spend);
        let mut budgets =
            NativeBudgetStoreV1::open(&dir.path().join("budgets.sqlite"), configuration(&node))
                .unwrap();
        let policy = NativeBudgetPolicyV1 {
            budget: [83; 32],
            source,
            monetary_cap: 3 * unit_price,
            deadline: 19,
            resource_cap: NativeBudgetResourcesV1::Serving {
                inference_cpu_ns: 1_000,
                output_tokens: 100,
            },
            max_inflight: 1,
        };
        budgets.open_budget(&mut node, policy.clone()).unwrap();
        let claim = NativeBudgetClaimV1 {
            claim: [84; 32],
            budget: policy.budget,
            subject: [81; 32],
            beneficiary: public(1),
            monetary_reservation: unit_price,
            resource_reservation: NativeBudgetResourcesV1::Serving {
                inference_cpu_ns: 100,
                output_tokens: 10,
            },
        };
        budgets.reserve(&mut node, claim.clone()).unwrap();
        budgets
            .begin_effect(&mut node, claim.claim, [85; 32], [86; 32])
            .unwrap();
        budgets
            .complete_effect(claim.claim, [85; 32], [87; 32])
            .unwrap();
        budgets
            .record_resources(
                claim.claim,
                NativeResourceOutcomeV1::Positive,
                Some(claim.resource_reservation.clone()),
            )
            .unwrap();
        let query = NativePaymentQueryV1 {
            source,
            subject: [81; 32],
            beneficiary: public(1),
            operation,
            maximum_gross_units: unit_price,
        };
        assert!(node.observe_payment(&query).is_err());
        mine(&mut node, first, vec![a, b, spend]);
        assert_eq!(
            balance(&node, public(1)),
            before + 2 * unit_price - fee_a - fee_b - 100 - spend_fee
        );
        let payment = node.observe_payment(&query).unwrap();
        assert_eq!(payment.gross_escrow_debit, unit_price);
        assert_eq!(payment.beneficiary_credit, unit_price - fee_a);
        let mut second = query.clone();
        second.subject = [82; 32];
        second.operation = operation_b;
        let payment_b = node.observe_payment(&second).unwrap();
        assert_eq!(payment_b.beneficiary_credit, unit_price - fee_b);
        second.subject = query.subject;
        assert!(
            node.observe_payment(&second).is_err(),
            "a second real use cannot prove the first result"
        );
        let mut wrong = query.clone();
        wrong.beneficiary = public(2);
        assert!(node.observe_payment(&wrong).is_err());
        wrong = query.clone();
        wrong.maximum_gross_units = unit_price - 1;
        assert!(node.observe_payment(&wrong).is_err());
        assert_eq!(
            budgets
                .record_native_payment(&mut node, claim.claim, operation)
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        assert_eq!(
            budgets.report().unwrap()["budgets"][0]["historically_observed_beneficiary_credit"],
            unit_price - fee_a
        );
    }
}

#[test]
fn native_payment_bridge_evaluated_release_claim_and_individual_reward_maturity() {
    use trnm_mvcc_fee::public_evaluation as evaluation;
    // The public evaluation policy here is explicitly attested development data.
    // This tests native payment authority, not empirical model improvement.
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node");
        let mut node = open(&path, backend);
        let settings = node.settings.clone();
        let genesis = settings.genesis();
        let contribution = |nonce: u64, artifact: Hash, components: Hash| {
            let cid = hash(
                b"contribution-v3",
                &[
                    &public(3),
                    &settings.app.family,
                    &[0; 32],
                    &artifact,
                    &components,
                    &0u64.to_le_bytes(),
                ],
            );
            let mut payload = Vec::new();
            for value in [cid, settings.app.family, [0; 32], artifact] {
                payload.extend(value);
            }
            payload.extend(1024u64.to_le_bytes());
            payload.extend(components);
            payload.extend(0u64.to_le_bytes());
            (cid, signed(&settings, 3, nonce, 6, payload))
        };
        let (cid, component) = contribution(1, [7; 32], [8; 32]);
        let allocation = hash(
            b"allocation-leaf",
            &[&cid, &public(3), &10u64.to_le_bytes()],
        );
        let (bundle, bundle_tx) = contribution(2, [10; 32], allocation);
        let amount = 10_000u64;
        let release = hash(
            b"release",
            &[
                &[0; 32],
                &bundle,
                &amount.to_le_bytes(),
                &allocation,
                &10u64.to_le_bytes(),
            ],
        );
        let source = NativeFundingSourceV1::Release(release);
        let mut claim_payload = release.to_vec();
        claim_payload.extend(cid);
        claim_payload.extend(10u64.to_le_bytes());
        claim_payload.push(0);
        let claim = signed(&settings, 3, 4, 9, claim_payload);
        let query = NativePaymentQueryV1 {
            source,
            subject: cid,
            beneficiary: public(3),
            operation: transaction_id(&claim),
            maximum_gross_units: amount,
        };
        let reward = hash(b"reward", &[&genesis, &1u64.to_le_bytes(), &public(3)]);
        let mut reward_query = NativePaymentQueryV1 {
            source: NativeFundingSourceV1::Reward(reward),
            subject: reward,
            beneficiary: public(3),
            operation: reward,
            maximum_gross_units: 0,
        };
        let mut tip = genesis;
        for height in 1..=77 {
            let before = working(&node);
            let transactions = match height {
                1 => vec![component.clone(), bundle_tx.clone()],
                16 | 32 => {
                    let mut transactions = Vec::new();
                    for who in 0u64..3 {
                        for (index, candidate) in [cid, bundle].into_iter().enumerate() {
                            let object =
                                &before[&format!("contribution:{}", hex::encode(candidate))];
                            let round = evaluation::round(&object["public_evaluation"]).unwrap();
                            let mut payload = candidate.to_vec();
                            payload.extend(round);
                            let nonce = index as u64 + if height == 16 { 1 } else { 3 };
                            let tag = if height == 16 {
                                payload.extend(evaluation::reveal_commitment(
                                    round,
                                    candidate,
                                    public(who),
                                    settings.app.plan,
                                    [9; 32],
                                    10,
                                    [who as u8 + 1; 32],
                                ));
                                14
                            } else {
                                payload.extend(settings.app.plan);
                                payload.extend([9; 32]);
                                payload.extend(10u64.to_le_bytes());
                                payload.extend([who as u8 + 1; 32]);
                                15
                            };
                            transactions.push(signed(&settings, who, nonce, tag, payload));
                        }
                    }
                    transactions
                }
                56 => {
                    let mut payload = Vec::new();
                    for value in [release, [0; 32], bundle] {
                        payload.extend(value);
                    }
                    payload.extend(amount.to_le_bytes());
                    payload.extend(allocation);
                    payload.extend(10u64.to_le_bytes());
                    payload.push(1);
                    payload.extend(cid);
                    payload.extend(10u64.to_le_bytes());
                    vec![signed(&settings, 3, 3, 8, payload)]
                }
                76 => vec![claim.clone()],
                _ => vec![],
            };
            tip = mine(&mut node, tip, transactions);
            if height == 1 {
                let observed = node.observe_funding(reward_query.source).unwrap();
                let row = observed.row.unwrap();
                reward_query.maximum_gross_units = row["amount"].as_u64().unwrap();
                assert_eq!(row["maturity"], 21);
                assert!(
                    node.observe_payment(&reward_query).is_err(),
                    "an immature real reward is not a credited payment"
                );
            }
            if height == 20 {
                assert!(node.observe_payment(&reward_query).is_err());
            }
            if height == 21 {
                let paid = node.observe_payment(&reward_query).unwrap();
                assert_eq!(paid.gross_escrow_debit, reward_query.maximum_gross_units);
                assert_eq!(paid.beneficiary_credit, paid.gross_escrow_debit);
                let mut wrong = reward_query.clone();
                wrong.operation = [90; 32];
                assert!(node.observe_payment(&wrong).is_err());
                wrong = reward_query.clone();
                wrong.beneficiary = public(1);
                assert!(node.observe_payment(&wrong).is_err());
            }
            if height == 56 {
                let observed = node.observe_funding(source).unwrap();
                let row = observed.row.unwrap();
                assert_eq!(row["remaining"], amount);
                assert_eq!(row["maturity"], 76);
                assert!(
                    node.observe_payment(&query).is_err(),
                    "an existing funded release is not a claimed allocation"
                );
            }
            if height == 75 {
                assert!(node.observe_payment(&query).is_err());
            }
            if height == 76 {
                let paid = node.observe_payment(&query).unwrap();
                assert_eq!(paid.gross_escrow_debit, amount);
                assert_eq!(paid.beneficiary_credit, amount);
                let row = node.observe_funding(source).unwrap().row.unwrap();
                assert_eq!(row["claims"][hex::encode(cid)], amount);
                assert_eq!(row["remaining"], 0);
                let mut wrong = query.clone();
                wrong.subject = bundle;
                assert!(node.observe_payment(&wrong).is_err());
                wrong = query.clone();
                wrong.beneficiary = public(0);
                assert!(node.observe_payment(&wrong).is_err());
                wrong = query.clone();
                wrong.maximum_gross_units = amount - 1;
                assert!(node.observe_payment(&wrong).is_err());
            }
        }
        // Fresh owners reproduce both historical facts from stored native blocks,
        // despite later rewards to the same beneficiary and evaluation cleanup.
        drop(node);
        let mut node = open(&path, backend);
        assert_eq!(
            node.observe_payment(&query).unwrap().gross_escrow_debit,
            amount
        );
        assert_eq!(
            node.observe_payment(&reward_query)
                .unwrap()
                .beneficiary_credit,
            reward_query.maximum_gross_units
        );
    }
}

#[test]
fn native_payment_bridge_reference_task_requires_confirmed_gsc2_transition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reference-node");
    let settings = crate::Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::growth_profile_v2::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(&path, settings.clone(), 1).unwrap();
    let initial = node.read_active().unwrap().2;
    assert_ne!(
        settings.state_root(&initial).unwrap(),
        trnm_mvcc_fee::pon_executor::root(&initial).unwrap()
    );
    let (task, reserve) = reserve_task(&settings, 1, 2_000, 20);
    let first = mine(&mut node, settings.genesis(), vec![reserve]);
    let source = NativeFundingSourceV1::Task(task);
    let observed = node.observe_funding(source).unwrap();
    assert_eq!(observed.anchor.state_root, node.record(first).unwrap().root);
    assert_eq!(observed.row.unwrap()["remaining"], 2_000);

    let output = [161; 32];
    let mut payload = task.to_vec();
    payload.extend(output);
    let receipt = signed(&settings, 1, 1, 4, payload.clone());
    let settle = signed(&settings, 0, 2, 5, payload);
    let query = NativePaymentQueryV1 {
        source,
        subject: output,
        beneficiary: public(1),
        operation: transaction_id(&settle),
        maximum_gross_units: 2_000,
    };
    // This separate reference journal records declared local observations. Even
    // its completed receipt is not a confirmed M06 payment or an M12 Positive.
    let reference = crate::NativeBudgetRequestV1 {
        operation: [162; 32],
        subject: output,
        beneficiary: public(1),
        lane: crate::NativeBudgetLaneV1::Storage,
        source: task,
        amount: 2_000,
        source_cap: 2_000,
        resource_cap: [100, 1_000],
        resource_reservation: [40, 400],
        contribution: None,
    };
    node.reserve_native_budget_v1(reference.clone()).unwrap();
    node.settle_native_budget_resources_v1(reference.operation, [40, 400])
        .unwrap();
    node.prepare_native_budget_effect_v1(reference.operation, [163; 32])
        .unwrap();
    let local = node
        .finish_native_budget_effect_v1(reference.operation, [163; 32], [164; 32])
        .unwrap();
    assert!(local.effect_completed);
    assert!(!local.chain_funds_locked && !local.payment_executed && !local.execution_authority);
    assert!(node.observe_payment(&query).is_err());

    let provider_before = balance(&node, public(1));
    let provider_fee = exact_fee(&settings, &receipt);
    let settled = mine(&mut node, first, vec![receipt, settle]);
    let paid = node.observe_payment(&query).unwrap();
    assert_eq!(paid.anchor.block, settled);
    assert_eq!(paid.anchor.state_root, node.record(settled).unwrap().root);
    assert_eq!(
        (paid.gross_escrow_debit, paid.beneficiary_credit),
        (2_000, 2_000)
    );
    assert_eq!(
        balance(&node, public(1)),
        provider_before + 2_000 - provider_fee
    );
    let mut wrong = query.clone();
    wrong.subject = [165; 32];
    assert!(node.observe_payment(&wrong).is_err());
    drop(node);
    let mut node = Node::open(&path, settings.clone(), 1).unwrap();
    assert_eq!(node.observe_payment(&query).unwrap(), paid);
    let mut fork = settings.genesis();
    for _ in 0..3 {
        fork = mine(&mut node, fork, vec![]);
    }
    assert_eq!(node.active().unwrap().0, fork);
    assert!(node.observe_payment(&query).is_err());
    let retained = node.reserve_native_budget_v1(reference).unwrap();
    assert!(retained.effect_completed && !retained.funding_current);
    assert!(!retained.payment_executed && !retained.execution_authority);
}
