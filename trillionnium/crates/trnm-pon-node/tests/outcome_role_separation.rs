//! One native chain with separate miner, model author and commissioned provider.
//!
//! This exercises actual W1 admission, signed M06 transfers, M12 payment readback
//! and cold reopen. Scores, output digests and NoGain resources are controlled
//! inputs. No optimizer, independent evaluator, storage service or Hepta FinalUse
//! runs here; controlled attestations are not evidence of useful model learning.
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation as evaluation};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::*;

const MINER: u64 = 0;
const PROVIDER: u64 = 1;
const PAYER: u64 = 2;
const AUTHOR: u64 = 3;
const CLOCK: u64 = 100_000;
const SERVICE_FEE: u64 = 2_000;
const MODEL_BUDGET: u64 = 10_000;
const SCORE: u64 = 10;

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}

fn signed(settings: &Settings, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(who),
        nonce,
        expiry: 2_000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn next_tx(node: &Node, who: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    signed(
        node.settings(),
        who,
        node.next_nonce(public(who)).unwrap(),
        tag,
        payload,
    )
}

fn mine(node: &mut Node, transactions: Vec<Vec<u8>>) -> Hash {
    let parent = node.active().unwrap().0;
    let height = node.parent_height(parent).unwrap() + 1;
    let packet = node
        .make(parent, transactions, public(MINER), 1 + height * 10, 4096)
        .unwrap();
    assert_eq!(packet.header.miner, public(MINER));
    assert!(!packet.proof.is_empty());
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate_observed(id, CLOCK).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    let state = node.read_active().unwrap().2;
    assert_eq!(state["meta:issued"], 40_000_000 + 1_000 * height);
    assert!(state
        .iter()
        .filter(|(key, _)| key.starts_with("reward:"))
        .all(|(_, reward)| reward["owner"] == hex::encode(public(MINER))));
    id
}

fn mine_to(node: &mut Node, height: u64) {
    while node.parent_height(node.active().unwrap().0).unwrap() < height {
        mine(node, vec![]);
    }
}

fn balance(node: &Node, who: u64) -> u64 {
    node.read_active().unwrap().2[&format!("account:{}", hex::encode(public(who)))]["balance"]
        .as_u64()
        .unwrap()
}

fn refused_without_effect(node: &Node, transaction: Vec<u8>, expected: &str) {
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let height = node.parent_height(before.0).unwrap() + 1;
    let error = node
        .make(
            before.0,
            vec![transaction],
            public(MINER),
            1 + height * 10,
            4096,
        )
        .unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.stats().unwrap(), stats);
}

fn contribution(
    settings: &Settings,
    cfg: &Config,
    nonce: u64,
    artifact: Hash,
    components: Hash,
) -> (Hash, Vec<u8>) {
    let id = hash(
        b"contribution-v3",
        &[
            &public(AUTHOR),
            &cfg.family,
            &[0; 32],
            &artifact,
            &components,
            &0_u64.to_le_bytes(),
        ],
    );
    let mut payload = id.to_vec();
    payload.extend(cfg.family);
    payload.extend([0; 32]);
    payload.extend(artifact);
    payload.extend(1024_u64.to_le_bytes());
    payload.extend(components);
    payload.extend(0_u64.to_le_bytes());
    (id, signed(settings, AUTHOR, nonce, 6, payload))
}

fn evaluation_transactions(
    node: &Node,
    cfg: &Config,
    candidates: &[(Hash, u64)],
    reveal: bool,
) -> Vec<Vec<u8>> {
    let state = node.read_active().unwrap().2;
    let mut transactions = Vec::new();
    for who in 0..3 {
        let first_nonce = node.next_nonce(public(who)).unwrap();
        for (index, &(candidate, score)) in candidates.iter().enumerate() {
            let round = evaluation::round(
                &state[&format!("contribution:{}", hex::encode(candidate))]["public_evaluation"],
            )
            .unwrap();
            let evidence = hash(b"controlled-role-separation-evaluation", &[&candidate]);
            let salt = [who as u8 + 1; 32];
            let mut payload = candidate.to_vec();
            payload.extend(round);
            if reveal {
                payload.extend(cfg.plan);
                payload.extend(evidence);
                payload.extend(score.to_le_bytes());
                payload.extend(salt);
            } else {
                payload.extend(evaluation::reveal_commitment(
                    round,
                    candidate,
                    public(who),
                    cfg.plan,
                    evidence,
                    score,
                    salt,
                ));
            }
            transactions.push(signed(
                node.settings(),
                who,
                first_nonce + index as u64,
                if reveal { 15 } else { 14 },
                payload,
            ));
        }
    }
    transactions
}

fn release_payload(bundle: Hash, component: Hash, root: Hash) -> (Hash, Vec<u8>) {
    let release = hash(
        b"release",
        &[
            &[0; 32],
            &bundle,
            &MODEL_BUDGET.to_le_bytes(),
            &root,
            &SCORE.to_le_bytes(),
        ],
    );
    let mut payload = release.to_vec();
    payload.extend([0; 32]);
    payload.extend(bundle);
    payload.extend(MODEL_BUDGET.to_le_bytes());
    payload.extend(root);
    payload.extend(SCORE.to_le_bytes());
    payload.push(1);
    payload.extend(component);
    payload.extend(SCORE.to_le_bytes());
    (release, payload)
}

fn claim_payload(release: Hash, component: Hash) -> Vec<u8> {
    let mut payload = release.to_vec();
    payload.extend(component);
    payload.extend(SCORE.to_le_bytes());
    payload.push(0);
    payload
}

fn evaluation_resources(amount: u64) -> NativeBudgetResourcesV1 {
    NativeBudgetResourcesV1::Evaluation {
        evaluation_cpu_ns: amount,
        evaluated_examples: amount,
    }
}

#[test]
fn native_work_model_reward_and_no_gain_service_payment_have_distinct_recipients() {
    assert_ne!(public(MINER), public(AUTHOR));
    assert_ne!(public(MINER), public(PROVIDER));
    assert_ne!(public(AUTHOR), public(PROVIDER));
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let budget_path = directory.path().join("budget.sqlite");
    let settings =
        Settings::development_with_evaluation_policy(Some(1), evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(&node_path, settings.clone(), 2).unwrap();
    let author_initial = balance(&node, AUTHOR);
    let provider_initial = balance(&node, PROVIDER);

    // A commissioned evaluator can complete its contract with no model gain.
    // The resource/outcome record is a controlled owner input, not an optimizer.
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(PAYER),
            &1_u64.to_le_bytes(),
            &public(PROVIDER),
            &SERVICE_FEE.to_le_bytes(),
            &20_u64.to_le_bytes(),
        ],
    );
    let output = hash(b"controlled-no-gain-service-output", &[&task]);
    let mut payload = task.to_vec();
    payload.extend(public(PROVIDER));
    payload.extend(SERVICE_FEE.to_le_bytes());
    payload.extend(20_u64.to_le_bytes());
    let reserve = next_tx(&node, PAYER, 2, payload);
    mine(&mut node, vec![reserve]);
    let configuration = NativeBudgetConfigV1 {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
        max_records: 32,
    };
    let mut budgets = NativeBudgetStoreV1::open(&budget_path, configuration.clone()).unwrap();
    let source = NativeFundingSourceV1::Task(task);
    let claim_id = [72; 32];
    budgets
        .open_budget(
            &mut node,
            NativeBudgetPolicyV1 {
                budget: [71; 32],
                source,
                monetary_cap: SERVICE_FEE,
                deadline: 19,
                resource_cap: evaluation_resources(10),
                max_inflight: 1,
            },
        )
        .unwrap();
    budgets
        .reserve(
            &mut node,
            NativeBudgetClaimV1 {
                claim: claim_id,
                budget: [71; 32],
                subject: output,
                beneficiary: public(PROVIDER),
                monetary_reservation: SERVICE_FEE,
                resource_reservation: evaluation_resources(4),
            },
        )
        .unwrap();
    assert_eq!(
        budgets
            .begin_effect(&mut node, claim_id, [73; 32], output)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    budgets
        .record_resources(
            claim_id,
            NativeResourceOutcomeV1::NoGain,
            Some(evaluation_resources(3)),
        )
        .unwrap();
    let mut result = task.to_vec();
    result.extend(output);
    refused_without_effect(&node, next_tx(&node, MINER, 4, result.clone()), "AUTHORITY");
    refused_without_effect(
        &node,
        next_tx(&node, AUTHOR, 4, result.clone()),
        "AUTHORITY",
    );
    let receipt = next_tx(&node, PROVIDER, 4, result.clone());
    mine(&mut node, vec![receipt]);
    let provider_after_receipt = balance(&node, PROVIDER);
    assert!(provider_after_receipt < provider_initial);
    let accept = next_tx(&node, PAYER, 5, result.clone());
    let service_operation = Envelope::decode(&accept).unwrap().id().unwrap();
    let service_query = NativePaymentQueryV1 {
        source,
        subject: output,
        beneficiary: public(PROVIDER),
        operation: service_operation,
        maximum_gross_units: SERVICE_FEE,
    };
    assert!(node.native_payment_observation(&service_query).is_err());
    mine(&mut node, vec![accept]);
    let service_payment = node.native_payment_observation(&service_query).unwrap();
    assert_eq!(service_payment.gross_escrow_debit, SERVICE_FEE);
    assert_eq!(service_payment.beneficiary_credit, SERVICE_FEE);
    assert_eq!(
        balance(&node, PROVIDER),
        provider_after_receipt + SERVICE_FEE
    );
    assert_eq!(balance(&node, AUTHOR), author_initial);
    assert!(budgets
        .record_native_payment(&mut node, claim_id, service_operation)
        .is_err());
    budgets
        .complete_effect(claim_id, [73; 32], [74; 32])
        .unwrap();
    assert_eq!(
        budgets
            .record_native_payment(&mut node, claim_id, service_operation)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        budgets
            .record_native_payment(&mut node, claim_id, service_operation)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    refused_without_effect(&node, next_tx(&node, PAYER, 5, result), "STATE");
    let service_report = budgets.report().unwrap();
    assert!(budgets
        .record_resources(
            claim_id,
            NativeResourceOutcomeV1::Positive,
            Some(evaluation_resources(3))
        )
        .is_err());
    assert_eq!(budgets.report().unwrap(), service_report);
    assert_eq!(service_report["authorizes_native_payment"], false);
    assert_eq!(service_report["production_activation"], false);

    // Three candidates share an author who has never mined or supplied service.
    // One completes with score zero; two controlled positive attestations permit
    // a finite, separately funded release. The author is no evaluator here.
    let (zero, zero_tx) = contribution(&settings, &cfg, 1, [41; 32], [0; 32]);
    let (component, component_tx) = contribution(&settings, &cfg, 2, [42; 32], [0; 32]);
    let allocation = hash(
        b"allocation-leaf",
        &[&component, &public(AUTHOR), &SCORE.to_le_bytes()],
    );
    let (bundle, bundle_tx) = contribution(&settings, &cfg, 3, [43; 32], allocation);
    mine(&mut node, vec![zero_tx, component_tx, bundle_tx]);
    let candidates = [(zero, 0), (component, SCORE), (bundle, SCORE)];
    mine_to(&mut node, 15);
    let commits = evaluation_transactions(&node, &cfg, &candidates, false);
    mine(&mut node, commits);
    mine_to(&mut node, 31);
    let reveals = evaluation_transactions(&node, &cfg, &candidates, true);
    mine(&mut node, reveals);
    mine_to(&mut node, 55);
    let state = node.read_active().unwrap().2;
    let zero_evaluation =
        &state[&format!("contribution:{}", hex::encode(zero))]["public_evaluation"]["closed"];
    assert_eq!(zero_evaluation["status"], "complete-scored");
    assert_eq!(zero_evaluation["score"], 0);
    assert_eq!(state["model:current"], hex::encode([0; 32]));
    assert!(!state.keys().any(|key| key.starts_with("release:")));
    let zero_root = hash(
        b"allocation-leaf",
        &[&zero, &public(AUTHOR), &SCORE.to_le_bytes()],
    );
    let (invented_release, zero_publish) = release_payload(zero, zero, zero_root);
    refused_without_effect(
        &node,
        next_tx(&node, PAYER, 8, zero_publish),
        "PUBLIC_EVAL_ADOPTION",
    );
    refused_without_effect(
        &node,
        next_tx(&node, AUTHOR, 9, claim_payload(invented_release, zero)),
        "STATE",
    );

    let (release, publish_payload) = release_payload(bundle, component, allocation);
    let publish = next_tx(&node, PAYER, 8, publish_payload);
    mine(&mut node, vec![publish]);
    assert_eq!(
        node.read_active().unwrap().2["model:current"],
        hex::encode(release)
    );
    let claim_bytes = claim_payload(release, component);
    refused_without_effect(
        &node,
        next_tx(&node, AUTHOR, 9, claim_bytes.clone()),
        "STATE",
    );
    mine_to(&mut node, 75);
    for wrong_payee in [MINER, PROVIDER, PAYER] {
        refused_without_effect(
            &node,
            next_tx(&node, wrong_payee, 9, claim_bytes.clone()),
            "ROOT",
        );
    }
    let provider_before_claim = balance(&node, PROVIDER);
    let claim = next_tx(&node, AUTHOR, 9, claim_bytes.clone());
    let model_operation = Envelope::decode(&claim).unwrap().id().unwrap();
    mine(&mut node, vec![claim]);
    let model_query = NativePaymentQueryV1 {
        source: NativeFundingSourceV1::Release(release),
        subject: component,
        beneficiary: public(AUTHOR),
        operation: model_operation,
        maximum_gross_units: MODEL_BUDGET,
    };
    let model_payment = node.native_payment_observation(&model_query).unwrap();
    assert_eq!(model_payment.gross_escrow_debit, MODEL_BUDGET);
    assert_eq!(model_payment.beneficiary_credit, MODEL_BUDGET);
    assert_eq!(balance(&node, PROVIDER), provider_before_claim);
    for wrong_payee in [MINER, PROVIDER] {
        let mut wrong_model = model_query.clone();
        wrong_model.beneficiary = public(wrong_payee);
        assert!(node.native_payment_observation(&wrong_model).is_err());
    }
    for wrong_payee in [MINER, AUTHOR] {
        let mut wrong_service = service_query.clone();
        wrong_service.beneficiary = public(wrong_payee);
        assert!(node.native_payment_observation(&wrong_service).is_err());
    }
    refused_without_effect(&node, next_tx(&node, AUTHOR, 9, claim_bytes), "DUPLICATE");
    let state = node.read_active().unwrap();
    assert_eq!(
        state.2[&format!("release:{}", hex::encode(release))]["claims"][hex::encode(component)],
        MODEL_BUDGET
    );
    assert_eq!(
        state.2[&format!("release:{}", hex::encode(release))]["remaining"],
        0
    );
    assert_eq!(budgets.report().unwrap(), service_report);
    drop(budgets);
    drop(node);

    let mut reopened = Node::open(&node_path, settings, 1).unwrap();
    let mut budgets = NativeBudgetStoreV1::open(&budget_path, configuration).unwrap();
    assert_eq!(reopened.read_active().unwrap(), state);
    assert_eq!(
        reopened
            .native_payment_observation(&service_query)
            .unwrap()
            .beneficiary_credit,
        SERVICE_FEE
    );
    assert_eq!(
        reopened
            .native_payment_observation(&model_query)
            .unwrap()
            .beneficiary_credit,
        MODEL_BUDGET
    );
    assert_eq!(budgets.report().unwrap(), service_report);
    assert_eq!(
        budgets
            .record_native_payment(&mut reopened, claim_id, service_operation)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert_eq!(budgets.report().unwrap(), service_report);
    eprintln!("native role separation: 76 W1 blocks; miner=0 author=3 provider=1 payer=2; completed zero-score candidate; NoGain service credit={SERVICE_FEE}; model-author credit={MODEL_BUDGET}; cold reopen; controlled inputs only");
}
