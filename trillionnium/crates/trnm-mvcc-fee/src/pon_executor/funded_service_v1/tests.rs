use super::*;
use crate::pon_executor::{execute, Output, State};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

const BUDGET: u64 = 2_000;
const BALANCE: u64 = 1_000_000;

fn public(who: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .unwrap()
        .verifying_key()
        .to_bytes()
}

fn configuration() -> Config {
    let mut cfg = Config::installed().unwrap();
    install(&mut cfg).unwrap();
    cfg
}

fn initial() -> State {
    let mut state = State::from([
        ("meta:issued".into(), json!(4 * BALANCE)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    for who in 0..4 {
        state.insert(
            format!("account:{}", hex::encode(public(who))),
            json!({"balance":BALANCE,"nonce":0}),
        );
    }
    state
}

fn contract() -> FundedServiceContractV1 {
    FundedServiceContractV1 {
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
        budget: BUDGET,
        delivery_deadline: 5,
        dispute_deadline: 10,
    }
}

fn signed(cfg: &Config, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: cfg.network,
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

fn block(state: &State, cfg: &Config, height: u64, transactions: Vec<Vec<u8>>) -> Result<Output> {
    execute(state, &transactions, height, public(3), [30; 32], 4, cfg)
}

fn reserve(cfg: &Config, contract: &FundedServiceContractV1) -> (Hash, State) {
    let task = contract.task_id(cfg.network, cfg.parameters, public(0), 1);
    let payload = FundedServiceReservationV1 {
        task,
        contract: contract.clone(),
    }
    .encode()
    .unwrap();
    let state = block(&initial(), cfg, 1, vec![signed(cfg, 0, 1, 2, payload)])
        .unwrap()
        .state;
    (task, state)
}

fn row(state: &State, task: Hash) -> &Value {
    &state[&format!("task:{}", hex::encode(task))]
}

fn balance(state: &State, who: u64) -> u64 {
    field(
        &state[&format!("account:{}", hex::encode(public(who)))],
        "balance",
    )
    .unwrap()
}

fn receipt(cfg: &Config, task: Hash, output: Hash) -> Vec<u8> {
    signed(cfg, 1, 1, 4, [task.as_slice(), output.as_slice()].concat())
}

fn decision(
    cfg: &Config,
    contract: &FundedServiceContractV1,
    task: Hash,
    output: Hash,
    verdict: FundedServiceVerdictV1,
) -> FundedServiceDecisionV1 {
    FundedServiceDecisionV1 {
        task,
        contract_digest: contract.digest(cfg.network, cfg.parameters, public(0)),
        output,
        evidence: [50; 32],
        verdict,
    }
}

#[test]
fn profile_changes_context_and_refuses_old_or_partial_admission() {
    let old = Config::installed().unwrap();
    let cfg = configuration();
    assert_ne!(cfg.network, old.network);
    assert_ne!(cfg.parameters, old.parameters);
    assert_eq!(cfg.fees, old.fees);
    let contract = contract();
    let payload = FundedServiceReservationV1 {
        task: contract.task_id(old.network, old.parameters, public(0), 1),
        contract,
    }
    .encode()
    .unwrap();
    let parent = initial();
    assert_eq!(
        block(&parent, &old, 1, vec![signed(&old, 0, 1, 2, payload)]).unwrap_err(),
        "SERVICE_CONTRACT_PROFILE"
    );
    assert_eq!(
        block(&parent, &cfg, 1, vec![signed(&cfg, 0, 1, 2, vec![1; 80])]).unwrap_err(),
        "SERVICE_CONTRACT_RESERVATION"
    );
    assert_eq!(parent, initial());
    let mut changed = cfg.clone();
    changed.params["funded_service_contract_policy"]["partial_settlement"] = json!(true);
    assert_eq!(check_config(&changed), Err("SERVICE_CONTRACT_PROFILE"));
    assert_eq!(
        block(&parent, &changed, 1, vec![]).unwrap_err(),
        "SERVICE_CONTRACT_PROFILE"
    );
    let mut changed = cfg.clone();
    changed.parameters = old.parameters;
    assert_eq!(check_config(&changed), Err("SERVICE_CONTRACT_CONTEXT"));
    assert_eq!(
        block(&parent, &changed, 1, vec![]).unwrap_err(),
        "SERVICE_CONTRACT_CONTEXT"
    );
    let mut changed = old;
    changed.params["account_authorization_profile"] = json!("pq-signed-development");
    assert_eq!(
        install(&mut changed),
        Err("SERVICE_CONTRACT_PQ_UNSUPPORTED")
    );
    let mut changed = cfg;
    changed.params["account_authorization_profile"] = json!("pq-signed-development");
    assert_eq!(check_config(&changed), Err("SERVICE_CONTRACT_PROFILE"));
    assert_eq!(
        block(&parent, &changed, 1, vec![]).unwrap_err(),
        "SERVICE_CONTRACT_PROFILE"
    );
}

#[test]
fn frozen_terms_and_actual_provider_receipt_precede_arbitration_payment() {
    let cfg = configuration();
    let contract = contract();
    let (task, reserved) = reserve(&cfg, &contract);
    let record = read_contract(task, row(&reserved, task), &cfg)
        .unwrap()
        .unwrap();
    assert_eq!(record.terms, contract);
    assert_eq!(record.delivered_output, None);
    assert_eq!(balance(&reserved, 1), BALANCE);
    assert!(balance(&reserved, 0) < BALANCE - BUDGET);

    let mut wrong_contract = contract.clone();
    wrong_contract.request[0] ^= 1;
    let payload = FundedServiceReservationV1 {
        task,
        contract: wrong_contract,
    }
    .encode()
    .unwrap();
    assert_eq!(
        block(&initial(), &cfg, 1, vec![signed(&cfg, 0, 1, 2, payload)]).unwrap_err(),
        "SERVICE_CONTRACT_BINDING"
    );
    let mut conflicted = contract.clone();
    conflicted.arbitrator = public(0);
    let payload = FundedServiceReservationV1 {
        task: conflicted.task_id(cfg.network, cfg.parameters, public(0), 1),
        contract: conflicted,
    }
    .encode()
    .unwrap();
    assert_eq!(
        block(&initial(), &cfg, 1, vec![signed(&cfg, 0, 1, 2, payload)]).unwrap_err(),
        "SERVICE_CONTRACT_BINDING"
    );
    let output = [40; 32];
    let pay = decision(
        &cfg,
        &contract,
        task,
        output,
        FundedServiceVerdictV1::PayProvider,
    );
    assert_eq!(
        block(
            &reserved,
            &cfg,
            2,
            vec![signed(&cfg, 2, 1, 5, pay.encode().unwrap())]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_ARBITRATOR"
    );
    let delivered = block(&reserved, &cfg, 2, vec![receipt(&cfg, task, output)])
        .unwrap()
        .state;
    let provider_before = balance(&delivered, 1);
    assert_eq!(
        block(
            &delivered,
            &cfg,
            3,
            vec![signed(&cfg, 3, 1, 5, pay.encode().unwrap())]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_ARBITRATOR"
    );
    for changed in [
        FundedServiceDecisionV1 {
            output: [41; 32],
            ..pay.clone()
        },
        FundedServiceDecisionV1 {
            contract_digest: [41; 32],
            ..pay.clone()
        },
    ] {
        assert_eq!(
            block(
                &delivered,
                &cfg,
                3,
                vec![signed(&cfg, 2, 1, 5, changed.encode().unwrap())]
            )
            .unwrap_err(),
            "SERVICE_CONTRACT_ARBITRATOR"
        );
    }
    let settled = block(
        &delivered,
        &cfg,
        3,
        vec![signed(&cfg, 2, 1, 5, pay.encode().unwrap())],
    )
    .unwrap()
    .state;
    assert_eq!(balance(&settled, 1), provider_before + BUDGET);
    assert_eq!(row(&settled, task)["remaining"], 0);
    assert_eq!(row(&settled, task)["status"], "settled");
    let final_record = read_contract(task, row(&settled, task), &cfg)
        .unwrap()
        .unwrap();
    assert_eq!(final_record.delivered_output, Some(output));
    assert_eq!(
        final_record.resolution.unwrap().kind,
        ServiceResolutionKindV1::ArbitratorPaid
    );
    let refund = FundedServiceDecisionV1 {
        verdict: FundedServiceVerdictV1::RefundPayer,
        ..pay
    };
    assert_eq!(
        block(
            &settled,
            &cfg,
            4,
            vec![signed(&cfg, 2, 2, 5, refund.encode().unwrap())]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_CLOSED"
    );
    let accept = signed(&cfg, 0, 2, 5, [task.as_slice(), output.as_slice()].concat());
    assert_eq!(
        block(&settled, &cfg, 4, vec![accept]).unwrap_err(),
        "SERVICE_CONTRACT_CLOSED"
    );
}

#[test]
fn delivery_cancellation_and_native_expiry_have_exact_ordering() {
    let cfg = configuration();
    let contract = contract();
    let (task, reserved) = reserve(&cfg, &contract);
    let cancellation = signed(&cfg, 0, 2, 3, task.to_vec());
    for height in [2, contract.delivery_deadline] {
        assert_eq!(
            block(&reserved, &cfg, height, vec![cancellation.clone()]).unwrap_err(),
            "SERVICE_CONTRACT_CANCELLATION"
        );
    }
    let output = [40; 32];
    assert!(block(
        &reserved,
        &cfg,
        contract.delivery_deadline,
        vec![receipt(&cfg, task, output)]
    )
    .is_ok());
    assert_eq!(
        block(
            &reserved,
            &cfg,
            contract.delivery_deadline + 1,
            vec![receipt(&cfg, task, output)]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_DELIVERY"
    );
    let before = balance(&reserved, 0);
    let fee =
        cfg.fees[3] + cancellation.len() as u64 * field(&cfg.params, "byte_fee_units").unwrap();
    let refunded = block(&reserved, &cfg, 6, vec![cancellation]).unwrap().state;
    assert_eq!(balance(&refunded, 0), before + BUDGET - fee);
    assert_eq!(balance(&refunded, 1), BALANCE);
    assert_eq!(row(&refunded, task)["status"], "refunded");
    assert_eq!(
        read_contract(task, row(&refunded, task), &cfg)
            .unwrap()
            .unwrap()
            .resolution
            .unwrap()
            .kind,
        ServiceResolutionKindV1::NonDeliveryRefund
    );

    let expired = block(&reserved, &cfg, contract.dispute_deadline, vec![])
        .unwrap()
        .state;
    assert_eq!(balance(&expired, 0), before + BUDGET);
    assert_eq!(balance(&expired, 1), BALANCE);
    assert_eq!(row(&expired, task)["status"], "expired");
    assert!(read_contract(task, row(&expired, task), &cfg)
        .unwrap()
        .unwrap()
        .resolution
        .is_none());
    let delivered = block(&reserved, &cfg, 2, vec![receipt(&cfg, task, output)])
        .unwrap()
        .state;
    let accept = signed(&cfg, 0, 2, 5, [task.as_slice(), output.as_slice()].concat());
    assert_eq!(
        block(&delivered, &cfg, contract.dispute_deadline, vec![accept]).unwrap_err(),
        "SERVICE_CONTRACT_CLOSED"
    );
}

#[test]
fn arbitration_refund_and_customer_acceptance_consume_the_same_native_escrow() {
    let cfg = configuration();
    let contract = contract();
    let (task, reserved) = reserve(&cfg, &contract);
    let no_delivery = decision(
        &cfg,
        &contract,
        task,
        [0; 32],
        FundedServiceVerdictV1::RefundPayer,
    );
    assert_eq!(
        block(
            &reserved,
            &cfg,
            5,
            vec![signed(&cfg, 2, 1, 5, no_delivery.encode().unwrap())]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_DELIVERY"
    );
    let refunded = block(
        &reserved,
        &cfg,
        6,
        vec![signed(&cfg, 2, 1, 5, no_delivery.encode().unwrap())],
    )
    .unwrap()
    .state;
    assert_eq!(balance(&refunded, 0), balance(&reserved, 0) + BUDGET);
    assert_eq!(balance(&refunded, 1), BALANCE);
    assert_eq!(row(&refunded, task)["status"], "refunded");
    assert_eq!(
        read_contract(task, row(&refunded, task), &cfg)
            .unwrap()
            .unwrap()
            .resolution
            .unwrap()
            .kind,
        ServiceResolutionKindV1::ArbitratorRefunded
    );

    let output = [40; 32];
    let delivered = block(&reserved, &cfg, 2, vec![receipt(&cfg, task, output)])
        .unwrap()
        .state;
    let refund = decision(
        &cfg,
        &contract,
        task,
        output,
        FundedServiceVerdictV1::RefundPayer,
    );
    let refunded = block(
        &delivered,
        &cfg,
        3,
        vec![signed(&cfg, 2, 1, 5, refund.encode().unwrap())],
    )
    .unwrap()
    .state;
    assert_eq!(balance(&refunded, 0), balance(&delivered, 0) + BUDGET);
    assert_eq!(balance(&refunded, 1), balance(&delivered, 1));
    let accept = signed(&cfg, 0, 2, 5, [task.as_slice(), output.as_slice()].concat());
    let accepted = block(&delivered, &cfg, 3, vec![accept.clone()])
        .unwrap()
        .state;
    assert_eq!(balance(&accepted, 1), balance(&delivered, 1) + BUDGET);
    assert_eq!(
        read_contract(task, row(&accepted, task), &cfg)
            .unwrap()
            .unwrap()
            .resolution
            .unwrap()
            .kind,
        ServiceResolutionKindV1::CustomerAccepted
    );
    assert_eq!(
        block(
            &delivered,
            &cfg,
            3,
            vec![accept, signed(&cfg, 2, 1, 5, refund.encode().unwrap())]
        )
        .unwrap_err(),
        "SERVICE_CONTRACT_CLOSED"
    );
    assert_eq!(row(&delivered, task)["remaining"], BUDGET);
    let mut forged = row(&accepted, task).clone();
    forged["provider"] = json!(hex::encode(public(3)));
    assert_eq!(
        read_contract(task, &forged, &cfg),
        Err("SERVICE_CONTRACT_RECORD")
    );
}
