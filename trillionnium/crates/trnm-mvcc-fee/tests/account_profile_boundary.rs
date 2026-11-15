//! Real M06 execution at the explicit account-profile configuration boundary.
//! Public test keys and in-memory state confer no production or PQ qualification.
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::{
    self as exec, funded_service_v1, BlockExecution, Config, ExecutionError, State,
};
use trnm_protocol::pon_wire::{Envelope, Hash};

const BALANCE: u64 = 1_000_000;
const DESTINATION: Hash = [251; 32];
const MINER: Hash = [249; 32];

fn fixture() -> (Config, State, Vec<u8>, Hash) {
    let cfg = Config::installed().unwrap();
    let key = signing_key_from_hex(&hex::encode([1; 32])).unwrap();
    let sender = key.verifying_key().to_bytes();
    let state = State::from([
        ("meta:issued".into(), json!(BALANCE)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode(sender)),
            json!({"balance":BALANCE,"nonce":0}),
        ),
    ]);
    let mut payload = DESTINATION.to_vec();
    payload.extend(7_u64.to_le_bytes());
    let mut tx = Envelope {
        network: cfg.network,
        sender,
        nonce: 1,
        expiry: 100,
        fee_limit: BALANCE,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    (cfg, state, tx.encode().unwrap(), sender)
}

fn selectors() -> [Value; 8] {
    [
        Value::Null,
        json!(false),
        json!(true),
        json!(0),
        json!(""),
        json!([]),
        json!({}),
        json!("native-pq-qtx1-account-v1"),
    ]
}

#[test]
fn absent_selector_retains_real_classical_transfer_and_signature_refusal() {
    let (cfg, state, raw, sender) = fixture();
    assert!(!cfg.is_pq_account_profile());
    assert!(exec::validate_main_envelope(&raw, 1, &cfg).is_ok());
    let before = state.clone();
    let fee = cfg.fees[1] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    let out = exec::execute(
        &state,
        std::slice::from_ref(&raw),
        1,
        MINER,
        [248; 32],
        1,
        &cfg,
    )
    .unwrap();
    assert_eq!(out.metrics.signature_verifications, 1);
    assert_eq!(
        out.state[&format!("account:{}", hex::encode(sender))],
        json!({"balance":BALANCE - 7 - fee,"nonce":1})
    );
    assert_eq!(
        out.state[&format!("account:{}", hex::encode(DESTINATION))],
        json!({"balance":7,"nonce":0})
    );
    let mut corrupt = raw;
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        exec::execute(&state, &[corrupt], 1, MINER, [248; 32], 1, &cfg).unwrap_err(),
        "SIGNATURE"
    );
    assert_eq!(state, before);
}

#[test]
fn present_qtx1_selector_cannot_reach_classical_transfer_or_empty_block_effects() {
    let (original, state, raw, sender) = fixture();
    let before = state.clone();
    for selector in selectors() {
        let mut cfg = original.clone();
        cfg.params["account_authorization_profile"] = selector.clone();
        for rows in [vec![raw.clone()], vec![]] {
            let entered = AtomicUsize::new(0);
            let result = exec::execute_with_progress(
                &state,
                BlockExecution {
                    timestamp: None,
                    transactions: &rows,
                    height: 1,
                    miner: MINER,
                    parent_id: [248; 32],
                    workers: 4,
                },
                &cfg,
                &|_| {
                    entered.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), Infallible>(())
                },
            );
            if let Ok(output) = &result {
                eprintln!(
                    "unexpected classical effects: {}",
                    json!({"selector":selector,"transactions":rows.len(),
                        "sender":output.state[&format!("account:{}",hex::encode(sender))],
                        "destination":output.state.get(&format!("account:{}",hex::encode(DESTINATION))),
                        "signatures":output.metrics.signature_verifications})
                );
            }
            assert_eq!(
                result.err(),
                Some(ExecutionError::Relation("PQ_ACCOUNT_PROFILE_UNAVAILABLE")),
                "selector {selector}, transactions {}",
                rows.len()
            );
            assert_eq!(entered.load(Ordering::Relaxed), 0);
            assert_eq!(state, before);
        }
        assert!(cfg.is_pq_account_profile());
        assert_eq!(
            exec::validate_main_envelope(&raw, 1, &cfg).unwrap_err(),
            "PQ_ACCOUNT_NATIVE_API_REQUIRED"
        );
    }
}

#[test]
fn present_qtx1_selector_cannot_install_a_classical_service_profile() {
    for selector in selectors() {
        let mut cfg = Config::installed().unwrap();
        cfg.params["account_authorization_profile"] = selector.clone();
        let before = (cfg.network, cfg.parameters, cfg.params.clone());
        assert_eq!(
            funded_service_v1::install(&mut cfg),
            Err("SERVICE_CONTRACT_PQ_UNSUPPORTED"),
            "selector {selector}"
        );
        assert_eq!((cfg.network, cfg.parameters, cfg.params), before);
    }
}

#[test]
fn present_npq_selector_still_requires_the_independent_native_owner() {
    let (original, state, raw, _) = fixture();
    for selector in selectors() {
        let mut cfg = original.clone();
        cfg.params["native_pq_accounts_profile"] = selector;
        assert!(cfg.is_pq_account_profile());
        assert_eq!(
            exec::execute(
                &state,
                std::slice::from_ref(&raw),
                1,
                MINER,
                [248; 32],
                1,
                &cfg
            )
            .unwrap_err(),
            "PQ2_PROFILE_REQUIRED"
        );
    }
}
