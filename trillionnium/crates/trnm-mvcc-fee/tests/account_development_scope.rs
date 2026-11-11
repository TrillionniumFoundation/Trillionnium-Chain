//! Actual M06 effects under the retained development profile, with fail-closed
//! scope and profile selection. Public deterministic fixture keys have no value.
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::{
    self as exec, pq_accounts_v2 as pq, BlockExecution, CanonicalTransitionObserver, Config,
    ExecutionError, ExecutionProgress, State,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const BALANCE: u64 = 50_000_000;
const MATURITY_AMOUNT: u64 = 777;
const TRANSFER_AMOUNT: u64 = 1234;
const PARENT: Hash = [177; 32];
const SCOPE_ERROR: &str = "ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED";

fn public(index: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(
        b"account-development-scope-test-key",
        &[&index.to_le_bytes()],
    )))
    .unwrap()
    .verifying_key()
    .to_bytes()
}

fn account(index: u64) -> String {
    format!("account:{}", hex::encode(public(index)))
}

fn mature_reward() -> String {
    format!("reward:{}", hex::encode([178; 32]))
}

fn initial() -> State {
    State::from([
        ("meta:issued".into(), json!(2 * BALANCE + MATURITY_AMOUNT)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (account(0), json!({"balance":BALANCE,"nonce":0})),
        (account(1), json!({"balance":BALANCE,"nonce":0})),
        (
            mature_reward(),
            json!({"owner":hex::encode(public(1)),"amount":MATURITY_AMOUNT,"maturity":1}),
        ),
    ])
}

fn transfer(cfg: &Config) -> Vec<u8> {
    let mut payload = public(1).to_vec();
    payload.extend(TRANSFER_AMOUNT.to_le_bytes());
    let mut envelope = Envelope {
        network: cfg.network,
        sender: public(0),
        nonce: 1,
        expiry: 100,
        fee_limit: 10_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"account-development-scope-test-key",
        &[&0_u64.to_le_bytes()],
    )))
    .unwrap();
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}

fn block(transactions: &[Vec<u8>], workers: usize) -> BlockExecution<'_> {
    BlockExecution {
        timestamp: Some(1501),
        transactions,
        height: 1,
        miner: public(2),
        parent_id: PARENT,
        workers,
    }
}

#[derive(Default)]
struct Observer {
    mandatory: AtomicUsize,
    transactions: AtomicUsize,
}

impl CanonicalTransitionObserver for Observer {
    fn mandatory(&self, _: &State, _: &State, _: &[Vec<u8>]) -> exec::Result<()> {
        self.mandatory.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn transaction(
        &self,
        _: usize,
        _: &Envelope,
        _: &State,
        _: &State,
        _: u64,
        _: &[u8],
    ) -> exec::Result<()> {
        self.transactions.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn expected_state(parent: &State, amount: u64, fee: u64) -> State {
    let mut state = parent.clone();
    state.remove(&mature_reward());
    state.insert(
        account(0),
        json!({"balance":BALANCE - amount - fee,"nonce":u64::from(amount != 0)}),
    );
    state.insert(
        account(1),
        json!({"balance":BALANCE + MATURITY_AMOUNT + amount,"nonce":0}),
    );
    let reward = hash(b"reward", &[&PARENT, &1_u64.to_le_bytes(), &public(2)]);
    state.insert(
        format!("reward:{}", hex::encode(reward)),
        json!({"owner":hex::encode(public(2)),"amount":1000 + fee,"maturity":21}),
    );
    state.insert(
        "meta:issued".into(),
        json!(2 * BALANCE + MATURITY_AMOUNT + 1000),
    );
    state
}

#[test]
fn classical_development_keeps_signed_transfer_maturity_fee_subsidy_and_receipt_bytes() {
    let cfg = Config::installed().unwrap();
    cfg.check_account_profile().unwrap();
    let parent = initial();
    let before = parent.clone();
    let raw = transfer(&cfg);
    let envelope = exec::validate_main_envelope(&raw, 1, &cfg).unwrap();
    assert_eq!(envelope.encode().unwrap(), raw);
    let fee = cfg.fees[1] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    let expected = expected_state(&parent, TRANSFER_AMOUNT, fee);
    let receipt = serde_json::to_vec(
        &json!({"tx":hex::encode(envelope.id().unwrap()),"fee":fee,"status":"applied"}),
    )
    .unwrap();
    let transactions = [raw];
    for workers in [1, 2, 4, 8] {
        let observer = Observer::default();
        let output =
            exec::execute_observed(&parent, block(&transactions, workers), &cfg, &observer)
                .unwrap();
        assert_eq!(output.state, expected);
        assert_eq!(output.root, exec::root(&expected).unwrap());
        assert_eq!(output.receipts, vec![receipt.clone()]);
        assert_eq!(output.metrics.signature_verifications, 1);
        assert_eq!(observer.mandatory.load(Ordering::Relaxed), 1);
        assert_eq!(observer.transactions.load(Ordering::Relaxed), 1);
        assert_eq!(parent, before);
    }
    assert_eq!(
        exec::root_for_config(&parent, &cfg).unwrap(),
        exec::root(&parent).unwrap()
    );
}

#[test]
fn classical_development_empty_block_keeps_real_maturity_and_subsidy_effects() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let before = parent.clone();
    let observer = Observer::default();
    let output = exec::execute_observed(&parent, block(&[], 1), &cfg, &observer).unwrap();
    assert_eq!(output.state, expected_state(&parent, 0, 0));
    assert_eq!(output.root, exec::root(&output.state).unwrap());
    assert!(output.receipts.is_empty());
    assert_eq!(output.metrics.signature_verifications, 0);
    assert_eq!(observer.mandatory.load(Ordering::Relaxed), 1);
    assert_eq!(observer.transactions.load(Ordering::Relaxed), 0);
    assert_eq!(parent, before);
}

fn assert_refused_before_effects(
    cfg: &Config,
    parent: &State,
    raw: &[u8],
    expected_error: &'static str,
) {
    let before = parent.clone();
    let before_root = exec::root(parent).unwrap();
    assert_eq!(cfg.check_account_profile(), Err(expected_error));
    assert_eq!(exec::root_for_config(parent, cfg), Err(expected_error));
    assert_eq!(
        exec::validate_main_envelope(raw, 1, cfg).unwrap_err(),
        expected_error
    );
    let signed = [raw.to_vec()];
    for transactions in [&[][..], &signed[..]] {
        for workers in [1, 4] {
            let calls = AtomicUsize::new(0);
            let progress = |_: ExecutionProgress| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok::<(), Infallible>(())
            };
            let error =
                exec::execute_with_progress(parent, block(transactions, workers), cfg, &progress)
                    .unwrap_err();
            assert_eq!(error, ExecutionError::Relation(expected_error));
            // No BeforeStateClone/mandatory/reward/commitment/output callback,
            // including an empty block that normally has real ledger effects.
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            let observer = Observer::default();
            assert_eq!(
                exec::execute_observed(parent, block(transactions, workers), cfg, &observer)
                    .unwrap_err(),
                expected_error
            );
            assert_eq!(observer.mandatory.load(Ordering::Relaxed), 0);
            assert_eq!(observer.transactions.load(Ordering::Relaxed), 0);
            assert_eq!(parent, &before);
            assert_eq!(exec::root(parent).unwrap(), before_root);
        }
    }
}

#[test]
fn altered_missing_null_or_mistyped_development_scope_refuses_real_and_empty_blocks() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let raw = transfer(&cfg);
    for field in ["production_activation", "not_mainnet", "coin_atomic_unit"] {
        let mut missing = cfg.clone();
        missing.params.as_object_mut().unwrap().remove(field);
        assert_refused_before_effects(&missing, &parent, &raw, SCOPE_ERROR);
        for value in [
            Value::Null,
            json!(true),
            json!(false),
            json!(0),
            json!(1),
            json!("true"),
            json!("false"),
            json!("TRNM"),
            json!([]),
            json!({}),
        ] {
            if value == cfg.params[field] {
                continue;
            }
            let mut changed = cfg.clone();
            changed.params[field] = value;
            assert_refused_before_effects(&changed, &parent, &raw, SCOPE_ERROR);
        }
    }
    for params in [Value::Null, json!(false), json!([]), json!({})] {
        let mut changed = cfg.clone();
        changed.params = params;
        assert_refused_before_effects(&changed, &parent, &raw, SCOPE_ERROR);
    }
}

#[test]
fn partial_null_and_unknown_pq_selections_never_authorize_classical_effects() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let raw = transfer(&cfg);
    for key in [
        "account_authorization_profile",
        "native_pq_profile",
        "native_pq_accounts_profile",
        "native_pq_v2_anchor",
        "native_pq_v2_descriptor",
        "native_pq_v2_base_fees",
        "native_pq_task_contract",
        "native_pq_task_migration_profile",
        "native_pq_future_algorithm",
    ] {
        for value in [Value::Null, json!(false), json!("unknown-future-profile")] {
            let mut changed = cfg.clone();
            changed.params[key] = value;
            let error = if key == "native_pq_accounts_profile" {
                // The existing native selector still reaches its actual owner
                // check and refuses the missing private policy.
                "PQ2_PROFILE_REQUIRED"
            } else {
                "PQ_ACCOUNT_PROFILE_UNAVAILABLE"
            };
            assert_refused_before_effects(&changed, &parent, &raw, error);
        }
    }
}

#[test]
fn real_native_pq_genesis_and_owner_checks_survive_the_development_scope_guard() {
    let key = SigningKey::<MlDsa65>::from_seed(&[179; 32].into());
    let mut spki =
        include_bytes!("../../trnm-protocol/tests/fixtures/pq_transfer/public.der")[..22].to_vec();
    spki.extend(key.verifying_key().encode().as_slice());
    let account = trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let (cfg, parent, genesis) = pq::genesis(
        &[pq::GenesisAccount {
            spki,
            balance: 2 * BALANCE,
        }],
        1500,
    )
    .unwrap();
    cfg.check_account_profile().unwrap();
    let context = pq::context(&cfg).unwrap();
    assert_eq!(context.network, cfg.network);
    assert_eq!(context.parameters, cfg.parameters);
    assert_eq!(context.genesis, genesis);
    assert_eq!(
        exec::root_for_config(&parent, &cfg).unwrap(),
        exec::root(&parent).unwrap()
    );
    let before = parent.clone();
    let output = exec::execute_with_progress(
        &parent,
        BlockExecution {
            miner: account,
            ..block(&[], 1)
        },
        &cfg,
        &|_| Ok::<(), Infallible>(()),
    )
    .unwrap();
    assert_eq!(output.state["meta:issued"], json!(2 * BALANCE + 1000));
    assert_eq!(output.metrics.signature_verifications, 0);
    assert_eq!(parent, before);

    let raw = transfer(&Config::installed().unwrap());
    let mut missing = cfg.clone();
    missing
        .params
        .as_object_mut()
        .unwrap()
        .remove("native_pq_accounts_profile");
    assert_refused_before_effects(&missing, &parent, &raw, "PQ2_CONFIG_CHANGED");
    let mut changed = cfg.clone();
    changed.params["native_pq_accounts_profile"] = Value::Null;
    assert_refused_before_effects(&changed, &parent, &raw, "PQ2_CONFIG_CHANGED");
    for (field, value) in [
        ("production_activation", json!(true)),
        ("not_mainnet", json!(false)),
        ("coin_atomic_unit", json!("TRNM")),
    ] {
        let mut changed = cfg.clone();
        changed.params[field] = value;
        assert_refused_before_effects(&changed, &parent, &raw, SCOPE_ERROR);
    }
}
