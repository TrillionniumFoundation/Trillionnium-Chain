use super::*;
use crate::pon_executor::{self, BlockExecution, ExecutionControl};
#[path = "../../../../trnm-protocol/tests/support/native_pq_fixture.rs"]
mod fixture;

fn setup() -> (Config, State, Hash, fixture::Key, fixture::Key) {
    let a = fixture::Key::public_test_seed(81);
    let b = fixture::Key::public_test_seed(82);
    let (cfg, state, genesis) = genesis(
        &[
            GenesisAccount {
                spki: a.spki.clone(),
                balance: 1_000_000,
            },
            GenesisAccount {
                spki: b.spki.clone(),
                balance: 1_000_000,
            },
        ],
        1000,
    )
    .unwrap();
    (cfg, state, genesis, a, b)
}
fn execute(
    state: &State,
    cfg: &Config,
    genesis: Hash,
    miner: Hash,
    raws: &[Vec<u8>],
    timestamp: Option<u64>,
) -> Result<pon_executor::Output> {
    pon_executor::relation_only(pon_executor::execute_with_control(
        state,
        BlockExecution {
            timestamp,
            transactions: raws,
            height: 1,
            miner,
            parent_id: genesis,
            workers: 1,
        },
        cfg,
        &ExecutionControl::new(&pon_executor::no_cancellation, &()),
    ))
}
#[test]
fn actual_mldsa_enters_original_m06_nonce_fee_balance_reward_and_root() {
    let (cfg, state, g, a, b) = setup();
    let raw = a.transfer(
        context(&cfg).unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[],
        None,
    );
    let expected_fee =
        cfg.fees[1] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    let out = execute(&state, &cfg, g, b.id, &[raw], Some(1100)).unwrap();
    assert_eq!(out.metrics.signature_verifications, 1);
    assert_eq!(
        out.state[&format!("account:{}", hex::encode(a.id))],
        json!({"balance":1_000_000-expected_fee-17,"nonce":1})
    );
    assert_eq!(
        out.state[&format!("account:{}", hex::encode(b.id))]["balance"],
        1_000_017
    );
    assert_eq!(
        out.root,
        pon_executor::root_for_config(&out.state, &cfg).unwrap()
    );
    assert!(out.state.keys().any(|key| key.starts_with("reward:")));
    validate_state(&out.state, &cfg).unwrap();
}
#[test]
fn time_is_explicit_header_seconds_and_signature_binds_genesis_and_parameters() {
    let (cfg, state, g, a, b) = setup();
    let ctx = context(&cfg).unwrap();
    let raw = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], None);
    assert!(execute(
        &state,
        &cfg,
        g,
        b.id,
        std::slice::from_ref(&raw),
        Some(1100)
    )
    .is_ok());
    assert!(execute(
        &state,
        &cfg,
        g,
        b.id,
        std::slice::from_ref(&raw),
        Some(1101)
    )
    .is_err());
    assert!(execute(&state, &cfg, g, b.id, &[raw], None).is_err());
    for changed in [
        ChainContext {
            genesis: [3; 32],
            ..ctx
        },
        ChainContext {
            parameters: [4; 32],
            ..ctx
        },
    ] {
        let raw = a.transfer(changed, b.id, 1, 1100, 17, 100_000, &[], None);
        assert!(execute(&state, &cfg, g, b.id, &[raw], Some(1001)).is_err());
    }
}
#[test]
fn actual_authority_reads_refuse_tampered_retirement_key_or_account_after_prepare() {
    let (cfg, state, _, a, b) = setup();
    let raw = a.transfer(
        context(&cfg).unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[],
        None,
    );
    let checked = prepare_signature(&raw, 1001, &cfg).unwrap();
    for kind in 0..4 {
        let mut changed = state.clone();
        let id = hex::encode(a.id);
        match kind {
            0 => changed.get_mut(&format!("pq-auth-v1:{id}")).unwrap()["retired"] = json!(true),
            1 => changed.get_mut(&format!("pq-auth-v1:{id}")).unwrap()["generation"] = json!(2),
            2 => {
                changed.insert(format!("pq-key-v1:{id}"), json!(hex::encode(&b.spki)));
            }
            _ => {
                changed.remove(&format!("pq-auth-v1:{id}"));
            }
        }
        assert!(validate_state(&changed, &cfg).is_err());
        assert!(apply(&changed, &checked, &cfg, None).is_err());
    }
    let patch = apply(&state, &checked, &cfg, None).unwrap();
    assert!(patch
        .reads
        .contains_key(&format!("pq-auth-v1:{}", hex::encode(a.id))));
    assert!(patch
        .reads
        .contains_key(&format!("pq-key-v1:{}", hex::encode(a.id))));
}
#[test]
fn randomized_valid_signatures_share_statement_and_cannot_advance_nonce_twice() {
    let (cfg, state, g, a, b) = setup();
    let ctx = context(&cfg).unwrap();
    let first = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], Some([1; 32]));
    let second = a.transfer(ctx, b.id, 1, 1100, 17, 100_000, &[], Some([2; 32]));
    let one = prepare_signature(&first, 1001, &cfg).unwrap();
    let two = prepare_signature(&second, 1001, &cfg).unwrap();
    assert_ne!(one.wire_id(), two.wire_id());
    assert_eq!(one.statement_id(), two.statement_id());
    assert!(execute(&state, &cfg, g, b.id, &[first, second], Some(1001)).is_err());
}
#[test]
fn state_key_cap_and_whole_npq1_cost_cannot_be_hidden_by_inner_frame() {
    let (cfg, state, g, a, b) = setup();
    let raw = a.transfer(
        context(&cfg).unwrap(),
        b.id,
        1,
        1100,
        17,
        100_000,
        &[7; 512],
        None,
    );
    assert_eq!(raw.len(), wire::MAX_BYTES);
    let mut list = vec![raw.clone(); 85];
    assert!(validate_block(&state, &list, b.id, Some(1001), &cfg).is_ok());
    list.push(raw);
    assert_eq!(
        validate_block(&state, &list, b.id, Some(1001), &cfg),
        Err("PQ_TRANSACTION_LIMIT")
    );
    let raw = a.transfer(context(&cfg).unwrap(), b.id, 1, 1100, 17, 1, &[], None);
    assert!(execute(&state, &cfg, g, b.id, &[raw], Some(1001)).is_err());
    let mut changed = cfg.clone();
    changed.params["byte_fee_units"] = json!(0);
    assert!(context(&changed).is_err());
}

#[test]
fn explicit_unknown_or_empty_pq_selection_cannot_use_a_legacy_root() {
    let mut old = Config::installed().unwrap();
    let state = State::new();
    assert!(pon_executor::root_for_config(&state, &old).is_ok());
    for marker in [json!("future-unknown-pq-profile"), Value::Null] {
        old.params["native_pq_profile"] = marker;
        assert_eq!(
            pon_executor::root_for_config(&state, &old),
            Err("PQ_PROFILE_REQUIRED")
        );
    }
}
