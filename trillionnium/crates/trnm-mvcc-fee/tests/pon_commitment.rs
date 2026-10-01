//! Real signed PoN transfers and unchanged complete-builder commitment parity.
use serde_json::json;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    pon_commitment::{self, CacheLimits, CommitmentMethod, ExecutionRequest, FullRootReason},
    pon_executor::{self, Config, State},
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(who: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(
        b"commitment-test-key",
        &[&who.to_le_bytes()],
    )))
    .unwrap()
    .verifying_key()
    .to_bytes()
}
fn initial() -> State {
    State::from([
        ("meta:issued".into(), json!(100_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode(public(0))),
            json!({"balance":50_000_000,"nonce":0}),
        ),
        (
            format!("account:{}", hex::encode(public(1))),
            json!({"balance":50_000_000,"nonce":0}),
        ),
    ])
}
fn transfer(cfg: &Config, who: u64, nonce: u64, destination: u64) -> Vec<u8> {
    let mut payload = public(destination).to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: cfg.network,
        sender: public(who),
        nonce,
        expiry: 900,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"commitment-test-key",
        &[&who.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn request<'a>(raws: &'a [Vec<u8>], height: u64, workers: usize) -> ExecutionRequest<'a> {
    ExecutionRequest {
        transactions: raws,
        height,
        miner: public(3),
        parent_id: [height as u8; 32],
        workers,
    }
}
fn replay_changes(parent: &State, changes: &[trnm_protocol::pon_state::Change]) -> State {
    let mut result = parent.clone();
    let mut previous = None;
    for change in changes {
        assert!(previous.as_ref().is_none_or(|key| key < &change.key));
        previous = Some(change.key.clone());
        let key = String::from_utf8(change.key.clone()).unwrap();
        assert_eq!(
            result.get(&key).map(|v| serde_json::to_vec(v).unwrap()),
            change.before
        );
        if let Some(value) = &change.after {
            result.insert(key, serde_json::from_slice(value).unwrap());
        } else {
            result.remove(&key);
        }
    }
    result
}
#[test]
fn real_signed_prefixes_parallel_receipts_and_complete_state_are_identical() {
    let cfg = Config::installed().unwrap();
    for workers in [1, 2, 4, 8] {
        let parent = initial();
        let root = pon_executor::root(&parent).unwrap();
        let base =
            pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
        let snapshot = base.snapshot.as_ref().unwrap();
        let mut raws = Vec::new();
        for nonce in 1..=8 {
            raws.push(transfer(&cfg, 0, nonce, 100 + nonce));
            raws.push(transfer(&cfg, 1, nonce, 200 + nonce));
            for len in [raws.len() - 1, raws.len()] {
                let txs = &raws[..len];
                let full =
                    pon_executor::execute(&parent, txs, 1, public(3), [1; 32], workers, &cfg)
                        .unwrap();
                let result = pon_commitment::execute_checked(
                    &parent,
                    root,
                    Some(snapshot),
                    request(txs, 1, workers),
                    &cfg,
                    CacheLimits::default(),
                )
                .unwrap();
                assert_eq!(result.output.state, full.state);
                assert_eq!(result.output.receipts, full.receipts);
                assert_eq!(result.output.root, full.root);
                assert_eq!(
                    result.output.metrics.signature_verifications,
                    full.metrics.signature_verifications
                );
                assert_eq!(result.output.metrics.reexecuted, full.metrics.reexecuted);
                assert_eq!(
                    replay_changes(&parent, &result.commitment.changes),
                    full.state
                );
                assert_eq!(
                    result.commitment.snapshot.as_ref().unwrap().root(),
                    full.root
                );
                assert_eq!(
                    result.commitment.observation.method,
                    CommitmentMethod::CheckedApply
                );
                assert_eq!(snapshot.root(), root);
            }
        }
    }
}
#[test]
fn serial_new_accounts_and_reward_maturity_match_each_actual_successor() {
    let cfg = Config::installed().unwrap();
    let mut parent = initial();
    let root = pon_executor::root(&parent).unwrap();
    let mut base =
        pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
    for height in 1..=12 {
        let txs = vec![transfer(&cfg, 0, height, 100 + height)];
        let full = pon_executor::execute(
            &parent,
            &txs,
            height,
            public(3),
            [height as u8; 32],
            4,
            &cfg,
        )
        .unwrap();
        let result = pon_commitment::execute_checked(
            &parent,
            base.root,
            base.snapshot.as_ref(),
            request(&txs, height, 4),
            &cfg,
            CacheLimits::default(),
        )
        .unwrap();
        assert_eq!(result.output.state, full.state);
        assert_eq!(result.output.receipts, full.receipts);
        assert_eq!(
            replay_changes(&parent, &result.commitment.changes),
            full.state
        );
        parent = result.output.state;
        base = result.commitment;
    }
    assert_eq!(base.root, pon_executor::root(&parent).unwrap());
}
#[test]
fn late_invalid_signature_nonce_and_funds_do_not_mutate_parent_or_snapshot() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let root = pon_executor::root(&parent).unwrap();
    let base =
        pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
    let snapshot = base.snapshot.as_ref().unwrap();
    let first = transfer(&cfg, 0, 1, 100);
    let mut bad_signature = transfer(&cfg, 0, 2, 101);
    *bad_signature.last_mut().unwrap() ^= 1;
    let unfunded = transfer(&cfg, 999, 1, 102);
    for invalid in [bad_signature, transfer(&cfg, 0, 3, 101), unfunded] {
        let raws = vec![first.clone(), invalid];
        let expected =
            pon_executor::execute(&parent, &raws, 1, public(3), [1; 32], 4, &cfg).unwrap_err();
        assert_eq!(
            pon_commitment::execute_checked(
                &parent,
                root,
                Some(snapshot),
                request(&raws, 1, 4),
                &cfg,
                CacheLimits::default()
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(snapshot.root(), root);
        assert_eq!(parent, initial());
    }
}
#[test]
fn same_context_changed_actual_state_wrong_root_and_wrong_snapshot_are_rejected() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let root = pon_executor::root(&parent).unwrap();
    let base =
        pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
    let snapshot = base.snapshot.as_ref().unwrap();
    let mut changed = parent.clone();
    changed.insert("new-key".into(), json!(0));
    assert_eq!(
        pon_commitment::checked_snapshot(&changed, root, Some(snapshot), CacheLimits::default())
            .unwrap_err(),
        "COMMITMENT_ROOT"
    );
    assert_eq!(
        pon_commitment::execute_checked(
            &changed,
            root,
            Some(snapshot),
            request(&[], 1, 1),
            &cfg,
            CacheLimits::default()
        )
        .unwrap_err(),
        "COMMITMENT_PARENT"
    );
    assert_eq!(
        pon_commitment::execute_checked(
            &parent,
            [9; 32],
            Some(snapshot),
            request(&[], 1, 1),
            &cfg,
            CacheLimits::default()
        )
        .unwrap_err(),
        "COMMITMENT_ROOT"
    );
    assert_eq!(
        pon_commitment::execute_checked(
            &changed,
            root,
            None,
            request(&[], 1, 1),
            &cfg,
            CacheLimits::default()
        )
        .unwrap_err(),
        "COMMITMENT_ROOT"
    );
    assert_eq!(snapshot.root(), root);
    // Explicit discard/reseed can process another valid actual context.
    let changed_root = pon_executor::root(&changed).unwrap();
    assert!(
        pon_commitment::checked_snapshot(&changed, changed_root, None, CacheLimits::default())
            .is_ok()
    );
}
#[test]
fn disabled_cache_still_executes_real_full_rules_and_exact_deltas() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let root = pon_executor::root(&parent).unwrap();
    let txs = vec![transfer(&cfg, 0, 1, 100)];
    let limits = CacheLimits {
        max_keys: 0,
        ..CacheLimits::default()
    };
    let prepared = pon_commitment::checked_snapshot(&parent, root, None, limits).unwrap();
    assert!(prepared.snapshot.is_none());
    assert_eq!(
        prepared.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::KeyBudget)
    );
    let full = pon_executor::execute(&parent, &txs, 1, public(3), [1; 32], 1, &cfg).unwrap();
    let result =
        pon_commitment::execute_checked(&parent, root, None, request(&txs, 1, 1), &cfg, limits)
            .unwrap();
    assert_eq!(result.output.state, full.state);
    assert_eq!(result.output.root, full.root);
    assert_eq!(result.output.receipts, full.receipts);
    assert!(result.commitment.snapshot.is_none());
    assert_eq!(
        replay_changes(&parent, &result.commitment.changes),
        full.state
    );
}
#[test]
fn cache_key_and_workspace_limits_are_fallbacks_not_protocol_rejections() {
    let mut state = State::new();
    for i in 0..8192 {
        state.insert(format!("k{i:05}"), json!(0));
    }
    let root = pon_executor::root(&state).unwrap();
    let before =
        pon_commitment::checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    assert_eq!(before.snapshot.as_ref().unwrap().keys(), 8192);
    state.insert("extra".into(), json!(0));
    let root = pon_executor::root(&state).unwrap();
    let after = pon_commitment::checked_snapshot(
        &state,
        root,
        before.snapshot.as_ref(),
        CacheLimits::default(),
    )
    .unwrap();
    assert!(after.snapshot.is_none());
    assert_eq!(after.root, root);
    assert_eq!(
        after.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::KeyBudget)
    );
    let small = initial();
    let root = pon_executor::root(&small).unwrap();
    let result = pon_commitment::checked_snapshot(
        &small,
        root,
        None,
        CacheLimits {
            max_workspace_charge_bytes: 1,
            ..CacheLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::WorkspaceBudget)
    );
    assert!(result.snapshot.is_none());
}
#[test]
fn payload_budget_fallback_is_explicit_and_real_root_is_unchanged() {
    let mut state = State::new();
    for i in 0..2048 {
        state.insert(format!("{i:04x}"), json!("x".repeat(4090)));
    }
    let root = pon_executor::root(&state).unwrap();
    let exact =
        pon_commitment::checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    assert_eq!(exact.observation.actual_payload_bytes, 8 * 1024 * 1024);
    // Software capacity accounting can conservatively choose a workspace fallback
    // at the payload boundary; both policies must produce the complete root.
    assert_eq!(exact.root, root);
    state.insert("over".into(), json!(0));
    let root = pon_executor::root(&state).unwrap();
    let over =
        pon_commitment::checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    assert_eq!(
        over.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::PayloadBudget)
    );
    assert!(over.snapshot.is_none());
}
#[test]
fn protocol_bounds_canonical_errors_and_full_key_limit_remain_enforced() {
    for state in [
        State::from([("x".repeat(161), json!(0))]),
        State::from([("x".into(), json!("x".repeat(4095)))]),
        State::from([("x".into(), json!(1.5))]),
        State::from([("x".into(), json!("非ASCII"))]),
    ] {
        let original = pon_executor::root(&state).unwrap_err();
        assert_eq!(
            pon_commitment::checked_snapshot(&state, [0; 32], None, CacheLimits::default())
                .unwrap_err(),
            original
        );
    }
    let mut state = State::new();
    for i in 0..65536 {
        state.insert(format!("k{i:05}"), json!(0));
    }
    let root = pon_executor::root(&state).unwrap();
    let exact =
        pon_commitment::checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    assert_eq!(exact.root, root);
    assert!(exact.snapshot.is_none());
    state.insert("over".into(), json!(0));
    assert_eq!(pon_executor::root(&state).unwrap_err(), "LIMIT");
    assert_eq!(
        pon_commitment::checked_snapshot(&state, [0; 32], None, CacheLimits::default())
            .unwrap_err(),
        "LIMIT"
    );
}
#[test]
fn branching_stages_and_unknown_parent_reseed_do_not_advance_base() {
    let cfg = Config::installed().unwrap();
    let parent = initial();
    let root = pon_executor::root(&parent).unwrap();
    let base =
        pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
    let snapshot = base.snapshot.as_ref().unwrap();
    let a = vec![transfer(&cfg, 0, 1, 100)];
    let b = vec![transfer(&cfg, 0, 1, 101)];
    let one = pon_commitment::execute_checked(
        &parent,
        root,
        Some(snapshot),
        request(&a, 1, 1),
        &cfg,
        CacheLimits::default(),
    )
    .unwrap();
    let two = pon_commitment::execute_checked(
        &parent,
        root,
        Some(snapshot),
        request(&b, 1, 4),
        &cfg,
        CacheLimits::default(),
    )
    .unwrap();
    assert_ne!(one.output.root, two.output.root);
    assert_eq!(snapshot.root(), root);
    let unknown = pon_commitment::execute_checked(
        &parent,
        root,
        None,
        request(&b, 1, 4),
        &cfg,
        CacheLimits::default(),
    )
    .unwrap();
    assert_eq!(unknown.output.state, two.output.state);
    assert_eq!(unknown.output.receipts, two.output.receipts);
    assert_eq!(unknown.output.root, two.output.root);
    assert_eq!(
        one.commitment.snapshot.as_ref().unwrap().root(),
        one.output.root
    );
}

#[test]
fn full_actual_difference_checks_removals_empty_values_and_late_bad_value() {
    let original = State::from([("empty".into(), json!("")), ("deleted".into(), json!(1))]);
    let original_root = pon_executor::root(&original).unwrap();
    let base =
        pon_commitment::checked_snapshot(&original, original_root, None, CacheLimits::default())
            .unwrap();
    let snapshot = base.snapshot.as_ref().unwrap();
    let changed = State::from([("empty".into(), json!("")), ("new".into(), json!(null))]);
    let expected = pon_executor::root(&changed).unwrap();
    let staged = pon_commitment::checked_snapshot(
        &changed,
        expected,
        Some(snapshot),
        CacheLimits::default(),
    )
    .unwrap();
    assert_eq!(replay_changes(&original, &staged.changes), changed);
    assert_eq!(staged.changes.len(), 2);
    let mut late_bad = changed;
    late_bad.insert("zz-last".into(), json!("x".repeat(4095)));
    assert_eq!(
        pon_commitment::checked_snapshot(
            &late_bad,
            expected,
            Some(snapshot),
            CacheLimits::default()
        )
        .unwrap_err(),
        "LIMIT"
    );
    assert_eq!(snapshot.root(), original_root);
    let empty = State::new();
    let empty_root = pon_executor::root(&empty).unwrap();
    let deleted = pon_commitment::checked_snapshot(
        &empty,
        empty_root,
        Some(snapshot),
        CacheLimits::default(),
    )
    .unwrap();
    assert_eq!(deleted.snapshot.as_ref().unwrap().keys(), 0);
    assert_eq!(replay_changes(&original, &deleted.changes), empty);
}
