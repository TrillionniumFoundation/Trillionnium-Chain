//! Same-block suffix execution against independent complete M06 executions.
use serde_json::json;
use std::sync::Mutex;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_commitment::{self, CacheLimits, CheckedExecutionParent, CheckedTransactionPrefix},
    pon_executor::{
        self, Config, ExecutionControl, ExecutionError, ExecutionProgress, PrefixContext, State,
    },
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(who: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(
        b"prefix-execution-test",
        &[&who.to_le_bytes()],
    )))
    .unwrap()
    .verifying_key()
    .to_bytes()
}
fn initial(cfg: &Config) -> State {
    let mut state = State::from([
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
    ]);
    if continuity_v1::enabled(cfg) {
        state.extend(continuity_v1::bootstrap_state(cfg).unwrap());
    }
    state
}
fn transfer(cfg: &Config, who: u64, nonce: u64, to: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(to).to_vec();
    payload.extend(amount.to_le_bytes());
    let mut tx = Envelope {
        network: cfg.network,
        sender: public(who),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"prefix-execution-test",
        &[&who.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn context(height: u64) -> PrefixContext {
    PrefixContext {
        height,
        miner: public(0),
        parent_id: [5; 32],
    }
}
fn builder<'a>(parent: &'a State, cfg: &Config, height: u64) -> CheckedTransactionPrefix<'a> {
    let progress = |_| Ok::<_, &'static str>(());
    CheckedExecutionParent::bind(
        parent,
        pon_executor::root(parent).unwrap(),
        None,
        CacheLimits::default(),
    )
    .unwrap()
    .into_prefix_with_control(context(height), cfg, &ExecutionControl::new(&progress, &()))
    .unwrap()
}
fn compare(
    parent: &State,
    cfg: &Config,
    height: u64,
    raws: &[Vec<u8>],
    actual: &pon_executor::Output,
) {
    let c = context(height);
    let full = pon_executor::execute(parent, raws, height, c.miner, c.parent_id, 1, cfg).unwrap();
    assert_eq!(actual.state, full.state);
    assert_eq!(actual.receipts, full.receipts);
    assert_eq!(actual.root, full.root);
}

#[test]
fn incremental_signed_prefixes_keep_one_prologue_complete_rewards_receipts_and_roots() {
    for cfg in [
        Config::installed().unwrap(),
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap(),
    ] {
        let mut parent = initial(&cfg);
        for height in 1..=20 {
            let c = context(height);
            parent =
                pon_executor::execute(&parent, &[], height, c.miner, [height as u8; 32], 1, &cfg)
                    .unwrap()
                    .state;
        }
        // A schema-valid funded expiry fixture is independent of Pool scheduling.
        parent.insert(format!("task:{}",hex::encode([8;32])),json!({"owner":hex::encode(public(1)),"remaining":1000,"budget":1000,"deadline":21,"status":"open"}));
        parent.insert(
            "meta:issued".into(),
            json!(parent["meta:issued"].as_u64().unwrap() + 1000),
        );
        let original = parent.clone();
        let raws = vec![
            transfer(&cfg, 0, 1, 2, 5000),
            transfer(&cfg, 2, 1, 1, 1000),
            transfer(&cfg, 1, 1, 0, 123),
        ];
        let mut prefix = builder(&parent, &cfg, 21);
        let mut signatures = 0;
        for end in 1..=raws.len() {
            let staged = prefix.execute(&raws[..end]).unwrap();
            compare(&parent, &cfg, 21, &raws[..end], &staged.output);
            let mut replayed = parent.clone();
            for change in &staged.commitment.changes {
                let key = String::from_utf8(change.key.clone()).unwrap();
                assert_eq!(
                    replayed.get(&key).map(|v| serde_json::to_vec(v).unwrap()),
                    change.before
                );
                if let Some(value) = &change.after {
                    replayed.insert(key, serde_json::from_slice(value).unwrap());
                } else {
                    replayed.remove(&key);
                }
            }
            assert_eq!(replayed, staged.output.state);
            signatures += staged.output.metrics.signature_verifications;
            assert_eq!(staged.output.metrics.committed_without_replay, 1);
            assert_eq!(staged.output.metrics.signature_verifications, 1);
            assert_eq!(staged.output.receipts.len(), end + 1); // exactly one mandatory expiry
            assert_eq!(prefix.len(), end);
            assert_eq!(
                staged
                    .output
                    .state
                    .keys()
                    .filter(|k| k.starts_with("reward:"))
                    .count(),
                20
            );
        }
        assert_eq!(signatures, raws.len());
        let repeated = prefix.execute(&raws).unwrap();
        compare(&parent, &cfg, 21, &raws, &repeated.output);
        assert_eq!(repeated.output.metrics.signature_verifications, 0);
        assert_eq!(repeated.output.metrics.committed_without_replay, 0);
        assert_eq!(parent, original);
    }
}

fn mandatory_partition_fixture(cfg: &Config) -> State {
    let mut parent = initial(cfg);
    parent.insert("meta:issued".into(), json!(100_001_507));
    parent.insert(
        "task:due".into(),
        json!({"owner":hex::encode(public(1)),"remaining":1000,"deadline":300,"status":"open"}),
    );
    parent.insert(
        "quota:future".into(),
        json!({"owner":hex::encode(public(2)),"remaining":7,"deadline":301,"status":"open"}),
    );
    parent.insert(
        "reward:mature".into(),
        json!({"owner":hex::encode(public(3)),"amount":500,"maturity":300}),
    );
    parent.insert(
        "release:retired".into(),
        json!({"owner":hex::encode(public(0)),"remaining":0,"deadline":10}),
    );
    parent.insert("contribution:retired".into(), json!({"parent":"other"}));
    parent.insert(
        "evaluation-archive:retired".into(),
        json!({"public_evaluation":{"closed":{"closed_height":1}}}),
    );
    parent.insert("artifact:old".into(), serde_json::Value::Null);
    parent.insert("retained:unknown".into(), serde_json::Value::Null);
    parent
}

#[test]
fn authenticated_mandatory_partition_executes_full_cleanup_refunds_and_maturity() {
    let cfg = Config::installed().unwrap();
    let parent = mandatory_partition_fixture(&cfg);
    let partition = parent
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let transactions = vec![transfer(&cfg, 0, 1, 1, 1)];
    let seen = Mutex::new(0usize);
    let completed = |before: &State, after: &State, receipts: &[Vec<u8>]| {
        assert_eq!(before, &parent);
        for removed in [
            "contribution:retired",
            "evaluation-archive:retired",
            "release:retired",
            "artifact:old",
            "reward:mature",
        ] {
            assert!(!after.contains_key(removed));
        }
        assert_eq!(after["retained:unknown"], serde_json::Value::Null);
        assert_eq!(after["task:due"]["remaining"], 0);
        assert_eq!(after["quota:future"]["remaining"], 7);
        assert_eq!(
            after[&format!("account:{}", hex::encode(public(1)))]["balance"],
            50_001_000
        );
        assert_eq!(
            after[&format!("account:{}", hex::encode(public(3)))],
            json!({"balance":500,"nonce":0})
        );
        assert_eq!(
            receipts,
            &[serde_json::to_vec(&json!({"expiry":"task:due"})).unwrap()]
        );
        *seen.lock().unwrap() += 1;
        Ok(())
    };
    let output = pon_executor::execute_with_authenticated_state_input(
        &parent,
        pon_executor::BlockExecution {
            transactions: &transactions,
            height: 300,
            miner: public(0),
            parent_id: [9; 32],
            workers: 1,
        },
        &cfg,
        &|_| Ok(()),
        &pon_executor::MandatoryStateInput {
            non_accounts: &partition,
            completed: &completed,
        },
        &|_| Ok::<_, &'static str>(()),
    )
    .unwrap();
    let reference =
        pon_executor::execute(&parent, &transactions, 300, public(0), [9; 32], 1, &cfg).unwrap();
    assert_eq!(output.state, reference.state);
    assert_eq!(output.root, reference.root);
    assert_eq!(output.receipts, reference.receipts);
    assert_eq!(seen.into_inner().unwrap(), 1);
    assert_eq!(parent, mandatory_partition_fixture(&cfg));
}

#[test]
fn authenticated_mandatory_refusal_prevents_transaction_preparation_and_missing_rows_refuse() {
    let cfg = Config::installed().unwrap();
    let parent = mandatory_partition_fixture(&cfg);
    let partition: State = parent
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let transactions = vec![transfer(&cfg, 0, 1, 1, 1)];
    let phases = Mutex::new(Vec::new());
    let result = pon_executor::execute_with_authenticated_state_input(
        &parent,
        pon_executor::BlockExecution {
            transactions: &transactions,
            height: 300,
            miner: public(0),
            parent_id: [9; 32],
            workers: 1,
        },
        &cfg,
        &|_| Ok(()),
        &pon_executor::MandatoryStateInput {
            non_accounts: &partition,
            completed: &|_, _, _| Err("EXPECTED_MANDATORY_REFUSAL"),
        },
        &|point| {
            phases.lock().unwrap().push(point);
            Ok::<_, &'static str>(())
        },
    );
    assert!(matches!(
        result,
        Err(ExecutionError::Relation("EXPECTED_MANDATORY_REFUSAL"))
    ));
    assert!(!phases
        .into_inner()
        .unwrap()
        .iter()
        .any(|point| matches!(point, ExecutionProgress::BeforePrepare { .. })));
    let mut omitted = partition;
    omitted.remove("retained:unknown");
    let result = pon_executor::execute_with_authenticated_state_input(
        &parent,
        pon_executor::BlockExecution {
            transactions: &transactions,
            height: 300,
            miner: public(0),
            parent_id: [9; 32],
            workers: 1,
        },
        &cfg,
        &|_| Ok(()),
        &pon_executor::MandatoryStateInput {
            non_accounts: &omitted,
            completed: &|_, _, _| panic!("incomplete input reached prologue"),
        },
        &|_| Ok::<_, &'static str>(()),
    );
    assert!(matches!(
        result,
        Err(ExecutionError::Relation("MANDATORY_STATE_PARTITION"))
    ));
    assert_eq!(parent, mandatory_partition_fixture(&cfg));
}

#[test]
fn invalid_partial_group_and_changed_prefix_leave_prior_nonce_fees_and_state() {
    let cfg = Config::installed().unwrap();
    let parent = initial(&cfg);
    let first = transfer(&cfg, 0, 1, 2, 5000);
    let second = transfer(&cfg, 0, 2, 3, 5000);
    let bad = transfer(&cfg, 1, 1, 4, u64::MAX);
    let mut prefix = builder(&parent, &cfg, 1);
    prefix.execute(std::slice::from_ref(&first)).unwrap();
    let rejected = vec![first.clone(), second.clone(), bad];
    assert_eq!(prefix.execute(&rejected).unwrap_err(), "FUNDS");
    assert_eq!(prefix.len(), 1);
    assert_eq!(
        prefix.execute(std::slice::from_ref(&second)).unwrap_err(),
        "PREFIX_BINDING"
    );
    let accepted = vec![first, second];
    let actual = prefix.execute(&accepted).unwrap();
    compare(&parent, &cfg, 1, &accepted, &actual.output);
    assert_eq!(actual.output.metrics.signature_verifications, 1);
    assert_eq!(prefix.len(), 2);
}

#[test]
fn every_suffix_cancellation_and_unwind_restores_the_last_complete_prefix() {
    let cfg = Config::installed().unwrap();
    let parent = initial(&cfg);
    let raws = vec![
        transfer(&cfg, 0, 1, 2, 5000),
        transfer(&cfg, 0, 2, 3, 5000),
        transfer(&cfg, 1, 1, 0, 123),
    ];
    for cut in [
        ExecutionProgress::BeforePrepare { index: 1 },
        ExecutionProgress::AfterPrepare { index: 1 },
        ExecutionProgress::BeforeApply { index: 1 },
        ExecutionProgress::AfterApply { index: 1 },
        ExecutionProgress::AfterApply { index: 2 },
        ExecutionProgress::BeforeReward,
        ExecutionProgress::BeforeCommitment,
        ExecutionProgress::AfterCommitment,
        ExecutionProgress::BeforeOutput,
    ] {
        let mut prefix = builder(&parent, &cfg, 1);
        prefix.execute(&raws[..1]).unwrap();
        let cancel = |point| {
            if point == cut {
                Err("caller-stop")
            } else {
                Ok(())
            }
        };
        assert!(matches!(
            prefix.execute_with_control(&raws, &ExecutionControl::new(&cancel, &())),
            Err(ExecutionError::Cancelled("caller-stop"))
        ));
        assert_eq!(prefix.len(), 1);
        let actual = prefix.execute(&raws).unwrap();
        compare(&parent, &cfg, 1, &raws, &actual.output);
        assert_eq!(actual.output.metrics.signature_verifications, 2);
    }
    let mut prefix = builder(&parent, &cfg, 1);
    prefix.execute(&raws[..1]).unwrap();
    let panic_after_apply = |point| -> Result<(), &'static str> {
        assert_ne!(
            point,
            ExecutionProgress::AfterApply { index: 2 },
            "owned scratch unwind"
        );
        Ok(())
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prefix.execute_with_control(&raws, &ExecutionControl::new(&panic_after_apply, &()))
    }));
    assert!(result.is_err());
    assert_eq!(prefix.len(), 1);
    compare(
        &parent,
        &cfg,
        1,
        &raws,
        &prefix.execute(&raws).unwrap().output,
    );
}

#[test]
fn actual_capacity_rejection_rolls_back_suffix_and_allows_existing_account_transfer() {
    let cfg =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    let mut parent = initial(&cfg);
    let bound = continuity_v1::capacity(&parent, 0, &cfg).unwrap();
    for index in 0..continuity_v1::MAX_KEYS - bound.required_keys - 1 {
        parent.insert(
            format!("account:{index:064x}"),
            json!({"balance":0,"nonce":11}),
        );
    }
    assert_eq!(
        continuity_v1::capacity(&parent, 0, &cfg)
            .unwrap()
            .required_keys,
        continuity_v1::MAX_KEYS - 1
    );
    let mut prefix = builder(&parent, &cfg, 1);
    let first = transfer(&cfg, 0, 1, 2, 5000);
    prefix.execute(std::slice::from_ref(&first)).unwrap();
    let too_many = vec![first.clone(), transfer(&cfg, 0, 2, 3, 5000)];
    let error = prefix.execute(&too_many).unwrap_err();
    assert_eq!(error, "STATE_CAPACITY");
    assert_eq!(prefix.len(), 1);
    let accepted = vec![first, transfer(&cfg, 0, 2, 1, 123)];
    compare(
        &parent,
        &cfg,
        1,
        &accepted,
        &prefix.execute(&accepted).unwrap().output,
    );
}

#[test]
fn changed_actual_parent_bytes_and_forged_root_never_construct_a_prefix() {
    let cfg = Config::installed().unwrap();
    let mut parent = initial(&cfg);
    let root = pon_executor::root(&parent).unwrap();
    parent
        .get_mut(&format!("account:{}", hex::encode(public(0))))
        .unwrap()["nonce"] = json!(1);
    assert!(matches!(
        CheckedExecutionParent::bind(&parent, root, None, CacheLimits::default()),
        Err("COMMITMENT_ROOT")
    ));
}

#[test]
fn warm_parent_and_full_root_fallback_keep_the_same_complete_prefix_outputs() {
    let cfg = Config::installed().unwrap();
    let parent = initial(&cfg);
    let root = pon_executor::root(&parent).unwrap();
    let base =
        pon_commitment::checked_snapshot(&parent, root, None, CacheLimits::default()).unwrap();
    let raws = [transfer(&cfg, 0, 1, 2, 5000), transfer(&cfg, 0, 2, 1, 123)];
    let progress = |_| Ok::<_, &'static str>(());
    for limits in [
        CacheLimits::default(),
        CacheLimits {
            max_keys: 0,
            max_payload_bytes: 0,
            max_workspace_charge_bytes: 0,
        },
    ] {
        let mut prefix =
            CheckedExecutionParent::bind(&parent, root, base.snapshot.as_ref(), limits)
                .unwrap()
                .into_prefix_with_control(context(1), &cfg, &ExecutionControl::new(&progress, &()))
                .unwrap();
        for end in 1..=raws.len() {
            let actual = prefix.execute(&raws[..end]).unwrap();
            compare(&parent, &cfg, 1, &raws[..end], &actual.output);
            assert_eq!(actual.output.metrics.signature_verifications, 1);
            if limits.max_keys == 0 {
                assert!(actual.commitment.snapshot.is_none());
            }
        }
    }
}
