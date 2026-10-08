use serde_json::json;
use trnm_mvcc_fee::{
    continuity_v1::{self, PROFILE},
    pon_executor::{self, Config, State},
};
use trnm_protocol::pon_wire::hash;

fn config() -> Config {
    Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap()
}
fn initial(cfg: &Config) -> State {
    let mut state = State::from([
        ("meta:issued".into(), json!(1_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode([1; 32])),
            json!({"balance":1_000_000,"nonce":17}),
        ),
    ]);
    state.extend(continuity_v1::bootstrap_state(cfg).unwrap());
    state
}

#[test]
fn new_profile_has_fresh_context_and_genesis_reserves_the_whole_queue() {
    let old = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v4",
    )
    .unwrap();
    let cfg = config();
    assert_ne!(old.network, cfg.network);
    assert_ne!(old.parameters, cfg.parameters);
    assert_eq!(old.params["consensus_revision"], 9);
    assert_eq!(cfg.params["consensus_revision"], 12);
    let state = initial(&cfg);
    let bound = continuity_v1::capacity(&state, 0, &cfg).unwrap();
    assert_eq!(bound.reward_queue_reserve, 20);
    assert_eq!(bound.required_keys, state.len() + 20);
    assert_eq!(continuity_v1::check_state(&state, 0, &cfg), Ok(()));
    let mut absent = state.clone();
    absent.remove(continuity_v1::MAINTENANCE_KEY);
    assert_eq!(
        continuity_v1::check_state(&absent, 0, &cfg),
        Err("CONTINUITY_MAINTENANCE")
    );
    // The old profile is not migrated or reinterpreted.
    assert_eq!(continuity_v1::check_state(&absent, 0, &old), Ok(()));
}

#[test]
fn all_future_credit_owners_and_archive_rows_are_reserved_once() {
    let cfg = config();
    let mut state = initial(&cfg);
    let owner = hex::encode([2; 32]);
    state.insert(
        "reward:component".into(),
        json!({"owner":owner,"amount":0,"maturity":21}),
    );
    state.insert(
        "task:component".into(),
        json!({"owner":owner,"remaining":100,"deadline":9}),
    );
    state.insert(
        "quota:component".into(),
        json!({"owner":hex::encode([3;32]),"remaining":1,"deadline":9}),
    );
    state.insert(
        "release:component".into(),
        json!({"owner":owner,"remaining":100,"deadline":9}),
    );
    state.insert("contribution:component".into(), json!({}));
    let count = continuity_v1::capacity(&state, 1, &cfg).unwrap();
    assert_eq!(count.credit_account_reserve, 2); // zero-amount reward still creates an account
    assert_eq!(count.archive_reserve, 1);
    assert_eq!(count.reward_queue_reserve, 19);
    assert_eq!(count.required_keys, state.len() + 22);
    state.insert(format!("account:{owner}"), json!({"balance":0,"nonce":23}));
    state.insert("evaluation-archive:component".into(), json!({}));
    let materialized = continuity_v1::capacity(&state, 1, &cfg).unwrap();
    assert_eq!(materialized.required_keys, count.required_keys);
    assert_eq!(materialized.credit_account_reserve, 1);
    assert_eq!(materialized.archive_reserve, 0);
}

#[test]
fn real_empty_execution_preserves_liability_bound_and_account_nonces() {
    let cfg = config();
    let mut state = initial(&cfg);
    for height in 1u64..=48 {
        // A different receiver creates a reservation before its account matures.
        let miner = hash(b"continuity-future-receiver", &[&height.to_le_bytes()]);
        let prior_bound = continuity_v1::capacity(&state, height - 1, &cfg).unwrap();
        let output = pon_executor::execute(&state, &[], height, miner, [7; 32], 2, &cfg).unwrap();
        let next_bound = continuity_v1::capacity(&output.state, height, &cfg).unwrap();
        assert_eq!(next_bound.required_keys, prior_bound.required_keys + 1);
        assert_eq!(
            output.state[&format!("account:{}", hex::encode([1; 32]))]["nonce"],
            17
        );
        state = output.state;
    }
    let prior = continuity_v1::capacity(&state, 48, &cfg).unwrap();
    let next = pon_executor::execute(&state, &[], 49, [1; 32], [7; 32], 1, &cfg).unwrap();
    assert_eq!(
        continuity_v1::capacity(&next.state, 49, &cfg)
            .unwrap()
            .required_keys,
        prior.required_keys
    );
}

#[test]
fn maturity_queue_gaps_duplicates_and_mutated_maintenance_reject() {
    let cfg = config();
    let state = initial(&cfg);
    let next = pon_executor::execute(&state, &[], 1, [1; 32], [7; 32], 1, &cfg)
        .unwrap()
        .state;
    let key = next
        .keys()
        .find(|key| key.starts_with("reward:"))
        .unwrap()
        .clone();
    let mut malformed = next.clone();
    malformed.get_mut(&key).unwrap()["maturity"] = json!(20);
    assert_eq!(
        continuity_v1::check_state(&malformed, 1, &cfg),
        Err("CONTINUITY_REWARD_QUEUE")
    );
    malformed = next.clone();
    malformed.insert("reward:duplicate".into(), next[&key].clone());
    assert_eq!(
        continuity_v1::check_state(&malformed, 1, &cfg),
        Err("CONTINUITY_REWARD_QUEUE")
    );
    malformed = next;
    malformed.get_mut(continuity_v1::MAINTENANCE_KEY).unwrap()["useful_output_credit"] = json!(1);
    assert_eq!(
        continuity_v1::check_state(&malformed, 1, &cfg),
        Err("CONTINUITY_MAINTENANCE")
    );
}

fn mature_queue_fixture(cfg: &Config, height: u64) -> State {
    let mut state = initial(cfg);
    for due in height + 1..=height + 20 {
        state.insert(
            format!(
                "reward:{}",
                hex::encode(hash(b"continuity-queue-fixture", &[&due.to_le_bytes()]))
            ),
            json!({"owner":hex::encode([1;32]),"amount":1000,"maturity":due}),
        );
    }
    state.insert("meta:issued".into(), json!(1_020_000));
    state
}
fn fill_potential(state: &mut State, height: u64, cfg: &Config) {
    let reserve = continuity_v1::capacity(state, height, cfg).unwrap();
    for index in 0..continuity_v1::MAX_KEYS - reserve.required_keys {
        state.insert(
            format!(
                "account:{}",
                hex::encode(hash(
                    b"continuity-capacity-fixture",
                    &[&(index as u64).to_le_bytes()]
                ))
            ),
            json!({"balance":0,"nonce":11}),
        );
    }
    assert_eq!(
        continuity_v1::capacity(state, height, cfg)
            .unwrap()
            .required_keys,
        continuity_v1::MAX_KEYS
    );
}

#[test]
fn native_deferred_funded_expiry_at_capacity_consumes_reserved_accounts() {
    // Current transaction-created expiry owners already have retained accounts.
    // Absent owners here deliberately seed a stronger schema robustness fixture;
    // this is actual M06 execution, not a claimed installed-genesis history.
    let cfg = config();
    let mut state = mature_queue_fixture(&cfg, 20);
    for index in 0u64..20 {
        let prefix = ["task", "quota", "release"][index as usize % 3];
        let owner = if prefix == "quota" { [3; 32] } else { [2; 32] };
        state.insert(format!("{prefix}:{}", hex::encode(hash(b"continuity-expiry-fixture", &[&index.to_le_bytes()]))),
            json!({"owner":hex::encode(owner),"remaining":11,"budget":11,"deadline":21,"status":"open"}));
    }
    state.insert("meta:issued".into(), json!(1_020_220));
    fill_potential(&mut state, 20, &cfg);
    assert_eq!(state.len(), continuity_v1::MAX_KEYS - 2);
    let first = pon_executor::execute(&state, &[], 21, [1; 32], [7; 32], 1, &cfg).unwrap();
    assert_eq!(first.receipts.len(), 16);
    assert_eq!(first.state.len(), continuity_v1::MAX_KEYS);
    assert_eq!(
        continuity_v1::capacity(&first.state, 21, &cfg)
            .unwrap()
            .credit_account_reserve,
        0
    );
    assert_eq!(
        first
            .state
            .iter()
            .filter(|(k, v)| (k.starts_with("task:")
                || k.starts_with("quota:")
                || k.starts_with("release:"))
                && v["remaining"] == 11)
            .count(),
        4
    );
    let next = pon_executor::execute(&first.state, &[], 22, [1; 32], [7; 32], 1, &cfg).unwrap();
    assert_eq!(next.receipts.len(), 4);
    assert_eq!(
        next.state[&format!("account:{}", hex::encode([2; 32]))]["balance"]
            .as_u64()
            .unwrap()
            + next.state[&format!("account:{}", hex::encode([3; 32]))]["balance"]
                .as_u64()
                .unwrap(),
        220
    );
    assert!(
        continuity_v1::capacity(&next.state, 22, &cfg)
            .unwrap()
            .required_keys
            < continuity_v1::MAX_KEYS
    );
}

#[test]
fn native_evaluation_closure_at_capacity_materializes_archive_then_cleans_it() {
    use trnm_mvcc_fee::public_evaluation;
    let cfg = config();
    let mut state = mature_queue_fixture(&cfg, 47);
    let cid = hash(
        b"contribution-v3",
        &[
            &[1; 32],
            &cfg.family,
            &[0; 32],
            &[8; 32],
            &[9; 32],
            &0u64.to_le_bytes(),
        ],
    );
    let candidate = format!("contribution:{}", hex::encode(cid));
    let archive = format!("evaluation-archive:{}", hex::encode(cid));
    let artifact = format!(
        "artifact:{}:0:{}",
        hex::encode([0; 32]),
        hex::encode([8; 32])
    );
    let mut row = json!({"owner":hex::encode([1;32]),"artifact":hex::encode([8;32]),
        "components_root":hex::encode([9;32]),"family":hex::encode(cfg.family),"parent":hex::encode([0;32]),
        "votes":{},"score":0,"status":"submitted","submitted_height":1,"submission_round":0});
    row["public_evaluation"] =
        public_evaluation::freeze(&cfg, cid, &row, 1, &std::collections::BTreeSet::new()).unwrap();
    state.insert(candidate.clone(), row);
    state.insert(artifact.clone(), json!(hex::encode(cid)));
    fill_potential(&mut state, 47, &cfg);
    assert_eq!(state.len(), continuity_v1::MAX_KEYS - 1);
    let closed = pon_executor::execute(&state, &[], 48, [1; 32], [7; 32], 1, &cfg).unwrap();
    assert_eq!(closed.state.len(), continuity_v1::MAX_KEYS);
    assert_eq!(
        closed.state[&archive]["public_evaluation"]["closed"]["status"],
        "aborted"
    );
    assert_eq!(
        closed.state[&archive]["public_evaluation"]["closed"]["closed_height"],
        48
    );
    assert_eq!(
        continuity_v1::capacity(&closed.state, 48, &cfg)
            .unwrap()
            .archive_reserve,
        0
    );
    // Separate retention-boundary fixture: advance the pending queue to height304
    // and remove the already-retired round0 candidate/artifact. No claim of 256
    // intervening mined blocks is made; the actual height305 transition is run.
    let mut retained = closed.state;
    retained.remove(&candidate);
    retained.remove(&artifact);
    for (offset, (_, reward)) in retained
        .iter_mut()
        .filter(|(k, _)| k.starts_with("reward:"))
        .enumerate()
    {
        reward["maturity"] = json!(305 + offset as u64);
    }
    let cleaned = pon_executor::execute(&retained, &[], 305, [1; 32], [7; 32], 1, &cfg).unwrap();
    assert!(!cleaned.state.contains_key(&archive));
    assert!(!cleaned.state.contains_key(&candidate));
    assert!(
        continuity_v1::capacity(&cleaned.state, 305, &cfg)
            .unwrap()
            .required_keys
            < continuity_v1::MAX_KEYS
    );
}
