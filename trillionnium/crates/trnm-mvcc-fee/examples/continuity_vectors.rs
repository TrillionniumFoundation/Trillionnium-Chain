//! Small actual native transition vectors for the independently coded Python
//! continuity oracle. No chain, mining, performance or hardness attestation.
use serde_json::json;
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, State},
};

fn main() {
    let cfg =
        Config::installed_with_profiles("legacy-first-two-v3", continuity_v1::PROFILE).unwrap();
    let mut state = State::from([
        ("meta:issued".into(), json!(1_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode([1; 32])),
            json!({"balance":1_000_000,"nonce":17}),
        ),
    ]);
    state.extend(continuity_v1::bootstrap_state(&cfg).unwrap());
    let initial = state.clone();
    let mut steps = Vec::new();
    for height in 1..=24u64 {
        let miner = [height as u8 + 1; 32];
        let output = pon_executor::execute(&state, &[], height, miner, [7; 32], 2, &cfg).unwrap();
        let bound = continuity_v1::capacity(&output.state, height, &cfg).unwrap();
        steps.push(
            json!({"height":height,"miner":hex::encode(miner),"root":hex::encode(output.root),
            "actual_keys":bound.actual_keys,"credit_reserve":bound.credit_account_reserve,
            "archive_reserve":bound.archive_reserve,"queue_reserve":bound.reward_queue_reserve,
            "required_keys":bound.required_keys}),
        );
        state = output.state;
    }
    println!(
        "{}",
        json!({"schema":"native-continuity-application-vectors-v1",
        "scope":"actual native application transitions; no full chain, mining or hardness acceptance",
        "network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),
        "params":cfg.params,"initial":initial,"steps":steps,"final":state})
    );
}
