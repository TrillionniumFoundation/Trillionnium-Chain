//! Bounded offline M06 bridge for independently generated continuity fixtures.
//! It supplies no expected state, oracle, mining, capacity or production acceptance.
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, State},
};
use trnm_protocol::pon_wire::Hash;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    evaluation_policy: String,
    state: State,
    first_height: u64,
    steps: u64,
    miner: String,
    parent: String,
}
fn hash(value: &str) -> Result<Hash, String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("HASH".into());
    }
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "HASH")?;
    Ok(out)
}
fn run() -> Result<(), String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(262_145)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 262_144 {
        return Err("INPUT_LIMIT".into());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if request.schema != "continuity-transition-request-v1"
        || !(1..=16).contains(&request.cases.len())
    {
        return Err("REQUEST".into());
    }
    let mut cases = Vec::new();
    for case in request.cases {
        if case.name.is_empty()
            || case.name.len() > 80
            || case.state.len() > 512
            || !(1..=4).contains(&case.steps)
            || !(1..=1000).contains(&case.first_height)
            || !matches!(
                case.evaluation_policy.as_str(),
                "legacy-first-two-v3" | "native-public-evaluation-dev-v1"
            )
        {
            return Err("CASE_LIMIT".into());
        }
        let cfg = Config::installed_with_profiles(&case.evaluation_policy, continuity_v1::PROFILE)
            .map_err(str::to_owned)?;
        let miner = hash(&case.miner)?;
        let parent = hash(&case.parent)?;
        let mut state = case.state;
        let mut rows = Vec::new();
        for height in case.first_height..case.first_height + case.steps {
            match pon_executor::execute(&state, &[], height, miner, parent, 2, &cfg) {
                Ok(output) => {
                    let cap = continuity_v1::capacity(&output.state, height, &cfg)
                        .map_err(str::to_owned)?;
                    rows.push(json!({"height":height,"status":"accepted","root":hex::encode(output.root),
                        "state":output.state,"receipts":output.receipts.iter().map(hex::encode).collect::<Vec<_>>(),
                        "capacity":{"actual_keys":cap.actual_keys,"credit_reserve":cap.credit_account_reserve,
                            "archive_reserve":cap.archive_reserve,"queue_reserve":cap.reward_queue_reserve,
                            "required_keys":cap.required_keys}}));
                    state = output.state;
                }
                Err(error) => {
                    rows.push(json!({"height":height,"status":"rejected","error":error,"unchanged_parent":state}));
                    break;
                }
            }
        }
        cases.push(json!({"name":case.name,"network":hex::encode(cfg.network),
            "parameters":hex::encode(cfg.parameters),"params":cfg.params,"rows":rows}));
    }
    println!(
        "{}",
        json!({"schema":"native-continuity-transition-observations-v1","cases":cases,
        "scope":"small seeded application fixtures; not signed-command reachability or full native chain",
        "production_activation":false,"independent_hardware_qualified":false,"work_hardness_accepted":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
