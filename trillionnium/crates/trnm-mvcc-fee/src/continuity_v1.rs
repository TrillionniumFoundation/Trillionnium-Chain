//! Explicit revision12 continuity: reserve mandatory state liabilities and bind
//! an immutable, genesis-defined maintenance task. No work hardness, useful demand,
//! production authority or legacy/task substitution follows from availability.
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "consensus-maintenance-continuity-dev-v1";
pub const CONSENSUS_REVISION: u64 = 12;
pub const MAINTENANCE_KEY: &str = "consensus-maintenance-v1";
pub const MAX_KEYS: usize = 65_536;

pub fn enabled(cfg: &Config) -> bool {
    cfg.task_profile() == PROFILE
}

pub(crate) fn configure(params: &mut Value, policy: &str) -> Result<()> {
    let registry: Value =
        serde_json::from_str(include_str!("../../../../config/pon/continuity-v1.json"))
            .map_err(|_| "CONFIG")?;
    if registry["id"] != PROFILE
        || registry["consensus_revision"] != CONSENSUS_REVISION
        || registry["production_eligible"] != false
        || registry["hardness_accepted"] != false
        || registry["useful_model_work_accepted"] != false
        || registry["capacity"]["maximum_keys"] != MAX_KEYS
        || params["reward_maturity_blocks"] != 20
    {
        return Err("CONFIG");
    }
    params["consensus_revision"] = json!(CONSENSUS_REVISION);
    params["work_task_profile"] = json!(PROFILE);
    params["chain_label"] = json!(format!("trnm-pon-continuity-devnet-12-{policy}"));
    params["continuity_policy_hash"] = json!(hex::encode(hash(
        b"consensus-maintenance-continuity-policy-v1",
        &[&canonical(&registry)?],
    )));
    let lifecycle: Value = serde_json::from_str(include_str!(
        "../../../../config/pon/qualified-task-lifecycle-v4.json"
    ))
    .map_err(|_| "CONFIG")?;
    if lifecycle["id"] != "signed-task-lifecycle-dev-v4"
        || lifecycle["consensus_revision"] != 9
        || lifecycle["atomic_overlap_window"] != true
        || lifecycle["standalone_renew_disabled"] != true
    {
        return Err("CONFIG");
    }
    params["qualified_task_registry_hash"] = json!(hex::encode(hash(
        b"qualified-task-registry-v4",
        &[&canonical(&lifecycle)?],
    )));
    Ok(())
}

/// Exact public bytes selected by the new genesis; different from every old
/// bootstrap fixture. The work verifier still checks the original full relation.
pub fn maintenance_matrices() -> (Vec<u32>, Vec<u32>) {
    (
        (0..pon_work::CELLS)
            .map(|i| ((13 * i + 17) % 257) as u32)
            .collect(),
        (0..pon_work::CELLS)
            .map(|i| ((29 * i + 31) % 263) as u32)
            .collect(),
    )
}
pub fn maintenance_material() -> (Vec<u8>, Vec<u8>) {
    let (a, b) = maintenance_matrices();
    (
        a.iter().flat_map(|n| n.to_le_bytes()).collect(),
        b.iter().flat_map(|n| n.to_le_bytes()).collect(),
    )
}
pub fn maintenance_task() -> Result<Hash> {
    let (a, b) = maintenance_matrices();
    pon_work::task_id(&a, &b).map_err(|_| "CONTINUITY_MATERIAL")
}
pub fn maintenance_record(cfg: &Config) -> Result<Value> {
    if !enabled(cfg) {
        return Err("CONTINUITY_PROFILE");
    }
    let (model, input) = maintenance_material();
    Ok(json!({
        "schema":"genesis-consensus-maintenance-v1",
        "network":hex::encode(cfg.network),
        "parameters":hex::encode(cfg.parameters),
        "policy":cfg.params["continuity_policy_hash"],
        "matrix_task":hex::encode(maintenance_task()?),
        "model":hex::encode(hash(b"artifact", &[&model])),
        "input":hex::encode(hash(b"qualified-task-input-v1", &[&input])),
        "source":"genesis-public-deterministic-maintenance-v1",
        "purpose":"ledger-continuity-maintenance",
        "useful_output_credit":0,
        "hardness_accepted":false,
        "useful_model_work_accepted":false
    }))
}
pub fn bootstrap_state(cfg: &Config) -> Result<State> {
    Ok(State::from([(
        MAINTENANCE_KEY.into(),
        maintenance_record(cfg)?,
    )]))
}
pub fn check_maintenance(state: &State, task: Hash, cfg: &Config) -> Result<()> {
    if task != maintenance_task()? || state.get(MAINTENANCE_KEY) != Some(&maintenance_record(cfg)?)
    {
        return Err("CONTINUITY_MAINTENANCE");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacity {
    pub actual_keys: usize,
    pub credit_account_reserve: usize,
    pub archive_reserve: usize,
    pub reward_queue_reserve: usize,
    pub required_keys: usize,
}
fn number(value: &Value, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or("CONTINUITY_STATE")
}
fn reserve_owner(state: &State, value: &Value, recipients: &mut BTreeSet<String>) -> Result<()> {
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("CONTINUITY_STATE")?;
    if owner.len() != 64
        || !owner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("CONTINUITY_STATE");
    }
    let key = format!("account:{owner}");
    if !state.contains_key(&key) {
        recipients.insert(key);
    }
    Ok(())
}
/// For an accepted state at `height`, reserve every key a later mandatory step
/// may create. Existing-account maintenance mining keeps this potential constant
/// or decreases it: reward maturation consumes a recipient reservation, and each
/// missing queue slot reserves the reward before the maturity queue is full.
pub fn capacity(state: &State, height: u64, cfg: &Config) -> Result<Capacity> {
    if !enabled(cfg) {
        return Err("CONTINUITY_PROFILE");
    }
    let maturity = cfg.params["reward_maturity_blocks"]
        .as_u64()
        .ok_or("CONFIG")?;
    let mut recipients = BTreeSet::new();
    let mut reward_heights = BTreeSet::new();
    let mut archives = 0usize;
    for (key, value) in state {
        if key.starts_with("reward:") {
            let due = number(value, "maturity")?;
            if due <= height
                || due > height.checked_add(maturity).ok_or("RANGE")?
                || !reward_heights.insert(due)
            {
                return Err("CONTINUITY_REWARD_QUEUE");
            }
            number(value, "amount")?;
            reserve_owner(state, value, &mut recipients)?;
        } else if key.starts_with("task:")
            || key.starts_with("quota:")
            || key.starts_with("release:")
        {
            if number(value, "remaining")? > 0 {
                reserve_owner(state, value, &mut recipients)?;
            }
        } else if crate::public_evaluation::enabled(cfg) && key.starts_with("contribution:") {
            let candidate = key
                .strip_prefix("contribution:")
                .ok_or("CONTINUITY_STATE")?;
            if !state.contains_key(&format!("evaluation-archive:{candidate}")) {
                archives = archives.checked_add(1).ok_or("RANGE")?;
            }
        }
    }
    // A generated block leaves exactly one reward for each of the latest M
    // heights; no gaps or extra maturity rows can manufacture reserve headroom.
    let expected_rewards = height.min(maturity) as usize;
    if reward_heights.len() != expected_rewards {
        return Err("CONTINUITY_REWARD_QUEUE");
    }
    for offset in 0..expected_rewards {
        let due = height
            .checked_add(maturity)
            .and_then(|n| n.checked_sub(offset as u64))
            .ok_or("RANGE")?;
        if !reward_heights.contains(&due) {
            return Err("CONTINUITY_REWARD_QUEUE");
        }
    }
    let queue_reserve = (maturity as usize)
        .checked_sub(expected_rewards)
        .ok_or("CONTINUITY_REWARD_QUEUE")?;
    let required = state
        .len()
        .checked_add(recipients.len())
        .and_then(|n| n.checked_add(archives))
        .and_then(|n| n.checked_add(queue_reserve))
        .ok_or("RANGE")?;
    Ok(Capacity {
        actual_keys: state.len(),
        credit_account_reserve: recipients.len(),
        archive_reserve: archives,
        reward_queue_reserve: queue_reserve,
        required_keys: required,
    })
}
/// Old profiles are byte-for-byte unchanged. New state and restored snapshots
/// require both the immutable maintenance commitment and the capacity invariant.
pub fn check_state(state: &State, height: u64, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    check_maintenance(state, maintenance_task()?, cfg)?;
    if capacity(state, height, cfg)?.required_keys > MAX_KEYS {
        return Err("STATE_CAPACITY");
    }
    Ok(())
}
