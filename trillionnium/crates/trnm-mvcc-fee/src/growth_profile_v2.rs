//! Explicit native full-State growth reference. It preserves complete scans and
//! recovery fences; it does not qualify bounded witness validation or activation.
use crate::pon_executor::{canonical, root, Config, Result, State};
use serde::Serialize;
use serde_json::{json, Value};
use trnm_protocol::pon_wire::{account_archive_root_from_accounts, hash, Hash};

pub const PROFILE: &str = "consensus-maintenance-growth-reference-dev-v2";
pub const REVISION: u64 = 17;
pub const COMMITMENT_PROFILE: &str = "native-permanent-account-state-v2";
pub const STORAGE_SCHEMA_DOMAIN: &str = "native-growth-reference-branch-schema-v2";
pub const MAX_PERMANENT_ACCOUNTS: usize = 1_000_000;
pub const MAX_WORKING_KEYS: usize = 65_536;
pub const MAX_TOTAL_KEYS: usize = MAX_PERMANENT_ACCOUNTS + MAX_WORKING_KEYS;
pub const ENCODED_BYTES: usize = 196;

pub fn enabled(cfg: &Config) -> bool {
    cfg.task_profile() == PROFILE
}

fn installed_policy() -> Result<Value> {
    let policy: Value = serde_json::from_str(include_str!(
        "../../../../config/pon/growth-reference-v2.json"
    ))
    .map_err(|_| "CONFIG")?;
    if policy["schema"] != "pon-native-growth-reference-policy-v2"
        || policy["id"] != PROFILE
        || policy["consensus_revision"] != REVISION
        || policy["state_commitment_profile"] != COMMITMENT_PROFILE
        || policy["storage_schema_domain"] != STORAGE_SCHEMA_DOMAIN
        || policy["capacity"]["maximum_permanent_accounts"] != MAX_PERMANENT_ACCOUNTS
        || policy["capacity"]["maximum_working_keys"] != MAX_WORKING_KEYS
        || policy["capacity"]["maximum_total_state_keys"] != MAX_TOTAL_KEYS
        || policy["validation"] != "complete-state-reference-not-bounded-witness"
        || [
            "production_eligible",
            "default_selected",
            "bounded_witness_qualified",
            "source_preserving_migration_accepted",
            "hardness_accepted",
            "public_service_accepted",
        ]
        .iter()
        .any(|field| policy[*field] != false)
    {
        return Err("CONFIG");
    }
    Ok(policy)
}
fn policy_hash() -> Result<Hash> {
    Ok(hash(
        b"native-growth-reference-policy-v2",
        &[&canonical(&installed_policy()?)?],
    ))
}

pub(crate) fn configure(params: &mut Value, policy: &str) -> Result<()> {
    let policy_hash = policy_hash()?;
    crate::continuity_v1::configure(params, policy)?;
    params["consensus_revision"] = json!(REVISION);
    params["work_task_profile"] = json!(PROFILE);
    params["chain_label"] = json!(format!("trnm-pon-growth-reference-v2-17-{policy}"));
    params["state_commitment_profile"] = json!(COMMITMENT_PROFILE);
    params["growth_reference_policy_hash"] = json!(hex::encode(policy_hash));
    params["maximum_permanent_accounts"] = json!(MAX_PERMANENT_ACCOUNTS);
    params["maximum_working_keys"] = json!(MAX_WORKING_KEYS);
    params["maximum_total_state_keys"] = json!(MAX_TOTAL_KEYS);
    params["growth_validation"] = json!("complete-state-reference-not-bounded-witness");
    Ok(())
}

fn check_profile(cfg: &Config) -> Result<()> {
    if !enabled(cfg)
        || cfg.params["consensus_revision"] != REVISION
        || cfg.params["state_commitment_profile"] != COMMITMENT_PROFILE
        || cfg.params["growth_reference_policy_hash"] != hex::encode(policy_hash()?)
        || cfg.params["maximum_permanent_accounts"] != MAX_PERMANENT_ACCOUNTS
        || cfg.params["maximum_working_keys"] != MAX_WORKING_KEYS
        || cfg.params["maximum_total_state_keys"] != MAX_TOTAL_KEYS
        || cfg.params["growth_validation"] != "complete-state-reference-not-bounded-witness"
    {
        return Err("GROWTH_PROFILE");
    }
    Ok(())
}

/// GSC2 is a native root relation with a separate domain from the research V2
/// observation. Network and parameters are fixed before genesis construction;
/// genesis is subsequently bound by the header parent, avoiding a root cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Commitment {
    pub network: Hash,
    pub parameters: Hash,
    pub account_root: Hash,
    pub account_count: u64,
    pub account_balance: u64,
    pub maximum_permanent_accounts: u64,
    pub working_root: Hash,
    pub working_count: u64,
    pub maximum_working_keys: u64,
    pub escrow_balance: u64,
    pub reward_balance: u64,
    pub issued: u64,
}
impl Commitment {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCODED_BYTES);
        bytes.extend(b"GSC2");
        bytes.extend(self.network);
        bytes.extend(self.parameters);
        bytes.extend(self.account_root);
        for value in [
            self.account_count,
            self.account_balance,
            self.maximum_permanent_accounts,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(self.working_root);
        for value in [
            self.working_count,
            self.maximum_working_keys,
            self.escrow_balance,
            self.reward_balance,
            self.issued,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), ENCODED_BYTES);
        bytes
    }
    pub fn id(&self) -> Hash {
        hash(COMMITMENT_PROFILE.as_bytes(), &[&self.encode()])
    }
}

/// Checked from every actual row, including zero-balance account existence and
/// nonce. A serialized Commitment is an observation, never a checked parent.
pub fn commitment(state: &State, cfg: &Config) -> Result<Commitment> {
    check_profile(cfg)?;
    // Finish the canonical grammar pass before reporting dimension limits.
    for value in state.values() {
        canonical(value)?;
    }
    if state.len() > MAX_TOTAL_KEYS {
        return Err("GROWTH_CAPACITY");
    }
    let mut accounts = Vec::new();
    let mut working = State::new();
    let mut balance = 0u64;
    let mut escrow = 0u64;
    let mut rewards = 0u64;
    for (key, value) in state {
        if key.len() > 160 || canonical(value)?.len() > 4096 {
            return Err("LIMIT");
        }
        if let Some(owner) = key.strip_prefix("account:") {
            if owner.len() != 64
                || !owner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("GROWTH_ACCOUNT");
            }
            let object = value.as_object().ok_or("GROWTH_ACCOUNT")?;
            if object.len() != 2 {
                return Err("GROWTH_ACCOUNT");
            }
            let amount = value["balance"].as_u64().ok_or("GROWTH_ACCOUNT")?;
            let nonce = value["nonce"].as_u64().ok_or("GROWTH_ACCOUNT")?;
            let mut address = [0; 32];
            hex::decode_to_slice(owner, &mut address).map_err(|_| "GROWTH_ACCOUNT")?;
            balance = balance.checked_add(amount).ok_or("RANGE")?;
            accounts.push((address, amount, nonce));
            if accounts.len() > MAX_PERMANENT_ACCOUNTS {
                return Err("GROWTH_CAPACITY");
            }
        } else {
            if key.starts_with("task:") || key.starts_with("quota:") || key.starts_with("release:")
            {
                escrow = escrow
                    .checked_add(value["remaining"].as_u64().ok_or("STATE")?)
                    .ok_or("RANGE")?;
            } else if key.starts_with("reward:") {
                rewards = rewards
                    .checked_add(value["amount"].as_u64().ok_or("STATE")?)
                    .ok_or("RANGE")?;
            }
            working.insert(key.clone(), value.clone());
            if working.len() > MAX_WORKING_KEYS {
                return Err("GROWTH_CAPACITY");
            }
        }
    }
    let issued = working
        .get("meta:issued")
        .and_then(Value::as_u64)
        .ok_or("STATE")?;
    if balance
        .checked_add(escrow)
        .and_then(|sum| sum.checked_add(rewards))
        != Some(issued)
    {
        return Err("CONSERVATION");
    }
    Ok(Commitment {
        network: cfg.network,
        parameters: cfg.parameters,
        account_root: account_archive_root_from_accounts(accounts.iter().copied())
            .map_err(|_| "GROWTH_ACCOUNT")?,
        account_count: accounts.len() as u64,
        account_balance: balance,
        maximum_permanent_accounts: MAX_PERMANENT_ACCOUNTS as u64,
        working_root: root(&working)?,
        working_count: working.len() as u64,
        maximum_working_keys: MAX_WORKING_KEYS as u64,
        escrow_balance: escrow,
        reward_balance: rewards,
        issued,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap()
    }
    #[test]
    fn growth_reference_root_is_context_bound_and_conserved() {
        let cfg = config();
        let key = format!("account:{}", hex::encode([9; 32]));
        let state = State::from([
            (key.clone(), json!({"balance":7,"nonce":3})),
            ("meta:issued".into(), json!(7)),
        ]);
        let committed = commitment(&state, &cfg).unwrap();
        assert_eq!(committed.account_count, 1);
        assert_eq!(committed.working_count, 1);
        assert_eq!(committed.encode().len(), ENCODED_BYTES);
        let old = Config::installed_with_profiles(
            "native-public-evaluation-dev-v1",
            crate::continuity_v1::PROFILE,
        )
        .unwrap();
        assert_eq!(
            crate::pon_executor::root_for_config(&state, &old).unwrap(),
            root(&state).unwrap()
        );
        assert_ne!(committed.id(), root(&state).unwrap());
        let mut changed = state.clone();
        changed.get_mut(&key).unwrap()["nonce"] = json!(4);
        assert_ne!(commitment(&changed, &cfg).unwrap().id(), committed.id());
        changed.insert("meta:issued".into(), json!(8));
        assert_eq!(commitment(&changed, &cfg), Err("CONSERVATION"));
        let mut forged = cfg.clone();
        forged.params["maximum_permanent_accounts"] = json!(MAX_PERMANENT_ACCOUNTS + 1);
        assert_eq!(commitment(&state, &forged), Err("GROWTH_PROFILE"));
        let mut forged_policy = cfg.clone();
        forged_policy.params["growth_reference_policy_hash"] = json!(hex::encode([0; 32]));
        assert_eq!(commitment(&state, &forged_policy), Err("GROWTH_PROFILE"));
        let mut cross = cfg.clone();
        cross.network[0] ^= 1;
        assert_ne!(commitment(&state, &cross).unwrap().id(), committed.id());
    }
    #[test]
    fn growth_reference_keeps_zero_nonce_history_and_working_bound() {
        let cfg = config();
        let mut state = State::from([("meta:issued".into(), json!(0))]);
        let absent = commitment(&state, &cfg).unwrap();
        state.insert(
            format!("account:{}", hex::encode([1; 32])),
            json!({"balance":0,"nonce":7}),
        );
        let present = commitment(&state, &cfg).unwrap();
        assert_eq!(present.account_balance, 0);
        assert_eq!(present.account_count, 1);
        assert_ne!(present.id(), absent.id());
        for index in 0..MAX_WORKING_KEYS {
            state.insert(format!("working:{index}"), json!(0));
        }
        assert_eq!(commitment(&state, &cfg), Err("GROWTH_CAPACITY"));
        assert_eq!(root(&state), Err("LIMIT"));
    }
    #[test]
    fn growth_reference_codec_matches_independent_vector() {
        let value = Commitment {
            network: [1; 32],
            parameters: [2; 32],
            account_root: [3; 32],
            account_count: 4,
            account_balance: 6,
            maximum_permanent_accounts: 1_000_000,
            working_root: [4; 32],
            working_count: 3,
            maximum_working_keys: 65_536,
            escrow_balance: 7,
            reward_balance: 11,
            issued: 24,
        };
        assert_eq!(value.encode().len(), 196);
        assert_eq!(
            hex::encode(value.id()),
            "ba20a82c4d08b745d8606f8ed273d9743fd9c60bf1d848c19cf6dbe240dd7179"
        );
    }
    fn vector(value: &Value) -> Commitment {
        let digest = |field: &str| -> Hash {
            hex::decode(value[field].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let number = |field: &str| value[field].as_u64().unwrap();
        Commitment {
            network: digest("network"),
            parameters: digest("parameters"),
            account_root: digest("account_root"),
            account_count: number("account_count"),
            account_balance: number("account_balance"),
            maximum_permanent_accounts: number("maximum_permanent_accounts"),
            working_root: digest("working_root"),
            working_count: number("working_count"),
            maximum_working_keys: number("maximum_working_keys"),
            escrow_balance: number("escrow_balance"),
            reward_balance: number("reward_balance"),
            issued: number("issued"),
        }
    }
    #[test]
    fn growth_reference_independent_full_vectors_and_field_mutations() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../tests/vectors/pon/native-growth-reference-v2.json"
        ))
        .unwrap();
        for row in vectors["vectors"].as_array().unwrap() {
            let committed = vector(&row["fields"]);
            assert_eq!(hex::encode(committed.encode()), row["encoded_hex"]);
            assert_eq!(hex::encode(committed.id()), row["id"]);
        }
        for row in vectors["field_binding_mutations"].as_array().unwrap() {
            assert_eq!(hex::encode(vector(&row["mutated_fields"]).id()), row["id"]);
            assert_ne!(row["id"], vectors["vectors"][1]["id"]);
        }
        let semantic = &vectors["vectors"][1];
        let accounts = vectors["semantic_accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let owner: Hash = hex::decode(row["owner"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                (
                    owner,
                    row["balance"].as_u64().unwrap(),
                    row["nonce"].as_u64().unwrap(),
                )
            });
        assert_eq!(
            hex::encode(account_archive_root_from_accounts(accounts).unwrap()),
            semantic["fields"]["account_root"]
        );
        let working: State = serde_json::from_value(vectors["semantic_working"].clone()).unwrap();
        assert_eq!(
            hex::encode(root(&working).unwrap()),
            semantic["fields"]["working_root"]
        );
        assert_ne!(semantic["id"], vectors["wrong_domain_id"]);
        assert_ne!(semantic["id"], vectors["semantic_legacy_full_state_root"]);
    }
}
