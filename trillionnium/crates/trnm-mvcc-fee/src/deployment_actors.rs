//! Explicit operator-supplied development genesis actors. Key possession and
//! byte commitments are not independence, truthful demand or random-key proofs.
use crate::pon_executor::{Config, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex, verifying_key_from_hex};
use trnm_protocol::pon_wire::{hash, Hash};
pub const PROFILE: &str = "native-operator-actors-dev-v1";
pub const SPEC_BYTES: usize = 32768;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisAllocation {
    pub public_key: String,
    pub balance: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMaterialSpec {
    pub model: String,
    pub input: String,
    pub source_record: String,
    pub authorization_scope: String,
    pub availability_manifest: String,
    pub availability_root: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorDeploymentSpec {
    pub schema: String,
    pub profile: String,
    pub deployment_id: String,
    pub genesis_timestamp: u64,
    pub evaluation_profile: String,
    pub task_profile: String,
    pub model_profile: String,
    pub source: String,
    pub requester: String,
    pub evaluators: Vec<String>,
    pub allocations: Vec<GenesisAllocation>,
    pub bootstrap: BootstrapMaterialSpec,
    pub production_activation: bool,
    pub public_network_ready: bool,
    pub independent_governance_accepted: bool,
    pub hardness_accepted: bool,
    pub demand_truth_accepted: bool,
    pub objective_model_quality: bool,
}
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::to_value(value).map_err(|_| "ACTOR_ENCODING")?)
        .map_err(|_| "ACTOR_ENCODING")
}
pub fn decode<T: DeserializeOwned + Serialize>(raw: &[u8], limit: usize) -> Result<T> {
    require(raw.len() <= limit, "ACTOR_LENGTH")?;
    let body = raw.strip_suffix(b"\n").unwrap_or(raw);
    let value: T = serde_json::from_slice(body).map_err(|_| "ACTOR_ENCODING")?;
    require(canonical(&value)? == body, "ACTOR_CANONICAL")?;
    Ok(value)
}
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
pub fn digest(raw: &str) -> Result<Hash> {
    require(
        raw.len() == 64
            && raw
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)),
        "ACTOR_IDENTITY",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(raw, &mut out).map_err(|_| "ACTOR_IDENTITY")?;
    require(out != [0; 32], "ACTOR_IDENTITY")?;
    Ok(out)
}
/// Exactly the existing 16 public funded fixture identities are excluded here.
/// This does not detect arbitrary predictable seeds or undisclosed key sharing.
pub fn operator_key(raw: &str) -> Result<Hash> {
    let key = digest(raw)?;
    let public = verifying_key_from_hex(raw).map_err(|_| "ACTOR_KEY")?;
    require(!public.is_weak(), "ACTOR_WEAK_KEY")?;
    for i in 0u64..16 {
        let secret = hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()]);
        let fixture = signing_key_from_hex(&hex::encode(secret)).map_err(|_| "ACTOR_KEY")?;
        require(raw != public_key_hex(&fixture), "ACTOR_KNOWN_FIXTURE_KEY")?;
    }
    Ok(key)
}
impl OperatorDeploymentSpec {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let spec: Self = decode(raw, SPEC_BYTES)?;
        spec.validate()?;
        Ok(spec)
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical(self)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(
            b"native-operator-actors-spec-v1",
            &[&self.canonical()?],
        ))
    }
    pub fn issued(&self) -> Result<u64> {
        self.allocations.iter().try_fold(0u64, |sum, a| {
            sum.checked_add(a.balance).ok_or("ACTOR_FUNDING")
        })
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == "pon-native-operator-actors-spec-v1" && self.profile == PROFILE,
            "ACTOR_PROFILE",
        )?;
        require(
            self.evaluation_profile == crate::public_evaluation::PROFILE
                && self.task_profile == trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE,
            "ACTOR_PROFILE",
        )?;
        require(
            matches!(
                self.model_profile.as_str(),
                "linear-expert-dev-v1" | "smollm2-135m-cpu-dev-v1"
            ),
            "ACTOR_PROFILE",
        )?;
        require(
            self.genesis_timestamp > 0 && self.genesis_timestamp <= i64::MAX as u64,
            "ACTOR_TIME",
        )?;
        require(
            !self.production_activation
                && !self.public_network_ready
                && !self.independent_governance_accepted
                && !self.hardness_accepted
                && !self.demand_truth_accepted
                && !self.objective_model_quality,
            "ACTOR_ACCEPTANCE",
        )?;
        digest(&self.deployment_id)?;
        operator_key(&self.source)?;
        operator_key(&self.requester)?;
        require(self.source != self.requester, "ACTOR_ROLE")?;
        require(
            (3..=16).contains(&self.evaluators.len()) && (1..=32).contains(&self.allocations.len()),
            "ACTOR_LIMIT",
        )?;
        let mut roles = BTreeSet::from([self.source.clone(), self.requester.clone()]);
        let mut previous = None;
        for key in &self.evaluators {
            operator_key(key)?;
            require(
                previous.is_none_or(|p: &String| p < key) && roles.insert(key.clone()),
                "ACTOR_ROSTER",
            )?;
            previous = Some(key);
        }
        let mut funded = BTreeSet::new();
        let mut previous = None;
        for allocation in &self.allocations {
            operator_key(&allocation.public_key)?;
            require(
                allocation.balance > 0
                    && previous.is_none_or(|p: &String| p < &allocation.public_key)
                    && funded.insert(allocation.public_key.clone()),
                "ACTOR_FUNDING",
            )?;
            previous = Some(&allocation.public_key);
        }
        require(roles.is_subset(&funded), "ACTOR_FUNDING")?;
        self.issued()?;
        for value in [
            &self.bootstrap.model,
            &self.bootstrap.input,
            &self.bootstrap.source_record,
            &self.bootstrap.authorization_scope,
            &self.bootstrap.availability_manifest,
            &self.bootstrap.availability_root,
        ] {
            digest(value)?;
        }
        require(canonical(self)?.len() <= SPEC_BYTES, "ACTOR_LENGTH")
    }
}
impl Config {
    /// No existing Config constructor changes. The public actor descriptor is
    /// committed BEFORE network/parameter derivation; no received Boolean grants authority.
    pub fn installed_with_operator_actors(spec: &OperatorDeploymentSpec) -> Result<Self> {
        spec.validate()?;
        let mut cfg = Self::installed_with_model_profiles(
            &spec.evaluation_profile,
            &spec.task_profile,
            &spec.model_profile,
        )?;
        let id = spec.id()?;
        cfg.params["actor_profile"] = json!(PROFILE);
        cfg.params["operator_actor_spec_hash"] = json!(hex::encode(id));
        cfg.params["genesis_timestamp"] = json!(spec.genesis_timestamp);
        cfg.params["genesis_accounts"] = json!(spec.allocations.len());
        cfg.params["genesis_funding_units_per_account"] = json!(0);
        cfg.params["genesis_issued_units"] = json!(spec.issued()?);
        let label = format!(
            "trnm-pon-operator-actors-dev-v1-{}-{}",
            spec.deployment_id,
            hex::encode(id)
        );
        cfg.params["chain_label"] = json!(label);
        cfg.network = hash(b"network", &[label.as_bytes()]);
        let wire: Value =
            serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))
                .map_err(|_| "CONFIG")?;
        let work: Value =
            serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))
                .map_err(|_| "CONFIG")?;
        let policy: Value = serde_json::from_str(include_str!(
            "../../../../config/pon/operator-actors-dev-v1.json"
        ))
        .map_err(|_| "CONFIG")?;
        require(
            policy["profile"] == PROFILE
                && policy["production_activation"] == false
                && policy["independent_governance_accepted"] == false
                && policy["public_network_ready"] == false
                && policy["hardness_accepted"] == false
                && policy["demand_truth_accepted"] == false
                && policy["objective_model_quality"] == false
                && policy["spec_max_bytes"] == SPEC_BYTES
                && policy["bootstrap_max_bytes"] == 8192
                && policy["allocations_max"] == 32
                && policy["evaluators_min"] == 3
                && policy["evaluators_max"] == 16
                && policy["known_fixture_key_count"] == 16
                && policy["task_profile"] == spec.task_profile,
            "CONFIG",
        )?;
        cfg.params["operator_actor_policy_hash"] = json!(hex::encode(hash(
            b"native-operator-actors-policy-v1",
            &[&canonical(&policy)?]
        )));
        cfg.parameters = hash(
            b"parameters",
            &[
                &canonical(&cfg.params)?,
                &canonical(&wire)?,
                &canonical(&work)?,
                &canonical(&cfg.model_registry)?,
            ],
        );
        cfg.evaluators = spec.evaluators.iter().cloned().collect();
        Ok(cfg)
    }
}
