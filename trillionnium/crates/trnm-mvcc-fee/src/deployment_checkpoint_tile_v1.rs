//! Fresh operator deployment combining the existing explicit roster/funding spec
//! with a context-free material policy. No signature establishes real demand.
use crate::{
    checkpoint_tile_policy_v1::{CheckpointTilePolicySpecV1, PROFILE as TASK_PROFILE},
    deployment_actors::{canonical, decode, OperatorDeploymentSpec},
    pon_executor::{Config, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use trnm_protocol::pon_wire::{hash, Hash};
pub const PROFILE: &str = "native-operator-checkpoint-tile-dev-v1";
pub const SPEC_BYTES: usize = 32768;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorCheckpointTileSpecV1 {
    pub schema: String,
    pub profile: String,
    pub task_profile: String,
    /// Reused V1 roster/funding/material fields; its V4 profile describes the
    /// unchanged base lease codec. The outer effective profile is revision10.
    pub actors: OperatorDeploymentSpec,
    pub material_policy: CheckpointTilePolicySpecV1,
}
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
impl OperatorCheckpointTileSpecV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == "pon-native-operator-checkpoint-tile-spec-v1"
                && self.profile == PROFILE
                && self.task_profile == TASK_PROFILE,
            "CHECKPOINT_ACTOR_PROFILE",
        )?;
        self.actors.validate()?;
        self.material_policy.validate()?;
        require(
            self.actors.bootstrap.model == self.material_policy.model
                && self.actors.bootstrap.input == self.material_policy.input,
            "CHECKPOINT_ACTOR_MATERIAL",
        )?;
        require(
            canonical(self)?.len() <= SPEC_BYTES,
            "CHECKPOINT_ACTOR_LENGTH",
        )
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value: Self = decode(raw, SPEC_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical(self)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(
            b"native-operator-checkpoint-tile-spec-v1",
            &[&self.canonical()?],
        ))
    }
}
impl Config {
    pub fn installed_with_operator_checkpoint_tile(
        spec: &OperatorCheckpointTileSpecV1,
    ) -> Result<Self> {
        spec.validate()?;
        let actors = Self::installed_with_operator_actors(&spec.actors)?;
        let mut cfg = Self::installed_with_checkpoint_tile_policy(
            &spec.actors.evaluation_profile,
            &spec.actors.model_profile,
            &spec.material_policy,
        )?;
        for key in [
            "genesis_timestamp",
            "genesis_accounts",
            "genesis_funding_units_per_account",
            "genesis_issued_units",
        ] {
            cfg.params[key] = actors.params[key].clone();
        }
        cfg.params["actor_profile"] = json!(PROFILE);
        cfg.params["operator_actor_spec_hash"] = json!(hex::encode(spec.id()?));
        cfg.params["operator_actors_base_spec_hash"] =
            actors.params["operator_actor_spec_hash"].clone();
        let registry: Value = serde_json::from_str(include_str!(
            "../../../../config/pon/operator-checkpoint-tile-v1.json"
        ))
        .map_err(|_| "CONFIG")?;
        require(
            registry["profile"] == PROFILE
                && registry["task_profile"] == TASK_PROFILE
                && registry["production_activation"] == false
                && registry["public_network_ready"] == false
                && registry["hardness_accepted"] == false
                && registry["full_original_replay_on_open"] == true
                && registry["schema"] == "operator-checkpoint-tile-policy-v1"
                && registry["base_actor_roster_profile"] == crate::deployment_actors::PROFILE
                && registry["spec_max_bytes"] == SPEC_BYTES
                && registry["bootstrap_max_bytes"] == 8192
                && registry["known_fixture_key_count"] == 16
                && [
                    "genuine_demand_verified",
                    "full_forward_verified",
                    "marginal_contribution_accepted",
                ]
                .iter()
                .all(|key| registry[*key] == false),
            "CONFIG",
        )?;
        cfg.params["operator_actor_policy_hash"] = json!(hex::encode(hash(
            b"native-operator-checkpoint-tile-policy-v1",
            &[&canonical(&registry)?]
        )));
        let label = format!(
            "trnm-pon-operator-checkpoint-tile-dev-v1-{}-{}",
            spec.actors.deployment_id,
            hex::encode(spec.id()?)
        );
        cfg.params["chain_label"] = json!(label);
        cfg.network = hash(b"network", &[label.as_bytes()]);
        let wire: Value =
            serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))
                .map_err(|_| "CONFIG")?;
        let work: Value =
            serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))
                .map_err(|_| "CONFIG")?;
        cfg.parameters = hash(
            b"parameters",
            &[
                &canonical(&cfg.params)?,
                &canonical(&wire)?,
                &canonical(&work)?,
                &canonical(&cfg.model_registry)?,
            ],
        );
        cfg.evaluators = actors.evaluators;
        Ok(cfg)
    }
}
