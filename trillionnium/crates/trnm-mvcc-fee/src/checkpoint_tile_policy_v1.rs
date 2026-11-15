//! Context-free immutable material policy. It establishes no chain or hardness
//! authority; Node must replay the complete originals whenever it installs/opens.
use crate::{
    checkpoint_tile_material_v1::{self, CheckedCheckpointTileMaterialV1, PinnedTileContextV1},
    deployment_actors::{canonical, decode, digest},
    pon_executor::{Config, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::{QualifiedWorkTask, TaskPurpose},
};

pub const PROFILE: &str = "signed-checkpoint-tile-maintenance-dev-v1";
pub const POLICY_BYTES: usize = 32768;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTilePolicySpecV1 {
    pub schema: String,
    pub material_policy: String,
    pub checkpoint_sha256: String,
    pub checkpoint_bytes: u64,
    pub activation_sha256: String,
    pub a_sha256: String,
    pub b_sha256: String,
    pub model: String,
    pub input: String,
    pub matrix_task: String,
    pub maintenance_only: bool,
    pub useful_output_limit: u64,
    pub chain_authority: bool,
    pub hardness_accepted: bool,
    pub genuine_demand_verified: bool,
    pub full_forward_verified: bool,
    pub marginal_contribution_accepted: bool,
    pub public_network_ready: bool,
}
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
impl CheckpointTilePolicySpecV1 {
    pub fn from_checked(checked: &CheckedCheckpointTileMaterialV1) -> Result<Self> {
        let d = checked.descriptor();
        let spec = Self {
            schema: "checkpoint-tile-context-free-policy-v1".into(),
            material_policy: d.policy.clone(),
            checkpoint_sha256: d.checkpoint_sha256.clone(),
            checkpoint_bytes: d.checkpoint_bytes,
            activation_sha256: d.activation_sha256.clone(),
            a_sha256: d.a_sha256.clone(),
            b_sha256: d.b_sha256.clone(),
            model: d.model.clone(),
            input: d.input.clone(),
            matrix_task: d.matrix_task.clone(),
            maintenance_only: true,
            useful_output_limit: 0,
            chain_authority: false,
            hardness_accepted: false,
            genuine_demand_verified: false,
            full_forward_verified: false,
            marginal_contribution_accepted: false,
            public_network_ready: false,
        };
        spec.validate()?;
        Ok(spec)
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == "checkpoint-tile-context-free-policy-v1"
                && self.material_policy == hex::encode(checkpoint_tile_material_v1::policy_id()),
            "CHECKPOINT_POLICY",
        )?;
        require(
            (10..=checkpoint_tile_material_v1::MAX_CHECKPOINT_BYTES)
                .contains(&self.checkpoint_bytes),
            "CHECKPOINT_POLICY_SIZE",
        )?;
        for value in [
            &self.checkpoint_sha256,
            &self.activation_sha256,
            &self.a_sha256,
            &self.b_sha256,
            &self.model,
            &self.input,
            &self.matrix_task,
        ] {
            digest(value).map_err(|_| "CHECKPOINT_POLICY_ID")?;
        }
        require(
            self.maintenance_only
                && self.useful_output_limit == 0
                && !self.chain_authority
                && !self.hardness_accepted
                && !self.genuine_demand_verified
                && !self.full_forward_verified
                && !self.marginal_contribution_accepted
                && !self.public_network_ready,
            "CHECKPOINT_POLICY_ACCEPTANCE",
        )?;
        require(
            canonical(self)?.len() <= POLICY_BYTES,
            "CHECKPOINT_POLICY_LENGTH",
        )
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value: Self = decode(raw, POLICY_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical(self)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(
            b"checkpoint-tile-context-free-policy-v1",
            &[&self.canonical()?],
        ))
    }
    pub fn context(&self, cfg: &Config) -> Result<PinnedTileContextV1> {
        self.validate()?;
        Ok(PinnedTileContextV1 {
            network: cfg.network,
            parameters: cfg.parameters,
            checkpoint_sha256: digest(&self.checkpoint_sha256)?,
            checkpoint_bytes: self.checkpoint_bytes,
            activation_sha256: digest(&self.activation_sha256)?,
            model: digest(&self.model)?,
            input: digest(&self.input)?,
        })
    }
    pub fn check_manifest(&self, m: &QualifiedWorkTask) -> Result<()> {
        self.validate()?;
        require(
            m.purpose == TaskPurpose::Maintenance
                && m.useful_output_limit == 0
                && m.hardness_status == 0,
            "CHECKPOINT_TASK_PURPOSE",
        )?;
        require(
            m.model == digest(&self.model)?
                && m.input == digest(&self.input)?
                && m.matrix_task == digest(&self.matrix_task)?
                && m.layer == QualifiedWorkTask::layer_id(m.model)
                && m.recipe == QualifiedWorkTask::recipe_id(),
            "CHECKPOINT_TASK_MATERIAL",
        )
    }
    pub fn check_replay(&self, checked: &CheckedCheckpointTileMaterialV1) -> Result<()> {
        require(
            Self::from_checked(checked)? == *self,
            "CHECKPOINT_POLICY_REPLAY",
        )
    }
}
impl Config {
    /// Explicit revision10; the context-free policy precedes N/P derivation.
    /// Construction does not imply its original bytes have been replayed by Node.
    pub fn installed_with_checkpoint_tile_policy(
        evaluation: &str,
        model: &str,
        policy: &CheckpointTilePolicySpecV1,
    ) -> Result<Self> {
        policy.validate()?;
        let mut cfg = Self::installed_with_model_profiles(
            evaluation,
            trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE,
            model,
        )?;
        let registry: Value = serde_json::from_str(include_str!(
            "../../../../config/pon/checkpoint-tile-task-v1.json"
        ))
        .map_err(|_| "CONFIG")?;
        require(
            registry["profile"] == PROFILE
                && registry["consensus_revision"] == 10
                && registry["production_eligible"] == false
                && registry["hardness_accepted"] == false
                && registry["maintenance_only"] == true
                && registry["full_original_replay_on_open"] == true
                && registry["schema"] == "checkpoint-tile-task-registry-v1"
                && registry["useful_output_limit"] == 0
                && registry["standalone_renew_disabled"] == true
                && registry["atomic_overlap_window"] == true
                && registry["material_policy_bytes_max"] == POLICY_BYTES
                && registry["checkpoint_bytes_max"]
                    == checkpoint_tile_material_v1::MAX_CHECKPOINT_BYTES
                && registry["activation_bytes_max"]
                    == checkpoint_tile_material_v1::MAX_ACTIVATION_BYTES
                && registry["wire_commands_reused"] == json!([18, 20, 21, 22])
                && registry["source_record_semantics_changed"] == false
                && [
                    "genuine_demand_verified",
                    "full_forward_verified",
                    "marginal_contribution_accepted",
                    "public_network_ready",
                ]
                .iter()
                .all(|key| registry[*key] == false),
            "CONFIG",
        )?;
        cfg.params["consensus_revision"] = json!(10);
        cfg.params["work_task_profile"] = json!(PROFILE);
        cfg.params["checkpoint_tile_policy"] =
            serde_json::to_value(policy).map_err(|_| "CONFIG")?;
        cfg.params["checkpoint_tile_policy_hash"] = json!(hex::encode(policy.id()?));
        cfg.params["qualified_task_registry_hash"] = json!(hex::encode(hash(
            b"checkpoint-tile-task-registry-v1",
            &[&canonical(&registry)?]
        )));
        let label = format!(
            "trnm-pon-checkpoint-tile-maintenance-devnet-10-{evaluation}-{model}-{}",
            hex::encode(policy.id()?)
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
        Ok(cfg)
    }
    pub fn checkpoint_tile_policy(&self) -> Result<Option<CheckpointTilePolicySpecV1>> {
        if self.task_profile() != PROFILE {
            return Ok(None);
        }
        let spec: CheckpointTilePolicySpecV1 =
            serde_json::from_value(self.params["checkpoint_tile_policy"].clone())
                .map_err(|_| "CHECKPOINT_POLICY_REQUIRED")?;
        spec.validate()?;
        require(
            self.params["checkpoint_tile_policy_hash"] == hex::encode(spec.id()?),
            "CHECKPOINT_POLICY_ID",
        )?;
        Ok(Some(spec))
    }
}
pub(crate) fn check_manifest(cfg: &Config, m: &QualifiedWorkTask) -> Result<()> {
    if let Some(policy) = cfg.checkpoint_tile_policy()? {
        policy.check_manifest(m)?;
    }
    Ok(())
}
