//! Native revision-3 application transitions. No work/fork/Hepta authority is implied.
//! Parallel workers speculate against one immutable snapshot; exact key and prefix
//! reads are validated in canonical order. Conflict or speculative rejection is
//! re-executed ONCE against that order's current state, never an unbounded retry loop.
use crate::checkpoint_tile_policy_v1::PROFILE as CHECKPOINT_TASK_PROFILE;
use crate::continuity_v1::{self, PROFILE as CONTINUITY_TASK_PROFILE};
use crate::public_evaluation;
use crate::qualified_task_lifecycle;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::qualified_work_task::{verify_development_statement, AdmissionContext};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_protocol::pon_wire::{hash, state_root_from_entries, Envelope, Hash, StateRootInputError};
use trnm_protocol::qualified_work_task::lifecycle_v2::PROFILE as LIFECYCLE_TASK_PROFILE;
use trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE as ATOMIC_TASK_PROFILE;
use trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE as OVERLAP_TASK_PROFILE;
use trnm_protocol::qualified_work_task::{SignedQualifiedWorkTask, TaskPurpose};

pub const SIGNED_TASK_PROFILE: &str = "signed-task-dev-v1";
pub const LEGACY_TASK_PROFILE: &str = "legacy-task-v1";
pub const QUALIFIED_DEMANDS: u64 = 16;

pub type State = BTreeMap<String, Value>;
pub type Result<T> = std::result::Result<T, &'static str>;
/// Optional computation-input gate for semantic account point accesses. The
/// callback itself conveys no proof, signature, parent or admission authority.
/// Aggregate balance scans and complete state commitments still use full State.
pub type AccountPointAccess<'a> = dyn Fn(&str) -> Result<()> + Sync + 'a;
/// Borrowed research check of the actual complete mandatory transition.
pub type MandatoryStateCheck<'a> = dyn Fn(&State, &State, &[Vec<u8>]) -> Result<()> + Sync + 'a;
/// Research-only input for the complete mandatory non-account partition. The
/// caller must authenticate these rows before entry. M06 additionally checks the
/// exact complete partition against its full parent reference, then executes the
/// actual mandatory relation using these supplied rows. A rejecting completion
/// check prevents any transaction or output from following that prologue.
pub struct MandatoryStateInput<'a> {
    pub non_accounts: &'a State,
    pub completed: &'a MandatoryStateCheck<'a>,
}
/// Complete monetary namespaces consumed by the explicit range-witness path.
/// The semantic set is shared with its range producer/verifier. Future and
/// zero-valued records are included; a due-only list is never sufficient.
pub const MONETARY_OBLIGATION_PREFIXES: [&str; 4] = ["quota:", "release:", "reward:", "task:"];
pub fn is_monetary_obligation(key: &str) -> bool {
    MONETARY_OBLIGATION_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}
/// Untrusted computation input; M06 checks its exact projection against the
/// complete parent before using these supplied rows for monetary discovery.
/// The Node research owner additionally verifies its authenticated range proof.
/// Other cleanup rules and the final complete successor remain unchanged.
pub struct MonetaryObligationInput<'a> {
    pub rows: &'a State,
}
#[derive(Default)]
struct StateInputs<'a> {
    accounts: Option<&'a AccountPointAccess<'a>>,
    mandatory: Option<&'a MandatoryStateInput<'a>>,
    monetary: Option<&'a MonetaryObligationInput<'a>>,
}
/// Caller-local observation only; no ledger byte or execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProgress {
    BeforeParentBinding,
    BeforeStateClone,
    AfterMandatory,
    BeforePrepare { index: usize },
    AfterPrepare { index: usize },
    BeforeApply { index: usize },
    AfterApply { index: usize },
    BeforeReward,
    BeforeCommitment,
    AfterCommitment,
    BeforeOutput,
    BeforePersistence,
    PersistenceDelta { index: usize },
    BeforeDurableCommit,
}
/// An abandoned preview is separate from a canonical application rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError<E> {
    Relation(&'static str),
    Cancelled(E),
}
impl<E> From<&'static str> for ExecutionError<E> {
    fn from(error: &'static str) -> Self {
        Self::Relation(error)
    }
}
pub type ControlledResult<T, E> = std::result::Result<T, ExecutionError<E>>;
/// Request-local accounting only. A guard is created on the actual worker and
/// dropped on that same worker on success, rejection, cancellation or unwind.
pub trait ExecutionWorkerInterval {}
pub trait ExecutionWorkerAccounting: Sync {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>>;
    fn worker_spawn_succeeded(&self);
    #[cfg(test)]
    fn test_spawn_allowed(&self, _index: usize) -> bool {
        true
    }
}
impl ExecutionWorkerAccounting for () {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        None
    }
    fn worker_spawn_succeeded(&self) {}
}
/// Keep progress and accounting together without changing canonical outputs.
pub struct ExecutionControl<'a, E> {
    pub progress: &'a (dyn Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
    pub worker_accounting: &'a dyn ExecutionWorkerAccounting,
}
impl<'a, E> ExecutionControl<'a, E> {
    pub fn new(
        progress: &'a (dyn Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
        worker_accounting: &'a dyn ExecutionWorkerAccounting,
    ) -> Self {
        Self {
            progress,
            worker_accounting,
        }
    }
}
pub(crate) fn relation_only<T>(result: ControlledResult<T, std::convert::Infallible>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(ExecutionError::Relation(error)) => Err(error),
        Err(ExecutionError::Cancelled(impossible)) => match impossible {},
    }
}
pub(crate) fn no_cancellation(
    _: ExecutionProgress,
) -> std::result::Result<(), std::convert::Infallible> {
    Ok(())
}
const ZERO: Hash = [0; 32];
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn num(v: &Value) -> Result<u64> {
    v.as_u64().ok_or("RANGE")
}
fn field(v: &Value, k: &str) -> Result<u64> {
    num(v.get(k).ok_or("STATE")?)
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or("STATE")
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("RANGE")
}
fn hash32(s: &str) -> Result<Hash> {
    require(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "NONCANONICAL",
    )?;
    let mut h = [0; 32];
    hex::decode_to_slice(s, &mut h).map_err(|_| "NONCANONICAL")?;
    Ok(h)
}
fn validate_canonical(v: &Value) -> Result<()> {
    match v {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) => require(n.is_u64() || n.is_i64(), "RANGE"),
        Value::String(s) => require(s.is_ascii(), "NONCANONICAL"),
        Value::Array(xs) => {
            for x in xs {
                validate_canonical(x)?;
            }
            Ok(())
        }
        Value::Object(m) => {
            for (k, v) in m {
                require(k.is_ascii(), "NONCANONICAL")?;
                validate_canonical(v)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn canonical(v: &Value) -> Result<Vec<u8>> {
    validate_canonical(v)?;
    serde_json::to_vec(v).map_err(|_| "NONCANONICAL")
}

pub fn root(state: &State) -> Result<Hash> {
    // Preserve the original complete grammar/error pass before wire limits.
    // A late noncanonical value must not be hidden by an earlier oversized key
    // or by the fixed state count cap. No encoded values are retained here.
    for value in state.values() {
        validate_canonical(value)?;
    }
    // The original wire root checks total count before per-row limits.
    if state.len() > 65_536 {
        return Err("LIMIT");
    }
    state_root_from_entries(state.iter().map(|(key, value)| {
        serde_json::to_vec(value)
            .map(|bytes| (key.as_bytes(), bytes))
            .map_err(|_| "NONCANONICAL")
    }))
    .map_err(|error| match error {
        StateRootInputError::Input(error) => error,
        StateRootInputError::Wire(_) => "LIMIT",
    })
}

#[derive(Clone)]
pub struct Config {
    pub network: Hash,
    pub parameters: Hash,
    pub family: Hash,
    pub plan: Hash,
    pub evaluators: BTreeSet<String>,
    pub fees: [u64; 24],
    pub params: Value,
    pub model_registry: Value,
}
impl Config {
    /// Installed experimental genesis context, not caller-supplied authority booleans.
    pub fn installed() -> Result<Self> {
        Self::installed_with_evaluation_policy("legacy-first-two-v3")
    }
    /// Explicit successor selects different network/parameter commitments. The default
    /// revision3 bytes and economics remain unchanged; this is not a hot upgrade.
    pub fn installed_with_evaluation_policy(policy: &str) -> Result<Self> {
        Self::installed_with_profiles(policy, LEGACY_TASK_PROFILE)
    }
    pub fn installed_with_profiles(policy: &str, task_profile: &str) -> Result<Self> {
        Self::installed_with_model_profiles(policy, task_profile, "linear-expert-dev-v1")
    }
    pub fn installed_with_model_profiles(
        policy: &str,
        task_profile: &str,
        model_profile: &str,
    ) -> Result<Self> {
        let mut params: Value =
            serde_json::from_str(include_str!("../../../../config/pon/devnet-v1.json"))
                .map_err(|_| "CONFIG")?;
        require(
            params["consensus_revision"] == 3 && params["production_activation"] == false,
            "CONFIG",
        )?;
        match policy {
            "legacy-first-two-v3" => {}
            trnm_verification_profiles::closed_round::PROFILE => {
                let policy: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/evaluation-round-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(policy["production_activation"] == false, "CONFIG")?;
                for (key, value) in policy["genesis_overrides"].as_object().ok_or("CONFIG")? {
                    params[key] = value.clone();
                }
                params["evaluation_policy_hash"] = json!(hex::encode(hash(
                    b"evaluation-policy",
                    &[&canonical(&policy)?]
                )));
            }
            public_evaluation::PROFILE => {
                let policy: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/public-evaluation-native-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    policy["production_activation"] == false
                        && policy["independent_governance_accepted"] == false
                        && policy["objective_model_quality"] == false,
                    "CONFIG",
                )?;
                require(
                    policy["storage_revision"] == public_evaluation::STORAGE_REVISION
                        && policy["maximum_record_bytes"] == 4096,
                    "CONFIG",
                )?;
                for (name, expected) in [
                    ("candidate_end_offset", public_evaluation::CANDIDATE_END),
                    ("commit_end_offset", public_evaluation::COMMIT_END),
                    ("reveal_end_offset", public_evaluation::REVEAL_END),
                    ("adoption_start_offset", public_evaluation::ADOPTION_START),
                    ("appeal_limit_per_candidate", 16),
                    ("archive_retention_blocks", 256),
                    ("round_blocks", 128),
                    ("maximum_candidates_per_round", 512),
                ] {
                    require(field(&policy, name)? == expected, "CONFIG")?;
                }
                for tag in 14..=17 {
                    require(
                        field(&policy["base_fee_units"], &tag.to_string())? == 160,
                        "CONFIG",
                    )?;
                }
                require(
                    field(&params, "candidate_round_blocks")? == 128
                        && field(&params, "max_candidate_history_per_round")? == 512,
                    "CONFIG",
                )?;
                for (key, value) in policy["genesis_overrides"].as_object().ok_or("CONFIG")? {
                    params[key] = value.clone();
                }
                params["evaluation_policy_hash"] = json!(hex::encode(hash(
                    b"evaluation-policy",
                    &[&canonical(&policy)?]
                )));
            }
            _ => return Err("EVALUATION_POLICY"),
        }
        match task_profile {
            LEGACY_TASK_PROFILE => {}
            SIGNED_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-work-task-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false,
                    "CONFIG",
                )?;
                let revision = if policy == public_evaluation::PROFILE {
                    6
                } else {
                    5
                };
                params["consensus_revision"] = json!(revision);
                params["chain_label"] =
                    json!(format!("trnm-pon-signed-task-devnet-{revision}-{policy}"));
                params["work_task_profile"] = json!(SIGNED_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v1",
                    &[&canonical(&registry)?]
                )));
            }
            LIFECYCLE_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-task-lifecycle-v2.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false,
                    "CONFIG",
                )?;
                params["consensus_revision"] = json!(7);
                params["chain_label"] = json!(format!("trnm-pon-task-lifecycle-devnet-7-{policy}"));
                params["work_task_profile"] = json!(LIFECYCLE_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v2",
                    &[&canonical(&registry)?]
                )));
            }
            ATOMIC_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-task-lifecycle-v3.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false
                        && registry["consensus_revision"] == 8
                        && registry["standalone_renew_disabled"] == true
                        && registry["exact_contract"]["atomic_renew_bytes"] == 1028
                        && registry["exact_contract"]["base_fee_units"]["22"] == 200,
                    "CONFIG",
                )?;
                params["consensus_revision"] = json!(8);
                params["chain_label"] = json!(format!("trnm-pon-task-lifecycle-devnet-8-{policy}"));
                params["work_task_profile"] = json!(ATOMIC_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v3",
                    &[&canonical(&registry)?]
                )));
            }
            OVERLAP_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-task-lifecycle-v4.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false
                        && registry["consensus_revision"] == 9
                        && registry["standalone_renew_disabled"] == true
                        && registry["atomic_overlap_window"] == true
                        && registry["exact_contract"]["atomic_renew_bytes"] == 1028
                        && registry["exact_contract"]["base_fee_units"]["22"] == 200,
                    "CONFIG",
                )?;
                params["consensus_revision"] = json!(9);
                params["chain_label"] = json!(format!("trnm-pon-task-lifecycle-devnet-9-{policy}"));
                params["work_task_profile"] = json!(OVERLAP_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v4",
                    &[&canonical(&registry)?]
                )));
            }
            CONTINUITY_TASK_PROFILE => continuity_v1::configure(&mut params, policy)?,
            CHECKPOINT_TASK_PROFILE => return Err("CHECKPOINT_POLICY_REQUIRED"),
            _ => return Err("WORK_TASK_PROFILE"),
        }
        if policy == public_evaluation::PROFILE {
            params["chain_label"] = json!(format!(
                "{}-evaluation-storage{}",
                text(&params, "chain_label")?,
                public_evaluation::STORAGE_REVISION
            ));
        }
        let model: Value = match model_profile {
            "linear-expert-dev-v1" => {
                serde_json::from_str(include_str!("../../../../config/pon/model-family-v1.json"))
                    .map_err(|_| "CONFIG")?
            }
            crate::integer_factor_candidate_v2::PROFILE
            | crate::model_evidence_v3::PROFILE
            | crate::model_composition_v4::PROFILE => {
                require(policy == public_evaluation::PROFILE, "MODEL_PROFILE_POLICY")?;
                require(
                    task_profile == LEGACY_TASK_PROFILE
                        || (matches!(
                            model_profile,
                            crate::model_evidence_v3::PROFILE
                                | crate::model_composition_v4::PROFILE
                        ) && task_profile == "consensus-maintenance-continuity-dev-v1"),
                    "MODEL_PROFILE_TASK",
                )?;
                let factor_policy: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/integer-factor-candidate-v2.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    factor_policy["production_activation"] == false
                        && factor_policy["tag"] == 23
                        && factor_policy["artifact_exact_bytes"]
                            == crate::integer_factor_candidate_v2::MODEL_BYTES
                        && factor_policy["rank_max"] == 2,
                    "CONFIG",
                )?;
                for (key, expected) in [
                    ("schema", json!("native-integer-factor-candidate-v2")),
                    (
                        "profile",
                        json!(crate::integer_factor_candidate_v2::PROFILE),
                    ),
                    ("consensus_revision", json!(11)),
                    ("magic", json!("ILF2")),
                    ("rank_min", json!(1)),
                    ("scale", json!(1024)),
                    ("coefficient_min", json!(-32767)),
                    ("coefficient_max", json!(32767)),
                    ("payload_bytes", json!([762, 1282])),
                    ("envelope_bytes", json!([921, 1441])),
                    ("artifact_max_bytes", json!(65536)),
                    ("chunk_bytes", json!(1024)),
                    ("chunk_count_max", json!(64)),
                    ("base_fee_units", json!(200)),
                    ("no_op_rejected", json!(true)),
                    ("source_budget_enforced", json!(false)),
                    ("quality_qualified", json!(false)),
                    ("general_model_equivalence", json!(false)),
                ] {
                    require(factor_policy[key] == expected, "CONFIG")?;
                }
                params["consensus_revision"] = json!(if model_profile
                    == crate::model_composition_v4::PROFILE
                {
                    crate::model_composition_v4::REVISION.max(field(&params, "consensus_revision")?)
                } else if model_profile == crate::model_evidence_v3::PROFILE {
                    crate::model_evidence_v3::REVISION.max(field(&params, "consensus_revision")?)
                } else {
                    11
                });
                params["model_profile"] = json!(model_profile);
                params["chain_label"] =
                    json!(format!("{}-{model_profile}", text(&params, "chain_label")?));
                params["factor_candidate_policy_hash"] = json!(hex::encode(hash(
                    b"integer-factor-candidate-policy-v2",
                    &[&canonical(&factor_policy)?]
                )));
                let mut model: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/model-family-integer-factor-v2.json"
                ))
                .map_err(|_| "CONFIG")?;
                if model_profile == crate::model_evidence_v3::PROFILE {
                    crate::model_evidence_v3::install(&mut params)?;
                    model["native_admission_profile"] = json!(model_profile);
                } else if model_profile == crate::model_composition_v4::PROFILE {
                    crate::model_composition_v4::install(&mut params)?;
                    model["native_admission_profile"] = json!(model_profile);
                }
                model
            }
            "smollm2-135m-cpu-dev-v1" => {
                require(policy == public_evaluation::PROFILE, "MODEL_PROFILE_POLICY")?;
                params["model_profile"] = json!(model_profile);
                params["chain_label"] =
                    json!(format!("{}-{model_profile}", text(&params, "chain_label")?));
                serde_json::from_str(include_str!(
                    "../../../../config/pon/model-family-smollm2-135m-v1.json"
                ))
                .map_err(|_| "CONFIG")?
            }
            _ => return Err("MODEL_PROFILE"),
        };
        if model_profile != "linear-expert-dev-v1" {
            let maximum = field(&model, "artifact_max_bytes")?;
            require(
                maximum > 0 && maximum <= field(&params, "max_artifact_bytes")?,
                "MODEL_PROFILE_LIMIT",
            )?;
            params["max_artifact_bytes"] = json!(maximum);
        }
        if matches!(
            model_profile,
            crate::integer_factor_candidate_v2::PROFILE
                | crate::model_evidence_v3::PROFILE
                | crate::model_composition_v4::PROFILE
        ) {
            for (key, expected) in [
                ("schema", json!("integer-linear-factor-family-v2")),
                ("version", json!(2)),
                ("dimensions", json!(257)),
                ("experts", json!(3)),
                ("logit_outputs", json!(3)),
                ("weight_scale", json!(1024)),
                ("weight_min", json!(-32767)),
                ("weight_max", json!(32767)),
                ("artifact_encoding", json!("ILM2-le-i16-complete-model-v2")),
                (
                    "artifact_exact_bytes",
                    json!(crate::integer_factor_candidate_v2::MODEL_BYTES),
                ),
                ("genesis_model", json!("canonical-full-zero-model-v2")),
                ("native_factor_rank_min", json!(1)),
                ("native_factor_rank_max", json!(2)),
                (
                    "tensor_shapes",
                    json!({"base":[3,257],"router":[3,257],"deltas":[3,3,257]}),
                ),
                ("consensus_authority", json!(false)),
                ("general_model_equivalence", json!(false)),
                ("model_utility_qualified", json!(false)),
            ] {
                require(model[key] == expected, "CONFIG")?;
            }
            let family = hash(b"family", &[&canonical(&model)?]);
            let artifact = crate::integer_factor_candidate_v2::IntegerModelV2::genesis(family);
            params["factor_genesis_artifact"] = json!(hex::encode(artifact.id()));
        }
        let wire: Value =
            serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))
                .map_err(|_| "CONFIG")?;
        let network = hash(b"network", &[text(&params, "chain_label")?.as_bytes()]);
        let work: Value =
            serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))
                .map_err(|_| "CONFIG")?;
        let parameters = hash(
            b"parameters",
            &[
                &canonical(&params)?,
                &canonical(&wire)?,
                &canonical(&work)?,
                &canonical(&model)?,
            ],
        );
        let family = hash(b"family", &[&canonical(&model)?]);
        let plan = if model_profile == crate::model_composition_v4::PROFILE {
            hash(
                b"plan",
                &[
                    b"native-integer-model-composition-plan-v4",
                    &family,
                    &hash32(text(&params, "factor_candidate_policy_hash")?)?,
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                    &hash32(text(&params, "model_evidence_policy_hash")?)?,
                    &hash32(text(&params, "model_evidence_tasks_hash")?)?,
                    &hash32(text(&params, "model_composition_policy_hash")?)?,
                ],
            )
        } else if model_profile == crate::model_evidence_v3::PROFILE {
            hash(
                b"plan",
                &[
                    b"native-integer-model-evidence-plan-v3",
                    &family,
                    &hash32(text(&params, "factor_candidate_policy_hash")?)?,
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                    &hash32(text(&params, "model_evidence_policy_hash")?)?,
                    &hash32(text(&params, "model_evidence_tasks_hash")?)?,
                ],
            )
        } else if model_profile == crate::integer_factor_candidate_v2::PROFILE {
            hash(
                b"plan",
                &[
                    b"native-integer-factor-evaluation-v2",
                    &family,
                    &hash32(text(&params, "factor_candidate_policy_hash")?)?,
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                ],
            )
        } else if model_profile != "linear-expert-dev-v1" {
            hash(
                b"plan",
                &[
                    b"native-llm-strong-baseline-dev-v1",
                    &family,
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                ],
            )
        } else if policy == "legacy-first-two-v3" {
            hash(b"plan", &[b"public-source-file-disjoint-v1"])
        } else {
            hash(
                b"plan",
                &[
                    b"public-source-file-disjoint-v1",
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                ],
            )
        };
        let mut fees = [0; 24];
        let mut tags = BTreeSet::new();
        for c in wire["commands"].as_array().ok_or("CONFIG")? {
            let tag = field(c, "tag")? as usize;
            require((1..=12).contains(&tag) && tags.insert(tag), "CONFIG")?;
            fees[tag] = field(c, "base_fee_units")?;
        }
        require(tags.len() == 12, "CONFIG")?;
        // The signed-task extension has an explicit fixed development base fee.
        // It is refused under every historical context even though its codec exists.
        fees[13] = 100;
        for fee in &mut fees[14..=17] {
            *fee = 160;
        }
        for fee in &mut fees[18..=21] {
            *fee = 100;
        }
        fees[22] = 200;
        fees[23] = 200;
        let mut evaluators = BTreeSet::new();
        for i in 0_u64..3 {
            let seed = hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()]);
            let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
                .map_err(|_| "CONFIG")?;
            evaluators.insert(trnm_crypto_primitives::public_key_hex(&key));
        }
        Ok(Self {
            network,
            parameters,
            family,
            plan,
            evaluators,
            fees,
            params,
            model_registry: model,
        })
    }
    fn limit(&self, name: &str) -> Result<u64> {
        field(&self.params, name)
    }
    pub fn task_profile(&self) -> &str {
        self.params["work_task_profile"]
            .as_str()
            .unwrap_or(LEGACY_TASK_PROFILE)
    }
    pub fn qualified_demand_id(&self, index: u64) -> Result<Hash> {
        require(
            self.task_profile() == SIGNED_TASK_PROFILE && index < QUALIFIED_DEMANDS,
            "TASK_DEMAND",
        )?;
        Ok(hash(
            b"qualified-development-demand-v1",
            &[&self.network, &self.parameters, &index.to_le_bytes()],
        ))
    }
    pub fn qualified_demand_purpose(index: u64) -> Result<TaskPurpose> {
        require(index < QUALIFIED_DEMANDS, "TASK_DEMAND")?;
        Ok(if index == 0 {
            TaskPurpose::Maintenance
        } else {
            match index % 3 {
                1 => TaskPurpose::InferenceContraction,
                2 => TaskPurpose::EvaluationContraction,
                _ => TaskPurpose::AdapterContraction,
            }
        })
    }
    pub fn qualified_task_context(&self, demand_id: Hash, height: u64) -> Result<AdmissionContext> {
        require(
            self.task_profile() == SIGNED_TASK_PROFILE,
            "WORK_TASK_PROFILE",
        )?;
        let mut known = false;
        for index in 0..QUALIFIED_DEMANDS {
            known |= self.qualified_demand_id(index)? == demand_id;
        }
        require(known, "TASK_DEMAND")?;
        let seed = hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]);
        let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
            .map_err(|_| "CONFIG")?;
        let source = key.verifying_key().to_bytes();
        Ok(AdmissionContext {
            network: self.network,
            parameters: self.parameters,
            source,
            demand_id,
            source_record: hash(
                b"qualified-development-source-record-v1",
                &[&demand_id, b"public-fixture-not-real-user-demand"],
            ),
            authorization_scope: hash(
                b"qualified-development-authorization-v1",
                &[
                    &self.network,
                    &self.parameters,
                    b"development-attestation-not-local-permission",
                ],
            ),
            withdrawal_head: hash(
                b"qualified-development-withdrawal-v1",
                &[&self.network, &self.parameters, &0_u64.to_le_bytes()],
            ),
            availability_manifest: hash(b"qualified-development-da-manifest-v1", &[&demand_id]),
            availability_root: hash(b"qualified-development-da-attestation-v1", &[&demand_id]),
            height,
            required_retention_blocks: 100,
        })
    }
}

#[derive(Default, Clone, Debug)]
pub struct Metrics {
    pub workers: usize,
    pub speculative: usize,
    pub reexecuted: usize,
    pub committed_without_replay: usize,
    pub peak_inflight: usize,
    pub serial_conflict_batches: usize,
    pub workers_spawned: usize,
    pub signature_verifications: usize,
    pub state_transition_ns: u128,
    pub state_root_ns: u128,
}
#[derive(Clone, Debug)]
pub struct Output {
    pub state: State,
    pub receipts: Vec<Vec<u8>>,
    pub root: Hash,
    pub metrics: Metrics,
}
#[derive(Clone, Debug)]
struct Patch {
    writes: BTreeMap<String, Value>,
    reads: BTreeMap<String, Option<Value>>,
    scans: BTreeMap<String, State>,
    fee: u64,
    receipt: Vec<u8>,
}
struct View<'a> {
    base: &'a State,
    account_access: Option<&'a AccountPointAccess<'a>>,
    writes: BTreeMap<String, Value>,
    reads: BTreeMap<String, Option<Value>>,
    scans: BTreeMap<String, State>,
}
impl<'a> View<'a> {
    fn new(base: &'a State, account_access: Option<&'a AccountPointAccess<'a>>) -> Self {
        Self {
            base,
            account_access,
            writes: BTreeMap::new(),
            reads: BTreeMap::new(),
            scans: BTreeMap::new(),
        }
    }
    fn get(&mut self, key: &str) -> Option<Value> {
        self.reads
            .entry(key.to_owned())
            .or_insert_with(|| self.base.get(key).cloned());
        self.writes.get(key).or_else(|| self.base.get(key)).cloned()
    }
    fn put(&mut self, key: String, value: Value) {
        self.reads
            .entry(key.clone())
            .or_insert_with(|| self.base.get(&key).cloned());
        self.writes.insert(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.scans.entry(prefix.to_owned()).or_insert_with(|| {
            self.base
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });
        let mut rows = self.scans[prefix].clone();
        rows.extend(
            self.writes
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        rows
    }
    fn account(&mut self, who: &str) -> Result<Value> {
        if let Some(access) = self.account_access {
            access(who)?;
        }
        Ok(self
            .get(&format!("account:{who}"))
            .unwrap_or_else(|| json!({"balance":0,"nonce":0})))
    }
    fn credit(&mut self, who: &str, amount: u64) -> Result<()> {
        let mut a = self.account(who)?;
        a["balance"] = json!(add(field(&a, "balance")?, amount)?);
        self.put(format!("account:{who}"), a);
        Ok(())
    }
    fn debit(&mut self, who: &str, amount: u64) -> Result<()> {
        let mut a = self.account(who)?;
        let b = field(&a, "balance")?;
        require(amount > 0 && b >= amount, "FUNDS")?;
        a["balance"] = json!(b - amount);
        self.put(format!("account:{who}"), a);
        Ok(())
    }
    fn object(&mut self, prefix: &str, id: Hash) -> Result<(String, Value)> {
        let k = format!("{prefix}{}", hex::encode(id));
        let v = self.get(&k).ok_or("STATE")?;
        Ok((k, v))
    }
    fn deadline(&mut self, cfg: &Config, d: u64, height: u64) -> Result<()> {
        self.deadline_with_lifetime(cfg, d, height, cfg.limit("max_task_lifetime_blocks")?)
    }
    fn deadline_with_lifetime(
        &mut self,
        cfg: &Config,
        d: u64,
        height: u64,
        lifetime: u64,
    ) -> Result<()> {
        require(height < d && d <= add(height, lifetime)?, "EXPIRED")?;
        let mut all = self.scan("task:");
        all.extend(self.scan("quota:"));
        all.extend(self.scan("release:"));
        let mut pending = 0;
        let mut due = 0;
        for v in all.values() {
            if field(v, "remaining")? > 0 {
                pending += 1;
                if field(v, "deadline")? == d {
                    due += 1;
                }
            }
        }
        require(
            pending < cfg.limit("max_pending_tasks")?
                && due < cfg.limit("mandatory_expiry_per_block")?,
            "LIMIT",
        )
    }
}
impl qualified_task_lifecycle::LifecycleState for View<'_> {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.get(key)
    }
    fn put(&mut self, key: String, value: Value) {
        self.put(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.scan(prefix)
    }
}
impl crate::integer_factor_candidate_v2::FactorState for View<'_> {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.get(key)
    }
    fn put(&mut self, key: String, value: Value) {
        self.put(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.scan(prefix)
    }
}
impl Patch {
    fn current(&self, state: &State) -> bool {
        self.reads.iter().all(|(k, v)| state.get(k) == v.as_ref())
            && self.scans.iter().all(|(prefix, old)| {
                state
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix))
                    .eq(old.iter())
            })
    }
    fn apply(self, state: &mut State) {
        state.extend(self.writes);
    }
}
struct Payload<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Payload<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.checked_add(N).ok_or("LENGTH")?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or("LENGTH")?
            .try_into()
            .map_err(|_| "LENGTH")?;
        self.pos = end;
        Ok(out)
    }
    fn n(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn h(&mut self) -> Result<Hash> {
        self.take()
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let length = u16::from_le_bytes(self.take()?) as usize;
        let end = self.pos.checked_add(length).ok_or("LENGTH")?;
        let value = self.bytes.get(self.pos..end).ok_or("LENGTH")?;
        self.pos = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }
}
fn allocation_leaf(cid: Hash, payee: Hash, score: u64) -> Hash {
    hash(b"allocation-leaf", &[&cid, &payee, &score.to_le_bytes()])
}
fn pair(a: Hash, b: Hash) -> Hash {
    if a < b {
        hash(b"allocation-node", &[&a, &b])
    } else {
        hash(b"allocation-node", &[&b, &a])
    }
}
fn allocation_root(mut leaves: Vec<Hash>) -> Result<Hash> {
    require(!leaves.is_empty(), "ROOT")?;
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().ok_or("ROOT")?);
        }
        leaves = leaves.chunks_exact(2).map(|x| pair(x[0], x[1])).collect();
    }
    Ok(leaves[0])
}
fn active_candidate(v: &Value, current: &str, height: u64, cfg: &Config) -> Result<bool> {
    let status = text(v, "status")?;
    let submitted = v
        .get("submitted_height")
        .map(num)
        .transpose()?
        .unwrap_or(height);
    Ok(text(v, "parent")? == current
        && v.get("submission_round").map(num).transpose()?.unwrap_or(0)
            == height / cfg.limit("candidate_round_blocks")?
        && (status == "submitted" || status == "evaluated")
        && (status != "evaluated" || field(v, "score")? > 0)
        && height <= add(submitted, cfg.limit("candidate_lifetime_blocks")?)?)
}

// This carrier is private and tied to the exact immutable input and installed context.
// Main-envelope verification is independent of branch state and is done only once.
// Consumer-use signatures still depend on the actual quota state and are checked there.
struct Prepared {
    envelope: Envelope,
    sender: String,
    encoded_len: usize,
}
/// Read-only native admission check for exact PNX1 canonical context, selected tag,
/// expiry and strict main signature. This grants no nonce, funds or execution fact.
pub fn validate_main_envelope(raw: &[u8], height: u64, cfg: &Config) -> Result<Envelope> {
    Ok(prepare(raw, height, cfg, &AtomicUsize::new(0))?.envelope)
}
fn prepare(raw: &[u8], height: u64, cfg: &Config, signatures: &AtomicUsize) -> Result<Prepared> {
    let tx = Envelope::decode(raw).map_err(|_| "ENCODING")?;
    require(
        !(18..=21).contains(&tx.tag) || qualified_task_lifecycle::enabled(cfg),
        "WORK_TASK_PROFILE",
    )?;
    require(
        tx.tag != 19 || cfg.task_profile() == LIFECYCLE_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(
        tx.tag != 22
            || matches!(
                cfg.task_profile(),
                ATOMIC_TASK_PROFILE
                    | OVERLAP_TASK_PROFILE
                    | CHECKPOINT_TASK_PROFILE
                    | CONTINUITY_TASK_PROFILE
            ),
        "WORK_TASK_PROFILE",
    )?;
    require(
        !(14..=17).contains(&tx.tag) || public_evaluation::enabled(cfg),
        "PUBLIC_EVAL_PROFILE",
    )?;
    require(
        tx.tag != 7 || !public_evaluation::enabled(cfg),
        "PUBLIC_EVAL_PROFILE",
    )?;
    require(
        tx.tag != 13 || cfg.task_profile() == SIGNED_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(
        tx.tag != 12 || cfg.task_profile() == LEGACY_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(
        tx.tag != 23 || crate::integer_factor_candidate_v2::enabled(cfg),
        "FACTOR_PROFILE",
    )?;
    require(
        tx.tag != 6 || !crate::integer_factor_candidate_v2::enabled(cfg),
        "FACTOR_PROFILE",
    )?;
    require(tx.network == cfg.network, "NETWORK")?;
    require(height <= tx.expiry, "EXPIRED")?;
    let sender = hex::encode(tx.sender);
    signatures.fetch_add(1, Ordering::Relaxed);
    verify_hex_strict(
        &sender,
        &tx.signing_digest().map_err(|_| "ENCODING")?,
        &hex::encode(tx.signature),
    )
    .map_err(|_| "SIGNATURE")?;
    Ok(Prepared {
        envelope: tx,
        sender,
        encoded_len: raw.len(),
    })
}
fn apply_prepared(base: &State, prepared: &Prepared, height: u64, cfg: &Config) -> Result<Patch> {
    apply_prepared_with_account_access(base, prepared, height, cfg, None)
}
fn apply_prepared_with_account_access(
    base: &State,
    prepared: &Prepared,
    height: u64,
    cfg: &Config,
    account_access: Option<&AccountPointAccess<'_>>,
) -> Result<Patch> {
    let tx = &prepared.envelope;
    let sender = prepared.sender.clone();
    let mut s = View::new(base, account_access);
    let acct = s.account(&sender)?;
    require(tx.nonce == add(field(&acct, "nonce")?, 1)?, "NONCE")?;
    let fee = add(
        cfg.fees[tx.tag as usize],
        (prepared.encoded_len as u64)
            .checked_mul(cfg.limit("byte_fee_units")?)
            .ok_or("RANGE")?,
    )?;
    require(tx.fee_limit >= fee, "FEE")?;
    if tx.tag != 11 {
        s.debit(&sender, fee)?;
    } else {
        s.put(format!("account:{sender}"), acct);
    }
    let mut p = Payload {
        bytes: &tx.payload,
        pos: 0,
    };
    match tx.tag {
        1 => {
            let recipient = hex::encode(p.h()?);
            let amount = p.n()?;
            s.debit(&sender, amount)?;
            s.credit(&recipient, amount)?;
        }
        2 => {
            let task = p.h()?;
            let provider = hex::encode(p.h()?);
            let budget = p.n()?;
            let deadline = p.n()?;
            require(
                task == hash(
                    b"task-instance-v3",
                    &[
                        &cfg.network,
                        &cfg.parameters,
                        &tx.sender,
                        &tx.nonce.to_le_bytes(),
                        &hash32(&provider)?,
                        &budget.to_le_bytes(),
                        &deadline.to_le_bytes(),
                    ],
                ),
                "RESOURCE_ID",
            )?;
            let k = format!("task:{}", hex::encode(task));
            require(s.get(&k).is_none(), "DUPLICATE")?;
            s.deadline(cfg, deadline, height)?;
            s.debit(&sender, budget)?;
            s.put(k,json!({"owner":sender,"provider":provider,"remaining":budget,"deadline":deadline,"status":"reserved","output":null}));
        }
        3 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            require(text(&o, "owner")? == sender, "AUTHORITY")?;
            require(text(&o, "status")? == "reserved", "STATE")?;
            s.credit(&sender, field(&o, "remaining")?)?;
            o["remaining"] = json!(0);
            o["status"] = json!("cancelled");
            s.put(k, o);
        }
        4 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            let output = p.h()?;
            require(text(&o, "provider")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "reserved" && height < field(&o, "deadline")?,
                "STATE",
            )?;
            require(output != ZERO, "EVIDENCE")?;
            o["output"] = json!(hex::encode(output));
            o["status"] = json!("receipt");
            s.put(k, o);
        }
        5 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            let output = hex::encode(p.h()?);
            require(text(&o, "owner")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "receipt"
                    && height < field(&o, "deadline")?
                    && text(&o, "output")? == output,
                "STATE",
            )?;
            s.credit(text(&o, "provider")?, field(&o, "remaining")?)?;
            o["remaining"] = json!(0);
            o["status"] = json!("settled");
            s.put(k, o);
        }
        23 => {
            let witness = trnm_protocol::integer_factor_v2::FactorWitnessV2::decode(&tx.payload)
                .map_err(|_| "FACTOR_ENCODING")?;
            let current = s
                .get("model:current")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or("STATE")?;
            let history = s.scan("contribution:");
            require(
                (history.len() as u64) < cfg.limit("max_candidate_history_per_round")?,
                "CANDIDATE_WINDOW_FULL",
            )?;
            let active = history
                .values()
                .map(|v| active_candidate(v, &current, height, cfg))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|b| *b)
                .count();
            require(
                (active as u64) < cfg.limit("max_model_candidates")?,
                "LIMIT",
            )?;
            let key = format!("contribution:{}", hex::encode(witness.contribution_id));
            require(s.get(&key).is_none(), "DUPLICATE")?;
            let mut contribution = crate::integer_factor_candidate_v2::admit(
                &mut s, cfg, tx.sender, height, &witness,
            )?;
            crate::model_evidence_v3::admit(
                &mut s,
                cfg,
                witness.contribution_id,
                &mut contribution,
            )?;
            let excluded = public_evaluation::excluded(&s.scan("evaluation-disqualified:"));
            contribution["public_evaluation"] = public_evaluation::freeze(
                cfg,
                witness.contribution_id,
                &contribution,
                height,
                &excluded,
            )?;
            s.put(key, contribution);
            p.pos = p.bytes.len();
        }
        6 => {
            let cid = p.h()?;
            let family = p.h()?;
            let parent = p.h()?;
            let artifact = p.h()?;
            let size = p.n()?;
            let components = p.h()?;
            let round = p.n()?;
            require(
                round == height / cfg.limit("candidate_round_blocks")?,
                "SUBMISSION_ROUND",
            )?;
            require(
                cid == hash(
                    b"contribution-v3",
                    &[
                        &tx.sender,
                        &family,
                        &parent,
                        &artifact,
                        &components,
                        &round.to_le_bytes(),
                    ],
                ),
                "ROOT",
            )?;
            let current = s
                .get("model:current")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or("STATE")?;
            require(
                family == cfg.family && hex::encode(parent) == current,
                "STATE",
            )?;
            require(
                size > 0 && size <= cfg.limit("max_artifact_bytes")?,
                "LIMIT",
            )?;
            require(artifact != ZERO, "EVIDENCE")?;
            let history = s.scan("contribution:");
            require(
                (history.len() as u64) < cfg.limit("max_candidate_history_per_round")?,
                "CANDIDATE_WINDOW_FULL",
            )?;
            let mut count = 0;
            for v in history.values() {
                if active_candidate(v, &current, height, cfg)? {
                    count += 1;
                }
            }
            require(count < cfg.limit("max_model_candidates")?, "LIMIT")?;
            let k = format!("contribution:{}", hex::encode(cid));
            let duplicate = format!(
                "artifact:{}:{}:{}",
                hex::encode(parent),
                round,
                hex::encode(artifact)
            );
            require(
                s.get(&k).is_none() && s.get(&duplicate).is_none(),
                "DUPLICATE",
            )?;
            let mut contribution = json!({"owner":sender,"artifact":hex::encode(artifact),"components_root":hex::encode(components),"family":hex::encode(family),"parent":hex::encode(parent),"votes":{},"score":0,"status":"submitted","submitted_height":height,"submission_round":round});
            if public_evaluation::enabled(cfg) {
                let excluded = public_evaluation::excluded(&s.scan("evaluation-disqualified:"));
                contribution["public_evaluation"] =
                    public_evaluation::freeze(cfg, cid, &contribution, height, &excluded)?;
            }
            s.put(k, contribution);
            s.put(duplicate, json!(hex::encode(cid)));
        }
        7 => {
            let (k, mut o) = s.object("contribution:", p.h()?)?;
            let plan = p.h()?;
            let evidence = p.h()?;
            let score = p.n()?;
            require(
                cfg.evaluators.contains(&sender) && text(&o, "owner")? != sender,
                "AUTHORITY",
            )?;
            let current = s.get("model:current").ok_or("STATE")?;
            require(
                text(&o, "status")? == "submitted" && o["parent"] == current,
                "STATE",
            )?;
            require(o["votes"].get(&sender).is_none(), "DUPLICATE")?;
            require(
                plan == cfg.plan && evidence != ZERO && score <= cfg.limit("max_evidence_score")?,
                "EVIDENCE",
            )?;
            o["votes"][&sender] = json!({"score":score,"evidence":hex::encode(evidence)});
            let votes = o["votes"].as_object().ok_or("STATE")?;
            let complete = match text(&cfg.params, "evaluation_profile")? {
                "explicit-attested-dev-profile-not-permissionless-utility" => {
                    votes.len() as u64 >= cfg.limit("evaluation_threshold")?
                }
                trnm_verification_profiles::closed_round::PROFILE => {
                    let author = text(&o, "owner")?;
                    let eligible = cfg
                        .evaluators
                        .iter()
                        .filter(|s| s.as_str() != author)
                        .cloned()
                        .collect();
                    let scores = votes
                        .iter()
                        .map(|(signer, vote)| Ok((signer.clone(), field(vote, "score")?)))
                        .collect::<Result<BTreeMap<_, _>>>()?;
                    trnm_verification_profiles::closed_round::complete_score(
                        &eligible,
                        &scores,
                        cfg.limit("max_evidence_score")?,
                    )?
                    .is_some()
                }
                _ => return Err("EVALUATION_POLICY"),
            };
            if complete {
                let minimum = votes
                    .values()
                    .map(|v| field(v, "score"))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .min()
                    .ok_or("STATE")?;
                o["score"] = json!(minimum);
                o["status"] = json!("evaluated");
            }
            s.put(k, o);
        }
        8 => {
            let release = p.h()?;
            let parent = p.h()?;
            let bundle_id = p.h()?;
            let budget = p.n()?;
            let supplied_root = p.h()?;
            let supplied_total = p.n()?;
            let count = p.byte()?;
            if crate::model_composition_v4::enabled(cfg) {
                require(
                    (2..=crate::model_composition_v4::MAX_COMPONENTS).contains(&usize::from(count)),
                    "MODEL_COMPOSITION_COUNT",
                )?;
            }
            let current = s.get("model:current").ok_or("STATE")?;
            require(current == json!(hex::encode(parent)), "STATE")?;
            let (bk, mut bundle) = s.object("contribution:", bundle_id)?;
            if public_evaluation::enabled(cfg) {
                let records = s.scan(&public_evaluation::record_prefix(bundle_id));
                let evaluation =
                    public_evaluation::hydrate(&bundle["public_evaluation"], bundle_id, &records)?;
                public_evaluation::adoption_allowed(&evaluation, height)?;
            }
            require(
                text(&bundle, "status")? == "evaluated"
                    && field(&bundle, "score")? >= cfg.limit("minimum_adoption_score")?,
                "EVIDENCE",
            )?;
            require(
                bundle["parent"] == current
                    && text(&bundle, "components_root")? == hex::encode(supplied_root),
                "ROOT",
            )?;
            let mut leaves = Vec::new();
            let mut adopted = Vec::new();
            let mut evidence_allocations = Vec::new();
            let mut total = 0_u64;
            for _ in 0..count {
                let cid = p.h()?;
                let score = p.n()?;
                let (k, mut o) = s.object("contribution:", cid)?;
                if public_evaluation::enabled(cfg) {
                    let records = s.scan(&public_evaluation::record_prefix(cid));
                    let evaluation =
                        public_evaluation::hydrate(&o["public_evaluation"], cid, &records)?;
                    if crate::model_composition_v4::enabled(cfg) {
                        crate::model_composition_v4::component_allowed(&evaluation, height)?;
                    } else {
                        public_evaluation::adoption_allowed(&evaluation, height)?;
                    }
                }
                require(
                    text(&o, "status")? == "evaluated"
                        && o["parent"] == current
                        && (crate::model_composition_v4::enabled(cfg)
                            || field(&o, "score")? == score)
                        && score > 0,
                    "EVIDENCE",
                )?;
                leaves.push(allocation_leaf(cid, hash32(text(&o, "owner")?)?, score));
                total = add(total, score)?;
                if crate::model_evidence_v3::enabled(cfg) {
                    evidence_allocations.push((cid, o.clone(), score));
                }
                o["status"] = json!("adopted");
                adopted.push((k, o));
            }
            require(
                allocation_root(leaves)? == supplied_root && total == supplied_total,
                "ROOT",
            )?;
            let composition_record = crate::model_evidence_v3::reserve_release(
                &mut s,
                cfg,
                bundle_id,
                &bundle,
                &evidence_allocations,
                budget,
                total,
            )?;
            require(
                release
                    == hash(
                        b"release",
                        &[
                            &parent,
                            &bundle_id,
                            &budget.to_le_bytes(),
                            &supplied_root,
                            &total.to_le_bytes(),
                        ],
                    ),
                "ROOT",
            )?;
            let rk = format!("release:{}", hex::encode(release));
            require(s.get(&rk).is_none(), "DUPLICATE")?;
            let horizon = add(
                cfg.limit("reward_maturity_blocks")?,
                cfg.limit("release_claim_window_blocks")?,
            )?;
            let expiry = add(height, horizon)?;
            s.deadline_with_lifetime(cfg, expiry, height, horizon)?;
            s.debit(&sender, budget)?;
            let mut release_record = json!({"owner":sender,"remaining":budget,"budget":budget,"total":total,"root":hex::encode(supplied_root),"maturity":add(height,cfg.limit("reward_maturity_blocks")?)?,"bundle":hex::encode(bundle_id),"artifact":bundle["artifact"].clone(),"family":bundle["family"].clone(),"components_root":bundle["components_root"].clone(),"parent":hex::encode(parent),"leaf_count":count,"claims":{},"deadline":expiry,"status":"open"});
            if let Some(record) = composition_record {
                release_record["model_composition_v4"] = record;
            }
            s.put(rk, release_record);
            for (k, o) in adopted {
                s.put(k, o);
            }
            bundle["status"] = json!("adopted");
            s.put(bk, bundle);
            s.put("model:current".into(), json!(hex::encode(release)));
        }
        9 => {
            let (rk, mut rel) = s.object("release:", p.h()?)?;
            let cid = p.h()?;
            let score = p.n()?;
            let count = p.byte()?;
            let c = hex::encode(cid);
            require(
                height >= field(&rel, "maturity")?
                    && height < field(&rel, "deadline")?
                    && text(&rel, "status")? == "open",
                "STATE",
            )?;
            require(rel["claims"].get(&c).is_none(), "DUPLICATE")?;
            let leaves = field(&rel, "leaf_count")?;
            require(leaves > 0, "ROOT")?;
            require(count as u32 == 64 - (leaves - 1).leading_zeros(), "ROOT")?;
            let mut leaf = allocation_leaf(cid, tx.sender, score);
            for _ in 0..count {
                leaf = pair(leaf, p.h()?);
            }
            require(leaf == hash32(text(&rel, "root")?)?, "ROOT")?;
            let total = field(&rel, "total")?;
            require(total > 0, "ROOT")?;
            let amount =
                u64::try_from((field(&rel, "budget")? as u128) * (score as u128) / (total as u128))
                    .map_err(|_| "RANGE")?;
            require(amount <= field(&rel, "remaining")?, "FUNDS")?;
            s.credit(&sender, amount)?;
            rel["remaining"] = json!(field(&rel, "remaining")? - amount);
            rel["claims"][&c] = json!(amount);
            s.put(rk, rel);
        }
        10 => {
            let quota = p.h()?;
            let consumer = hex::encode(p.h()?);
            let provider = hex::encode(p.h()?);
            let units = p.n()?;
            let deadline = p.n()?;
            require(
                quota
                    == hash(
                        b"quota-instance-v3",
                        &[
                            &cfg.network,
                            &cfg.parameters,
                            &tx.sender,
                            &tx.nonce.to_le_bytes(),
                            &hash32(&consumer)?,
                            &hash32(&provider)?,
                            &units.to_le_bytes(),
                            &deadline.to_le_bytes(),
                        ],
                    ),
                "RESOURCE_ID",
            )?;
            let k = format!("quota:{}", hex::encode(quota));
            require(s.get(&k).is_none(), "DUPLICATE")?;
            s.deadline(cfg, deadline, height)?;
            require(units > 0 && units <= cfg.limit("max_quota_units")?, "LIMIT")?;
            let cost = units
                .checked_mul(cfg.limit("quota_unit_price")?)
                .ok_or("RANGE")?;
            s.debit(&sender, cost)?;
            s.put(k,json!({"owner":sender,"consumer":consumer,"provider":provider,"remaining":cost,"units":units,"deadline":deadline,"status":"reserved"}));
        }
        11 => {
            let quota = p.h()?;
            let (k, mut o) = s.object("quota:", quota)?;
            let units = p.n()?;
            let result = p.h()?;
            let signature = p.take::<64>()?;
            require(text(&o, "provider")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "reserved" && height < field(&o, "deadline")?,
                "STATE",
            )?;
            require(
                units > 0 && units <= field(&o, "units")? && result != ZERO,
                "LIMIT",
            )?;
            let digest = hash(
                b"use",
                &[
                    &cfg.network,
                    &cfg.parameters,
                    &quota,
                    &tx.sender,
                    &tx.nonce.to_le_bytes(),
                    &units.to_le_bytes(),
                    &result,
                ],
            );
            verify_hex_strict(text(&o, "consumer")?, &digest, &hex::encode(signature))
                .map_err(|_| "SIGNATURE")?;
            let cost = units
                .checked_mul(cfg.limit("quota_unit_price")?)
                .ok_or("RANGE")?;
            require(cost >= fee && field(&o, "remaining")? >= cost, "FUNDS")?;
            o["remaining"] = json!(field(&o, "remaining")? - cost);
            o["units"] = json!(field(&o, "units")? - units);
            s.credit(&sender, cost - fee)?;
            if field(&o, "units")? == 0 {
                o["status"] = json!("spent");
            }
            s.put(k, o);
        }
        12 => {
            let task = p.h()?;
            let k = format!("work:{}", hex::encode(task));
            require(task != ZERO && s.get(&k).is_none(), "DUPLICATE")?;
            s.put(k, json!(true));
        }
        13 => {
            let signed =
                SignedQualifiedWorkTask::decode(&tx.payload).map_err(|_| "TASK_MANIFEST")?;
            let manifest = &signed.manifest;
            let context = cfg.qualified_task_context(manifest.demand_id, height)?;
            require(tx.sender == context.source, "TASK_SOURCE")?;
            let statement = verify_development_statement(&tx.payload, &context)
                .map_err(|_| "TASK_STATEMENT")?;
            let registry_key = format!("work-demand-registry:{}", hex::encode(manifest.demand_id));
            let registered = s.get(&registry_key).ok_or("TASK_DEMAND")?;
            require(
                field(&registered, "purpose")? == manifest.purpose as u64,
                "TASK_PURPOSE",
            )?;
            let withdrawal_key = format!("work-withdrawal:{}", hex::encode(context.source));
            require(
                s.get(&withdrawal_key) == Some(json!(hex::encode(context.withdrawal_head))),
                "TASK_WITHDRAWAL",
            )?;
            let sequence_key = format!("work-source:{}", hex::encode(context.source));
            let previous_sequence = s.get(&sequence_key).ok_or("TASK_SOURCE")?;
            require(
                manifest.demand_nonce == add(num(&previous_sequence)?, 1)?,
                "TASK_SOURCE_NONCE",
            )?;
            let demand_key = format!("work-demand:{}", hex::encode(manifest.demand_id));
            let work_key = format!("work:{}", hex::encode(manifest.matrix_task));
            require(
                s.get(&demand_key).is_none() && s.get(&work_key).is_none(),
                "TASK_REPLAY",
            )?;
            s.put(sequence_key, json!(manifest.demand_nonce));
            s.put(demand_key, json!(hex::encode(statement.manifest_id())));
            s.put(work_key, json!({"schema":"qualified-work-registration-v1","manifest":hex::encode(&tx.payload),"admitted_height":height,"manifest_id":hex::encode(statement.manifest_id())}));
            p.pos = p.bytes.len();
        }
        18..=22 => {
            qualified_task_lifecycle::apply_verified_command(&mut s, tx, height, cfg)?;
            p.pos = tx.payload.len();
        }
        14..=17 => {
            let cid = p.h()?;
            let active_key = format!("contribution:{}", hex::encode(cid));
            let archive_key = format!("evaluation-archive:{}", hex::encode(cid));
            let (key, mut contribution) = if let Some(value) = s.get(&active_key) {
                (active_key, value)
            } else {
                require(matches!(tx.tag, 16 | 17), "STATE")?;
                (archive_key.clone(), s.get(&archive_key).ok_or("STATE")?)
            };
            let records = s.scan(&public_evaluation::record_prefix(cid));
            contribution["public_evaluation"] =
                public_evaluation::hydrate(&contribution["public_evaluation"], cid, &records)?;
            let evaluation = &mut contribution["public_evaluation"];
            require(
                public_evaluation::enabled(cfg) && !evaluation.is_null(),
                "PUBLIC_EVAL_PROFILE",
            )?;
            match tx.tag {
                14 => public_evaluation::commit(evaluation, &sender, p.h()?, p.h()?, height)?,
                15 => {
                    let value = public_evaluation::Reveal {
                        candidate: cid,
                        round: p.h()?,
                        evaluator: tx.sender,
                        plan: p.h()?,
                        evidence: p.h()?,
                        score: p.n()?,
                        salt: p.h()?,
                    };
                    crate::model_evidence_v3::check_reveal(cfg, &contribution, &value)?;
                    public_evaluation::reveal(
                        &mut contribution["public_evaluation"],
                        value,
                        height,
                    )?;
                }
                16 => {
                    let first = p.blob()?;
                    let second = p.blob()?;
                    let disqualified =
                        public_evaluation::conflict(evaluation, cfg, cid, first, second)?;
                    s.put(format!("evaluation-disqualified:{disqualified}"),json!({"evidence_candidate":hex::encode(cid),"height":height,"scope":"exact development key; no hidden-controller independence claim"}));
                }
                17 => {
                    let author = contribution["owner"].as_str().ok_or("STATE")?.to_owned();
                    public_evaluation::appeal(
                        &mut contribution["public_evaluation"],
                        &author,
                        &sender,
                        p.h()?,
                        p.h()?,
                        p.h()?,
                        height,
                    )?;
                }
                _ => unreachable!(),
            }
            for (record_key, value) in
                public_evaluation::record_rows(cid, &contribution["public_evaluation"])?
            {
                if let Some(previous) = records.get(&record_key) {
                    require(previous == &value, "PUBLIC_EVAL_RECORD_MUTATION")?;
                } else {
                    s.put(record_key, value);
                }
            }
            contribution["public_evaluation"] =
                public_evaluation::compact(&contribution["public_evaluation"])?;
            if !contribution["public_evaluation"]["closed"].is_null() {
                s.put(archive_key, contribution.clone());
            }
            s.put(key, contribution);
        }
        _ => return Err("VERSION"),
    }
    require(p.pos == p.bytes.len(), "LENGTH")?;
    let mut a = s.account(&sender)?;
    a["nonce"] = json!(tx.nonce);
    s.put(format!("account:{sender}"), a);
    let receipt = canonical(
        &json!({"tx":hex::encode(tx.id().map_err(|_|"ENCODING")?),"fee":fee,"status":"applied"}),
    )?;
    Ok(Patch {
        writes: s.writes,
        reads: s.reads,
        scans: s.scans,
        fee,
        receipt,
    })
}

fn funds(state: &State) -> Result<u64> {
    let mut total = 0_u64;
    for (k, v) in state {
        let amount = if k.starts_with("account:") {
            field(v, "balance")?
        } else if k.starts_with("task:") || k.starts_with("quota:") || k.starts_with("release:") {
            field(v, "remaining")?
        } else if k.starts_with("reward:") {
            field(v, "amount")?
        } else {
            0
        };
        total = add(total, amount)?;
    }
    Ok(total)
}
fn credit_state(
    state: &mut State,
    who: &str,
    amount: u64,
    account_access: Option<&AccountPointAccess<'_>>,
) -> Result<()> {
    if let Some(access) = account_access {
        access(who)?;
    }
    let key = format!("account:{who}");
    let mut account = state
        .get(&key)
        .cloned()
        .unwrap_or_else(|| json!({"balance":0,"nonce":0}));
    account["balance"] = json!(add(field(&account, "balance")?, amount)?);
    state.insert(key, account);
    Ok(())
}
fn mandatory(
    state: &mut State,
    height: u64,
    cfg: &Config,
    account_access: Option<&AccountPointAccess<'_>>,
    monetary_input: Option<&MonetaryObligationInput<'_>>,
) -> Result<Vec<Vec<u8>>> {
    let current = state
        .get("model:current")
        .and_then(Value::as_str)
        .ok_or("STATE")?
        .to_owned();
    let keys: Vec<_> = state.keys().cloned().collect();
    if public_evaluation::enabled(cfg) {
        let candidates: Vec<_> = keys
            .iter()
            .filter(|key| key.starts_with("contribution:"))
            .cloned()
            .collect();
        for key in candidates {
            let cid = hash32(key.strip_prefix("contribution:").ok_or("STATE")?)?;
            let mut evaluation = public_evaluation::read_evaluation(state, cid)?;
            let closed = public_evaluation::close(&mut evaluation, height)?;
            let value = state.get_mut(&key).ok_or("STATE")?;
            value["public_evaluation"] = public_evaluation::compact(&evaluation)?;
            if let Some(score) = closed {
                value["score"] = json!(score);
                value["status"] = json!("evaluated");
            } else if value["public_evaluation"]["closed"]["status"] == "aborted" {
                value["score"] = json!(0);
                value["status"] = json!("evaluation-aborted");
            }
            if !value["public_evaluation"]["closed"].is_null() {
                let archive = value.clone();
                state.insert(
                    format!(
                        "evaluation-archive:{}",
                        key.strip_prefix("contribution:").ok_or("STATE")?
                    ),
                    archive,
                );
            }
        }
    }
    for k in keys {
        if k.starts_with("contribution:") {
            let v = state.get_mut(&k).ok_or("STATE")?;
            if text(v, "parent")? != current
                || v.get("submission_round").map(num).transpose()?.unwrap_or(0)
                    != height / cfg.limit("candidate_round_blocks")?
            {
                state.remove(&k);
            } else {
                let submitted = v
                    .get("submitted_height")
                    .map(num)
                    .transpose()?
                    .unwrap_or(height);
                if height > add(submitted, cfg.limit("candidate_lifetime_blocks")?)?
                    && matches!(text(v, "status")?, "submitted" | "evaluated")
                {
                    v["status"] = json!("expired");
                    v["votes"] = json!({});
                    v["score"] = json!(0);
                }
            }
        } else if k.starts_with("evaluation-archive:") {
            let value = state.get(&k).ok_or("STATE")?;
            let closed = field(&value["public_evaluation"]["closed"], "closed_height")?;
            if height.saturating_sub(closed) > 256 {
                state.remove(&k);
            }
        } else if k.starts_with("task:") || k.starts_with("quota:") {
            let value = state.get(&k).ok_or("STATE")?;
            if field(value, "remaining")? == 0 && field(value, "deadline")? < height {
                state.remove(&k);
            }
        } else if k.starts_with("artifact:") {
            let parts: Vec<_> = k.split(':').collect();
            let round = (height / cfg.limit("candidate_round_blocks")?).to_string();
            if parts.len() != 4 || parts[1] != current || parts[2] != round {
                state.remove(&k);
            }
        }
    }
    if public_evaluation::enabled(cfg) {
        // Remove records only after both active candidate and retained archive vanish.
        // Branch state cleanup never touches physical/local operation journals.
        let orphaned: Vec<_> = state
            .keys()
            .filter(|key| key.starts_with(&format!("{}:", public_evaluation::RECORD_NAMESPACE)))
            .filter(|key| {
                key.strip_prefix(&format!("{}:", public_evaluation::RECORD_NAMESPACE))
                    .and_then(|suffix| suffix.split_once(':'))
                    .is_some_and(|(candidate, _)| {
                        !state.contains_key(&format!("contribution:{candidate}"))
                            && !state.contains_key(&format!("evaluation-archive:{candidate}"))
                    })
            })
            .cloned()
            .collect();
        for key in orphaned {
            state.remove(&key);
        }
    }
    let retired: Vec<_> = state
        .iter()
        .filter_map(|(k, v)| {
            if k.starts_with("release:") && &k[8..] != current.as_str() && v["remaining"] == 0 {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    for k in retired {
        state.remove(&k);
    }
    let mut due = Vec::new();
    // Positive escrow records survive the preceding cleanup unchanged. Range
    // inputs enumerate every original monetary record, including future rows;
    // zero/retired rows are naturally ineligible under the ordinary predicates.
    for (k, v) in monetary_input.map_or(&*state, |input| input.rows) {
        if (k.starts_with("task:") || k.starts_with("quota:") || k.starts_with("release:"))
            && field(v, "remaining")? > 0
            && field(v, "deadline")? <= height
        {
            due.push((field(v, "deadline")?, k.clone()));
        }
    }
    due.sort();
    let mut receipts = Vec::new();
    for (_, k) in due
        .into_iter()
        .take(cfg.limit("mandatory_expiry_per_block")? as usize)
    {
        let mut v = state.get(&k).cloned().ok_or("STATE")?;
        credit_state(
            state,
            text(&v, "owner")?,
            field(&v, "remaining")?,
            account_access,
        )?;
        v["remaining"] = json!(0);
        v["status"] = json!("expired");
        state.insert(k.clone(), v);
        receipts.push(canonical(&json!({"expiry":k}))?);
    }
    let mature = monetary_input
        .map_or(&*state, |input| input.rows)
        .iter()
        .filter(|(k, _)| k.starts_with("reward:"))
        .map(|(k, v)| Ok((k.clone(), field(v, "maturity")?)))
        .collect::<Result<Vec<_>>>()?;
    for (k, maturity) in mature {
        if maturity <= height {
            let reward = state.remove(&k).ok_or("STATE")?;
            credit_state(
                state,
                text(&reward, "owner")?,
                field(&reward, "amount")?,
                account_access,
            )?;
        }
    }
    crate::integer_factor_candidate_v2::cleanup(state, height, cfg)?;
    crate::model_evidence_v3::cleanup(state, cfg, height)?;
    Ok(receipts)
}

/// Execute context-selected signed commands in exact ledger order. Failed blocks never
/// mutate `parent`. Only observed dependencies cause one canonical re-execution.
pub fn execute(
    parent: &State,
    transactions: &[Vec<u8>],
    height: u64,
    miner: Hash,
    parent_id: Hash,
    workers: usize,
    cfg: &Config,
) -> Result<Output> {
    execute_with_commitment(
        parent,
        BlockExecution {
            transactions,
            height,
            miner,
            parent_id,
            workers,
        },
        cfg,
        |_, next| root(next),
    )
}
/// Cooperative pure preview; all spawned workers are joined before any return.
/// Individual signatures, State operations and root construction are not preempted.
pub fn execute_with_progress<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    execute_with_commitment_and_progress(parent, block, cfg, |_, next| root(next), progress)
}
pub fn execute_with_control<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    control: &ExecutionControl<'_, E>,
) -> ControlledResult<Output, E> {
    execute_with_commitment_and_control(parent, block, cfg, |_, next| root(next), control)
}
/// Explicit serial research consumer of semantic account point-access evidence.
/// This function still requires a complete State and performs its ordinary funds,
/// prefix, capacity and root checks. It neither authenticates the callback nor
/// grants permission to substitute a partial State or bypass Node admission.
pub fn execute_with_account_point_access<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    account_access: &AccountPointAccess<'_>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    require(block.workers == 1, "ACCOUNT_ACCESS_WORKERS")?;
    execute_with_state_inputs(
        parent,
        block,
        cfg,
        |_, next| root(next),
        &ExecutionControl::new(progress, &()),
        StateInputs {
            accounts: Some(account_access),
            ..StateInputs::default()
        },
    )
}
/// Explicit research relation using authenticated account point access and a
/// complete non-account partition. It retains the ordinary full-State funds,
/// capacity and root reference; this is not partial-State or admission authority.
pub fn execute_with_authenticated_state_input<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    account_access: &AccountPointAccess<'_>,
    mandatory_input: &MandatoryStateInput<'_>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    require(block.workers == 1, "ACCOUNT_ACCESS_WORKERS")?;
    execute_with_state_inputs(
        parent,
        block,
        cfg,
        |_, next| root(next),
        &ExecutionControl::new(progress, &()),
        StateInputs {
            accounts: Some(account_access),
            mandatory: Some(mandatory_input),
            monetary: None,
        },
    )
}
/// Explicit full-reference M06 relation whose mandatory monetary enumeration
/// and original capacity scan consume authenticated namespace-range rows.
/// Account access, other non-account rules, every transaction, the new reward
/// and final successor capacity/conservation checks retain their ordinary rules.
pub fn execute_with_authenticated_obligation_input<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    account_access: &AccountPointAccess<'_>,
    mandatory_input: &MandatoryStateInput<'_>,
    monetary_input: &MonetaryObligationInput<'_>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    require(block.workers == 1, "ACCOUNT_ACCESS_WORKERS")?;
    execute_with_state_inputs(
        parent,
        block,
        cfg,
        |_, next| root(next),
        &ExecutionControl::new(progress, &()),
        StateInputs {
            accounts: Some(account_access),
            mandatory: Some(mandatory_input),
            monetary: Some(monetary_input),
        },
    )
}
/// Ordinary caller-supplied facts, not prepared execution or admission authority.
pub struct BlockExecution<'a> {
    pub transactions: &'a [Vec<u8>],
    pub height: u64,
    pub miner: Hash,
    pub parent_id: Hash,
    pub workers: usize,
}
pub(crate) fn execute_with_commitment(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
) -> Result<Output> {
    relation_only(execute_with_commitment_and_progress(
        parent,
        block,
        cfg,
        commitment,
        &no_cancellation,
    ))
}
pub(crate) fn execute_with_commitment_and_progress<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    execute_with_commitment_and_control(
        parent,
        block,
        cfg,
        commitment,
        &ExecutionControl::new(progress, &()),
    )
}
pub(crate) fn execute_with_commitment_and_control<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
    control: &ExecutionControl<'_, E>,
) -> ControlledResult<Output, E> {
    execute_with_state_inputs(
        parent,
        block,
        cfg,
        commitment,
        control,
        StateInputs::default(),
    )
}
fn execute_with_state_inputs<E: Send>(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    mut commitment: impl FnMut(&State, &State) -> Result<Hash>,
    control: &ExecutionControl<'_, E>,
    inputs: StateInputs<'_>,
) -> ControlledResult<Output, E> {
    let StateInputs {
        accounts: account_access,
        mandatory: mandatory_input,
        monetary: monetary_input,
    } = inputs;
    let progress = control.progress;
    let BlockExecution {
        transactions,
        height,
        miner,
        parent_id,
        workers,
    } = block;
    require([1, 2, 4, 8].contains(&workers), "WORKERS")?;
    require(
        transactions.len() as u64 <= cfg.limit("max_transactions")?,
        "LIMIT",
    )?;
    progress(ExecutionProgress::BeforeStateClone).map_err(ExecutionError::Cancelled)?;
    let (mut state, mut receipts) = prepare_block_state_with_inputs(
        parent,
        height,
        cfg,
        account_access,
        mandatory_input,
        monetary_input,
    )?;
    progress(ExecutionProgress::AfterMandatory).map_err(ExecutionError::Cancelled)?;
    let mut fees = 0;
    let mut metrics = Metrics {
        workers,
        ..Metrics::default()
    };
    let transition_start = std::time::Instant::now();
    let signatures = AtomicUsize::new(0);
    // Same sender means every transaction writes the same nonce. Preserve a serial
    // state path, while independent cryptographic checks may still use the bounded pool.
    let serial_state = workers == 1
        || (transactions.len() > 1
            && transactions[0].len() >= 68
            && transactions
                .iter()
                .all(|raw| raw.get(36..68) == transactions[0].get(36..68)));
    struct Predicted {
        prepared: Result<Prepared>,
        patch: Option<Result<Patch>>,
    }
    let predict = |index: usize, raw: &[u8]| -> ControlledResult<Predicted, E> {
        progress(ExecutionProgress::BeforePrepare { index }).map_err(ExecutionError::Cancelled)?;
        let prepared = prepare(raw, height, cfg, &signatures);
        progress(ExecutionProgress::AfterPrepare { index }).map_err(ExecutionError::Cancelled)?;
        let range_command = prepared
            .as_ref()
            .is_ok_and(|p| matches!(p.envelope.tag, 2 | 6 | 8 | 10 | 23));
        // Prefix-capacity operations remain canonical: do not retain one full
        // prefix snapshot per transaction merely to parallelize shared budgets.
        let patch = if serial_state || range_command {
            None
        } else {
            Some(prepared.as_ref().map_err(|e| *e).and_then(|tx| {
                apply_prepared_with_account_access(&state, tx, height, cfg, account_access)
            }))
        };
        Ok(Predicted { prepared, patch })
    };
    let count = workers.min(transactions.len());
    let predicted = if count <= 1 {
        transactions
            .iter()
            .enumerate()
            .map(|(index, raw)| predict(index, raw))
            .collect::<ControlledResult<Vec<_>, E>>()?
    } else {
        // One bounded group of scoped workers PER BLOCK, not per short batch.
        // No clone of the full state per worker; everyone reads the same snapshot.
        metrics.workers_spawned = count;
        std::thread::scope(|scope| -> ControlledResult<Vec<Predicted>, E> {
            let mut handles = Vec::with_capacity(count);
            for worker in 0..count {
                let work = &predict;
                #[cfg(test)]
                let allowed = control.worker_accounting.test_spawn_allowed(worker);
                #[cfg(not(test))]
                let allowed = true;
                let handle = if allowed {
                    std::thread::Builder::new()
                        .name(format!("pon-exec-{worker}"))
                        .spawn_scoped(scope, move || {
                            let _interval = control.worker_accounting.worker_started();
                            (worker..transactions.len())
                                .step_by(count)
                                .map(|index| {
                                    work(index, &transactions[index]).map(|value| (index, value))
                                })
                                .collect::<ControlledResult<Vec<_>, E>>()
                        })
                } else {
                    Err(std::io::Error::other(
                        "test-only partial worker start refusal",
                    ))
                };
                match handle {
                    Ok(h) => {
                        control.worker_accounting.worker_spawn_succeeded();
                        handles.push(h);
                    }
                    Err(_) => {
                        // Join already started workers on partial-spawn failure too.
                        for h in handles {
                            let _ = h.join();
                        }
                        return Err("WORKER_START".into());
                    }
                }
            }
            let mut rows = Vec::with_capacity(transactions.len());
            let mut panicked = false;
            let mut cancelled = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(mut values)) => rows.append(&mut values),
                    Ok(Err(error)) => {
                        if cancelled.is_none() {
                            cancelled = Some(error);
                        }
                    }
                    Err(_) => panicked = true,
                }
            }
            require(!panicked, "WORKER_PANIC")?;
            // Every handle is joined above before cancellation is returned.
            if let Some(error) = cancelled {
                return Err(error);
            }
            rows.sort_by_key(|(index, _)| *index);
            require(rows.len() == transactions.len(), "WORKER_RESULT")?;
            Ok(rows.into_iter().map(|(_, result)| result).collect())
        })?
    };
    metrics.signature_verifications = signatures.load(Ordering::Relaxed);
    metrics.peak_inflight = if serial_state {
        usize::from(!transactions.is_empty())
    } else {
        count
    };
    if serial_state && workers > 1 && !transactions.is_empty() {
        metrics.serial_conflict_batches = 1;
    }
    for (index, result) in predicted.into_iter().enumerate() {
        progress(ExecutionProgress::BeforeApply { index }).map_err(ExecutionError::Cancelled)?;
        // Consume failures at their canonical transaction position. A bad later
        // signature never bypasses an earlier state error or mutates the parent.
        let prepared = result.prepared?;
        let patch = if serial_state || result.patch.is_none() {
            metrics.committed_without_replay += 1;
            apply_prepared_with_account_access(&state, &prepared, height, cfg, account_access)?
        } else {
            metrics.speculative += 1;
            match result.patch.ok_or("WORKER_RESULT")? {
                Ok(patch) if patch.current(&state) => {
                    metrics.committed_without_replay += 1;
                    patch
                }
                _ => {
                    metrics.reexecuted += 1;
                    // Exactly one canonical state replay, no duplicate main-signature work.
                    apply_prepared_with_account_access(
                        &state,
                        &prepared,
                        height,
                        cfg,
                        account_access,
                    )?
                }
            }
        };
        fees = add(fees, patch.fee)?;
        receipts.push(patch.receipt.clone());
        patch.apply(&mut state);
        progress(ExecutionProgress::AfterApply { index }).map_err(ExecutionError::Cancelled)?;
    }
    metrics.state_transition_ns = transition_start.elapsed().as_nanos();
    progress(ExecutionProgress::BeforeReward).map_err(ExecutionError::Cancelled)?;
    state.extend(block_reward_updates(
        &state, height, miner, parent_id, fees, cfg,
    )?);
    check_completed_block_state_with_account_access(&state, height, cfg, account_access)?;
    let root_start = std::time::Instant::now();
    progress(ExecutionProgress::BeforeCommitment).map_err(ExecutionError::Cancelled)?;
    let root = commitment(parent, &state)?;
    progress(ExecutionProgress::AfterCommitment).map_err(ExecutionError::Cancelled)?;
    metrics.state_root_ns = root_start.elapsed().as_nanos();
    progress(ExecutionProgress::BeforeOutput).map_err(ExecutionError::Cancelled)?;
    Ok(Output {
        state,
        receipts,
        root,
        metrics,
    })
}

/// One original block prologue. Prefix previews retain its pre-reward successor,
/// never a completed block with a second maturity, expiry or subsidy transition.
fn prepare_block_state(parent: &State, height: u64, cfg: &Config) -> Result<(State, Vec<Vec<u8>>)> {
    prepare_block_state_with_account_access(parent, height, cfg, None)
}
fn prepare_block_state_with_account_access(
    parent: &State,
    height: u64,
    cfg: &Config,
    account_access: Option<&AccountPointAccess<'_>>,
) -> Result<(State, Vec<Vec<u8>>)> {
    prepare_block_state_with_inputs(parent, height, cfg, account_access, None, None)
}
fn prepare_block_state_with_inputs(
    parent: &State,
    height: u64,
    cfg: &Config,
    account_access: Option<&AccountPointAccess<'_>>,
    mandatory_input: Option<&MandatoryStateInput<'_>>,
    monetary_input: Option<&MonetaryObligationInput<'_>>,
) -> Result<(State, Vec<Vec<u8>>)> {
    if let Some(input) = monetary_input {
        require(
            parent
                .iter()
                .filter(|(key, _)| is_monetary_obligation(key))
                .eq(input.rows.iter()),
            "MONETARY_OBLIGATION_PARTITION",
        )?;
    }
    if let Some(input) = mandatory_input {
        require(
            !input
                .non_accounts
                .keys()
                .any(|key| key.starts_with("account:"))
                && parent
                    .iter()
                    .filter(|(key, _)| !key.starts_with("account:"))
                    .eq(input.non_accounts.iter()),
            "MANDATORY_STATE_PARTITION",
        )?;
    }
    if continuity_v1::enabled(cfg) {
        continuity_v1::check_state_with_account_access_and_monetary(
            parent,
            height.checked_sub(1).ok_or("HEIGHT")?,
            cfg,
            account_access,
            monetary_input.map(|input| input.rows),
        )?;
    }
    let mut state = if let Some(input) = mandatory_input {
        let mut complete: State = parent
            .iter()
            .filter(|(key, _)| key.starts_with("account:"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        complete.extend(input.non_accounts.clone());
        complete
    } else {
        parent.clone()
    };
    let receipts = mandatory(&mut state, height, cfg, account_access, monetary_input)?;
    if let Some(input) = mandatory_input {
        (input.completed)(parent, &state, &receipts)?;
    }
    Ok((state, receipts))
}

/// All block epilogue writes are returned together so an operation-local prefix
/// can remove exactly those writes before accepting another ordinary transaction.
fn block_reward_updates(
    state: &State,
    height: u64,
    miner: Hash,
    parent_id: Hash,
    fees: u64,
    cfg: &Config,
) -> Result<State> {
    let halvings = (height / cfg.limit("subsidy_halving_interval")?).min(64);
    let subsidy = cfg
        .limit("block_subsidy_units")?
        .checked_shr(halvings as u32)
        .unwrap_or(0);
    let reward = hash(b"reward", &[&parent_id, &height.to_le_bytes(), &miner]);
    let reward = (
        format!("reward:{}", hex::encode(reward)),
        json!({"owner":hex::encode(miner),"amount":add(fees,subsidy)?,"maturity":add(height,cfg.limit("reward_maturity_blocks")?)?}),
    );
    let issued = add(num(state.get("meta:issued").ok_or("STATE")?)?, subsidy)?;
    Ok(State::from([reward, ("meta:issued".into(), json!(issued))]))
}

fn check_completed_block_state(state: &State, height: u64, cfg: &Config) -> Result<()> {
    check_completed_block_state_with_account_access(state, height, cfg, None)
}
fn check_completed_block_state_with_account_access(
    state: &State,
    height: u64,
    cfg: &Config,
    account_access: Option<&AccountPointAccess<'_>>,
) -> Result<()> {
    require(
        funds(state)? == num(state.get("meta:issued").ok_or("STATE")?)?,
        "CONSERVATION",
    )?;
    continuity_v1::check_state_with_account_access(state, height, cfg, account_access)
}

/// Exact fixed context for a series of prefixes of ONE candidate block.
/// This is computation input only; no consensus, Pool or owner permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixContext {
    pub height: u64,
    pub miner: Hash,
    pub parent_id: Hash,
}

/// Private unfinalized prefix state. Only a checked original-parent binding can
/// construct the public commitment wrapper. All authority stays with that caller.
pub(crate) struct TransactionPrefix {
    state: State,
    receipts: Vec<Vec<u8>>,
    fees: u64,
    transactions: Vec<Vec<u8>>,
    context: PrefixContext,
    config: Config,
}

/// Changed-key rollback includes partial groups, finalizer writes and unwinding.
/// It is scratch only and cannot undo any durable or external operation.
struct PrefixRollback<'a> {
    state: &'a mut State,
    before: BTreeMap<String, Option<Value>>,
    committed: bool,
}
impl PrefixRollback<'_> {
    fn apply(&mut self, writes: State) {
        for (key, value) in writes {
            self.before
                .entry(key.clone())
                .or_insert_with(|| self.state.get(&key).cloned());
            self.state.insert(key, value);
        }
    }
    fn restore(&mut self, values: BTreeMap<String, Option<Value>>) {
        for (key, value) in values {
            if let Some(value) = value {
                self.state.insert(key, value);
            } else {
                self.state.remove(&key);
            }
        }
    }
}
impl Drop for PrefixRollback<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let before = std::mem::take(&mut self.before);
            self.restore(before);
        }
    }
}

impl TransactionPrefix {
    pub(crate) fn new<E: Send>(
        parent: &State,
        context: PrefixContext,
        config: &Config,
        control: &ExecutionControl<'_, E>,
    ) -> ControlledResult<Self, E> {
        (control.progress)(ExecutionProgress::BeforeStateClone)
            .map_err(ExecutionError::Cancelled)?;
        let (state, receipts) = prepare_block_state(parent, context.height, config)?;
        (control.progress)(ExecutionProgress::AfterMandatory).map_err(ExecutionError::Cancelled)?;
        Ok(Self {
            state,
            receipts,
            fees: 0,
            transactions: Vec::new(),
            context,
            config: config.clone(),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.transactions.len()
    }

    /// The full byte prefix is compared on every call. Only its new suffix is
    /// prepared/applied; rejection, cancellation or panic retains the last prefix.
    /// Output metrics describe this suffix, while state/receipts describe the full
    /// candidate. Full state/root construction remains required per accepted group.
    pub(crate) fn execute_with_commitment_and_control<E: Send>(
        &mut self,
        transactions: &[Vec<u8>],
        mut commitment: impl FnMut(&State) -> Result<Hash>,
        control: &ExecutionControl<'_, E>,
    ) -> ControlledResult<Output, E> {
        require(
            transactions.len() as u64 <= self.config.limit("max_transactions")?,
            "LIMIT",
        )?;
        require(
            transactions.starts_with(&self.transactions),
            "PREFIX_BINDING",
        )?;
        let progress = control.progress;
        let first = self.transactions.len();
        let suffix = &transactions[first..];
        let signatures = AtomicUsize::new(0);
        let transition_start = std::time::Instant::now();
        let mut prepared = Vec::with_capacity(suffix.len());
        for (offset, raw) in suffix.iter().enumerate() {
            let index = first + offset;
            progress(ExecutionProgress::BeforePrepare { index })
                .map_err(ExecutionError::Cancelled)?;
            prepared.push(prepare(raw, self.context.height, &self.config, &signatures));
            progress(ExecutionProgress::AfterPrepare { index })
                .map_err(ExecutionError::Cancelled)?;
        }
        // Complete raw cloning/capacity growth before any scratch mutation. The
        // final publish then only moves initialized Vecs into reserved capacity.
        let mut appended_transactions = suffix.to_vec();
        self.transactions.reserve(appended_transactions.len());
        let mut staged = PrefixRollback {
            state: &mut self.state,
            before: BTreeMap::new(),
            committed: false,
        };
        let mut fees = self.fees;
        let mut receipts = self.receipts.clone();
        for (offset, prepared) in prepared.into_iter().enumerate() {
            let index = first + offset;
            progress(ExecutionProgress::BeforeApply { index })
                .map_err(ExecutionError::Cancelled)?;
            let patch =
                apply_prepared(staged.state, &prepared?, self.context.height, &self.config)?;
            fees = add(fees, patch.fee)?;
            receipts.push(patch.receipt);
            staged.apply(patch.writes);
            progress(ExecutionProgress::AfterApply { index }).map_err(ExecutionError::Cancelled)?;
        }
        let mut metrics = Metrics {
            workers: 1,
            committed_without_replay: suffix.len(),
            peak_inflight: usize::from(!suffix.is_empty()),
            signature_verifications: signatures.load(Ordering::Relaxed),
            state_transition_ns: transition_start.elapsed().as_nanos(),
            ..Metrics::default()
        };
        progress(ExecutionProgress::BeforeReward).map_err(ExecutionError::Cancelled)?;
        let writes = block_reward_updates(
            staged.state,
            self.context.height,
            self.context.miner,
            self.context.parent_id,
            fees,
            &self.config,
        )?;
        let before_reward = writes
            .keys()
            .map(|key| (key.clone(), staged.state.get(key).cloned()))
            .collect();
        staged.apply(writes);
        check_completed_block_state(staged.state, self.context.height, &self.config)?;
        let root_start = std::time::Instant::now();
        progress(ExecutionProgress::BeforeCommitment).map_err(ExecutionError::Cancelled)?;
        let root = commitment(staged.state)?;
        progress(ExecutionProgress::AfterCommitment).map_err(ExecutionError::Cancelled)?;
        metrics.state_root_ns = root_start.elapsed().as_nanos();
        progress(ExecutionProgress::BeforeOutput).map_err(ExecutionError::Cancelled)?;
        let output = Output {
            state: staged.state.clone(),
            receipts: receipts.clone(),
            root,
            metrics,
        };
        staged.restore(before_reward);
        staged.committed = true;
        self.fees = fees;
        self.receipts = receipts;
        self.transactions.append(&mut appended_transactions);
        Ok(output)
    }
}

/// Compute cache only. The caller remains the sole authoritative ledger owner.
/// A request must name the exact predecessor root and monotonically increasing sequence.
/// Every failed transaction, commitment check or sequence mismatch preserves this session.
pub struct ExecutionSession {
    state: State,
    tree: trnm_protocol::pon_state::StateTree,
    config: Config,
    sequence: u64,
}
#[derive(Debug)]
pub struct SessionOutput {
    pub predecessor: Hash,
    pub root: Hash,
    pub sequence: u64,
    pub changes: Vec<(String, Option<Value>, Option<Value>)>,
    pub receipts: Vec<Vec<u8>>,
    pub metrics: Metrics,
    pub commitment_nodes: usize,
}
impl ExecutionSession {
    pub fn new(state: State, expected_root: Hash, config: Config) -> Result<Self> {
        let mut bytes = BTreeMap::new();
        for (key, value) in &state {
            bytes.insert(key.as_bytes().to_vec(), canonical(value)?);
        }
        let tree =
            trnm_protocol::pon_state::StateTree::from_values(&bytes).map_err(|_| "STATE_TREE")?;
        require(tree.root() == expected_root, "SESSION_ROOT")?;
        Ok(Self {
            state,
            tree,
            config,
            sequence: 0,
        })
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn execute(
        &mut self,
        predecessor: (u64, Hash),
        transactions: &[Vec<u8>],
        height: u64,
        miner: Hash,
        parent_id: Hash,
        workers: usize,
    ) -> Result<SessionOutput> {
        require(
            predecessor == (self.sequence, self.tree.root()),
            "SESSION_PREDECESSOR",
        )?;
        let sequence = self.sequence.checked_add(1).ok_or("SESSION_SEQUENCE")?;
        let mut staged = None;
        let mut changes = Vec::new();
        let output = execute_with_commitment(
            &self.state,
            BlockExecution {
                transactions,
                height,
                miner,
                parent_id,
                workers,
            },
            &self.config,
            |before, after| {
                use trnm_protocol::pon_state::Change;
                let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
                let mut updates = Vec::new();
                for key in keys {
                    let old = before.get(key);
                    let new = after.get(key);
                    if old != new {
                        updates.push(Change {
                            key: key.as_bytes().to_vec(),
                            before: old.map(canonical).transpose()?,
                            after: new.map(canonical).transpose()?,
                        });
                        changes.push((key.clone(), old.cloned(), new.cloned()));
                    }
                }
                let next = self
                    .tree
                    .apply(predecessor.1, &updates)
                    .map_err(|_| "STATE_TREE")?;
                let root = next.root();
                staged = Some(next);
                Ok(root)
            },
        )?;
        let tree = staged.ok_or("STATE_TREE")?;
        let result = SessionOutput {
            predecessor: predecessor.1,
            root: output.root,
            sequence,
            changes,
            receipts: output.receipts,
            metrics: output.metrics,
            commitment_nodes: tree.allocated_nodes(),
        };
        self.state = output.state;
        self.tree = tree;
        self.sequence = sequence;
        Ok(result)
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn initial() -> State {
        BTreeMap::from([
            ("meta:issued".into(), json!(0)),
            ("model:current".into(), json!(hex::encode([0; 32]))),
        ])
    }

    #[test]
    fn session_state_and_receipts_equal_existing_complete_builder() {
        let state = initial();
        let cfg = Config::installed().unwrap();
        let old_root = root(&state).unwrap();
        let mut session = ExecutionSession::new(state.clone(), old_root, cfg.clone()).unwrap();
        for height in 1..=8 {
            let expected = execute(
                session.state(),
                &[],
                height,
                [1; 32],
                [height as u8; 32],
                4,
                &cfg,
            )
            .unwrap();
            let observed = session
                .execute(
                    (session.sequence(), session.root()),
                    &[],
                    height,
                    [1; 32],
                    [height as u8; 32],
                    4,
                )
                .unwrap();
            assert_eq!(observed.root, expected.root);
            assert_eq!(observed.receipts, expected.receipts);
            assert_eq!(session.state(), &expected.state);
            assert_eq!(session.sequence(), height);
        }
        assert_eq!(root(&state).unwrap(), old_root);
    }

    #[test]
    fn invalid_context_transaction_and_sequence_never_publish_session_state() {
        let state = initial();
        let old_root = root(&state).unwrap();
        let mut session =
            ExecutionSession::new(state.clone(), old_root, Config::installed().unwrap()).unwrap();
        assert_eq!(
            session
                .execute((99, old_root), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_PREDECESSOR"
        );
        assert_eq!(
            session
                .execute((0, [9; 32]), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_PREDECESSOR"
        );
        assert!(session
            .execute((0, old_root), &[vec![0; 159]], 1, [1; 32], [2; 32], 8)
            .is_err());
        assert_eq!(session.sequence(), 0);
        assert_eq!(session.root(), old_root);
        assert_eq!(session.state(), &state);
        session.sequence = u64::MAX;
        assert_eq!(
            session
                .execute((u64::MAX, old_root), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_SEQUENCE"
        );
        assert_eq!(session.state(), &state);
    }
}

#[cfg(test)]
mod streaming_root_tests {
    use super::*;
    use trnm_protocol::pon_wire::state_root;

    fn original(state: &State) -> Result<Hash> {
        let mut bytes = BTreeMap::new();
        for (key, value) in state {
            bytes.insert(key.as_bytes().to_vec(), canonical(value)?);
        }
        state_root(&bytes).map_err(|_| "LIMIT")
    }

    #[test]
    fn streamed_m06_root_keeps_complete_canonical_value_errors_before_wire_limits() {
        for bad in [json!(0.5), json!(-0.0), json!("λ"), json!({"bad": ["λ"]})] {
            let values = State::from([("a".repeat(161), json!(0)), ("z".into(), bad)]);
            assert_eq!(root(&values), original(&values));
            assert_ne!(root(&values), Err("LIMIT"));
        }
        let mut over: State = (0..65_537)
            .map(|i| (format!("k-{i:06}"), Value::Null))
            .collect();
        assert_eq!(root(&over), Err("LIMIT"));
        over.insert("zz-last".into(), json!(false));
        assert_eq!(root(&over), original(&over));
        over.insert("zz-last".into(), json!(["λ"]));
        assert_eq!(root(&over), original(&over));
        assert_eq!(root(&over), Err("NONCANONICAL"));
    }

    #[test]
    fn streamed_m06_root_matches_original_values_removals_and_branch_edits() {
        let initial: State = (0..257)
            .map(|i| {
                (
                    format!("key-{i:04}"),
                    json!({"nonce": i, "array": [null, false, "ascii"], "negative": -1}),
                )
            })
            .collect();
        let frozen = initial.clone();
        for count in [0, 1, 16, 31, 129, 257] {
            let mut state: State = initial
                .iter()
                .take(count)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            assert_eq!(root(&state), original(&state));
            state.insert("key-0000".into(), Value::Null);
            state.remove("key-0015");
            state.insert("first".into(), json!(u64::MAX));
            assert_eq!(root(&state), original(&state));
        }
        assert_eq!(initial, frozen);
        for size in [4094, 4095] {
            let state = State::from([("payload".into(), json!("x".repeat(size)))]);
            assert_eq!(root(&state), original(&state));
        }
    }

    #[test]
    #[ignore = "explicit paired complete-root cost; synthetic values, not native ledger growth"]
    fn complete_root_encoding_cost() {
        // One selected implementation per process keeps the measured RSS from
        // inheriting the other implementation's peak. The caller must compare
        // complete roots, source/binary identity and all failures across runs.
        let implementation = std::env::var("TRNM_ROOT_ENCODING_IMPLEMENTATION")
            .expect("select original or streamed explicitly");
        assert!(matches!(implementation.as_str(), "original" | "streamed"));
        let state: State = (0..16_384)
            .map(|i| (format!("root-cost-{i:05}"), json!("x".repeat(4094))))
            .collect();
        let start = std::time::Instant::now();
        let result = if implementation == "original" {
            original(std::hint::black_box(&state))
        } else {
            root(std::hint::black_box(&state))
        };
        let elapsed_ns = start.elapsed().as_nanos();
        // Equality between the two implementations is checked by the separate
        // paired caller and the non-ignored independent reference regressions.
        // This output cannot attest process RSS, source or whole-Node capacity.
        let digest = result.expect("complete root must actually finish");
        println!(
            "{}",
            json!({
                "schema": "pon-complete-root-encoding-cost-v1",
                "implementation": implementation,
                "state_keys": state.len(),
                "value_encoding_bytes": 4096,
                "root": hex::encode(digest),
                "root_wall_ns": elapsed_ns,
                "native_ledger_admission": false,
                "end_to_end_throughput": false,
                "production_activation": false
            })
        );
    }
}
