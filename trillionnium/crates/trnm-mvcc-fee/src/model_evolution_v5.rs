//! Explicit complete-model evolution for a bounded three-expert integer family.
//! Joint base/router/expert updates are admitted against actual branch state.
//! The expert mask is a small executable graph, not arbitrary topology or code.
//! Evaluation remains the fixed public retrospective v3 material and controlled
//! quorum. Neither repeated rounds nor this profile imply fresh-data governance.
use crate::integer_factor_candidate_v2::{self as factor, FactorState, IntegerModelV2};
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::sync::OnceLock;
use trnm_protocol::integer_evolution_v3::{EvolutionOperationV3, EvolutionWitnessV3};
use trnm_protocol::integer_factor_v2::{COLUMNS, ROWS};
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "linear-model-evolution-dev-v5";
pub const REVISION: u64 = 16;
const POLICY: &str = include_str!("../../../../config/pon/model-evolution-v5.json");

fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE
}
fn policy_hash() -> Result<Hash> {
    static HASH: OnceLock<Result<Hash>> = OnceLock::new();
    *HASH.get_or_init(|| {
        let policy: Value = serde_json::from_str(POLICY).map_err(|_| "EVOLUTION_CONFIG")?;
        for (key, expected) in [
            ("schema", json!("native-integer-model-evolution-v5")),
            ("profile", json!(PROFILE)),
            ("consensus_revision", json!(REVISION)),
            ("admission_tag", json!(24)),
            ("witness_encoding", json!("ILF3")),
            ("artifact_encoding", json!("ILM3")),
            ("artifact_exact_bytes", json!(factor::EVOLUTION_MODEL_BYTES)),
            (
                "targets",
                json!(["base", "router", "expert0", "expert1", "expert2"]),
            ),
            ("max_operations", json!(3)),
            ("max_rank_per_operation", json!(2)),
            ("max_rank_sum", json!(3)),
            ("coefficient_min", json!(-32767)),
            ("coefficient_max", json!(32767)),
            (
                "numeric",
                json!("exact-integer-BA-add-no-rounding-scale1024-v3"),
            ),
            ("graph", json!("nonempty-three-bit-enabled-experts-mask")),
            ("release", json!("one-self-allocation-native-positive-gain")),
            (
                "contribution_identity",
                json!("author-context-parent-full-model-update-round-excludes-allocation-root"),
            ),
            ("empirical_material", json!("model-evidence-v3.json")),
            (
                "evaluation_policy",
                json!("native-public-evaluation-quorum-dev-v2"),
            ),
            ("base_fee_units", json!(240)),
            ("fresh_dataset_activation", json!(false)),
            ("arbitrary_topology", json!(false)),
            ("independent_governance_accepted", json!(false)),
            ("prospective_accepted", json!(false)),
            ("public_reward_eligible", json!(false)),
            ("production_activation", json!(false)),
        ] {
            check(policy[key] == expected, "EVOLUTION_CONFIG")?;
        }
        Ok(hash(
            b"native-model-evolution-policy-v5",
            &[&canonical(&policy)?],
        ))
    })
}
pub(crate) fn install(params: &mut Value) -> Result<()> {
    crate::model_evidence_v3::install(params)?;
    params["model_evolution_policy_hash"] = json!(hex::encode(policy_hash()?));
    Ok(())
}
pub(crate) fn check_context(cfg: &Config) -> Result<()> {
    check(
        enabled(cfg)
            && crate::public_evaluation::quorum_enabled(cfg)
            && cfg.params["consensus_revision"] == REVISION
            && cfg.params["model_evolution_policy_hash"] == hex::encode(policy_hash()?),
        "EVOLUTION_PROFILE",
    )
}
pub fn source_key(round: u64, source: Hash) -> String {
    format!("model-source-v5:{round}:{}", hex::encode(source))
}
pub(crate) fn evidence_key(cid: Hash) -> String {
    format!("model-evidence-v5:{}", hex::encode(cid))
}
pub fn evidence(state: &State, cid: Hash) -> Result<Value> {
    state
        .get(&evidence_key(cid))
        .cloned()
        .ok_or("MODEL_EVIDENCE_MISSING")
}
/// Resolve current release to complete, hash-checked ILM3 bytes in this branch.
pub fn current_model(state: &State, cfg: &Config) -> Result<IntegerModelV2> {
    check_context(cfg)?;
    Ok(factor::parent(&mut ReadState(state), cfg)?.1)
}

struct ReadState<'a>(&'a State);
impl FactorState for ReadState<'_> {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.0.get(key).cloned()
    }
    fn put(&mut self, _: String, _: Value) {
        unreachable!("read-only builder")
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.0
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}
struct Derived {
    model: IntegerModelV2,
    update: Hash,
}
fn derive(s: &mut impl FactorState, cfg: &Config, w: &EvolutionWitnessV3) -> Result<Derived> {
    check_context(cfg)?;
    check(w.family == cfg.family, "EVOLUTION_FAMILY")?;
    w.encode().map_err(|_| "EVOLUTION_ENCODING")?;
    let (reference, parent) = factor::parent(s, cfg)?;
    check(
        w.parent_ref == reference && w.parent_artifact == parent.id(),
        "EVOLUTION_PARENT",
    )?;
    let mut coefficients = parent.coefficients().to_vec();
    for operation in &w.operations {
        let rank = usize::from(operation.rank);
        let offset = usize::from(operation.target) * ROWS * COLUMNS;
        let mut nonzero = false;
        for row in 0..ROWS {
            for column in 0..COLUMNS {
                let mut delta = 0_i64;
                for k in 0..rank {
                    let b = i64::from(operation.factors[row * rank + k]);
                    let a = i64::from(operation.factors[ROWS * rank + k * COLUMNS + column]);
                    delta = b
                        .checked_mul(a)
                        .and_then(|p| delta.checked_add(p))
                        .ok_or("EVOLUTION_ARITHMETIC")?;
                }
                check((-32767..=32767).contains(&delta), "EVOLUTION_DELTA_RANGE")?;
                nonzero |= delta != 0;
                let index = offset + row * COLUMNS + column;
                let next = i64::from(coefficients[index])
                    .checked_add(delta)
                    .ok_or("EVOLUTION_ARITHMETIC")?;
                check((-32767..=32767).contains(&next), "EVOLUTION_MODEL_RANGE")?;
                coefficients[index] = next as i16;
            }
        }
        check(nonzero, "EVOLUTION_NOOP_OPERATION")?;
    }
    let model =
        IntegerModelV2::from_evolution_coefficients(cfg.family, coefficients, w.active_experts)?;
    check(model != parent, "EVOLUTION_NOOP")?;
    // Normalize by complete resulting bytes, so equivalent factor bases, ranks,
    // authors and allocation-root choices cannot mint another update in this window.
    let update = hash(
        b"integer-linear-model-update-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &cfg.family,
            &reference,
            &parent.id(),
            &w.round.to_le_bytes(),
            &model.encode(),
        ],
    );
    Ok(Derived { model, update })
}
/// Allocation root is signed in ILF3 but omitted from this fresh identity to avoid
/// the self-leaf circularity. Native tag8 verifies exactly this candidate/owner/score.
pub fn contribution_id(cfg: &Config, sender: Hash, w: &EvolutionWitnessV3) -> Hash {
    hash(
        b"integer-evolution-contribution-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &sender,
            &w.family,
            &w.parent_ref,
            &w.parent_artifact,
            &w.candidate_artifact,
            &w.update_id,
            &w.round.to_le_bytes(),
        ],
    )
}
/// Producer helper. Native tag24 independently loads the same current parent and
/// recomputes all coefficients, model identity, normalized update and evidence.
pub fn build_witness(
    state: &State,
    cfg: &Config,
    sender: Hash,
    round: u64,
    active_experts: u8,
    operations: Vec<EvolutionOperationV3>,
    components_root: Hash,
) -> Result<EvolutionWitnessV3> {
    let mut s = ReadState(state);
    let (parent_ref, parent) = factor::parent(&mut s, cfg)?;
    let mut w = EvolutionWitnessV3 {
        active_experts,
        family: cfg.family,
        parent_ref,
        parent_artifact: parent.id(),
        candidate_artifact: [0; 32],
        update_id: [0; 32],
        contribution_id: [0; 32],
        components_root,
        round,
        operations,
    };
    let derived = derive(&mut s, cfg, &w)?;
    w.candidate_artifact = derived.model.id();
    w.update_id = derived.update;
    w.contribution_id = contribution_id(cfg, sender, &w);
    Ok(w)
}
pub(crate) fn admit(
    s: &mut impl FactorState,
    cfg: &Config,
    sender: Hash,
    height: u64,
    w: &EvolutionWitnessV3,
) -> Result<Value> {
    check(
        w.round
            == height
                / cfg.params["candidate_round_blocks"]
                    .as_u64()
                    .ok_or("CONFIG")?,
        "SUBMISSION_ROUND",
    )?;
    let derived = derive(s, cfg, w)?;
    check(
        w.candidate_artifact == derived.model.id()
            && w.update_id == derived.update
            && w.contribution_id == contribution_id(cfg, sender, w),
        "EVOLUTION_COMPUTED_HASH",
    )?;
    let key = format!("linear-update-v3:{}", hex::encode(w.update_id));
    let metadata = json!({"schema":"integer-model-update-v3","parent":hex::encode(w.parent_ref),
        "parent_artifact":hex::encode(w.parent_artifact),"round":w.round,
        "family":hex::encode(cfg.family),"artifact":hex::encode(w.candidate_artifact)});
    if let Some(previous) = s.get(&key) {
        check(previous == metadata, "EVOLUTION_UPDATE_COLLISION")?;
        let stored = factor::load_model(s, w.candidate_artifact, cfg.family)?;
        check(stored == derived.model, "EVOLUTION_UPDATE_COLLISION")?;
        return Err("DUPLICATE_FUNCTION_UPDATE");
    }
    factor::store_model(s, &derived.model)?;
    s.put(key, metadata);
    Ok(
        json!({"owner":hex::encode(sender),"artifact":hex::encode(w.candidate_artifact),
        "artifact_bytes":factor::EVOLUTION_MODEL_BYTES,"components_root":hex::encode(w.components_root),
        "family":hex::encode(cfg.family),"parent":hex::encode(w.parent_ref),"votes":{},"score":0,
        "status":"submitted","submitted_height":height,"submission_round":w.round,
        "evolution_profile":PROFILE,"factor_parent_artifact":hex::encode(w.parent_artifact),
        "function_update_id":hex::encode(w.update_id),"active_experts":w.active_experts}),
    )
}
pub(crate) fn cleanup(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let current = state.get("model:current").cloned().ok_or("FACTOR_PARENT")?;
    let round = height
        / cfg.params["candidate_round_blocks"]
            .as_u64()
            .ok_or("CONFIG")?;
    state.retain(|key, value| {
        !key.starts_with("linear-update-v3:")
            || (value["parent"] == current && value["round"] == round)
    });
    Ok(())
}
