//! Native empirical evidence and known-source budgets for one explicit integer family.
//! This replays a fixed public retrospective dataset. It proves neither prospective
//! benefit nor source independence, training provenance, demand, or mining hardness.
use crate::integer_factor_candidate_v2::{self as factor, FactorState, IntegerModelV2};
use crate::model_composition_v4 as composition;
use crate::pon_executor::{canonical, Config, Result, State};
use crate::public_evaluation;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "linear-factor-evidence-dev-v3";
pub const REVISION: u64 = 13;
pub const MAX_INTAKES: u64 = 4;
pub const MAX_RESERVED_UNITS: u64 = 100_000;
pub const MAX_CANDIDATES: u64 = 16;
const SCALE: u64 = 1_000_000;
const POLICY: &str = include_str!("../../../../config/pon/model-evidence-v3.json");

fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn n(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().ok_or("MODEL_EVIDENCE_STATE")
}
fn h(s: &str) -> Result<Hash> {
    check(
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "MODEL_EVIDENCE_HASH",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| "MODEL_EVIDENCE_HASH")?;
    Ok(out)
}
fn vh(v: &Value, key: &str) -> Result<Hash> {
    h(v[key].as_str().ok_or("MODEL_EVIDENCE_STATE")?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Task {
    id: String,
    source_group: String,
    source_path: String,
    source_content_sha256: String,
    label: usize,
    features: Vec<i16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    role: String,
    legacy_artifact: String,
    coefficients_le_i16_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    author: String,
    source: String,
}
struct Installed {
    value: Value,
    tasks: Vec<Task>,
    controls: Vec<Control>,
    sources: Vec<Source>,
    policy_hash: Hash,
    tasks_hash: Hash,
}
fn installed() -> Result<&'static Installed> {
    static VALUE: OnceLock<Result<Installed>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            let value: Value = serde_json::from_str(POLICY).map_err(|_| "MODEL_EVIDENCE_CONFIG")?;
            for (key, expected) in [
                ("schema", json!("native-integer-model-evidence-v3")),
                ("profile", json!(PROFILE)),
                ("consensus_revision", json!(REVISION)),
                (
                    "metric",
                    json!("equal-source-group-accuracy-with-one-row-per-group-v3"),
                ),
                ("score_scale", json!(SCALE)),
                ("minimum_gain_score", json!(1)),
                ("max_intakes_per_source_round", json!(MAX_INTAKES)),
                (
                    "max_reserved_units_per_source_round",
                    json!(MAX_RESERVED_UNITS),
                ),
                ("max_candidates_per_round", json!(MAX_CANDIDATES)),
                (
                    "review_policy",
                    json!("pre-adoption-participant-objection-aborts-candidate-v3"),
                ),
                ("production_activation", json!(false)),
                ("prospective_accepted", json!(false)),
                ("independent_accepted", json!(false)),
                ("public_reward_eligible", json!(false)),
            ] {
                check(value[key] == expected, "MODEL_EVIDENCE_CONFIG")?;
            }
            let tasks: Vec<Task> = serde_json::from_value(value["tasks"].clone())
                .map_err(|_| "MODEL_EVIDENCE_CONFIG")?;
            let controls: Vec<Control> = serde_json::from_value(value["controls"].clone())
                .map_err(|_| "MODEL_EVIDENCE_CONFIG")?;
            let sources: Vec<Source> = serde_json::from_value(value["sources"].clone())
                .map_err(|_| "MODEL_EVIDENCE_CONFIG")?;
            check(
                (1..=32).contains(&tasks.len())
                    && controls.len() == 4
                    && (1..=16).contains(&sources.len()),
                "MODEL_EVIDENCE_CONFIG",
            )?;
            let mut ids = BTreeSet::new();
            let mut groups = BTreeSet::new();
            let mut content = BTreeSet::new();
            for task in &tasks {
                check(
                    ids.insert(h(&task.id)?) && groups.insert(h(&task.source_group)?),
                    "MODEL_EVIDENCE_TASK_ALIAS",
                )?;
                check(
                    content.insert(h(&task.source_content_sha256)?),
                    "MODEL_EVIDENCE_TASK_ALIAS",
                )?;
                check(
                    hex::encode(Sha256::digest(task.source_path.as_bytes())) == task.source_group,
                    "MODEL_EVIDENCE_TASK",
                )?;
                check(
                    !task.source_path.is_empty()
                        && task.source_path.len() <= 256
                        && task.source_path.is_ascii()
                        && task.label < 3
                        && task.features.len() == 257
                        && task.features.iter().all(|x| (-8..=8).contains(x))
                        && task.features[256] == 8,
                    "MODEL_EVIDENCE_TASK",
                )?;
            }
            for (control, role) in
                controls
                    .iter()
                    .zip(["current", "best_single", "mean_merge", "pooled"])
            {
                check(control.role == role, "MODEL_EVIDENCE_CONTROL")?;
                h(&control.legacy_artifact)?;
                control_model(control, [0; 32])?;
            }
            let mut authors = BTreeSet::new();
            for source in &sources {
                check(authors.insert(h(&source.author)?), "MODEL_EVIDENCE_SOURCE")?;
                h(&source.source)?;
            }
            let policy_hash = hash(b"native-model-evidence-policy-v3", &[&canonical(&value)?]);
            let tasks_hash = hash(
                b"native-model-evidence-tasks-v3",
                &[&canonical(&value["tasks"])?],
            );
            Ok(Installed {
                value,
                tasks,
                controls,
                sources,
                policy_hash,
                tasks_hash,
            })
        })
        .as_ref()
        .map_err(|e| *e)
}
fn control_model(control: &Control, family: Hash) -> Result<IntegerModelV2> {
    let hex = &control.coefficients_le_i16_hex;
    check(
        hex.len() == 3 * 257 * 5 * 4
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "MODEL_EVIDENCE_CONTROL",
    )?;
    let raw = hex::decode(hex).map_err(|_| "MODEL_EVIDENCE_CONTROL")?;
    let coefficients = raw
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    IntegerModelV2::from_coefficients(family, coefficients)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE || composition::enabled(cfg)
}
pub(crate) fn install(params: &mut Value) -> Result<()> {
    let policy = installed()?;
    params["model_evidence_policy_hash"] = json!(hex::encode(policy.policy_hash));
    params["model_evidence_tasks_hash"] = json!(hex::encode(policy.tasks_hash));
    params["max_model_candidates"] = json!(MAX_CANDIDATES);
    params["max_candidate_history_per_round"] = json!(MAX_CANDIDATES);
    Ok(())
}
fn check_context(cfg: &Config) -> Result<&'static Installed> {
    let p = installed()?;
    check(
        enabled(cfg)
            && cfg.params["model_evidence_policy_hash"] == hex::encode(p.policy_hash)
            && cfg.params["model_evidence_tasks_hash"] == hex::encode(p.tasks_hash),
        "MODEL_EVIDENCE_PROFILE",
    )?;
    if composition::enabled(cfg) {
        composition::check_context(cfg)?;
    }
    Ok(p)
}
pub(crate) fn controls(cfg: &Config) -> Result<Vec<IntegerModelV2>> {
    check_context(cfg)?
        .controls
        .iter()
        .map(|c| control_model(c, cfg.family))
        .collect()
}
fn source(cfg: &Config, author: Hash) -> Result<Hash> {
    let author = hex::encode(author);
    let entry = check_context(cfg)?
        .sources
        .iter()
        .find(|s| s.author == author)
        .ok_or("MODEL_EVIDENCE_SOURCE")?;
    h(&entry.source)
}
pub fn source_key(round: u64, source: Hash) -> String {
    format!("model-source-v3:{round}:{}", hex::encode(source))
}
fn evidence_key(cid: Hash) -> String {
    format!("model-evidence-v3:{}", hex::encode(cid))
}
fn context_evidence_key(cfg: &Config, cid: Hash) -> String {
    if composition::enabled(cfg) {
        composition::evidence_key(cid)
    } else {
        evidence_key(cid)
    }
}
fn context_source_key(cfg: &Config, round: u64, source: Hash) -> String {
    if composition::enabled(cfg) {
        composition::source_key(round, source)
    } else {
        source_key(round, source)
    }
}
fn metadata_key(cfg: &Config) -> &'static str {
    if composition::enabled(cfg) {
        "model_evidence_v4"
    } else {
        "model_evidence_v3"
    }
}
fn correct(model: &IntegerModelV2, tasks: &[Task]) -> Result<u64> {
    let coefficients = model.coefficients();
    let dot = |weights: &[i16], x: &[i16]| -> Result<i64> {
        weights.iter().zip(x).try_fold(0_i64, |sum, (&w, &x)| {
            sum.checked_add(i64::from(w) * i64::from(x))
                .ok_or("MODEL_EVIDENCE_ARITHMETIC")
        })
    };
    let argmax = |values: [i64; 3]| -> usize {
        let mut best = 0;
        for i in 1..3 {
            if values[i] > values[best] {
                best = i;
            }
        }
        best
    };
    let mut count = 0;
    for task in tasks {
        let mut router = [0; 3];
        for (i, score) in router.iter_mut().enumerate() {
            *score = dot(
                &coefficients[771 + i * 257..771 + (i + 1) * 257],
                &task.features,
            )?;
        }
        let slot = argmax(router);
        let mut logits = [0; 3];
        for (i, score) in logits.iter_mut().enumerate() {
            let start = (2 + slot) * 771 + i * 257;
            *score = dot(&coefficients[i * 257..(i + 1) * 257], &task.features)?
                .checked_add(dot(&coefficients[start..start + 257], &task.features)?)
                .ok_or("MODEL_EVIDENCE_ARITHMETIC")?;
        }
        count += u64::from(argmax(logits) == task.label);
    }
    Ok(count)
}
pub(crate) fn model_correct(cfg: &Config, model: &IntegerModelV2) -> Result<u64> {
    correct(model, &check_context(cfg)?.tasks)
}
fn record(
    s: &mut impl FactorState,
    cfg: &Config,
    cid: Hash,
    contribution: &Value,
) -> Result<Value> {
    let policy = check_context(cfg)?;
    let artifact = vh(contribution, "artifact")?;
    let parent = vh(contribution, "factor_parent_artifact")?;
    let candidate_model = factor::load_model(s, artifact, cfg.family)?;
    let parent_model = factor::load_model(s, parent, cfg.family)?;
    let candidate_correct = correct(&candidate_model, &policy.tasks)?;
    let parent_correct = correct(&parent_model, &policy.tasks)?;
    let mut strongest = parent_correct;
    let mut control_records = Vec::new();
    for control in &policy.controls {
        let expected = control_model(control, cfg.family)?;
        let actual = factor::load_model(s, expected.id(), cfg.family)?;
        let control_correct = correct(&actual, &policy.tasks)?;
        strongest = strongest.max(control_correct);
        control_records.push(json!({"role":control.role,"artifact":hex::encode(actual.id()),"correct":control_correct}));
    }
    let count = policy.tasks.len() as u64;
    let score = candidate_correct
        .saturating_sub(strongest)
        .checked_mul(SCALE)
        .ok_or("MODEL_EVIDENCE_ARITHMETIC")?
        / count;
    let mut result = json!({"schema":"native-integer-model-evidence-record-v3","network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),"family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),"policy":hex::encode(policy.policy_hash),"tasks":hex::encode(policy.tasks_hash),"contribution":hex::encode(cid),"candidate":hex::encode(artifact),"parent":hex::encode(parent),"rows":count,"candidate_correct":candidate_correct,"parent_correct":parent_correct,"controls":control_records,"strongest_correct":strongest,"score":score,"scope":"exact-public-retrospective-integer-dataset-only","prospective_accepted":false,"independent_accepted":false,"public_reward_eligible":false});
    let domain: &[u8] = if composition::enabled(cfg) {
        result["schema"] = json!("native-integer-model-evidence-record-v4");
        result["composition_policy"] = cfg.params["model_composition_policy_hash"].clone();
        b"native-model-empirical-record-v4"
    } else {
        b"native-model-empirical-record-v3"
    };
    let digest = hash(domain, &[&canonical(&result)?]);
    result["digest"] = json!(hex::encode(digest));
    Ok(result)
}
/// Inspect the native evidence already retained in branch state. No scoring authority.
pub fn evidence(state: &State, cid: Hash) -> Result<Value> {
    state
        .get(&evidence_key(cid))
        .cloned()
        .ok_or("MODEL_EVIDENCE_MISSING")
}
pub(crate) fn admit(
    s: &mut impl FactorState,
    cfg: &Config,
    cid: Hash,
    contribution: &mut Value,
) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let admitted_source = source(cfg, vh(contribution, "owner")?)?;
    let round = n(contribution, "submission_round")?;
    let key = context_source_key(cfg, round, admitted_source);
    let schema = if composition::enabled(cfg) {
        "native-model-source-budget-v4"
    } else {
        "native-model-source-budget-v3"
    };
    let mut quota = s.get(&key).unwrap_or_else(|| json!({"schema":schema,"source":hex::encode(admitted_source),"round":round,"intakes":0,"reserved_units":0}));
    check(
        n(&quota, "intakes")? < MAX_INTAKES,
        "MODEL_EVIDENCE_SOURCE_LIMIT",
    )?;
    let result = record(s, cfg, cid, contribution)?;
    let domain: &[u8] = if composition::enabled(cfg) {
        b"native-model-source-root-work-v4"
    } else {
        b"native-model-source-root-work-v3"
    };
    let root_work = hash(
        domain,
        &[
            &cfg.network,
            &cfg.parameters,
            &round.to_le_bytes(),
            &admitted_source,
        ],
    );
    contribution[metadata_key(cfg)] = json!({"digest":result["digest"],"score":result["score"],"source":hex::encode(admitted_source),"root_work":hex::encode(root_work)});
    check(
        s.get(&context_evidence_key(cfg, cid)).is_none(),
        "MODEL_EVIDENCE_DUPLICATE",
    )?;
    quota["intakes"] = json!(n(&quota, "intakes")? + 1);
    s.put(key, quota);
    s.put(context_evidence_key(cfg, cid), result);
    Ok(())
}
pub(crate) fn check_reveal(
    cfg: &Config,
    contribution: &Value,
    value: &public_evaluation::Reveal,
) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    check(
        value.score == n(&contribution[metadata_key(cfg)], "score")?
            && value.evidence == vh(&contribution[metadata_key(cfg)], "digest")?,
        "MODEL_EVIDENCE_REVEAL",
    )
}
fn adoption(
    s: &mut impl FactorState,
    cfg: &Config,
    cid: Hash,
    contribution: &Value,
    require_gain: bool,
) -> Result<Value> {
    let actual = record(s, cfg, cid, contribution)?;
    check(
        s.get(&context_evidence_key(cfg, cid)) == Some(actual.clone())
            && actual["digest"] == contribution[metadata_key(cfg)]["digest"]
            && actual["score"] == contribution["score"],
        "MODEL_EVIDENCE_BINDING",
    )?;
    if require_gain {
        check(n(&actual, "score")? > 0, "MODEL_EVIDENCE_GAIN")?;
    }
    let rows = s.scan(&public_evaluation::record_prefix(cid));
    let evaluation = public_evaluation::hydrate(&contribution["public_evaluation"], cid, &rows)?;
    let start = n(&evaluation["plan"], "adoption_start")?;
    let appeals = evaluation["appeals"]
        .as_object()
        .ok_or("MODEL_EVIDENCE_STATE")?;
    for appeal in appeals.values() {
        check(n(appeal, "height")? >= start, "MODEL_EVIDENCE_REVIEW_HOLD")?;
    }
    Ok(actual)
}
/// Reserve actual payout amounts once at release, across all known author aliases.
/// Caps are per installed source and round, not per account, parent, or leaf nonce.
pub(crate) fn reserve_release(
    s: &mut impl FactorState,
    cfg: &Config,
    bundle_id: Hash,
    bundle: &Value,
    allocations: &[(Hash, Value, u64)],
    budget: u64,
    total: u64,
) -> Result<Option<Value>> {
    if !enabled(cfg) {
        return Ok(None);
    }
    let bundle_evidence = adoption(s, cfg, bundle_id, bundle, true)?;
    check(total > 0, "MODEL_EVIDENCE_GAIN")?;
    let mut checked = Vec::with_capacity(allocations.len());
    if composition::enabled(cfg) {
        for (cid, contribution, weight) in allocations {
            let evidence = adoption(s, cfg, *cid, contribution, false)?;
            checked.push(composition::CheckedComponent {
                id: *cid,
                contribution,
                weight: *weight,
                evidence,
            });
        }
    }
    let composition_record = if composition::enabled(cfg) {
        Some(composition::validate(
            s,
            cfg,
            bundle_id,
            bundle,
            &bundle_evidence,
            &checked,
        )?)
    } else {
        None
    };
    let mut additions = BTreeMap::<String, u64>::new();
    for (cid, contribution, score) in allocations {
        if !composition::enabled(cfg) {
            adoption(s, cfg, *cid, contribution, true)?;
        }
        let admitted_source = source(cfg, vh(contribution, "owner")?)?;
        check(
            contribution[metadata_key(cfg)]["source"] == hex::encode(admitted_source),
            "MODEL_EVIDENCE_SOURCE",
        )?;
        let round = n(contribution, "submission_round")?;
        check(
            round == n(bundle, "submission_round")?,
            "MODEL_EVIDENCE_SOURCE",
        )?;
        let amount = u64::try_from(u128::from(budget) * u128::from(*score) / u128::from(total))
            .map_err(|_| "MODEL_EVIDENCE_ARITHMETIC")?;
        let entry = additions
            .entry(context_source_key(cfg, round, admitted_source))
            .or_default();
        *entry = entry
            .checked_add(amount)
            .ok_or("MODEL_EVIDENCE_ARITHMETIC")?;
    }
    for (key, amount) in additions {
        let mut quota = s.get(&key).ok_or("MODEL_EVIDENCE_SOURCE")?;
        let reserved = n(&quota, "reserved_units")?
            .checked_add(amount)
            .ok_or("MODEL_EVIDENCE_ARITHMETIC")?;
        check(
            reserved <= MAX_RESERVED_UNITS,
            "MODEL_EVIDENCE_SOURCE_BUDGET",
        )?;
        quota["reserved_units"] = json!(reserved);
        s.put(key, quota);
    }
    Ok(composition_record)
}
pub(crate) fn cleanup(state: &mut State, cfg: &Config, height: u64) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let round = height / n(&cfg.params, "candidate_round_blocks")?;
    let (source_prefix, evidence_prefix) = if composition::enabled(cfg) {
        ("model-source-v4:", "model-evidence-v4:")
    } else {
        ("model-source-v3:", "model-evidence-v3:")
    };
    let removed: Vec<_> = state
        .iter()
        .filter_map(|(key, value)| {
            if key.starts_with(source_prefix) {
                (value["round"] != round).then(|| key.clone())
            } else if let Some(cid) = key.strip_prefix(evidence_prefix) {
                (!state.contains_key(&format!("contribution:{cid}"))
                    && !state.contains_key(&format!("evaluation-archive:{cid}")))
                .then(|| key.clone())
            } else {
                None
            }
        })
        .collect();
    for key in removed {
        state.remove(&key);
    }
    Ok(())
}
/// Immutable development policy for offline readers; native acceptance uses installed bytes.
pub fn installed_policy() -> Result<Value> {
    Ok(installed()?.value.clone())
}
