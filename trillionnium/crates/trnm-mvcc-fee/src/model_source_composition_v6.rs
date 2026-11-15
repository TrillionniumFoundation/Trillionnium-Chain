//! Known-source complete-update aggregation in a fresh development context.
//! Historical V4 remains unchanged. The installed source/payee map is an
//! explicit assumption, not a Sybil detector or independent utility evidence.
use crate::integer_factor_candidate_v2::{self as factor, FactorState, IntegerModelV2};
use crate::model_composition_v4::CheckedComponent;
use crate::model_evidence_v3 as empirical;
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "linear-factor-source-composition-dev-v6";
pub const REVISION: u64 = 18;
pub const MAX_COMPONENTS: usize = 4;
pub const SCALE: u64 = 1_000_000;
const POLICY: &str = include_str!("../../../../config/pon/model-source-composition-v6.json");
const RECORD_PREFIX: &str = "model-source-composition-v6:";
const RECORD_SCHEMA: &str = "native-model-source-composition-record-v6";
const REFERENCE_SCHEMA: &str = "native-model-source-composition-reference-v6";

fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key].as_u64().ok_or("MODEL_SOURCE_STATE")
}
fn identity(value: &Value, key: &str) -> Result<Hash> {
    let text = value[key].as_str().ok_or("MODEL_SOURCE_STATE")?;
    check(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "MODEL_SOURCE_STATE",
    )?;
    let mut result = [0; 32];
    hex::decode_to_slice(text, &mut result).map_err(|_| "MODEL_SOURCE_STATE")?;
    Ok(result)
}
struct Installed {
    hash: Hash,
    payees: BTreeMap<Hash, Hash>,
}
fn installed() -> Result<&'static Installed> {
    static POLICY_VALUE: OnceLock<Result<Installed>> = OnceLock::new();
    POLICY_VALUE.get_or_init(|| {
        let value: Value = serde_json::from_str(POLICY).map_err(|_| "MODEL_SOURCE_CONFIG")?;
        let fields = [
            ("schema", json!("native-integer-model-source-composition-v6")),
            ("profile", json!(PROFILE)), ("consensus_revision", json!(REVISION)),
            ("empirical_material", json!("model-evidence-v3.json")),
            ("component_min", json!(2)), ("component_max", json!(MAX_COMPONENTS)),
            ("source_min", json!(2)), ("source_max", json!(MAX_COMPONENTS)),
            ("aggregation", json!("complete-parent-relative-update-before-source-omission-and-allocation")),
            ("subset_rule", json!("reject-any-subset-of-two-or-more-known-sources-with-exact-zero-full-parent-relative-sum")),
            ("evaluation", json!("complete-native-source-aggregate-and-leave-source-out-no-error-to-zero")),
            ("bundle_gate", json!("strictly-better-than-parent-frozen-controls-and-every-source-aggregate")),
            ("source_weight", json!("floor-positive-leave-source-out-correct-count-gain-times-scale-over-task-count")),
            ("score_scale", json!(SCALE)),
            ("allocation", json!("one-positive-leaf-at-smallest-contribution-id-owned-by-authorized-source-payee-all-other-leaves-zero")),
            ("payout", json!("one-floor-per-source-budget-times-source-weight-over-total-source-weight")),
            ("dust", json!("original-release-deadline-refund")),
            ("source_budget", json!("original-installed-source-round-intake-and-actual-payout-caps")),
            ("production_activation", json!(false)), ("prospective_accepted", json!(false)),
            ("independent_accepted", json!(false)), ("unknown_common_control_discovered", json!(false)),
            ("public_reward_eligible", json!(false)), ("shapley_fairness_accepted", json!(false)),
        ];
        check(value.as_object().is_some_and(|v| v.len() == fields.len() + 1), "MODEL_SOURCE_CONFIG")?;
        for (key, expected) in fields { check(value[key] == expected, "MODEL_SOURCE_CONFIG")?; }
        let empirical_policy = empirical::installed_policy()?;
        let sources = empirical_policy["sources"].as_array().ok_or("MODEL_SOURCE_CONFIG")?;
        let known: BTreeSet<_> = sources.iter().map(|v| identity(v, "source")).collect::<Result<_>>()?;
        let mut payees = BTreeMap::new();
        for entry in value["source_payees"].as_array().ok_or("MODEL_SOURCE_CONFIG")? {
            check(entry.as_object().is_some_and(|v| v.len() == 2), "MODEL_SOURCE_CONFIG")?;
            let source = identity(entry, "source")?;
            let payee = identity(entry, "payee")?;
            check(sources.iter().any(|v| v["source"] == entry["source"] && v["author"] == entry["payee"]), "MODEL_SOURCE_PAYEE")?;
            check(payees.insert(source, payee).is_none(), "MODEL_SOURCE_PAYEE")?;
        }
        check(payees.keys().copied().collect::<BTreeSet<_>>() == known, "MODEL_SOURCE_PAYEE")?;
        Ok(Installed { hash: hash(b"native-model-source-composition-policy-v6", &[&canonical(&value)?]), payees })
    }).as_ref().map_err(|e| *e)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE
}
pub(crate) fn install(params: &mut Value) -> Result<()> {
    empirical::install(params)?;
    params["model_source_composition_policy_hash"] = json!(hex::encode(installed()?.hash));
    Ok(())
}
pub(crate) fn check_context(cfg: &Config) -> Result<()> {
    check(
        enabled(cfg)
            && cfg.params["model_source_composition_policy_hash"] == hex::encode(installed()?.hash),
        "MODEL_SOURCE_PROFILE",
    )
}
pub fn source_key(round: u64, source: Hash) -> String {
    format!("model-source-v6:{round}:{}", hex::encode(source))
}
pub fn composition_key(bundle_id: Hash) -> String {
    format!("{RECORD_PREFIX}{}", hex::encode(bundle_id))
}
pub(crate) fn evidence_key(cid: Hash) -> String {
    format!("model-evidence-v6:{}", hex::encode(cid))
}
pub fn evidence(state: &State, cid: Hash) -> Result<Value> {
    state
        .get(&evidence_key(cid))
        .cloned()
        .ok_or("MODEL_EVIDENCE_MISSING")
}

/// Original tag8/9 shapes, with independent V6 commitment domains. `release:`
/// stays the monetary owner prefix so original maturity/refund/accounting run.
pub fn allocation_leaf(cfg: &Config, cid: Hash, payee: Hash, weight: u64) -> Hash {
    hash(
        b"source-allocation-leaf-v6",
        &[
            &cfg.network,
            &cfg.parameters,
            &cid,
            &payee,
            &weight.to_le_bytes(),
        ],
    )
}
pub fn pair(a: Hash, b: Hash) -> Hash {
    if a <= b {
        hash(b"source-allocation-node-v6", &[&a, &b])
    } else {
        hash(b"source-allocation-node-v6", &[&b, &a])
    }
}
pub fn allocation_root(mut leaves: Vec<Hash>) -> Result<Hash> {
    check(
        !leaves.is_empty() && leaves.len() <= MAX_COMPONENTS,
        "MODEL_SOURCE_COUNT",
    )?;
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().ok_or("MODEL_SOURCE_COUNT")?);
        }
        leaves = leaves.chunks_exact(2).map(|p| pair(p[0], p[1])).collect();
    }
    Ok(leaves[0])
}
pub fn release_id(
    cfg: &Config,
    parent: Hash,
    bundle: Hash,
    budget: u64,
    root: Hash,
    total: u64,
) -> Hash {
    hash(
        b"source-release-v6",
        &[
            &cfg.network,
            &cfg.parameters,
            &parent,
            &bundle,
            &budget.to_le_bytes(),
            &root,
            &total.to_le_bytes(),
        ],
    )
}
fn checked_digest(record: &Value) -> Result<Hash> {
    check(record["schema"] == RECORD_SCHEMA, "MODEL_SOURCE_RECORD")?;
    let digest = identity(record, "digest")?;
    let mut unsigned = record.clone();
    unsigned
        .as_object_mut()
        .ok_or("MODEL_SOURCE_RECORD")?
        .remove("digest");
    check(
        digest
            == hash(
                b"native-model-source-composition-record-v6",
                &[&canonical(&unsigned)?],
            ),
        "MODEL_SOURCE_RECORD_DIGEST",
    )?;
    Ok(digest)
}

/// The full evidence has its own state row, leaving room for all original
/// component claims in the monetary row under the unchanged 4096-byte limit.
pub(crate) fn reference(record: &Value) -> Result<Value> {
    let digest = checked_digest(record)?;
    Ok(json!({
        "schema": REFERENCE_SCHEMA,
        "record_key": composition_key(identity(record, "bundle")?),
        "policy": hex::encode(identity(record, "policy")?),
        "digest": hex::encode(digest),
    }))
}

fn reference_key(reference: &Value) -> Result<&str> {
    check(
        reference.as_object().is_some_and(|v| v.len() == 4)
            && reference["schema"] == REFERENCE_SCHEMA,
        "MODEL_SOURCE_RECORD_REFERENCE",
    )?;
    identity(reference, "policy")?;
    identity(reference, "digest")?;
    let key = reference["record_key"]
        .as_str()
        .ok_or("MODEL_SOURCE_RECORD_REFERENCE")?;
    let suffix = key
        .strip_prefix(RECORD_PREFIX)
        .ok_or("MODEL_SOURCE_RECORD_REFERENCE")?;
    check(
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "MODEL_SOURCE_RECORD_REFERENCE",
    )?;
    Ok(key)
}

pub(crate) fn check_release(cfg: &Config, release: &Value) -> Result<()> {
    let is_v6 = release["model_profile"] == PROFILE;
    check(enabled(cfg) == is_v6, "MODEL_SOURCE_RELEASE_PROFILE")?;
    if is_v6 {
        check_context(cfg)?;
        let reference = &release["model_composition_v6"];
        check(
            release["schema"] == "native-model-source-release-v6"
                && release["network"] == hex::encode(cfg.network)
                && release["parameters"] == hex::encode(cfg.parameters)
                && release["allocation_domain"] == "source-allocation-v6"
                && reference["policy"] == hex::encode(installed()?.hash)
                && reference_key(reference)? == composition_key(identity(release, "bundle")?),
            "MODEL_SOURCE_RELEASE_PROFILE",
        )?;
    } else {
        check(
            release.get("model_composition_v6").is_none()
                && release["schema"] != "native-model-source-release-v6"
                && release["allocation_domain"] != "source-allocation-v6",
            "MODEL_SOURCE_RELEASE_PROFILE",
        )?;
    }
    Ok(())
}

pub(crate) fn check_record(cfg: &Config, release: &Value, record: &Value) -> Result<()> {
    check_context(cfg)?;
    check_release(cfg, release)?;
    check(
        reference(record)? == release["model_composition_v6"],
        "MODEL_SOURCE_RECORD_REFERENCE",
    )?;
    for (key, expected) in [
        ("network", cfg.network),
        ("parameters", cfg.parameters),
        ("family", cfg.family),
        ("plan", cfg.plan),
        ("policy", installed()?.hash),
        ("tasks", identity(&cfg.params, "model_evidence_tasks_hash")?),
    ] {
        check(
            identity(record, key)? == expected,
            "MODEL_SOURCE_RECORD_CONTEXT",
        )?;
    }
    for key in ["bundle", "artifact", "family", "parent"] {
        check(
            identity(record, key)? == identity(release, key)?,
            "MODEL_SOURCE_RECORD_CONTEXT",
        )?;
    }
    identity(record, "parent_artifact")?;
    number(record, "round")?;
    number(record, "slot")?;
    for key in [
        "prospective_accepted",
        "independent_accepted",
        "public_reward_eligible",
        "unknown_common_control_discovered",
        "shapley_fairness_accepted",
    ] {
        check(record[key] == false, "MODEL_SOURCE_RECORD")?;
    }
    let rows = number(record, "rows")?;
    let correct = number(record, "correct")?;
    let strongest = number(record, "strongest_correct")?;
    check(
        record["evaluation_status"] == "complete-scored"
            && rows > 0
            && number(record, "observed_rows")? == rows
            && correct <= rows
            && correct > strongest,
        "MODEL_SOURCE_EVALUATION_INCOMPLETE",
    )?;
    let sources = record["sources"].as_array().ok_or("MODEL_SOURCE_RECORD")?;
    check(
        (2..=MAX_COMPONENTS).contains(&sources.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    let mut seen_sources = BTreeSet::new();
    let mut seen_components = BTreeSet::new();
    let mut total_weight = 0_u64;
    for source in sources {
        let source_id = identity(source, "source")?;
        let payee = identity(source, "payee")?;
        check(
            seen_sources.insert(source_id) && installed()?.payees.get(&source_id) == Some(&payee),
            "MODEL_SOURCE_PAYEE",
        )?;
        identity(source, "aggregate_artifact")?;
        identity(source, "without_artifact")?;
        let aggregate_correct = number(source, "aggregate_correct")?;
        let without_correct = number(source, "without_correct")?;
        check(
            aggregate_correct <= strongest && without_correct < correct,
            "MODEL_SOURCE_GAIN",
        )?;
        let weight = number(source, "weight")?;
        check(
            weight > 0
                && weight
                    == (correct - without_correct)
                        .checked_mul(SCALE)
                        .ok_or("MODEL_SOURCE_RANGE")?
                        / rows,
            "MODEL_SOURCE_WEIGHT",
        )?;
        total_weight = total_weight
            .checked_add(weight)
            .ok_or("MODEL_SOURCE_RANGE")?;
        let components = source["components"]
            .as_array()
            .ok_or("MODEL_SOURCE_RECORD")?;
        check(!components.is_empty(), "MODEL_SOURCE_COUNT")?;
        let representative = source["representative"].clone();
        identity(source, "representative")?;
        check(components.contains(&representative), "MODEL_SOURCE_PAYEE")?;
        for component in components {
            let id = identity(&json!({"id": component}), "id")?;
            check(seen_components.insert(id), "MODEL_SOURCE_ORDER")?;
        }
    }
    check(
        (2..=MAX_COMPONENTS).contains(&seen_components.len())
            && number(release, "leaf_count")? == seen_components.len() as u64
            && number(record, "total_weight")? == total_weight
            && number(release, "total")? == total_weight
            && number(record, "zero_source_subset_checks")?
                == (1_u64 << sources.len()) - sources.len() as u64 - 1,
        "MODEL_SOURCE_RECORD_CONTEXT",
    )
}

/// Collect every live release reference before deleting anything. A malformed
/// reference fails closed, including when another release still owns the row.
pub(crate) fn cleanup(state: &mut State) -> Result<()> {
    let mut referenced = BTreeSet::new();
    for (_, release) in state
        .range("release:".to_owned()..)
        .take_while(|(key, _)| key.starts_with("release:"))
    {
        if let Some(reference) = release.get("model_composition_v6") {
            let key = reference_key(reference)?;
            check(
                key == composition_key(identity(release, "bundle")?),
                "MODEL_SOURCE_RECORD_REFERENCE",
            )?;
            referenced.insert(key.to_owned());
        } else {
            check(
                release["model_profile"] != PROFILE,
                "MODEL_SOURCE_RECORD_REFERENCE",
            )?;
        }
    }
    let obsolete: Vec<_> = state
        .range(RECORD_PREFIX.to_owned()..)
        .take_while(|(key, _)| key.starts_with(RECORD_PREFIX))
        .filter(|(key, _)| !referenced.contains(*key))
        .map(|(key, _)| key.clone())
        .collect();
    for key in obsolete {
        state.remove(&key);
    }
    Ok(())
}

/// A complete zero score is distinct from a model that cannot run or an
/// evaluation that did not complete. Only the native complete variant can pay.
#[derive(Debug)]
pub enum EvaluationOutcome {
    CompleteScored {
        artifact: Hash,
        rows: u64,
        observed_rows: u64,
        correct: u64,
    },
    NotExecutable {
        reason: &'static str,
    },
    Incomplete {
        reason: &'static str,
    },
}
impl EvaluationOutcome {
    fn complete(&self, expected_rows: u64) -> Result<(Hash, u64, u64)> {
        match self {
            Self::CompleteScored {
                artifact,
                rows,
                observed_rows,
                correct,
            } => {
                check(
                    *rows == expected_rows
                        && *observed_rows == *rows
                        && *rows > 0
                        && *correct <= *rows,
                    "MODEL_SOURCE_EVALUATION_INCOMPLETE",
                )?;
                Ok((*artifact, *observed_rows, *correct))
            }
            Self::NotExecutable { .. } => Err("MODEL_SOURCE_NOT_EXECUTABLE"),
            Self::Incomplete { .. } => Err("MODEL_SOURCE_EVALUATION_INCOMPLETE"),
        }
    }
}
fn evaluate(cfg: &Config, model: Result<IntegerModelV2>) -> EvaluationOutcome {
    let model = match model {
        Ok(model) => model,
        Err(reason) => return EvaluationOutcome::NotExecutable { reason },
    };
    match empirical::complete_model_evaluation(cfg, &model) {
        Ok((rows, correct)) => EvaluationOutcome::CompleteScored {
            artifact: model.id(),
            rows,
            observed_rows: rows,
            correct,
        },
        Err(reason) => EvaluationOutcome::Incomplete { reason },
    }
}
/// All included deltas have the same full parent. Intermediate sums stay i64;
/// every complete aggregate and ablation must fit the original executable ILM2.
fn derive(
    family: Hash,
    parent: &IntegerModelV2,
    models: &[IntegerModelV2],
    included: &[usize],
) -> Result<IntegerModelV2> {
    let mut coefficients = Vec::with_capacity(parent.coefficients().len());
    for (coordinate, &base) in parent.coefficients().iter().enumerate() {
        let mut value = i64::from(base);
        for &index in included {
            let model = models.get(index).ok_or("MODEL_SOURCE_COUNT")?;
            let delta = i64::from(model.coefficients()[coordinate])
                .checked_sub(i64::from(base))
                .ok_or("MODEL_SOURCE_RANGE")?;
            value = value.checked_add(delta).ok_or("MODEL_SOURCE_RANGE")?;
        }
        check((-32767..=32767).contains(&value), "MODEL_SOURCE_RANGE")?;
        coefficients.push(i16::try_from(value).map_err(|_| "MODEL_SOURCE_RANGE")?);
    }
    IntegerModelV2::from_coefficients(family, coefficients)
}
fn reject_redundant_sources(
    parent: &IntegerModelV2,
    models: &[IntegerModelV2],
    groups: &BTreeMap<Hash, Vec<usize>>,
) -> Result<u64> {
    let groups: Vec<_> = groups.values().collect();
    check(
        (2..=MAX_COMPONENTS).contains(&groups.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    let mut checked = 0;
    for mask in 0_u32..(1 << groups.len()) {
        if mask.count_ones() < 2 {
            continue;
        }
        checked += 1;
        let mut zero = true;
        for (coordinate, &base) in parent.coefficients().iter().enumerate() {
            let mut delta = 0_i64;
            for (source_index, indices) in groups.iter().enumerate() {
                if mask & (1 << source_index) != 0 {
                    for &index in indices.iter() {
                        delta = delta
                            .checked_add(
                                i64::from(models[index].coefficients()[coordinate])
                                    - i64::from(base),
                            )
                            .ok_or("MODEL_SOURCE_RANGE")?;
                    }
                }
            }
            if delta != 0 {
                zero = false;
                break;
            }
        }
        check(!zero, "MODEL_SOURCE_REDUNDANT_SUBSET")?;
    }
    Ok(checked)
}
pub(crate) fn validate(
    state: &mut impl FactorState,
    cfg: &Config,
    bundle_id: Hash,
    bundle: &Value,
    bundle_evidence: &Value,
    components: &[CheckedComponent<'_>],
) -> Result<Value> {
    check_context(cfg)?;
    check(
        (2..=MAX_COMPONENTS).contains(&components.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    check(
        components.windows(2).all(|w| w[0].id < w[1].id)
            && components.iter().all(|c| c.id != bundle_id),
        "MODEL_SOURCE_ORDER",
    )?;
    let (parent_ref, parent) = factor::parent(state, cfg)?;
    check(
        identity(bundle, "parent")? == parent_ref
            && identity(bundle, "factor_parent_artifact")? == parent.id(),
        "MODEL_SOURCE_PARENT",
    )?;
    let actual = factor::load_model(state, identity(bundle, "artifact")?, cfg.family)?;
    // The source-bound empirical owner already recomputed the full bundle and
    // every component at adoption. Repeat complete derived-model inference here.
    let (_, rows, correct) =
        evaluate(cfg, Ok(actual.clone())).complete(number(bundle_evidence, "rows")?)?;
    check(
        correct == number(bundle_evidence, "candidate_correct")?,
        "MODEL_SOURCE_EVIDENCE",
    )?;
    let mut models = Vec::with_capacity(components.len());
    let mut groups = BTreeMap::<Hash, Vec<usize>>::new();
    for (index, component) in components.iter().enumerate() {
        for name in [
            "parent",
            "factor_parent_artifact",
            "family",
            "submission_round",
            "slot",
        ] {
            check(
                component.contribution[name] == bundle[name],
                "MODEL_SOURCE_PARENT",
            )?;
        }
        check(
            number(&component.evidence, "rows")? == rows,
            "MODEL_SOURCE_EVIDENCE",
        )?;
        let source = empirical::source(cfg, identity(component.contribution, "owner")?)?;
        check(
            component.contribution["model_evidence_v6"]["source"] == hex::encode(source),
            "MODEL_EVIDENCE_SOURCE",
        )?;
        groups.entry(source).or_default().push(index);
        models.push(factor::load_model(
            state,
            identity(component.contribution, "artifact")?,
            cfg.family,
        )?);
    }
    check(
        (2..=MAX_COMPONENTS).contains(&groups.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    let all: Vec<_> = (0..models.len()).collect();
    check(
        derive(cfg.family, &parent, &models, &all)? == actual,
        "MODEL_SOURCE_DERIVATION",
    )?;
    let zero_source_subset_checks = reject_redundant_sources(&parent, &models, &groups)?;
    let mut strongest = number(bundle_evidence, "strongest_correct")?;
    let mut measured = Vec::with_capacity(groups.len());
    let mut total_weight = 0_u64;
    for (source, indices) in &groups {
        let payee = *installed()?
            .payees
            .get(source)
            .ok_or("MODEL_SOURCE_PAYEE")?;
        let representative = indices
            .iter()
            .copied()
            .find(|&i| components[i].contribution["owner"] == hex::encode(payee))
            .ok_or("MODEL_SOURCE_PAYEE")?;
        let (aggregate_artifact, _, aggregate_correct) =
            evaluate(cfg, derive(cfg.family, &parent, &models, indices)).complete(rows)?;
        strongest = strongest.max(aggregate_correct);
        let without_indices: Vec<_> = all
            .iter()
            .copied()
            .filter(|i| !indices.contains(i))
            .collect();
        let (without_artifact, _, without_correct) =
            evaluate(cfg, derive(cfg.family, &parent, &models, &without_indices)).complete(rows)?;
        check(correct > without_correct, "MODEL_SOURCE_MARGINAL")?;
        let weight = (correct - without_correct)
            .checked_mul(SCALE)
            .ok_or("MODEL_SOURCE_RANGE")?
            / rows;
        check(weight > 0, "MODEL_SOURCE_WEIGHT")?;
        for &i in indices {
            check(
                components[i].weight == if i == representative { weight } else { 0 },
                "MODEL_SOURCE_WEIGHT",
            )?;
        }
        total_weight = total_weight
            .checked_add(weight)
            .ok_or("MODEL_SOURCE_RANGE")?;
        measured.push(json!({
            "source": hex::encode(source), "payee": hex::encode(payee),
            "representative": hex::encode(components[representative].id),
            "components": indices.iter().map(|&i|hex::encode(components[i].id)).collect::<Vec<_>>(),
            "aggregate_artifact": hex::encode(aggregate_artifact),
            "aggregate_correct": aggregate_correct,
            "without_artifact": hex::encode(without_artifact),
            "without_correct": without_correct, "weight": weight,
        }));
    }
    check(correct > strongest, "MODEL_SOURCE_GAIN")?;
    let mut result = json!({
        "schema": RECORD_SCHEMA,
        "network": hex::encode(cfg.network), "parameters": hex::encode(cfg.parameters),
        "family": hex::encode(cfg.family), "plan": hex::encode(cfg.plan),
        "policy": hex::encode(installed()?.hash), "bundle": hex::encode(bundle_id),
        "artifact": hex::encode(actual.id()), "parent": hex::encode(parent_ref),
        "parent_artifact": hex::encode(parent.id()), "round": bundle["submission_round"],
        "slot": bundle["slot"], "rows": rows, "observed_rows": rows,
        "evaluation_status": "complete-scored", "correct": correct,
        "strongest_correct": strongest, "sources": measured, "total_weight": total_weight,
        "prospective_accepted": false, "independent_accepted": false,
        "public_reward_eligible": false, "unknown_common_control_discovered": false,
        "shapley_fairness_accepted": false,
    });
    result["tasks"] = bundle_evidence["tasks"].clone();
    result["zero_source_subset_checks"] = json!(zero_source_subset_checks);
    result["digest"] = json!(hex::encode(hash(
        b"native-model-source-composition-record-v6",
        &[&canonical(&result)?]
    )));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model(value: i16) -> IntegerModelV2 {
        let mut coefficients = vec![0; 3855];
        coefficients[1542] = value;
        IntegerModelV2::from_coefficients([7; 32], coefficients).unwrap()
    }
    #[test]
    fn source_aggregation_counts_nonzero_parent_once_for_every_partition() {
        let parent = model(10);
        let models = [model(23), model(0), model(8)];
        assert_eq!(
            derive([7; 32], &parent, &models, &[0, 1]).unwrap(),
            model(13)
        );
        assert_eq!(
            derive([7; 32], &parent, &models, &[0, 1, 2]).unwrap(),
            model(11)
        );
        assert_eq!(derive([7; 32], &parent, &models, &[2]).unwrap(), model(8));
        assert_eq!(derive([7; 32], &parent, &models, &[]).unwrap(), parent);
    }
    #[test]
    fn unexecutable_ablation_and_incomplete_evaluation_are_never_zero_scores() {
        let mut cfg = Config::installed_with_model_profiles(
            crate::public_evaluation::PROFILE,
            crate::continuity_v1::PROFILE,
            PROFILE,
        )
        .unwrap();
        let native = IntegerModelV2::genesis(cfg.family);
        let completed = evaluate(&cfg, Ok(native.clone()));
        assert!(completed.complete(25).is_ok());
        assert_eq!(
            completed.complete(24),
            Err("MODEL_SOURCE_EVALUATION_INCOMPLETE")
        );
        cfg.params["model_evidence_tasks_hash"] = json!(hex::encode([0; 32]));
        let failed = evaluate(&cfg, Ok(native));
        assert!(matches!(
            failed,
            EvaluationOutcome::Incomplete {
                reason: "MODEL_EVIDENCE_PROFILE"
            }
        ));
        assert_eq!(
            failed.complete(25),
            Err("MODEL_SOURCE_EVALUATION_INCOMPLETE")
        );
        assert_eq!(
            derive(
                [7; 32],
                &model(20_000),
                &[model(32_000), model(32_000), model(2_000)],
                &[0, 1]
            ),
            Err("MODEL_SOURCE_RANGE")
        );
        assert_eq!(
            EvaluationOutcome::NotExecutable {
                reason: "MODEL_SOURCE_RANGE"
            }
            .complete(25),
            Err("MODEL_SOURCE_NOT_EXECUTABLE")
        );
        assert_eq!(
            EvaluationOutcome::Incomplete { reason: "missing" }.complete(25),
            Err("MODEL_SOURCE_EVALUATION_INCOMPLETE")
        );
        let complete = EvaluationOutcome::CompleteScored {
            artifact: [0; 32],
            rows: 25,
            observed_rows: 25,
            correct: 0,
        };
        assert_eq!(complete.complete(25), Ok(([0; 32], 25, 0)));
        assert_eq!(
            complete.complete(24),
            Err("MODEL_SOURCE_EVALUATION_INCOMPLETE")
        );
        assert_eq!(
            EvaluationOutcome::CompleteScored {
                artifact: [0; 32],
                rows: 25,
                observed_rows: 24,
                correct: 0
            }
            .complete(25),
            Err("MODEL_SOURCE_EVALUATION_INCOMPLETE")
        );
    }

    #[test]
    fn whole_source_and_legal_split_have_identical_aggregates_and_ablations() {
        let parent = model(10);
        let whole = [model(13), model(8)];
        let split = [model(23), model(0), model(8)];
        for (whole_indices, split_indices) in [
            (vec![0, 1], vec![0, 1, 2]),
            (vec![0], vec![0, 1]),
            (vec![1], vec![2]),
        ] {
            assert_eq!(
                derive([7; 32], &parent, &whole, &whole_indices).unwrap(),
                derive([7; 32], &parent, &split, &split_indices).unwrap(),
            );
        }
        let groups = BTreeMap::from([([1; 32], vec![0, 1]), ([2; 32], vec![2])]);
        assert_eq!(reject_redundant_sources(&parent, &split, &groups), Ok(1));
        // A third useful source cannot hide a cancelling pair of complete
        // source updates, even when one of those sources has two components.
        let cancelling = [model(23), model(0), model(7), model(8)];
        let groups = BTreeMap::from([
            ([1; 32], vec![0, 1]),
            ([2; 32], vec![2]),
            ([3; 32], vec![3]),
        ]);
        assert_eq!(
            reject_redundant_sources(&parent, &cancelling, &groups),
            Err("MODEL_SOURCE_REDUNDANT_SUBSET"),
        );
    }

    #[test]
    fn separate_record_and_fully_claimed_release_fit_with_headroom_and_live_references_survive() {
        let policy = installed().unwrap();
        // This revision installs three known sources; a changed installation
        // must requalify the bound rather than inherit this acceptance.
        assert_eq!(policy.payees.len(), 3);
        let h = hex::encode([0xaa; 32]);
        let ids: Vec<_> = (1_u8..=4).map(|id| hex::encode([id; 32])).collect();
        let sources: Vec<_> = policy
            .payees
            .iter()
            .enumerate()
            .map(|(i, (source, payee))| {
                let components = if i == 0 {
                    ids[..2].to_vec()
                } else {
                    vec![ids[i + 1].clone()]
                };
                json!({
                    "source": hex::encode(source), "payee": hex::encode(payee),
                    "representative": components[0], "components": components,
                    "aggregate_artifact": h, "aggregate_correct": u64::MAX,
                    "without_artifact": h, "without_correct": u64::MAX,
                    "weight": u64::MAX,
                })
            })
            .collect();
        // Deliberately maximize every numeric field, even bounded task counts.
        // This is a wire-size upper bound, not admissible evaluation evidence.
        let mut record = json!({
            "schema": RECORD_SCHEMA, "network": h, "parameters": h, "family": h,
            "plan": h, "policy": hex::encode(policy.hash), "bundle": h, "artifact": h,
            "parent": h, "parent_artifact": h, "round": u64::MAX, "slot": u64::MAX,
            "rows": u64::MAX, "observed_rows": u64::MAX,
            "evaluation_status": "complete-scored", "correct": u64::MAX,
            "strongest_correct": u64::MAX, "sources": sources, "total_weight": u64::MAX,
            "prospective_accepted": false, "independent_accepted": false,
            "public_reward_eligible": false, "unknown_common_control_discovered": false,
            "shapley_fairness_accepted": false, "tasks": h,
            "zero_source_subset_checks": u64::MAX,
        });
        record["digest"] = json!(hex::encode(hash(
            b"native-model-source-composition-record-v6",
            &[&canonical(&record).unwrap()],
        )));
        let record_ref = reference(&record).unwrap();
        let mut claims = serde_json::Map::new();
        for id in &ids {
            claims.insert(id.clone(), json!(u64::MAX));
        }
        let release = json!({
            "owner": h, "remaining": u64::MAX, "budget": u64::MAX, "total": u64::MAX,
            "root": h, "maturity": u64::MAX, "bundle": h, "artifact": h, "family": h,
            "components_root": h, "parent": h, "leaf_count": u64::MAX, "claims": claims,
            "deadline": u64::MAX, "status": "open", "schema": "native-model-source-release-v6",
            "model_profile": PROFILE, "network": h, "parameters": h,
            "allocation_domain": "source-allocation-v6", "model_composition_v6": record_ref,
        });
        let record_bytes = canonical(&record).unwrap().len();
        let release_bytes = canonical(&release).unwrap().len();
        assert!(record_bytes <= 4096 - 512, "record size: {record_bytes}");
        assert!(release_bytes <= 4096 - 512, "release size: {release_bytes}");
        let record_key = composition_key([0xaa; 32]);
        assert!(record_key.len() <= 160);
        let release_key = format!("release:{}", hex::encode([0xbb; 32]));
        let mut state = State::from([
            (record_key.clone(), record.clone()),
            (release_key.clone(), release.clone()),
        ]);
        crate::pon_executor::root(&state).unwrap();
        let mut tampered = record.clone();
        tampered["correct"] = json!(u64::MAX - 1);
        assert_eq!(reference(&tampered), Err("MODEL_SOURCE_RECORD_DIGEST"));
        cleanup(&mut state).unwrap();
        assert!(state.contains_key(&record_key));

        let other_release = format!("release:{}", hex::encode([0xcc; 32]));
        let orphan = composition_key([0xdd; 32]);
        state.insert(orphan.clone(), record);
        let mut malformed = release.clone();
        malformed["model_composition_v6"]
            .as_object_mut()
            .unwrap()
            .remove("record_key");
        state.insert(other_release.clone(), malformed);
        assert_eq!(cleanup(&mut state), Err("MODEL_SOURCE_RECORD_REFERENCE"));
        assert!(state.contains_key(&orphan));
        state.insert(other_release.clone(), release);
        cleanup(&mut state).unwrap();
        assert!(!state.contains_key(&orphan));
        state.remove(&release_key);
        cleanup(&mut state).unwrap();
        assert!(state.contains_key(&record_key));
        state.remove(&other_release);
        cleanup(&mut state).unwrap();
        assert!(!state.contains_key(&record_key));
    }
}
