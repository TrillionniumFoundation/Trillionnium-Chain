//! Exact bounded composition and leave-one-out allocation for a fresh context.
//! The data and controls remain public retrospective material, not generalization
//! or Shapley fairness evidence. Complete models, not producer predictions, are used.
use crate::integer_factor_candidate_v2::{self as factor, FactorState, IntegerModelV2};
use crate::model_evidence_v3 as empirical;
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::sync::OnceLock;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "linear-factor-composition-dev-v4";
pub const REVISION: u64 = 14;
pub const MAX_COMPONENTS: usize = 4;
pub const SCALE: u64 = 1_000_000;
const POLICY: &str = include_str!("../../../../config/pon/model-composition-v4.json");

fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key].as_u64().ok_or("MODEL_COMPOSITION_STATE")
}
fn identity(value: &Value, key: &str) -> Result<Hash> {
    let value = value[key].as_str().ok_or("MODEL_COMPOSITION_STATE")?;
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "MODEL_COMPOSITION_STATE",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "MODEL_COMPOSITION_STATE")?;
    Ok(out)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE
}
fn policy_hash() -> Result<Hash> {
    static HASH: OnceLock<Result<Hash>> = OnceLock::new();
    *HASH.get_or_init(|| {
        let p: Value = serde_json::from_str(POLICY).map_err(|_| "MODEL_COMPOSITION_CONFIG")?;
        for (key, expected) in [
            ("schema", json!("native-integer-model-composition-v4")),
            ("profile", json!(PROFILE)),
            ("consensus_revision", json!(REVISION)),
            ("empirical_material", json!("model-evidence-v3.json")),
            ("component_min", json!(2)),
            ("component_max", json!(MAX_COMPONENTS)),
            ("component_order", json!("strict-ascending-contribution-id")),
            (
                "parent_rule",
                json!("same-current-reference-full-artifact-family-round-and-slot"),
            ),
            (
                "derivation",
                json!("parent-plus-exact-sum-of-component-minus-parent"),
            ),
            (
                "subset_rule",
                json!("reject-any-subset-of-two-or-more-with-exact-zero-full-parent-relative-sum"),
            ),
            (
                "integer_rule",
                json!("checked-i64-accumulation-final-i16-minus32767-through32767-no-rounding"),
            ),
            (
                "representation",
                json!("existing-ILF2-single-slot-rank-one-or-two-no-approximation"),
            ),
            (
                "bundle_gate",
                json!("strictly-better-than-parent-frozen-controls-and-every-component"),
            ),
            (
                "component_gate",
                json!("complete-native-evaluation-and-positive-leave-one-out-weight"),
            ),
            (
                "weight_rule",
                json!(
                    "floor-positive-leave-one-out-correct-count-gain-times-scale-over-task-count"
                ),
            ),
            ("score_scale", json!(SCALE)),
            (
                "payout_rule",
                json!("floor-budget-times-weight-over-sum-of-weights"),
            ),
            ("dust_rule", json!("existing-release-deadline-refund")),
            (
                "source_budget_rule",
                json!("existing-installed-source-map-cap-actual-floor-payouts"),
            ),
            ("admission_tag", json!(8)),
            ("production_activation", json!(false)),
            ("prospective_accepted", json!(false)),
            ("independent_accepted", json!(false)),
            ("public_reward_eligible", json!(false)),
            ("shapley_fairness_accepted", json!(false)),
        ] {
            check(p[key] == expected, "MODEL_COMPOSITION_CONFIG")?;
        }
        Ok(hash(
            b"native-model-composition-policy-v4",
            &[&canonical(&p)?],
        ))
    })
}
pub(crate) fn install(params: &mut Value) -> Result<()> {
    empirical::install(params)?;
    params["model_composition_policy_hash"] = json!(hex::encode(policy_hash()?));
    Ok(())
}
pub(crate) fn check_context(cfg: &Config) -> Result<()> {
    check(
        enabled(cfg) && cfg.params["model_composition_policy_hash"] == hex::encode(policy_hash()?),
        "MODEL_COMPOSITION_PROFILE",
    )
}
pub fn source_key(round: u64, source: Hash) -> String {
    format!("model-source-v4:{round}:{}", hex::encode(source))
}
pub(crate) fn evidence_key(cid: Hash) -> String {
    format!("model-evidence-v4:{}", hex::encode(cid))
}
/// Read the retained empirical record; composition qualification happens at tag8.
pub fn evidence(state: &State, cid: Hash) -> Result<Value> {
    state
        .get(&evidence_key(cid))
        .cloned()
        .ok_or("MODEL_EVIDENCE_MISSING")
}
/// A component is not individually promoted. A complete zero empirical score may
/// enter a bundle only if exact ablation later establishes a positive marginal.
pub(crate) fn component_allowed(evaluation: &Value, height: u64) -> Result<()> {
    check(
        height >= number(&evaluation["plan"], "adoption_start")?
            && evaluation["closed"]["status"] == "complete-scored"
            && evaluation["closed"]["score"].as_u64().is_some()
            && evaluation["conflicts"]
                .as_object()
                .ok_or("MODEL_COMPOSITION_STATE")?
                .is_empty(),
        "PUBLIC_EVAL_ADOPTION",
    )
}

pub(crate) struct CheckedComponent<'a> {
    pub id: Hash,
    pub contribution: &'a Value,
    pub weight: u64,
    pub evidence: Value,
}

/// Sum actual full-model deltas with a single common parent. No weighted merge,
/// averaging, clipping, factor-basis comparison, or intermediate quantization.
fn derive(
    family: Hash,
    parent: &IntegerModelV2,
    components: &[IntegerModelV2],
    omit: Option<usize>,
) -> Result<IntegerModelV2> {
    let mut result = Vec::with_capacity(parent.coefficients().len());
    for (coordinate, &base) in parent.coefficients().iter().enumerate() {
        let mut next = i64::from(base);
        for (i, component) in components.iter().enumerate() {
            if omit != Some(i) {
                let delta = i64::from(component.coefficients()[coordinate])
                    .checked_sub(i64::from(base))
                    .ok_or("MODEL_COMPOSITION_RANGE")?;
                next = next.checked_add(delta).ok_or("MODEL_COMPOSITION_RANGE")?;
            }
        }
        check((-32767..=32767).contains(&next), "MODEL_COMPOSITION_RANGE")?;
        result.push(i16::try_from(next).map_err(|_| "MODEL_COMPOSITION_RANGE")?);
    }
    IntegerModelV2::from_coefficients(family, result)
}

/// Reject exactly cancelling groups, not approximately equivalent predictions.
/// At most eleven subsets of two or more components are checked. Each coordinate
/// sums at most four differences in [-65534, 65534], still using checked i64.
fn reject_redundant_subsets(parent: &IntegerModelV2, components: &[IntegerModelV2]) -> Result<u64> {
    check(
        (2..=MAX_COMPONENTS).contains(&components.len()),
        "MODEL_COMPOSITION_COUNT",
    )?;
    let mut checked = 0;
    for mask in 0_u32..(1_u32 << components.len()) {
        if mask.count_ones() < 2 {
            continue;
        }
        checked += 1;
        let mut zero = true;
        for (coordinate, &base) in parent.coefficients().iter().enumerate() {
            let mut sum = 0_i64;
            for (index, component) in components.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    let delta = i64::from(component.coefficients()[coordinate])
                        .checked_sub(i64::from(base))
                        .ok_or("MODEL_COMPOSITION_RANGE")?;
                    sum = sum.checked_add(delta).ok_or("MODEL_COMPOSITION_RANGE")?;
                }
            }
            if sum != 0 {
                zero = false;
                break;
            }
        }
        check(!zero, "MODEL_COMPOSITION_REDUNDANT_SUBSET")?;
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
        "MODEL_COMPOSITION_COUNT",
    )?;
    check(
        components.windows(2).all(|pair| pair[0].id < pair[1].id)
            && components.iter().all(|component| component.id != bundle_id),
        "MODEL_COMPOSITION_ORDER",
    )?;
    let parent_id = identity(bundle, "factor_parent_artifact")?;
    let (current_ref, current_model) = factor::parent(state, cfg)?;
    check(
        identity(bundle, "parent")? == current_ref && parent_id == current_model.id(),
        "MODEL_COMPOSITION_PARENT",
    )?;
    let actual_bundle = factor::load_model(state, identity(bundle, "artifact")?, cfg.family)?;
    let mut models = Vec::with_capacity(components.len());
    let mut strongest = number(bundle_evidence, "strongest_correct")?;
    for component in components {
        for name in [
            "parent",
            "factor_parent_artifact",
            "family",
            "submission_round",
        ] {
            check(
                component.contribution[name] == bundle[name],
                "MODEL_COMPOSITION_PARENT",
            )?;
        }
        check(
            component.contribution["slot"] == bundle["slot"],
            "MODEL_COMPOSITION_SLOT",
        )?;
        strongest = strongest.max(number(&component.evidence, "candidate_correct")?);
        models.push(factor::load_model(
            state,
            identity(component.contribution, "artifact")?,
            cfg.family,
        )?);
    }
    let zero_subset_checks = reject_redundant_subsets(&current_model, &models)?;
    let derived = derive(cfg.family, &current_model, &models, None)?;
    check(derived == actual_bundle, "MODEL_COMPOSITION_DERIVATION")?;
    let correct = number(bundle_evidence, "candidate_correct")?;
    check(correct > strongest, "MODEL_COMPOSITION_GAIN")?;
    let rows = number(bundle_evidence, "rows")?;
    check(rows > 0, "MODEL_COMPOSITION_STATE")?;
    let mut total = 0_u64;
    let mut measured = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        let without = derive(cfg.family, &current_model, &models, Some(index))?;
        let without_correct = empirical::model_correct(cfg, &without)?;
        check(correct > without_correct, "MODEL_COMPOSITION_MARGINAL")?;
        let weight = (correct - without_correct)
            .checked_mul(SCALE)
            .ok_or("MODEL_COMPOSITION_RANGE")?
            / rows;
        check(
            weight > 0 && component.weight == weight,
            "MODEL_COMPOSITION_WEIGHT",
        )?;
        total = total.checked_add(weight).ok_or("MODEL_COMPOSITION_RANGE")?;
        measured.push(json!({"contribution":hex::encode(component.id),"artifact":component.contribution["artifact"],"owner":component.contribution["owner"],"correct":component.evidence["candidate_correct"],"without_artifact":hex::encode(without.id()),"without_correct":without_correct,"weight":weight}));
    }
    let gain_score = (correct - strongest)
        .checked_mul(SCALE)
        .ok_or("MODEL_COMPOSITION_RANGE")?
        / rows;
    let mut record = json!({"schema":"native-model-composition-record-v4","network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),"family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),"policy":hex::encode(policy_hash()?),"bundle":hex::encode(bundle_id),"artifact":hex::encode(actual_bundle.id()),"parent":hex::encode(current_ref),"parent_artifact":hex::encode(parent_id),"round":bundle["submission_round"],"slot":bundle["slot"],"rows":rows,"correct":correct,"strongest_correct":strongest,"gain_score":gain_score,"components":measured,"total_weight":total,"zero_subset_checks":zero_subset_checks,"prospective_accepted":false,"independent_accepted":false,"public_reward_eligible":false,"shapley_fairness_accepted":false});
    record["digest"] = json!(hex::encode(hash(
        b"native-model-composition-record-v4",
        &[&canonical(&record)?]
    )));
    Ok(record)
}

#[cfg(test)]
mod oracle_observations;

#[cfg(test)]
mod tests {
    use super::*;

    fn model(value: i16) -> IntegerModelV2 {
        let mut coefficients = vec![0; 3 * 257 * 5];
        coefficients[2 * 3 * 257] = value;
        IntegerModelV2::from_coefficients([7; 32], coefficients).unwrap()
    }

    #[test]
    fn exact_sum_and_ablation_count_a_nonzero_parent_once() {
        let parent = model(10);
        let components = [model(13), model(8)];
        assert_eq!(
            derive([7; 32], &parent, &components, None).unwrap(),
            model(11)
        );
        assert_eq!(
            derive([7; 32], &parent, &components, Some(0)).unwrap(),
            model(8)
        );
        assert_eq!(
            derive([7; 32], &parent, &components, Some(1)).unwrap(),
            model(13)
        );
        assert_eq!(reject_redundant_subsets(&parent, &components), Ok(1));
    }

    #[test]
    fn exact_zero_subset_is_refused_even_when_full_bundle_is_nonzero() {
        let parent = model(10);
        let components = [model(13), model(7), model(15)];
        assert_eq!(derive([7; 32], &parent, &components, None), Ok(model(15)));
        assert_eq!(
            reject_redundant_subsets(&parent, &components),
            Err("MODEL_COMPOSITION_REDUNDANT_SUBSET")
        );
        // A zero pair in one coordinate is insufficient: the complete delta
        // vector must cancel, including a coefficient in another expert slot.
        let mut distinct = components[1].coefficients().to_vec();
        distinct[4 * 3 * 257 + 1] = 1;
        let distinct = IntegerModelV2::from_coefficients([7; 32], distinct).unwrap();
        assert_eq!(
            reject_redundant_subsets(&parent, &[model(13), distinct, model(15)]),
            Ok(4)
        );
        assert_eq!(
            reject_redundant_subsets(&parent, &[model(11), model(12), model(14), model(18)]),
            Ok(11)
        );
        assert_eq!(
            reject_redundant_subsets(&parent, &[model(11), model(12), model(14), model(3)]),
            Err("MODEL_COMPOSITION_REDUNDANT_SUBSET")
        );
    }

    #[test]
    fn wide_sum_preserves_cancellation_but_checks_every_ablation_range() {
        for sign in [1_i16, -1] {
            let parent = model(sign * 20_000);
            let components = [
                model(sign * 32_000),
                model(sign * 32_000),
                model(sign * 2_000),
            ];
            assert_eq!(
                derive([7; 32], &parent, &components, None).unwrap(),
                model(sign * 26_000)
            );
            assert_eq!(
                derive([7; 32], &parent, &components, Some(2)),
                Err("MODEL_COMPOSITION_RANGE")
            );
            assert_eq!(
                derive([7; 32], &parent, &components[..2], None),
                Err("MODEL_COMPOSITION_RANGE")
            );
        }
    }

    #[test]
    fn a_rank_three_sum_has_no_rank_three_ilf2_witness_escape() {
        let cfg = Config::installed_with_model_profiles(
            crate::public_evaluation::PROFILE,
            crate::pon_executor::LEGACY_TASK_PROFILE,
            PROFILE,
        )
        .unwrap();
        let state = factor::bootstrap_state(&cfg).unwrap();
        let mut first = vec![0; 3 * 257 * 5];
        first[2 * 3 * 257] = 1;
        first[2 * 3 * 257 + 257 + 1] = 1;
        let mut second = vec![0; 3 * 257 * 5];
        second[2 * 3 * 257 + 2 * 257 + 2] = 1;
        let components = [
            IntegerModelV2::from_coefficients(cfg.family, first).unwrap(),
            IntegerModelV2::from_coefficients(cfg.family, second).unwrap(),
        ];
        let full = derive(
            cfg.family,
            &IntegerModelV2::genesis(cfg.family),
            &components,
            None,
        )
        .unwrap();
        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(
                    full.coefficients()[2 * 3 * 257 + i * 257 + j],
                    i16::from(i == j)
                );
            }
        }
        // The resulting leading minor is identity3, so an exact rank<=2 update
        // cannot represent it. Increasing the submitted rank is not accepted.
        let mut factors = vec![1, 0, 0, 0, 1, 0, 0, 0, 1];
        for i in 0..3 {
            for j in 0..257 {
                factors.push(i16::from(i == j));
            }
        }
        assert_eq!(
            factor::build_witness(
                &state,
                &cfg,
                [1; 32],
                0,
                factor::FactorInputV2 {
                    slot: 0,
                    rank: 3,
                    coefficients: factors
                },
                [0; 32]
            ),
            Err("FACTOR_ENCODING")
        );
    }
}
