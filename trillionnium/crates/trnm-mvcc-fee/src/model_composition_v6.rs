//! Known-source composition for one fresh, bounded exact-integer profile.
//!
//! Complete parent-relative updates are aggregated before any evaluation,
//! positive part, cap or rounding. The invariant is the source's total gross
//! entitlement, for representations that both pass admission and have the same
//! canonical source game. Admission limits and transaction fees remain separate.
//! This does not establish unknown-source Sybil resistance, coalition-proofness,
//! truthful bidding, prospective benefit or Shapley fairness.
use crate::integer_factor_candidate_v2::{self as factor, FactorState, IntegerModelV2};
use crate::model_composition_v4::CheckedComponent;
use crate::model_evidence_v3 as empirical;
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "linear-source-composition-dev-v6";
pub const REVISION: u64 = 17;
pub const MAX_COMPONENTS: usize = 4;
pub const MAX_RECORD_BYTES: usize = 2700;
pub const SCALE: u64 = 1_000_000;
const POLICY: &str = include_str!("../../../../config/pon/model-composition-v6.json");
const INSUFFICIENT: &str = "MODEL_SOURCE_INSUFFICIENT_EVIDENCE";

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
    let value = value[key].as_str().ok_or("MODEL_SOURCE_STATE")?;
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "MODEL_SOURCE_STATE",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "MODEL_SOURCE_STATE")?;
    Ok(out)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE
}
fn policy_hash() -> Result<Hash> {
    static HASH: OnceLock<Result<Hash>> = OnceLock::new();
    *HASH.get_or_init(|| {
        let p: Value = serde_json::from_str(POLICY).map_err(|_| "MODEL_SOURCE_CONFIG")?;
        for (key, expected) in [
            ("schema", json!("native-integer-source-composition-v6")),
            ("profile", json!(PROFILE)),
            ("consensus_revision", json!(REVISION)),
            ("empirical_material", json!("model-evidence-v3.json")),
            ("component_min", json!(1)),
            ("component_max", json!(MAX_COMPONENTS)),
            ("maximum_source_record_bytes", json!(MAX_RECORD_BYTES)),
            ("component_order", json!("strict-ascending-contribution-id")),
            ("component_wire_marker", json!(1)),
            ("source_identity", json!("installed-author-to-source-map-only")),
            ("parent_rule", json!("same-current-reference-full-artifact-family-round-and-slot")),
            ("aggregation", json!("sum-complete-parent-relative-deltas-by-source-before-evaluation")),
            ("integer_rule", json!("checked-i64-no-intermediate-clipping-rounding-or-positive-part")),
            ("representation", json!("complete-ILM2-models-from-existing-bounded-ILF2-admission")),
            ("bundle_gate", json!("strictly-better-than-parent-frozen-controls-and-if-multiple-sources-each-source-alone")),
            ("counterfactual_rule", json!("materialize-and-run-complete-source-omission-or-InsufficientEvidence")),
            ("weight_rule", json!("floor-positive-source-omission-correct-count-gain-times-scale-over-task-count")),
            ("score_scale", json!(SCALE)),
            ("payout_rule", json!("min-frozen-remaining-source-cap-floor-budget-times-source-weight-over-sum")),
            ("zero_value_rule", json!("zero-source-rewards-full-budget-refund")),
            ("internal_payment_rule", json!("equal-per-component-owner-signed-claims-cid-ascending-source-dust")),
            ("dust_rule", json!("source-internal-remainders-paid-exactly-unallocated-budget-deadline-refund")),
            ("game_identity", json!("context-plan-tasks-parent-full-source-deltas-budget-and-frozen-source-caps-no-component-or-payee-aliases")),
            ("admission_tag", json!(8)),
            ("claim_tag", json!(9)),
            ("fees", json!("separate-existing-transaction-fees-not-part-of-source-entitlement")),
            ("guarantee_scope", json!("equivalent-representations-that-both-pass-admission-with-identical-canonical-source-game")),
            ("unknown_sybil_resistance", json!(false)),
            ("coalition_proofness", json!(false)),
            ("truthful_bidding", json!(false)),
            ("production_activation", json!(false)),
            ("prospective_accepted", json!(false)),
            ("independent_accepted", json!(false)),
            ("public_reward_eligible", json!(false)),
            ("shapley_fairness_accepted", json!(false)),
        ] { check(p[key] == expected, "MODEL_SOURCE_CONFIG")?; }
        Ok(hash(b"native-source-composition-policy-v6", &[&canonical(&p)?]))
    })
}
pub(crate) fn install(params: &mut Value) -> Result<()> {
    empirical::install(params)?;
    params["model_source_policy_hash"] = json!(hex::encode(policy_hash()?));
    Ok(())
}
pub(crate) fn check_context(cfg: &Config) -> Result<()> {
    check(
        enabled(cfg)
            && cfg.params["consensus_revision"] == REVISION
            && cfg.params["model_source_policy_hash"] == hex::encode(policy_hash()?),
        "MODEL_SOURCE_PROFILE",
    )
}
pub fn source_key(round: u64, source: Hash) -> String {
    format!("model-source-v6:{round}:{}", hex::encode(source))
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceUpdate {
    source: Hash,
    delta: Vec<i64>,
}
/// Complete models have passed native loading and installed author mapping.
/// Even a zero aggregate stays: the declared source roster is part of the game.
fn aggregate(
    parent: &IntegerModelV2,
    components: &[(Hash, IntegerModelV2)],
) -> Result<Vec<SourceUpdate>> {
    check(
        (1..=MAX_COMPONENTS).contains(&components.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    check(!parent.is_evolution(), INSUFFICIENT)?;
    let mut grouped = BTreeMap::<Hash, Vec<i64>>::new();
    for (source, model) in components {
        check(
            !model.is_evolution() && model.coefficients().len() == parent.coefficients().len(),
            INSUFFICIENT,
        )?;
        let delta = grouped
            .entry(*source)
            .or_insert_with(|| vec![0; parent.coefficients().len()]);
        for ((sum, &coefficient), &base) in delta
            .iter_mut()
            .zip(model.coefficients())
            .zip(parent.coefficients())
        {
            let value = i64::from(coefficient)
                .checked_sub(i64::from(base))
                .ok_or("MODEL_SOURCE_ARITHMETIC")?;
            *sum = sum.checked_add(value).ok_or("MODEL_SOURCE_ARITHMETIC")?;
        }
    }
    Ok(grouped
        .into_iter()
        .map(|(source, delta)| SourceUpdate { source, delta })
        .collect())
}
/// Materialize valid ILM2; an unrepresentable counterfactual is missing evidence,
/// never a model whose utility is silently set to zero.
fn derive(
    family: Hash,
    parent: &IntegerModelV2,
    sources: &[SourceUpdate],
    include: impl Fn(Hash) -> bool,
) -> Result<IntegerModelV2> {
    let mut coefficients = Vec::with_capacity(parent.coefficients().len());
    for (coordinate, &base) in parent.coefficients().iter().enumerate() {
        let mut next = i64::from(base);
        for source in sources {
            if include(source.source) {
                next = next
                    .checked_add(*source.delta.get(coordinate).ok_or(INSUFFICIENT)?)
                    .ok_or(INSUFFICIENT)?;
            }
        }
        check((-32767..=32767).contains(&next), INSUFFICIENT)?;
        coefficients.push(i16::try_from(next).map_err(|_| INSUFFICIENT)?);
    }
    IntegerModelV2::from_coefficients(family, coefficients).map_err(|_| INSUFFICIENT)
}
fn delta_bytes(source: &SourceUpdate) -> Vec<u8> {
    source.delta.iter().flat_map(|v| v.to_le_bytes()).collect()
}
/// Excludes component IDs, owners, counts, bundle IDs and packaging roots.
fn game_identity(
    context: &Value,
    sources: &[SourceUpdate],
    caps: &BTreeMap<Hash, u64>,
) -> Result<Hash> {
    check(
        sources
            .windows(2)
            .all(|pair| pair[0].source < pair[1].source)
            && caps.len() == sources.len(),
        "MODEL_SOURCE_ORDER",
    )?;
    let canonical_sources: Vec<_> = sources.iter().map(|source| {
        let cap = caps.get(&source.source).ok_or("MODEL_SOURCE_STATE")?;
        Ok(json!({"source":hex::encode(source.source),"delta_i64_le":hex::encode(delta_bytes(source)),"cap":cap}))
    }).collect::<Result<_>>()?;
    Ok(hash(
        b"native-source-value-game-v6",
        &[&canonical(
            &json!({"context":context,"sources":canonical_sources}),
        )?],
    ))
}
/// Floor and cap once per source. Unallocated budget stays escrowed for refund.
fn allocate_source_rewards(
    budget: u64,
    weights: &[u64],
    caps: &[u64],
) -> Result<(Vec<u64>, u64, u64)> {
    check(weights.len() == caps.len(), "MODEL_SOURCE_STATE")?;
    let total = weights.iter().try_fold(0_u64, |sum, &weight| {
        sum.checked_add(weight).ok_or("MODEL_SOURCE_ARITHMETIC")
    })?;
    let mut allocated = 0_u64;
    let mut rewards = Vec::with_capacity(weights.len());
    for (&weight, &cap) in weights.iter().zip(caps) {
        let reward = if total == 0 {
            0
        } else {
            let proportion = u128::from(budget) * u128::from(weight) / u128::from(total);
            cap.min(u64::try_from(proportion).map_err(|_| "MODEL_SOURCE_ARITHMETIC")?)
        };
        allocated = allocated
            .checked_add(reward)
            .ok_or("MODEL_SOURCE_ARITHMETIC")?;
        rewards.push(reward);
    }
    let refund = budget
        .checked_sub(allocated)
        .ok_or("MODEL_SOURCE_ARITHMETIC")?;
    Ok((rewards, total, refund))
}
/// The signed contribution owner claims this fixed internal share with tag9.
fn internal_amounts(reward: u64, count: usize) -> Result<Vec<u64>> {
    check((1..=MAX_COMPONENTS).contains(&count), "MODEL_SOURCE_COUNT")?;
    let count = u64::try_from(count).map_err(|_| "MODEL_SOURCE_ARITHMETIC")?;
    let quotient = reward / count;
    let remainder = reward % count;
    Ok((0..count)
        .map(|index| quotient + u64::from(index < remainder))
        .collect())
}
/// Calculate the source game without writes. The caller atomically reserves
/// every returned source reward together with the funded release. A wire weight
/// is a V6 presence marker, exactly one, not a caller-selected source value.
pub(crate) fn validate(
    state: &mut impl FactorState,
    cfg: &Config,
    bundle_id: Hash,
    bundle: &Value,
    bundle_evidence: &Value,
    components: &[CheckedComponent<'_>],
    budget: u64,
) -> Result<Value> {
    check_context(cfg)?;
    check(
        (1..=MAX_COMPONENTS).contains(&components.len()),
        "MODEL_SOURCE_COUNT",
    )?;
    check(
        components.windows(2).all(|pair| pair[0].id < pair[1].id)
            && components.iter().all(|component| component.id != bundle_id),
        "MODEL_SOURCE_ORDER",
    )?;
    check(
        components.iter().all(|component| component.weight == 1),
        "MODEL_SOURCE_MARKER",
    )?;
    let (parent_ref, parent) = factor::parent(state, cfg)?;
    check(
        identity(bundle, "parent")? == parent_ref
            && identity(bundle, "factor_parent_artifact")? == parent.id(),
        "MODEL_SOURCE_PARENT",
    )?;
    let round = number(bundle, "submission_round")?;
    let slot = number(bundle, "slot")?;
    let actual_bundle = factor::load_model(state, identity(bundle, "artifact")?, cfg.family)?;
    let mut models = Vec::with_capacity(components.len());
    let mut members = BTreeMap::<Hash, Vec<usize>>::new();
    for (index, component) in components.iter().enumerate() {
        for key in [
            "parent",
            "factor_parent_artifact",
            "family",
            "submission_round",
            "slot",
        ] {
            check(
                component.contribution[key] == bundle[key],
                "MODEL_SOURCE_PARENT",
            )?;
        }
        let source = empirical::source(cfg, identity(component.contribution, "owner")?)?;
        check(
            identity(&component.contribution["model_evidence_v6"], "source")? == source,
            "MODEL_SOURCE_IDENTITY",
        )?;
        members.entry(source).or_default().push(index);
        models.push((
            source,
            factor::load_model(
                state,
                identity(component.contribution, "artifact")?,
                cfg.family,
            )?,
        ));
    }
    let sources = aggregate(&parent, &models)?;
    let complete = derive(cfg.family, &parent, &sources, |_| true)?;
    check(complete == actual_bundle, "MODEL_SOURCE_DERIVATION")?;
    let correct = empirical::model_correct(cfg, &complete)?;
    let rows = number(bundle_evidence, "rows")?;
    check(
        rows > 0 && correct <= rows && correct == number(bundle_evidence, "candidate_correct")?,
        "MODEL_SOURCE_EVIDENCE",
    )?;
    let mut strongest = number(bundle_evidence, "strongest_correct")?;
    let mut caps = BTreeMap::new();
    let mut measured = Vec::with_capacity(sources.len());
    let mut weights = Vec::with_capacity(sources.len());
    for source in &sources {
        let standalone = derive(cfg.family, &parent, &sources, |id| id == source.source)?;
        let standalone_correct = empirical::model_correct(cfg, &standalone)?;
        if sources.len() > 1 {
            strongest = strongest.max(standalone_correct);
        }
        let without = derive(cfg.family, &parent, &sources, |id| id != source.source)?;
        let without_correct = empirical::model_correct(cfg, &without)?;
        check(
            standalone_correct <= rows && without_correct <= rows,
            "MODEL_SOURCE_EVIDENCE",
        )?;
        let weight = correct
            .saturating_sub(without_correct)
            .checked_mul(SCALE)
            .ok_or("MODEL_SOURCE_ARITHMETIC")?
            / rows;
        let quota = state
            .get(&source_key(round, source.source))
            .ok_or("MODEL_SOURCE_BUDGET")?;
        check(
            quota["schema"] == "native-model-source-budget-v6"
                && identity(&quota, "source")? == source.source
                && number(&quota, "round")? == round,
            "MODEL_SOURCE_BUDGET",
        )?;
        let reserved = number(&quota, "reserved_units")?;
        let cap = empirical::MAX_RESERVED_UNITS
            .checked_sub(reserved)
            .ok_or("MODEL_SOURCE_BUDGET")?;
        caps.insert(source.source, cap);
        weights.push(weight);
        measured.push(json!({
            "source":hex::encode(source.source),
            "delta_hash":hex::encode(hash(b"native-complete-source-delta-v6", &[&delta_bytes(source)])),
            "standalone_correct":standalone_correct,
            "without_correct":without_correct,
            "weight":weight,"cap":cap,"reward":0
        }));
    }
    check(correct > strongest, "MODEL_SOURCE_GAIN")?;
    let game = game_identity(
        &json!({
            "profile":PROFILE,"network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),
            "family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),"policy":hex::encode(policy_hash()?),
            "tasks":hex::encode(identity(&cfg.params,"model_evidence_tasks_hash")?),
            "empirical_policy":hex::encode(identity(&cfg.params,"model_evidence_policy_hash")?),
            "parent":hex::encode(parent_ref),"parent_artifact":hex::encode(parent.id()),
            "round":round,"slot":slot,"artifact":hex::encode(complete.id()),"budget":budget
        }),
        &sources,
        &caps,
    )?;
    let (rewards, total_weight, refund) = allocate_source_rewards(
        budget,
        &weights,
        &caps.values().copied().collect::<Vec<_>>(),
    )?;
    let mut payments = Vec::with_capacity(components.len());
    for ((source, record), reward) in sources.iter().zip(&mut measured).zip(rewards) {
        record["reward"] = json!(reward);
        let indices = members.get(&source.source).ok_or("MODEL_SOURCE_STATE")?;
        for (&index, amount) in indices.iter().zip(internal_amounts(reward, indices.len())?) {
            let component = &components[index];
            payments.push(
                json!({"contribution":hex::encode(component.id),"source":hex::encode(source.source),
                "payee":component.contribution["owner"],"marker":1,"amount":amount}),
            );
        }
    }
    payments.sort_by(|a, b| a["contribution"].as_str().cmp(&b["contribution"].as_str()));
    // Shared context and complete counterfactual artifacts are already bound
    // by game_digest and the enclosing release. Keep this row bounded through
    // four sources, four payments and the final four claim entries.
    let mut record = json!({
        "schema":"native-source-composition-record-v6","policy":hex::encode(policy_hash()?),
        "game_digest":hex::encode(game),"rows":rows,"correct":correct,"strongest_correct":strongest,
        "sources":measured,"total_weight":total_weight,"budget":budget,
        "allocated":budget-refund,"refund":refund,"payments":payments,"fees_separate":true,
        "prospective_accepted":false,"public_reward_eligible":false,
        "shapley_fairness_accepted":false,"unknown_sybil_resistance":false,
        "production_activation":false
    });
    seal_record(&mut record)?;
    check(
        canonical(&record)?.len() <= MAX_RECORD_BYTES,
        "MODEL_SOURCE_RECORD_SIZE",
    )?;
    Ok(record)
}
fn seal_record(record: &mut Value) -> Result<()> {
    record
        .as_object_mut()
        .ok_or("MODEL_SOURCE_RECORD")?
        .remove("digest");
    let digest = hash(
        b"native-source-composition-record-v6",
        &[&canonical(record)?],
    );
    record["digest"] = json!(hex::encode(digest));
    Ok(())
}

/// Corruption/consistency check over the native release record, not independent
/// authorization. The owner still verifies the signed claim, allocation proof,
/// current release, maturity, replay protection and atomic account mutation.
pub(crate) fn claim_amount(record: &Value, cid: Hash, payee: Hash, marker: u64) -> Result<u64> {
    check(
        canonical(record)?.len() <= MAX_RECORD_BYTES,
        "MODEL_SOURCE_RECORD_SIZE",
    )?;
    check(
        marker == 1
            && record["schema"] == "native-source-composition-record-v6"
            && record["policy"] == hex::encode(policy_hash()?),
        "MODEL_SOURCE_CLAIM",
    )?;
    let digest = identity(record, "digest")?;
    let mut unsealed = record.clone();
    unsealed
        .as_object_mut()
        .ok_or("MODEL_SOURCE_RECORD")?
        .remove("digest");
    check(
        digest
            == hash(
                b"native-source-composition-record-v6",
                &[&canonical(&unsealed)?],
            ),
        "MODEL_SOURCE_RECORD",
    )?;
    let sources = record["sources"].as_array().ok_or("MODEL_SOURCE_RECORD")?;
    let payments = record["payments"].as_array().ok_or("MODEL_SOURCE_RECORD")?;
    check(
        (1..=MAX_COMPONENTS).contains(&sources.len())
            && (sources.len()..=MAX_COMPONENTS).contains(&payments.len()),
        "MODEL_SOURCE_RECORD",
    )?;
    let rows = number(record, "rows")?;
    let correct = number(record, "correct")?;
    let strongest = number(record, "strongest_correct")?;
    check(
        rows > 0 && correct <= rows && correct > strongest,
        "MODEL_SOURCE_RECORD",
    )?;
    let mut source_ids = Vec::with_capacity(sources.len());
    let mut weights = Vec::with_capacity(sources.len());
    let mut caps = Vec::with_capacity(sources.len());
    let mut source_records = BTreeMap::new();
    for source in sources {
        let id = identity(source, "source")?;
        check(
            source_ids.last().is_none_or(|last| *last < id),
            "MODEL_SOURCE_RECORD",
        )?;
        source_ids.push(id);
        identity(source, "delta_hash")?;
        let standalone = number(source, "standalone_correct")?;
        let without = number(source, "without_correct")?;
        check(
            standalone <= rows
                && without <= rows
                && (sources.len() == 1 || strongest >= standalone),
            "MODEL_SOURCE_RECORD",
        )?;
        let weight = correct
            .saturating_sub(without)
            .checked_mul(SCALE)
            .ok_or("MODEL_SOURCE_ARITHMETIC")?
            / rows;
        check(number(source, "weight")? == weight, "MODEL_SOURCE_RECORD")?;
        let cap = number(source, "cap")?;
        check(cap <= empirical::MAX_RESERVED_UNITS, "MODEL_SOURCE_RECORD")?;
        weights.push(weight);
        caps.push(cap);
        source_records.insert(id, source);
    }
    let budget = number(record, "budget")?;
    let (rewards, total, refund) = allocate_source_rewards(budget, &weights, &caps)?;
    check(
        number(record, "total_weight")? == total
            && number(record, "refund")? == refund
            && number(record, "allocated")? == budget - refund,
        "MODEL_SOURCE_RECORD",
    )?;
    let mut previous = None;
    let mut grouped = BTreeMap::<Hash, Vec<&Value>>::new();
    let mut selected = None;
    for payment in payments {
        let contribution = identity(payment, "contribution")?;
        let owner = identity(payment, "payee")?;
        let source = identity(payment, "source")?;
        check(
            previous.is_none_or(|id| id < contribution)
                && number(payment, "marker")? == 1
                && source_records.contains_key(&source),
            "MODEL_SOURCE_RECORD",
        )?;
        previous = Some(contribution);
        grouped.entry(source).or_default().push(payment);
        if contribution == cid {
            check(owner == payee, "MODEL_SOURCE_CLAIM")?;
            selected = Some(number(payment, "amount")?);
        }
    }
    check(grouped.len() == sources.len(), "MODEL_SOURCE_RECORD")?;
    for ((id, source), reward) in source_ids.iter().zip(sources).zip(rewards) {
        check(number(source, "reward")? == reward, "MODEL_SOURCE_RECORD")?;
        let group = grouped.get(id).ok_or("MODEL_SOURCE_RECORD")?;
        for (payment, amount) in group.iter().zip(internal_amounts(reward, group.len())?) {
            check(number(payment, "amount")? == amount, "MODEL_SOURCE_RECORD")?;
        }
    }
    selected.ok_or("MODEL_SOURCE_CLAIM")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model(value: i16) -> IntegerModelV2 {
        let mut coefficients = vec![0; 3 * 257 * 5];
        coefficients[2 * 3 * 257] = value;
        IntegerModelV2::from_coefficients([7; 32], coefficients).unwrap()
    }
    #[test]
    fn source_aggregation_preserves_nonzero_parent_and_split_permutations() {
        let parent = model(10);
        let baseline = aggregate(&parent, &[([1; 32], model(13)), ([2; 32], model(8))]).unwrap();
        let parts = [
            ([1; 32], model(30)),
            ([1; 32], model(-7)),
            ([2; 32], model(8)),
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let split = aggregate(&parent, &order.map(|i| parts[i].clone())).unwrap();
            assert_eq!(split, baseline);
            assert_eq!(derive([7; 32], &parent, &split, |_| true), Ok(model(11)));
            assert_eq!(
                derive([7; 32], &parent, &split, |id| id != [1; 32]),
                Ok(model(8))
            );
            let caps = BTreeMap::from([([1; 32], 100_000), ([2; 32], 100_000)]);
            let context = json!({"parent_artifact":hex::encode(parent.id()),"budget":100_000});
            assert_eq!(
                game_identity(&context, &baseline, &caps),
                game_identity(&context, &split, &caps)
            );
        }
    }
    #[test]
    fn source_counterfactual_out_of_range_is_insufficient_not_zero_utility() {
        for sign in [1_i16, -1] {
            let parent = model(sign * 20_000);
            let sources = aggregate(
                &parent,
                &[
                    ([1; 32], model(sign * 32_000)),
                    ([1; 32], model(sign * 32_000)),
                    ([2; 32], model(sign * 2_000)),
                ],
            )
            .unwrap();
            assert_eq!(
                derive([7; 32], &parent, &sources, |_| true),
                Ok(model(sign * 26_000))
            );
            assert_eq!(
                derive([7; 32], &parent, &sources, |id| id != [2; 32]),
                Err(INSUFFICIENT)
            );
        }
    }
    #[test]
    fn cancelling_components_are_aggregated_before_any_positive_part() {
        let parent = model(10);
        let sources = aggregate(
            &parent,
            &[
                ([1; 32], model(30)),
                ([1; 32], model(-10)),
                ([2; 32], model(12)),
            ],
        )
        .unwrap();
        assert!(sources[0].delta.iter().all(|&value| value == 0));
        assert_eq!(derive([7; 32], &parent, &sources, |_| true), Ok(model(12)));
        assert_eq!(
            derive([7; 32], &parent, &sources, |id| id != [1; 32]),
            Ok(model(12))
        );
    }
    #[test]
    fn source_floor_cap_and_refund_do_not_redistribute_capped_rewards() {
        assert_eq!(
            allocate_source_rewards(100_000, &[80_000, 40_000], &[100_000, 100_000]),
            Ok((vec![66_666, 33_333], 120_000, 1))
        );
        assert_eq!(
            allocate_source_rewards(100_000, &[80_000, 40_000], &[12_345, 100_000]),
            Ok((vec![12_345, 33_333], 120_000, 54_322))
        );
        assert_eq!(
            allocate_source_rewards(100_000, &[0, 0], &[100_000, 100_000]),
            Ok((vec![0, 0], 0, 100_000))
        );
        assert_eq!(
            allocate_source_rewards(100_000, &[0, 40_000], &[100_000, 100_000]),
            Ok((vec![0, 100_000], 40_000, 0))
        );
    }
    #[test]
    fn internal_partition_pays_the_whole_source_entitlement_exactly() {
        for reward in [0, 1, 2, 3, 4, 65_535, 66_666, u64::MAX] {
            for count in 1..=MAX_COMPONENTS {
                let amounts = internal_amounts(reward, count).unwrap();
                assert_eq!(
                    amounts.iter().map(|&value| u128::from(value)).sum::<u128>(),
                    u128::from(reward)
                );
                assert!(amounts.windows(2).all(|p| p[0] >= p[1] && p[0] - p[1] <= 1));
            }
        }
    }
    #[test]
    fn wide_budget_math_and_identity_bind_frozen_caps_and_full_signed_delta() {
        assert_eq!(
            allocate_source_rewards(u64::MAX, &[u64::MAX], &[u64::MAX]),
            Ok((vec![u64::MAX], u64::MAX, 0))
        );
        assert_eq!(
            allocate_source_rewards(1, &[u64::MAX, 1], &[1, 1]),
            Err("MODEL_SOURCE_ARITHMETIC")
        );
        let parent = model(10);
        let sources = aggregate(&parent, &[([1; 32], model(13))]).unwrap();
        let context = json!({"budget":100_000});
        let caps = BTreeMap::from([([1; 32], 100_000)]);
        let digest = game_identity(&context, &sources, &caps).unwrap();
        assert_ne!(
            digest,
            game_identity(&context, &sources, &BTreeMap::from([([1; 32], 99_999)])).unwrap()
        );
        assert_ne!(
            digest,
            game_identity(&json!({"budget":99_999}), &sources, &caps).unwrap()
        );
        let changed = aggregate(&parent, &[([1; 32], model(7))]).unwrap();
        assert_ne!(digest, game_identity(&context, &changed, &caps).unwrap());
    }
    fn claim_fixture() -> Value {
        let h = |n: u8| hex::encode([n; 32]);
        let mut record = json!({
            "schema":"native-source-composition-record-v6","policy":hex::encode(policy_hash().unwrap()),
            "rows":25,"correct":25,"strongest_correct":24,"budget":100_000,"allocated":99_999,"refund":1,"total_weight":120_000,
            "sources":[
                {"source":h(1),"delta_hash":h(11),"standalone_correct":24,"without_correct":23,"weight":80_000,"cap":100_000,"reward":66_666},
                {"source":h(2),"delta_hash":h(21),"standalone_correct":23,"without_correct":24,"weight":40_000,"cap":100_000,"reward":33_333}
            ],
            "payments":[
                {"contribution":h(31),"source":h(1),"payee":h(41),"marker":1,"amount":33_333},
                {"contribution":h(32),"source":h(1),"payee":h(42),"marker":1,"amount":33_333},
                {"contribution":h(33),"source":h(2),"payee":h(43),"marker":1,"amount":33_333}
            ]
        });
        seal_record(&mut record).unwrap();
        record
    }
    #[test]
    fn claims_require_matching_native_record_owner_and_fixed_marker() {
        let record = claim_fixture();
        assert_eq!(claim_amount(&record, [31; 32], [41; 32], 1), Ok(33_333));
        assert_eq!(
            claim_amount(&record, [31; 32], [42; 32], 1),
            Err("MODEL_SOURCE_CLAIM")
        );
        assert_eq!(
            claim_amount(&record, [31; 32], [41; 32], 2),
            Err("MODEL_SOURCE_CLAIM")
        );
        assert_eq!(
            claim_amount(&record, [34; 32], [41; 32], 1),
            Err("MODEL_SOURCE_CLAIM")
        );
        let mut stale = record.clone();
        stale["payments"][0]["amount"] = json!(33_334);
        assert_eq!(
            claim_amount(&stale, [31; 32], [41; 32], 1),
            Err("MODEL_SOURCE_RECORD")
        );
    }
    #[test]
    fn resealed_inconsistent_payouts_duplicate_leaves_caps_or_totals_still_reject() {
        for mutation in 0..7 {
            let mut record = claim_fixture();
            match mutation {
                0 => record["payments"][0]["amount"] = json!(33_334),
                1 => record["payments"][1] = record["payments"][0].clone(),
                2 => record["sources"][0]["reward"] = json!(66_667),
                3 => record["sources"][0]["cap"] = json!(10_000),
                4 => record["total_weight"] = json!(120_001),
                5 => record["refund"] = json!(0),
                6 => record["sources"][1]["source"] = record["sources"][0]["source"].clone(),
                _ => unreachable!(),
            }
            seal_record(&mut record).unwrap();
            assert_eq!(
                claim_amount(&record, [31; 32], [41; 32], 1),
                Err("MODEL_SOURCE_RECORD")
            );
        }
    }
    #[test]
    fn stored_record_bounds_four_sources_and_four_extreme_width_claims() {
        let h = |n: u8| hex::encode([n; 32]);
        let sources: Vec<_> = (0_u8..4)
            .map(|i| {
                json!({
                    "source":h(i+1),"delta_hash":h(i+11),"standalone_correct":24,
                    "without_correct":0,"weight":SCALE,"cap":100_000,"reward":100_000
                })
            })
            .collect();
        let payments: Vec<_> = (0_u8..4).map(|i| json!({
            "contribution":h(i+31),"source":h(i+1),"payee":h(i+41),"marker":1,"amount":100_000
        })).collect();
        let claims: serde_json::Map<String, Value> =
            (0_u8..4).map(|i| (h(i + 31), json!(u64::MAX))).collect();
        let mut record = json!({
            "schema":"native-source-composition-record-v6","policy":hex::encode(policy_hash().unwrap()),
            "game_digest":h(60),"rows":25,"correct":25,"strongest_correct":24,"sources":sources,
            "total_weight":4*SCALE,"budget":u64::MAX,"allocated":400_000,"refund":u64::MAX-400_000,
            "payments":payments,"fees_separate":true,"prospective_accepted":false,
            "public_reward_eligible":false,"shapley_fairness_accepted":false,
            "unknown_sybil_resistance":false,"production_activation":false
        });
        seal_record(&mut record).unwrap();
        assert!(canonical(&record).unwrap().len() <= MAX_RECORD_BYTES);
        assert_eq!(claim_amount(&record, [31; 32], [41; 32], 1), Ok(100_000));
        let release = json!({
            "owner":h(1),"remaining":u64::MAX,"budget":u64::MAX,"total":4,"root":h(2),
            "maturity":u64::MAX,"bundle":h(3),"artifact":h(4),"family":h(5),
            "components_root":h(2),"parent":h(6),"leaf_count":4,"claims":claims,
            "deadline":u64::MAX,"status":"open","model_composition_v6":record
        });
        let bytes = canonical(&release).unwrap().len();
        assert!(bytes <= 3800, "all-four-claims release has {bytes} bytes");
    }
}
