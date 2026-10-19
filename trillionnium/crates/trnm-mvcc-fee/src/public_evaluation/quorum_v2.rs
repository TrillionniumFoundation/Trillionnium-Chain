//! Explicit development acceptance threshold for fully replayed native evidence.
//! This is neither a BFT certificate nor a claim of independently controlled keys.
use super::{check, digest, n, records_digest, Reveal};
use crate::pon_executor::{Config, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "native-public-evaluation-quorum-dev-v2";
pub const REVISION: u64 = 15;
pub const STORAGE_REVISION: u64 = 3;
pub const RECORD_NAMESPACE: &str = "evaluation-record-v3";
pub const REVIEW_POLICY: &str = "native-replay-quorum-and-record-only-appeals-v2";

fn keys(value: &Value) -> Result<BTreeSet<String>> {
    let rows = value.as_array().ok_or("PUBLIC_EVAL_STATE")?;
    let mut result = BTreeSet::new();
    for row in rows {
        let key = row.as_str().ok_or("PUBLIC_EVAL_STATE")?;
        super::identity("r", key)?;
        check(result.insert(key.to_owned()), "PUBLIC_EVAL_ROSTER")?;
    }
    check(
        rows.iter()
            .filter_map(Value::as_str)
            .eq(result.iter().map(String::as_str)),
        "PUBLIC_EVAL_ROSTER",
    )?;
    Ok(result)
}

fn generation_context(plan: &Value) -> Result<Hash> {
    Ok(hash(
        b"native-public-evaluation-generation-v2",
        &[
            &digest(plan, "network")?,
            &digest(plan, "parameters")?,
            &digest(plan, "family")?,
            &digest(plan, "model_and_task_contract")?,
            &digest(plan, "dataset")?,
            &digest(plan, "parent")?,
            &n(plan, "generation")?.to_le_bytes(),
        ],
    ))
}

pub(super) fn configure_plan(
    plan: &mut Value,
    cfg: &Config,
    author: &str,
    excluded: &BTreeSet<String>,
    generation: u64,
) -> Result<()> {
    check(
        crate::model_evidence_v3::enabled(cfg),
        "PUBLIC_EVAL_NATIVE_REPLAY_REQUIRED",
    )?;
    let roster = keys(&plan["roster"])?;
    let disqualified: BTreeSet<_> = roster.intersection(excluded).cloned().collect();
    let quorum = (2 * roster.len()).div_ceil(3);
    check(
        (3..=16).contains(&roster.len()) && roster.len() - disqualified.len() >= quorum,
        "PUBLIC_EVAL_ROSTER",
    )?;
    plan["schema"] = json!("pon-native-frozen-evaluation-v2");
    plan["profile"] = json!(PROFILE);
    plan["author"] = json!(author);
    plan["quorum"] = json!(quorum);
    plan["disqualified_at_freeze"] = json!(disqualified);
    plan["generation"] = json!(generation);
    plan["dataset"] = json!(hex::encode(crate::model_evidence_v3::dataset_root(
        cfg, generation
    )?));
    plan["review_policy"] = json!(REVIEW_POLICY);
    plan["identity_scope"] = json!("controlled-development-keys; common administration possible");
    plan["generation_context"] = json!(hex::encode(generation_context(plan)?));
    validate_plan(plan)
}

/// Validate the exact frozen threshold and its parent/round/dataset commitment.
/// A later conflict can remove voters, but it cannot alter this denominator.
pub fn validate_plan(plan: &Value) -> Result<()> {
    check(
        plan["schema"] == "pon-native-frozen-evaluation-v2"
            && plan["profile"] == PROFILE
            && plan["review_policy"] == REVIEW_POLICY
            && plan["independent_governance_accepted"] == false
            && plan["objective_model_quality"] == false,
        "PUBLIC_EVAL_PROFILE",
    )?;
    let roster = keys(&plan["roster"])?;
    let excluded = keys(&plan["disqualified_at_freeze"])?;
    let author = plan["author"].as_str().ok_or("PUBLIC_EVAL_STATE")?;
    super::identity("r", author)?;
    let quorum = (2 * roster.len()).div_ceil(3);
    check(
        (3..=16).contains(&roster.len())
            && !roster.contains(author)
            && excluded.is_subset(&roster)
            && n(plan, "quorum")? == quorum as u64
            && roster.len() - excluded.len() >= quorum,
        "PUBLIC_EVAL_ROSTER",
    )?;
    check(
        n(plan, "start")?
            == n(plan, "generation")?
                .checked_mul(128)
                .ok_or("PUBLIC_EVAL_STATE")?
            && digest(plan, "generation_context")? == generation_context(plan)?,
        "PUBLIC_EVAL_GENERATION",
    )
}

pub(super) fn reveal_commitment(value: &Reveal) -> Hash {
    hash(
        b"native-public-evaluation-reveal-v2",
        &[
            &value.round,
            &value.candidate,
            &value.evaluator,
            &value.plan,
            &value.evidence,
            &value.score.to_le_bytes(),
            &value.salt,
        ],
    )
}

fn disqualified(evaluation: &Value) -> Result<BTreeSet<String>> {
    let roster = keys(&evaluation["plan"]["roster"])?;
    let mut result = keys(&evaluation["plan"]["disqualified_at_freeze"])?;
    for conflict in evaluation["conflicts"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?
        .values()
    {
        let signer = conflict["signer"].as_str().ok_or("PUBLIC_EVAL_STATE")?;
        check(roster.contains(signer), "PUBLIC_EVAL_AUTHORITY")?;
        result.insert(signer.to_owned());
    }
    Ok(result)
}

/// A genuine signed conflict affects this key only. Absence creates no vote.
pub(super) fn eligible(evaluation: &Value, sender: &str) -> Result<()> {
    check(
        !disqualified(evaluation)?.contains(sender),
        "PUBLIC_EVAL_DISQUALIFIED",
    )
}

struct Count {
    score: Option<u64>,
    evidence: Option<Hash>,
    matching: usize,
    revealed: usize,
    missing: usize,
    disqualified: BTreeSet<String>,
}

fn count(evaluation: &Value, current_disqualified: &BTreeSet<String>) -> Result<Count> {
    // Bind the complete frozen roster and threshold as well as the generation
    // context before closing or consuming a retained evaluation.
    super::round(evaluation)?;
    let roster = keys(&evaluation["plan"]["roster"])?;
    let mut excluded = disqualified(evaluation)?;
    excluded.extend(roster.intersection(current_disqualified).cloned());
    let reveals = evaluation["reveals"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?;
    let commits = evaluation["commits"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?;
    let mut groups = BTreeMap::<(u64, Hash), usize>::new();
    let mut revealed = 0;
    for (signer, value) in reveals {
        check(
            roster.contains(signer) && commits.contains_key(signer),
            "PUBLIC_EVAL_STATE",
        )?;
        let score = n(value, "score")?;
        let evidence = digest(value, "evidence")?;
        check(
            score <= n(&evaluation["plan"], "max_score")? && evidence != [0; 32],
            "PUBLIC_EVAL_STATE",
        )?;
        if !excluded.contains(signer) {
            *groups.entry((score, evidence)).or_default() += 1;
            revealed += 1;
        }
    }
    let quorum = n(&evaluation["plan"], "quorum")? as usize;
    let accepted: Vec<_> = groups
        .iter()
        .filter(|(_, count)| **count >= quorum)
        .collect();
    check(accepted.len() <= 1, "PUBLIC_EVAL_STATE")?;
    let (score, evidence, matching) = accepted
        .first()
        .map_or((None, None, 0), |((score, evidence), count)| {
            (Some(*score), Some(*evidence), **count)
        });
    Ok(Count {
        score,
        evidence,
        matching,
        revealed,
        missing: roster
            .iter()
            .filter(|key| !reveals.contains_key(*key))
            .count(),
        disqualified: excluded,
    })
}

pub(super) fn close(
    evaluation: &mut Value,
    height: u64,
    current_disqualified: &BTreeSet<String>,
) -> Result<Option<u64>> {
    let counted = count(evaluation, current_disqualified)?;
    let conflicts = evaluation["conflicts"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?
        .len();
    evaluation["closed"] = json!({
        "schema":"pon-native-closed-evaluation-v3",
        "round":evaluation["round"],"candidate":evaluation["plan"]["candidate"],
        "generation_context":evaluation["plan"]["generation_context"],
        "status":if counted.score.is_some(){"complete-scored"}else{"aborted"},
        "score":counted.score,"evidence":counted.evidence.map(hex::encode),
        "quorum":evaluation["plan"]["quorum"],
        "eligible_reveal_count":counted.revealed,"matching_reveal_count":counted.matching,
        "missing_reveal_count":counted.missing,"disqualified_count_before_close":counted.disqualified.len(),
        "disqualified_signers_before_close":counted.disqualified,
        "conflict_count_before_close":conflicts,
        "records_digest":hex::encode(records_digest(evaluation)?),"closed_height":height,
        "objective_model_quality":false,"independent_governance_accepted":false,
        "execution_authority":false,"consensus_finality":false
    });
    Ok(counted.score)
}

/// Recount inside the native tag8 state transaction, including late conflicts.
/// The immutable closure and already executed effects are never rewritten here.
pub fn adoption_allowed(
    evaluation: &Value,
    height: u64,
    allow_zero: bool,
    current_disqualified: &BTreeSet<String>,
) -> Result<()> {
    validate_plan(&evaluation["plan"])?;
    check(
        height >= n(&evaluation["plan"], "adoption_start")?
            && evaluation["closed"]["schema"] == "pon-native-closed-evaluation-v3"
            && evaluation["closed"]["status"] == "complete-scored"
            && evaluation["closed"]["round"] == evaluation["round"]
            && evaluation["closed"]["candidate"] == evaluation["plan"]["candidate"]
            && evaluation["closed"]["quorum"] == evaluation["plan"]["quorum"]
            && evaluation["closed"]["generation_context"]
                == evaluation["plan"]["generation_context"],
        "PUBLIC_EVAL_ADOPTION",
    )?;
    let score = n(&evaluation["closed"], "score")?;
    let counted = count(evaluation, current_disqualified)?;
    check(
        (allow_zero || score > 0)
            && counted.score == Some(score)
            && counted.evidence == Some(digest(&evaluation["closed"], "evidence")?),
        "PUBLIC_EVAL_ADOPTION",
    )
}
