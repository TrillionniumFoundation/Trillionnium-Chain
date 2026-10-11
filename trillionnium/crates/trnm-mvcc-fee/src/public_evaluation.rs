//! Native branch-state commit/reveal evaluation. Signatures attest opinions,
//! not objective model quality or independent identities. No fork weight changes.
use crate::pon_executor::{Config, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const RECORD_NAMESPACE: &str = "evaluation-record-v2";
pub const STORAGE_REVISION: u64 = 2;
const MAPS: [(&str, &str, usize); 4] = [
    ("c", "commits", 16),
    ("r", "reveals", 16),
    ("f", "conflicts", 32),
    ("a", "appeals", 16),
];
pub const PROFILE: &str = "native-public-evaluation-dev-v1";
pub const CANDIDATE_END: u64 = 15;
pub const COMMIT_END: u64 = 31;
pub const REVEAL_END: u64 = 47;
pub const ADOPTION_START: u64 = 56;

fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn n(v: &Value, field: &str) -> Result<u64> {
    v[field].as_u64().ok_or("PUBLIC_EVAL_STATE")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| "PUBLIC_EVAL_STATE")
}
fn digest(v: &Value, field: &str) -> Result<Hash> {
    let value = v[field].as_str().ok_or("PUBLIC_EVAL_STATE")?;
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PUBLIC_EVAL_STATE",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "PUBLIC_EVAL_STATE")?;
    Ok(out)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["evaluation_profile"] == PROFILE
}
pub fn freeze(
    cfg: &Config,
    cid: Hash,
    contribution: &Value,
    height: u64,
    excluded: &BTreeSet<String>,
) -> Result<Value> {
    check(enabled(cfg), "PUBLIC_EVAL_PROFILE")?;
    let width = n(&cfg.params, "candidate_round_blocks")?;
    check(
        width > ADOPTION_START && height % width <= CANDIDATE_END,
        "PUBLIC_EVAL_CANDIDATE_PHASE",
    )?;
    let author = contribution["owner"].as_str().ok_or("PUBLIC_EVAL_STATE")?;
    let roster: BTreeSet<_> = cfg
        .evaluators
        .iter()
        .filter(|key| key.as_str() != author && !excluded.contains(*key))
        .cloned()
        .collect();
    check((2..=16).contains(&roster.len()), "PUBLIC_EVAL_ROSTER")?;
    let start = height / width * width;
    let plan = json!({"schema":"pon-native-frozen-evaluation-v1","network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),"candidate":hex::encode(cid),"artifact":contribution["artifact"],"components_root":contribution["components_root"],"parent":contribution["parent"],"family":hex::encode(cfg.family),"model_and_task_contract":hex::encode(cfg.plan),"roster":roster,"start":start,"candidate_end":start+CANDIDATE_END,"commit_end":start+COMMIT_END,"reveal_end":start+REVEAL_END,"adoption_start":start+ADOPTION_START,"max_score":cfg.params["max_evidence_score"],"independent_governance_accepted":false,"objective_model_quality":false});
    let round = hash(b"native-public-evaluation-round-v1", &[&bytes(&plan)?]);
    Ok(
        json!({"storage_revision":STORAGE_REVISION,"plan":plan,"round":hex::encode(round),"record_counts":{"commits":0,"reveals":0,"conflicts":0,"appeals":0},"closed":null}),
    )
}
pub fn round(evaluation: &Value) -> Result<Hash> {
    digest(evaluation, "round")
}
pub fn reveal_commitment(
    round: Hash,
    cid: Hash,
    evaluator: Hash,
    plan: Hash,
    evidence: Hash,
    score: u64,
    salt: Hash,
) -> Hash {
    hash(
        b"native-public-evaluation-reveal-v1",
        &[
            &round,
            &cid,
            &evaluator,
            &plan,
            &evidence,
            &score.to_le_bytes(),
            &salt,
        ],
    )
}
fn evaluator(evaluation: &Value, sender: &str, round_id: Hash) -> Result<()> {
    check(round(evaluation)? == round_id, "PUBLIC_EVAL_ROUND")?;
    let roster = evaluation["plan"]["roster"]
        .as_array()
        .ok_or("PUBLIC_EVAL_STATE")?;
    check(
        roster.iter().any(|key| key.as_str() == Some(sender)),
        "PUBLIC_EVAL_AUTHORITY",
    )
}
pub fn commit(
    evaluation: &mut Value,
    sender: &str,
    round_id: Hash,
    commitment: Hash,
    height: u64,
) -> Result<()> {
    evaluator(evaluation, sender, round_id)?;
    let plan = &evaluation["plan"];
    check(
        height > n(plan, "candidate_end")?
            && height <= n(plan, "commit_end")?
            && evaluation["closed"].is_null(),
        "PUBLIC_EVAL_COMMIT_PHASE",
    )?;
    check(commitment != [0; 32], "PUBLIC_EVAL_COMMITMENT")?;
    check(evaluation["commits"].get(sender).is_none(), "DUPLICATE")?;
    evaluation["commits"][sender] = json!(hex::encode(commitment));
    Ok(())
}
pub struct Reveal {
    pub candidate: Hash,
    pub round: Hash,
    pub evaluator: Hash,
    pub plan: Hash,
    pub evidence: Hash,
    pub score: u64,
    pub salt: Hash,
}
pub fn reveal(evaluation: &mut Value, value: Reveal, height: u64) -> Result<()> {
    let sender = hex::encode(value.evaluator);
    evaluator(evaluation, &sender, value.round)?;
    let plan = &evaluation["plan"];
    check(
        height > n(plan, "commit_end")?
            && height <= n(plan, "reveal_end")?
            && evaluation["closed"].is_null(),
        "PUBLIC_EVAL_REVEAL_PHASE",
    )?;
    check(
        value.plan == digest(plan, "model_and_task_contract")?
            && value.evidence != [0; 32]
            && value.score <= n(plan, "max_score")?,
        "PUBLIC_EVAL_REVEAL_CONTEXT",
    )?;
    check(evaluation["reveals"].get(&sender).is_none(), "DUPLICATE")?;
    let commitment = reveal_commitment(
        value.round,
        value.candidate,
        value.evaluator,
        value.plan,
        value.evidence,
        value.score,
        value.salt,
    );
    check(
        evaluation["commits"][&sender] == hex::encode(commitment),
        "PUBLIC_EVAL_COMMITMENT_BINDING",
    )?;
    evaluation["reveals"][&sender] = json!({"score":value.score,"evidence":hex::encode(value.evidence),"salt":hex::encode(value.salt)});
    Ok(())
}
/// Closure is a mandatory block transition after the admitted chain height deadline.
/// Missing signatures are an abort, never synthetic votes or a reduced quorum.
pub fn close(evaluation: &mut Value, height: u64) -> Result<Option<u64>> {
    if height <= n(&evaluation["plan"], "reveal_end")? || !evaluation["closed"].is_null() {
        return Ok(None);
    }
    let roster = evaluation["plan"]["roster"]
        .as_array()
        .ok_or("PUBLIC_EVAL_STATE")?;
    let missing: Vec<_> = roster
        .iter()
        .filter(|key| {
            evaluation["reveals"]
                .get(key.as_str().unwrap_or(""))
                .is_none()
        })
        .cloned()
        .collect();
    let conflicts = evaluation["conflicts"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?;
    let aborted = !missing.is_empty() || !conflicts.is_empty();
    let score = if aborted {
        None
    } else {
        evaluation["reveals"]
            .as_object()
            .ok_or("PUBLIC_EVAL_STATE")?
            .values()
            .map(|v| n(v, "score"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min()
    };
    check(aborted || score.is_some(), "PUBLIC_EVAL_STATE")?;
    evaluation["closed"] = json!({"schema":"pon-native-closed-evaluation-v2","round":evaluation["round"],"candidate":evaluation["plan"]["candidate"],"status":if aborted{"aborted"}else{"complete-scored"},"score":score,"missing_reveal_count":missing.len(),"conflict_count_before_close":conflicts.len(),"records_digest":hex::encode(records_digest(evaluation)?),"closed_height":height,"objective_model_quality":false,"independent_governance_accepted":false});
    Ok(score)
}
pub fn adoption_allowed(evaluation: &Value, height: u64) -> Result<()> {
    check(
        height >= n(&evaluation["plan"], "adoption_start")?
            && evaluation["closed"]["status"] == "complete-scored"
            && n(&evaluation["closed"], "score")? > 0
            && evaluation["conflicts"]
                .as_object()
                .ok_or("PUBLIC_EVAL_STATE")?
                .is_empty(),
        "PUBLIC_EVAL_ADOPTION",
    )
}
pub fn closed_digest(evaluation: &Value) -> Result<Hash> {
    check(!evaluation["closed"].is_null(), "PUBLIC_EVAL_NOT_CLOSED")?;
    Ok(hash(
        b"native-public-evaluation-closed-v2",
        &[&bytes(&evaluation["closed"])?],
    ))
}
pub fn appeal(
    evaluation: &mut Value,
    author: &str,
    sender: &str,
    result: Hash,
    claim: Hash,
    evidence: Hash,
    height: u64,
) -> Result<()> {
    check(
        height > n(&evaluation["plan"], "reveal_end")?,
        "PUBLIC_EVAL_APPEAL_PHASE",
    )?;
    if sender != author {
        evaluator(evaluation, sender, round(evaluation)?)?;
    }
    check(
        result == closed_digest(evaluation)? && claim != [0; 32] && evidence != [0; 32],
        "PUBLIC_EVAL_APPEAL_RESULT",
    )?;
    let id = hex::encode(hash(
        b"native-public-evaluation-appeal-v1",
        &[sender.as_bytes(), &result, &claim, &evidence],
    ));
    let appeals = evaluation["appeals"]
        .as_object()
        .ok_or("PUBLIC_EVAL_STATE")?;
    check(appeals.len() < 16, "PUBLIC_EVAL_APPEAL_LIMIT")?;
    check(!appeals.contains_key(&id), "DUPLICATE")?;
    evaluation["appeals"][id] = json!({"signer":sender,"result":hex::encode(result),"claim":hex::encode(claim),"evidence":hex::encode(evidence),"height":height,"effect":"record-only; closed score and past reward unchanged"});
    Ok(())
}
/// Independently verify two full signed transaction envelopes. Conflict evidence
/// can arrive outside the original phase, but cannot replace the frozen roster.
pub fn conflict(
    evaluation: &mut Value,
    cfg: &Config,
    candidate: Hash,
    first: &[u8],
    second: &[u8],
) -> Result<String> {
    let a = Envelope::decode(first).map_err(|_| "PUBLIC_EVAL_CONFLICT_CODEC")?;
    let b = Envelope::decode(second).map_err(|_| "PUBLIC_EVAL_CONFLICT_CODEC")?;
    check(
        a.network == cfg.network
            && b.network == cfg.network
            && a.sender == b.sender
            && a.tag == b.tag
            && matches!(a.tag, 14 | 15),
        "PUBLIC_EVAL_CONFLICT_CONTEXT",
    )?;
    for tx in [&a, &b] {
        verify_hex_strict(
            &hex::encode(tx.sender),
            &tx.signing_digest()
                .map_err(|_| "PUBLIC_EVAL_CONFLICT_CODEC")?,
            &hex::encode(tx.signature),
        )
        .map_err(|_| "PUBLIC_EVAL_CONFLICT_SIGNATURE")?;
        check(
            tx.payload[..32] == candidate && tx.payload[32..64] == round(evaluation)?,
            "PUBLIC_EVAL_CONFLICT_CONTEXT",
        )?;
        evaluator(evaluation, &hex::encode(tx.sender), round(evaluation)?)?;
        if tx.tag == 14 {
            check(tx.payload[64..96] != [0; 32], "PUBLIC_EVAL_COMMITMENT")?;
        } else {
            check(
                tx.payload[64..96] == cfg.plan
                    && tx.payload[96..128] != [0; 32]
                    && u64::from_le_bytes(
                        tx.payload[128..136]
                            .try_into()
                            .map_err(|_| "PUBLIC_EVAL_STATE")?,
                    ) <= n(&evaluation["plan"], "max_score")?,
                "PUBLIC_EVAL_REVEAL_CONTEXT",
            )?;
        }
    }
    check(a.payload != b.payload, "PUBLIC_EVAL_NOT_CONFLICT")?;
    let sender = hex::encode(a.sender);
    let key = format!("{sender}:{}", a.tag);
    check(evaluation["conflicts"].get(&key).is_none(), "DUPLICATE")?;
    let mut records = [hex::encode(first), hex::encode(second)];
    records.sort();
    evaluation["conflicts"][key] = json!({"records":records,"signer":sender,"effect":"current adoption blocked; next-round identity excluded; historical closure unchanged"});
    Ok(sender)
}

pub fn excluded(state: &BTreeMap<String, Value>) -> BTreeSet<String> {
    state
        .keys()
        .filter_map(|key| {
            key.strip_prefix("evaluation-disqualified:")
                .map(str::to_owned)
        })
        .collect()
}

/// Exact per-candidate prefix participates in MVCC scan validation.
pub fn record_prefix(candidate: Hash) -> String {
    format!("{RECORD_NAMESPACE}:{}:", hex::encode(candidate))
}
fn identity(kind: &str, id: &str) -> Result<()> {
    let valid_hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    check(
        if kind == "f" {
            id.split_once(':')
                .is_some_and(|(key, tag)| valid_hex(key) && matches!(tag, "14" | "15"))
        } else {
            valid_hex(id)
        },
        "PUBLIC_EVAL_RECORD_KEY",
    )
}
pub fn record_rows(candidate: Hash, evaluation: &Value) -> Result<BTreeMap<String, Value>> {
    check(
        evaluation["plan"]["candidate"] == hex::encode(candidate),
        "PUBLIC_EVAL_RECORD_CONTEXT",
    )?;
    let prefix = record_prefix(candidate);
    let mut rows = BTreeMap::new();
    for (kind, name, maximum) in MAPS {
        let map = evaluation[name].as_object().ok_or("PUBLIC_EVAL_STATE")?;
        check(map.len() <= maximum, "PUBLIC_EVAL_RECORD_LIMIT")?;
        for (id, value) in map {
            identity(kind, id)?;
            let key = format!("{prefix}{kind}:{id}");
            let row = json!({"schema":"pon-native-evaluation-record-v2","candidate":hex::encode(candidate),"kind":kind,"id":id,"value":value});
            check(
                key.len() <= 160 && bytes(&row)?.len() <= 4096,
                "PUBLIC_EVAL_RECORD_LIMIT",
            )?;
            rows.insert(key, row);
        }
    }
    Ok(rows)
}
pub fn compact(evaluation: &Value) -> Result<Value> {
    check(
        evaluation["storage_revision"] == STORAGE_REVISION,
        "PUBLIC_EVAL_STORAGE_REVISION",
    )?;
    let mut value = evaluation.clone();
    for (_, name, maximum) in MAPS {
        let map = value[name].as_object().ok_or("PUBLIC_EVAL_STATE")?;
        check(map.len() <= maximum, "PUBLIC_EVAL_RECORD_LIMIT")?;
        let count = map.len();
        value["record_counts"][name] = json!(count);
        value
            .as_object_mut()
            .ok_or("PUBLIC_EVAL_STATE")?
            .remove(name);
    }
    check(bytes(&value)?.len() <= 4096, "PUBLIC_EVAL_RECORD_LIMIT")?;
    Ok(value)
}
pub fn hydrate(compact: &Value, candidate: Hash, rows: &BTreeMap<String, Value>) -> Result<Value> {
    check(
        compact["storage_revision"] == STORAGE_REVISION
            && compact["plan"]["candidate"] == hex::encode(candidate),
        "PUBLIC_EVAL_STORAGE_REVISION",
    )?;
    let mut value = compact.clone();
    for (_, name, _) in MAPS {
        check(value.get(name).is_none(), "PUBLIC_EVAL_STORAGE_SHAPE")?;
        value[name] = json!({});
    }
    let prefix = record_prefix(candidate);
    for (key, row) in rows {
        let suffix = key
            .strip_prefix(&prefix)
            .ok_or("PUBLIC_EVAL_RECORD_CONTEXT")?;
        let (kind, id) = suffix.split_once(':').ok_or("PUBLIC_EVAL_RECORD_KEY")?;
        identity(kind, id)?;
        let (_, name, _) = MAPS
            .iter()
            .find(|(k, _, _)| *k == kind)
            .ok_or("PUBLIC_EVAL_RECORD_KEY")?;
        check(
            row.as_object().is_some_and(|m| m.len() == 5)
                && row["schema"] == "pon-native-evaluation-record-v2"
                && row["candidate"] == hex::encode(candidate)
                && row["kind"] == kind
                && row["id"] == id,
            "PUBLIC_EVAL_RECORD_CONTEXT",
        )?;
        value[*name][id] = row["value"].clone();
    }
    let expected = record_rows(candidate, &value)?;
    check(expected == *rows, "PUBLIC_EVAL_RECORD_CONTEXT")?;
    for (_, name, _) in MAPS {
        check(
            n(&value["record_counts"], name)?
                == value[name].as_object().ok_or("PUBLIC_EVAL_STATE")?.len() as u64,
            "PUBLIC_EVAL_RECORD_COUNT",
        )?;
    }
    Ok(value)
}
pub fn read_evaluation(state: &BTreeMap<String, Value>, candidate: Hash) -> Result<Value> {
    let hex = hex::encode(candidate);
    let contribution = state
        .get(&format!("contribution:{hex}"))
        .or_else(|| state.get(&format!("evaluation-archive:{hex}")))
        .ok_or("STATE")?;
    let prefix = record_prefix(candidate);
    let rows = state
        .range(prefix.clone()..)
        .take_while(|(key, _)| key.starts_with(&prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    hydrate(&contribution["public_evaluation"], candidate, &rows)
}
fn records_digest(evaluation: &Value) -> Result<Hash> {
    let snapshot = json!({"commits":evaluation["commits"],"reveals":evaluation["reveals"],"conflicts":evaluation["conflicts"]});
    Ok(hash(
        b"native-public-evaluation-closure-records-v2",
        &[&bytes(&snapshot)?],
    ))
}
