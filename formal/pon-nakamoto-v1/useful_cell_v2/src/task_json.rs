//! Strict bounded fixture/task transport. A parsed task is caller input, not an
//! authenticated model artifact, independently replayed corpus or owner grant.
use crate::*;
use serde_json::{Map, Value};
use trnm_crypto_primitives::{decode_hash32, Hash32};

pub const MAX_TASK_BYTES: usize = 256 * 1024;
fn fields<'a>(value: &'a Value, expected: &[&str]) -> Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or("JSON_OBJECT")?;
    if map.len() != expected.len() || expected.iter().any(|key| !map.contains_key(*key)) {
        return Err("JSON_FIELDS");
    }
    Ok(map)
}
fn hash(value: &Value) -> Result<Hash32> {
    let s = value.as_str().ok_or("JSON_HASH")?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("JSON_HASH");
    }
    decode_hash32("task", s).map_err(|_| "JSON_HASH")
}
fn uint(value: &Value) -> Result<u64> {
    value.as_u64().ok_or("JSON_UINT")
}
fn vector(value: &Value) -> Result<[i32; DIM]> {
    let values = value.as_array().ok_or("JSON_ARRAY")?;
    if values.len() != DIM {
        return Err("JSON_VECTOR_SHAPE");
    }
    let mut result = [0; DIM];
    for (out, value) in result.iter_mut().zip(values) {
        *out = i32::try_from(value.as_i64().ok_or("JSON_INT")?).map_err(|_| "JSON_I32")?;
    }
    Ok(result)
}
fn matrix(value: &Value) -> Result<[[i32; DIM]; CLASSES]> {
    let values = value.as_array().ok_or("JSON_ARRAY")?;
    if values.len() != CLASSES {
        return Err("JSON_MATRIX_SHAPE");
    }
    let mut result = [[0; DIM]; CLASSES];
    for (out, value) in result.iter_mut().zip(values) {
        *out = vector(value)?;
    }
    Ok(result)
}

/// Exact serde_json canonical representation (sorted object keys, no padding
/// whitespace). Equality to reserialization also rejects duplicate keys and
/// alternative numeric/escape spellings before accepting the parsed contract.
pub fn parse(bytes: &[u8]) -> Result<(PreparedModel, TaskContract)> {
    if bytes.len() > MAX_TASK_BYTES {
        return Err("TASK_SIZE");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "TASK_JSON")?;
    if serde_json::to_vec(&value).map_err(|_| "TASK_JSON")? != bytes {
        return Err("TASK_CANONICAL");
    }
    let top = fields(
        &value,
        &[
            "schema",
            "model",
            "context",
            "requests",
            "state",
            "bindings",
            "policy",
            "issued_at_ns",
            "valid_until_ns",
        ],
    )?;
    if top["schema"] != "pon-useful-cell-task-v2" {
        return Err("TASK_SCHEMA");
    }
    let m = fields(
        &top["model"],
        &["model_version", "base", "router", "deltas"],
    )?;
    let ds = m["deltas"].as_array().ok_or("JSON_ARRAY")?;
    if ds.len() != EXPERTS {
        return Err("JSON_EXPERT_SHAPE");
    }
    let mut deltas = [[[0; DIM]; CLASSES]; EXPERTS];
    for (out, value) in deltas.iter_mut().zip(ds) {
        *out = matrix(value)?;
    }
    let model = PreparedModel::new(Model {
        version: hash(&m["model_version"])?,
        base: matrix(&m["base"])?,
        router: matrix(&m["router"])?,
        deltas,
    })?;
    let c = fields(
        &top["context"],
        &["chain", "parent", "challenge", "batch_id"],
    )?;
    let context = Context {
        chain: hash(&c["chain"])?,
        parent: hash(&c["parent"])?,
        challenge: hash(&c["challenge"])?,
        batch_id: hash(&c["batch_id"])?,
    };
    let rs = top["requests"].as_array().ok_or("JSON_ARRAY")?;
    if !(1..=MAX_BATCH).contains(&rs.len()) {
        return Err("BATCH_SIZE");
    }
    let mut requests = Vec::with_capacity(rs.len());
    for item in rs {
        let r = fields(item, &["id", "scope", "arrival_ns", "deadline_ns", "x"])?;
        requests.push(Request {
            id: hash(&r["id"])?,
            scope: hash(&r["scope"])?,
            arrival_ns: uint(&r["arrival_ns"])?,
            deadline_ns: uint(&r["deadline_ns"])?,
            x: vector(&r["x"])?,
        });
    }
    let s = fields(
        &top["state"],
        &["cell_id", "generation", "snapshot_root", "model_commitment"],
    )?;
    let state = ReadOnlyState {
        cell_id: hash(&s["cell_id"])?,
        generation: uint(&s["generation"])?,
        snapshot_root: hash(&s["snapshot_root"])?,
        model_commitment: hash(&s["model_commitment"])?,
    };
    let b = fields(
        &top["bindings"],
        &[
            "program_digest",
            "extractor_digest",
            "source_inputs_digest",
            "consumer",
            "allowed_use",
            "candidate_artifact",
        ],
    )?;
    let bindings = Bindings {
        program_digest: hash(&b["program_digest"])?,
        extractor_digest: hash(&b["extractor_digest"])?,
        source_inputs_digest: hash(&b["source_inputs_digest"])?,
        consumer: hash(&b["consumer"])?,
        allowed_use: hash(&b["allowed_use"])?,
        candidate_artifact: hash(&b["candidate_artifact"])?,
    };
    let p = fields(
        &top["policy"],
        &["shift", "clamp_abs", "activation", "stop_rule"],
    )?;
    let activation = match p["activation"].as_str() {
        Some("identity") => Activation::Identity,
        Some("relu") => Activation::Relu,
        _ => return Err("ACTIVATION_POLICY"),
    };
    let stop = &p["stop_rule"];
    let stop_rule = match stop.get("kind").and_then(Value::as_str) {
        Some("disabled") => {
            fields(stop, &["kind"])?;
            StopRule::Disabled
        }
        Some("margin_at_least") => {
            let s = fields(stop, &["kind", "threshold"])?;
            StopRule::MarginAtLeast(
                u32::try_from(uint(&s["threshold"])?).map_err(|_| "STOP_POLICY")?,
            )
        }
        _ => return Err("STOP_POLICY"),
    };
    let policy = Policy {
        shift: u8::try_from(uint(&p["shift"])?).map_err(|_| "QUANTIZATION_POLICY")?,
        clamp_abs: i32::try_from(uint(&p["clamp_abs"])?).map_err(|_| "QUANTIZATION_POLICY")?,
        activation,
        stop_rule,
    };
    let expected = TaskContract::new(
        &model,
        context,
        requests,
        state,
        bindings,
        policy,
        uint(&top["issued_at_ns"])?,
        uint(&top["valid_until_ns"])?,
    )?;
    Ok((model, expected))
}
