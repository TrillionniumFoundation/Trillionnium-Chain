//! PQ evidence uses bounded canonical chunks under the original State root.
//! Full signatures are retained; chunks use SHA-384 integrity, not extra signatures.
use super::*;
use sha2::{Digest, Sha384};

pub const REVISION: u64 = 6;
pub const QUORUM_REVISION: u64 = 7;
pub const NAMESPACE: &str = "ev-pq-v6";
/// Signed evidence does not attest when a signature was created. Its effect is
/// limited to the exact frozen authority generation and round that it names.
pub const CONFLICT_SCOPE: &str = "frozen-authority-round-v1";
const CHUNK_BYTES: usize = 1024;
const MAX_ENTRY_BYTES: usize = 65_536;
const MAX_CHUNKS: usize = MAX_ENTRY_BYTES / CHUNK_BYTES;
const SCHEMA: &str = "pon-evaluation-pq-chunk-v6";

pub fn enabled(evaluation: &Value) -> bool {
    matches!(
        evaluation["storage_revision"].as_u64(),
        Some(REVISION | QUORUM_REVISION)
    )
}

pub fn rows(candidate: Hash, evaluation: &Value) -> Result<BTreeMap<String, Value>> {
    is_quorum(evaluation)?;
    check(
        enabled(evaluation) && evaluation["plan"]["candidate"] == hex::encode(candidate),
        "PQ_EVAL_CONTEXT",
    )?;
    super::pq_conflict_signers(evaluation)?;
    let prefix = record_prefix_for(candidate, evaluation)?;
    let mut output = BTreeMap::new();
    for (kind, name, maximum) in MAPS {
        let map = evaluation[name].as_object().ok_or("PUBLIC_EVAL_STATE")?;
        check(map.len() <= maximum, "PUBLIC_EVAL_RECORD_LIMIT")?;
        for (id, value) in map {
            identity(kind, id)?;
            let raw = bytes(value)?;
            check(
                !raw.is_empty() && raw.len() <= MAX_ENTRY_BYTES,
                "PUBLIC_EVAL_RECORD_LIMIT",
            )?;
            let count = raw.len().div_ceil(CHUNK_BYTES);
            let base = format!("{prefix}{kind}:{id}");
            output.insert(format!("{base}:m"), json!({"schema":SCHEMA,"bytes":raw.len(),"chunks":count,"sha384":hex::encode(Sha384::digest(&raw))}));
            for (index, chunk) in raw.chunks(CHUNK_BYTES).enumerate() {
                output.insert(
                    format!("{base}:{index:04x}"),
                    json!({"schema":SCHEMA,"index":index,"bytes":hex::encode(chunk)}),
                );
            }
        }
    }
    check(
        output
            .iter()
            .all(|(k, v)| k.len() <= 160 && bytes(v).is_ok_and(|b| b.len() <= 4096)),
        "PUBLIC_EVAL_RECORD_LIMIT",
    )?;
    Ok(output)
}

pub fn hydrate(
    compact: &Value,
    candidate: Hash,
    records: &BTreeMap<String, Value>,
) -> Result<Value> {
    is_quorum(compact)?;
    check(
        enabled(compact) && compact["plan"]["candidate"] == hex::encode(candidate),
        "PQ_EVAL_CONTEXT",
    )?;
    check(
        records.len() <= MAPS.iter().map(|(_, _, n)| *n).sum::<usize>() * (MAX_CHUNKS + 1),
        "PUBLIC_EVAL_RECORD_LIMIT",
    )?;
    let prefix = record_prefix_for(candidate, compact)?;
    let mut value = compact.clone();
    for (_, name, _) in MAPS {
        check(value.get(name).is_none(), "PUBLIC_EVAL_STORAGE_SHAPE")?;
        value[name] = json!({});
    }
    for (key, manifest) in records.iter().filter(|(key, _)| key.ends_with(":m")) {
        let suffix = key
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(":m"))
            .ok_or("PQ_EVAL_CONTEXT")?;
        let (kind, id) = suffix.split_once(':').ok_or("PUBLIC_EVAL_RECORD_KEY")?;
        identity(kind, id)?;
        let (_, name, maximum) = MAPS
            .iter()
            .find(|(k, _, _)| *k == kind)
            .ok_or("PUBLIC_EVAL_RECORD_KEY")?;
        check(
            value[*name].as_object().ok_or("PUBLIC_EVAL_STATE")?.len() < *maximum,
            "PUBLIC_EVAL_RECORD_LIMIT",
        )?;
        let length =
            usize::try_from(n(manifest, "bytes")?).map_err(|_| "PUBLIC_EVAL_RECORD_LIMIT")?;
        let count =
            usize::try_from(n(manifest, "chunks")?).map_err(|_| "PUBLIC_EVAL_RECORD_LIMIT")?;
        check(
            length > 0
                && length <= MAX_ENTRY_BYTES
                && count == length.div_ceil(CHUNK_BYTES)
                && manifest["schema"] == SCHEMA,
            "PQ_EVAL_MANIFEST",
        )?;
        let base = key.strip_suffix(":m").ok_or("PQ_EVAL_MANIFEST")?;
        let mut raw = Vec::with_capacity(length);
        for index in 0..count {
            let row = records
                .get(&format!("{base}:{index:04x}"))
                .ok_or("PQ_EVAL_CHUNK_MISSING")?;
            check(
                row["schema"] == SCHEMA && n(row, "index")? == index as u64,
                "PQ_EVAL_CHUNK",
            )?;
            let encoded = row["bytes"].as_str().ok_or("PQ_EVAL_CHUNK")?;
            let expected = (length - index * CHUNK_BYTES).min(CHUNK_BYTES);
            check(encoded.len() == expected * 2, "PQ_EVAL_CHUNK")?;
            let chunk = hex::decode(encoded).map_err(|_| "PQ_EVAL_CHUNK")?;
            check(hex::encode(&chunk) == encoded, "PQ_EVAL_CHUNK")?;
            raw.extend(chunk);
        }
        check(
            manifest["sha384"] == hex::encode(Sha384::digest(&raw)),
            "PQ_EVAL_DIGEST",
        )?;
        let record: Value = serde_json::from_slice(&raw).map_err(|_| "PUBLIC_EVAL_STATE")?;
        check(bytes(&record)? == raw, "PQ_EVAL_CANONICAL")?;
        value[*name][id] = record;
    }
    check(
        rows(candidate, &value)? == *records,
        "PQ_EVAL_RECORD_COVERAGE",
    )?;
    for (_, name, _) in MAPS {
        check(
            n(&value["record_counts"], name)?
                == value[name].as_object().ok_or("PUBLIC_EVAL_STATE")?.len() as u64,
            "PUBLIC_EVAL_RECORD_COUNT",
        )?;
    }
    Ok(value)
}
