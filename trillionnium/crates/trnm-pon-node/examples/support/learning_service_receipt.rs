//! Bounded byte binding for the existing inherited-runtime operation readback.
//!
//! This is a local development service contract, not an independent evaluator
//! or an execution attestation. The Python operation owner remains responsible
//! for executing and verifying the model. This adapter checks its exact retained
//! files and never upgrades an unsigned receipt into model or reward authority.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use trnm_pon_node::Result;
use trnm_protocol::pon_wire::{hash, Hash};

pub const MAX_JSON: u64 = 2 * 1024 * 1024;
pub const MAX_ARTIFACT: u64 = 16 * 1024 * 1024;
pub const REQUEST_SCHEMA: &str = "native-learning-service-request-v1";
pub const READBACK_SCHEMA: &str = "hepta-smollm-operation-readback-v1";

pub fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(code.into())
    }
}

pub fn sha(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub fn digest(text: &str) -> Result<Hash> {
    check(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "LEARNING_DIGEST",
    )?;
    let value: Hash = hex::decode(text)
        .map_err(|_| "LEARNING_DIGEST")?
        .try_into()
        .map_err(|_| "LEARNING_DIGEST")?;
    check(value != [0; 32], "LEARNING_DIGEST")?;
    Ok(value)
}

pub fn field_digest(value: &Value, field: &str) -> Result<Hash> {
    digest(value[field].as_str().ok_or("LEARNING_DIGEST")?)
}

fn label(text: &str) -> Result<()> {
    check(
        !text.is_empty()
            && text.len() <= 128
            && text.as_bytes()[0].is_ascii_alphanumeric()
            && text
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "LEARNING_OPERATION_ID",
    )
}

pub fn no_authority() -> Value {
    json!({"installation_authorized":false,"selection_authorized":false,
        "independent_accepted":false,"prospective_accepted":false,
        "public_reward_eligible":false,"hepta_final_use":false})
}

/// Reject aliases and read one regular-file descriptor into an immutable bound.
pub fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    check(
        path.is_absolute() && path.canonicalize()? == path,
        "LEARNING_FILE_PATH",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    check(
        before.is_file() && before.nlink() == 1 && before.len() > 0 && before.len() <= maximum,
        "LEARNING_FILE_BOUND",
    )?;
    let mut raw = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    check(
        raw.len() as u64 == before.len() && identity(&before) == identity(&after),
        "LEARNING_FILE_CHANGED",
    )?;
    Ok(raw)
}

// Value's ordinary deserializer accepts duplicate object keys. These receipts
// are commitments, so reject duplicates at every depth without rewriting bytes.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut input: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = input.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut input: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = input.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub fn decode(raw: &[u8]) -> Result<Value> {
    check(raw.len() as u64 <= MAX_JSON, "LEARNING_JSON_BOUND")?;
    Ok(serde_json::from_slice::<Unique>(raw)?.0)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub provider_authority_id: String,
    pub operation_id: String,
    pub output_directory: String,
    pub base_fee: u64,
    pub training_cpu_cap_ns: u64,
    pub parameter_byte_cap: u64,
    pub evaluation_protocol_sha256: String,
}

impl Request {
    pub fn parse(raw: &[u8], plan: &Value) -> Result<Self> {
        let request: Self = serde_json::from_value(decode(raw)?)?;
        check(request.schema == REQUEST_SCHEMA, "LEARNING_REQUEST_SCHEMA")?;
        digest(&request.provider_authority_id)?;
        digest(&request.evaluation_protocol_sha256)?;
        label(&request.operation_id)?;
        check(
            (1..=1_000_000).contains(&request.base_fee)
                && (1..=(1_u64 << 62)).contains(&request.training_cpu_cap_ns)
                && (1..=MAX_ARTIFACT).contains(&request.parameter_byte_cap),
            "LEARNING_REQUEST_BUDGET",
        )?;
        let output = Path::new(&request.output_directory);
        check(
            output.is_absolute()
                && output.file_name().is_some()
                && output
                    .parent()
                    .ok_or("LEARNING_OUTPUT_PATH")?
                    .canonicalize()?
                    == output.parent().ok_or("LEARNING_OUTPUT_PATH")?,
            "LEARNING_OUTPUT_PATH",
        )?;
        check(
            plan["schema"] == "hepta-smollm-inherited-execution-v1"
                && plan["phase"] == "train"
                && plan["operation_id"] == request.operation_id
                && plan["authority"] == no_authority()
                && plan["runtime"]["backend"] == "cpu"
                && plan["runtime"]["threads"]
                    .as_u64()
                    .is_some_and(|n| (1..=4).contains(&n)),
            "LEARNING_PLAN_SCOPE",
        )?;
        let parent = &plan["parent"];
        check(
            parent["schema"] == "hepta-smollm-parent-material-v1"
                && parent["operation_id"]
                    .as_str()
                    .is_some_and(|s| s != request.operation_id)
                && parent["generation"].as_u64().and_then(|n| n.checked_add(1))
                    == plan["generation"].as_u64()
                && plan["generation"]
                    .as_u64()
                    .is_some_and(|n| (2..(1_u64 << 63)).contains(&n)),
            "LEARNING_PARENT_REQUIRED",
        )?;
        for key in ["contract", "adapter", "file_sha256"] {
            field_digest(parent, key)?;
        }
        field_digest(plan, "inputs_sha256")?;
        let source = plan["source_pins"]
            .as_object()
            .ok_or("LEARNING_SOURCE_PINS")?;
        check(
            !source.is_empty() && source.len() <= 16,
            "LEARNING_SOURCE_PINS",
        )?;
        for value in source.values() {
            digest(value.as_str().ok_or("LEARNING_SOURCE_PINS")?)?;
        }
        Ok(request)
    }

    pub fn native_operation(&self) -> Result<Hash> {
        Ok(hash(
            b"native-learning-provider-operation-v1",
            &[
                &digest(&self.provider_authority_id)?,
                self.operation_id.as_bytes(),
            ],
        ))
    }
}

pub struct SuccessfulReadback {
    pub canonical_readback: Vec<u8>,
    pub files: Vec<(&'static str, Vec<u8>)>,
    pub provider_costs: Value,
    pub cpu_ns: Option<u64>,
    pub artifact_bytes: u64,
    pub artifact: Hash,
    pub output: Hash,
    pub receipt: Hash,
    pub measurement_receipt: Hash,
}

pub fn validate_readback(
    value: &Value,
    request: &Request,
    plan_sha256: Hash,
    intent: Hash,
) -> Result<()> {
    let fields = [
        "schema",
        "authority_id",
        "operation_id",
        "intent_sha256",
        "status",
        "dispatch_allowed",
        "reservation",
        "original_output",
        "plan_sha256",
        "observation",
        "no_update_decided",
        "payment_authorized",
        "authority",
        "evaluation_profile_sha256",
    ];
    let object = value.as_object().ok_or("LEARNING_READBACK")?;
    check(
        object.len() == fields.len() && fields.iter().all(|name| object.contains_key(*name)),
        "LEARNING_READBACK_FIELDS",
    )?;
    check(
        value["schema"] == READBACK_SCHEMA
            && value["authority_id"] == request.provider_authority_id
            && value["operation_id"] == request.operation_id
            && field_digest(value, "intent_sha256")? == intent
            && field_digest(value, "plan_sha256")? == plan_sha256
            && value["evaluation_profile_sha256"] == request.evaluation_protocol_sha256
            && value["original_output"] == request.output_directory
            && value["dispatch_allowed"] == false
            && value["reservation"] == "RETAINED"
            && value["no_update_decided"] == false
            && value["payment_authorized"] == false
            && value["authority"] == no_authority(),
        "LEARNING_READBACK_BINDING",
    )?;
    match value["status"].as_str() {
        Some("UNKNOWN") => check(value["observation"].is_null(), "LEARNING_UNKNOWN"),
        Some(status @ ("SUCCESS" | "FAILED")) => check(
            value["observation"]["status"] == status,
            "LEARNING_TERMINAL_STATUS",
        ),
        _ => Err("LEARNING_READBACK_STATUS".into()),
    }
}

/// Read every pinned local output once. This does not authenticate the provider
/// journal or independently establish that the claimed training happened.
pub fn success(
    value: &Value,
    request: &Request,
    plan_raw: &[u8],
    plan: &Value,
) -> Result<SuccessfulReadback> {
    check(value["status"] == "SUCCESS", "LEARNING_SUCCESS_REQUIRED")?;
    const FILES: [&str; 7] = [
        "execution-plan.json",
        "supervisor.json",
        "worker/actual-receipt.json",
        "worker/parent-material.json",
        "worker/target-contract.json",
        "worker/wrapped-adapter.json",
        "worker/artifact.safetensors",
    ];
    let observation = &value["observation"];
    let pins = observation["pins"]
        .as_object()
        .ok_or("LEARNING_FILE_PINS")?;
    check(
        pins.len() == FILES.len() && FILES.iter().all(|n| pins.contains_key(*n)),
        "LEARNING_FILE_PINS",
    )?;
    let directory = Path::new(&request.output_directory);
    let mut files = Vec::new();
    for name in FILES {
        let maximum = if name.ends_with("safetensors") {
            MAX_ARTIFACT
        } else {
            MAX_JSON
        };
        let raw = read(&directory.join(name), maximum)?;
        check(
            pins[name].as_object().is_some_and(|m| m.len() == 2)
                && pins[name]["bytes"] == raw.len() as u64
                && field_digest(&pins[name], "sha256")? == sha(&raw),
            "LEARNING_FILE_IDENTITY",
        )?;
        files.push((name, raw));
    }
    check(files[0].1 == plan_raw, "LEARNING_EXECUTION_PLAN_CHANGED")?;
    let supervisor = decode(&files[1].1)?;
    check(
        supervisor["outcome"] == "success"
            && supervisor["exit_code"] == 0
            && supervisor["stop_reason"].is_null()
            && supervisor["waited_child_reaped"] == true
            && supervisor["owned_child_reap_resolved"] == true
            && supervisor["waited_child_observation_error"].is_null()
            && supervisor["budget"] == plan["runtime"]["training_budget"],
        "LEARNING_SUPERVISOR_UNRESOLVED",
    )?;
    let costs = &observation["costs"];
    let cost_fields = [
        "observed_wall_ns",
        "child_cpu_ns",
        "observer_cpu_ns",
        "waited_child_peak_rss_bytes",
    ];
    check(
        costs
            .as_object()
            .is_some_and(|m| m.len() == cost_fields.len()),
        "LEARNING_COSTS",
    )?;
    for key in cost_fields {
        check(
            costs.get(key).is_some()
                && (costs[key].is_null() || costs[key].as_u64().is_some_and(|n| n < 1_u64 << 63))
                && costs[key] == supervisor[key],
            "LEARNING_COST_BINDING",
        )?;
    }
    let cpu_ns = match (
        costs["child_cpu_ns"].as_u64(),
        costs["observer_cpu_ns"].as_u64(),
    ) {
        (Some(child), Some(observer)) => {
            Some(child.checked_add(observer).ok_or("LEARNING_CPU_OVERFLOW")?)
        }
        _ => None,
    };
    let actual = decode(&files[2].1)?;
    for key in [
        "operation_id",
        "phase",
        "generation",
        "parent",
        "source_pins",
        "authority",
    ] {
        check(actual[key] == plan[key], "LEARNING_ACTUAL_RECEIPT_BINDING")?;
    }
    let artifact = field_digest(observation, "artifact")?;
    check(
        actual["schema"] == "hepta-smollm-inherited-execution-v1"
            && actual["outcome"] == "success"
            && actual["actual_backend"] == "cpu"
            && field_digest(&actual, "artifact")? == artifact
            && actual["actual_loaded_parent"] == plan["parent"]["adapter"]
            && actual["contract"] == plan["parent"]["contract"]
            && actual["input_sha256"] == plan["inputs_sha256"]
            && field_digest(&actual, "plan_sha256")? == sha(plan_raw)
            && field_digest(&actual, "parent_material_sha256")? == sha(&files[3].1),
        "LEARNING_ACTUAL_RECEIPT_BINDING",
    )?;
    let steps = plan["runtime"]["training_steps"]
        .as_u64()
        .ok_or("LEARNING_TRAINING_STEPS")?;
    check(
        (1..=100).contains(&steps)
            && actual["training"]["steps"] == steps
            && actual["training"]["loss"]
                .as_array()
                .is_some_and(|v| v.len() as u64 == steps)
            && actual["training"]["tokens"].as_u64().is_some_and(|n| n > 0)
            && actual["training"]["supervised_tokens"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "LEARNING_TRAINING_COMPLETION",
    )?;
    let material = decode(&files[3].1)?;
    check(
        material["schema"] == "hepta-smollm-parent-material-v1"
            && material["operation_id"] == request.operation_id
            && material["generation"] == plan["generation"]
            && material["directory"].as_str() == directory.join("worker").to_str()
            && material["contract"] == actual["contract"]
            && field_digest(&material, "adapter")? == artifact
            && field_digest(&material, "file_sha256")? == sha(&files[6].1),
        "LEARNING_OUTPUT_MATERIAL_BINDING",
    )?;
    // The original Python owner verifies tensor semantics. Here both complete
    // manifests are also retained and hash-bound, with no claim of a Rust replay.
    let target = decode(&files[4].1)?;
    let wrapped = decode(&files[5].1)?;
    check(
        target["schema"] == "pon-target-decoder-adapter-contract-v1"
            && hash(b"target-decoder-adapter-contract-v1", &[&files[4].1])
                == field_digest(&material, "contract")?
            && wrapped["schema"] == "pon-wrapped-decoder-lora-material-v1"
            && wrapped["contract"] == material["contract"]
            && hash(b"wrapped-decoder-lora-material-v1", &[&files[5].1]) == artifact,
        "LEARNING_MANIFEST_IDENTITY",
    )?;
    let artifact_bytes = files[6].1.len() as u64;
    check(
        artifact_bytes <= request.parameter_byte_cap,
        "LEARNING_PARAMETER_CAP",
    )?;
    if let Some(cpu) = cpu_ns {
        check(cpu <= request.training_cpu_cap_ns, "LEARNING_CPU_CAP")?;
    }
    let canonical_readback = serde_json::to_vec(value)?;
    let receipt = hash(
        b"native-learning-provider-readback-v1",
        &[&canonical_readback],
    );
    let output = hash(
        b"native-learning-service-output-v1",
        &[
            &artifact,
            &sha(&files[6].1),
            &sha(&files[2].1),
            &sha(plan_raw),
        ],
    );
    Ok(SuccessfulReadback {
        canonical_readback,
        provider_costs: costs.clone(),
        cpu_ns,
        artifact_bytes,
        artifact,
        output,
        receipt,
        measurement_receipt: sha(&files[1].1),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_commitment_keys_at_every_depth() {
        for raw in [br#"{"a":1,"a":2}"#.as_slice(), br#"{"a":[{"b":1,"b":2}]}"#] {
            assert!(decode(raw).is_err());
        }
        assert_eq!(
            decode(br#"{"a":[1,true,null]}"#).unwrap(),
            json!({"a":[1,true,null]})
        );
    }

    #[test]
    fn snapshots_refuse_links_and_oversized_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("receipt.json");
        fs::write(&file, b"{}").unwrap();
        assert!(read(&file, 1).is_err());
        let link = directory.path().join("alias.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read(&link, MAX_JSON).is_err());
        assert_eq!(read(&file, MAX_JSON).unwrap(), b"{}");
    }
}
