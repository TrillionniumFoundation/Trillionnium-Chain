//! Exact original development service request and bounded immutable file reader.
//! The request grammar is retained from learning_service_receipt without any
//! runtime execution, model loader, payment or installation capability.
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
        before.is_file()
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= maximum,
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
