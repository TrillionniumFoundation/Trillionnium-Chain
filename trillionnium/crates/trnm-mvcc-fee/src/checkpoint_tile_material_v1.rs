//! Independent checkpoint-to-material replay, never ledger or hardness authority.
//! Full checkpoint bytes, bounded original activation bits and all derived A/B
//! values are checked. An observed hook is not proof of a complete model forward.
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Seek, SeekFrom},
};
use trnm_crypto_primitives::{pon_work, qualified_work_task::DevelopmentTaskAdmission};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::QualifiedWorkTask,
};

pub const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACTIVATION_BYTES: usize = 1024 * 1024;
pub const MAX_DESCRIPTOR_BYTES: usize = 32 * 1024;
const TENSOR: &str = "model.layers.0.self_attn.q_proj.weight";
const WIDTH: usize = 576;
const SIDE: usize = 64;
const BYTES: usize = 64 * 64 * 4;
const Q: i64 = 4294967291;
const ORIGIN: &str = "actual-layer0-q_proj-prehook-post-RMSNorm";
const SCOPE: &str =
    "observed CPU base-model hook; no independent full-forward proof or source authority";
pub type MaterialResult<T> = std::result::Result<T, &'static str>;
fn require(ok: bool, error: &'static str) -> MaterialResult<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}

/// Independent caller pinnings. Descriptor fields never select these expectations.
#[derive(Clone, Debug)]
pub struct PinnedTileContextV1 {
    pub network: Hash,
    pub parameters: Hash,
    pub checkpoint_sha256: Hash,
    pub checkpoint_bytes: u64,
    pub activation_sha256: Hash,
    pub model: Hash,
    pub input: Hash,
}
impl PinnedTileContextV1 {
    fn validate(&self) -> MaterialResult<()> {
        require(
            (10..=MAX_CHECKPOINT_BYTES).contains(&self.checkpoint_bytes),
            "CHECKPOINT_LIMIT",
        )?;
        require(
            [
                self.network,
                self.parameters,
                self.checkpoint_sha256,
                self.activation_sha256,
                self.model,
                self.input,
            ]
            .iter()
            .all(|v| *v != [0; 32]),
            "PINNED_CONTEXT",
        )
    }
}
pub fn policy_id() -> Hash {
    hash(b"checkpoint-tile-material-policy-v1", &[b"complete-SHA256-file512MiB/header16MiB/unique-json-depth128-map8192-array65536-name256/Smol-qproj-BF16-576x576-prefix64/F32LE-activation1MiB-T1..64-width576/exact-integer-ties-even-scale14-4-clip32767-128/no-nonfinite/field4294967291-Aoutk-Bktoken-pad-to64/descriptor32KiB/private-checked-no-chain-no-forward-no-hardness"])
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TileMaterialDescriptorV1 {
    pub schema: String,
    pub policy: String,
    pub network: String,
    pub parameters: String,
    pub checkpoint_sha256: String,
    pub checkpoint_bytes: u64,
    pub header_sha256: String,
    pub header_bytes: u64,
    pub tensor_count: usize,
    pub tensor: String,
    pub tensor_dtype: String,
    pub tensor_shape: [u64; 2],
    pub tensor_offsets: [u64; 2],
    pub output_coordinates: [u64; 2],
    pub input_coordinates: [u64; 2],
    pub activation_sha256: String,
    pub activation_width: u64,
    pub real_token_columns: usize,
    pub padded_token_columns: usize,
    pub weight_scale_power: u8,
    pub activation_scale_power: u8,
    pub weight_clip: i64,
    pub activation_clip: i64,
    pub weight_clipped: usize,
    pub activation_clipped: usize,
    pub a_nonzero: usize,
    pub b_nonzero: usize,
    pub a_sha256: String,
    pub b_sha256: String,
    pub model: String,
    pub input: String,
    pub matrix_task: String,
    pub dense_base_product_multiplications: usize,
    pub sparse_b_base_product_multiplications: usize,
    pub chain_authority: bool,
    pub full_forward_verified: bool,
    pub hardness_accepted: bool,
    pub genuine_demand_verified: bool,
    pub marginal_contribution_accepted: bool,
}
/// Only successful original-byte replay constructs this immutable relationship.
#[derive(Debug)]
pub struct CheckedCheckpointTileMaterialV1 {
    descriptor: TileMaterialDescriptorV1,
    canonical_descriptor: Vec<u8>,
    descriptor_id: Hash,
    context: PinnedTileContextV1,
    matrix_task: Hash,
    checkpoint_bytes_read: u64,
}
impl CheckedCheckpointTileMaterialV1 {
    pub fn descriptor(&self) -> &TileMaterialDescriptorV1 {
        &self.descriptor
    }
    pub fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }
    pub fn descriptor_id(&self) -> Hash {
        self.descriptor_id
    }
    pub fn checkpoint_bytes_read(&self) -> u64 {
        self.checkpoint_bytes_read
    }
    /// Bind the source-signature/context-checked crypto manifest. This does not
    /// check durable parent eligibility, withdrawal, replay or output consumption;
    /// the original Node owner still decides those facts from actual chain State.
    /// This produces no transaction, source permission, reward or chain weight.
    pub fn bind_admission(&self, admission: &DevelopmentTaskAdmission) -> MaterialResult<Hash> {
        let m = admission.manifest();
        m.validate().map_err(|_| "ADMISSION_MANIFEST")?;
        require(
            m.network == self.context.network && m.parameters == self.context.parameters,
            "ADMISSION_CONTEXT",
        )?;
        require(
            m.model == self.context.model
                && m.input == self.context.input
                && m.matrix_task == self.matrix_task
                && m.layer == QualifiedWorkTask::layer_id(self.context.model)
                && m.recipe == QualifiedWorkTask::recipe_id(),
            "ADMISSION_MATERIAL",
        )?;
        Ok(hash(
            b"checkpoint-tile-admission-binding-v1",
            &[&self.descriptor_id, &admission.manifest_id()],
        ))
    }
}

// Unique keys are checked recursively before conversion to typed closed records.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded unique JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, _v: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("JSON_FLOAT"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut rows = Vec::new();
                while let Some(v) = a.next_element::<UniqueValue>()? {
                    if rows.len() >= 65536 {
                        return Err(de::Error::custom("JSON_ARRAY_LIMIT"));
                    }
                    rows.push(v.0);
                }
                Ok(UniqueValue(Value::Array(rows)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut rows = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if rows.len() >= 8192 {
                        return Err(de::Error::custom("JSON_MAP_LIMIT"));
                    }
                    if rows.contains_key(&k) {
                        return Err(de::Error::custom("JSON_DUPLICATE"));
                    }
                    rows.insert(k, a.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(rows)))
            }
        }
        d.deserialize_any(V)
    }
}
fn parse(raw: &[u8], limit: usize) -> MaterialResult<Value> {
    require(raw.len() <= limit, "JSON_BYTE_LIMIT")?;
    let mut d = serde_json::Deserializer::from_slice(raw);
    let v = UniqueValue::deserialize(&mut d).map_err(|_| "STRICT_JSON")?;
    d.end().map_err(|_| "STRICT_JSON")?;
    Ok(v.0)
}
fn sha(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn canonical_descriptor(d: &TileMaterialDescriptorV1) -> MaterialResult<Vec<u8>> {
    let v = serde_json::to_value(d).map_err(|_| "DESCRIPTOR_ENCODING")?;
    let sorted: BTreeMap<_, _> = v
        .as_object()
        .ok_or("DESCRIPTOR_ENCODING")?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    serde_json::to_vec(&sorted).map_err(|_| "DESCRIPTOR_ENCODING")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tensor {
    dtype: String,
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}
fn tensor_header(raw: &[u8], payload: u64) -> MaterialResult<([u64; 2], usize)> {
    let v = parse(raw, MAX_HEADER_BYTES)?;
    let map = v.as_object().ok_or("HEADER_OBJECT")?;
    let mut spans = Vec::new();
    let mut target = None;
    for (name, item) in map {
        require(!name.is_empty() && name.len() <= 256, "TENSOR_NAME")?;
        if name == "__metadata__" {
            require(
                item.as_object().is_some_and(|m| {
                    m.iter()
                        .all(|(k, v)| k.len() <= 256 && v.as_str().is_some_and(|s| s.len() <= 4096))
                }),
                "METADATA",
            )?;
            continue;
        }
        let t: Tensor = serde_json::from_value(item.clone()).map_err(|_| "TENSOR_FIELDS")?;
        require(
            (1..=8).contains(&t.shape.len()) && t.shape.iter().all(|d| *d > 0 && *d < (1 << 31)),
            "TENSOR_SHAPE",
        )?;
        let width = match t.dtype.as_str() {
            "BOOL" | "U8" | "I8" => 1,
            "U16" | "I16" | "F16" | "BF16" => 2,
            "U32" | "I32" | "F32" => 4,
            "U64" | "I64" | "F64" => 8,
            _ => return Err("TENSOR_DTYPE"),
        };
        let bytes = t
            .shape
            .iter()
            .try_fold(width, |a: u64, b| a.checked_mul(*b))
            .ok_or("TENSOR_EXTENT")?;
        require(
            t.data_offsets[1].checked_sub(t.data_offsets[0]) == Some(bytes)
                && t.data_offsets[1] <= payload,
            "TENSOR_EXTENT",
        )?;
        if name == TENSOR {
            require(
                t.dtype == "BF16" && t.shape == [WIDTH as u64; 2],
                "TARGET_TENSOR",
            )?;
            target = Some(t.data_offsets);
        }
        spans.push(t.data_offsets);
    }
    spans.sort_unstable();
    let mut end = 0;
    for [start, next] in &spans {
        require(*start == end, "TENSOR_COVERAGE")?;
        end = *next;
    }
    require(!spans.is_empty() && end == payload, "TENSOR_COVERAGE")?;
    Ok((target.ok_or("TARGET_TENSOR")?, spans.len()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    device: String,
    python: String,
    torch: String,
    transformers: String,
    safetensors: String,
    numpy: String,
    threads: u64,
    base_only: bool,
    training: bool,
    local_files_only: bool,
    trust_remote_code: bool,
    forward_calls: u64,
    hook_calls: u64,
    parameter_count: u64,
    storage_dtype: String,
    material_manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    schema: String,
    checkpoint_sha256: String,
    dtype: String,
    shape: [u64; 3],
    token_ids: Vec<u64>,
    attention_mask: Vec<u64>,
    positions: Vec<u64>,
    hidden_hex: String,
    producer_script_sha256: String,
    prompt_utf8_sha256: String,
    runtime: Runtime,
    activation_origin: String,
    scope: String,
}
fn hex_hash(v: &str) -> MaterialResult<Hash> {
    require(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "HASH_ENCODING",
    )?;
    hex::decode(v)
        .map_err(|_| "HASH_ENCODING")?
        .try_into()
        .map_err(|_| "HASH_ENCODING")
}
fn activation(raw: &[u8], ctx: &PinnedTileContextV1) -> MaterialResult<(usize, Vec<u8>)> {
    require(sha(raw) == ctx.activation_sha256, "ACTIVATION_PIN")?;
    let a: Activation = serde_json::from_value(parse(raw, MAX_ACTIVATION_BYTES)?)
        .map_err(|_| "ACTIVATION_FIELDS")?;
    require(
        a.schema == "checkpoint-qproj-postnorm-activation-v1"
            && hex_hash(&a.checkpoint_sha256)? == ctx.checkpoint_sha256
            && a.dtype == "F32LE"
            && a.activation_origin == ORIGIN
            && a.scope == SCOPE,
        "ACTIVATION_PROFILE",
    )?;
    require(
        a.shape[0] == 1 && a.shape[2] == WIDTH as u64 && (1..=64).contains(&a.shape[1]),
        "ACTIVATION_SHAPE",
    )?;
    let t = a.shape[1] as usize;
    require(
        a.token_ids.len() == t
            && a.token_ids.iter().all(|v| *v < 49152)
            && a.attention_mask == vec![1; t]
            && a.positions == (0..t as u64).collect::<Vec<_>>(),
        "TOKEN_FIELDS",
    )?;
    hex_hash(&a.producer_script_sha256)?;
    hex_hash(&a.prompt_utf8_sha256)?;
    let r = a.runtime;
    hex_hash(&r.material_manifest_sha256)?;
    require(
        r.device == "cpu"
            && r.storage_dtype == "float32"
            && r.base_only
            && !r.training
            && r.local_files_only
            && !r.trust_remote_code
            && r.threads == 2
            && r.forward_calls == 1
            && r.hook_calls == 1
            && r.parameter_count == 134515008
            && [
                &r.python,
                &r.torch,
                &r.transformers,
                &r.safetensors,
                &r.numpy,
            ]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 128),
        "ACTIVATION_OBSERVATION_SCOPE",
    )?;
    require(
        a.hidden_hex.len() == t * WIDTH * 8
            && a.hidden_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "ACTIVATION_BITS",
    )?;
    Ok((t, hex::decode(a.hidden_hex).map_err(|_| "ACTIVATION_BITS")?))
}
/// Integer-only IEEE decoding, exact nearest/even before clipping. Large finite
/// exponents saturate before a shift; subnormals and signed zeros remain exact.
fn quantize(bits: u32, mantissa: u32, scale: i32, clip: i64) -> MaterialResult<(i64, bool)> {
    let exponent = (bits >> mantissa) & 255;
    require(exponent != 255, "NONFINITE")?;
    let negative = bits >> (mantissa + 8) != 0;
    let fraction = bits & ((1 << mantissa) - 1);
    let significand = if exponent == 0 {
        fraction as u64
    } else {
        (fraction | (1 << mantissa)) as u64
    };
    let power = if exponent == 0 {
        1 - 127 - mantissa as i32 + scale
    } else {
        exponent as i32 - 127 - mantissa as i32 + scale
    };
    let rounded = if power >= 0 {
        if power >= 63 || significand > (clip as u64 >> power) {
            clip as u64 + 1
        } else {
            significand << power
        }
    } else {
        let n = (-power) as u32;
        if n >= 64 {
            0
        } else {
            let whole = significand >> n;
            let rem = significand & ((1u64 << n) - 1);
            let half = 1u64 << (n - 1);
            whole + u64::from(rem > half || (rem == half && whole & 1 == 1))
        }
    };
    let clipped = rounded > clip as u64;
    let value = rounded.min(clip as u64) as i64;
    Ok((if negative { -value } else { value }, clipped))
}
fn encode_matrix(values: &[i64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| (v.rem_euclid(Q) as u32).to_le_bytes())
        .collect()
}

/// Derive and check all original material bytes. The full hash and tile use the
/// same second streaming read, with parsed header bytes compared against that
/// stream. No later un-hashed tile read can race the original-file commitment.
pub fn derive_checkpoint_tile_material_v1<R: Read + Seek, F: FnMut(u64) -> MaterialResult<()>>(
    checkpoint: &mut R,
    activation_raw: &[u8],
    expected_a: &[u8],
    expected_b: &[u8],
    ctx: &PinnedTileContextV1,
    mut progress: F,
) -> MaterialResult<CheckedCheckpointTileMaterialV1> {
    ctx.validate()?;
    require(
        activation_raw.len() <= MAX_ACTIVATION_BYTES
            && expected_a.len() == BYTES
            && expected_b.len() == BYTES,
        "MATERIAL_LIMIT",
    )?;
    let (tokens, hidden) = activation(activation_raw, ctx)?;
    require(
        checkpoint
            .seek(SeekFrom::End(0))
            .map_err(|_| "CHECKPOINT_IO")?
            == ctx.checkpoint_bytes,
        "CHECKPOINT_SIZE",
    )?;
    checkpoint
        .seek(SeekFrom::Start(0))
        .map_err(|_| "CHECKPOINT_IO")?;
    let mut length = [0; 8];
    checkpoint
        .read_exact(&mut length)
        .map_err(|_| "CHECKPOINT_IO")?;
    let n = u64::from_le_bytes(length);
    require(
        (2..=MAX_HEADER_BYTES as u64).contains(&n) && n + 8 <= ctx.checkpoint_bytes,
        "HEADER_LIMIT",
    )?;
    let mut header = vec![0; n as usize];
    checkpoint
        .read_exact(&mut header)
        .map_err(|_| "CHECKPOINT_IO")?;
    progress(n + 8)?;
    let (offsets, tensor_count) = tensor_header(&header, ctx.checkpoint_bytes - 8 - n)?;
    let payload = 8 + n;
    checkpoint
        .seek(SeekFrom::Start(0))
        .map_err(|_| "CHECKPOINT_IO")?;
    let mut tile = vec![0; SIDE * SIDE * 2];
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut pos = 0u64;
    while pos < ctx.checkpoint_bytes {
        let amount = (ctx.checkpoint_bytes - pos).min(buffer.len() as u64) as usize;
        checkpoint
            .read_exact(&mut buffer[..amount])
            .map_err(|_| "CHECKPOINT_IO")?;
        let chunk = &buffer[..amount];
        hasher.update(chunk);
        if pos < 8 {
            let last = 8.min(pos + amount as u64);
            require(
                chunk[..(last - pos) as usize] == length[pos as usize..last as usize],
                "CHECKPOINT_CHANGED",
            )?;
        }
        let lo = pos.max(8);
        let hi = (pos + amount as u64).min(payload);
        if lo < hi {
            require(
                chunk[(lo - pos) as usize..(hi - pos) as usize]
                    == header[(lo - 8) as usize..(hi - 8) as usize],
                "CHECKPOINT_CHANGED",
            )?;
        }
        for row in 0..SIDE {
            let start = payload + offsets[0] + (row * WIDTH * 2) as u64;
            let lo = pos.max(start);
            let hi = (pos + amount as u64).min(start + (SIDE * 2) as u64);
            if lo < hi {
                tile[row * SIDE * 2 + (lo - start) as usize
                    ..row * SIDE * 2 + (hi - start) as usize]
                    .copy_from_slice(&chunk[(lo - pos) as usize..(hi - pos) as usize]);
            }
        }
        pos += amount as u64;
        progress(n + 8 + pos)?;
    }
    let mut extra = [0];
    require(
        checkpoint.read(&mut extra).map_err(|_| "CHECKPOINT_IO")? == 0,
        "CHECKPOINT_CHANGED",
    )?;
    require(
        Hash::from(hasher.finalize()) == ctx.checkpoint_sha256,
        "CHECKPOINT_PIN",
    )?;
    let mut a = Vec::with_capacity(4096);
    let mut b = vec![0; 4096];
    let (mut ca, mut cb) = (0, 0);
    for bytes in tile.chunks_exact(2) {
        let (v, clipped) = quantize(
            u16::from_le_bytes(bytes.try_into().map_err(|_| "TILE_BITS")?) as u32,
            7,
            14,
            32767,
        )?;
        a.push(v);
        ca += usize::from(clipped);
    }
    // Reject every original activation nonfinite, including unselected coordinates.
    for bytes in hidden.chunks_exact(4) {
        require(
            (u32::from_le_bytes(bytes.try_into().map_err(|_| "ACTIVATION_BITS")?) >> 23) & 255
                != 255,
            "NONFINITE",
        )?;
    }
    for k in 0..SIDE {
        for token in 0..tokens {
            let at = (token * WIDTH + k) * 4;
            let (v, clipped) = quantize(
                u32::from_le_bytes(
                    hidden[at..at + 4]
                        .try_into()
                        .map_err(|_| "ACTIVATION_BITS")?,
                ),
                23,
                4,
                128,
            )?;
            b[k * SIDE + token] = v;
            cb += usize::from(clipped);
        }
    }
    let aa = encode_matrix(&a);
    let bb = encode_matrix(&b);
    require(aa == expected_a && bb == expected_b, "MATRIX_REPLAY")?;
    require(
        hash(b"artifact", &[&aa]) == ctx.model
            && hash(b"qualified-task-input-v1", &[&bb]) == ctx.input,
        "MATERIAL_PIN",
    )?;
    let av: Vec<_> = a.iter().map(|v| v.rem_euclid(Q) as u32).collect();
    let bv: Vec<_> = b.iter().map(|v| v.rem_euclid(Q) as u32).collect();
    let task = pon_work::task_id(&av, &bv).map_err(|_| "MATRIX_TASK")?;
    let nz = b.iter().filter(|v| **v != 0).count();
    let d = TileMaterialDescriptorV1 {
        schema: "checkpoint-tile-material-v1".into(),
        policy: hex::encode(policy_id()),
        network: hex::encode(ctx.network),
        parameters: hex::encode(ctx.parameters),
        checkpoint_sha256: hex::encode(ctx.checkpoint_sha256),
        checkpoint_bytes: ctx.checkpoint_bytes,
        header_sha256: hex::encode(sha(&header)),
        header_bytes: n,
        tensor_count,
        tensor: TENSOR.into(),
        tensor_dtype: "BF16LE".into(),
        tensor_shape: [576, 576],
        tensor_offsets: offsets,
        output_coordinates: [0, 64],
        input_coordinates: [0, 64],
        activation_sha256: hex::encode(ctx.activation_sha256),
        activation_width: 576,
        real_token_columns: tokens,
        padded_token_columns: 64 - tokens,
        weight_scale_power: 14,
        activation_scale_power: 4,
        weight_clip: 32767,
        activation_clip: 128,
        weight_clipped: ca,
        activation_clipped: cb,
        a_nonzero: a.iter().filter(|v| **v != 0).count(),
        b_nonzero: nz,
        a_sha256: hex::encode(sha(&aa)),
        b_sha256: hex::encode(sha(&bb)),
        model: hex::encode(ctx.model),
        input: hex::encode(ctx.input),
        matrix_task: hex::encode(task),
        dense_base_product_multiplications: 262144,
        sparse_b_base_product_multiplications: 64 * nz,
        chain_authority: false,
        full_forward_verified: false,
        hardness_accepted: false,
        genuine_demand_verified: false,
        marginal_contribution_accepted: false,
    };
    let canonical = canonical_descriptor(&d)?;
    require(canonical.len() <= MAX_DESCRIPTOR_BYTES, "DESCRIPTOR_LIMIT")?;
    let id = hash(b"checkpoint-tile-material-receipt-v1", &[&canonical]);
    Ok(CheckedCheckpointTileMaterialV1 {
        descriptor: d,
        canonical_descriptor: canonical,
        descriptor_id: id,
        context: ctx.clone(),
        matrix_task: task,
        checkpoint_bytes_read: n + 8 + pos,
    })
}
/// Closed canonical descriptor replay; descriptor claims cannot alter pinnings.
pub fn verify_checkpoint_tile_material_v1<R: Read + Seek, F: FnMut(u64) -> MaterialResult<()>>(
    checkpoint: &mut R,
    activation_raw: &[u8],
    descriptor_raw: &[u8],
    expected_a: &[u8],
    expected_b: &[u8],
    ctx: &PinnedTileContextV1,
    progress: F,
) -> MaterialResult<CheckedCheckpointTileMaterialV1> {
    let claimed: TileMaterialDescriptorV1 =
        serde_json::from_value(parse(descriptor_raw, MAX_DESCRIPTOR_BYTES)?)
            .map_err(|_| "DESCRIPTOR_FIELDS")?;
    require(
        canonical_descriptor(&claimed)? == descriptor_raw,
        "DESCRIPTOR_CANONICAL",
    )?;
    let checked = derive_checkpoint_tile_material_v1(
        checkpoint,
        activation_raw,
        expected_a,
        expected_b,
        ctx,
        progress,
    )?;
    require(claimed == checked.descriptor, "DESCRIPTOR_REPLAY")?;
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_finite_bf16_patterns_match_independent_exact_f64_powers_and_even_rounding() {
        // BF16 significands and the fixed power-of-two scale are exactly
        // representable in f64, including largest finite/subnormal patterns.
        for bits in 0..=u16::MAX {
            let raw = u32::from(bits) << 16;
            let value = f32::from_bits(raw) as f64;
            if value.is_finite() {
                let rounded = (value * 16384.0).round_ties_even();
                let clipped = rounded.clamp(-32767.0, 32767.0);
                assert_eq!(
                    quantize(u32::from(bits), 7, 14, 32767).unwrap(),
                    (clipped as i64, clipped != rounded),
                    "{bits:04x}"
                );
            } else {
                assert_eq!(quantize(u32::from(bits), 7, 14, 32767), Err("NONFINITE"));
            }
        }
    }
    #[test]
    fn ieee_integer_rounding_zero_subnormal_ties_clips_and_nonfinite() {
        for (value, expected) in [
            (0f32, 0),
            (-0f32, 0),
            (0.03125, 0),
            (0.09375, 2),
            (-0.09375, -2),
            (0.15625, 2),
            (8.0, 128),
            (8.03125, 128),
            (8.09375, 128),
        ] {
            assert_eq!(quantize(value.to_bits(), 23, 4, 128).unwrap().0, expected);
        }
        assert!(!quantize(8.03125f32.to_bits(), 23, 4, 128).unwrap().1);
        assert!(quantize(8.09375f32.to_bits(), 23, 4, 128).unwrap().1);
        for bits in [1, 0x80000001, 0x007fffff] {
            assert_eq!(quantize(bits, 23, 4, 128).unwrap(), (0, false));
        }
        assert_eq!(
            quantize(f32::MAX.to_bits(), 23, 4, 128).unwrap(),
            (128, true)
        );
        assert_eq!(quantize(0xff7fffff, 23, 4, 128).unwrap(), (-128, true));
        for bits in [0x7f800000, 0xff800000, 0x7fc00001] {
            assert_eq!(quantize(bits, 23, 4, 128), Err("NONFINITE"));
        }
        assert_eq!(quantize(0x3f80, 7, 14, 32767).unwrap(), (16384, false));
        assert_eq!(quantize(0x4000, 7, 14, 32767).unwrap(), (32767, true));
        assert_eq!(quantize(0x8000, 7, 14, 32767).unwrap(), (0, false));
        assert_eq!(quantize(0x7f7f, 7, 14, 32767).unwrap(), (32767, true));
        assert_eq!(quantize(0x7f80, 7, 14, 32767), Err("NONFINITE"));
    }
}
