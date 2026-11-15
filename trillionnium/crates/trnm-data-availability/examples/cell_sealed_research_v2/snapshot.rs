//! Construct the dense contract from the same independently pinned CAS bytes.
//! CTS1 is metadata admission. The pinned existing worker remains responsible
//! for the actual SmolLM architecture, tokenizer, parent/LoRA and runtime checks.

use super::*;
use std::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserializer, Serialize,
};

const WORKER_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/llm_cell_sealed_worker_v1.py"
));
const HEADER_BOUND: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotSpec {
    pub schema: String,
    pub model_loader: String,
    pub environment_loader: String,
    pub tensor_codec: String,
    pub quantization: String,
    pub composition_file: String,
    pub composition_profile: String,
    pub material_profile: String,
    pub worker_sha256: String,
}

impl SnapshotSpec {
    pub(super) fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.cell-sealed-research-snapshot.v2"
                && self.model_loader == "sealed-smollm2-dense-v1"
                && self.environment_loader == "sealed-python-runtime-snapshot-v1"
                && self.tensor_codec == "safetensors-dense-f32-f16-bf16-v1"
                && self.quantization == "none"
                && self.composition_file == "adapter/target-contract.json"
                && self.composition_profile == "sealed-smollm2-parent-lora-v1"
                && matches!(
                    self.material_profile.as_str(),
                    "current-contract-v1" | "smollm2-public-v2-material-runtime-bridge-v1"
                )
                && digest(&self.worker_sha256)?
                    == <[u8; 32]>::from(Sha256::digest(WORKER_SOURCE.as_bytes())),
            "known dense sealed worker and explicit composition interpreter required",
        )
    }

    fn profile(&self, kind: &[u8], name: &str) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/SealedResearchLoader/v2\0");
        for value in [kind, name.as_bytes(), self.material_profile.as_bytes()] {
            hash.update((value.len() as u32).to_be_bytes());
            hash.update(value);
        }
        hash.update(digest(&self.worker_sha256)?);
        Ok(hash.finalize().into())
    }

    pub(super) fn model_loader_profile(&self) -> Result<[u8; 32]> {
        self.profile(b"model", &self.model_loader)
    }

    pub(super) fn environment_loader_profile(&self) -> Result<[u8; 32]> {
        self.profile(b"environment", &self.environment_loader)
    }

    fn composition_pin(&self) -> Result<[u8; 32]> {
        self.profile(b"composition", &self.composition_profile)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tensor {
    dtype: String,
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}

struct Metadata(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct MetadataVisitor;
        impl<'de> Visitor<'de> for MetadataVisitor {
            type Value = Metadata;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("unique bounded string metadata")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if values.len() >= 1024
                        || key.len() > 255
                        || value.len() > 16_384
                        || values.insert(key, value).is_some()
                    {
                        return Err(de::Error::custom("duplicate or unbounded tensor metadata"));
                    }
                }
                Ok(Metadata(values))
            }
        }
        deserializer.deserialize_map(MetadataVisitor)
    }
}

struct Header {
    tensors: BTreeMap<String, Tensor>,
    metadata: BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = Header;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a unique dense safetensors roster")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut tensors = BTreeMap::new();
                let mut metadata = None;
                while let Some(name) = map.next_key::<String>()? {
                    if name == "__metadata__" {
                        if metadata.is_some() {
                            return Err(de::Error::custom("duplicate tensor metadata"));
                        }
                        metadata = Some(map.next_value::<Metadata>()?.0);
                    } else {
                        let tensor = map.next_value::<Tensor>()?;
                        if tensors.len() >= 16_384
                            || name.is_empty()
                            || name.len() > 255
                            || tensors.insert(name, tensor).is_some()
                        {
                            return Err(de::Error::custom("duplicate or unbounded tensor roster"));
                        }
                    }
                }
                Ok(Header {
                    tensors,
                    metadata: metadata.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

fn tensor_roster(header: &[u8], data_bytes: u64) -> Result<Vec<CellTensorSpecV1>> {
    check(
        !header.is_empty() && header.len() <= HEADER_BOUND,
        "bounded captured tensor header",
    )?;
    let header: Header = serde_json::from_slice(header)?;
    check(
        !header.tensors.is_empty(),
        "nonempty captured tensor roster",
    )?;
    for (key, value) in header.metadata {
        let key = key.to_ascii_lowercase();
        check(
            !(key.contains("quant") || key.contains("compression")) || value == "none",
            "quantized tensor metadata is outside the declared dense profile",
        )?;
    }
    let mut tensors = Vec::new();
    let mut offsets = Vec::new();
    for (name, tensor) in header.tensors {
        let (dtype, mut bytes) = match tensor.dtype.as_str() {
            "F32" => (CellTensorDTypeV1::F32, 4_u64),
            "F16" => (CellTensorDTypeV1::F16, 2_u64),
            "BF16" => (CellTensorDTypeV1::Bf16, 2_u64),
            _ => return Err("unknown or quantized safetensors dtype".into()),
        };
        check(tensor.shape.len() <= 8, "declared dense tensor rank")?;
        for dimension in &tensor.shape {
            check(
                (1..=u64::from(u32::MAX)).contains(dimension),
                "declared dense tensor dimension",
            )?;
            bytes = bytes
                .checked_mul(*dimension)
                .ok_or("tensor shape overflow")?;
        }
        let [start, end] = tensor.data_offsets;
        check(
            end <= data_bytes && end.checked_sub(start) == Some(bytes),
            "actual dense tensor offsets",
        )?;
        offsets.push((start, end));
        tensors.push(CellTensorSpecV1 {
            name,
            dtype,
            shape: tensor.shape,
        });
    }
    offsets.sort_unstable();
    let mut end = 0;
    for (start, next) in offsets {
        check(start == end, "complete nonoverlapping dense tensor data")?;
        end = next;
    }
    check(end == data_bytes, "complete dense tensor payload coverage")?;
    Ok(tensors)
}

fn prefix(
    store: &CellStoreV1,
    manifest: &CellManifestV1,
    size: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    check(
        size <= HEADER_BOUND + 8 && size as u64 <= manifest.size(),
        "bounded original metadata prefix",
    )?;
    let mut bytes = Vec::with_capacity(size);
    for chunk in manifest.chunks() {
        check(
            Instant::now() < deadline,
            "original tensor metadata deadline",
        )?;
        let raw = store
            .chunk(chunk.sha256)?
            .ok_or("captured tensor chunk absent")?;
        check(
            raw.len() == chunk.size as usize
                && <[u8; 32]>::from(Sha256::digest(&raw)) == chunk.sha256,
            "captured tensor metadata chunk pin",
        )?;
        check(
            Instant::now() < deadline,
            "original tensor metadata read deadline",
        )?;
        let take = (size - bytes.len()).min(raw.len());
        bytes.extend_from_slice(&raw[..take]);
        if bytes.len() == size {
            break;
        }
    }
    check(bytes.len() == size, "complete captured metadata prefix")?;
    Ok(bytes)
}

fn member<'a>(version: &'a CellVersionManifestV1, path: &str) -> Result<(u16, &'a CellManifestV1)> {
    let (index, file) = version
        .model()
        .closure()
        .files()
        .iter()
        .enumerate()
        .find(|(_, file)| file.path == path)
        .ok_or("required composition member absent")?;
    let manifest = version
        .manifests()
        .iter()
        .find(|manifest| manifest.id() == file.manifest)
        .ok_or("required composition manifest absent")?;
    Ok((u16::try_from(index)?, manifest))
}

fn composition(
    store: &CellStoreV1,
    version: &CellVersionManifestV1,
    spec: &SnapshotSpec,
    deadline: Instant,
) -> Result<u16> {
    let (_, config) = member(version, "base/config.json")?;
    let config: Value = serde_json::from_slice(&prefix(
        store,
        config,
        usize::try_from(config.size())?,
        deadline,
    )?)?;
    check(
        config.is_object()
            && config["quantization_config"].is_null()
            && config["compression_config"].is_null(),
        "quantized/compressed base configuration is unsupported",
    )?;
    let (index, contract) = member(version, &spec.composition_file)?;
    let contract: Value = serde_json::from_slice(&prefix(
        store,
        contract,
        usize::try_from(contract.size())?,
        deadline,
    )?)?;
    check(
        contract["numeric"]["quantization"] == "none"
            && contract["numeric"]["storage_dtype"] == "float32"
            && contract["numeric"]["accumulation_dtype"] == "float32",
        "the declared sealed parent/LoRA interpreter requires its dense original contract",
    )?;
    // The unchanged worker checks the complete architecture, exact target
    // modules/rank/alpha, tokenizer and actually loaded parent. The CTS1 owner
    // only admits the dense schema and retains these pinned rules for that use.
    Ok(index)
}

pub(super) fn capture(
    store: &CellStoreV1,
    version: &CellVersionManifestV1,
    spec: &SnapshotSpec,
    deadline: Instant,
) -> Result<CellReleaseSnapshotV1> {
    spec.validate()?;
    let worker = version
        .environment()
        .files()
        .iter()
        .find(|file| file.path == WORKER)
        .ok_or("declared composition interpreter absent")?;
    check(
        worker.payload_sha256 == digest(&spec.worker_sha256)?,
        "same captured composition worker required",
    )?;
    let mut files = Vec::new();
    for (index, file) in version.model().closure().files().iter().enumerate() {
        if !matches!(file.role, CellFileRoleV1::Base | CellFileRoleV1::Adapter) {
            continue;
        }
        check(
            file.path.ends_with(".safetensors"),
            "declared dense tensor file codec",
        )?;
        let manifest = version
            .manifests()
            .iter()
            .find(|manifest| manifest.id() == file.manifest)
            .ok_or("complete original tensor manifest")?;
        let size = prefix(store, manifest, 8, deadline)?;
        let header_size = u64::from_le_bytes(size.try_into().map_err(|_| "tensor header length")?);
        check(
            header_size > 0
                && header_size <= HEADER_BOUND as u64
                && header_size
                    .checked_add(8)
                    .is_some_and(|size| size < manifest.size()),
            "bounded nonempty original safetensors header",
        )?;
        let prefix = prefix(store, manifest, header_size as usize + 8, deadline)?;
        let tensors = tensor_roster(&prefix[8..], manifest.size() - header_size - 8)?;
        files.push(CellTensorFileV1 {
            file_index: u16::try_from(index)?,
            tensors,
        });
    }
    let contract = CellTensorContractV1::new(version.model().id(), files)?;
    let tensors = CellTensorModelManifestV1::new(version.model().clone(), contract)?;
    let composition_file = composition(store, version, spec, deadline)?;
    check(
        Instant::now() < deadline,
        "original typed snapshot capture deadline",
    )?;
    Ok(CellReleaseSnapshotV1::new(
        version.clone(),
        tensors,
        composition_file,
        spec.composition_pin()?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SnapshotSpec {
        SnapshotSpec {
            schema: "trnm.cell-sealed-research-snapshot.v2".into(),
            model_loader: "sealed-smollm2-dense-v1".into(),
            environment_loader: "sealed-python-runtime-snapshot-v1".into(),
            tensor_codec: "safetensors-dense-f32-f16-bf16-v1".into(),
            quantization: "none".into(),
            composition_file: "adapter/target-contract.json".into(),
            composition_profile: "sealed-smollm2-parent-lora-v1".into(),
            material_profile: "current-contract-v1".into(),
            worker_sha256: hex::encode(Sha256::digest(WORKER_SOURCE.as_bytes())),
        }
    }

    #[test]
    fn actual_worker_and_closed_composition_profile_are_required() {
        spec().validate().unwrap();
        let mut changed = spec();
        changed.composition_profile = "opaque-hash-compatible".into();
        assert!(changed.validate().is_err());
        changed = spec();
        changed.worker_sha256 = "01".repeat(32);
        assert!(changed.validate().is_err());
        changed = spec();
        changed.quantization = "int4".into();
        assert!(changed.validate().is_err());
    }

    #[test]
    fn dense_roster_rejects_unknown_dtype_duplicate_fields_and_layout_gaps() {
        let raw = br#"{"weight":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
        let tensors = tensor_roster(raw, 8).unwrap();
        assert_eq!(tensors[0].dtype, CellTensorDTypeV1::F32);
        assert_eq!(tensors[0].shape, vec![2]);
        for raw in [
            r#"{"weight":{"dtype":"I8","shape":[8],"data_offsets":[0,8]}}"#,
            r#"{"weight":{"dtype":"F32","dtype":"F16","shape":[4],"data_offsets":[0,8]}}"#,
            r#"{"weight":{"dtype":"F32","shape":[2],"data_offsets":[1,9]}}"#,
            r#"{"weight":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}"#,
            r#"{"__metadata__":{"quantization":"int4"},"weight":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        ] {
            assert!(tensor_roster(raw.as_bytes(), 8).is_err());
        }
    }
}
