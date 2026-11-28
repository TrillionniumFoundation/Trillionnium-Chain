//! Connect retained JSON/LE pins to the unchanged typed research core.
//! This authenticates neither the pin provider nor training, utility or authority.

use crate::pft_readout_f64_v1 as core;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[path = "pft_native_loader_v1/json.rs"]
mod json;

pub const PROFILE: &str = "trnm.pft.native-pinned-json-loader.v1";
const MAX_BYTES: usize = 16 * 1024 * 1024;
type Pin = [u8; 32];
type Result<T> = std::result::Result<T, NativePftErrorV1>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePftErrorV1 {
    Json,
    DuplicateKey,
    Limit,
    Fields,
    Pin,
    Contract,
    Shape,
    Numeric,
    Core(core::PftErrorV1),
}

/// Separately retained comparison policy; matching it conveys no permission.
#[derive(Clone, Debug)]
pub struct PftNativeExpectationsV1 {
    pub profile: String,
    pub model: core::PftModelDescriptorV1,
    pub input: core::PftInputDescriptorV1,
    pub parent_model_sha256: Pin,
    pub objective_sha256: Pin,
    pub feature_binary_sha256: Pin,
}

pub struct LoadedPftReadoutV1 {
    model: core::PreparedPftReadoutV1,
    input: core::PreparedPftInputV1,
    expectations: PftNativeExpectationsV1,
}

impl LoadedPftReadoutV1 {
    pub fn expectations(&self) -> &PftNativeExpectationsV1 {
        &self.expectations
    }

    /// Bounded arithmetic only; no original owner, adoption, effect or payment.
    pub fn predict(&self) -> std::result::Result<core::PftPredictionV1, core::PftErrorV1> {
        self.model.predict(&self.input)
    }

    /// Keeps the caller's live resource/withdrawal checks inside numeric work.
    pub fn predict_checked(
        &self,
        check_current: impl FnMut() -> bool,
    ) -> std::result::Result<core::PftPredictionV1, core::PftErrorV1> {
        self.model.predict_checked(&self.input, check_current)
    }
}

/// Parses immutable borrowed bytes, then retains owned typed weights/features.
/// No filesystem, network, dispatch, source signature or authority is consulted.
pub fn load_pinned_pft(
    candidate: &[u8],
    features: &[u8],
    expected: &PftNativeExpectationsV1,
) -> Result<LoadedPftReadoutV1> {
    require(
        candidate.len() <= MAX_BYTES && features.len() <= MAX_BYTES,
        NativePftErrorV1::Limit,
    )?;
    require(expected.profile == PROFILE, NativePftErrorV1::Contract)?;
    require(
        [
            expected.parent_model_sha256,
            expected.objective_sha256,
            expected.feature_binary_sha256,
        ]
        .iter()
        .all(|p| *p != [0; 32]),
        NativePftErrorV1::Pin,
    )?;
    require(
        hash(candidate) == expected.model.candidate_sha256
            && hash(features) == expected.input.feature_packet_sha256,
        NativePftErrorV1::Pin,
    )?;
    let candidate = json::parse(candidate)?;
    let features = json::parse(features)?;
    let (descriptor, weights) = model_bytes(
        &candidate,
        &expected.model,
        expected.parent_model_sha256,
        expected.objective_sha256,
    )?;
    let model =
        core::PreparedPftReadoutV1::prepare(&descriptor, &weights, &expected.model, &weights)
            .map_err(NativePftErrorV1::Core)?;
    let (descriptor, bytes) = feature_bytes(&features, &descriptor, expected)?;
    let input = model
        .prepare_input(&descriptor, &bytes, &expected.input, &bytes)
        .map_err(NativePftErrorV1::Core)?;
    Ok(LoadedPftReadoutV1 {
        model,
        input,
        expectations: expected.clone(),
    })
}

fn model_bytes(
    value: &Value,
    expected: &core::PftModelDescriptorV1,
    parent_model_sha256: Pin,
    objective_sha256: Pin,
) -> Result<(core::PftModelDescriptorV1, Vec<u8>)> {
    let c = fields(value, "schema contract contract_sha256 contract_canonical_json head revision head_material_canonical_json count weight_shape weight weight_encoding weight_sha256")?;
    constant(c, "schema", "pft-online-candidate-v1")?;
    constant(c, "weight_encoding", "float64-le-c-rowmajor")?;
    let raw = text(&c["contract_canonical_json"], 4096)?;
    let contract_pin = pin(&c["contract_sha256"])?;
    require(
        hash(raw.as_bytes()) == contract_pin && contract_pin == expected.contract_sha256,
        NativePftErrorV1::Pin,
    )?;
    let contract = json::parse(raw.as_bytes())?;
    require(c["contract"] == contract, NativePftErrorV1::Contract)?;
    let q = fields(&contract, "schema model_family epoch parent_model_sha256 feature_program_sha256 normalization_sha256 objective_sha256 time_semantics_sha256 dimension outputs regularizer dtype aggregation statistics_validation")?;
    for (field, value) in [
        ("schema", "pft-online-statistics-v1"),
        ("model_family", core::FAMILY),
        ("dtype", "float64"),
        ("aggregation", "sum-f64-canonical-batch-id"),
        ("statistics_validation", "augmented-psd-rtol-1e-10-v1"),
    ] {
        constant(q, field, value)?;
    }
    uint(&q["epoch"], 0, i64::MAX as u64)?;
    require(real(&q["regularizer"])? > 0.0, NativePftErrorV1::Numeric)?;
    require(
        pin(&q["parent_model_sha256"])? == parent_model_sha256
            && pin(&q["objective_sha256"])? == objective_sha256,
        NativePftErrorV1::Pin,
    )?;
    let d = uint(&q["dimension"], 1, 1024)? as u32;
    let m = uint(&q["outputs"], 1, 32)? as u32;
    let head = check_head(c, contract_pin, expected.head)?;
    let shape = array(&c["weight_shape"])?;
    require(
        shape.len() == 2
            && uint(&shape[0], 1, 1024)? == u64::from(d)
            && uint(&shape[1], 1, 32)? == u64::from(m),
        NativePftErrorV1::Shape,
    )?;
    let weights = matrix(&c["weight"], d as usize, m as usize)?;
    let weight_pin = pin(&c["weight_sha256"])?;
    require(
        hash(&weights) == weight_pin && weight_pin == expected.weight_sha256,
        NativePftErrorV1::Pin,
    )?;
    Ok((
        core::PftModelDescriptorV1 {
            schema: core::MODEL_SCHEMA.into(),
            family: core::FAMILY.into(),
            numeric_profile: core::PROFILE.into(),
            candidate_sha256: expected.candidate_sha256,
            contract_sha256: contract_pin,
            head,
            weight_sha256: weight_pin,
            feature_program_sha256: pin(&q["feature_program_sha256"])?,
            normalization_sha256: pin(&q["normalization_sha256"])?,
            time_semantics_sha256: pin(&q["time_semantics_sha256"])?,
            dimension: d,
            outputs: m,
        },
        weights,
    ))
}

/// Internal inspection only. The complete candidate hash and contract/base pins
/// must come from the actual selected manifest, not a peer's expectations packet.
/// No executable model, input, feature bytes or weight buffer leaves this call.
pub(crate) fn inspect_selected_candidate(
    candidate: &[u8],
    candidate_sha256: Pin,
    contract_sha256: Pin,
    parent_model_sha256: Pin,
) -> Result<core::PftModelDescriptorV1> {
    require(
        !candidate.is_empty() && candidate.len() <= MAX_BYTES,
        NativePftErrorV1::Limit,
    )?;
    require(
        ![candidate_sha256, contract_sha256, parent_model_sha256].contains(&[0; 32])
            && hash(candidate) == candidate_sha256,
        NativePftErrorV1::Pin,
    )?;
    let value = json::parse(candidate)?;
    let q = &value["contract"];
    let expected = core::PftModelDescriptorV1 {
        schema: core::MODEL_SCHEMA.into(),
        family: core::FAMILY.into(),
        numeric_profile: core::PROFILE.into(),
        candidate_sha256,
        contract_sha256,
        head: pin(&value["head"])?,
        weight_sha256: pin(&value["weight_sha256"])?,
        feature_program_sha256: pin(&q["feature_program_sha256"])?,
        normalization_sha256: pin(&q["normalization_sha256"])?,
        time_semantics_sha256: pin(&q["time_semantics_sha256"])?,
        dimension: uint(&q["dimension"], 1, 1024)? as u32,
        outputs: uint(&q["outputs"], 1, 32)? as u32,
    };
    // Remaining labels are pinned by the already matched complete payload and
    // the independently selected contract, then checked against actual bytes.
    let (descriptor, _) = model_bytes(
        &value,
        &expected,
        parent_model_sha256,
        pin(&q["objective_sha256"])?,
    )?;
    require(descriptor == expected, NativePftErrorV1::Contract)?;
    Ok(descriptor)
}

fn check_head(c: &Map<String, Value>, contract: Pin, expected: Pin) -> Result<Pin> {
    let raw = text(&c["head_material_canonical_json"], 131072)?;
    let head = pin(&c["head"])?;
    require(
        hash(raw.as_bytes()) == head && head == expected,
        NativePftErrorV1::Pin,
    )?;
    let material = json::parse(raw.as_bytes())?;
    let h = fields(&material, "contract_sha256 batches")?;
    require(
        pin(&h["contract_sha256"])? == contract,
        NativePftErrorV1::Contract,
    )?;
    let batches = array(&h["batches"])?;
    let revision = uint(&c["revision"], 1, 256)?;
    require(batches.len() as u64 == revision, NativePftErrorV1::Contract)?;
    uint(&c["count"], revision, revision * 100000)?;
    let mut previous = None;
    for batch in batches {
        let pair = array(batch)?;
        require(pair.len() == 2, NativePftErrorV1::Contract)?;
        let id = text(&pair[0], 128)?;
        require(
            !id.is_empty()
                && id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                && previous.is_none_or(|old| old < id),
            NativePftErrorV1::Contract,
        )?;
        pin(&pair[1])?;
        previous = Some(id);
    }
    Ok(head)
}

fn feature_bytes(
    value: &Value,
    model: &core::PftModelDescriptorV1,
    expected: &PftNativeExpectationsV1,
) -> Result<(core::PftInputDescriptorV1, Vec<u8>)> {
    let f = fields(value, "schema model_family request_id contract_sha256 feature_program_sha256 normalization_sha256 time_semantics_sha256 source_sha256 row_ids features")?;
    constant(f, "schema", "pft-feature-input-v1")?;
    constant(f, "model_family", core::FAMILY)?;
    let rows = array(&f["features"])?;
    require((1..=256).contains(&rows.len()), NativePftErrorV1::Shape)?;
    let ids = array(&f["row_ids"])?;
    require(ids.len() == rows.len(), NativePftErrorV1::Shape)?;
    let mut seen = BTreeSet::new();
    let mut canonical_ids = String::from("[");
    for (index, id) in ids.iter().enumerate() {
        require(seen.insert(pin(id)?), NativePftErrorV1::Contract)?;
        if index != 0 {
            canonical_ids.push(',');
        }
        canonical_ids.push('"');
        canonical_ids.push_str(text(id, 64)?);
        canonical_ids.push('"');
    }
    canonical_ids.push(']');
    let row_ids = hash(canonical_ids.as_bytes());
    require(
        row_ids == expected.input.row_ids_sha256,
        NativePftErrorV1::Pin,
    )?;
    let bytes = matrix(&f["features"], rows.len(), model.dimension as usize)?;
    require(
        hash(&bytes) == expected.feature_binary_sha256,
        NativePftErrorV1::Pin,
    )?;
    Ok((
        core::PftInputDescriptorV1 {
            schema: core::INPUT_SCHEMA.into(),
            candidate_sha256: model.candidate_sha256,
            weight_sha256: model.weight_sha256,
            contract_sha256: pin(&f["contract_sha256"])?,
            feature_program_sha256: pin(&f["feature_program_sha256"])?,
            normalization_sha256: pin(&f["normalization_sha256"])?,
            time_semantics_sha256: pin(&f["time_semantics_sha256"])?,
            request_id: pin(&f["request_id"])?,
            source_sha256: pin(&f["source_sha256"])?,
            row_ids_sha256: row_ids,
            feature_packet_sha256: expected.input.feature_packet_sha256,
            rows: rows.len() as u32,
            dimension: model.dimension,
        },
        bytes,
    ))
}

fn matrix(value: &Value, rows: usize, columns: usize) -> Result<Vec<u8>> {
    let values = array(value)?;
    require(values.len() == rows, NativePftErrorV1::Shape)?;
    let mut bytes = Vec::with_capacity(rows * columns * 8);
    for row in values {
        let values = array(row)?;
        require(values.len() == columns, NativePftErrorV1::Shape)?;
        for value in values {
            bytes.extend_from_slice(&real(value)?.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn fields<'a>(value: &'a Value, names: &str) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(NativePftErrorV1::Fields)?;
    require(
        object.len() == names.split_whitespace().count()
            && names.split_whitespace().all(|key| object.contains_key(key)),
        NativePftErrorV1::Fields,
    )?;
    Ok(object)
}

fn constant(object: &Map<String, Value>, key: &str, expected: &str) -> Result<()> {
    require(
        object[key].as_str() == Some(expected),
        NativePftErrorV1::Contract,
    )
}

fn text(value: &Value, maximum: usize) -> Result<&str> {
    let text = value.as_str().ok_or(NativePftErrorV1::Contract)?;
    require(text.len() <= maximum, NativePftErrorV1::Limit)?;
    Ok(text)
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or(NativePftErrorV1::Shape)
}

fn uint(value: &Value, low: u64, high: u64) -> Result<u64> {
    let n = value.as_u64().ok_or(NativePftErrorV1::Contract)?;
    require((low..=high).contains(&n), NativePftErrorV1::Contract)?;
    Ok(n)
}

fn real(value: &Value) -> Result<f64> {
    let n = value.as_f64().ok_or(NativePftErrorV1::Numeric)?;
    require(
        n.is_finite() && (n == 0.0 || n.is_normal()),
        NativePftErrorV1::Numeric,
    )?;
    Ok(n)
}

fn pin(value: &Value) -> Result<Pin> {
    let value = text(value, 64)?;
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        NativePftErrorV1::Pin,
    )?;
    let mut out = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        out[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    require(out != [0; 32], NativePftErrorV1::Pin)?;
    Ok(out)
}

fn hash(bytes: &[u8]) -> Pin {
    Sha256::digest(bytes).into()
}
fn require(condition: bool, error: NativePftErrorV1) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
#[path = "pft_native_loader_v1/tests.rs"]
mod tests;
