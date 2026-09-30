//! Bounded signed-development task descriptions. Decoding does not grant authority,
//! establish genuine demand, prove model provenance, or qualify computational hardness.
use crate::pon_wire::{hash, Hash};

/// Fresh-context renewable demand controls and source signatures; never v1 authority.
pub mod lifecycle_v2;

pub const MANIFEST_BYTES: usize = 584;
pub const SIGNED_TASK_BYTES: usize = 4 + MANIFEST_BYTES + 64;
pub const MAX_MATERIAL_BYTES: u32 = 64 * 1024 * 1024;
pub const MAX_VALIDITY_BLOCKS: u64 = 1000;
pub const MATRIX_SIDE: u16 = 64;
pub const LOGICAL_MULTIPLY_ADD_UNITS: u64 = 64 * 64 * 64;
pub const MATRIX_ARTIFACT_BYTES: u32 = 64 * 64 * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskPurpose {
    Maintenance = 1,
    AdapterContraction = 2,
    EvaluationContraction = 3,
    InferenceContraction = 4,
}
impl TaskPurpose {
    fn decode(value: u8) -> Result<Self, TaskError> {
        match value {
            1 => Ok(Self::Maintenance),
            2 => Ok(Self::AdapterContraction),
            3 => Ok(Self::EvaluationContraction),
            4 => Ok(Self::InferenceContraction),
            _ => Err(TaskError::Purpose),
        }
    }
    pub fn output_limit(self) -> u32 {
        if self == Self::Maintenance {
            0
        } else {
            1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskError {
    Length,
    Version,
    Purpose,
    Profile,
    Shape,
    CostClass,
    NumericEncoding,
    Recipe,
    HardnessNotAccepted,
    Reuse,
    Identity,
    OutputMeter,
    Layer,
    Limits,
    Validity,
    Reserved,
}

/// An exact manifest, not a verified admission. All hashes are caller-visible claims.
/// Version 1 deliberately has no representation of accepted hardness or model utility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedWorkTask {
    pub purpose: TaskPurpose,
    pub cost_class: u8,
    pub numeric_encoding: u8,
    pub hardness_status: u8,
    pub reuse: u8,
    pub network: Hash,
    pub parameters: Hash,
    pub work_profile: Hash,
    pub source: Hash,
    pub demand_id: Hash,
    pub source_record: Hash,
    pub model: Hash,
    pub layer: Hash,
    pub input: Hash,
    pub recipe: Hash,
    pub matrix_task: Hash,
    pub availability_manifest: Hash,
    pub availability_root: Hash,
    pub authorization_scope: Hash,
    pub withdrawal_head: Hash,
    pub output_meter: Hash,
    pub rows: u16,
    pub inner: u16,
    pub columns: u16,
    pub demand_nonce: u64,
    pub not_before: u64,
    pub expires: u64,
    pub available_until: u64,
    pub logical_multiply_add_units: u64,
    pub model_bytes: u32,
    pub input_bytes: u32,
    pub useful_output_limit: u32,
}

impl QualifiedWorkTask {
    pub fn profile_id() -> Hash {
        hash(
            b"qualified-task-profile-v1",
            &[b"pon-matmul-transcript-64-v1"],
        )
    }
    pub fn recipe_id() -> Hash {
        hash(
            b"qualified-task-recipe-v1",
            &[b"canonical-field-matrix64-product-v1"],
        )
    }
    pub fn layer_id(model: Hash) -> Hash {
        hash(
            b"qualified-task-layer-v1",
            &[&model, b"entire-row-major-field-layer-64x64"],
        )
    }
    /// Independent of mining nonce, challenge, transcript, signature and demand nonce.
    /// The persistent owner must deduplicate this key before crediting an output.
    pub fn derived_output_meter(&self) -> Hash {
        hash(
            b"qualified-task-output-meter-v1",
            &[
                &self.network,
                &self.parameters,
                &self.demand_id,
                &self.model,
                &self.layer,
                &self.input,
                &self.recipe,
                &self.matrix_task,
            ],
        )
    }
    pub fn validate(&self) -> Result<(), TaskError> {
        if self.work_profile != Self::profile_id() {
            return Err(TaskError::Profile);
        }
        if self.cost_class != 1 || self.logical_multiply_add_units != LOGICAL_MULTIPLY_ADD_UNITS {
            return Err(TaskError::CostClass);
        }
        if self.numeric_encoding != 1 {
            return Err(TaskError::NumericEncoding);
        }
        if self.recipe != Self::recipe_id() {
            return Err(TaskError::Recipe);
        }
        if self.hardness_status != 0 {
            return Err(TaskError::HardnessNotAccepted);
        }
        if self.reuse != 1 {
            return Err(TaskError::Reuse);
        }
        if [self.rows, self.inner, self.columns] != [MATRIX_SIDE; 3] {
            return Err(TaskError::Shape);
        }
        if self.hashes().iter().any(|value| **value == [0; 32]) {
            return Err(TaskError::Identity);
        }
        if self.layer != Self::layer_id(self.model) {
            return Err(TaskError::Layer);
        }
        if self.output_meter != self.derived_output_meter() {
            return Err(TaskError::OutputMeter);
        }
        if self.demand_nonce == 0
            || self.model_bytes != MATRIX_ARTIFACT_BYTES
            || self.input_bytes != MATRIX_ARTIFACT_BYTES
            || self.model_bytes > MAX_MATERIAL_BYTES
            || self.input_bytes > MAX_MATERIAL_BYTES
            || self.useful_output_limit != self.purpose.output_limit()
        {
            return Err(TaskError::Limits);
        }
        if self.expires < self.not_before
            || self.expires - self.not_before > MAX_VALIDITY_BLOCKS
            || self.available_until < self.expires
        {
            return Err(TaskError::Validity);
        }
        Ok(())
    }
    fn hashes(&self) -> [&Hash; 16] {
        [
            &self.network,
            &self.parameters,
            &self.work_profile,
            &self.source,
            &self.demand_id,
            &self.source_record,
            &self.model,
            &self.layer,
            &self.input,
            &self.recipe,
            &self.matrix_task,
            &self.availability_manifest,
            &self.availability_root,
            &self.authorization_scope,
            &self.withdrawal_head,
            &self.output_meter,
        ]
    }
    pub fn encode(&self) -> Result<Vec<u8>, TaskError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(MANIFEST_BYTES);
        bytes.extend_from_slice(b"QWT1");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&[
            self.purpose as u8,
            self.cost_class,
            self.numeric_encoding,
            self.hardness_status,
            self.reuse,
            0,
        ]);
        for value in self.hashes() {
            bytes.extend_from_slice(value);
        }
        for value in [self.rows, self.inner, self.columns, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            self.demand_nonce,
            self.not_before,
            self.expires,
            self.available_until,
            self.logical_multiply_add_units,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [self.model_bytes, self.input_bytes, self.useful_output_limit] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), MANIFEST_BYTES);
        Ok(bytes)
    }
    pub fn id(&self) -> Result<Hash, TaskError> {
        Ok(hash(b"qualified-task-manifest-v1", &[&self.encode()?]))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, TaskError> {
        if bytes.len() != MANIFEST_BYTES {
            return Err(TaskError::Length);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take::<4>()? != *b"QWT1" || reader.take::<2>()? != 1_u16.to_le_bytes() {
            return Err(TaskError::Version);
        }
        let purpose = TaskPurpose::decode(reader.take::<1>()?[0])?;
        let cost_class = reader.take::<1>()?[0];
        let numeric_encoding = reader.take::<1>()?[0];
        let hardness_status = reader.take::<1>()?[0];
        let reuse = reader.take::<1>()?[0];
        if reader.take::<1>()? != [0] {
            return Err(TaskError::Reserved);
        }
        let mut task = Self {
            purpose,
            cost_class,
            numeric_encoding,
            hardness_status,
            reuse,
            network: reader.take()?,
            parameters: reader.take()?,
            work_profile: reader.take()?,
            source: reader.take()?,
            demand_id: reader.take()?,
            source_record: reader.take()?,
            model: reader.take()?,
            layer: reader.take()?,
            input: reader.take()?,
            recipe: reader.take()?,
            matrix_task: reader.take()?,
            availability_manifest: reader.take()?,
            availability_root: reader.take()?,
            authorization_scope: reader.take()?,
            withdrawal_head: reader.take()?,
            output_meter: reader.take()?,
            rows: u16::from_le_bytes(reader.take()?),
            inner: u16::from_le_bytes(reader.take()?),
            columns: u16::from_le_bytes(reader.take()?),
            demand_nonce: 0,
            not_before: 0,
            expires: 0,
            available_until: 0,
            logical_multiply_add_units: 0,
            model_bytes: 0,
            input_bytes: 0,
            useful_output_limit: 0,
        };
        if reader.take::<2>()? != [0, 0] {
            return Err(TaskError::Reserved);
        }
        task.demand_nonce = u64::from_le_bytes(reader.take()?);
        task.not_before = u64::from_le_bytes(reader.take()?);
        task.expires = u64::from_le_bytes(reader.take()?);
        task.available_until = u64::from_le_bytes(reader.take()?);
        task.logical_multiply_add_units = u64::from_le_bytes(reader.take()?);
        task.model_bytes = u32::from_le_bytes(reader.take()?);
        task.input_bytes = u32::from_le_bytes(reader.take()?);
        task.useful_output_limit = u32::from_le_bytes(reader.take()?);
        task.validate()?;
        Ok(task)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedQualifiedWorkTask {
    pub manifest: QualifiedWorkTask,
    pub signature: [u8; 64],
}
impl SignedQualifiedWorkTask {
    pub fn signing_message(manifest: &QualifiedWorkTask) -> Result<Hash, TaskError> {
        Ok(hash(
            b"qualified-task-source-sign-v1",
            &[&manifest.encode()?],
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, TaskError> {
        let mut bytes = Vec::with_capacity(SIGNED_TASK_BYTES);
        bytes.extend_from_slice(b"QWA1");
        bytes.extend_from_slice(&self.manifest.encode()?);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, TaskError> {
        if bytes.len() != SIGNED_TASK_BYTES {
            return Err(TaskError::Length);
        }
        if bytes[..4] != *b"QWA1" {
            return Err(TaskError::Version);
        }
        Ok(Self {
            manifest: QualifiedWorkTask::decode(&bytes[4..4 + MANIFEST_BYTES])?,
            signature: bytes[4 + MANIFEST_BYTES..]
                .try_into()
                .map_err(|_| TaskError::Length)?,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], TaskError> {
        let end = self.position.checked_add(N).ok_or(TaskError::Length)?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(TaskError::Length)?
            .try_into()
            .map_err(|_| TaskError::Length)?;
        self.position = end;
        Ok(result)
    }
}
