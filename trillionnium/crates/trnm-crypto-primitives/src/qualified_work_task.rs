//! Source-authenticated development admission; never a scientific hardness certificate.
//! Caller-pinned owner records are an explicit trust contract, not proof of genuine
//! demand, lawful authorization, correct model-to-layer extraction, or remote retention.
use crate::{pon_work, verify_hex_strict};

pub mod lifecycle_v2;
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::{
        QualifiedWorkTask, SignedQualifiedWorkTask, TaskError, TaskPurpose, MATRIX_ARTIFACT_BYTES,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    Manifest(TaskError),
    Context,
    Source,
    Demand,
    Authorization,
    Withdrawal,
    Signature,
    Height,
    Availability,
    MaterialLength,
    Model,
    Input,
    MatrixTask,
    WorkTask,
    MatrixBinding,
    Numeric,
}
impl From<TaskError> for AdmissionError {
    fn from(error: TaskError) -> Self {
        Self::Manifest(error)
    }
}

/// Independently supplied local pinnings. Passing these is not verification of the
/// owner's rights or the truth of its demand. No wire-supplied true flag is accepted.
pub struct AdmissionContext {
    pub network: Hash,
    pub parameters: Hash,
    pub source: Hash,
    pub demand_id: Hash,
    pub source_record: Hash,
    pub authorization_scope: Hash,
    pub withdrawal_head: Hash,
    pub availability_manifest: Hash,
    pub availability_root: Hash,
    pub height: u64,
    pub required_retention_blocks: u64,
}
pub struct TaskMaterial<'a> {
    pub model: &'a [u8],
    pub input: &'a [u8],
    pub a: &'a [u32],
    pub b: &'a [u32],
}

/// Only a strict source signature and branch-context check; model/data availability,
/// matrix derivation and real-world authority remain unverified at this layer.
#[derive(Debug)]
pub struct AuthenticatedTaskStatement {
    manifest: QualifiedWorkTask,
    manifest_id: Hash,
}
impl AuthenticatedTaskStatement {
    pub fn manifest(&self) -> &QualifiedWorkTask {
        &self.manifest
    }
    pub fn manifest_id(&self) -> Hash {
        self.manifest_id
    }
}

/// The version-1 recipe interprets exactly4096 canonical LE32 field values in each
/// artifact as row-major A(model layer) and B(batch inputs). It certifies this one
/// linear contraction, not a whole classifier/LLM, training step or consent provenance.
pub fn derive_matrices(model: &[u8], input: &[u8]) -> Result<(Vec<u32>, Vec<u32>), AdmissionError> {
    fn decode(bytes: &[u8]) -> Result<Vec<u32>, AdmissionError> {
        if bytes.len() != MATRIX_ARTIFACT_BYTES as usize {
            return Err(AdmissionError::MaterialLength);
        }
        let mut values = Vec::with_capacity(pon_work::CELLS);
        for bytes in bytes.chunks_exact(4) {
            let value = u32::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| AdmissionError::MaterialLength)?,
            );
            if u128::from(value) >= pon_work::Q {
                return Err(AdmissionError::Numeric);
            }
            values.push(value);
        }
        Ok(values)
    }
    Ok((decode(model)?, decode(input)?))
}

/// Private construction prevents unsigned manifests from creating this checked fact.
/// Durable parent admission, withdrawal/replay checks and output-meter consumption are
/// separate responsibilities of the existing branch-state owner.
#[derive(Debug)]
pub struct DevelopmentTaskAdmission {
    manifest: QualifiedWorkTask,
    manifest_id: Hash,
}
impl DevelopmentTaskAdmission {
    pub fn manifest(&self) -> &QualifiedWorkTask {
        &self.manifest
    }
    pub fn manifest_id(&self) -> Hash {
        self.manifest_id
    }
    pub fn matrix_task(&self) -> Hash {
        self.manifest.matrix_task
    }
    pub fn output_meter(&self) -> Hash {
        self.manifest.output_meter
    }
    pub fn purpose(&self) -> TaskPurpose {
        self.manifest.purpose
    }
    pub fn bind_verified_output(
        &self,
        work: &pon_work::VerifiedWork,
    ) -> Result<BoundTaskOutput, AdmissionError> {
        if work.task() != self.matrix_task() {
            return Err(AdmissionError::WorkTask);
        }
        let product: Vec<u8> = work
            .product()
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        Ok(BoundTaskOutput {
            meter: self.output_meter(),
            product: hash(b"qualified-task-product-v1", &[&product]),
            challenge: work.challenge(),
            maximum_output_credit: self.manifest.useful_output_limit,
        })
    }
}

/// Exact arithmetic output identity, not measured utility or a reward entitlement.
#[derive(Debug)]
pub struct BoundTaskOutput {
    meter: Hash,
    product: Hash,
    challenge: Hash,
    maximum_output_credit: u32,
}
impl BoundTaskOutput {
    pub fn meter(&self) -> Hash {
        self.meter
    }
    pub fn product(&self) -> Hash {
        self.product
    }
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn maximum_output_credit(&self) -> u32 {
        self.maximum_output_credit
    }
}

pub fn verify_development_statement(
    packet: &[u8],
    context: &AdmissionContext,
) -> Result<AuthenticatedTaskStatement, AdmissionError> {
    let signed = SignedQualifiedWorkTask::decode(packet)?;
    let manifest = &signed.manifest;
    if manifest.network != context.network || manifest.parameters != context.parameters {
        return Err(AdmissionError::Context);
    }
    if manifest.source != context.source {
        return Err(AdmissionError::Source);
    }
    if manifest.demand_id != context.demand_id || manifest.source_record != context.source_record {
        return Err(AdmissionError::Demand);
    }
    if manifest.authorization_scope != context.authorization_scope {
        return Err(AdmissionError::Authorization);
    }
    if manifest.withdrawal_head != context.withdrawal_head {
        return Err(AdmissionError::Withdrawal);
    }
    if context.height < manifest.not_before || context.height > manifest.expires {
        return Err(AdmissionError::Height);
    }
    let required_until = manifest
        .expires
        .checked_add(context.required_retention_blocks)
        .ok_or(AdmissionError::Availability)?;
    if manifest.availability_manifest != context.availability_manifest
        || manifest.availability_root != context.availability_root
        || manifest.available_until < required_until
    {
        return Err(AdmissionError::Availability);
    }
    let message = SignedQualifiedWorkTask::signing_message(manifest)?;
    verify_hex_strict(
        &hex::encode(manifest.source),
        &message,
        &hex::encode(signed.signature),
    )
    .map_err(|_| AdmissionError::Signature)?;
    let manifest_id = manifest.id()?;
    Ok(AuthenticatedTaskStatement {
        manifest: signed.manifest,
        manifest_id,
    })
}

pub fn verify_development_admission(
    packet: &[u8],
    material: TaskMaterial<'_>,
    context: &AdmissionContext,
) -> Result<DevelopmentTaskAdmission, AdmissionError> {
    let statement = verify_development_statement(packet, context)?;
    let manifest = &statement.manifest;
    if material.model.len() != manifest.model_bytes as usize
        || material.input.len() != manifest.input_bytes as usize
    {
        return Err(AdmissionError::MaterialLength);
    }
    if hash(b"artifact", &[material.model]) != manifest.model {
        return Err(AdmissionError::Model);
    }
    if hash(b"qualified-task-input-v1", &[material.input]) != manifest.input {
        return Err(AdmissionError::Input);
    }
    let (derived_a, derived_b) = derive_matrices(material.model, material.input)?;
    if material.a != derived_a || material.b != derived_b {
        return Err(AdmissionError::MatrixBinding);
    }
    if pon_work::task_id(material.a, material.b).map_err(|_| AdmissionError::MatrixTask)?
        != manifest.matrix_task
    {
        return Err(AdmissionError::MatrixTask);
    }
    Ok(DevelopmentTaskAdmission {
        manifest: statement.manifest,
        manifest_id: statement.manifest_id,
    })
}
