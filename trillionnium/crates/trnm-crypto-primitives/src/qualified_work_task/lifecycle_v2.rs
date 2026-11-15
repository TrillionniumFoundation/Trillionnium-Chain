//! Lease-bound source signatures and actual matrix materials, not real-demand,
//! independent-custodian, cost-hardness, training or model-utility certificates.
use super::{
    derive_matrices, AdmissionError, AuthenticatedTaskStatement, DevelopmentTaskAdmission,
    TaskMaterial,
};
use crate::{pon_work, verify_hex_strict};
use trnm_protocol::{
    pon_wire::hash,
    qualified_work_task::lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
};

pub fn verify_lifecycle_statement(
    packet: &[u8],
    lease: &DemandLeaseV2,
    height: u64,
) -> Result<AuthenticatedTaskStatement, AdmissionError> {
    lease.validate().map_err(|_| AdmissionError::Demand)?;
    let signed = SignedLifecycleTaskV2::decode(packet).map_err(|_| AdmissionError::Demand)?;
    let manifest = &signed.manifest;
    if signed.lease_id != lease.id().map_err(|_| AdmissionError::Demand)?
        || manifest.network != lease.network
        || manifest.parameters != lease.parameters
    {
        return Err(AdmissionError::Context);
    }
    if manifest.source != lease.source {
        return Err(AdmissionError::Source);
    }
    if manifest.demand_id != lease.demand_id
        || manifest.source_record
            != lease
                .bound_source_record()
                .map_err(|_| AdmissionError::Demand)?
        || manifest.purpose != lease.purpose
        || manifest.cost_class != lease.cost_class
    {
        return Err(AdmissionError::Demand);
    }
    if manifest.authorization_scope != lease.authorization_scope {
        return Err(AdmissionError::Authorization);
    }
    if manifest.withdrawal_head
        != lease
            .withdrawal_frontier()
            .map_err(|_| AdmissionError::Withdrawal)?
    {
        return Err(AdmissionError::Withdrawal);
    }
    if manifest.not_before != lease.not_before
        || manifest.expires != lease.expires
        || height < lease.not_before
        || height > lease.expires
    {
        return Err(AdmissionError::Height);
    }
    if manifest.availability_manifest != lease.availability_manifest
        || manifest.availability_root != lease.availability_root
        || manifest.available_until != lease.available_until
    {
        return Err(AdmissionError::Availability);
    }
    verify_hex_strict(
        &hex::encode(lease.source),
        &signed
            .signing_message()
            .map_err(|_| AdmissionError::Signature)?,
        &hex::encode(signed.signature),
    )
    .map_err(|_| AdmissionError::Signature)?;
    Ok(AuthenticatedTaskStatement {
        manifest: signed.manifest.clone(),
        manifest_id: signed.id().map_err(|_| AdmissionError::Demand)?,
    })
}

/// The caller must additionally check the current parent lease status, sequence,
/// stored statement ID and one-output meter. Decoding a lease is not that admission.
pub fn verify_lifecycle_admission(
    packet: &[u8],
    material: TaskMaterial<'_>,
    lease: &DemandLeaseV2,
    height: u64,
) -> Result<DevelopmentTaskAdmission, AdmissionError> {
    let statement = verify_lifecycle_statement(packet, lease, height)?;
    let manifest = statement.manifest();
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
    let (a, b) = derive_matrices(material.model, material.input)?;
    if material.a != a || material.b != b {
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
