//! Independent requester/source ML-DSA proofs in the exact NPQ5 namespace.
//! The M06 caller must resolve these keys from its actual parent State. This
//! cryptographic layer never treats caller-provided keys as ledger permission.
use super::{
    derive_matrices, AdmissionError, AuthenticatedTaskStatement, DevelopmentTaskAdmission,
    TaskMaterial,
};
use crate::{pon_work, pq_auth::verify_tpq1};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    pq_frame::PqFrameExpectation,
    pq_native_accounts_v2::{self as wire, AccountProfile, ChainContext, UnverifiedEnvelope},
    qualified_work_task::pq_lifecycle_v5::{AtomicRenewTaskV5, DemandLeaseV5, TaskRegistrationV5},
};

pub struct ResolvedTaskAuthority<'a> {
    pub account: Hash,
    pub key_id: Hash,
    pub generation: u64,
    pub spki: &'a [u8],
}
pub struct TaskAuthorityContext<'a> {
    pub chain: ChainContext,
    pub requester: ResolvedTaskAuthority<'a>,
    pub source: ResolvedTaskAuthority<'a>,
    /// Header time of the original command admission, not the current clock.
    /// Command expiry and the separately signed lease-height window differ.
    pub admitted_at: u64,
    pub height: u64,
}

/// Exact semantic binding only. Success carries no signature or State authority.
pub fn check_registration_binding(
    registration: &TaskRegistrationV5,
    lease: &DemandLeaseV5,
    height: u64,
) -> Result<(), AdmissionError> {
    lease.validate().map_err(|_| AdmissionError::Demand)?;
    let manifest = &registration.manifest;
    manifest.encode()?;
    if registration.lease_id != lease.id().map_err(|_| AdmissionError::Demand)?
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
    Ok(())
}

pub fn statement_id(raw: &[u8]) -> Result<Hash, AdmissionError> {
    statement_id_for_profile(raw, AccountProfile::TasksV5)
}

/// The protected owner selects a single profile; input bytes never select one.
pub fn statement_id_for_profile(
    raw: &[u8],
    profile: AccountProfile,
) -> Result<Hash, AdmissionError> {
    if !profile.task_v5() {
        return Err(AdmissionError::Context);
    }
    let tx = UnverifiedEnvelope::decode_for_profile(raw, profile)
        .map_err(|_| AdmissionError::Signature)?;
    if !matches!(tx.kind, 21 | 22) {
        return Err(AdmissionError::Signature);
    }
    Ok(hash(
        match profile {
            AccountProfile::TasksV5 => b"qualified-pq-task-statement-v5",
            AccountProfile::ApplicationV6 => b"qualified-pq-task-statement-v6",
            _ => return Err(AdmissionError::Context),
        },
        &[tx.core()],
    ))
}

pub fn verify_statement(
    raw: &[u8],
    lease: &DemandLeaseV5,
    context: &TaskAuthorityContext<'_>,
) -> Result<AuthenticatedTaskStatement, AdmissionError> {
    verify_statement_for_profile(raw, lease, context, AccountProfile::TasksV5, &mut || Ok(()))
}

/// The callback is called immediately before every real verification attempt,
/// including failed attempts. It grants no signature authority.
pub fn verify_statement_for_profile(
    raw: &[u8],
    lease: &DemandLeaseV5,
    context: &TaskAuthorityContext<'_>,
    profile: AccountProfile,
    before_verification: &mut impl FnMut() -> Result<(), AdmissionError>,
) -> Result<AuthenticatedTaskStatement, AdmissionError> {
    if !profile.task_v5() {
        return Err(AdmissionError::Context);
    }
    let tx = UnverifiedEnvelope::decode_for_profile(raw, profile)
        .map_err(|_| AdmissionError::Signature)?;
    if !matches!(tx.kind, 21 | 22)
        || tx.common.context != context.chain
        || tx.common.account != lease.requester
        || context.requester.account != lease.requester
        || context.source.account != lease.source
        || context.requester.account == context.source.account
        || context.admitted_at == 0
    {
        return Err(AdmissionError::Context);
    }
    let registration = match tx.kind {
        21 => TaskRegistrationV5::decode(tx.payload).map_err(|_| AdmissionError::Demand)?,
        22 => {
            let atomic =
                AtomicRenewTaskV5::decode(tx.payload).map_err(|_| AdmissionError::Demand)?;
            if &atomic.successor != lease {
                return Err(AdmissionError::Demand);
            }
            atomic.registration
        }
        _ => return Err(AdmissionError::Signature),
    };
    check_registration_binding(&registration, lease, context.height)?;
    for (index, authority) in [&context.requester, &context.source]
        .into_iter()
        .enumerate()
    {
        let witness = &tx.witnesses()[index];
        if witness.generation != authority.generation || witness.key_id != authority.key_id {
            return Err(AdmissionError::Source);
        }
        before_verification()?;
        verify_tpq1(
            witness.frame,
            &PqFrameExpectation {
                purpose: witness.role,
                network: context.chain.network,
                owner_context: wire::owner_context_for_profile(
                    profile,
                    &tx.common,
                    tx.kind,
                    witness.role,
                )
                .map_err(|_| AdmissionError::Context)?,
                signer_key_id: authority.key_id,
                owner_generation: authority.generation,
                operation_sequence: tx.common.nonce,
                expires_at: tx.common.expires_at,
                now: context.admitted_at,
                payload: tx.core(),
            },
            authority.spki,
        )
        .map_err(|_| AdmissionError::Signature)?;
    }
    Ok(AuthenticatedTaskStatement {
        manifest: registration.manifest,
        manifest_id: statement_id_for_profile(raw, profile)?,
    })
}

/// Rechecks both actual signatures, exact lease and supplied matrix bytes. M06
/// separately checks active status, current authority and source sequence.
pub fn verify_admission(
    raw: &[u8],
    lease: &DemandLeaseV5,
    context: &TaskAuthorityContext<'_>,
    material: TaskMaterial<'_>,
) -> Result<DevelopmentTaskAdmission, AdmissionError> {
    verify_admission_for_profile(
        raw,
        lease,
        context,
        material,
        AccountProfile::TasksV5,
        &mut || Ok(()),
    )
}

pub fn verify_admission_for_profile(
    raw: &[u8],
    lease: &DemandLeaseV5,
    context: &TaskAuthorityContext<'_>,
    material: TaskMaterial<'_>,
    profile: AccountProfile,
    before_verification: &mut impl FnMut() -> Result<(), AdmissionError>,
) -> Result<DevelopmentTaskAdmission, AdmissionError> {
    let statement =
        verify_statement_for_profile(raw, lease, context, profile, before_verification)?;
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
