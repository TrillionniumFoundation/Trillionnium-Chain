use std::sync::Arc;

use crate::verification::backend::{
    parse_tee_attestation_payload, BackendVerificationRequest, VerificationBackendError,
    VerificationBackendFamily, ZkBackendKind, ZkBackendRegistry,
};
use trnm_types::TaskObject;

pub(super) fn verify_backend(
    backends: &Arc<ZkBackendRegistry>,
    backend_kind: &ZkBackendKind,
    task: &TaskObject,
    proof_data: &[u8],
) -> Result<(), VerificationBackendError> {
    let backend = backends.resolve(VerificationBackendFamily::Tee, backend_kind)?;
    let tee_payload = if matches!(backend_kind, ZkBackendKind::Noop) {
        None
    } else {
        Some(parse_tee_attestation_payload(proof_data)?)
    };
    backend.verify(BackendVerificationRequest {
        family: VerificationBackendFamily::Tee,
        task,
        proof_data,
        tee_payload: tee_payload.as_ref(),
        zk_payload: None,
        resolved_vk_ref: None,
    })?;
    Ok(())
}
