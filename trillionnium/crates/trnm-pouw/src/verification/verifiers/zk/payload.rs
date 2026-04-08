use crate::verification::backend::{
    normalize_backend_token, parse_zk_proof_payload, BackendExecutionError,
    ParsedZkProofPayload, VerificationBackendConfig,
};
use trnm_types::TaskObject;

use super::helpers::has_json_envelope;

pub(super) fn parse_payload(
    config: &VerificationBackendConfig,
    task: &TaskObject,
    proof_data: &[u8],
) -> Result<Option<ParsedZkProofPayload>, BackendExecutionError> {
    let flags = &config.zk_features;
    let has_json_envelope = has_json_envelope(proof_data);

    if flags.zk_payload_v0_envelope && !has_json_envelope {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: canonical JSON object is required when zk_payload_v0_envelope is enabled".to_string(),
        });
    }

    if !has_json_envelope {
        return Ok(None);
    }

    let payload = parse_zk_proof_payload(task, proof_data)?;

    if flags.zk_payload_v0_envelope && payload.schema_version != "trnm.zk.payload.v0" {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: schema_version must be trnm.zk.payload.v0".to_string(),
        });
    }

    if flags.zk_explicit_backend_required {
        let has_explicit_backend_selector = payload
            .backend_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|backend_id| {
                backend_id.eq_ignore_ascii_case("noop")
                    || normalize_backend_token(backend_id).is_some()
            });

        if !has_explicit_backend_selector {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id is required when zk_explicit_backend_required is enabled".to_string(),
            });
        }
    }

    Ok(Some(payload))
}
