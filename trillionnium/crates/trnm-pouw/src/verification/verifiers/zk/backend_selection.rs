use crate::verification::backend::{
    normalize_backend_token, ParsedZkProofPayload, VerificationBackendConfig,
    VerificationBackendError, ZkBackendKind,
};

use super::helpers::validate_selected_backend_token;

pub(super) fn select_backend(
    config: &VerificationBackendConfig,
    configured_backend: &ZkBackendKind,
    zk_payload: Option<&ParsedZkProofPayload>,
) -> Result<ZkBackendKind, VerificationBackendError> {
    let flags = &config.zk_features;

    if flags.zk_platform_v0 && flags.zk_backend_router {
        if let Some(payload_backend_id) = zk_payload
            .and_then(|payload| payload.backend_id.as_deref())
            .map(str::trim)
        {
            if payload_backend_id.eq_ignore_ascii_case("noop") {
                return Ok(ZkBackendKind::Noop);
            }
            if normalize_backend_token(payload_backend_id).is_some() {
                return Ok(ZkBackendKind::Custom(payload_backend_id.to_string()));
            }
        }
    }

    validate_selected_backend_token(configured_backend.key())?;
    Ok(configured_backend.clone())
}
