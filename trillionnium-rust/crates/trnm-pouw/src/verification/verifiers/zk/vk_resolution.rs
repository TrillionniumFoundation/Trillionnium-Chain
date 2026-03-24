use crate::verification::backend::{
    backend_token_family_hint, backend_token_zk_system_hints, normalize_backend_token,
    normalize_zk_system, resolve_zk_vk_ref, BackendExecutionError, ParsedZkProofPayload,
    ResolvedVkRef, VerificationBackendConfig, VerificationBackendFamily, VkRefRegistry,
    ZkBackendKind,
};

pub(super) fn resolve_vk_ref_for_backend(
    config: &VerificationBackendConfig,
    vk_refs: &VkRefRegistry,
    selected_backend: &ZkBackendKind,
    zk_payload: Option<&ParsedZkProofPayload>,
) -> Result<Option<ResolvedVkRef>, BackendExecutionError> {
    let Some(payload) = zk_payload else {
        return Ok(None);
    };

    let flags = &config.zk_features;
    let resolved = resolve_zk_vk_ref(vk_refs, payload)?;

    let resolved_system = match resolved.zk_system.as_deref() {
        Some(raw_system) => {
            let normalized = normalize_zk_system(raw_system).ok_or_else(|| {
                BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: vk_ref '{}' is missing canonical zk_system metadata",
                        resolved.vk_ref
                    ),
                }
            })?;

            if raw_system != normalized {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: vk_ref '{}' must use canonical zk_system metadata '{}'",
                        resolved.vk_ref, normalized
                    ),
                });
            }

            normalized
        }
        None => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: vk_ref '{}' is missing canonical zk_system metadata",
                    resolved.vk_ref
                ),
            });
        }
    };

    if let Some(payload_system) = payload.zk_system.as_deref().and_then(normalize_zk_system) {
        if payload_system != resolved_system {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: zk_system '{payload_system}' does not match vk_ref '{}'",
                    resolved.vk_ref
                ),
            });
        }
    }

    if let Some(payload_backend_id) = payload
        .backend_id
        .as_deref()
        .map(str::trim)
        .filter(|backend| !backend.is_empty())
    {
        match backend_token_family_hint(payload_backend_id) {
            Some(VerificationBackendFamily::Tee) => {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend_id '{}' declares tee family and does not match zk vk_ref '{}'",
                        payload_backend_id, resolved.vk_ref
                    ),
                });
            }
            Some(VerificationBackendFamily::Zk)
                if backend_token_zk_system_hints(payload_backend_id).is_empty() =>
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend_id '{}' must not be a family-only zk router token without a canonical zk_system hint",
                        payload_backend_id
                    ),
                });
            }
            _ => {}
        }

        if let Some(payload_backend_system) = normalize_zk_system(payload_backend_id) {
            if payload_backend_system != resolved_system {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend_id '{}' does not match vk_ref '{}'",
                        payload_backend_id, resolved.vk_ref
                    ),
                });
            }
        } else if normalize_backend_token(payload_backend_id).is_some() {
            let hinted_systems = backend_token_zk_system_hints(payload_backend_id);

            if hinted_systems.len() > 1 {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend_id '{}' carries multiple zk_system hints and does not match vk_ref '{}'",
                        payload_backend_id, resolved.vk_ref
                    ),
                });
            }

            if let Some(payload_backend_system) = hinted_systems.into_iter().next() {
                if payload_backend_system != resolved_system {
                    return Err(BackendExecutionError::InvalidProof {
                        backend: "zk:payload".to_string(),
                        reason: format!(
                            "invalid zk payload: backend_id '{}' does not match vk_ref '{}'",
                            payload_backend_id, resolved.vk_ref
                        ),
                    });
                }
            } else if flags.zk_explicit_backend_required
                && !payload_backend_id.eq_ignore_ascii_case("noop")
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend_id '{}' must carry a canonical zk_system hint when zk_explicit_backend_required is enabled",
                        payload_backend_id
                    ),
                });
            }
        } else if flags.zk_explicit_backend_required
            && !payload_backend_id.eq_ignore_ascii_case("noop")
        {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend_id '{}' must carry a canonical zk_system hint when zk_explicit_backend_required is enabled",
                    payload_backend_id
                ),
            });
        }
    }

    if let Some(VerificationBackendFamily::Tee) = backend_token_family_hint(selected_backend.key()) {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' declares tee family and does not match zk vk_ref '{}'",
                selected_backend.key(),
                resolved.vk_ref
            ),
        });
    }

    let selected_backend_hints = backend_token_zk_system_hints(selected_backend.key());
    if matches!(
        backend_token_family_hint(selected_backend.key()),
        Some(VerificationBackendFamily::Zk)
    ) && selected_backend_hints.is_empty()
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' must not be a family-only zk router token without a canonical zk_system hint",
                selected_backend.key()
            ),
        });
    }
    if selected_backend_hints.len() > 1 {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' carries multiple zk_system hints and does not match vk_ref '{}'",
                selected_backend.key(),
                resolved.vk_ref
            ),
        });
    }

    if let Some(selected_backend_system) = selected_backend_hints.into_iter().next() {
        if selected_backend_system != resolved_system {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' does not match vk_ref '{}'",
                    selected_backend.key(),
                    resolved.vk_ref
                ),
            });
        }
    }

    Ok(Some(resolved))
}
