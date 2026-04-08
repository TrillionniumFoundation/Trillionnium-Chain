use super::*;

pub fn parse_zk_proof_payload(
    task: &TaskObject,
    proof_data: &[u8],
) -> Result<ParsedZkProofPayload, BackendExecutionError> {
    let raw =
        std::str::from_utf8(proof_data).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof envelope is not valid utf-8".to_string(),
        })?;
    let body = raw
        .strip_prefix("ZK:")
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: missing canonical ZK: prefix".to_string(),
        })?;
    let payload: ParsedZkProofPayload =
        serde_json::from_str(body).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: body must be canonical JSON object".to_string(),
        })?;

    let expected_hash =
        hex::encode(
            task.result_hash
                .ok_or_else(|| BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: missing task result_hash binding context"
                        .to_string(),
                })?,
        );

    if payload.task_id != task.task_id {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: task_id mismatch".to_string(),
        });
    }
    if payload.worker != task.worker.as_deref().unwrap_or_default() {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: worker mismatch".to_string(),
        });
    }
    if payload.proof_type != "zk" {
        let reason = if payload.proof_type.eq_ignore_ascii_case("zk") {
            "invalid zk payload: proof_type must use canonical lowercase token 'zk'".to_string()
        } else {
            "invalid zk payload: proof_type must be zk".to_string()
        };
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason,
        });
    }
    if payload.result_hash != expected_hash {
        let reason = if payload.result_hash.eq_ignore_ascii_case(&expected_hash) {
            "invalid zk payload: result_hash must use canonical lowercase hex".to_string()
        } else {
            "invalid zk payload: result_hash mismatch".to_string()
        };
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason,
        });
    }
    let raw_zk_system =
        payload
            .zk_system
            .as_deref()
            .ok_or_else(|| BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: zk_system is required".to_string(),
            })?;
    let normalized_zk_system = normalize_zk_system(raw_zk_system).ok_or_else(|| {
        BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: unsupported zk_system '{}'",
                raw_zk_system.trim()
            ),
        }
    })?;
    if raw_zk_system != normalized_zk_system {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: zk_system must use canonical token '{}'",
                normalized_zk_system
            ),
        });
    }
    if payload.schema_version != "trnm.zk.payload.v0" {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: schema_version must be trnm.zk.payload.v0".to_string(),
        });
    }
    if payload.vk_ref.trim().is_empty() {
        return Err(VkRefResolutionError::Missing.into_backend_execution_error());
    }
    if payload.vk_ref != payload.vk_ref.trim() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: vk_ref must not contain surrounding whitespace"
                .to_string(),
        });
    }
    if payload
        .vk_ref
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: vk_ref must be a single opaque token without embedded whitespace or control characters"
                .to_string(),
        });
    }
    if let Some(backend_id) = payload.backend_id.as_deref() {
        if backend_id != backend_id.trim() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must not contain surrounding whitespace"
                    .to_string(),
            });
        }
        if backend_id.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must not be empty when provided"
                    .to_string(),
            });
        }
        if contains_forbidden_opaque_token_chars(backend_id) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must be a single opaque token without embedded whitespace or control characters"
                    .to_string(),
            });
        }
        if backend_id.eq_ignore_ascii_case("noop") {
            if backend_id != "noop" {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: legacy noop backend_id must use canonical lowercase token 'noop'"
                        .to_string(),
                });
            }
            if payload.backend_version.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: backend_version must not be provided for legacy noop backend_id"
                        .to_string(),
                });
            }
        } else if normalize_backend_token(backend_id).is_none() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend_id '{}' must contain at least one visible canonical backend token segment",
                    backend_id
                ),
            });
        }
    }
    if let Some(backend_version) = payload.backend_version.as_deref() {
        if backend_version != backend_version.trim() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason:
                    "invalid zk payload: backend_version must not contain surrounding whitespace"
                        .to_string(),
            });
        }
        if backend_version.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version must not be empty when provided"
                    .to_string(),
            });
        }
        if contains_forbidden_opaque_token_chars(backend_version) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version must be a single opaque token without embedded whitespace or control characters"
                    .to_string(),
            });
        }
        if payload
            .backend_id
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
        {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version requires backend_id".to_string(),
            });
        }
    }
    if payload.proof.trim().is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof bytes are required".to_string(),
        });
    }
    if payload.proof != payload.proof.trim() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof must not contain surrounding whitespace".to_string(),
        });
    }
    if payload
        .proof
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof must be encoded as a single token without embedded whitespace or control characters".to_string(),
        });
    }
    let mut expected_public_inputs = vec![task.task_id.to_string(), "zk".to_string()];
    let mut expected_order = vec!["task_id".to_string(), "proof_type".to_string()];
    if let Some(worker) = task.worker.as_ref() {
        expected_public_inputs.push(worker.clone());
        expected_order.push("worker".to_string());
    }
    expected_public_inputs.push(expected_hash.clone());
    expected_order.push("result_hash".to_string());

    if payload.public_inputs.order.len() != payload.public_inputs.values.len() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs order/value length mismatch".to_string(),
        });
    }

    let mut seen_fields = HashSet::with_capacity(payload.public_inputs.order.len());
    for field in &payload.public_inputs.order {
        if !seen_fields.insert(field.as_str()) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!("invalid zk payload: duplicate public_inputs field '{field}'"),
            });
        }
    }

    if payload.public_inputs.order != expected_order {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs order is not canonical".to_string(),
        });
    }

    if payload.public_inputs.values != expected_public_inputs {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs mismatch".to_string(),
        });
    }
    let _ = payload.decode_proof_bytes()?;
    Ok(payload)
}

pub fn resolve_zk_vk_ref(
    resolver: &dyn VkRefResolver,
    payload: &ParsedZkProofPayload,
) -> Result<ResolvedVkRef, BackendExecutionError> {
    let resolved = resolver
        .resolve(&payload.vk_ref)
        .map_err(VkRefResolutionError::into_backend_execution_error)?;

    if let (Some(payload_system), Some(resolved_system)) = (
        payload.zk_system.as_deref().and_then(normalize_zk_system),
        resolved.zk_system.as_deref().and_then(normalize_zk_system),
    ) {
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

    Ok(resolved)
}

pub(crate) fn decode_base64(raw: &str) -> Result<Vec<u8>, String> {
    let cleaned = raw
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return Err("invalid zk payload: proof bytes are required".to_string());
    }
    if cleaned.len() % 4 != 0 {
        return Err("invalid zk payload: proof is not valid base64".to_string());
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        let mut vals = [0u8; 4];
        let mut padding = 0usize;
        for (idx, ch) in chunk.iter().copied().enumerate() {
            vals[idx] = match ch {
                b'A'..=b'Z' => ch - b'A',
                b'a'..=b'z' => ch - b'a' + 26,
                b'0'..=b'9' => ch - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return Err("invalid zk payload: proof is not valid base64".to_string()),
            };
            if padding > 0 && idx < 2 {
                return Err("invalid zk payload: base64 padding must be terminal".to_string());
            }
            if padding > 0 && ch != b'=' {
                return Err("invalid zk payload: base64 padding must be terminal".to_string());
            }
        }
        if padding > 2 {
            return Err("invalid zk payload: proof is not valid base64".to_string());
        }

        let block = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push(((block >> 16) & 0xff) as u8);
        if padding < 2 {
            out.push(((block >> 8) & 0xff) as u8);
        }
        if padding == 0 {
            out.push((block & 0xff) as u8);
        }
    }

    if out.is_empty() {
        return Err("invalid zk payload: proof bytes are required".to_string());
    }
    Ok(out)
}
