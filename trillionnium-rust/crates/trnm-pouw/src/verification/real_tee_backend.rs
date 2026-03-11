use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::verification::backend::{
    BackendExecutionError, BackendVerificationRequest, BackendVerificationSuccess,
    VerificationBackend, VerificationBackendFamily, ZkBackendRegistry,
};
#[cfg(test)]
use crate::verification::backend::{VerificationBackendConfig, VerificationBackendKind};
#[cfg(test)]
use crate::verification::{registry::VerifierRegistry, VerificationResult};
#[cfg(test)]
use trnm_types::{ProofType, TaskObject, TaskStatus};

#[derive(Debug, Clone, Deserialize)]
struct TeeFixtureManifest {
    backend_id: String,
    attestation_target: String,
    measurement: String,
    quote: String,
    report_data_hash: String,
}

#[derive(Debug, Clone)]
struct TeeFixture {
    backend_id: String,
    attestation_target: String,
    measurement: String,
    quote: String,
    report_data_hash: String,
}

impl TeeFixture {
    fn from_embedded_json(raw: &str) -> Self {
        let manifest: TeeFixtureManifest =
            serde_json::from_str(raw).expect("embedded tee fixture manifest must be valid json");
        Self {
            backend_id: manifest.backend_id,
            attestation_target: normalize_attestation_target(&manifest.attestation_target)
                .expect("embedded tee fixture target must be supported"),
            measurement: manifest.measurement,
            quote: manifest.quote,
            report_data_hash: manifest.report_data_hash.trim().to_ascii_lowercase(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTeeAttestation {
    attestation_target: String,
    measurement: String,
    report_data_hash: String,
    quote: String,
}

#[derive(Debug, Default)]
pub struct RealTeeBackend {
    fixtures: Vec<TeeFixture>,
}

impl RealTeeBackend {
    pub fn new() -> Self {
        Self {
            fixtures: load_embedded_fixtures(),
        }
    }

    fn parse_attestation_fields(
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ParsedTeeAttestation, BackendExecutionError> {
        let raw = std::str::from_utf8(request.proof_data).map_err(|_| {
            BackendExecutionError::MalformedProof {
                backend: request.backend_label(Self::backend_id_static()),
                reason: "tee receipt must be valid utf-8".to_string(),
            }
        })?;
        let body =
            raw.strip_prefix("TEE:")
                .ok_or_else(|| BackendExecutionError::MalformedProof {
                    backend: request.backend_label(Self::backend_id_static()),
                    reason: "tee receipt must start with TEE:".to_string(),
                })?;
        let fields = parse_kv_fields(body, request)?;

        let raw_target = required_field(&fields, "attestation_target", request)?;
        let attestation_target = normalize_attestation_target(raw_target).ok_or_else(|| {
            BackendExecutionError::MalformedProof {
                backend: request.backend_label(Self::backend_id_static()),
                reason: format!(
                    "invalid tee receipt: unsupported attestation_target '{}'",
                    raw_target.trim()
                ),
            }
        })?;
        let measurement = required_field(&fields, "measurement", request)?.to_string();
        let report_data_hash =
            required_field(&fields, "report_data_hash", request)?.to_ascii_lowercase();
        let quote = required_field(&fields, "quote", request)?.to_string();

        Ok(ParsedTeeAttestation {
            attestation_target,
            measurement,
            report_data_hash,
            quote,
        })
    }

    const fn backend_id_static() -> &'static str {
        "real-tee-backend"
    }
}

impl VerificationBackend for RealTeeBackend {
    fn backend_id(&self) -> &str {
        Self::backend_id_static()
    }

    fn family(&self) -> VerificationBackendFamily {
        VerificationBackendFamily::Tee
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        if request.family != VerificationBackendFamily::Tee {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "real tee backend only supports tee verification family".to_string(),
            });
        }

        let parsed = Self::parse_attestation_fields(&request)?;
        let expected_hash = request.task.result_hash.map(hex::encode).ok_or_else(|| {
            BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "missing task result_hash binding context".to_string(),
            }
        })?;

        if parsed.report_data_hash != expected_hash {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "attestation report_data_hash '{}' does not match task result hash",
                    parsed.report_data_hash
                ),
            });
        }

        let Some(fixture) = self
            .fixtures
            .iter()
            .find(|fixture| fixture.attestation_target == parsed.attestation_target)
        else {
            return Err(BackendExecutionError::Unavailable {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "no embedded attestation vector registered for target '{}'",
                    parsed.attestation_target
                ),
            });
        };

        if parsed.measurement != fixture.measurement {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "tee attestation measurement '{}' does not match target '{}' fixture",
                    parsed.measurement, parsed.attestation_target
                ),
            });
        }

        if parsed.quote != fixture.quote {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "tee attestation quote does not match target '{}' fixture",
                    parsed.attestation_target
                ),
            });
        }

        Ok(BackendVerificationSuccess {
            backend_id: fixture.backend_id.clone(),
        })
    }
}

fn load_embedded_fixtures() -> Vec<TeeFixture> {
    [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/tee/sgx_dcap_valid.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/tee/tdx_qgs_valid.json"
        )),
    ]
    .into_iter()
    .map(TeeFixture::from_embedded_json)
    .collect()
}

pub fn register_optional_backends(registry: &mut ZkBackendRegistry) {
    registry.register(Arc::new(RealTeeBackend::new()));
}

fn parse_kv_fields(
    body: &str,
    request: &BackendVerificationRequest<'_>,
) -> Result<BTreeMap<String, String>, BackendExecutionError> {
    let mut fields = BTreeMap::new();
    for entry in body.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!("invalid tee receipt field '{}'", trimmed),
            });
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if key.is_empty() || value.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!("invalid tee receipt field '{}'", trimmed),
            });
        }
        if fields.insert(key.clone(), value).is_some() {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!("duplicate tee receipt field '{}'", key),
            });
        }
    }
    Ok(fields)
}

fn required_field<'a>(
    fields: &'a BTreeMap<String, String>,
    key: &str,
    request: &BackendVerificationRequest<'_>,
) -> Result<&'a str, BackendExecutionError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!("invalid tee receipt: missing {key}"),
        })
}

fn normalize_attestation_target(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();

    match normalized.as_str() {
        "sgx" | "sgxdcap" => Some("sgx-dcap".to_string()),
        "tdx" | "tdxqgs" => Some("tdx-qgs".to_string()),
        "snp" | "sevsnp" => Some("sev-snp".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    fn tee_config() -> VerificationBackendConfig {
        VerificationBackendConfig {
            tee_backend: VerificationBackendKind::Custom("real-tee-backend".into()),
            ..VerificationBackendConfig::default()
        }
    }

    #[test]
    fn real_tee_backend_accepts_valid_sgx_vector() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1";

        assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
    }

    #[test]
    fn real_tee_backend_accepts_valid_tdx_vector() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-tdx-qgs-demo-v1";

        assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
    }

    #[test]
    fn real_tee_backend_rejects_unsupported_attestation_target_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=nitro-enclave,measurement=enclave:demo,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-demo";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("unsupported attestation_target 'nitro-enclave'")
        ));
    }

    #[test]
    fn real_tee_backend_rejects_report_data_hash_mismatch_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=2222222222222222222222222222222222222222222222222222222222222222,quote=quote-sgx-dcap-demo-v1";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("report_data_hash") && msg.contains("does not match task result hash")
        ));
    }
}
