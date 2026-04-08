use super::*;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeEvidenceKind {
    Quote,
    Report,
}

impl TeeEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::Report => "report",
        }
    }

    pub fn verifier_kind(self) -> &'static str {
        match self {
            Self::Quote => "quote-verifier",
            Self::Report => "report-verifier",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TeeVerifierMetadata {
    pub collateral: Option<String>,
    pub cert_chain: Option<String>,
    pub issuer: Option<String>,
    pub vcek: Option<String>,
    pub report_signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTeeProofPayload {
    pub attestation_target: String,
    pub verifier_kind: String,
    pub measurement_field: String,
    pub measurement: String,
    pub report_data_hash: String,
    pub evidence_kind: TeeEvidenceKind,
    pub quote: Option<String>,
    pub report: Option<String>,
    pub verifier_metadata: TeeVerifierMetadata,
}

impl ParsedTeeProofPayload {
    pub fn evidence(&self) -> Option<&str> {
        match self.evidence_kind {
            TeeEvidenceKind::Quote => self.quote.as_deref(),
            TeeEvidenceKind::Report => self.report.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TeeAttestationTargetSpec {
    canonical: &'static str,
    measurement_field: &'static str,
    measurement_prefix: &'static str,
    evidence_kind: TeeEvidenceKind,
}

fn resolve_tee_attestation_target(raw: &str) -> Option<TeeAttestationTargetSpec> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();

    match normalized.as_str() {
        "sgx" | "sgxdcap" => Some(TeeAttestationTargetSpec {
            canonical: "sgx-dcap",
            measurement_field: "mrenclave",
            measurement_prefix: "mrenclave:",
            evidence_kind: TeeEvidenceKind::Quote,
        }),
        "tdx" | "tdxqgs" => Some(TeeAttestationTargetSpec {
            canonical: "tdx-qgs",
            measurement_field: "mrtd",
            measurement_prefix: "mrtd:",
            evidence_kind: TeeEvidenceKind::Quote,
        }),
        "snp" | "sevsnp" => Some(TeeAttestationTargetSpec {
            canonical: "sev-snp",
            measurement_field: "measurement",
            measurement_prefix: "measurement:",
            evidence_kind: TeeEvidenceKind::Report,
        }),
        _ => None,
    }
}

fn parse_tee_kv_fields(body: &str) -> Result<HashMap<String, String>, BackendExecutionError> {
    let mut fields = HashMap::new();
    for entry in body.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!("invalid tee receipt field '{trimmed}'"),
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
                backend: "tee:payload".to_string(),
                reason: format!("invalid tee receipt field '{trimmed}'"),
            });
        }
        if fields.insert(key.clone(), value).is_some() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!("duplicate tee receipt field '{key}'"),
            });
        }
    }
    Ok(fields)
}

fn required_tee_field<'a>(
    fields: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, BackendExecutionError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!("invalid tee receipt: missing {key}"),
        })
}

pub fn parse_tee_attestation_payload(
    proof_data: &[u8],
) -> Result<ParsedTeeProofPayload, BackendExecutionError> {
    let raw =
        std::str::from_utf8(proof_data).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: "tee receipt must be valid utf-8".to_string(),
        })?;
    let body = raw
        .strip_prefix("TEE:")
        .or_else(|| raw.strip_prefix("tee:"))
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: "tee receipt must start with TEE:".to_string(),
        })?;
    let fields = parse_tee_kv_fields(body)?;

    let raw_target = required_tee_field(&fields, "attestation_target")?;
    let target = resolve_tee_attestation_target(raw_target).ok_or_else(|| {
        BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!(
                "invalid tee receipt: unsupported attestation_target '{}'",
                raw_target.trim()
            ),
        }
    })?;

    let measurement = required_tee_field(&fields, "measurement")?.to_string();
    if !measurement
        .trim()
        .to_ascii_lowercase()
        .starts_with(target.measurement_prefix)
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!(
                "invalid tee receipt: target '{}' requires measurement prefix '{}'",
                target.canonical, target.measurement_prefix
            ),
        });
    }

    let report_data_hash = required_tee_field(&fields, "report_data_hash")?
        .trim()
        .to_ascii_lowercase();
    let quote = fields.get("quote").cloned();
    let report = fields.get("report").cloned();
    let verifier_metadata = TeeVerifierMetadata {
        collateral: fields.get("collateral").cloned(),
        cert_chain: fields.get("cert_chain").cloned(),
        issuer: fields.get("issuer").cloned(),
        vcek: fields.get("vcek").cloned(),
        report_signer: fields.get("report_signer").cloned(),
    };

    match target.evidence_kind {
        TeeEvidenceKind::Quote if quote.is_none() => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!(
                    "invalid tee receipt: target '{}' requires quote evidence",
                    target.canonical
                ),
            })
        }
        TeeEvidenceKind::Report if report.is_none() => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!(
                    "invalid tee receipt: target '{}' requires report evidence",
                    target.canonical
                ),
            })
        }
        _ => {}
    }

    match target.evidence_kind {
        TeeEvidenceKind::Quote => {
            if verifier_metadata.collateral.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires collateral metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.cert_chain.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires cert_chain metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.issuer.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires issuer metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.vcek.is_some() || verifier_metadata.report_signer.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' does not accept report verifier metadata",
                        target.canonical
                    ),
                });
            }
        }
        TeeEvidenceKind::Report => {
            if verifier_metadata.vcek.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires vcek metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.cert_chain.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires cert_chain metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.report_signer.is_none() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires report_signer metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.collateral.is_some() || verifier_metadata.issuer.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' does not accept quote verifier metadata",
                        target.canonical
                    ),
                });
            }
        }
    }

    Ok(ParsedTeeProofPayload {
        attestation_target: target.canonical.to_string(),
        verifier_kind: target.evidence_kind.verifier_kind().to_string(),
        measurement_field: target.measurement_field.to_string(),
        measurement,
        report_data_hash,
        evidence_kind: target.evidence_kind,
        quote,
        report,
        verifier_metadata,
    })
}
