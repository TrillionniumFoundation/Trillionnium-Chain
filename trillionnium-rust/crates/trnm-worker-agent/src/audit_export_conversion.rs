use sha2::{Digest, Sha256};

use crate::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_optional_field,
    normalized_provenance_label, normalized_provider_request_id, MessageIngressRecord,
};

use super::audit_export_types::EnterpriseAuditExportRecord;

pub(crate) fn build_provenance_fingerprint(
    schema_version: Option<&str>,
    provider: Option<&str>,
    model: Option<&str>,
    adapter: Option<&str>,
    agent_protocol: Option<&str>,
    compliance_profile: Option<&str>,
) -> Option<String> {
    let schema = schema_version?;
    let has_any_provenance_label = provider.is_some()
        || model.is_some()
        || adapter.is_some()
        || agent_protocol.is_some()
        || compliance_profile.is_some();
    if !has_any_provenance_label {
        return None;
    }

    let material = format!(
        "schema={};provider={};model={};adapter={};agent_protocol={};compliance_profile={}",
        schema,
        provider.unwrap_or("-"),
        model.unwrap_or("-"),
        adapter.unwrap_or("-"),
        agent_protocol.unwrap_or("-"),
        compliance_profile.unwrap_or("-")
    );
    let mut h = Sha256::new();
    h.update(material.as_bytes());
    Some(hex::encode(h.finalize()))
}

pub(crate) fn normalized_schema_version(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let alias_key: String = normalized
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    match alias_key.as_str() {
        "llmv1" | "llm1" => Some("llm.v1".to_string()),
        "llmv2" | "llm2" => Some("llm.v2".to_string()),
        _ => None,
    }
}

pub(crate) fn to_enterprise_audit_export(
    rec: &MessageIngressRecord,
) -> EnterpriseAuditExportRecord {
    let provenance = rec.llm_provenance.as_ref();
    let schema_version = normalized_schema_version(rec.provenance_schema_version.as_deref());
    let is_v2 = schema_version.as_deref() == Some("llm.v2");

    let provider = normalized_provenance_label(provenance.and_then(|p| p.provider.as_deref()), 64);
    let model = normalized_provenance_label(provenance.and_then(|p| p.model.as_deref()), 128);
    let adapter = normalized_provenance_label(provenance.and_then(|p| p.adapter.as_deref()), 64);
    let agent_protocol = is_v2
        .then(|| normalized_agent_protocol(provenance.and_then(|p| p.agent_protocol.as_deref())))
        .flatten();
    let compliance_profile = is_v2
        .then(|| {
            normalized_compliance_profile(provenance.and_then(|p| p.compliance_profile.as_deref()))
        })
        .flatten();

    let provenance_fingerprint = build_provenance_fingerprint(
        schema_version.as_deref(),
        provider.as_deref(),
        model.as_deref(),
        adapter.as_deref(),
        agent_protocol.as_deref(),
        compliance_profile.as_deref(),
    );

    EnterpriseAuditExportRecord {
        request_id: rec.request_id.clone(),
        task_id: rec.task_id,
        status: rec.status.clone(),
        provider_request_id: normalized_provider_request_id(rec.provider_request_id.as_deref()),
        provenance_schema_version: schema_version,
        provenance_fingerprint,
        provider,
        model,
        adapter,
        agent_protocol,
        compliance_profile,
    }
}
