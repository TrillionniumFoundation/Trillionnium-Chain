use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, path::PathBuf};

use crate::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_optional_field,
    normalized_provenance_label, normalized_provider_request_id, trim_boundary_audit_fillers,
    MessageIngressRecord,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnterpriseAuditExportRecord {
    pub(crate) request_id: String,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) provider_request_id: Option<String>,
    pub(crate) provenance_schema_version: Option<String>,
    pub(crate) provenance_fingerprint: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) adapter: Option<String>,
    pub(crate) agent_protocol: Option<String>,
    pub(crate) compliance_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditExportIndex {
    pub(crate) version: u8,
    pub(crate) total_records: usize,
    pub(crate) by_task_id: BTreeMap<String, Vec<usize>>,
    pub(crate) by_status: BTreeMap<String, Vec<usize>>,
    pub(crate) by_status_phase: BTreeMap<String, Vec<usize>>,
    pub(crate) by_provider: BTreeMap<String, Vec<usize>>,
    pub(crate) by_model: BTreeMap<String, Vec<usize>>,
    pub(crate) by_agent_protocol: BTreeMap<String, Vec<usize>>,
    pub(crate) by_compliance_profile: BTreeMap<String, Vec<usize>>,
    pub(crate) by_provenance_fingerprint: BTreeMap<String, Vec<usize>>,
}

pub(crate) fn audit_status_phase(status: &str) -> &'static str {
    match status {
        "completed" | "slashed" | "rejected" | "cancelled" => "terminal",
        _ => "active",
    }
}

pub(crate) fn build_audit_export_index(
    exports: &[EnterpriseAuditExportRecord],
) -> AuditExportIndex {
    let mut by_task_id = BTreeMap::<String, Vec<usize>>::new();
    let mut by_status = BTreeMap::<String, Vec<usize>>::new();
    let mut by_status_phase = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provider = BTreeMap::<String, Vec<usize>>::new();
    let mut by_model = BTreeMap::<String, Vec<usize>>::new();
    let mut by_agent_protocol = BTreeMap::<String, Vec<usize>>::new();
    let mut by_compliance_profile = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provenance_fingerprint = BTreeMap::<String, Vec<usize>>::new();

    for (idx, rec) in exports.iter().enumerate() {
        by_task_id
            .entry(rec.task_id.to_string())
            .or_default()
            .push(idx);

        if let Some(status) = normalized_optional_field(Some(rec.status.as_str())) {
            let normalized_status: String = status.to_ascii_lowercase();
            by_status
                .entry(normalized_status.clone())
                .or_default()
                .push(idx);
            by_status_phase
                .entry(audit_status_phase(&normalized_status).to_string())
                .or_default()
                .push(idx);
        }

        if let Some(provider) = normalized_optional_field(rec.provider.as_deref()) {
            by_provider.entry(provider).or_default().push(idx);
        }

        if let Some(model) = normalized_optional_field(rec.model.as_deref()) {
            by_model.entry(model).or_default().push(idx);
        }

        if let Some(agent_protocol) = normalized_agent_protocol(rec.agent_protocol.as_deref()) {
            by_agent_protocol
                .entry(agent_protocol)
                .or_default()
                .push(idx);
        }

        if let Some(compliance_profile) =
            normalized_compliance_profile(rec.compliance_profile.as_deref())
        {
            by_compliance_profile
                .entry(compliance_profile)
                .or_default()
                .push(idx);
        }

        if let Some(fingerprint) =
            normalized_provenance_label(rec.provenance_fingerprint.as_deref(), 128)
                .map(|value: String| value.to_ascii_lowercase())
        {
            by_provenance_fingerprint
                .entry(fingerprint)
                .or_default()
                .push(idx);
        }
    }

    AuditExportIndex {
        version: 1,
        total_records: exports.len(),
        by_task_id,
        by_status,
        by_status_phase,
        by_provider,
        by_model,
        by_agent_protocol,
        by_compliance_profile,
        by_provenance_fingerprint,
    }
}

pub(crate) fn query_audit_export_by_task_id<'a>(
    exports: &'a [EnterpriseAuditExportRecord],
    index: &AuditExportIndex,
    task_id: u64,
) -> Vec<&'a EnterpriseAuditExportRecord> {
    index
        .by_task_id
        .get(&task_id.to_string())
        .into_iter()
        .flat_map(|rows| rows.iter().filter_map(|idx| exports.get(*idx)))
        .collect()
}

pub(crate) fn normalize_provenance_fingerprint_lookup(value: &str) -> Option<String> {
    let mut normalized =
        trim_boundary_audit_fillers(normalized_optional_field(Some(value))?.as_str()).to_string();

    for _ in 0..16 {
        let bytes = normalized.as_bytes();
        let mut peeled = false;

        if bytes.len() >= 2
            && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
                || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
                || (bytes[0] == b'`' && bytes[bytes.len() - 1] == b'`'))
        {
            normalized = normalized[1..normalized.len() - 1].trim().to_string();
            peeled = true;
        } else if bytes.len() >= 4
            && bytes[0] == b'\\'
            && bytes[bytes.len() - 2] == b'\\'
            && ((bytes[1] == b'\'' && bytes[bytes.len() - 1] == b'\'')
                || (bytes[1] == b'"' && bytes[bytes.len() - 1] == b'"')
                || (bytes[1] == b'`' && bytes[bytes.len() - 1] == b'`'))
        {
            normalized = normalized[2..normalized.len() - 2].trim().to_string();
            peeled = true;
        }

        if peeled {
            normalized = trim_boundary_audit_fillers(normalized.as_str()).to_string();
            if normalized.is_empty() {
                return None;
            }
            continue;
        }

        break;
    }
    normalized_provenance_label(Some(normalized.as_str()), 128).map(|v| v.to_ascii_lowercase())
}

pub(crate) fn query_audit_export_by_provenance_fingerprint<'a>(
    exports: &'a [EnterpriseAuditExportRecord],
    index: &AuditExportIndex,
    provenance_fingerprint: &str,
) -> Vec<&'a EnterpriseAuditExportRecord> {
    let Some(normalized) = normalize_provenance_fingerprint_lookup(provenance_fingerprint) else {
        return Vec::new();
    };
    index
        .by_provenance_fingerprint
        .get(&normalized)
        .into_iter()
        .flat_map(|rows| rows.iter().filter_map(|idx| exports.get(*idx)))
        .collect()
}

#[derive(Debug, Serialize)]
pub(crate) struct QueryAuditRecord {
    #[serde(flatten)]
    pub(crate) record: EnterpriseAuditExportRecord,
    pub(crate) proof_type: Option<String>,
    pub(crate) settlement_status: String,
    pub(crate) timestamp_unix_ms: Option<u128>,
}

impl From<EnterpriseAuditExportRecord> for QueryAuditRecord {
    fn from(record: EnterpriseAuditExportRecord) -> Self {
        let settlement_status = record.status.clone();
        Self {
            record,
            proof_type: None,
            settlement_status,
            timestamp_unix_ms: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct QueryAuditOutput {
    pub(crate) hit_indexes: Vec<usize>,
    pub(crate) records: Vec<QueryAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provenance_fingerprint: Option<String>,
}

pub(crate) fn audit_export_index_path(output_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.index.json", output_file.display()))
}

pub(crate) fn validate_audit_export_index(
    index: &AuditExportIndex,
    exports_len: usize,
) -> Result<()> {
    if index.version != 1 {
        anyhow::bail!(
            "unsupported audit index version={} (expected=1)",
            index.version
        );
    }
    if index.total_records != exports_len {
        anyhow::bail!(
            "audit index total_records mismatch: index={} exports={}",
            index.total_records,
            exports_len
        );
    }

    for (label, offsets) in [
        ("by_task_id", &index.by_task_id),
        ("by_status", &index.by_status),
        ("by_status_phase", &index.by_status_phase),
        ("by_provider", &index.by_provider),
        ("by_model", &index.by_model),
        ("by_agent_protocol", &index.by_agent_protocol),
        ("by_compliance_profile", &index.by_compliance_profile),
        (
            "by_provenance_fingerprint",
            &index.by_provenance_fingerprint,
        ),
    ] {
        for (key, rows) in offsets {
            for idx in rows {
                if *idx >= index.total_records {
                    anyhow::bail!(
                        "audit index offset out of bounds: map={} key={} idx={} total_records={}",
                        label,
                        key,
                        idx,
                        index.total_records
                    );
                }
            }
        }
    }

    Ok(())
}

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
        compliance_profile.unwrap_or("-"),
    );
    let mut h = Sha256::new();
    h.update(material.as_bytes());
    Some(hex::encode(h.finalize()))
}

pub(crate) fn normalized_schema_version(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let alias_key: String = normalized
        .chars()
        .filter(|c: &char| c.is_ascii_alphanumeric())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditExportFormat {
    Jsonl,
    Markdown,
}

pub(crate) fn detect_audit_export_format(path: &Path) -> AuditExportFormat {
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("markdown"))
        .unwrap_or(false)
    {
        AuditExportFormat::Markdown
    } else {
        AuditExportFormat::Jsonl
    }
}

pub(crate) fn markdown_escape(value: Option<&str>) -> String {
    value
        .unwrap_or("-")
        .replace(['\r', '\n'], " ")
        .replace('|', "\\|")
}

pub(crate) fn render_enterprise_audit_markdown(exports: &[EnterpriseAuditExportRecord]) -> String {
    let mut out = String::from(
        "| request_id | task_id | status | provider_request_id | provenance_schema_version | provenance_fingerprint | provider | model | adapter | agent_protocol | compliance_profile |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

    for rec in exports {
        let row = format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_escape(Some(rec.request_id.as_str())),
            rec.task_id,
            markdown_escape(Some(rec.status.as_str())),
            markdown_escape(rec.provider_request_id.as_deref()),
            markdown_escape(rec.provenance_schema_version.as_deref()),
            markdown_escape(rec.provenance_fingerprint.as_deref()),
            markdown_escape(rec.provider.as_deref()),
            markdown_escape(rec.model.as_deref()),
            markdown_escape(rec.adapter.as_deref()),
            markdown_escape(rec.agent_protocol.as_deref()),
            markdown_escape(rec.compliance_profile.as_deref()),
        );
        out.push_str(&row);
    }

    out
}
