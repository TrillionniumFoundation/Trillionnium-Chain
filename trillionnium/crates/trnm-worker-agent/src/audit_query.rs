use anyhow::{anyhow, Result};
use serde::Serialize;
use std::{fs, path::PathBuf};

use crate::{normalized_optional_field, normalized_provenance_label, trim_boundary_audit_fillers};

use super::audit_export::{
    audit_export_index_path, detect_audit_export_format, validate_audit_export_index,
    AuditExportFormat, AuditExportIndex, EnterpriseAuditExportRecord,
};

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

pub(crate) fn handle_query_audit(
    output_file: PathBuf,
    task_id: Option<u64>,
    provenance_fingerprint: Option<String>,
) -> Result<()> {
    if task_id.is_some() == provenance_fingerprint.is_some() {
        return Err(anyhow!(
            "query-audit requires exactly one filter: --task-id or --provenance-fingerprint"
        ));
    }

    let index_file = audit_export_index_path(&output_file);
    if !index_file.exists() {
        return Err(anyhow!(
            "query-audit missing index file: {}",
            index_file.display()
        ));
    }

    if detect_audit_export_format(&output_file) != AuditExportFormat::Jsonl {
        return Err(anyhow!(
            "query-audit only supports JSONL audit exports: {}",
            output_file.display()
        ));
    }

    let mut exports = Vec::new();
    for line in fs::read_to_string(&output_file)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        exports.push(serde_json::from_str::<EnterpriseAuditExportRecord>(line)?);
    }
    let index: AuditExportIndex = serde_json::from_str(&fs::read_to_string(&index_file)?)?;
    validate_audit_export_index(&index, exports.len())?;

    let (hit_indexes, records, normalized_fp) = if let Some(task_id) = task_id {
        let key = task_id.to_string();
        let hits = index.by_task_id.get(&key).cloned().unwrap_or_default();
        let rows: Vec<EnterpriseAuditExportRecord> =
            query_audit_export_by_task_id(&exports, &index, task_id)
                .into_iter()
                .cloned()
                .collect();
        (hits, rows, None)
    } else {
        let raw = provenance_fingerprint.expect("checked above");
        let normalized = normalize_provenance_fingerprint_lookup(raw.as_str())
            .ok_or_else(|| anyhow!("invalid provenance fingerprint filter"))?;
        let hits = index
            .by_provenance_fingerprint
            .get(&normalized)
            .cloned()
            .unwrap_or_default();
        let rows: Vec<EnterpriseAuditExportRecord> =
            query_audit_export_by_provenance_fingerprint(&exports, &index, &normalized)
                .into_iter()
                .cloned()
                .collect();
        (hits, rows, Some(normalized))
    };

    let out = QueryAuditOutput {
        hit_indexes,
        records: records.into_iter().map(QueryAuditRecord::from).collect(),
        provenance_fingerprint: normalized_fp,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
