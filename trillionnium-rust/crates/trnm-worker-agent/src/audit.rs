use anyhow::{anyhow, Result};
use std::{fs, io::Write, path::PathBuf};

#[path = "audit_ops.rs"]
mod audit_ops;

#[allow(unused_imports)]
pub(crate) use self::audit_ops::{
    audit_export_index_path, build_audit_export_index, build_provenance_fingerprint,
    detect_audit_export_format, normalize_provenance_fingerprint_lookup,
    query_audit_export_by_provenance_fingerprint, query_audit_export_by_task_id,
    render_enterprise_audit_markdown, to_enterprise_audit_export, validate_audit_export_index,
    AuditExportFormat, AuditExportIndex, EnterpriseAuditExportRecord, QueryAuditOutput,
    QueryAuditRecord,
};

use crate::load_ingress_records;
pub(crate) fn handle_export_audit(ingress_file: PathBuf, output_file: PathBuf) -> Result<()> {
    let records = load_ingress_records(&ingress_file)?;
    let mut exports = Vec::new();

    for rec in &records {
        if matches!(
            rec.status.as_str(),
            "reveal_submitted" | "rejected" | "failed_submission" | "failed_adapter"
        ) {
            exports.push(to_enterprise_audit_export(rec));
        }
    }

    if let Some(parent) = output_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(&output_file)?;
    match detect_audit_export_format(&output_file) {
        AuditExportFormat::Jsonl => {
            for export in &exports {
                let line = serde_json::to_string(export)?;
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
        }
        AuditExportFormat::Markdown => {
            file.write_all(render_enterprise_audit_markdown(&exports).as_bytes())?;
        }
    }

    let index = build_audit_export_index(&exports);
    if let Some(first) = exports.first() {
        let _ = query_audit_export_by_task_id(&exports, &index, first.task_id);
    }
    let index_file = audit_export_index_path(&output_file);
    fs::write(&index_file, serde_json::to_string_pretty(&index)?)?;

    println!(
        "[agent] exported audit records={} file={} index_file={} format={:?}",
        exports.len(),
        output_file.display(),
        index_file.display(),
        detect_audit_export_format(&output_file)
    );
    Ok(())
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
        let normalized = audit_ops::normalize_provenance_fingerprint_lookup(raw.as_str())
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
