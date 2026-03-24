use anyhow::Result;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::load_ingress_records;

use super::super::{
    audit_query::query_audit_export_by_task_id, audit_render::render_enterprise_audit_markdown,
};
use super::{
    audit_export_conversion::to_enterprise_audit_export,
    audit_export_index::build_audit_export_index, audit_export_types::EnterpriseAuditExportRecord,
};

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

pub(crate) fn audit_export_index_path(output_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.index.json", output_file.display()))
}

pub(crate) fn handle_export_audit(ingress_file: PathBuf, output_file: PathBuf) -> Result<()> {
    let records = load_ingress_records(&ingress_file)?;
    let mut exports: Vec<EnterpriseAuditExportRecord> = Vec::new();

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
