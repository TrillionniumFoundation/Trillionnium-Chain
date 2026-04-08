use super::*;
#[test]
fn export_audit_detects_markdown_output_extension() {
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.md")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.markdown")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.jsonl")),
        AuditExportFormat::Jsonl
    );
}
