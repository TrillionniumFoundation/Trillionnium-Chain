use super::audit_export::EnterpriseAuditExportRecord;

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
