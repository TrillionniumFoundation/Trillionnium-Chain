use anyhow::Result;
use std::collections::BTreeMap;

use crate::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_optional_field,
    normalized_provenance_label,
};

use super::audit_export_types::{AuditExportIndex, EnterpriseAuditExportRecord};

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
            let normalized_status = status.to_ascii_lowercase();
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
                .map(|value| value.to_ascii_lowercase())
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
