use anyhow::Result;
use clap::Parser;
#[cfg(test)]
use std::collections::BTreeMap;
mod adapter;
mod adapter_error;
mod adapter_parse;
mod adapter_retry;
mod assigned;
mod audit;
mod cli;
mod command_runtime;
mod dispatch;
mod flush;
mod proof_adapter;
mod state;
mod workflow;

pub(crate) use adapter::*;
pub(crate) use adapter_parse::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_optional_field,
    normalized_provenance_label, normalized_provider_request_id, trim_boundary_audit_fillers,
    verify_model_output,
};
pub(crate) use adapter_retry::{
    resolve_llm_adapter_policy, resolve_tx_retry_policy, run_adapter_with_retry,
    run_llm_adapter_with_retry,
};
pub(crate) use state::*;

#[cfg(test)]
pub(crate) use adapter_parse::parse_tx_hash;

#[cfg(test)]
pub(crate) use adapter_retry::{
    backoff_delay_ms, exp_backoff_delay_ms, resolve_u32, resolve_u64, run_llm_adapter_once,
    run_llm_adapter_with_retry_inner, truncate_for_error,
};

#[cfg(test)]
pub(crate) use command_runtime::{parse_command_spec, run_command_with_timeout};

#[cfg(test)]
pub(crate) use audit::{
    audit_export_index_path, build_audit_export_index, build_provenance_fingerprint,
    detect_audit_export_format, query_audit_export_by_provenance_fingerprint,
    query_audit_export_by_task_id, render_enterprise_audit_markdown, to_enterprise_audit_export,
    validate_audit_export_index, AuditExportFormat, AuditExportIndex, EnterpriseAuditExportRecord,
    QueryAuditOutput,
};
use audit::{handle_export_audit, handle_query_audit};
use cli::Args;
use dispatch::dispatch_command;

#[cfg(test)]
mod tests;

fn main() -> Result<()> {
    let args = Args::parse();
    dispatch_command(args.cmd)
}
