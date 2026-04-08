use anyhow::Result;
use std::path::PathBuf;

use crate::{handle_export_audit, handle_query_audit};

pub(crate) fn dispatch_export_audit(ingress_file: PathBuf, output_file: PathBuf) -> Result<()> {
    handle_export_audit(ingress_file, output_file)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn dispatch_query_audit(
    output_file: PathBuf,
    task_id: Option<u64>,
    provenance_fingerprint: Option<String>,
) -> Result<()> {
    handle_query_audit(output_file, task_id, provenance_fingerprint)
}
