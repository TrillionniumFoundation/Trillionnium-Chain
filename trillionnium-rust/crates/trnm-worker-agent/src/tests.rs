use super::*;
use std::{env, fs, path::Path, time::Duration};
use trnm_types::RequestStatus;

use crate::proof_adapter::{build_proof_adapter, StandardProofAdapter};
use anyhow::anyhow;

#[cfg(test)]
#[path = "tests_status_parse.rs"]
mod tests_status_parse;

#[cfg(test)]
#[path = "tests_adapter_path.rs"]
mod tests_adapter_path;

#[cfg(test)]
#[path = "tests_audit_export.rs"]
mod tests_audit_export;

#[cfg(test)]
#[path = "tests_audit_query.rs"]
mod tests_audit_query;

#[cfg(test)]
#[path = "tests_audit_provenance_fields.rs"]
mod tests_audit_provenance_fields;

#[cfg(test)]
#[path = "tests_compliance_profile.rs"]
mod tests_compliance_profile;
