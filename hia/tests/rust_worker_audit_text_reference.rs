// Exercise the unchanged original rendering module. The fixture struct supplies
// types only; the one imported cell formatter owns all expected output bytes.
#![allow(dead_code)]

mod audit_export {
    pub struct EnterpriseAuditExportRecord {
        pub request_id: String,
        pub task_id: u64,
        pub status: String,
        pub provider_request_id: Option<String>,
        pub provenance_schema_version: Option<String>,
        pub provenance_fingerprint: Option<String>,
        pub provider: Option<String>,
        pub model: Option<String>,
        pub adapter: Option<String>,
        pub agent_protocol: Option<String>,
        pub compliance_profile: Option<String>,
    }
}

#[path = "../../trillionnium/crates/trnm-worker-agent/src/audit_render.rs"]
mod audit_render;

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut encoded = Vec::new();
    io::stdin().read_to_end(&mut encoded)?;
    let mut remaining = encoded.as_slice();
    let mut out = io::stdout().lock();
    while !remaining.is_empty() {
        let (length, body) = remaining.split_at(4);
        let size = usize::try_from(u32::from_le_bytes(length.try_into().unwrap())).unwrap();
        let (request, rest) = body.split_at(size);
        let value = match request {
            [0] => None,
            [1, body @ ..] => Some(std::str::from_utf8(body).unwrap()),
            _ => panic!("invalid oracle fixture envelope"),
        };
        let result = audit_render::markdown_escape(value);
        let size = u32::try_from(result.len()).unwrap();
        out.write_all(&size.to_le_bytes())?;
        out.write_all(result.as_bytes())?;
        remaining = rest;
    }
    out.flush()
}
