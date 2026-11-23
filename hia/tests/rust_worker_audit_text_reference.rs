// Exercise the unchanged original rendering module. The fixture struct supplies
// types only; the imported cell and report functions own all output bytes.
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
    let mode = std::env::args().nth(1);
    let mut out = io::stdout().lock();
    while !remaining.is_empty() {
        let (length, body) = remaining.split_at(4);
        let size = usize::try_from(u32::from_le_bytes(length.try_into().unwrap())).unwrap();
        let (request, rest) = body.split_at(size);
        let result = if mode.as_deref() == Some("--report") {
            render_report(request)
        } else {
            let value = match request {
                [0] => None,
                [1, body @ ..] => Some(std::str::from_utf8(body).unwrap()),
                _ => panic!("invalid oracle fixture envelope"),
            };
            audit_render::markdown_escape(value)
        };
        let size = u32::try_from(result.len()).unwrap();
        out.write_all(&size.to_le_bytes())?;
        out.write_all(result.as_bytes())?;
        remaining = rest;
    }
    out.flush()
}

fn render_report(request: &[u8]) -> String {
    use audit_export::EnterpriseAuditExportRecord;
    let mut remaining = request
        .strip_prefix(b"WAR1")
        .expect("report fixture marker");
    let mut records = Vec::new();
    while !remaining.is_empty() {
        let (task, rest) = remaining.split_at(8);
        remaining = rest;
        let task_id = u64::from_le_bytes(task.try_into().unwrap());
        let mut cell = || {
            let (len, rest) = remaining.split_at(4);
            let size = u32::from_le_bytes(len.try_into().unwrap());
            if size == u32::MAX {
                remaining = rest;
                None
            } else {
                let (value, rest) = rest.split_at(usize::try_from(size).unwrap());
                remaining = rest;
                Some(String::from_utf8(value.to_vec()).unwrap())
            }
        };
        records.push(EnterpriseAuditExportRecord {
            task_id,
            request_id: cell().unwrap(),
            status: cell().unwrap(),
            provider_request_id: cell(),
            provenance_schema_version: cell(),
            provenance_fingerprint: cell(),
            provider: cell(),
            model: cell(),
            adapter: cell(),
            agent_protocol: cell(),
            compliance_profile: cell(),
        });
    }
    audit_render::render_enterprise_audit_markdown(&records)
}
