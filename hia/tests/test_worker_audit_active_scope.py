"""Measure the active Worker Markdown ABI separately from the WAR1 baseline."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from hia.tests.test_worker_audit_report import HEADER, expected_report
from hia.tests.test_worker_audit_text import ROOT

WORKER = ROOT / "trillionnium/crates/trnm-worker-agent/src"
ACTIVE_COLUMNS = (
    b"request_id task_id status provider_request_id provenance_schema_version "
    b"provenance_fingerprint provider model adapter agent_protocol compliance_profile "
    b"reputation_label reputation_delta reputation_tier reputation_weight_bps "
    b"reputation_score_bps reputation_rank_ordinal reputation_gap_bps_from_best"
).split()


def active_block(source, signature):
    blocks = re.findall(rb"^" + re.escape(signature) + rb".*?^\}\n",
                        source, re.MULTILINE | re.DOTALL)
    if len(blocks) != 1:
        raise ValueError("Expected one active Rust audit declaration: " + str(signature))
    return blocks[0]


def active_fixture():
    main = (WORKER / "main.rs").read_bytes()
    source = (WORKER / "audit.rs").read_bytes()
    if (b"\nmod audit;\n" not in main
            or b"file.write_all(render_enterprise_audit_markdown(&exports).as_bytes())?" not in source):
        raise ValueError("Active Worker export ownership changed")
    record = active_block(source, b"pub(crate) struct EnterpriseAuditExportRecord {\n")
    # The type body stays unchanged except for field attributes that require Serde.
    record = record.replace(b"    #[serde(default)]\n", b"")
    escape = active_block(source, b"pub(crate) fn markdown_escape(value: Option<&str>) -> String {\n")
    render = active_block(source, b"pub(crate) fn render_enterprise_audit_markdown("
                          b"exports: &[EnterpriseAuditExportRecord]) -> String {\n")
    return record + escape + render + r'''
fn main() {
    let mut record = EnterpriseAuditExportRecord {
        request_id: "request|鏈".into(),
        task_id: u64::MAX,
        status: "ready\r\n".into(),
        provider_request_id: None,
        provenance_schema_version: Some(String::new()),
        provenance_fingerprint: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: None,
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    };
    let missing = render_enterprise_audit_markdown(std::slice::from_ref(&record));
    record.reputation_label = Some("a|b\r\n".into());
    record.reputation_delta = Some(i32::MIN);
    record.reputation_tier = Some(u8::MAX);
    record.reputation_weight_bps = Some(u16::MAX);
    record.reputation_score_bps = Some(i32::MAX);
    record.reputation_rank_ordinal = Some(0);
    record.reputation_gap_bps_from_best = Some(-1);
    let populated = render_enterprise_audit_markdown(&[record]);
    print!("{missing}{populated}");
}
'''.encode()


class WorkerAuditActiveScope(unittest.TestCase):
    def test_active_markdown_has_seven_typed_columns_beyond_war1(self):
        rustc = os.environ.get("RUSTC", "rustc")
        version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                                 text=True, timeout=15).stdout.split()
        self.assertEqual(version[:2], ["rustc", "1.95.0"])
        with tempfile.TemporaryDirectory(prefix="trnm-worker-active-audit-") as tmp:
            source = Path(tmp) / "audit.rs"
            source.write_bytes(active_fixture())
            binary = Path(tmp) / "active"
            subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            active = subprocess.run([str(binary)], check=True, capture_output=True, timeout=30)
        self.assertEqual(active.stderr, b"")
        original = expected_report([(2**64 - 1, ("request|鏈", "ready\r\n", None, "",
                                                 *(None,) * 6))])
        prefix = original[len(HEADER):].removesuffix(b"|\n")
        header = b"| " + b" | ".join(ACTIVE_COLUMNS) + b" |\n"
        divider = b"| " + b" | ".join([b"---"] * 18) + b" |\n"
        self.assertEqual(active.stdout, header + divider
                         + prefix + b"| - | - | - | - | - | - | - |\n"
                         + header + divider
                         + prefix + b"| a\\|b   | -2147483648 | 255 | 65535 | 2147483647 | 0 | -1 |\n")
        self.assertNotEqual(active.stdout, original + original)
