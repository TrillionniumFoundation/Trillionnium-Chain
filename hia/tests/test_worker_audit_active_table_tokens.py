"""Exact table tokens from the active Rust Worker report, not the WAR1 profile."""
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_active_scope import ACTIVE_COLUMNS, active_fixture
from hia.tests.test_worker_audit_report import HEADER as WAR1_HEADER

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/worker_agent/audit_active_table_tokens.hepta"
SHORT = 0xFFFFFFFE
INVALID = 0xFFFFFFFF
SENTINEL = b"\xe1"
SCRATCH = b"\x7d" * 19
REQUEST = b"trnm-task-marker"
STATUS = b"trnm-status-marker"


def original_reference(directory):
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=10).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("Original Worker oracle requires pinned rustc")
    fixture = active_fixture()
    originals, marker, _ = fixture.rpartition(b"\nfn main() {\n")
    if not marker:
        raise ValueError("Active Worker oracle template changed")
    source = directory / "active.rs"
    source.write_bytes(originals + br"""
fn main() {
    let rows: Vec<_> = std::env::args().skip(1).map(|value| {
        EnterpriseAuditExportRecord {
            request_id: "trnm-task-marker".into(),
            task_id: value.parse().expect("u64 argument"),
            status: "trnm-status-marker".into(),
            provider_request_id: None,
            provenance_schema_version: None,
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
        }
    }).collect();
    print!("{}", render_enterprise_audit_markdown(&rows));
}
""")
    exe = directory / "active"
    subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(exe)],
                   check=True, capture_output=True, timeout=30)
    return exe


class WorkerAuditActiveTableTokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-worker-active-tokens-")
        cls.addClassCleanup(temporary.cleanup)
        cls.exe = original_reference(Path(temporary.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            native = NativeModule(SOURCE, backend=backend, byte_exports=("f0",))
            cls.addClassCleanup(native.close)
            cls.backends[backend] = native

    def oracle(self, values):
        result = subprocess.run([str(self.exe), *(str(value) for value in values)],
                                check=True, capture_output=True, timeout=20)
        self.assertEqual(result.stderr, b"")
        lines = result.stdout.splitlines(keepends=True)
        self.assertEqual(len(lines), 2 + len(values))
        return b"".join(lines[:2]), lines[2:]

    def assert_cases(self, packets):
        for backend, native in self.backends.items():
            with self.subTest(backend=backend):
                self.assertEqual(native.exports, frozenset({"f0"}))
                results = native.call_many([
                    ("f0", (packet, SENTINEL * capacity, SCRATCH))
                    for packet, capacity, _ in packets
                ])
                for result, (packet, capacity, expected) in zip(results, packets, strict=True):
                    result.require_returned()
                    restored, out, scratch = result.arguments
                    self.assertEqual(restored, packet)
                    self.assertEqual(scratch, SCRATCH)
                    if isinstance(expected, bytes):
                        self.assertEqual(result.value, len(expected))
                        self.assertEqual(out, expected + SENTINEL * (capacity - len(expected)))
                    else:
                        self.assertEqual(result.value, expected)
                        self.assertEqual(out, SENTINEL * capacity)

    def test_empty_exact_active_header_and_structural_tokens(self):
        header, _ = self.oracle([])
        data_header, rows = self.oracle([0])
        self.assertEqual(data_header, header)
        self.assertNotEqual(header, WAR1_HEADER)
        labels, divider = header.splitlines()
        self.assertEqual(labels.split(b"|")[1:-1], [b" " + x + b" " for x in ACTIVE_COLUMNS])
        self.assertEqual(divider.split(b"|")[1:-1], [b" --- "] * 18)
        self.assertEqual(len(header), 446)
        row = rows[0]
        self.assertEqual(row.count(b"|"), 19)
        prefix, anchor, suffix = row.partition(REQUEST)
        self.assertEqual(anchor, REQUEST)
        separator, anchor, _ = suffix.partition(b"0" + b" | " + STATUS)
        self.assertTrue(anchor)
        ending = row[row.rfind(b"|") - 1:]
        self.assert_cases([(b"\0", 446, header), (b"\0", 478, header),
                           (b"\1", len(prefix), prefix), (b"\2", 7, separator),
                           (b"\3", len(ending), ending)])

    def test_exact_unsigned_task_decimal_and_protected_extent(self):
        values = sorted({0, 2**63, 2**64 - 1,
                         *(10**i + delta for i in range(20) for delta in (-1, 0, 1))})
        rng = random.Random(949)
        values.extend(rng.getrandbits(64) for _ in range(48))
        _, rows = self.oracle(values)
        cases = []
        for value, row in zip(values, rows, strict=True):
            expected = row.split(b"|")[2].strip()
            packet = b"\4" + value.to_bytes(8, "little")
            cases.extend(((packet, len(expected), expected), (packet, len(expected) - 1, SHORT),
                          (packet, len(expected) + 2, expected)))
        self.assert_cases(cases)

    def test_invalid_frames_and_undersized_tokens_never_publish_partial_bytes(self):
        invalid = [b"", b"\x05", b"\xff", b"WAR1", b"\0\0", b"\1\0", b"\2\0", b"\3\0"]
        invalid.extend(b"\4" + b"\xff" * n for n in (*range(8), 9, 64))
        self.assert_cases([(packet, cap, INVALID) for packet in invalid for cap in (0, 447)]
                          + [(bytes([tag]), needed - 1, SHORT)
                             for tag, needed in enumerate((446, 2, 3, 3))])


    def test_scope_is_not_full_row_report_or_retirement(self):
        inventory = json.loads((ROOT / "config/hia-migration-v1.json").read_text())
        identity = "worker-agent/audit-active-table-tokens"
        [component] = [row for row in inventory["components"] if row["id"] == identity]
        [owner] = [row for row in inventory["legacy_packages"] if identity in row["components"]]
        self.assertIs(component["node_integration_complete"], False)
        self.assertEqual(component["state"], "native-kernel-implemented")
        self.assertEqual(owner["package"], "trnm-worker-agent")
        self.assertEqual(owner["state"], "partially-ported")
        self.assertIs(owner["retirement_accepted"], False)
