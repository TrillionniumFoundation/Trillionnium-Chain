"""Active Rust Worker Markdown numerical tail versus native HIA WAR2."""
import os
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_active_scope import active_fixture
from hia.tests.test_worker_audit_text import INVALID, ROOT, SCRATCH, SENTINEL, SHORT

SOURCE = ROOT / "hia/src/worker_agent/audit_reputation_fragment.hepta"
MAX_OUTPUT = 62
OFFSETS = ((5, 4), (9, 1), (10, 2), (12, 4), (16, 1), (17, 4))
MIN = -(2**31)
MAX = 2**31 - 1


def frame(values):
    mask = sum(1 << index for index, value in enumerate(values) if value is not None)
    payload = struct.pack("<iBHiBi", *(0 if value is None else value for value in values))
    return b"WAR2" + bytes([mask]) + payload


def expected_tail(values):
    return b"".join(b" | " + (b"-" if value is None else str(value).encode("ascii"))
                    for value in values)


def samples():
    for presence in range(64):
        for populated in ((0,) * 6, (MIN, 255, 65535, MIN, 255, MIN),
                          (MAX, 1, 10, -1, 10, 1)):
            yield tuple(value if presence & (1 << index) else None
                        for index, value in enumerate(populated))
    # Each u8 value in both the tier and rank position, without masking.
    for byte in range(256):
        yield (None, byte, None, None, byte ^ 173, None)
    for signed_field in (0, 3, 5):
        for n in (MIN, MIN + 1, MAX - 1, MAX, -1, 0, 1):
            values = [None] * 6
            values[signed_field] = n
            yield tuple(values)
    for exponent in range(10):
        for digit_boundary in range(10**exponent - 1, 10**exponent + 2):
            yield (digit_boundary, 99, min(digit_boundary, 65535),
                   -digit_boundary, 100, -digit_boundary)
    for n in (9, 10, 99, 100, 999, 1000, 9999, 10000, 60000, 65534, 65535):
        yield (0, 0, n, None, 0, None)
    rng = random.Random(0x57415232)
    for _ in range(416):
        spans = [(MIN, MAX), (0, 255), (0, 65535), (MIN, MAX), (0, 255), (MIN, MAX)]
        yield tuple(None if rng.randrange(5) == 0 else rng.randint(lo, hi)
                    for lo, hi in spans)


# Only the fixture entry point is replaced. It passes typed records through the
# unchanged active renderer and extracts the substring after a unique label.
RUST_DRIVER = r'''
use std::io::{self, BufRead};

const MARKER: &str = "fixture-numeric-tail-start";
fn option<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value == "none" {
        None
    } else {
        Some(value.parse().ok().expect("typed numeric field"))
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("fixture line");
        let values: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(values.len(), 6);
        let record = EnterpriseAuditExportRecord {
            request_id: "positive-control|行".into(),
            task_id: u64::MAX,
            status: "ok\r\n".into(),
            provider_request_id: None,
            provenance_schema_version: Some(String::new()),
            provenance_fingerprint: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: None,
            reputation_label: Some(MARKER.into()),
            reputation_delta: option::<i32>(values[0]),
            reputation_tier: option::<u8>(values[1]),
            reputation_weight_bps: option::<u16>(values[2]),
            reputation_score_bps: option::<i32>(values[3]),
            reputation_rank_ordinal: option::<u8>(values[4]),
            reputation_gap_bps_from_best: option::<i32>(values[5]),
        };
        let report = render_enterprise_audit_markdown(&[record]);
        let (_, tail) = report.split_once(MARKER).expect("unique label marker");
        assert_eq!(tail.lines().count(), 1);
        println!("{}", tail.strip_suffix(" |\n").expect("row closing syntax"));
    }
}
'''.encode()


def active_rust_tails(rows):
    prefix, marker, _driver = active_fixture().partition(b"\nfn main() {\n")
    if not marker:
        raise ValueError("Expected original active Rust declarations plus fixture entry")
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    if version[:2] != ["rustc", toolchain]:
        raise ValueError(f"Expected pinned rustc {toolchain}, got {version[:2]}")
    lines = [" ".join("none" if item is None else str(item) for item in values)
             for values in rows]
    with tempfile.TemporaryDirectory(prefix="trnm-worker-reputation-rust-") as tmp:
        source = Path(tmp) / "audit.rs"
        source.write_bytes(prefix + RUST_DRIVER)
        binary = Path(tmp) / "active"
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(binary)],
                       check=True, capture_output=True, timeout=30)
        active = subprocess.run([str(binary)], input=("\n".join(lines) + "\n").encode(),
                                check=True, capture_output=True, timeout=30)
    if active.stderr:
        raise ValueError(active.stderr)
    return active.stdout.splitlines()


class WorkerAuditReputationFragment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_cases(self, cases):
        for offset in range(0, len(cases), 32):
            batch = cases[offset:offset + 32]
            answers = self.native.call_many([
                ("f0", [raw, SENTINEL * capacity, SCRATCH])
                for raw, capacity, _, _ in batch
            ])
            for answer, (raw, capacity, status, output) in zip(answers, batch, strict=True):
                answer.require_returned()
                self.assertEqual(answer.value, status, raw.hex())
                self.assertEqual(answer.arguments,
                                 [raw, output + SENTINEL * (capacity - len(output)), SCRATCH])

    def test_contiguous_numeric_tail_matches_active_rust(self):
        rows = list(samples())
        tails = active_rust_tails(rows)
        self.assertEqual(tails, [expected_tail(row) for row in rows])
        self.assertEqual(max(map(len, tails)), MAX_OUTPUT)
        self.check_cases([(frame(values), MAX_OUTPUT + 7, len(output), output)
                          for values, output in zip(rows, tails, strict=True)])

    def test_maximum_and_minimum_capacity_with_atomic_refusal(self):
        rows = [(None,) * 6, (0,) * 6, (MIN, 255, 65535, MIN, 255, MIN),
                (MAX, 5, None, -1, None, 0)]
        cases = []
        for row in rows:
            raw, out = frame(row), expected_tail(row)
            cases.extend((raw, capacity, SHORT, b"") for capacity in range(len(out)))
            cases.extend((raw, capacity, len(out), out)
                         for capacity in (len(out), len(out) + 1))
        self.check_cases(cases)

    def test_noncanonical_frames_never_modify_caller_buffers(self):
        raw = frame((0,) * 6)
        absent = frame((None,) * 6)
        invalid = [raw[:i] for i in range(len(raw))]
        invalid += [raw + b"\0", b"WAR1" + raw[4:], b"\0" * len(raw)]
        for high_mask in range(64, 256):
            invalid.append(raw[:4] + bytes([high_mask]) + raw[5:])
        # Nonzero data in every absent field, including its high byte. Rejection
        # must beat capacity status, even when the late field is malformed.
        for index, (offset, width) in enumerate(OFFSETS):
            for byte_offset in range(offset, offset + width):
                bad = bytearray(absent)
                bad[4] = (1 << index) - 1
                bad[byte_offset] = 0x80
                invalid.append(bytes(bad))
        self.check_cases([(bad, capacity, INVALID, b"")
                          for bad in invalid for capacity in (0, MAX_OUTPUT)])
