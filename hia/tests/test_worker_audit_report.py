"""Full self-hosted Worker Agent audit Markdown versus original Rust."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_text import (
    ADAPTER, INVALID, ORIGINAL, ORIGINAL_SHA256, ROOT, SCRATCH, SENTINEL, SHORT,
    golden, wire,
)

SOURCE = ROOT / "hia/src/worker_agent/audit_report.hepta"
MAGIC = b"WAR1"
HEADER = (
    b"| request_id | task_id | status | provider_request_id | provenance_schema_version"
    b" | provenance_fingerprint | provider | model | adapter | agent_protocol | compliance_profile |\n"
    b"| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
)
ROW = (0, ("", "ready", None, "", "hash |", "provider", "model\r\n", "adapter",
           "MCP 😀", None))


def encode_row(task_id, values):
    return struct.pack("<Q", task_id) + b"".join(
        b"\xff" * 4 if value is None else wire(value.encode()) for value in values)


def report(rows):
    return MAGIC + b"".join(encode_row(task, values) for task, values in rows)


def expected_report(rows):
    chunks = [HEADER]
    for task, values in rows:
        encoded = [golden(value) for value in values]
        encoded.insert(1, str(task).encode())
        chunks.append(b"| " + b" | ".join(encoded) + b" |\n")
    return b"".join(chunks)


def corpus():
    yield []
    yield [ROW]
    # Boundaries for every decimal place with blank and missing cells.
    values = ("\r\n", "|\\|", "唯一", "", None, "A", "B", "C", "D", "E")
    edges = [0, 1, 0xFFFFFFFF, 0x100000000, 2**63 - 1, 2**63, 2**64 - 1]
    edges += [10**power + delta for power in range(1, 20) for delta in (-1, 0, 1)]
    yield [(value, values) for value in edges]
    yield [(2**64 - 1, ("|" * 32768, "", None, "é", "e\u0301", "链", "😀", "", "\0", "\t"))]
    yield [(7, ROW[1])] * 257
    rng = random.Random(0x57415231)
    alphabet = "\r\n|\\A\0é\u0301链😀\u2028\ufeff\U0010ffff"
    for _ in range(240):
        rows = []
        for _ in range(rng.randrange(1, 13)):
            task = rng.getrandbits(64)
            cells = tuple(
                None if field >= 2 and rng.randrange(3) == 0
                else "".join(rng.choices(alphabet, k=rng.randrange(45)))
                for field in range(10)
            )
            rows.append((task, cells))
        yield rows


class WorkerAuditReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_native(self, cases):
        for offset in range(0, len(cases), 32):
            batch = cases[offset:offset + 32]
            answers = self.native.call_many([
                ("f0", [raw, SENTINEL * capacity, SCRATCH])
                for raw, capacity, _, _ in batch
            ])
            for answer, (raw, capacity, status, output) in zip(answers, batch, strict=True):
                answer.require_returned()
                self.assertEqual(answer.value, status, raw[:32].hex())
                self.assertEqual(answer.arguments,
                                 [raw, output + SENTINEL * (capacity - len(output)), SCRATCH])

    def test_exact_original_full_report(self):
        before = ORIGINAL.read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(), ORIGINAL_SHA256)
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        rustc = os.environ.get("RUSTC", "rustc")
        version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                                 text=True, timeout=15).stdout.split()
        self.assertEqual(version[:2], ["rustc", toolchain])
        rows = list(corpus())
        frames = [report(table) for table in rows]
        expected = [expected_report(table) for table in rows]
        with tempfile.TemporaryDirectory(prefix="trnm-worker-report-rust-") as tmp:
            binary = Path(tmp) / "original"
            subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(ADAPTER), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            rust = subprocess.run([str(binary), "--report"], input=b"".join(map(wire, frames)),
                                  check=True, capture_output=True, timeout=30)
        self.assertEqual(rust.stderr, b"")
        self.assertEqual(ORIGINAL.read_bytes(), before)
        self.assertEqual(rust.stdout, b"".join(map(wire, expected)))
        self.check_native([(raw, len(out) + 17, len(out), out)
                           for raw, out in zip(frames, expected, strict=True)])

    def test_exact_fit_and_short_output(self):
        choose = [[], [ROW], [ROW] * 8, [(2**64 - 1, ("|" * 2048, "", *(None,) * 8))]]
        cases = []
        for rows in choose:
            raw, out = report(rows), expected_report(rows)
            cases += [(raw, len(out), len(out), out),
                      (raw, len(out) - 1, SHORT, b""), (raw, 0, SHORT, b"")]
        self.check_native(cases)

    def test_malformed_late_failure_has_no_partial_output(self):
        row = encode_row(*ROW)
        invalid = [b"", b"WAR", b"WAR2", MAGIC + b"\0"]
        invalid += [MAGIC + row + row[:n] for n in range(1, len(row))]
        for required in (0, 1):
            task, fields = ROW
            bad_fields = fields[:required] + (None,) + fields[required + 1:]
            invalid.append(MAGIC + row + encode_row(task, bad_fields))
        invalid += [MAGIC + row + struct.pack("<QI", 1, n) + b"\0" * 36
                    for n in (256, 2**31, 0xFFFFFFFE)]
        self.check_native([(raw, cap, INVALID, b"") for raw in invalid for cap in (0, 1111)])

    def test_max_input_reaches_atomic_capacity_check(self):
        maximum = 1 << 20
        payload_bytes = maximum - len(MAGIC) - 48
        raw = report([(2**64 - 1, ("|" * payload_bytes, "", *(None,) * 8))])
        self.assertEqual(len(raw), maximum)
        self.check_native([(raw, 17, SHORT, b"")])


if __name__ == "__main__":
    unittest.main()
