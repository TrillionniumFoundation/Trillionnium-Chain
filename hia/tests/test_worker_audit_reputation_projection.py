"""Compare the audit-only seven-field projection with the actual Worker CLI."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame
from hia.tests.test_worker_audit_select import (
    BACKENDS, ENCODER, FILL, INCLUDED, INSUFFICIENT, INVALID, build_worker,
    ingress_rows, observed_call, original_inputs,
)


PROJECTION = ROOT / "hia/src/worker_agent/audit_reputation_projection.hepta"
REPUTATION_FIELDS = (
    "reputation_label", "reputation_delta", "reputation_tier", "reputation_weight_bps",
    "reputation_score_bps", "reputation_rank_ordinal", "reputation_gap_bps_from_best",
)
RECORD = struct.Struct("<BiBHiBiB")
NULLS = (None,) * len(REPUTATION_FIELDS)


def request(delta):
    return b"WJR1" + struct.pack("<Bi", int(delta is not None), delta or 0)


def decode_output(raw):
    if raw == b"\0":
        return NULLS
    present, delta, tier, weight, score, rank, gap, length = RECORD.unpack_from(raw)
    label = raw[RECORD.size:]
    if present != 1 or len(label) != length or not label:
        raise AssertionError("Invalid native audit reputation record")
    return label.decode("ascii"), delta, tier, weight, score, rank, gap


class WorkerAuditReputationProjection(unittest.TestCase):
    def test_all_canonical_rounding_and_empty_projections(self):
        cases = (
            (3, ("accepted", 3, 3, 10000, 10000, 0, 0)),
            (-1, ("adapter_retry_exhausted", -1, 2, 6666, -3333, 1, 13333)),
            (-2, ("verifier_rejected", -2, 1, 3333, -6666, 2, 16666)),
            (-3, ("adapter_non_retriable", -3, 0, 0, -10000, 3, 20000)),
            (None, NULLS), (0, NULLS), (1, NULLS), (-4, NULLS),
            (-(1 << 31), NULLS), ((1 << 31) - 1, NULLS),
        )
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    PROJECTION, backend=backend, byte_exports=("f0",)) as native:
                for delta, expected in cases:
                    raw = request(delta)
                    length = 1 if expected == NULLS else RECORD.size + len(expected[0])
                    n, output = observed_call(native, raw, length + 5)
                    self.assertEqual(n, length)
                    self.assertEqual(output[n:], FILL * 5)
                    self.assertEqual(decode_output(output[:n]), expected)
                    self.assertEqual(observed_call(native, raw, length)[1], output[:n])
                    self.assertEqual(observed_call(native, raw, length - 1),
                                     (INSUFFICIENT, FILL * (length - 1)))

    def test_malformed_optional_envelope_preserves_output(self):
        valid = request(3)
        malformed = (b"", valid[:8], valid + b"\0", b"WJR2" + valid[4:], valid[:4] + b"\2" + valid[5:],
                     b"WJR1\x00" + struct.pack("<i", -1))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    PROJECTION, backend=backend, byte_exports=("f0",)) as native:
                for item in malformed:
                    self.assertEqual(observed_call(native, item, 64), (INVALID, FILL * 64))


def observe_original_projection(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker binary does not bind to the current original source")
    rng = random.Random(0x574A5231)
    deltas = [
        None, 3, -1, -2, -3, 0, 1, 2, 4, -4, (1 << 31) - 1, -(1 << 31), None,
        *[rng.randrange(-(1 << 31), 1 << 31) for _ in range(40)],
    ]
    journal = directory / "ingress.jsonl"
    statuses = [INCLUDED[i % len(INCLUDED)] for i in range(len(deltas))]
    rows = ingress_rows(statuses)
    for index, (row, delta) in enumerate(zip(rows, deltas, strict=True)):
        row.pop("reputation_delta", None)
        if index != 0:
            row["reputation_delta"] = delta
    journal.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
                                 for row in rows))
    journal.chmod(0o600)
    destination = directory / "original.jsonl"
    outcome = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                              "--output-file", str(destination)], cwd=directory, capture_output=True,
                             timeout=25)
    (directory / "original.stdout.raw").write_bytes(outcome.stdout)
    (directory / "original.stderr.raw").write_bytes(outcome.stderr)
    if outcome.returncode or outcome.stderr:
        raise AssertionError(f"Actual original Worker export failed: {outcome.stderr!r}")
    raw_output = destination.read_bytes()
    rows_and_lines = [(json.loads(line), line) for line in raw_output.splitlines(keepends=True)]
    identity = lambda row: (row["request_id"], row["task_id"], row["status"])
    if [identity(row) for row, _ in rows_and_lines] != [identity(row) for row in rows]:
        raise AssertionError("Original Worker failed to export the complete ordered input")
    backends = {}
    for backend in BACKENDS:
        with ExitStack() as stack:
            projection = stack.enter_context(NativeModule(
                PROJECTION, backend=backend, byte_exports=("f0",)))
            encoder = stack.enter_context(NativeModule(ENCODER, backend=backend, byte_exports=("f0",)))
            transcript = []
            complete = []
            for delta, (row, line) in zip(deltas, rows_and_lines, strict=True):
                n, wire = observed_call(projection, request(delta), 64)
                if not 0 < n <= 64 or wire[n:] != FILL * (64 - n):
                    raise AssertionError("Native audit reputation wrote outside its result")
                typed = decode_output(wire[:n])
                if typed != tuple(row[field] for field in REPUTATION_FIELDS):
                    raise AssertionError(f"Projection differs from actual Worker for {delta}")
                result = dict(row)
                result.update(zip(REPUTATION_FIELDS, typed, strict=True))
                size, output = observed_call(encoder, frame(tuple(result[key] for key in FIELDS)),
                                             len(line) + 5)
                if size != len(line) or output[:size] != line or output[size:] != FILL * 5:
                    raise AssertionError(f"Composed native WJL row differs from real export for {delta}")
                complete.append(output[:size])
                transcript.append({"delta": delta, "native_projection_hex": wire[:n].hex()})
            native = b"".join(complete)
            if native != raw_output:
                raise AssertionError("Native audit output stream differs from actual Worker")
            (directory / f"{backend}.export.jsonl").write_bytes(native)
            (directory / f"{backend}.projection.json").write_text(
                json.dumps(transcript, indent=2) + "\n")
            backends[backend] = {"projection_sha256": projection.artifact_sha256,
                                 "encoder_sha256": encoder.artifact_sha256}
    if not bound():
        raise AssertionError("Actual Worker source or binary changed during the observation")
    report = {
        "original_cli_executed": True,
        "audit_reputation_only": True,
        "other_fields_from_original_cli": True,
        "native_journal_io": False,
        "production_dispatch_changed": False,
        "rows": len(rows_and_lines),
        "original_export_sha256": sha256(raw_output).hexdigest(),
        "original_binary_sha256": build["executable_sha256"],
        "backends": backends,
    }
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="Compare actual Worker export with native audit projection.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo-target", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    target = args.cargo_target.resolve() if args.cargo_target else output / "cargo-target"
    if output.is_relative_to(ROOT) or target.is_relative_to(ROOT):
        parser.error("Observation output and Cargo target must be outside the checkout")
    output.mkdir(mode=0o700)
    binary, receipt = build_worker(output, target)
    print(json.dumps(observe_original_projection(binary, receipt, output), sort_keys=True))


if __name__ == "__main__":
    main()
