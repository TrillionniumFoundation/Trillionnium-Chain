"""One native call selects and serializes a complete typed Worker audit batch."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_display_labels import source_rows
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame, invalid_frames
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, MAX_RECORDS,
    build_worker, ingress_rows, observed_call, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_jsonl_batch.hepta"
HEADER = struct.Struct("<4sI")
LENGTH = struct.Struct("<I")


def request(frames):
    return HEADER.pack(b"WJB1", len(frames)) + b"".join(
        LENGTH.pack(len(data)) + data for data in frames)


def typed(source, retained=None):
    """Transfer typed facts only. Do not decide order, inclusion, or output bytes."""
    return frame(tuple(source[key] if key in ("request_id", "task_id", "status")
                       else (retained or {}).get(key) for key in FIELDS))


def observe(native, raw, length):
    return observed_call(native, raw, length)


class WorkerAuditJsonlBatch(unittest.TestCase):
    def test_one_call_selects_encodes_and_preserves_order_duplicate_identity(self):
        statuses = ("waiting", "reveal_submitted", "Rejected", "rejected", "rejected ",
                    "failed_submission", "failed_adapter", " failed_adapter", "reveal_submitted")
        rows = ingress_rows(statuses)
        rows[-1].update({k: rows[1][k] for k in ("request_id", "task_id", "status")})
        rows[3].update(request_id='r"\\\t\x1f😀', task_id=(1 << 64) - 1)
        optional = {3: {"provider_request_id": "", "reputation_score_bps": -(1 << 31),
                        "reputation_rank_ordinal": 0, "reputation_weight_bps": 65535}}
        raw = request([typed(row, optional.get(i)) for i, row in enumerate(rows)])
        def expected(idx):
            return (json.dumps(
                {k: rows[idx][k] if k in ("request_id", "task_id", "status")
                 else optional.get(idx, {}).get(k) for k in FIELDS},
                ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        # Fixed positive roster, independently encoded; neither this nor the
        # real-CLI comparison selects the framed input on the host.
        out = b"".join(expected(i) for i in (1, 3, 5, 6, 8))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observe(native, raw, len(out)), (len(out), out))
                self.assertEqual(observe(native, raw, len(out) + 9), (len(out), out + FILL * 9))
                self.assertEqual(observe(native, raw, len(out) - 1),
                                 (INSUFFICIENT, FILL * (len(out) - 1)))
                for case in (request([]), request([typed(ingress_rows(["REJECTED"])[0])])):
                    self.assertEqual(observe(native, case, 0), (0, b""))
                    self.assertEqual(observe(native, case, 3), (0, FILL * 3))

    def test_late_error_is_atomic_even_on_unselected_row(self):
        good = typed(ingress_rows(["rejected"])[0])
        excluded = typed(ingress_rows(["waiting"])[0])
        bad_utf8_excluded = excluded[:-1] + b"\xff"
        raw = request([good, excluded])
        bad = [b"", raw[:7], b"WJB2" + raw[4:], raw[:-1], raw + b"x",
               HEADER.pack(b"WJB1", MAX_RECORDS + 1), HEADER.pack(b"WJB1", MAX_RECORDS),
               raw[:8] + b"\xff" * 4 + raw[12:], request([good, bad_utf8_excluded])]
        bad.extend(request([good, row]) for row in invalid_frames(good))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                for case in bad:
                    # Validates the whole frame before reporting even zero capacity.
                    self.assertEqual(observe(native, case, 0), (INVALID, b""))
                    self.assertEqual(observe(native, case, 571), (INVALID, FILL * 571))


def identity(row):
    return (row["request_id"], row["task_id"], row["status"])


def cli_scenarios():
    # Same genuine display labels, including valid retained provenance/hash facts,
    # plus interleaved statuses and a repeated exact identity (no optional facts).
    _, corpus = source_rows()
    combined = []
    for i, row in enumerate(corpus):
        row["reputation_delta"] = (3, -1, -2, -3, None, 0, -(1 << 31))[i % 7]
        if i % 4 == 0:
            ignored = ingress_rows([("Rejected", "waiting", "rejected ", "✦")[(i // 4) % 4]])[0]
            ignored["request_id"] = f"ignored-{i}\x1f"
            combined.append(ignored)
        combined.append(row)
    repeated = dict(ingress_rows(["rejected"])[0], request_id="exact repeated")
    combined += [repeated, dict(repeated)]
    return {"mixed": combined,
            "excluded": ingress_rows(["waiting", "", "failed_adapter ", "REJECTED", "✦"]),
            "empty": []}


def observe_original_batch(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker binary does not bind to current exact source and lock")
    report = {}
    with ExitStack() as stack:
        modules = {backend: stack.enter_context(NativeModule(
            NATIVE, backend=backend, byte_exports=("f0",))) for backend in BACKENDS}
        for name, records in cli_scenarios().items():
            cwd = directory / name
            cwd.mkdir(mode=0o700)
            source, dest = cwd / "ingress.jsonl", cwd / "original.jsonl"
            source.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode()
                                        for row in records))
            source.chmod(0o600)
            cli = subprocess.run([str(binary), "export-audit", "--ingress-file", str(source),
                                  "--output-file", str(dest)], cwd=cwd, capture_output=True,
                                 timeout=25)
            (cwd / "cli.stdout.raw").write_bytes(cli.stdout)
            (cwd / "cli.stderr.raw").write_bytes(cli.stderr)
            if cli.returncode or cli.stderr:
                raise AssertionError(f"Original CLI failure: {cli.stderr!r}")
            original = dest.read_bytes()
            retained = {}
            for line in original.splitlines():
                row = json.loads(line)
                key = identity(row)
                if key in retained and retained[key] != row:
                    raise AssertionError("Duplicate fixture has ambiguous producer-projected values")
                retained[key] = row
            # Every typed input row is transferred, including those the genuine
            # Worker didn't export. The lookup supplies optional values only.
            raw = request([typed(row, retained.get(identity(row))) for row in records])
            (cwd / "native.request.raw").write_bytes(raw)
            for backend, native in modules.items():
                out_len, emitted = observe(native, raw, len(original) + 7)
                out = emitted[:out_len]
                if out_len != len(original) or out != original or emitted[out_len:] != FILL * 7:
                    raise AssertionError(f"Whole-batch byte difference: {name} {backend}")
                (cwd / f"{backend}.jsonl").write_bytes(out)
                native_count = out.count(b"\n")
                # CLI owns stdout paths and index. Match only the selected
                # record count from the actual stdout to native JSONL lines.
                if not cli.stdout.startswith(f"[agent] exported audit records={native_count} ".encode()):
                    raise AssertionError(f"Actual stdout disagrees with native selected row count: {name}")
            report[name] = {"inputs": len(records), "exports": original.count(b"\n"),
                            "original_and_native_sha256": sha256(original).hexdigest()}
    if not bound():
        raise AssertionError("Original Worker binding changed during proof")
    result = {
        "original_cli_executed": True, "original_binary_sha256": build["executable_sha256"],
        "one_native_call_per_scenario_and_backend": True,
        "retained_optional_fields_from_actual_cli": True,
        "native_io_index_or_stdout": False, "production_dispatch_changed": False,
        "backends": {name: module.artifact_sha256 for name, module in modules.items()},
        "scenarios": report,
    }
    (directory / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo-target", type=Path)
    parser.add_argument("--original-binary", type=Path)
    parser.add_argument("--original-build-receipt", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    target = args.cargo_target.resolve() if args.cargo_target else output / "cargo-target"
    if output.is_relative_to(ROOT) or target.is_relative_to(ROOT):
        parser.error("Observation output and Cargo target must be outside the checkout")
    if bool(args.original_binary) != bool(args.original_build_receipt):
        parser.error("Supply the original executable and build receipt together")
    output.mkdir(mode=0o700)
    if args.original_binary:
        binary = args.original_binary.resolve()
        receipt = json.loads(args.original_build_receipt.read_bytes())
    else:
        binary, receipt = build_worker(output, target)
    print(json.dumps(observe_original_batch(binary, receipt, output), sort_keys=True))


if __name__ == "__main__":
    main()
