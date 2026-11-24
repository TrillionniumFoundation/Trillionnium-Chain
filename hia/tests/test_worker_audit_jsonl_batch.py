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
from hia.tests.test_worker_audit_display_labels import LABELS, source_rows
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame, invalid_frames
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, MAX_RECORDS,
    build_worker, ingress_rows, observed_call, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_jsonl_batch.hepta"
HEADER = struct.Struct("<4sI")
LENGTH = struct.Struct("<I")
DELTA = struct.Struct("<Bi")


def request(frames):
    return HEADER.pack(b"WJB1", len(frames)) + b"".join(
        LENGTH.pack(len(data)) + data for data in frames)


def project_request(frames, *, display=False):
    return HEADER.pack(b"WJB3" if display else b"WJB2", len(frames)) + b"".join(
        LENGTH.pack(len(row)) + row + DELTA.pack(int(delta is not None), delta or 0)
        for row, delta in frames)


def typed(source, retained=None, *, project=False, display=False):
    """Transfer typed facts only. Do not decide order, inclusion, or output bytes."""
    carried = FIELDS[:-7] if project else FIELDS
    values = dict(retained or {})
    values.update((key, source[key]) for key in ("request_id", "task_id", "status"))
    if display:
        values["provenance_schema_version"] = source.get("provenance_schema_version")
        labels = source.get("llm_provenance") or {}
        values.update((key, labels.get(key)) for key in LABELS[1:])
    return frame(tuple(values.get(key) for key in carried) + ((None,) * 7 if project else ()))


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
        bad = [b"", raw[:7], b"WJB4" + raw[4:], raw[:-1], raw + b"x",
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


    def test_v2_matches_canonical_reputation_inside_the_single_call(self):
        canonical = {
            3: ("accepted", 3, 3, 10000, 10000, 0, 0),
            -1: ("adapter_retry_exhausted", -1, 2, 6666, -3333, 1, 13333),
            -2: ("verifier_rejected", -2, 1, 3333, -6666, 2, 16666),
            -3: ("adapter_non_retriable", -3, 0, 0, -10000, 3, 20000),
        }
        nulls = (None,) * 7
        supply = (3, -1, -2, -3, None, 0, 1, -4, -(1 << 31), (1 << 31) - 1)
        rows = ingress_rows([INCLUDED[i % len(INCLUDED)] for i in range(len(supply))])
        excluded = ingress_rows(["REJECTED"])[0]
        typed_source = [(typed(row, project=True), delta) for row, delta in zip(rows, supply, strict=True)]
        typed_source.insert(2, (typed(excluded, project=True), 3))
        wire = project_request(typed_source)
        expected = b"".join((json.dumps(
            dict(zip(FIELDS, (row["request_id"], row["task_id"], row["status"],
                              *((None,) * 8), *canonical.get(delta, nulls)), strict=True)),
            ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            for row, delta in zip(rows, supply, strict=True))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observe(native, wire, len(expected) + 5),
                                 (len(expected), expected + FILL * 5))
                self.assertEqual(observe(native, wire, len(expected) - 1),
                                 (INSUFFICIENT, FILL * (len(expected) - 1)))
                self.assertEqual(observe(native, project_request([]), 9), (0, FILL * 9))

    def test_v2_rejects_noncanonical_or_truncated_reputation_atomically(self):
        selected, excluded = ingress_rows(["rejected", "waiting"])
        prefix, last = (typed(row, project=True) for row in (selected, excluded))
        valid = project_request([(prefix, 3), (last, None)])
        mark = lambda row, at: row[:at] + b"\x01" + row[at + 1:]
        supplied_numbers = [mark(last, at) for at in (16, 24, 32, 40, 48, 56)]
        candidates = (
            valid[:-1], valid + b"x", valid[:-5] + b"\2" + valid[-4:],
            valid[:-1] + b"\xff", request([prefix, last]).replace(b"WJB1", b"WJB2", 1),
            *(project_request([(prefix, 3), (bad, None)])
              for bad in (mark(last, 5), mark(last, 104), *supplied_numbers)),
        )
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                for raw in candidates:
                    self.assertEqual(observe(native, raw, 0), (INVALID, b""))
                    self.assertEqual(observe(native, raw, 1024), (INVALID, FILL * 1024))


    def test_v3_raw_spans_use_rust_display_rules_in_existing_column_order(self):
        rows = ingress_rows(["rejected", "failed_adapter", "waiting"])
        rows[0]["provenance_schema_version"] = " .LLM/✦V_2 "
        rows[0]["llm_provenance"] = {"provider": '\u0085 Fancy "\\ \u3000',
                                     "model": "m" * 128, "adapter": "bad\tlabel"}
        rows[1]["provenance_schema_version"] = "LLM.v10"
        rows[1]["llm_provenance"] = {"provider": "x" * 65, "model": " m ",
                                     "adapter": "\u2002Queue?\u2009"}
        rows[2]["llm_provenance"] = {"provider": "never output"}
        raw = project_request([(typed(row, project=True, display=True), None) for row in rows],
                              display=True)
        projected = [("llm.v2", 'Fancy "\\', "m" * 128, None),
                     (None, None, "m", "Queue?")]
        expected = b""
        for row, values in zip(rows[:2], projected, strict=True):
            object_fields = dict.fromkeys(FIELDS)
            object_fields.update(zip(LABELS, values, strict=True))
            object_fields.update((key, row[key]) for key in ("request_id", "task_id", "status"))
            expected += (json.dumps(object_fields, ensure_ascii=False, separators=(",", ":"))
                         + "\n").encode()
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observe(native, raw, len(expected)), (len(expected), expected))
                self.assertEqual(observe(native, raw, len(expected) + 7),
                                 (len(expected), expected + FILL * 7))
                self.assertEqual(observe(native, raw, len(expected) - 1),
                                 (INSUFFICIENT, FILL * (len(expected) - 1)))
                self.assertEqual(observe(native, project_request([], display=True), 0), (0, b""))

    def test_v3_invalid_raw_utf8_in_last_excluded_row_preserves_output(self):
        selected, excluded = ingress_rows(["rejected", "waiting"])
        excluded["llm_provenance"] = {"provider": "a", "model": "b"}
        first, last = [typed(row, project=True, display=True) for row in (selected, excluded)]
        self.assertTrue(last.endswith(b"ab"))
        invalid = (last[:-1] + b"\xff", last[:-2] + b"\xc3\xa9")
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                for row in invalid:
                    raw = project_request([(first, 3), (row, None)], display=True)
                    self.assertEqual(observe(native, raw, 0), (INVALID, b""))
                    self.assertEqual(observe(native, raw, 2048), (INVALID, FILL * 2048))


def identity(row):
    return (row["request_id"], row["task_id"], row["status"])


def cli_scenarios(*, project=False, display=False):
    # Same genuine display labels, including valid retained provenance/hash facts,
    # plus interleaved statuses and repeated identity, with distinct raw
    # reputation in WJB2 to catch any grouping by identity.
    _, corpus = source_rows()
    combined = []
    for i, row in enumerate(corpus):
        if display:
            row.pop("provider_request_id", None)
        row["reputation_delta"] = (3, -1, -2, -3, None, 0, -(1 << 31))[i % 7]
        if i % 4 == 0:
            ignored = ingress_rows([("Rejected", "waiting", "rejected ", "✦")[(i // 4) % 4]])[0]
            ignored["request_id"] = f"ignored-{i}\x1f"
            combined.append(ignored)
        combined.append(row)
    repeated = dict(ingress_rows(["rejected"])[0], request_id="exact repeated")
    combined += [repeated, dict(repeated, reputation_delta=-3) if project else dict(repeated)]
    return {"mixed": combined,
            "excluded": ingress_rows(["waiting", "", "failed_adapter ", "REJECTED", "✦"]),
            "empty": []}


def observe_original_batch(binary, build, directory, *, project=False, display=False):
    if display and not project:
        raise ValueError("WJB3 requires the raw reputation suffix as well as display fields")
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker binary does not bind to current exact source and lock")
    report = {}
    with ExitStack() as stack:
        modules = {backend: stack.enter_context(NativeModule(
            NATIVE, backend=backend, byte_exports=("f0",))) for backend in BACKENDS}
        for name, records in cli_scenarios(project=project, display=display).items():
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
                retained_fields = FIELDS[3:-7] if project else FIELDS[3:]
                other = {field: row[field] for field in retained_fields
                         if not display or field not in LABELS}
                if key in retained and retained[key] != other:
                    raise AssertionError("Duplicate fixture has ambiguous retained non-native values")
                retained[key] = other
            # Every typed input row is transferred, including those the genuine
            # Worker didn't export. The lookup supplies optional values only.
            if project:
                raw = project_request([
                    (typed(row, retained.get(identity(row)), project=True, display=display),
                     row.get("reputation_delta")) for row in records], display=display)
            else:
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
        "native_raw_reputation_projection": project,
        "retained_reputation_fields_from_actual_cli": not project,
        "native_raw_display_normalization": display,
        "retained_display_fields_from_actual_cli": not display,
        "native_io_index_or_stdout": False, "production_dispatch_changed": False,
        "backends": {name: module.artifact_sha256 for name, module in modules.items()},
        "scenarios": report,
    }
    (directory / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--project-reputation", action="store_true", help="Observe the raw WJB2 input")
    mode.add_argument("--project-display", action="store_true", help="Observe the raw WJB3 input")
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
    print(json.dumps(observe_original_batch(binary, receipt, output,
                                            project=args.project_reputation or args.project_display,
                                            display=args.project_display), sort_keys=True))


if __name__ == "__main__":
    main()
