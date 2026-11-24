"""Project only the original Worker audit display labels; compare genuine CLI bytes."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame
from hia.tests.test_worker_audit_select import (
    BACKENDS, ENCODER, FILL, INCLUDED, INSUFFICIENT, INVALID, SCRATCH, build_worker,
    ingress_rows, original_inputs,
)


NATIVE = ROOT / "hia/src/worker_agent/audit_display_labels.hepta"
LABELS = ("provenance_schema_version", "provider", "model", "adapter")
SPACE = tuple(chr(n) for n in (9, 10, 11, 12, 13, 32, 0x85, 0xA0, 0x1680,
                              *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000))


def request(kind, value):
    return b"WJP1" + bytes((kind, int(value is not None))) + (value or "").encode("utf-8")


def decode(raw):
    if raw == b"\0":
        return None
    if len(raw) < 2 or raw[0] != 1:
        raise AssertionError("Invalid native display label option")
    return raw[1:].decode("ascii")


def observe_many(module, cases):
    for start in range(0, len(cases), 20):
        chunk = cases[start:start + 20]
        results = module.call_many([("f0", [wire, FILL * capacity, SCRATCH])
                                    for wire, capacity in chunk])
        for (wire, _), result in zip(chunk, results, strict=True):
            result.require_returned()
            source, emitted, scratch = result.arguments
            if source != wire or scratch != SCRATCH:
                raise AssertionError("Audit display operation modified source or scratch")
            yield result.value, emitted


class WorkerAuditDisplayLabels(unittest.TestCase):
    def test_exact_display_controls_and_no_partial_output(self):
        cases = [
            (0, None, None), (0, "", None), (0, " LLM.v1 ", "llm.v1"),
            (0, "LLM2", "llm.v2"), (0, "l/🧾l_m\0v.2", "llm.v2"),
            (0, "LLM.v10", None), (0, "llm", None), (0, "LLM.v3", None),
            (0, "ＬＬＭ-v2", None), (1, None, None), (1, "", None),
            (1, " a B  c! ", "a B  c!"), (1, "a\0b", None),
            (1, "a\u00a0b", None), (1, "B\u200b", None), (1, "a\x7fb", None),
            (1, "p" * 64, "p" * 64), (1, "p" * 65, None),
            (2, "m" * 128, "m" * 128), (2, "m" * 129, None),
            (3, "a" * 64, "a" * 64), (3, "a" * 65, None),
            *[(1, s + "Keep Case !" + s, "Keep Case !") for s in SPACE],
            (3, "".join(SPACE), None),
        ]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as module:
                inputs, expected_results = [], []
                for kind, value, expected in cases:
                    result = b"\0" if expected is None else b"\x01" + expected.encode("ascii")
                    n = len(result)
                    wire = request(kind, value)
                    inputs += [(wire, n + 3), (wire, n), (wire, n - 1)]
                    expected_results += [(n, result + FILL * 3), (n, result),
                                         (INSUFFICIENT, FILL * (n - 1))]
                self.assertEqual(list(observe_many(module, inputs)), expected_results)

    def test_invalid_frame_and_utf8_are_distinct_from_null(self):
        controls = (b"", b"WJP1\x01", b"WJP2\x01\x01A", b"WJP1\x04\x01A",
                    b"WJP1\x02\x02A", b"WJP1\x01\x00A", b"WJP1\x00\x01llmv2\xff",
                    b"WJP1\x01\x01\xc3")
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as module:
                self.assertEqual(list(observe_many(module, [(control, 11) for control in controls])),
                                 [(INVALID, FILL * 11)] * len(controls))


def source_rows():
    rows = [
        (None, None, None, None), ("LLM.v1", "Case Provider", "Model 4", "Adapter-1"),
        (" LLM / v 2 ", "Ｐ", "é", "a\tB"),
        ("llm1", "p" * 64, "m" * 128, "a" * 64),
        ("llm2", "p" * 65, "m" * 129, "a" * 65),
        ("llmv3", "a\u00a0b", "a\x7fb", "a\0b"),
        ("l-🧾l-M-v_1", "a\u2028b", "a\u200bb", "a\u061cb"),
        ("llmv10", "p\u200B", "\ufeffm", "a\u2060"),
        ("ＬＬＭＶ２", "", "", ""),
        ("llmv2\0", "P!  q", "m@Model", "Adapter?!"),
        ("", "\0 P", "M\0", "A \0"),
        ("llm", "\t", "\u00a0", "\u3000"),
        *[(s + "LLM.v2" + s, s + "P" + s, s + "Model Value" + s, s + "A" + s)
          for s in SPACE],
        ("!" * 4096 + "LLM.v2", " " * 4096 + "P", "x" * 4096, "A" + " " * 4096),
    ]
    statuses = [INCLUDED[n % len(INCLUDED)] for n in range(len(rows))]
    messages = ingress_rows(statuses)
    for idx, (message, row) in enumerate(zip(messages, rows, strict=True)):
        message.pop("provenance_schema_version", None)
        message.pop("llm_provenance", None)
        if idx:
            message["provenance_schema_version"] = row[0]
            message["llm_provenance"] = dict(zip(LABELS[1:], row[1:], strict=True))
    return rows, messages


def observe_original_labels(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker binary does not bind to exact current source and lock")
    typed_inputs, messages = source_rows()
    journal = directory / "ingress.jsonl"
    journal.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
                                 for row in messages))
    journal.chmod(0o600)
    dest = directory / "original.jsonl"
    observed = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                                "--output-file", str(dest)], cwd=directory, capture_output=True,
                              timeout=25)
    (directory / "original.stdout.raw").write_bytes(observed.stdout)
    (directory / "original.stderr.raw").write_bytes(observed.stderr)
    if observed.returncode or observed.stderr:
        raise AssertionError(f"Actual original Worker did not export: {observed.stderr!r}")
    original = dest.read_bytes()
    lines = original.splitlines(keepends=True)
    records = [json.loads(line) for line in lines]
    identity = lambda row: (row["request_id"], row["task_id"], row["status"])
    if [identity(row) for row in records] != [identity(row) for row in messages]:
        raise AssertionError("Original Worker did not retain the exact ordered input rows")
    results = {}
    for backend in BACKENDS:
        with ExitStack() as stack:
            native, encoder = [stack.enter_context(NativeModule(
                source, backend=backend, byte_exports=("f0",))) for source in (NATIVE, ENCODER)]
            complete, transcript, row_requests = [], [], []
            label_requests = [(request(kind, value), 132)
                              for values in typed_inputs for kind, value in enumerate(values)]
            labels = iter(observe_many(native, label_requests))
            for values, row, line in zip(typed_inputs, records, lines, strict=True):
                fields = []
                for _ in LABELS:
                    n, returned = next(labels)
                    if not 0 < n <= 129 or returned[n:] != FILL * (132 - n):
                        raise AssertionError("Native audit option wrote beyond its measured bytes")
                    fields.append(decode(returned[:n]))
                if fields != [row[key] for key in LABELS]:
                    raise AssertionError(f"Audit display labels differ from original Worker: {values!r}")
                output_row = dict(row)
                output_row.update(zip(LABELS, fields, strict=True))
                row_requests.append((frame(tuple(output_row[k] for k in FIELDS)), len(line) + 5))
                transcript.append(fields)
            if next(labels, None) is not None:
                raise AssertionError("Native display returned an extra row")
            for (n, emitted), line in zip(observe_many(encoder, row_requests), lines, strict=True):
                if n != len(line) or emitted[:n] != line or emitted[n:] != FILL * 5:
                    raise AssertionError("WJL replay using the four native display fields differs")
                complete.append(emitted[:n])
            stream = b"".join(complete)
            if stream != original:
                raise AssertionError("Composed WJL output does not equal actual original bytes")
            (directory / f"{backend}.jsonl").write_bytes(stream)
            (directory / f"{backend}.display.json").write_text(json.dumps(transcript, indent=2) + "\n")
            results[backend] = {"labels_sha256": native.artifact_sha256,
                                "encoder_sha256": encoder.artifact_sha256}
    if not bound():
        raise AssertionError("Actual Worker source, lock or binary changed")
    report = {
        "original_cli_executed": True, "display_fields": LABELS,
        "other_fields_from_original_cli": True,
        "native_fingerprint_or_protocol_policy": False, "production_dispatch_changed": False,
        "rows": len(lines), "original_export_sha256": sha256(original).hexdigest(),
        "original_binary_sha256": build["executable_sha256"], "backends": results,
    }
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="Compare native display labels to actual local export-audit.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo-target", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    target = args.cargo_target.resolve() if args.cargo_target else output / "cargo-target"
    if output.is_relative_to(ROOT) or target.is_relative_to(ROOT):
        parser.error("Observation output and Cargo target must be outside the checkout")
    output.mkdir(mode=0o700)
    binary, receipt = build_worker(output, target)
    print(json.dumps(observe_original_labels(binary, receipt, output), sort_keys=True))


if __name__ == "__main__":
    main()
