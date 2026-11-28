"""One native call renders the complete active Worker Markdown file contents."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame, invalid_frames
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, MAX_RECORDS,
    ingress_rows, observed_call, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_markdown_batch.hepta"
HEADER = struct.Struct("<4sI")
LENGTH = struct.Struct("<I")
ACTIVE_HEADER = ("| " + " | ".join(FIELDS) + " |\n| " + " | ".join(["---"] * 18) + " |\n").encode()


def request(rows):
    return HEADER.pack(b"WMA1", len(rows)) + b"".join(LENGTH.pack(len(row)) + row for row in rows)


class WorkerAuditMarkdownBatch(unittest.TestCase):
    def test_complete_header_rows_escapes_optional_widths_and_exact_capacity(self):
        supplied = ("a|😀\r\nb", (1 << 64) - 1, "done", "", None, None, "p", "M|N", None,
                    "a\t b", "c\r", "label", -(1 << 31), 255, 65535, (1 << 31) - 1, 0, -1)
        expected = (b"| a\\|" + "😀".encode() + b"  b | 18446744073709551615 | done |  | - | - | p"
                    b" | M\\|N | - | a\t b | c  | label | -2147483648 | 255 | 65535 | 2147483647"
                    b" | 0 | -1 |\n")
        second = ("", 0, "", *([None] * 15))
        second_expected = b"|  | 0 | " + b" | ".join([b""] + [b"-"] * 15) + b" |\n"
        raw = request([frame(supplied), frame(second), frame(supplied)])
        wanted = ACTIVE_HEADER + expected + second_expected + expected
        self.assertEqual(len(ACTIVE_HEADER), 446)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observed_call(native, raw, len(wanted)), (len(wanted), wanted))
                self.assertEqual(observed_call(native, raw, len(wanted) + 3), (len(wanted), wanted + FILL * 3))
                self.assertEqual(observed_call(native, raw, len(wanted) - 1),
                                 (INSUFFICIENT, FILL * (len(wanted) - 1)))
                self.assertEqual(observed_call(native, request([]), 446), (446, ACTIVE_HEADER))
                self.assertEqual(observed_call(native, request([]), 445), (INSUFFICIENT, FILL * 445))

    def test_invalid_late_typed_row_does_not_publish_even_header(self):
        good = frame(("local", 9, "rejected", *([None] * 15)))
        raw = request([good, good])
        bad = (b"", raw[:7], raw[:-1], raw + b"x", b"WMA2" + raw[4:],
               HEADER.pack(b"WMA1", MAX_RECORDS + 1),
               raw[:8] + b"\xff" * 4 + raw[12:],
               *(request([good, broken]) for broken in invalid_frames(good)))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                for payload in bad:
                    self.assertEqual(observed_call(native, payload, 0), (INVALID, b""))
                    self.assertEqual(observed_call(native, payload, 2048), (INVALID, FILL * 2048))


def scenarios():
    rows = ingress_rows(["waiting", "rejected", "Rejected", "failed_adapter",
                         "reveal_submitted", "failed_submission", "waiting", "failed_adapter",
                         "rejected", "rejected "])
    for i, row in enumerate(rows):
        # All identifiers and labels are fixed synthetic fixture values, not
        # production records or assertions about the original identity owner.
        row["request_id"] = f"fixture|{i}\\l\r\n🧾"
        row.pop("provider_request_id", None)
        row.pop("llm_provenance", None)
        row.pop("provenance_schema_version", None)
        row["reputation_delta"] = (None, 3, -1, -2, -3, -1)[i % 6]
    rows[1]["task_id"] = (1 << 64) - 1
    rows[7].update(llm_provenance={"provider": "Demo|Co", "model": "v2", "adapter": "Local"},
                   provenance_schema_version="llm.v1")
    rows[8]["request_id"] = ""
    rows.extend([dict(rows[1]), dict(rows[7])])
    return {"mixed": rows, "excluded": ingress_rows(["waiting", "Rejected"]), "empty": []}


def observe_original_markdown(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker binary/source binding differs")
    observed = {}
    with ExitStack() as stack:
        native = {backend: stack.enter_context(NativeModule(
            NATIVE, backend=backend, byte_exports=("f0",))) for backend in BACKENDS}
        for case, rows in scenarios().items():
            root = directory / case
            root.mkdir(mode=0o700)
            journal = root / "synthetic-ingress.jsonl"
            journal.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode()
                                         for row in rows))
            journal.chmod(0o600)
            same_input = sha256(journal.read_bytes()).hexdigest()
            for ext in ("jsonl", "md"):
                dest = root / f"original.{ext}"
                result = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                                         "--output-file", str(dest)], cwd=root, capture_output=True,
                                        timeout=25)
                (root / f"original.{ext}.stdout.raw").write_bytes(result.stdout)
                (root / f"original.{ext}.stderr.raw").write_bytes(result.stderr)
                if result.returncode or result.stderr or sha256(journal.read_bytes()).hexdigest() != same_input:
                    raise AssertionError(f"Original export failed or mutated its input: {case} {ext}")
            # The first untouched CLI invocation is only the ordered typed
            # source. Neither Python nor the JSONL encoder prepares Markdown.
            typed_rows = [json.loads(line) for line in (root / "original.jsonl").read_bytes().splitlines()]
            stream = request([frame(tuple(row[key] for key in FIELDS)) for row in typed_rows])
            (root / "ordered-typed-input.raw").write_bytes(stream)
            expected = (root / "original.md").read_bytes()
            for backend, module in native.items():
                n, output = observed_call(module, stream, len(expected) + 5)
                if n != len(expected) or output != expected + FILL * 5:
                    raise AssertionError(f"Complete active Markdown byte mismatch: {case} {backend}")
                (root / f"{backend}.md").write_bytes(output[:n])
            observed[case] = {"ingress_rows": len(rows), "selected_typed_rows": len(typed_rows),
                              "markdown_bytes": len(expected), "sha256": sha256(expected).hexdigest()}
    if not bound():
        raise AssertionError("Original Worker binary/source changed during proof")
    result = {"original_binary_sha256": build["executable_sha256"], "original_cli_executed": True,
              "original_jsonl_supplies_ordered_typed_rows": True, "host_supplies_markdown_bytes": False,
              "native_index_or_file_publication": False, "production_dispatch_changed": False,
              "backends": {name: module.artifact_sha256 for name, module in native.items()},
              "scenarios": observed}
    (directory / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-binary", type=Path, required=True)
    parser.add_argument("--original-build-receipt", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error("Store private proof outside the checkout")
    output.mkdir(mode=0o700)
    result = observe_original_markdown(args.original_binary.resolve(strict=True),
                                       json.loads(args.original_build_receipt.read_bytes()), output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
