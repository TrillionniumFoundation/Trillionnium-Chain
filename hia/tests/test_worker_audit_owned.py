"""Call the named Worker ELF entry, including an independent original CLI run."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.platform.worker_audit.build import (
    BACKENDS, ENTRY, MAX_EXTENT, build, fresh_directory,
)
from hia.tests import native_support
from hia.tests.test_worker_audit_jsonl_batch import (
    ingress_rows, observe_original_batch, project_request, request, typed,
)
from hia.tests.test_worker_audit_select import FILL, INSUFFICIENT, INVALID


class OwnedBinding:
    """Transport exact private artifact bytes to the existing sealed test child."""
    def __init__(self, path, backend):
        self.library, self.receipt = build(path, backend)
        self.artifact_sha256 = self.receipt["artifact_sha256"]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def call(self, raw, capacity, reserved=b""):
        initial = [raw, FILL * capacity, reserved]
        arguments = [{"type": typ, "bytes": base64.b64encode(blob).decode("ascii")}
                     for typ, blob in zip(("readbuf", "mutbuf", "mutbuf"), initial, strict=True)]
        request = {"library": str(self.library), "sha256": self.artifact_sha256, "cpu_seconds": 10,
                   "cases": [{"function": ENTRY, "arguments": arguments,
                              "returns": ["u32"], "byte_abi": True}]}
        out = subprocess.run([sys.executable, "-I", "-S", "-B", native_support.__file__, "--worker"],
                             input=json.dumps(request), capture_output=True, text=True, timeout=15)
        if out.returncode or out.stderr:
            raise AssertionError(f"Named native invocation did not return: {out.returncode} {out.stderr!r}")
        observation = json.loads(out.stdout)
        if (observation["artifact_sha256"] != self.artifact_sha256
                or observation["host_compiler_modules_loaded"]):
            raise AssertionError("Native child loaded different bytes or a compiler")
        (case,) = observation["cases"]
        if case["function"] != ENTRY:
            raise AssertionError("Child did not call the public symbol")
        input_after, output, reserve_after = [
            base64.b64decode(arg["bytes"], validate=True) for arg in case["arguments"]]
        if input_after != raw or reserve_after != reserved or len(output) != capacity:
            raise AssertionError("Named audit entry changed an unowned buffer or output extent")
        return case["abi_status"], case["value"], output


def invoke(artifact, raw, capacity):
    abi, result, output = artifact.call(raw, capacity)
    if abi:
        raise AssertionError("Valid named audit buffers refused by the outer ABI")
    return result, output


class WorkerAuditOwnedLibrary(unittest.TestCase):
    def test_named_binary_surface_success_caps_and_atomic_refusal(self):
        good = project_request([], display=True)
        record = typed(ingress_rows(["rejected"])[0], project=True, display=True)
        positive = project_request([(record, 3)], display=True)
        demand = (1 << 20)
        with tempfile.TemporaryDirectory(prefix="trnm-worker-owned-test-") as temp:
            for backend in BACKENDS:
                with self.subTest(backend=backend):
                    owner = OwnedBinding(Path(temp) / backend, backend)
                    self.assertEqual(owner.receipt["dynamic"]["dynamic_exports"], [ENTRY])
                    expected_imports = [] if backend == "selfhost" else ["abort"]
                    self.assertEqual(owner.receipt["dynamic"]["unresolved_imports"], expected_imports)
                    original = owner.library.read_bytes()
                    with self.assertRaises(FileExistsError):
                        build(owner.library.parent, backend)
                    self.assertEqual(owner.library.read_bytes(), original)
                    if backend == "selfhost":
                        self.assertTrue(owner.receipt["linked_text_equals_relocatable_text"])
                    self.assertEqual(owner.call(good, 4), (0, 0, FILL * 4))
                    abi, written, complete = owner.call(positive, 1024)
                    self.assertEqual(abi, 0)
                    self.assertGreater(written, 0)
                    self.assertEqual(complete[written:], FILL * (1024 - written))
                    self.assertEqual(json.loads(complete[:written])["reputation_label"], "accepted")
                    self.assertEqual(owner.call(positive, written), (0, written, complete[:written]))
                    self.assertEqual(owner.call(positive, written - 1),
                                     (0, INSUFFICIENT, FILL * (written - 1)))
                    for invalid in (request([]), project_request([]), positive[:-1], b""):
                        self.assertEqual(owner.call(invalid, 1024), (0, INVALID, FILL * 1024))
                    self.assertEqual(owner.call(good, 4, b"a"), (0, INVALID, FILL * 4))
                    self.assertEqual(demand, MAX_EXTENT)
                    self.assertEqual(owner.call(good, demand), (0, 0, FILL * demand))
                    status, error, filled = owner.call(good, demand + 1)
                    if backend == "direct":
                        self.assertEqual(status, 1)  # Exact pinned foreign buffer extent status.
                    else:
                        self.assertEqual((status, error), (0, INSUFFICIENT))
                    self.assertEqual(filled, FILL * (demand + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-binary", type=Path, required=True)
    parser.add_argument("--original-build-receipt", type=Path, required=True)
    args = parser.parse_args()
    output = fresh_directory(args.output)
    reports = {}

    def owned(backend):
        owner = OwnedBinding(output / backend, backend)
        reports[backend] = owner.receipt
        return owner

    result = observe_original_batch(args.original_binary.resolve(strict=True),
                                    json.loads(args.original_build_receipt.read_bytes()), output,
                                    project=True, display=True, open_native=owned, invoke=invoke)
    for backend, build_receipt in reports.items():
        if result["backends"][backend] != build_receipt["artifact_sha256"]:
            raise AssertionError("Genuine Rust CLI comparison used a different library")
    report = {**result, "named_symbol_physically_called": ENTRY, "candidate_only": True,
              "runtime_has_no_filesystem_or_network_api": True}
    (output / "owned-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
