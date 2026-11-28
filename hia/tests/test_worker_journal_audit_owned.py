"""Exercise the versioned raw journal ELF with a genuinely linked Rust caller."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.platform.worker_audit.build import TOOLS, fresh_directory, run
from hia.platform.worker_journal_audit.build import BACKENDS, ENTRY, LIBRARY, build
from hia.tests.test_worker_audit_export_transaction import NAMES, artifacts
from hia.tests.test_worker_audit_select import INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_journal_audit_dto import ROOT, declared_input, make, raw
from hia.tests.test_worker_journal_audit_export import SCRATCH_BYTES, scenarios, snapshot
from hia.tests.test_worker_journal_line_frame import cli_artifacts

CALLER = ROOT / "hia/tests/rust_worker_journal_audit_caller.rs"
RUST_VERSION = "rustc 1.95.0 "
RUST_REVISION = "59807616e1fa2540724bfbac14d7976d7e4a3860"
EXPECTED_SCRATCH = 102_400


def invoke(exe, data, output_capacity, scratch_capacity):
    obs = subprocess.run([str(exe), str(output_capacity), str(scratch_capacity)], input=data,
                         capture_output=True, check=True, env={"LC_ALL": "C"}, timeout=15)
    if obs.stderr:
        raise AssertionError(obs.stderr)
    status, result = struct.unpack_from("<II", obs.stdout)
    return status, result, obs.stdout[8:]


def link_caller(directory, backend, rustc):
    library, proof = build(directory, backend)
    if (proof["dynamic"]["dynamic_exports"] != [ENTRY]
            or proof["dynamic"]["unresolved_imports"] != ([] if backend == "selfhost" else ["abort"])):
        raise AssertionError("Expected allowlisted ELF boundary")
    receipt = (proof["artifact_sha256"], sha256(CALLER.read_bytes()).hexdigest())
    compiler = run(rustc, "--version", "--verbose").decode("ascii")
    if (not compiler.startswith(RUST_VERSION) or f"commit-hash: {RUST_REVISION}" not in compiler
            or "\nhost: x86_64-unknown-linux-gnu\n" not in compiler):
        raise AssertionError("Offline Rust caller must use the pinned Linux x86-64 version")
    exe = directory / "offline-rust-caller"
    run(rustc, CALLER, "--edition=2024", "-C", "opt-level=2", "-C", "strip=symbols",
        "-C", "link-arg=-Wl,-rpath,$ORIGIN", "-L", f"native={directory}",
        "-l", "dylib=trnm_worker_journal_audit_v1", "-o", exe)
    dynamic = run(TOOLS["readelf"], "-dW", exe).decode("ascii")
    undefined = run(TOOLS["readelf"], "--dyn-syms", "--wide", exe).decode("ascii")
    if (f"Shared library: [{LIBRARY}]" not in dynamic
            or "Library runpath: [$ORIGIN]" not in dynamic
            or not any(" UND " in row and row.split()[-1] == ENTRY
                       for row in undefined.splitlines() if row.split())
            or (sha256(library.read_bytes()).hexdigest(), sha256(CALLER.read_bytes()).hexdigest()) != receipt):
        raise AssertionError("Rust caller did not bind the measured sole named symbol/library")
    return exe, {"library": proof, "rustc": compiler, "rustc_sha256": sha256(rustc.read_bytes()).hexdigest(),
                 "caller_source_sha256": receipt[1], "caller_elf_sha256": sha256(exe.read_bytes()).hexdigest()}


def direct_refusal(path):
    from hepta.object_symbols import inspect_object_symbols

    try:
        build(path, "direct")
    except ValueError as error:
        if not str(error).startswith("Unexpected compiled Worker object surface: "):
            raise
    else:
        raise AssertionError("Direct WQX1 must not silently weaken the fixed import gate")
    before = inspect_object_symbols((path / "raw.o").read_bytes(), "ELF64", 62)
    observed = sorted(before["undefined"])
    if observed != ["abort", "memcpy", "memmove", "memset"] or (path / LIBRARY).exists():
        raise AssertionError("Direct WQX1 object/closed-ABI disposition changed")
    return {"artifact_published": False, "object_undefined_symbols": observed}



def reject_checks(exe, good, size, late):
    if SCRATCH_BYTES != EXPECTED_SCRATCH:
        raise AssertionError("Existing WQX scratch bound changed")
    for data, cap, scratch, code in (
        (late, size, SCRATCH_BYTES + 13, INVALID),
        (good[:-1], size, SCRATCH_BYTES, INVALID),
        (good, size - 1, SCRATCH_BYTES, INSUFFICIENT),
        (good, size, SCRATCH_BYTES - 1, INSUFFICIENT),
        (b"\n" * 65_537, size, SCRATCH_BYTES, INSUFFICIENT),
    ):
        if invoke(exe, data, cap, scratch) != (0, code, b""):
            raise AssertionError(f"Unexpected named raw journal refusal ({code:#010x})")


def qualify(binary, original_build, directory, rustc):
    def bound():
        return (original_build["repository_inputs"] == original_inputs()
                and original_build["executable_sha256"] == sha256(binary.read_bytes()).hexdigest())
    if not bound():
        raise AssertionError("Actual locked Worker sources/executable differ")
    declaration = declared_input()
    nodes = {backend: link_caller(directory / backend, backend, rustc) for backend in BACKENDS}
    direct = direct_refusal(directory / "direct-closed")
    late = snapshot(raw(make("rejected", 2)), raw({**make("pending", 4), "reputation_delta": -1}))
    case_dir = fresh_directory(directory / "late-outside-profile")
    original = case_dir / "genuine.jsonl"
    original.write_bytes(late)
    original.chmod(0o600)
    genuine = cli_artifacts(binary, original, "original", True, None)
    if json.loads(genuine[2])["total_records"] != 1:
        raise AssertionError("Late control was not accepted independently by the original Rust CLI")
    cases = {}
    for label, (data, count, selected) in scenarios().items():
        case_dir = fresh_directory(directory / label)
        original = case_dir / "genuine.jsonl"
        original.write_bytes(data)
        original.chmod(0o600)
        expected = cli_artifacts(binary, original, "original", True, None)
        index = json.loads(expected[2])
        if index["total_records"] != selected or len(expected) != 3:
            raise AssertionError("Known original cardinality changed")
        if label == "maximum_records" and (b"source-63" not in expected[0] or b"source-60" in expected[0]):
            raise AssertionError("Known exact original carry-high attendance changed")
        size = 16 + sum(map(len, expected))
        for backend, (exe, receipt) in nodes.items():
            # Rust consumes the same whole held bytes, issues one named FFI
            # call, checks source/tails, and returns opaque WAO1 to the test.
            abi, n, received = invoke(exe, data, size + 13, SCRATCH_BYTES + 13)
            if (abi, n, len(received)) != (0, size, size) or artifacts(received) != expected:
                raise AssertionError(f"Original whole-file parity lost: {backend} {label}")
            if invoke(exe, data, size, SCRATCH_BYTES) != (0, size, received):
                raise AssertionError("Rust caller exact-capacity repeat differs")
            (case_dir / (backend + ".wao")).write_bytes(received)
            if label == "maximum_records":
                reject_checks(exe, data, size, late)
            if (sha256(exe.read_bytes()).hexdigest() != receipt["caller_elf_sha256"]
                    or sha256((exe.parent / LIBRARY).read_bytes()).hexdigest()
                        != receipt["library"]["artifact_sha256"]):
                raise AssertionError("Observed binary or private library changed")
        cases[label] = {"raw": len(data), "rows": count, "selected": selected, "wao_bytes": size,
                        "files": dict(zip(NAMES, (sha256(v).hexdigest() for v in expected), strict=True))}
    if not bound() or declaration != declared_input():
        raise AssertionError("Independent original inputs changed")
    report = {"pins": original_inputs(), "original_executable_sha256": original_build["executable_sha256"],
              "original_struct_sha256": declaration, "scope": "offline held WQX1 bytes only",
              "named_entry": ENTRY, "native_calls_per_invocation": 1, "production_dispatch": False,
              "original_valid_late_unsupported_refusal_atomic": True, "cases": cases,
              "direct_packaging_refusal": direct, "backends": {b: r for b, (_, r) in nodes.items()}}
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


class WorkerJournalAuditOwned(unittest.TestCase):
    def test_direct_extra_toolchain_imports_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="trnm-worker-journal-direct-closed-") as tmp:
            self.assertFalse(direct_refusal(Path(tmp) / "direct")["artifact_published"])

    def test_linked_rust_single_call_and_named_surface(self):
        rustc = rustc_path()
        with tempfile.TemporaryDirectory(prefix="trnm-worker-journal-owned-") as tmp:
            data = snapshot(raw(make("rejected", 7)))
            for backend in BACKENDS:
                exe, receipt = link_caller(Path(tmp) / backend, backend, rustc)
                abi, size, packet = invoke(exe, data, 2048, SCRATCH_BYTES + 13)
                self.assertEqual((abi, size), (0, len(packet)))
                self.assertEqual(json.loads(artifacts(packet)[2])["total_records"], 1)
                reject_checks(exe, data, size, data + b"{}\n")
                with self.assertRaises(FileExistsError):
                    build(exe.parent, backend)
                self.assertEqual(sha256((exe.parent / LIBRARY).read_bytes()).hexdigest(),
                                 receipt["library"]["artifact_sha256"])


def rustc_path():
    from shutil import which
    configured = os.environ.get("HIA_RUSTC") or which("rustc")
    if not configured:
        raise RuntimeError("Rust 1.95.0 is required for the linked audit caller")
    path = Path(configured).resolve(strict=True)
    if path.name == "rustup":
        found = subprocess.run([str(path), "which", "rustc"], check=True, capture_output=True,
                               text=True, cwd=ROOT, timeout=10).stdout.strip()
        path = Path(found).resolve(strict=True)
    return path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--original-binary", type=Path, required=True)
    p.add_argument("--original-build-receipt", type=Path, required=True)
    args = p.parse_args()
    report = qualify(args.original_binary.resolve(strict=True),
                     json.loads(args.original_build_receipt.read_bytes()),
                     fresh_directory(args.output), rustc_path())
    print(json.dumps(report["cases"], sort_keys=True))


if __name__ == "__main__":
    main()
