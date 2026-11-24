"""Native selection tests; the optional observation runs the unchanged Worker CLI."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame


SELECTOR = ROOT / "hia/src/worker_agent/audit_select.hepta"
ENCODER = ROOT / "hia/src/worker_agent/audit_jsonl_row.hepta"
INCLUDED = ("reveal_submitted", "rejected", "failed_submission", "failed_adapter")
BACKENDS = ("selfhost", "direct")
INVALID, INSUFFICIENT = 0xFFFFFFFF, 0xFFFFFFFE
MAX_RECORDS = 100_000
FILL, SCRATCH = b"\xa5", b"\x53\x7e"
ORIGINAL_PATHS = (
    "trillionnium/Cargo.lock", "trillionnium/Cargo.toml",
    "trillionnium/crates/trnm-worker-agent/Cargo.toml",
    "trillionnium/crates/trnm-worker-agent/src",
    "trillionnium/crates/trnm-types/Cargo.toml", "trillionnium/crates/trnm-types/src",
)


def select_frame(statuses):
    raw = [s.encode("utf-8") if isinstance(s, str) else s for s in statuses]
    return struct.pack("<4sI", b"WJS1", len(raw)) + b"".join(
        struct.pack("<I", len(s)) + s for s in raw)


def observed_call(module, raw, max_output):
    result = module.call("f0", [raw, FILL * max_output, SCRATCH]).require_returned()
    input_after, output_after, scratch_after = result.arguments
    if raw != input_after or scratch_after != SCRATCH:
        raise AssertionError("Native audit operation modified read-only data or scratch")
    return result.value, output_after


class WorkerAuditSelect(unittest.TestCase):
    def test_exact_status_selection_in_original_input_order(self):
        statuses = ["", "février", *INCLUDED, "Rejected", "rejected ", " rejected",
                    "failed", "reveal_submitted\n", "REVEAL_SUBMITTED", "rejected\0",
                    "rejected", "completed", "failed_adapter", "🧾", "failed_submissioN"]
        wanted = bytes([0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0])
        request = select_frame(statuses)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    SELECTOR, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observed_call(native, request, len(wanted) + 3),
                                 (len(wanted), wanted + FILL * 3))
                self.assertEqual(observed_call(native, select_frame([]), 3), (0, FILL * 3))
                self.assertEqual(observed_call(native, request, len(wanted) - 1),
                                 (INSUFFICIENT, FILL * (len(wanted) - 1)))

    def test_journal_count_limit_and_atomic_refusal(self):
        full = select_frame([""] * (MAX_RECORDS - 1) + ["rejected"])
        wanted = bytes(MAX_RECORDS - 1) + b"\x01"
        valid = select_frame(["rejected", "reveal_submitted"])
        malformed = (
            b"", valid[:7], b"WJS2" + valid[4:], valid[:-1], valid + b"x",
            struct.pack("<4sI", b"WJS1", MAX_RECORDS + 1),
            select_frame(["rejected", b"\xc3", b"\xa9"]),
            valid[:8] + b"\xff\xff\xff\xff" + valid[12:],
        )
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    SELECTOR, backend=backend, byte_exports=("f0",)) as native:
                self.assertEqual(observed_call(native, full, MAX_RECORDS), (MAX_RECORDS, wanted))
                for request in malformed:
                    self.assertEqual(observed_call(native, request, 8), (INVALID, FILL * 8))


def original_inputs():
    cmd = ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *ORIGINAL_PATHS]
    if subprocess.check_output(cmd, cwd=ROOT):
        raise AssertionError("Original Worker build source is locally modified")
    ids = subprocess.check_output(["git", "rev-parse",
                                   *("HEAD:" + p for p in ORIGINAL_PATHS)], cwd=ROOT).decode().splitlines()
    return dict(zip(ORIGINAL_PATHS, ids, strict=True))


def build_worker(observations, target):
    source = original_inputs()
    cargo, rustc = os.environ.get("CARGO", "cargo"), os.environ.get("RUSTC", "rustc")
    versions = {}
    for name, tool in (("cargo", cargo), ("rustc", rustc)):
        version = subprocess.check_output([tool, "--version"], text=True, timeout=15).strip()
        if version.split()[:2] != [name, "1.95.0"]:
            raise AssertionError("Exact Rust/Cargo 1.95.0 required for Worker CLI observation")
        versions[name] = version
    command = [cargo, "build", "--offline", "--locked", "--message-format=json",
               "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
               "-p", "trnm-worker-agent", "--bin", "trnm-worker-agent"]
    env = dict(os.environ, RUSTC=rustc, CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="1",
               CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0")
    result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, timeout=180)
    (observations / "cargo.stdout.jsonl").write_bytes(result.stdout)
    (observations / "cargo.stderr.raw").write_bytes(result.stderr)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    binaries = []
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact" and message.get("executable")
                and message["target"]["name"] == "trnm-worker-agent"
                and Path(message["target"]["src_path"]).resolve()
                == (ROOT / "trillionnium/crates/trnm-worker-agent/src/main.rs").resolve()):
            binaries.append(Path(message["executable"]))
    if (len(binaries) != 1 or not binaries[0].resolve().is_relative_to(target.resolve())
            or source != original_inputs()):
        raise AssertionError("Worker binary lacks exact original source binding")
    binary, = binaries
    report = {"command": command, "tools": versions, "repository_inputs": source,
              "executable_sha256": sha256(binary.read_bytes()).hexdigest()}
    (observations / "build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return binary, report


def ingress_rows(statuses):
    result = []
    for i, status in enumerate(statuses):
        row = {
            "request_id": ("repeated" if i in (1, 7) else f"request-{i}-🧾"),
            "task_id": ((1 << 64) - 1 if i == 7 else 101 + i),
            "channel": "fixture", "user_id": "local-test", "session_id": "test",
            "text": "local format fixture", "idempotency_key": f"id-{i}",
            "status": status, "created_at_unix_ms": 7,
        }
        if i == 1:
            row["reputation_delta"] = -1
        if i == 7:
            row["provider_request_id"] = "fixture-provider-request"
            row["provenance_schema_version"] = "LLM.v2"
            row["llm_provenance"] = {"provider": "fixture", "model": "model", "adapter": "local"}
        result.append(row)
    return result


def observe_cli(binary, build, observations):
    check = lambda: sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"]
    if not check():
        raise AssertionError("Worker binary changed after its exact locked build")
    scenarios = {
        "interleaved": [
            "waiting", "reveal_submitted", "Rejected", "rejected", "rejected ", "failed_submission",
            "completed", "failed_adapter", "failed_adapter", "REVEAL_SUBMITTED", "reveal_submitted",
            "", "", "😀",
        ],
        "all-excluded": ["waiting", "", "Failed_Adapter"],
        "empty": [],
    }
    runs = {}
    with ExitStack() as stack:
        modules = {backend: [stack.enter_context(NativeModule(
            path, backend=backend, byte_exports=("f0",))) for path in (SELECTOR, ENCODER)]
                   for backend in BACKENDS}
        for scenario, statuses in scenarios.items():
            private = observations / scenario
            private.mkdir(mode=0o700)
            records = ingress_rows(statuses)
            journal = private / "ingress.jsonl"
            journal.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
                                         for row in records))
            journal.chmod(0o600)
            dest = private / "actual-export.jsonl"
            result = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                                     "--output-file", str(dest)], cwd=private, capture_output=True,
                                    timeout=25)
            (private / "stdout.raw").write_bytes(result.stdout)
            (private / "stderr.raw").write_bytes(result.stderr)
            if result.returncode != 0 or result.stderr:
                raise AssertionError(f"Original export CLI failed: {scenario} {result.stderr!r}")
            original = dest.read_bytes()
            original_lines = original.splitlines(keepends=True)
            typed_rows = [json.loads(line) for line in original_lines]
            identity = lambda row: (row["request_id"], row["task_id"], row["status"])
            results = {}
            for backend, (selector, encoder) in modules.items():
                length, chosen = observed_call(selector, select_frame(statuses), len(records) + 3)
                if length != len(records) or chosen[length:] != FILL * 3:
                    raise AssertionError("Native selection did not preserve the record count")
                mask = chosen[:length]
                if any(code not in (0, 1) for code in mask):
                    raise AssertionError("Unexpected native selection bit")
                selected = [identity(row) for bit, row in zip(mask, records, strict=True) if bit]
                if selected != [identity(row) for row in typed_rows]:
                    raise AssertionError(f"Native selection differed from actual original CLI: {scenario}")
                encoded = []
                for row, line in zip(typed_rows, original_lines, strict=True):
                    n, actual = observed_call(encoder, frame(tuple(row[key] for key in FIELDS)),
                                               len(line) + 9)
                    if n != len(line) or actual[n:] != FILL * 9:
                        raise AssertionError("Invalid Worker JSONL output extent")
                    encoded.append(actual[:n])
                native = b"".join(encoded)
                if native != original:
                    raise AssertionError(f"Native row stream differed from actual Worker bytes: {scenario}")
                (private / f"{backend}.selection.raw").write_bytes(mask)
                (private / f"{backend}.export.jsonl").write_bytes(native)
                results[backend] = [selector.artifact_sha256, encoder.artifact_sha256]
            runs[scenario] = {"input": len(records), "exported": len(original_lines),
                              "export_sha256": sha256(original).hexdigest(), "backends": results}
    if not check() or build["repository_inputs"] != original_inputs():
        raise AssertionError("Original Worker source or binary changed during the observation")
    report = {
        "scope": "actual original export-audit versus native status selection and JSONL bytes",
        "original_cli_executed": True, "native_conversion": False, "native_file_io": False,
        "native_index": False, "production_routing_changed": False,
        "original_binary_sha256": build["executable_sha256"], "scenarios": runs,
    }
    (observations / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="Run the unchanged Worker CLI against local audit fixtures.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo-target", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT) or (args.cargo_target and args.cargo_target.resolve().is_relative_to(ROOT)):
        parser.error("Observation output and Cargo target must be outside the checkout")
    output.mkdir(mode=0o700)
    target = args.cargo_target.resolve() if args.cargo_target else output / "cargo-target"
    binary, receipt = build_worker(output, target)
    print(json.dumps(observe_cli(binary, receipt, output), sort_keys=True))


if __name__ == "__main__":
    main()
