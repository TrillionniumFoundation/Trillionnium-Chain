"""Compile and invoke the original private Node functions in an isolated test copy.

This is an independent reference executable. It is never called by HIA runtime
code, and no copied request grammar or authentication implementation is used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from hia.platform.build import sha256, write_json

HERE = Path(__file__).resolve().parent
INGRESS = "trillionnium/crates/trnm-pon-node/src/ingress.rs"
DECLARATION = (b'\n#[cfg(test)]\n#[path = "hia_authenticated_request_oracle.rs"]\n'
               b'mod hia_authenticated_request_oracle;\n')
TEST = "ingress::hia_authenticated_request_oracle::evaluate"
ORIGINAL_TESTS = (
    "ingress::tests::test_authenticated_bytes_bind_session_signature_and_canonical_request",
    "ingress::account_scope_tests::invalid_account_scope_refuses_classical_session_and_signed_request",
    "ingress::account_scope_tests::current_local_scope_refuses_previously_valid_classical_request",
    "ingress::account_scope_tests::valid_development_scope_retains_classical_signature_and_socket_path",
    "ingress::account_scope_tests::explicit_pq_selector_retains_classical_route_refusal_precedence",
    "ingress::tests::test_slow_partial_frame_cannot_extend_the_absolute_deadline",
)
MARKER = "HIA_TRANSPORT_ORACLE:"


def command(argv, cwd: Path, output: Path, label: str, *, env=None, timeout=180):
    directory = output / label
    directory.mkdir(mode=0o700)
    stdout_path, stderr_path = directory / "stdout.raw", directory / "stderr.raw"
    started = time.monotonic_ns()
    cleanup = None
    timed_out = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                   start_new_session=True, umask=0o077)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup_start = time.monotonic_ns()
            try:
                os.killpg(process.pid, signal.SIGKILL)
                outcome = "sent"
            except ProcessLookupError:
                outcome = "already_exited"
            process.wait(timeout=3)
            cleanup = {"signal": "SIGKILL", "signal_outcome": outcome,
                       "elapsed_ns": time.monotonic_ns() - cleanup_start,
                       "complete": process.returncode is not None}
    out, err = stdout_path.read_bytes(), stderr_path.read_bytes()
    row = {"argv": [str(value) for value in argv], "cwd": str(cwd),
        "exit_code": process.returncode, "timed_out": timed_out,
        "wall_limit_seconds": timeout, "cleanup_limit_seconds": 3, "cleanup": cleanup,
        "stdout_sha256": sha256(out), "stdout_bytes": len(out),
        "stderr_sha256": sha256(err), "stderr_bytes": len(err),
        "elapsed_ns": time.monotonic_ns() - started}
    write_json(directory / "receipt.json", row)
    if timed_out or process.returncode != 0:
        raise RuntimeError("Original Rust stage failed; raw observation retained: " + str(directory))
    return out, row


def records(raw: bytes):
    rows = []
    for line in raw.decode().splitlines():
        if MARKER in line:
            rows.append(json.loads(line.split(MARKER, 1)[1]))
    return rows


class RustOracle:
    def __init__(self, repository: Path, output: Path):
        self.repository = repository
        self.output = output
        output.mkdir(mode=0o700)
        self.isolated = output / "isolated-source"
        self.isolated.mkdir(mode=0o700)
        self.sources = {}
        # These complete original source/config/vector roots satisfy the
        # package's compile-time include_* inputs. No target/cache is copied.
        for directory in ("trillionnium", "config", "formal"):
            for path in sorted((repository / directory).rglob("*")):
                relative = path.relative_to(repository)
                if any(part in {"target", "__pycache__", ".pytest_cache"} for part in relative.parts):
                    continue
                if path.is_symlink():
                    raise ValueError("Symlinked original Cargo input: " + str(relative))
                if not path.is_file():
                    continue
                raw = path.read_bytes()
                destination = self.isolated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                self.sources[relative.as_posix()] = {"bytes": len(raw), "sha256": sha256(raw)}
        ingress = self.isolated / INGRESS
        original = ingress.read_bytes()
        if b"mod hia_authenticated_request_oracle" in original:
            raise ValueError("Original source already contains a test oracle hook")
        self.hook = (HERE / "rust_reference.rs").read_bytes()
        self.hook_path = ingress.parent / "hia_authenticated_request_oracle.rs"
        if self.hook_path.exists():
            raise FileExistsError("Refusing to replace an original module")
        self.hook_path.write_bytes(self.hook)
        ingress.write_bytes(original + DECLARATION)
        assert ingress.read_bytes()[:len(original)] == original
        self.original_ingress = original
        self.stages = []
        for tool in ("cargo", "rustc"):
            if shutil.which(tool) is None:
                raise RuntimeError("Required original Rust toolchain unavailable: " + tool)
        version, row = command(["rustc", "-Vv"], self.isolated, output, "rustc-version", timeout=10)
        self.stages.append(row)
        self.compiler = version.decode()
        self.target = output / "cargo-target"
        argv = ["cargo", "test", "--locked", "--manifest-path",
                str(self.isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node",
                "--lib", "--no-run", "--message-format=json", "--target-dir", str(self.target)]
        raw, row = command(argv, self.isolated, output, "cargo-original-test-build", timeout=600)
        self.stages.append(row)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        artifacts = [item for item in events if item.get("reason") == "compiler-artifact"]
        serde = [item for item in artifacts if item["target"]["name"] == "serde_json"]
        binaries = [item for item in artifacts if item["target"]["name"] == "trnm_pon_node"
                    and item.get("executable") and item["profile"].get("test")]
        if len(serde) != 1 or len(binaries) != 1:
            raise ValueError("Expected one actual serde_json artifact and one Node lib-test executable")
        self.serde = serde[0]
        if (not str(self.serde["package_id"]).endswith("serde_json@1.0.149")
                or set(self.serde["features"]) != {"default", "std"}):
            raise ValueError("Original targeted Cargo serde_json profile differs: " +
                             json.dumps(self.serde, sort_keys=True))
        self.binary = Path(binaries[0]["executable"])
        self.binary_sha256 = sha256(self.binary.read_bytes())
        self.binary_profile = binaries[0]["profile"]
        available, row = command([str(self.binary), "--list"], self.isolated, output, "list-tests", timeout=20)
        self.stages.append(row)
        names = {line.removesuffix(": test") for line in available.decode().splitlines()
                 if line.endswith(": test")}
        if not set((TEST,) + ORIGINAL_TESTS) <= names:
            raise ValueError("Original test names missing: " + str(set((TEST,) + ORIGINAL_TESTS) - names))
        self.original_test_receipts = []
        for index, name in enumerate(ORIGINAL_TESTS):
            _, row = command([str(self.binary), "--exact", name, "--nocapture", "--test-threads=1"],
                self.isolated, output, "original-test-" + str(index), timeout=180)
            self.original_test_receipts.append({"name": name, "receipt": row})
        self.check_sources()

    def check_sources(self):
        for relative, expected in self.sources.items():
            original = self.repository / relative
            copied = self.isolated / relative
            raw = original.read_bytes()
            if len(raw) != expected["bytes"] or sha256(raw) != expected["sha256"]:
                raise ValueError("Original Rust source changed: " + relative)
            if copied.read_bytes() != raw + (DECLARATION if relative == INGRESS else b""):
                raise ValueError("Isolated original source changed: " + relative)
        if self.hook_path.read_bytes() != self.hook or (HERE / "rust_reference.rs").read_bytes() != self.hook:
            raise ValueError("Independent Rust test hook changed")
        if hasattr(self, "binary") and sha256(self.binary.read_bytes()) != self.binary_sha256:
            raise ValueError("Original reference executable changed")

    def invoke(self, mode, corpus: Path | None = None):
        self.check_sources()
        env = dict(os.environ, TRNM_HIA_TRANSPORT_ORACLE_MODE=mode)
        if corpus is not None:
            env["TRNM_HIA_TRANSPORT_ORACLE_CORPUS"] = str(corpus)
        raw, row = command([str(self.binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            self.isolated, self.output, "original-" + mode, env=env, timeout=180)
        self.stages.append(row)
        self.check_sources()
        return records(raw)

    def describe(self):
        rows = self.invoke("describe")
        if len(rows) != 1 or rows[0]["mode"] != "describe":
            raise ValueError("Missing original Settings/session description")
        return rows[0]

    def verify(self, cases, native_rows):
        corpus = self.output / "corpus.jsonl"
        selected = [case for case in cases if case["expected_code"] < 100]
        with corpus.open("x") as stream:
            for index, case in enumerate(selected):
                path = self.output / ("input-" + str(index) + ".raw")
                path.write_bytes(case["input"])
                stream.write(json.dumps({"name": case["name"], "input_path": str(path)}) + "\n")
        result = self.invoke("verify", corpus)
        if [row["name"] for row in result] != [case["name"] for case in selected]:
            raise ValueError("Original oracle returned a missing, extra or reordered case")
        native = {row["name"]: row for row in native_rows}
        observations = []
        for case, row in zip(selected, result):
            same = row["code"] == native[case["name"]]["actual_code"] == case["expected_code"]
            if row["code"] == 0:
                same = same and bytes.fromhex(row["metadata_hex"]) == case["expected_output"]
                count = int.from_bytes(case["input"][144:152], "little")
                wire = case["input"][152 + 32 * count:]
                consumed = int.from_bytes(wire[:4], "big") + 4
                same = same and bytes.fromhex(row["remaining_frame_hex"]) == wire[consumed:]
            observations.append({"name": case["name"], "status": "PASS" if same else "FAIL",
                "original": row, "native_code": native[case["name"]]["actual_code"],
                "comparison": "original frame/auth family and exact successful metadata; capture EOF mapped to NeedMore"})
        write_json(self.output / "comparison.json", {"controls": observations})
        if not all(row["status"] == "PASS" for row in observations):
            raise ValueError("Original Rust request differential failed")
        return {"status": "PASS", "compared": len(observations), "failed": 0,
            "new_owner_container_cases_excluded": len(cases) - len(selected),
            "original_tests": self.original_test_receipts, "controls": observations,
            "rustc": self.compiler, "executable_sha256": self.binary_sha256,
            "cargo_profile": self.binary_profile, "serde_json_artifact": self.serde,
            "source_inputs": self.sources, "original_functions_byte_preserved": True,
            "original_ingress_sha256": sha256(self.original_ingress),
            "test_hook_sha256": sha256(self.hook), "appended_declaration_hex": DECLARATION.hex(),
            "stages": self.stages, "production_runtime_dependency": False}
