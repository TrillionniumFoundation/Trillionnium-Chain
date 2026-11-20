"""Independent exact retained Node/serde oracle, never a HIA runtime dependency."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

from hia.platform.build import sha256, write_json
from hia.platform.transport_request.rust_oracle import command

HERE = Path(__file__).resolve().parent
INGRESS = "trillionnium/crates/trnm-pon-node/src/ingress.rs"
DECLARATION = (b'\n#[cfg(test)]\n#[path = "hia_authenticated_response_oracle.rs"]\n'
               b'mod hia_authenticated_response_oracle;\n')
TEST = "ingress::hia_authenticated_response_oracle::evaluate"
MARKER = "HIA_RESPONSE_ORACLE:"
ORIGINAL_TESTS = (
    "ingress::tests::test_authenticated_bytes_bind_session_signature_and_canonical_request",
    "ingress::tests::test_durable_pending_request_recovers_and_completed_response_replays",
    "ingress::tests::test_authenticated_socket_replays_response_after_client_loses_first_ack",
    "ingress::tests::test_cached_terminal_error_is_reverified_and_counted_as_rejected",
    "ingress::tests::test_durable_client_retries_exact_wire_after_lost_server_response",
    "ingress::tests::authenticated_activation_recovery::signed_socket_local_queue_busy_keeps_exact_nonce_for_retry_and_invalid_work_terminal",
)


class RustOracle:
    def __init__(self, repository: Path, output: Path):
        for name in ("cargo", "rustc"):
            if shutil.which(name) is None:
                raise RuntimeError("Required retained-original oracle tool unavailable: " + name)
        self.repository, self.output = repository, output
        output.mkdir(mode=0o700)
        self.isolated = output / "isolated-source"
        self.isolated.mkdir(mode=0o700)
        self.sources = {}
        self.stages = []
        self.comparisons = {}
        for directory in ("trillionnium", "config", "formal"):
            for path in sorted((repository / directory).rglob("*")):
                relative = path.relative_to(repository)
                if any(part in {"target", "__pycache__", ".pytest_cache"} for part in relative.parts):
                    continue
                if path.is_symlink():
                    raise ValueError("Symlinked original Cargo source: " + str(relative))
                if not path.is_file():
                    continue
                raw = path.read_bytes()
                destination = self.isolated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                self.sources[relative.as_posix()] = {"bytes": len(raw), "sha256": sha256(raw)}
        ingress = self.isolated / INGRESS
        self.original_ingress = ingress.read_bytes()
        if b"mod hia_authenticated_response_oracle" in self.original_ingress:
            raise ValueError("Original source already contains the test-only response hook")
        self.hook = (HERE / "rust_reference.rs").read_bytes()
        self.hook_path = ingress.parent / "hia_authenticated_response_oracle.rs"
        if self.hook_path.exists():
            raise FileExistsError("Refusing to replace an original Rust module")
        self.hook_path.write_bytes(self.hook)
        ingress.write_bytes(self.original_ingress + DECLARATION)
        raw, row = command(["rustc", "-Vv"], self.isolated, output, "rustc-version", timeout=10)
        self.compiler = raw.decode(); self.stages.append(row)
        self.target = output / "cargo-target"
        argv = ["cargo", "test", "--locked", "--manifest-path",
            str(self.isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node", "--lib",
            "--no-run", "--message-format=json", "--target-dir", str(self.target)]
        raw, row = command(argv, self.isolated, output, "cargo-original-test-build", timeout=600)
        self.stages.append(row)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
        serde = [item for item in artifacts if item["target"]["name"] == "serde_json"]
        binaries = [item for item in artifacts if item["target"]["name"] == "trnm_pon_node"
            and item.get("executable") and item["profile"].get("test")]
        if len(serde) != 1 or len(binaries) != 1:
            raise ValueError("Expected one actual serde_json artifact and one original Node lib-test executable")
        self.serde = serde[0]
        if (not str(self.serde["package_id"]).endswith("serde_json@1.0.149")
                or set(self.serde["features"]) != {"default", "std"}):
            raise ValueError("Ordinary retained Node serde profile changed: " + json.dumps(self.serde))
        self.binary = Path(binaries[0]["executable"])
        self.binary_sha256 = sha256(self.binary.read_bytes())
        self.binary_profile = binaries[0]["profile"]
        raw, row = command([str(self.binary), "--list"], self.isolated, output, "list-tests", timeout=20)
        self.stages.append(row)
        names = {line.removesuffix(": test") for line in raw.decode().splitlines() if line.endswith(": test")}
        if not set((TEST,) + ORIGINAL_TESTS) <= names:
            raise ValueError("Original response test names missing: " + str(set((TEST,) + ORIGINAL_TESTS) - names))
        self.original_tests = []
        for index, name in enumerate(ORIGINAL_TESTS):
            _, row = command([str(self.binary), "--exact", name, "--nocapture", "--test-threads=1"],
                self.isolated, output, "original-test-" + str(index), timeout=180)
            self.original_tests.append({"name": name, "receipt": row})
        self.check_sources()

    def check_sources(self):
        for relative, expected in self.sources.items():
            raw = (self.repository / relative).read_bytes()
            if len(raw) != expected["bytes"] or sha256(raw) != expected["sha256"]:
                raise ValueError("Retained original source changed: " + relative)
            extra = DECLARATION if relative == INGRESS else b""
            if (self.isolated / relative).read_bytes() != raw + extra:
                raise ValueError("Isolated original source changed: " + relative)
        if self.hook_path.read_bytes() != self.hook or (HERE / "rust_reference.rs").read_bytes() != self.hook:
            raise ValueError("Response test hook changed")
        if hasattr(self, "binary") and sha256(self.binary.read_bytes()) != self.binary_sha256:
            raise ValueError("Original oracle executable changed")

    def invoke(self, mode: str, corpus: Path | None = None):
        self.check_sources()
        env = dict(os.environ, TRNM_HIA_RESPONSE_ORACLE_MODE=mode)
        if corpus is not None:
            env["TRNM_HIA_RESPONSE_ORACLE_CORPUS"] = str(corpus)
        raw, row = command([str(self.binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            self.isolated, self.output, "original-" + mode, env=env, timeout=180)
        self.stages.append(row)
        self.check_sources()
        return [json.loads(line.split(MARKER, 1)[1]) for line in raw.decode().splitlines() if MARKER in line]

    def describe(self):
        rows = self.invoke("describe")
        if len(rows) != 1 or rows[0]["mode"] != "describe":
            raise ValueError("Original Settings description absent or ambiguous")
        return rows[0]

    def compare(self, mode: str, cases, native):
        directory = self.output / (mode + "-corpus")
        directory.mkdir(mode=0o700)
        corpus = directory / "inputs.jsonl"
        locations = []
        with corpus.open("x") as stream:
            for index, case in enumerate(cases):
                path = directory / (str(index) + ".input.raw")
                path.write_bytes(case["input"])
                destination = directory / (str(index) + ".output.raw")
                locations.append(destination)
                row = {"name": case["name"], "input_path": str(path), "output_path": str(destination)}
                if "request" in case:
                    row["request"] = case["request"]
                stream.write(json.dumps(row, ensure_ascii=True) + "\n")
        observed = self.invoke(mode, corpus)
        if [row["name"] for row in observed] != [case["name"] for case in cases]:
            raise ValueError("Original oracle returned a missing, duplicated, extra or reordered case")
        rows = []
        for case, original, destination in zip(cases, observed, locations):
            actual = destination.read_bytes()
            row = native[case["name"]]
            same = (original["code"] == row["actual_code"] == case["expected_code"]
                and actual == case["expected_output"] and sha256(actual) == row["result_sha256"])
            if mode == "verify" and original["code"] == 0:
                frame = case["input"][280:]
                end = int.from_bytes(frame[:4], "big") + 4
                same = same and bytes.fromhex(original["remaining_frame_hex"]) == frame[end:]
            rows.append({"name": case["name"], "status": "PASS" if same else "FAIL",
                "original": original, "original_output_sha256": sha256(actual),
                "native_code": row["actual_code"], "native_result_sha256": row["result_sha256"]})
        comparison = {"status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
            "compared": len(rows), "controls": rows}
        self.comparisons[mode] = comparison
        write_json(directory / "comparison.json", comparison)
        if comparison["status"] != "PASS":
            raise ValueError("Original response differential failed: " + mode)
        return comparison

    def receipt(self):
        self.check_sources()
        return {"status": "PASS", "comparisons": self.comparisons, "original_tests": self.original_tests,
            "rustc": self.compiler, "executable_sha256": self.binary_sha256,
            "cargo_profile": self.binary_profile, "serde_json_artifact": self.serde,
            "source_inputs": self.sources, "original_functions_byte_preserved": True,
            "original_ingress_sha256": sha256(self.original_ingress),
            "test_hook_sha256": sha256(self.hook), "appended_declaration_hex": DECLARATION.hex(),
            "stages": self.stages, "production_runtime_dependency": False,
            "scope": "retained original serde, response, framing and identity functions; synthetic JVT2 constructs Values only"}
