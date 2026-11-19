"""Compare the HIA RS46 byte kernel with the unchanged original Rust crate.

The original Cargo workspace is copied in full; a cfg(test) observation child
is appended only to cell/erasure.rs in that private copy. Every original byte,
the complete case roster, both outputs and the actual compiler executable are
bound in the result. Missing tools, an empty suite or a failing original build
cannot become a passing comparison. The adapter supplies a selected chunk pin;
TCM1/context ownership, provider storage and package retirement are separate.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hia.platform.transport_request.rust_oracle import command

HERE = Path(__file__).resolve().parent
PINS = HERE / "rs46_original_sources.json"
ADAPTER = HERE / "rs46_original.rs"
ORIGINAL = "trillionnium/crates/trnm-data-availability/src/cell/erasure.rs"
DECLARATION = (b'\n#[cfg(test)]\n#[path = "hia_rs46_original.rs"]\n'
               b'mod hia_rs46_original;\n')
TEST = "cell::erasure::hia_rs46_original::evaluate"
MARKER = "HIA_RS46_ORIGINAL:"
MAX_CHUNK = 4 * 1024 * 1024
FORBIDDEN_ENVIRONMENT = {
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "RUSTC", "RUSTDOC", "CARGO",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC_BOOTSTRAP",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_TARGET", "CARGO_BUILD_BUILD_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_TARGET_DIR",
}
RETAINED = (
    "every_field_product_matches_independent_polynomial_division",
    "exact_systematic_and_partial_shard_vectors_and_crs1_identity",
    "all_fifteen_four_shard_subsets_restore_real_non_aligned_chunk",
    "insufficient_duplicate_and_reordered_shards_are_not_silently_reinterpreted",
    "corrupted_required_or_extra_shards_never_return_verified_source_bytes",
    "nonzero_padding_is_rejected_even_when_original_payload_hash_would_match",
    "internal_context_object_and_chunk_pins_cannot_be_replaced_by_shard_headers",
    "every_single_byte_wire_mutation_is_rejected_by_shape_or_pinned_recovery",
    "truncated_extra_oversized_and_hostile_headers_refuse_before_payload_copy",
    "all_padding_remainders_and_short_sources_are_reconstructed_exactly",
    "full_four_mebibyte_chunk_recovers_with_two_missing_systematic_shards",
    "singular_matrix_is_an_error_and_does_not_claim_recovery",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Nonregular source/artifact: " + str(path))
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": digest(raw)}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def verify_pins(repository):
    pins = json.loads(PINS.read_text(), object_pairs_hook=unique)
    if pins["schema"] != "trnm.hia.rs46-original-sources.v1" or not pins["files"]:
        raise ValueError("Invalid original RS46 source pins")
    for row in pins["files"]:
        if identity(repository / row["path"]) != {k: row[k] for k in ("bytes", "sha256")}:
            raise ValueError("Original RS46 source pin changed: " + row["path"])
    return pins


def source_roster(repository):
    result = {"rust-toolchain.toml": identity(repository / "rust-toolchain.toml")}
    for name in ("trillionnium", "config", "formal", "tests"):
        for path in sorted((repository / name).rglob("*")):
            relative = path.relative_to(repository)
            if any(part in {"target", "__pycache__", ".pytest_cache"} for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("Symlinked original input: " + str(relative))
            if path.is_file():
                result[relative.as_posix()] = identity(path)
    return result


def build_environment(directory):
    for key, value in os.environ.items():
        forbidden = (key in FORBIDDEN_ENVIRONMENT or key.startswith("CARGO_PROFILE_")
                     or (key.startswith("CARGO_TARGET_")
                         and key.endswith(("_RUSTFLAGS", "_RUSTDOCFLAGS", "_LINKER", "_RUNNER"))))
        if value and forbidden:
            raise ValueError("Unbound original compilation/runtime override: " + key)
    environment = dict(os.environ, RUSTUP_TOOLCHAIN="1.95.0", PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONOPTIMIZE", None)
    cargo_home = Path(environment.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    locations = [cargo_home] + [path / ".cargo" for path in (directory, *directory.parents)]
    for location in locations:
        for name in ("config", "config.toml"):
            path = location / name
            if path.exists() or path.is_symlink():
                raise ValueError("Unbound Cargo configuration: " + str(path))
    return environment


def select_binary(raw, target, manifest, source):
    events = [json.loads(line, object_pairs_hook=unique) for line in raw.splitlines() if line.strip()]
    finished = [e for e in events if e.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        raise ValueError("No complete successful Cargo build event")
    matches = []
    for event in events:
        item = event.get("target", {})
        if (event.get("reason") != "compiler-artifact" or item.get("name") != "trnm_data_availability"
                or item.get("kind") != ["lib"] or event.get("profile", {}).get("test") is not True):
            continue
        if event.get("manifest_path") != str(manifest) or item.get("src_path") != str(source):
            raise ValueError("Original Cargo artifact source identity differs")
        path = Path(event["executable"])
        if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(target):
            raise ValueError("Original Cargo artifact escaped its private target")
        matches.append(path)
    if len(matches) != 1:
        raise ValueError("Missing or ambiguous original crate test executable")
    return matches[0]


class RustOracle:
    def __init__(self, repository, output):
        self.repository, self.output = repository.resolve(), output.resolve()
        self.output.mkdir(mode=0o700)
        self.original_pins = verify_pins(self.repository)
        for tool in ("cargo", "rustc"):
            if shutil.which(tool) is None:
                raise RuntimeError("Required original tool unavailable: " + tool)
        self.tool_inputs = {str(p): identity(p) for p in (
            Path(__file__), PINS, ADAPTER,
            ROOT / "hia/platform/transport_request/rust_oracle.py")}
        self.sources = source_roster(self.repository)
        write_json(self.output / "source-inputs.json", {"original_pins": self.original_pins,
            "complete_original_sources": self.sources, "oracle_sources": self.tool_inputs})
        self.isolated = self.output / "isolated-source"
        self.isolated.mkdir(mode=0o700)
        for relative in self.sources:
            destination = self.isolated / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((self.repository / relative).read_bytes())
        self.original_path = self.isolated / ORIGINAL
        self.original_bytes = self.original_path.read_bytes()
        if b"mod hia_rs46_original" in self.original_bytes:
            raise ValueError("Original source already contains this oracle hook")
        self.hook_path = self.original_path.parent / "hia_rs46_original.rs"
        if self.hook_path.exists():
            raise FileExistsError("Refusing to replace an original source")
        self.hook_path.write_bytes(ADAPTER.read_bytes())
        self.original_path.write_bytes(self.original_bytes + DECLARATION)
        self.stages = []
        self.binary = None
        self.environment = build_environment(self.isolated)
        compiler, row = command(["rustc", "-Vv"], self.isolated, self.output, "rustc-version",
                                env=self.environment, timeout=10)
        self.stages.append(row)
        self.compiler = compiler.decode()
        if "release: 1.95.0\n" not in self.compiler:
            raise ValueError("Original comparison requires pinned Rust 1.95.0")
        raw, row = command(["rustc", "--print", "sysroot"], self.isolated, self.output, "rustc-sysroot",
                           env=self.environment, timeout=10)
        self.stages.append(row)
        sysroot = Path(raw.decode().strip()).resolve(strict=True)
        self.actual_tools = {tool: {"path": str((sysroot / "bin" / tool).resolve(strict=True)),
                                   **identity((sysroot / "bin" / tool).resolve(strict=True))}
                             for tool in ("rustc", "cargo", "rustdoc")}
        self.environment.update(RUSTC=self.actual_tools["rustc"]["path"],
            CARGO=self.actual_tools["cargo"]["path"], RUSTDOC=self.actual_tools["rustdoc"]["path"],
            RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="",
            PATH=str(sysroot / "bin") + os.pathsep + self.environment.get("PATH", ""))
        raw, row = command([self.actual_tools["rustc"]["path"], "-Vv"], self.isolated, self.output,
                           "actual-rustc-version", env=self.environment, timeout=10)
        self.stages.append(row)
        if raw != compiler:
            raise ValueError("Actual original compiler differs from selected pinned toolchain")
        target = self.output / "cargo-target"
        package = self.isolated / "trillionnium/crates/trnm-data-availability"
        raw, row = command([self.actual_tools["cargo"]["path"], "test", "--locked", "--manifest-path",
            str(self.isolated / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability", "--lib",
            "--no-run", "--message-format=json", "--target-dir", str(target)],
            self.isolated, self.output, "cargo-original-build", env=self.environment, timeout=900)
        self.stages.append(row)
        self.cargo_binary = select_binary(raw, target, package / "Cargo.toml", package / "src/lib.rs")
        self.binary_identity = identity(self.cargo_binary)
        self.binary = self.output.parent / "original-rs46-tests"
        self.binary.write_bytes(self.cargo_binary.read_bytes())
        self.binary.chmod(0o500)
        if identity(self.binary) != self.binary_identity:
            raise ValueError("Retained original executable differs from the Cargo artifact")
        write_json(self.output / "original-binary.json", {"cargo_artifact": str(self.cargo_binary),
            "executed_retained_artifact": "original-rs46-tests", **self.binary_identity})
        raw, row = command([str(self.binary), "--list"], self.isolated, self.output, "original-roster",
                           env=self.environment, timeout=20)
        self.stages.append(row)
        names = [line.removesuffix(": test") for line in raw.decode().splitlines() if line.endswith(": test")]
        required = {"cell::erasure::tests::" + n for n in RETAINED}
        actual = {n for n in names if n.startswith("cell::erasure::tests::")}
        if actual != required or names.count(TEST) != 1:
            raise ValueError("Original retained test or adapter roster differs")
        raw, row = command([str(self.binary), "cell::erasure::tests::", "--nocapture", "--test-threads=1"],
            self.isolated, self.output, "original-retained-tests", env=self.environment, timeout=180)
        self.stages.append(row)
        passed = re.findall(r"^test (cell::erasure::tests::\S+) \.\.\. ok$", raw.decode(), re.MULTILINE)
        if len(passed) != len(required) or set(passed) != required or "12 passed; 0 failed; 0 ignored" not in raw.decode():
            raise ValueError("Original retained tests did not all actually execute")
        self.retained_tests = passed
        self.check_sources()

    def check_sources(self):
        verify_pins(self.repository)
        if source_roster(self.repository) != self.sources:
            raise ValueError("Complete original source roster changed")
        isolated = source_roster(self.isolated)
        expected = dict(self.sources)
        expected[ORIGINAL] = {"bytes": len(self.original_bytes + DECLARATION),
                              "sha256": digest(self.original_bytes + DECLARATION)}
        expected[self.hook_path.relative_to(self.isolated).as_posix()] = identity(ADAPTER)
        if isolated != expected:
            raise ValueError("Isolated production bytes or complete input roster changed")
        for name, before in self.tool_inputs.items():
            if identity(Path(name)) != before:
                raise ValueError("Oracle source changed: " + name)
        build_environment(self.isolated)
        for tool, before in self.actual_tools.items():
            if identity(Path(before["path"])) != {key: before[key] for key in ("bytes", "sha256")}:
                raise ValueError("Original compiler/Cargo changed")
        if self.binary is not None and (identity(self.binary) != self.binary_identity
                                       or identity(self.cargo_binary) != self.binary_identity):
            raise ValueError("Original executed or Cargo executable changed")

    def evaluate(self, cases, label):
        self.check_sources()
        directory = self.output / label
        directory.mkdir(mode=0o700)
        corpus = directory / "corpus.jsonl"
        rows = []
        for i, case in enumerate(cases):
            stem = f"{i:05}"
            (directory / (stem + ".input")).write_bytes(case["request"])
            rows.append({"name": case["name"], "stem": stem})
        corpus.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
        before = identity(corpus)
        raw, stage = command([str(self.binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            self.isolated, self.output, label + "-execution",
            env=dict(self.environment, TRNM_HIA_RS46_ORACLE_CORPUS=str(corpus)), timeout=180)
        self.stages.append(stage)
        if identity(corpus) != before or "1 passed; 0 failed; 0 ignored" not in raw.decode():
            raise ValueError("Original corpus or executed test changed")
        observed = [json.loads(line.split(MARKER, 1)[1], object_pairs_hook=unique)
                    for line in raw.decode().splitlines() if MARKER in line]
        if [row["name"] for row in observed] != [case["name"] for case in cases]:
            raise ValueError("Original output roster missing, duplicated or reordered")
        outputs = []
        for i, (case, row) in enumerate(zip(cases, observed)):
            input_path = directory / (f"{i:05}.input")
            output_path = directory / (f"{i:05}.original")
            if input_path.read_bytes() != case["request"] or row["input_sha256"] != digest(case["request"]):
                raise ValueError("Original input bytes changed")
            if type(row["accepted"]) is not bool or type(row["output_bytes"]) is not int:
                raise ValueError("Original result types differ")
            if row["accepted"]:
                value = output_path.read_bytes()
                if len(value) != row["output_bytes"] or digest(value) != row["output_sha256"]:
                    raise ValueError("Original output identity differs")
            else:
                if output_path.exists() or row["output_bytes"] != 0 or row["output_sha256"] is not None:
                    raise ValueError("Original refusal published an output")
                value = None
            outputs.append(value)
        write_json(directory / "observations.json", observed)
        self.check_sources()
        return outputs, observed, directory


def request(data, *, op=0, count=0, index=0, manifest=None, source_hash=None, size=None, body=None):
    manifest = bytes(range(32)) if manifest is None else manifest
    source_hash = hashlib.sha256(data).digest() if source_hash is None else source_hash
    size = len(data) if size is None else size
    return (b"HRS1" + bytes((1, op, count, 0)) + manifest + struct.pack("<II", index, size)
            + source_hash + (data if body is None else body))


def case(name, raw, out_length):
    return {"name": name, "request": raw, "out_length": out_length}


def encode_cases():
    lengths = list(range(1, 21)) + [55, 56, 63, 64, 65, 119, 120, 257, 4097, 16401, MAX_CHUNK]
    result = []
    for n in lengths:
        data = bytes((i * 17 + i // 65536) % 251 for i in range(n))
        result.append(case(f"encode-{n}", request(data), 6 * (81 + (n + 3) // 4)))
    result.append(case("encode-padding-helper", request(b"x\0\0\1"), 6 * 82))
    result.append(case("encode-highest-index", request(b"abcde", index=16383), 6 * 83))
    return result


def recovery_cases(encodes, outputs):
    result = []
    for sent, wire in zip(encodes, outputs):
        if wire is None:
            raise ValueError("Original valid encode unexpectedly refused")
        raw = sent["request"]
        n = struct.unpack_from("<I", raw, 44)[0]
        width = 81 + (n + 3) // 4
        shards = [wire[i * width:(i + 1) * width] for i in range(6)]
        selections = ([(2, 3, 4, 5)] if n == MAX_CHUNK else
                      list(itertools.combinations(range(6), 4))
                      + list(itertools.combinations(range(6), 5)) + [tuple(range(6))])
        def recover(indices, pieces=None):
            return raw[:5] + bytes((1, len(indices), 0)) + raw[8:80] + b"".join(
                shards[i] for i in indices) if pieces is None else (
                raw[:5] + bytes((1, len(indices), 0)) + raw[8:80] + b"".join(pieces))
        for indices in selections:
            result.append(case(sent["name"] + "-recover-" + "".join(map(str, indices)), recover(indices), n))
        if sent["name"] != "encode-4":
            continue
        for indices in [(0, 1, 2, 2), (3, 2, 1, 0), (0, 2, 1, 5)]:
            result.append(case("order-" + "".join(map(str, indices)), recover(indices), n))
        for i in range(6):
            pieces = list(shards)
            changed = bytearray(pieces[i]); changed[81] ^= 1; pieces[i] = bytes(changed)
            result.append(case(f"corrupt-shard-{i}", recover(tuple(range(6)), pieces), n))
        for offset in range(width):
            changed = bytearray(shards[4]); changed[offset] ^= 1
            result.append(case(f"wire-mutation-{offset}", recover((0, 1, 2, 4), shards[:3] + [bytes(changed)]), n))
        valid = recover((0, 1, 2, 4))
        for offset in [0, 4, 5, 7, 8, 40, 44, 48]:
            changed = bytearray(valid); changed[offset] ^= 1
            result.append(case(f"request-mutation-{offset}", bytes(changed), n))
        for count in [0, 1, 2, 3, 7, 255]:
            changed = bytearray(valid); changed[6] = count
            result.append(case(f"bad-count-{count}", bytes(changed), n))
        for cut in range(80):
            result.append(case(f"truncated-wrapper-{cut}", valid[:cut], n))
        for cut in [80, 81, len(valid) - 1]:
            result.append(case(f"truncated-wire-{cut}", valid[:cut], n))
        result.append(case("trailing-wire", valid + b"\0", n))
    # A consistent alternate codeword has the same original byte x but nonzero
    # padding. Parity bytes come from the actual original encoding above.
    helper = outputs[[c["name"] for c in encodes].index("encode-padding-helper")]
    digest_x = hashlib.sha256(b"x").digest()
    pieces = []
    for i in range(6):
        shard = bytearray(helper[i * 82:(i + 1) * 82])
        shard[40:44] = (1).to_bytes(4, "big")
        shard[44:76] = digest_x
        pieces.append(bytes(shard))
    result.append(case("nonzero-consistent-padding", request(b"x", op=1, count=6, body=b"".join(pieces)), 1))
    result.append(case("encode-wrong-sha", request(b"abcde", source_hash=bytes(32)), 6 * 83))
    return result


def compare(native, cases, originals, observations, directory):
    rows = []
    for start in range(0, len(cases), 16):
        chunk = cases[start:start + 16]
        timeout = 240 if any(len(c["request"]) > 1 << 20 or c["out_length"] > 1 << 20 for c in chunk) else 60
        calls = native.call_many([(c["request"], c["out_length"]) for c in chunk], timeout=timeout)
        if len(calls) != len(chunk):
            raise ValueError("Native result count differs")
        for i, (sent, call) in enumerate(zip(chunk, calls), start):
            write_json(directory / (f"{i:05}.native-call.json"), {
                "name": sent["name"], "status": call.status, "returncode": call.returncode,
                "value": call.value, "abi_status": call.abi_status, "stderr": call.stderr})
            call.require_returned()
            if type(call.value) is not int or call.arguments[0] != sent["request"]:
                raise ValueError("Native return or immutable input differs")
            output = call.arguments[1]
            (directory / (f"{i:05}.native")).write_bytes(output)
            expected = originals[i]
            accepted = call.value == 0
            if accepted != observations[i]["accepted"]:
                raise ValueError("Original/native acceptance differs: " + sent["name"])
            if accepted and output != expected:
                raise ValueError("Original/native complete bytes differ: " + sent["name"])
            if not accepted and output != b"\xa5" * sent["out_length"]:
                raise ValueError("Native refusal changed caller output: " + sent["name"])
            rows.append({"name": sent["name"], "status": "PASS", "accepted": accepted,
                         "native_code": call.value, "input_sha256": digest(sent["request"]),
                         "native_output_bytes": len(output), "native_output_sha256": digest(output),
                         "original_error": observations[i]["error"]})
    write_json(directory / "comparison.json", rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    report = {"schema": "trnm.hia.rs46-original-comparison.v1", "status": "FAIL",
              "whole_chain_native": False, "retirement_accepted": False,
              "runtime_dependency": False, "TCM1_context_owner_qualified": False}
    try:
        oracle = RustOracle(args.repository, output / "original")
        from hia.tests.rs46_native import RS46Native, SOURCE
        native_source = identity(SOURCE)
        native_tool_inputs = {str(path): identity(path) for path in (
            ROOT / "hia/tests/rs46_native.py", ROOT / "hia/tests/native_support.py",
            ROOT / "hia/tools/toolchain.py", ROOT / "hia/components.json",
            ROOT / "hia/toolchain.lock.json")}
        with RS46Native(SOURCE) as native:
            write_json(output / "native-build.json", native.receipt)
            native_artifact = output / "native-rs46.so"
            native_artifact.write_bytes(native.library.read_bytes())
            native_artifact_identity = identity(native_artifact)
            if (native_artifact_identity != identity(native.library)
                    or native_artifact_identity["sha256"] != native.artifact_sha256):
                raise ValueError("Retained native artifact differs from the actually executed library")
            encodes = encode_cases()
            encoded, observations, directory = oracle.evaluate(encodes, "encode")
            comparisons = compare(native, encodes, encoded, observations, directory)
            recoveries = recovery_cases(encodes, encoded)
            recovered, observations, directory = oracle.evaluate(recoveries, "recover")
            comparisons += compare(native, recoveries, recovered, observations, directory)
            oracle.check_sources()
            if identity(SOURCE) != native_source:
                raise ValueError("Native RS46 source changed during comparison")
            if (identity(native_artifact) != native_artifact_identity
                    or identity(native.library) != native_artifact_identity):
                raise ValueError("Actually executed or retained native artifact changed")
            for name, before in native_tool_inputs.items():
                if identity(Path(name)) != before:
                    raise ValueError("Native compilation or observation source changed: " + name)
            report.update(status="PASS", compared=len(comparisons), failed=0,
                original_retained_tests=oracle.retained_tests, original_source_inputs=oracle.sources,
                original_source_pins=oracle.original_pins, original_production_bytes_preserved=True,
                original_source_sha256=digest(oracle.original_bytes), test_only_declaration_hex=DECLARATION.hex(),
                original_compiler=oracle.compiler, actual_tools=oracle.actual_tools,
                original_executable={"path": "original-rs46-tests", **oracle.binary_identity},
                original_stages=oracle.stages, native_tool_inputs=native_tool_inputs,
                native_source=native_source, native_artifact=native.receipt,
                retained_native_artifact={"path": "native-rs46.so", **native_artifact_identity},
                scope="finite selected-chunk RS46/CRS1 byte relation; complete original retained tests")
        write_json(output / "report.json", report)
        print(json.dumps({k: report[k] for k in ("schema", "status", "compared", "failed")}, sort_keys=True))
        return 0
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
        write_json(output / "report.json", report)
        print(json.dumps({"status": "FAIL", "error": repr(error), "output": str(output)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
