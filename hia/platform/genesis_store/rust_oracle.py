"""Run the exact original default Settings/Node against a source-bound native bundle.

This hosted verifier is not a runtime dependency.  It admits the complete current
builder closure and exact input corpus before copying source or discovering Cargo.
The original Node and Settings implementations remain byte-for-byte unchanged.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

HERE = Path(__file__).absolute().parent
REPOSITORY = HERE.parents[2]
OWNED = "hia/platform/genesis_store"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
HOOK = "hia_genesis_owner_oracle.rs"
DECLARATION = b'\n#[cfg(test)]\n#[path = "hia_genesis_owner_oracle.rs"]\nmod hia_genesis_owner_oracle;\n'
TEST = "store::hia_genesis_owner_oracle::evaluate"
MARKER = "HIA_GENESIS_OWNER_ORACLE:"
ORIGINAL_TESTS = (
    "store::init_marker_tests::initialization_marker_preserves_exact_context_errors",
    "store::init_marker_tests::initialization_marker_recovery_and_cold_reopen_preserve_state",
    "store::init_marker_tests::initialization_marker_rejects_special_files_and_post_precheck_substitution",
)
REQUIRED_IGNORED_CHILD = "store::init_marker_tests::initialization_marker_special_file_child"
OWNED_REQUIRED = frozenset({
    "README.md", "abi.json", "build.py", "cases.py", "linux_emitter.hepta",
    "native_io.py", "owner_policy.hepta", "source-inputs.json",
    "qualify.py", "rust_oracle.py", "rust_reference.rs", "test_integrity.py",
})
SOURCE_SUFFIXES = frozenset({".py", ".rs", ".json", ".hepta", ".md"})
EXPLICIT_INPUTS = (
    "hia/platform/build.py", "hia/tools/toolchain.py", "hia/components.json",
    "hia/tests/native_support.py", "hia/toolchain.lock.json",
    "hia/qualification/compiler-binding.json",
)
CONFIGURATION_INPUTS = frozenset({
    "config/pon/devnet-v1.json", "config/pon/ledger-v1.json",
    "config/pon/model-family-v1.json", "config/pon/work-profile-v1.json",
})
CANONICAL_ROOTS = (
    "src/node/settings_development.hepta", "src/protocol/state_root_compact.hepta",
)
SKIP_ORIGINAL = frozenset({"target", ".git", "__pycache__", ".pytest_cache"})
INPUT_KEYS = ("name", "timestamp", "workers")
MAX_U64 = (1 << 64) - 1
COMP_SCHEMA = "trnm.native-default-genesis-comparison.v1"
BUILD_SCHEMA = "trnm.hia.default-genesis-store-build.v1"
REPORT_SCHEMA = "trnm.hia.original-default-genesis-differential.v1"
TABLES = frozenset({
    "metadata", "blocks", "deltas", "active", "kv", "reorg",
    "reorg_lifecycle_v1", "steps", "events", "snapshots", "local_pool_metadata",
    "local_pool_groups", "local_pool_rows", "local_pool_removals",
    "peer_replay", "peer_request_audit", "peer_outbox", "ancestry_jump",
})


def need(value, message):
    if not value:
        raise ValueError(message)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON key: " + str(key))
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def load_json(raw):
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid_constant)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def same_json(left, right):
    return canonical_json(left) == canonical_json(right)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw)}


def valid_identity(value):
    return (isinstance(value, dict) and set(value) == {"bytes", "sha256"}
        and type(value["bytes"]) is int and value["bytes"] >= 0
        and isinstance(value["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)


def canonical_root(value):
    path = Path(value).absolute()
    need(path.exists() and path.is_dir() and path.resolve(strict=True) == path,
         "Root is absent, symbolic, or noncanonical: " + str(path))
    current = path
    while current != current.parent:
        need(not current.is_symlink(), "Symlinked root ancestor: " + str(current))
        current = current.parent
    return path


def canonical_path(root, relative, *, directory=False):
    need(isinstance(relative, str) and relative and "\\" not in relative and "\0" not in relative,
         "Invalid relative source path")
    name = Path(relative)
    need(not name.is_absolute() and ".." not in name.parts
         and name.as_posix() == relative and relative != ".",
         "Escaping or noncanonical relative path: " + relative)
    root = canonical_root(root)
    current = root
    for component in name.parts:
        current = current / component
        need(not current.is_symlink(), "Symlinked source path: " + relative)
    metadata = current.stat()
    need(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
         "Not the required regular file/directory: " + relative)
    need(current.resolve(strict=True) == current, "Symbolic source ancestor: " + relative)
    return current


def file_identity(path):
    need(not path.is_symlink() and path.is_file(), "Not a regular artifact: " + str(path))
    size, sha = 0, hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            size += len(block)
            sha.update(block)
    return {"bytes": size, "sha256": sha.hexdigest()}


def write_json(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)


def source_functions(raw):
    declarations = re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)
    bodies = re.findall(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw)
    need(len(declarations) == len(set(declarations)) == len(bodies)
         and set(declarations) == set(bodies), "Ambiguous HIA function boundaries")
    return {name.decode() for name in declarations}


def literal_assignment(raw, name):
    matches = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets):
            need(len(node.targets) == 1, "Ambiguous bound constant: " + name)
            matches.append(ast.literal_eval(node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            matches.append(ast.literal_eval(node.value))
    need(len(matches) == 1, "Missing or ambiguous bound constant: " + name)
    return matches[0]


def complete_source_manifest(repository):
    """Mirror the actual builder's complete closure, without importing its code."""
    need(__debug__, "Optimized Python is not admitted")
    repository = canonical_root(repository)
    captured = {}
    def capture(relative):
        path = canonical_path(repository, relative)
        raw = path.read_bytes()
        need(relative not in captured or captured[relative] == raw,
             "Source changed during closure discovery: " + relative)
        captured[relative] = raw
        return raw

    directory = canonical_path(repository, OWNED, directory=True)
    names = set()
    for path in sorted(directory.iterdir()):
        need(not path.is_symlink(), "Owned symbolic path: " + path.name)
        need(path.name != "__pycache__" and path.suffix != ".pyc", "Stale owned Python cache")
        if path.is_dir():
            # Qualification data may be nested. Executable source is not silently
            # omitted merely because the current builder scans direct children.
            for nested in path.rglob("*"):
                need(not nested.is_symlink(), "Symbolic owned descendant")
                need(nested.name != "__pycache__" and nested.suffix not in
                     {".py", ".pyc", ".rs", ".hepta"}, "Unbound nested owner source/cache")
            continue
        need(path.is_file(), "Nonregular owned source path")
        if path.suffix in SOURCE_SUFFIXES:
            capture(path.relative_to(repository).as_posix())
            names.add(path.name)
    need(OWNED_REQUIRED <= names, "Missing mandatory owner sources: " +
         repr(sorted(OWNED_REQUIRED - names)))
    for relative in EXPLICIT_INPUTS:
        capture(relative)
    pinned = literal_assignment(captured["hia/platform/build.py"], "INPUTS")
    need(isinstance(pinned, (tuple, list)) and pinned
         and all(isinstance(name, str) for name in pinned)
         and len(pinned) == len(set(pinned)), "Malformed pinned platform INPUTS")
    for relative in pinned:
        capture("hia/" + relative)

    declared = load_json(captured[OWNED + "/source-inputs.json"])
    need(isinstance(declared, dict) and set(declared) == {"schema", "files"}
         and declared["schema"] == "trnm.hia.genesis-default-inputs.v1"
         and isinstance(declared["files"], list)
         and all(isinstance(name, str) for name in declared["files"])
         and len(declared["files"]) == len(set(declared["files"])), "Malformed default configuration declaration")
    need(set(declared["files"]) == CONFIGURATION_INPUTS,
         "Default Settings configuration declaration differs")
    for relative in declared["files"]:
        capture(relative)
    components = load_json(captured["hia/components.json"])
    need(isinstance(components, dict) and set(components) == {"schema", "includes"}
         and components["schema"] == "trnm.hia.component-includes.v1"
         and isinstance(components["includes"], dict), "Malformed component manifest")
    def component_path(name):
        need(isinstance(name, str) and name.startswith(("src/", "platform/", "storage/"))
             and name.endswith(".hepta"), "Invalid HIA dependency path")
        return canonical_path(repository, "hia/" + name)
    for name in components["includes"]:
        component_path(name)
    visited = {}
    def visit(name, ancestors):
        component_path(name)
        need(name not in ancestors, "Cyclic canonical HIA dependency")
        if name in visited:
            return visited[name]
        owned = source_functions(capture("hia/" + name))
        selected = set(owned)
        rows = components["includes"].get(name, [])
        need(isinstance(rows, list), "Component includes are not a list")
        for row in rows:
            need(isinstance(row, dict) and set(row) == {"source", "functions"}
                 and isinstance(row["functions"], list) and row["functions"]
                 and all(isinstance(function, str) and
                         re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", function)
                         for function in row["functions"]), "Malformed explicit HIA dependency")
            available = visit(row["source"], (*ancestors, name))
            for function in row["functions"]:
                need(function in available and function not in selected,
                     "Unknown, re-exported, or duplicate canonical function: " + function)
                selected.add(function)
        visited[name] = owned
        return owned
    for root in CANONICAL_ROOTS:
        visit(root, ())
    for relative, raw in captured.items():
        need(canonical_path(repository, relative).read_bytes() == raw,
             "Source changed during closure discovery: " + relative)
    return {name: identity(raw) for name, raw in sorted(captured.items())}


def original_manifest(repository):
    repository = canonical_root(repository)
    found = {}
    for top in ("trillionnium", "config", "formal"):
        directory = canonical_path(repository, top, directory=True)
        for current, children, files in os.walk(directory, followlinks=False):
            children[:] = sorted(name for name in children if name not in SKIP_ORIGINAL)
            for name in children:
                canonical_path(repository, (Path(current) / name).relative_to(repository).as_posix(),
                               directory=True)
            for name in sorted(files):
                if name in SKIP_ORIGINAL:
                    continue
                relative = (Path(current) / name).relative_to(repository).as_posix()
                found[relative] = file_identity(canonical_path(repository, relative))
    need({"trillionnium/Cargo.lock", "trillionnium/Cargo.toml", STORE} <= set(found),
         "Complete original Cargo/store source is absent")
    return dict(sorted(found.items()))


def validate_source_bindings(repository, comparison):
    need(__debug__, "Optimized Python is not admitted")
    need(isinstance(comparison, dict) and comparison.get("schema") == COMP_SCHEMA
         and comparison.get("status") == "PASS", "Native comparison did not pass")
    built = comparison.get("build")
    need(isinstance(built, dict) and built.get("schema") == BUILD_SCHEMA
         and built.get("status") == "PASS", "Native build did not pass")
    supplied = built.get("source_inputs")
    need(isinstance(supplied, dict) and supplied, "Missing native source bindings")
    for relative, item in supplied.items():
        canonical_path(repository, relative)
        need(valid_identity(item), "Malformed source identity: " + relative)
    actual = complete_source_manifest(repository)
    need(supplied == actual, "Incomplete, extra, or changed native source dependency closure")
    need(built.get("source_set_sha256") == digest(canonical_json(actual)),
         "Native source-set digest differs")
    if "source_inputs" in comparison:
        need(comparison["source_inputs"] == actual, "Top-level source bindings differ")
    for key in ("source_inputs_stable",):
        need(built.get(key) is True, "Build lacks successful source fence: " + key)
    for key in ("runtime_host_proxy", "rust_or_interpreter_fallback", "complete_node",
                "successor_block_admission"):
        need(built.get(key) is False, "Unexpected build scope/runtime claim: " + key)
    return actual


def bound_corpus(repository):
    path = canonical_path(repository, OWNED + "/cases.py")
    raw = path.read_bytes()
    tree = ast.parse(raw, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            need(all(alias.name == "json" for alias in node.names), "Unbound case-generator import")
        elif isinstance(node, ast.ImportFrom):
            need(node.module == "__future__", "Unbound case-generator import")
    namespace = {"__file__": str(path), "__name__": "_source_bound_genesis_inputs"}
    exec(compile(tree, str(path), "exec", dont_inherit=True), namespace)
    data = namespace["canonical_bytes"]()
    need(type(data) is bytes and data.endswith(b"\n"), "Canonical corpus must be complete bytes")
    rows = [load_json(line) for line in data.splitlines()]
    generated = list(namespace["cases"]())
    need(same_json(generated, rows) and rows, "Source-defined case iteration differs from canonical bytes")
    names = set()
    for row in rows:
        need(isinstance(row, dict) and set(row) == set(INPUT_KEYS), "Unexpected canonical input fields")
        name, timestamp, workers = (row[key] for key in INPUT_KEYS)
        need(isinstance(name, str) and name and name not in names, "Duplicate/empty canonical case name")
        names.add(name)
        need(timestamp is None or type(timestamp) is int and 0 <= timestamp <= MAX_U64,
             "Invalid source-defined timestamp")
        need(type(workers) is int and 0 <= workers <= MAX_U64, "Invalid source-defined workers")
    need(path.read_bytes() == raw, "Input generator changed during source compilation")
    return data, rows


def bounded_xz(path, expected):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
    remaining, pieces = len(expected), []
    with path.open("rb") as compressed:
        while not decoder.eof:
            block = compressed.read(65536) if decoder.needs_input else b""
            need(block or not decoder.needs_input, "Truncated corpus archive")
            decoded = decoder.decompress(block, max_length=min(1 << 20, remaining + 1))
            need(len(decoded) <= remaining, "Corpus archive exceeds source-defined extent")
            pieces.append(decoded)
            remaining -= len(decoded)
        need(remaining == 0 and not decoder.unused_data and compressed.read(1) == b"",
             "Truncated, concatenated, or trailing corpus archive")
    actual = b"".join(pieces)
    need(actual == expected, "Archived corpus differs from source-defined input bytes")
    return actual


def validate_corpus(repository, bundle, comparison):
    expected, inputs = bound_corpus(repository)
    declared = comparison.get("corpus")
    need(isinstance(declared, dict) and set(declared) == {"path", "raw", "compressed"}
         and declared["path"] == "corpus.jsonl.xz"
         and valid_identity(declared["raw"]) and valid_identity(declared["compressed"]),
         "Malformed native corpus identity")
    need(declared["raw"] == identity(expected), "Native corpus identity differs from bound cases")
    raw_path = canonical_path(bundle, "corpus.jsonl")
    with raw_path.open("rb") as stream:
        raw = stream.read(len(expected) + 1)
    need(raw == expected, "Actual plain corpus differs from source-defined inputs")
    compressed = canonical_path(bundle, "corpus.jsonl.xz")
    need(file_identity(compressed) == declared["compressed"], "Compressed corpus identity differs")
    bounded_xz(compressed, expected)
    cases = comparison.get("cases")
    need(type(comparison.get("case_count")) is int and comparison["case_count"] == len(inputs)
         and isinstance(cases, list) and len(cases) == len(inputs), "Missing or extra native cases")
    for actual, item in zip(cases, inputs, strict=True):
        need(isinstance(actual, dict) and
             same_json({key: actual.get(key) for key in INPUT_KEYS}, item), "Native cases reordered or inputs changed")
    return expected, inputs


def native_decoder(repository):
    """Compile only the bound pure observation functions, never Session/build."""
    path = canonical_path(repository, OWNED + "/native_io.py")
    source = path.read_bytes()
    names = {"identity", "parse_record", "parse_success"}
    selected = [node for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in selected} == names and len(selected) == len(names),
         "Native observation decoder changed its public function boundary")
    module = ast.Module(body=selected, type_ignores=[])
    namespace = {"json": json, "struct": struct, "hashlib": hashlib, "need": need}
    exec(compile(module, str(path), "exec", dont_inherit=True), namespace)
    need(path.read_bytes() == source, "Native observation decoder changed")
    return namespace["parse_success"]


def decode_hex(value, *, limit):
    need(isinstance(value, str) and len(value) <= limit * 2
         and len(value) % 2 == 0 and re.fullmatch("[0-9a-f]*", value) is not None,
         "Invalid or oversized native hex field")
    return bytes.fromhex(value)


def process_receipt(process, item, build, *, mode, code, stdout):
    need(isinstance(process, dict) and process.get("schema") == "trnm.native-genesis-process.v1",
         "Missing actual native process receipt")
    need(type(process.get("pid")) is int and process["pid"] > 0
         and process.get("timed_out") is False and type(process.get("exit_code")) is int
         and process["exit_code"] == code,
         "Native process did not reach the required terminal status")
    for key, value in (("timestamp", item["timestamp"]), ("workers", item["workers"]), ("mode", mode)):
        need(type(process.get(key)) is type(value) and process[key] == value,
             "Native process input differs: " + key)
    need(process.get("child_budget_seconds") == 240 and process.get("cleanup_budget_seconds") == 3,
         "Native process budget was changed")
    need(type(process.get("elapsed_ns")) is int and process["elapsed_ns"] >= 0,
         "Missing native process duration")
    need(process.get("executable") == {key: build["executable"][key] for key in ("bytes", "sha256")},
         "Native process executable differs from the built image")
    need(process.get("stdout") == identity(stdout), "Native stdout identity differs")
    stderr = decode_hex(process.get("stderr_hex"), limit=56)
    need(process.get("stderr") == identity(stderr), "Native stderr identity differs")
    need(process.get("events") == [], "Semantic corpus unexpectedly used diagnostic pause gates")
    need(valid_identity(process.get("stdin")), "Missing native bootstrap input identity")
    attempted = decode_hex(process.get("stdin_hex"), limit=96)
    sent = decode_hex(process.get("stdin_actual_hex"), limit=96)
    written = process.get("stdin_actual_write_bytes")
    need(type(written) is int and 64 <= written <= len(attempted)
         and sent == attempted[:written] and len(sent) == written,
         "Actual native input is not the recorded complete bootstrap prefix")
    need(process["stdin"] == identity(attempted), "Native attempted input hash differs")
    need(attempted[:8] == b"NGBOOT01" and len(attempted) >= 64, "Native bootstrap framing differs")
    descriptor, actual_mode, option, timestamp, workers, gate_w, gate_r = struct.unpack("<7Q", attempted[8:64])
    need(3 <= descriptor <= 2147483647 and actual_mode == mode
         and option == int(item["timestamp"] is not None)
         and timestamp == (item["timestamp"] if item["timestamp"] is not None else 0)
         and workers == item["workers"] and gate_w == gate_r == MAX_U64,
         "Actual native bootstrap bytes differ from the canonical input")
    suffix = ((b"NGCMD001" + struct.pack("<Q", 1)) if code != 67 else b"") \
             + b"NGCMD001" + struct.pack("<Q", 2)
    need(attempted[64:] == suffix, "Actual native command suffix differs")
    if code == 0:
        need(written == len(attempted) == 96, "Successful native history did not receive all commands")
    if code == 0:
        need(stderr == b"" and process.get("diagnostic") is None, "Successful native process emitted error")
    else:
        need(stdout == b"" and len(stderr) == 56, "Native refusal has output or lacks exact diagnostic")
        parsed = list(struct.unpack("<7Q", stderr))
        need(same_json(process.get("diagnostic"), parsed) and parsed[0] == code, "Native diagnostic fields differ")
    return list(struct.unpack("<7Q", stderr)) if stderr else None


def validate_native_cases(repository, comparison):
    decode = native_decoder(repository)
    built = comparison["build"]
    need(isinstance(built.get("executable"), dict)
         and valid_identity({key: built["executable"].get(key) for key in ("bytes", "sha256")}),
         "Missing native ELF identity")
    processes_seen = set()
    for item in comparison["cases"]:
        need(item.get("original_error_strings_equivalent") is False,
             "Native errors must not claim Rust Display/source equivalence")
        processes = item.get("processes")
        need(isinstance(processes, list), "Native process history is absent")
        if item.get("status") == "OK":
            need(len(processes) == 3 and item.get("error_phase") is None
                 and item.get("native_error_diagnostic") is None, "Malformed successful native case")
            decoded = []
            for key, process, mode in (("first", processes[0], 0), ("reopened", processes[2], 1)):
                snapshot = item.get(key)
                need(isinstance(snapshot, dict), "Missing complete native snapshot")
                raw = (decode_hex(snapshot.get("opened_receipt_hex"), limit=256)
                       + decode_hex(snapshot.get("read_header_hex"), limit=64)
                       + decode_hex(snapshot.get("record_hex"), limit=16896))
                actual, record = decode(raw)
                need(same_json(actual, snapshot), "Native snapshot differs from its complete actual output")
                need(struct.unpack_from("<Q", raw, 8)[0] == mode
                     and struct.unpack_from("<Q", raw, 24)[0] == item["workers"],
                     "Native opened mode/workers differ")
                process_receipt(process, item, built, mode=mode, code=0, stdout=raw)
                decoded.append(record)
            need(decoded[0] == decoded[1] and item.get("full_reopen_record_equal") is True
                 and item.get("cold_namespace_unchanged") is True, "Native cold reopen differs")
            probe = item.get("held_lock_probe")
            need(isinstance(probe, dict) and set(probe) == {"opened", "process"}
                 and probe["opened"] is False and same_json(probe["process"], processes[1]),
                 "Missing independent held-owner lock refusal")
            diagnostic = process_receipt(processes[1], item, built, mode=1, code=67, stdout=b"")
            need(diagnostic[1] == 15 and diagnostic[2] == (1 << 64) - 11
                 and diagnostic[3:] == [0, 0, 0, 0], "Native held-lock failure order differs")
        elif item.get("status") == "ERR":
            need(len(processes) == 1 and item.get("first") is None and item.get("reopened") is None
                 and item.get("held_lock_probe") is None and item.get("namespace_unchanged") is True,
                 "Malformed native constructor/worker refusal")
            diagnostic = process_receipt(processes[0], item, built, mode=0, code=68, stdout=b"")
            need(same_json(item.get("native_error_diagnostic"), diagnostic) and diagnostic[1] == 2
                 and diagnostic[3:] == [0, 0, 0, 0], "Native construction refusal mutated authority")
            last = diagnostic[2]
            if last >= 4294967280:
                need(last <= 4294967295, "Unexpected native constructor error representation")
                phase = "Settings::development"
            else:
                need(576 <= last <= 16384, "Worker refusal lacks successful private constructor result")
                phase = "first.Node::open"
            need(item.get("error_phase") == phase, "Native error phase was not derived from the actual diagnostic")
        else:
            raise ValueError("Unknown native case outcome")
        for process in processes:
            # PID reuse is legal; receipt directories, not numeric PIDs, identify runs.
            path = process.get("path")
            need(isinstance(path, str) and path and path not in processes_seen,
                 "Native process receipt was duplicated")
            processes_seen.add(path)
    return {"cases": len(comparison["cases"]), "processes": len(processes_seen)}


def validate_native_verification(report, comparison):
    """A PASS requires the actual post-run source fence and successful cleanup."""
    built = comparison["build"]
    expected = {
        "source_after": {"status": "PASS", "source_set_sha256": built["source_set_sha256"],
                         "native_source_files": len(built["source_inputs"]),
                         "original_source_files": len(built["original_sources"])},
        "primary_error": None,
        "cleanup_errors": [],
    }
    need(same_json(report.get("verification"), expected),
         "Native final verification is missing, failed, or bound to different sources")


def validate_bundle(repository, bundle):
    """All validation here precedes Rust discovery, source copying, and execution."""
    need(__debug__, "Optimized Python is not admitted")
    repository, bundle = canonical_root(repository), canonical_root(bundle)
    raw = canonical_path(bundle, "native-comparison.json").read_bytes()
    comparison = load_json(raw)
    sources = validate_source_bindings(repository, comparison)
    corpus, inputs = validate_corpus(repository, bundle, comparison)
    original = original_manifest(repository)
    supplied = comparison["build"].get("original_sources")
    need(isinstance(supplied, dict) and all(valid_identity(value) for value in supplied.values())
         and supplied == original, "Complete original source differs from native qualification")
    native_counts = validate_native_cases(repository, comparison)
    report_raw = canonical_path(bundle, "native-report.json").read_bytes()
    report = load_json(report_raw)
    need(isinstance(report, dict) and report.get("status") == "PASS",
         "Native full qualification report did not pass")
    need(report.get("schema") == "trnm.native-default-genesis-qualification.v1"
         and report.get("suite") == "semantic"
         and same_json(report.get("build"), comparison["build"]),
         "Native report/schema/build differs from comparison")
    need(type(report.get("controls_total")) is int and report["controls_total"] == len(inputs)
         and type(report.get("real_native_processes")) is int
         and report["real_native_processes"] == native_counts["processes"],
         "Native qualification totals differ")
    expected_controls = [{"name": item["name"], "status": "PASS", "case": item}
                         for item in comparison["cases"]]
    need(same_json(report.get("controls"), expected_controls), "Native report cases differ")
    details = report.get("details")
    need(isinstance(details, dict) and details.get("semantic_cases") == len(inputs)
         and same_json(details.get("corpus"), comparison["corpus"]),
         "Native report corpus binding differs")
    need(report.get("native_child_budget_seconds") == 240
         and report.get("cleanup_budget_seconds") == 3, "Native report budgets changed")
    expected_scope = {"native_runtime": True, "runtime_host_proxy": False,
        "full_genesis_file_reads": True, "physical_power_loss": False,
        "os_page_cache_flushed": False, "continuous_hostile_same_uid_safety": False,
        "successor_admission": False, "arbitrary_commit": False, "complete_node": False,
        "original_rust": "NOT_RUN"}
    need(same_json(report.get("scope"), expected_scope), "Native qualification scope differs")
    validate_native_verification(report, comparison)
    artifact_map = {name: file_identity(canonical_path(bundle, name)) for name in (
        "native-comparison.json", "native-report.json", "corpus.jsonl", "corpus.jsonl.xz")}
    need(canonical_path(bundle, "native-comparison.json").read_bytes() == raw,
         "Native comparison changed during admission")
    return {"comparison": comparison, "comparison_raw": raw, "source_inputs": sources,
            "original_sources": original, "corpus_raw": corpus, "inputs": inputs,
            "native_counts": native_counts, "bundle_artifacts": artifact_map}


def decode_state(snapshot):
    rows = snapshot["rows"]
    need(isinstance(rows, list) and len(rows) == 7, "Native default State does not contain seven rows")
    decoded = {}
    for row in rows:
        need(isinstance(row, dict) and set(row) == {"key", "value_hex"}
             and isinstance(row["key"], str) and row["key"] not in decoded,
             "Native State contains malformed/duplicate rows")
        decoded[row["key"]] = load_json(decode_hex(row["value_hex"], limit=4096))
    need([row["key"] for row in rows] == sorted(decoded), "Native State row order changed")
    return decoded


def expected_logical_settings(snapshot):
    settings = snapshot["settings"]
    state = decode_state(snapshot)
    evaluators = settings["evaluators"]
    need(isinstance(evaluators, list) and len(evaluators) == 3
         and evaluators == sorted(set(evaluators)), "Native evaluator set differs from canonical order")
    need(settings["genesis_time"] == settings["params"]["genesis_timestamp"],
         "Native Settings timestamp fields disagree")
    work = [(key, value) for key, value in state.items() if key.startswith("work:")]
    need(work == [("work:" + settings["task"], True)], "Native maintenance identity differs from actual State")
    return {
        "params": settings["params"], "params_canonical_hex": settings["params_canonical_hex"],
        "network_hex": snapshot["network"], "parameters_hex": snapshot["parameters"],
        "genesis_hex": snapshot["genesis"], "initial_state": state,
        "initial_root_hex": snapshot["state_root"], "family_hex": settings["family"],
        "plan_hex": settings["plan"], "evaluators": evaluators, "fees": settings["fees"],
        "model_registry": settings["model_registry"],
        "model_registry_canonical_hex": settings["model_registry_canonical_hex"],
        "has_task_windows": False, "has_operator_bootstrap": False,
        "has_operator_material": False, "has_checkpoint_tile_paths": False,
        "is_permanent_account_growth_v2": False, "pq_enabled": False,
    }


def compare_case(native, original):
    """Compare complete logical facts; preserve original SQL/error details unchanged."""
    differences = []
    def equal(path, expected, actual):
        if not same_json(expected, actual):
            differences.append({"field": path, "native": expected, "original": actual})
    need(isinstance(original, dict), "Original case is not an observation object")
    for key in INPUT_KEYS:
        equal(key, native[key], original.get(key))
    equal("status", native["status"], original.get("status"))
    equal("error_phase", native["error_phase"], original.get("error_phase"))
    equal("arbitrary_successor_or_delta_supplied", False,
          original.get("arbitrary_successor_or_delta_supplied"))
    equal("cross_format_sqlite_compatibility_claimed", False,
          original.get("cross_format_sqlite_compatibility_claimed"))
    attempted = original.get("public_and_observation_invocations_attempted")
    need(isinstance(attempted, list) and all(isinstance(value, str) for value in attempted),
         "Original invocation history is missing")

    if native["status"] == "ERR":
        equal("first", None, original.get("first"))
        equal("reopened", None, original.get("reopened"))
        equal("held_lock_probe", None, original.get("held_lock_probe"))
        equal("full_reopen_observation_equal", None, original.get("full_reopen_observation_equal"))
        error = original.get("error")
        need(isinstance(error, dict) and set(error) ==
             {"display", "code", "kind", "requires_owner_stop", "source_displays"}
             and isinstance(error["display"], str) and error["display"]
             and isinstance(error["kind"], str) and type(error["requires_owner_stop"]) is bool
             and (error["code"] is None or isinstance(error["code"], str))
             and isinstance(error["source_displays"], list)
             and all(isinstance(value, str) for value in error["source_displays"]),
             "Original exact error observation is missing")
        if native["error_phase"] == "Settings::development":
            equal("constructed", None, original.get("constructed"))
            equal("invocation_order", ["Settings::development"], attempted)
        else:
            need(isinstance(original.get("constructed"), dict), "Worker refusal lost actual Settings observation")
            equal("invocation_order", ["Settings::development", "observe_actual_Settings", "first.Node::open"],
                  attempted)
        return differences

    equal("error", None, original.get("error"))
    equal("full_reopen_observation_equal", True, original.get("full_reopen_observation_equal"))
    equal("full_original_reopen", original.get("first"), original.get("reopened"))
    settings = original.get("constructed")
    need(isinstance(settings, dict), "Original Settings snapshot is absent")
    expected_settings = expected_logical_settings(native["first"])
    equal("Settings.field_set", sorted((*expected_settings, "initial_state_canonical_hex")), sorted(settings))
    for key, value in expected_settings.items():
        equal("Settings." + key, value, settings.get(key))
    original_canonical = settings.get("initial_state_canonical_hex")
    decode_hex(original_canonical, limit=65536)
    equal("held_lock_probe", {
        "opened": False,
        "error": {"display": "WRITER_BUSY", "code": None, "kind": "Unclassified",
                  "requires_owner_stop": False, "source_displays": []},
    }, original.get("held_lock_probe"))

    sequence = ["Settings::development", "observe_actual_Settings", "first.Node::open"]
    observation_calls = ("Node::read_active", "Node::record", "Node::slot", "Settings::state_root",
        "SQL.kv", "SQL.blocks", "SQL.active", "SQL.snapshots", "SQL.metadata",
        "SQL.all_catalog_counts", "SQL.schema")
    sequence += ["first." + name for name in observation_calls]
    sequence += ["held_lock.Node::open", "first.drop_Node", "reopen.Node::open"]
    sequence += ["reopen." + name for name in observation_calls]
    sequence += ["reopen.drop_Node"]
    equal("invocation_order", sequence, attempted)

    for pass_name in ("first", "reopened"):
        observed = original.get(pass_name)
        snapshot = native[pass_name]
        need(isinstance(observed, dict), "Original complete open/reopen observation is absent")
        state = decode_state(snapshot)
        rows = snapshot["rows"]
        equal(pass_name + ".legacy_backend", True, observed.get("is_legacy_backend"))
        equal(pass_name + ".workers", native["workers"], observed.get("workers"))
        for key, native_key in (("tip_hex", "active_tip"), ("generation", "generation"),
                                ("slot", "slot"), ("state_root_hex", "state_root")):
            equal(pass_name + "." + key, snapshot[native_key], observed.get(key))
        equal(pass_name + ".complete_state", state, observed.get("complete_state"))
        equal(pass_name + ".complete_state_canonical_hex", original_canonical,
              observed.get("complete_state_canonical_hex"))
        equal(pass_name + ".read_state_equals_settings_initial", True,
              observed.get("read_state_equals_settings_initial"))
        logical = [{"key": row["key"], "key_hex": row["key"].encode().hex(),
                    "value": state[row["key"]], "value_canonical_hex": row["value_hex"]} for row in rows]
        equal(pass_name + ".logical_rows", logical, observed.get("logical_rows"))
        kv = [{"slot": snapshot["slot"], "key": row["key"], "key_hex": row["key"].encode().hex(),
               "value_hex": row["value_hex"], "value": state[row["key"]],
               "key_sql_type": "text", "value_sql_type": "blob", "canonical_exact": True} for row in rows]
        equal(pass_name + ".actual_kv_rows", kv, observed.get("actual_kv_rows"))
        record = {"parent_hex": snapshot["parent"], "height": snapshot["height"],
                  "chainwork_hex": snapshot["chainwork"], "state_root_hex": snapshot["state_root"]}
        equal(pass_name + ".record", record, observed.get("record"))
        blocks = [{"id_hex": snapshot["genesis"], **record, "packet_hex": snapshot["packet"]}]
        equal(pass_name + ".actual_block_rows", blocks, observed.get("actual_block_rows"))
        active = [{"singleton": 1, "tip_hex": snapshot["active_tip"],
                   "generation": snapshot["generation"], "state_slot": snapshot["slot"]}]
        equal(pass_name + ".actual_active_rows", active, observed.get("actual_active_rows"))
        snapshots = [{"block_hex": snapshot["genesis"], "state_hex": original_canonical,
                      "state": state, "canonical_exact": True,
                      "equals_complete_read_active_state": True,
                      "equals_complete_read_active_canonical": True, "names_active_tip": True}]
        equal(pass_name + ".actual_snapshot_rows", snapshots, observed.get("actual_snapshot_rows"))
        counts = dict(snapshot["collections"], metadata=3, active=1, kv=len(rows))
        equal(pass_name + ".table_set", sorted(TABLES), sorted(counts))
        equal(pass_name + ".actual_table_counts", counts, observed.get("actual_table_counts"))
        original_schema_id = observed.get("original_selected_schema_id_hex")
        need(len(decode_hex(original_schema_id, limit=32)) == 32, "Original SQL schema identity is missing")
        metadata = [{"key": key, "value_hex": value, "key_sql_type": "text", "value_sql_type": "blob"}
                    for key, value in (("genesis", snapshot["genesis"]),
                        ("parameters", snapshot["parameters"]), ("schema", original_schema_id))]
        equal(pass_name + ".actual_metadata_rows", metadata, observed.get("actual_metadata_rows"))
        need(isinstance(observed.get("original_sql_schema"), dict) and observed["original_sql_schema"]
             and all("table:" + name in observed["original_sql_schema"] for name in TABLES)
             and all(isinstance(key, str) and isinstance(value, str)
                     for key, value in observed["original_sql_schema"].items()),
             "Original actual SQLite schema observation is absent")
        equal(pass_name + ".schema_cross_format_equivalence_claimed", False,
              observed.get("schema_cross_format_equivalence_claimed"))
    return differences


def run_command(argv, cwd, output, label, stages, *, timeout, environment):
    """Keep actual streams even for launch, timeout, drain, and nonzero failures."""
    directory = output / label
    directory.mkdir(mode=0o700)
    receipt = {"stage": label, "argv": [str(item) for item in argv], "cwd": str(cwd),
               "wall_limit_seconds": timeout, "cleanup_limit_seconds": 10,
               "started_monotonic_ns": time.monotonic_ns(), "exit_code": None,
               "timed_out": False, "launch_error": None, "cleanup_error": None}
    stdout_path, stderr_path = directory / "stdout.raw", directory / "stderr.raw"
    process = None
    primary = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True, umask=0o077)
            receipt["pid"] = process.pid
            try:
                receipt["exit_code"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                primary = error
                receipt["timed_out"] = True
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        receipt["cleanup_signal"] = "SIGKILL_SENT"
                    except ProcessLookupError:
                        receipt["cleanup_signal"] = "ALREADY_EXITED"
                    receipt["exit_code"] = process.wait(timeout=10)
                except BaseException as cleanup_error:
                    receipt["cleanup_error"] = repr(cleanup_error)
        except BaseException as error:
            if primary is None:
                primary = error
            receipt["launch_error"] = repr(error)
            if process is not None and process.poll() is None:
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    receipt["exit_code"] = process.wait(timeout=10)
                except BaseException as cleanup_error:
                    receipt["cleanup_error"] = repr(cleanup_error)
    receipt["finished_monotonic_ns"] = time.monotonic_ns()
    receipt["elapsed_ns"] = receipt["finished_monotonic_ns"] - receipt["started_monotonic_ns"]
    receipt["stdout"] = file_identity(stdout_path)
    receipt["stderr"] = file_identity(stderr_path)
    receipt["output_files_closed"] = True
    receipt["status"] = "PASS" if primary is None and receipt["exit_code"] == 0 and not receipt["cleanup_error"] else "FAIL"
    write_json(directory / "receipt.json", receipt)
    stages.append(receipt)
    need(receipt["status"] == "PASS", "Actual subprocess failed; retained stage " + label)
    return stdout_path.read_bytes(), receipt


def assert_test_executed(raw, name):
    text = raw.decode()
    need(re.search(r"(?m)^running 1 test\r?$", text) is not None
         and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None,
         "Actual exact test did not execute once: " + name)


def parse_original_rows(raw):
    rows = []
    for line in raw.decode().splitlines():
        if MARKER in line:
            prefix, value = line.split(MARKER, 1)
            need(prefix in ("", "test " + TEST + " ... "), "Unexpected original oracle output framing")
            rows.append(load_json(value))
    return rows


def safe_target(value, output, repository, bundle, isolated):
    path = Path(value).absolute() if value else output / "cargo-target"
    need(path == path.resolve(), "Symbolic Cargo target")
    for source in (repository, bundle, isolated):
        need(path != source and source not in path.parents, "Cargo target is inside bound input source")
    # An external shared target is permitted only through the caller's serialized
    # ownership. Its previous cached binary is never used as evidence.
    return path


def capture_serde_graph(metadata, isolated, output):
    import io
    import tarfile
    import tomllib
    need(isinstance(metadata, dict) and isinstance(metadata.get("packages"), list)
         and isinstance(metadata.get("resolve"), dict), "Cargo metadata graph is missing")
    packages = [row for row in metadata["packages"] if row.get("name") == "serde_json"]
    need(len(packages) == 1 and packages[0].get("version") == "1.0.149",
         "The original locked serde_json package changed")
    package = packages[0]
    nodes = [row for row in metadata["resolve"].get("nodes", []) if row.get("id") == package["id"]]
    need(len(nodes) == 1 and {"default", "std"} <= set(nodes[0].get("features", [])),
         "The actual serde_json feature graph differs")
    cargo_lock = tomllib.loads(canonical_path(isolated, "trillionnium/Cargo.lock").read_text())
    locked = [row for row in cargo_lock["package"] if row.get("name") == "serde_json"]
    need(len(locked) == 1 and locked[0].get("version") == "1.0.149"
         and locked[0].get("source") == package.get("source")
         and isinstance(package.get("source"), str) and package["source"].startswith("registry+"),
         "Serde package source differs from Cargo.lock")
    checksum = locked[0].get("checksum")
    need(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None,
         "Locked registry archive checksum is missing")
    manifest = Path(package["manifest_path"]).absolute()
    crate = canonical_root(manifest.parent)
    need(manifest.name == "Cargo.toml" and crate.name == package["name"] + "-" + package["version"]
         and crate.parent.parent.name == "src" and crate.parent.parent.parent.name == "registry",
         "Unadmitted registry source/cache layout")
    canonical_path(crate, manifest.name)
    cache = canonical_root(crate.parent.parent.parent / "cache" / crate.parent.name)
    archive = canonical_path(cache, crate.name + ".crate")

    def archive_sources():
        # Hash and parse the same bounded immutable byte snapshot. A normal Cargo
        # registry unpack has no vendor .cargo-checksum.json; its .crate is the
        # object authenticated by the original Cargo.lock checksum.
        need(canonical_root(crate) == crate and canonical_root(cache) == cache,
             "Registry source/cache identity became symbolic")
        current_archive = canonical_path(cache, crate.name + ".crate")
        with current_archive.open("rb") as stream:
            raw = stream.read((16 << 20) + 1)
        need(len(raw) <= 16 << 20 and digest(raw) == checksum,
             "Actual registry archive differs from the original Cargo.lock checksum")
        found, total = {}, 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as packed:
            for member in packed:
                parts = member.name.split("/")
                need(member.isfile() and len(parts) >= 2 and parts[0] == crate.name
                     and all(part not in ("", ".", "..") for part in parts)
                     and "\\" not in member.name and "\x00" not in member.name,
                     "Nonregular or escaping registry archive member")
                relative = "/".join(parts[1:])
                need(relative not in found and relative != ".cargo-ok",
                     "Duplicate or Cargo-generated registry archive member")
                need(0 <= member.size <= 8 << 20 and len(found) < 4096,
                     "Registry archive member exceeds the source admission bound")
                total += member.size
                need(total <= 64 << 20, "Registry archive exceeds the source admission bound")
                with packed.extractfile(member) as stream:
                    data = stream.read(member.size + 1)
                need(len(data) == member.size, "Truncated registry archive member")
                found[relative] = identity(data)
        need("Cargo.toml" in found and "src/lib.rs" in found,
             "Incomplete locked registry archive")
        return identity(raw), found

    archive_identity, archived = archive_sources()

    def capture():
        observed_archive, observed_members = archive_sources()
        need(observed_archive == archive_identity and observed_members == archived,
             "Locked registry archive changed after admission")
        found = {}
        for path in sorted(crate.rglob("*")):
            relative = path.relative_to(crate).as_posix()
            need(not path.is_symlink(), "Symbolic serde dependency source")
            if path.is_file():
                found[relative] = file_identity(canonical_path(crate, relative))
            else:
                need(path.is_dir(), "Nonregular serde dependency source")
        need(set(archived) <= set(found) and set(found) - set(archived) <= {".cargo-ok"},
             "Missing or unexpected unpacked registry source")
        for name, expected in archived.items():
            need(found[name] == expected, "Serde file differs from the locked registry archive: " + name)
        if ".cargo-ok" in found:
            need(found[".cargo-ok"]["bytes"] <= 1024 and
                 same_json(load_json(canonical_path(crate, ".cargo-ok").read_bytes()), {"v": 1}),
                 "Unadmitted Cargo-generated readiness marker")
        return found

    sources = capture()
    binding = {"package": package, "resolve_node": nodes[0], "locked_package": locked[0],
               "crate_directory": str(crate), "crate_sources": sources,
               "crate_source_set_sha256": digest(canonical_json(sources)),
               "registry_archive": {"path": str(archive), **archive_identity},
               "archive_source_files": archived,
               "archive_source_set_sha256": digest(canonical_json(archived)),
               "optional_cargo_generated_files": {
                   name: sources[name] for name in (".cargo-ok",) if name in sources},
               "vendor_checksum_file_required": False}
    write_json(output / "serde-json-source-before.json", binding)
    return binding, capture


def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise RuntimeError("Optimized Python is not admitted by this verifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    repository = canonical_root(args.repository)
    script = canonical_path(repository, OWNED + "/rust_oracle.py")
    need(script == Path(__file__).absolute(), "Run the exact oracle from the selected repository")
    bundle = canonical_root(args.bundle)
    output = args.output.absolute()
    need(output == output.resolve() and not output.exists() and not output.is_symlink(),
         "Use a fresh, nonsymbolic output directory")
    for source in (repository, bundle):
        need(output != source and source not in output.parents, "Output is inside bound input source")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic_ns()
    base = {
        "schema": REPORT_SCHEMA, "production_runtime_dependency": False,
        "complete_node": False, "successor_admission": False, "arbitrary_commit": False,
        "cross_format_sqlite_compatibility_claimed": False,
        "cross_format_namespace_error_parity": False,
        "original_error_strings_equivalent": False, "physical_power_loss": False,
        "original_production_function_bytes_preserved": True,
    }
    stages, source_fences, controls, retained = [], [], [], []
    primary_error, final_errors, missing = None, [], []
    admitted = None
    isolated = output / "isolated-source"
    copied = False
    original_store = hook = corpus_path = None
    isolated_expected = binary = binary_identity = compiled_binary = None
    serde = serde_capture = serde_artifact = compiler = None
    partial_original = []
    status = "FAIL"

    def fence(label):
        observations, errors = {}, []
        def check(name, operation):
            try:
                observations[name] = operation()
            except BaseException as error:
                errors.append({"check": name, "error": repr(error)})
        if admitted is not None:
            def native_source():
                value = validate_source_bindings(repository, admitted["comparison"])
                need(value == admitted["source_inputs"], "Source closure changed after admission")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            def original_source():
                value = original_manifest(repository)
                need(value == admitted["original_sources"], "Original production source changed")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            def artifacts():
                observed = {name: file_identity(canonical_path(bundle, name))
                            for name in admitted["bundle_artifacts"]}
                need(observed == admitted["bundle_artifacts"], "Bound native bundle changed")
                raw, rows = bound_corpus(repository)
                need(raw == admitted["corpus_raw"] and rows == admitted["inputs"], "Canonical input generator changed")
                return {"status": "MATCH", "artifacts": observed}
            check("native_source", native_source)
            check("original_source", original_source)
            check("bundle_and_corpus", artifacts)
        if copied:
            def isolated_source():
                value = original_manifest(isolated)
                need(value == isolated_expected, "Isolated original/hook source changed or gained files")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            check("isolated_original_with_only_declared_hook", isolated_source)
            def actual_corpus():
                value = file_identity(canonical_path(output, "corpus.jsonl"))
                need(value == admitted["comparison"]["corpus"]["raw"], "Actual original corpus changed")
                return {"status": "MATCH", **value}
            check("actual_original_corpus", actual_corpus)
        if binary is not None:
            def executable():
                value = file_identity(canonical_path(output, "original-test-binary"))
                need(value == binary_identity, "Independent original test binary changed")
                return {"status": "MATCH", **value}
            check("independent_executable", executable)
        if serde_capture is not None:
            def dependency():
                value = serde_capture()
                need(value == serde["crate_sources"], "Locked actual serde dependency sources changed")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            check("actual_serde_dependency", dependency)
        receipt = {"label": label, "status": ("NOT_REACHED" if admitted is None else "PASS") if not errors else "FAIL",
                   "observations": observations, "errors": errors}
        source_fences.append(receipt)
        write_json(output / (label + ".json"), receipt)
        need(not errors, "Final source/binary fence failed: " + repr(errors))

    try:
        admitted = validate_bundle(repository, bundle)
        write_json(output / "admission.json", {
            "status": "ADMITTED_NOT_ORIGINAL_EXECUTED",
            "source_inputs": admitted["source_inputs"], "original_sources": admitted["original_sources"],
            "native_source_set_sha256": admitted["comparison"]["build"]["source_set_sha256"],
            "bundle_artifacts": admitted["bundle_artifacts"], "native_counts": admitted["native_counts"],
            "corpus": admitted["comparison"]["corpus"]["raw"],
        })
        fence("source-before")
        missing = [name for name in ("cargo", "rustc") if shutil.which(name) is None]
        if missing:
            status = "NOT_RUN"
            raise RuntimeError("Required actual Rust tools are unavailable: " + repr(missing))
        # A wrapper, preload, or encoded compiler flag would replace the selected
        # build invocation. Refuse it rather than silently changing the environment.
        for variable in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                         "CARGO_ENCODED_RUSTFLAGS", "LD_PRELOAD"):
            need(not os.environ.get(variable), "Unadmitted compiler/runtime override: " + variable)
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        corpus_path = output / "corpus.jsonl"
        with corpus_path.open("xb") as stream:
            stream.write(admitted["corpus_raw"])
        hook = canonical_path(repository, OWNED + "/rust_reference.rs").read_bytes()
        need(identity(hook) == admitted["source_inputs"][OWNED + "/rust_reference.rs"],
             "Original hook is not the native-bound source")
        isolated.mkdir(mode=0o700)
        for relative, expected in admitted["original_sources"].items():
            original_path = canonical_path(repository, relative)
            destination = isolated / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with original_path.open("rb") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1 << 20)
            need(file_identity(destination) == expected, "Source changed while copying: " + relative)
        store = isolated / STORE
        original_store = store.read_bytes()
        need(b"mod hia_genesis_owner_oracle" not in original_store, "Original store already contains oracle")
        hook_path = store.parent / HOOK
        with hook_path.open("xb") as stream:
            stream.write(hook)
        with store.open("ab") as stream:
            stream.write(DECLARATION)
        isolated_expected = dict(admitted["original_sources"])
        isolated_expected[STORE] = identity(original_store + DECLARATION)
        isolated_expected[hook_path.relative_to(isolated).as_posix()] = identity(hook)
        copied = True
        fence("isolated-source-before")
        target = safe_target(args.target_dir, output, repository, bundle, isolated)
        version, _ = run_command(["rustc", "-Vv"], isolated, output, "rustc-version", stages,
                                 timeout=15, environment=environment)
        compiler = version.decode()
        need(re.search(r"(?m)^host: x86_64-unknown-linux-gnu$", compiler) is not None,
             "Original target does not implement the native x86-64 u64 worker domain")
        metadata_raw, _ = run_command(["cargo", "metadata", "--locked", "--format-version=1",
            "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path",
            str(isolated / "trillionnium/Cargo.toml")], isolated, output,
            "cargo-original-metadata", stages, timeout=120, environment=environment)
        serde, serde_capture = capture_serde_graph(load_json(metadata_raw), isolated, output)
        built_raw, _ = run_command(["cargo", "test", "--locked", "--manifest-path",
            str(isolated / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node", "--lib", "--no-run",
            "--message-format=json", "--target-dir", str(target)], isolated, output,
            "cargo-original-test-build", stages, timeout=900, environment=environment)
        events = [load_json(line) for line in built_raw.splitlines() if line.startswith(b"{")]
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
        serde_rows = [event for event in artifacts if event.get("target", {}).get("name") == "serde_json"]
        binaries = [event for event in artifacts if event.get("target", {}).get("name") == "trnm_pon_node"
                    and event.get("executable") and event.get("profile", {}).get("test") is True]
        need(len(serde_rows) == 1 and len(binaries) == 1, "Expected one serde artifact and one actual Node test binary")
        serde_artifact = serde_rows[0]
        need(serde_artifact["package_id"] == serde["package"]["id"]
             and set(serde_artifact.get("features", [])) == {"default", "std"},
             "Actually compiled serde package/features differ from the locked metadata graph")
        compiled_binary = Path(binaries[0]["executable"]).absolute()
        need(compiled_binary == compiled_binary.resolve(strict=True)
             and target.resolve() in compiled_binary.parents, "Cargo reported a binary outside its isolated target")
        binary_identity = file_identity(compiled_binary)
        binary = output / "original-test-binary"
        with compiled_binary.open("rb") as source, binary.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1 << 20)
        binary.chmod(0o500)
        need(file_identity(binary) == binary_identity and file_identity(compiled_binary) == binary_identity,
             "Original independent binary copy differs")
        write_json(output / "original-binary-before.json", {
            "source": str(compiled_binary), "retained": str(binary), **binary_identity,
            "independent_copy_before_all_tests": True, "mode": stat.S_IMODE(binary.stat().st_mode)})
        fence("compiled-source-and-binary-before")
        listed, _ = run_command([str(binary), "--list"], isolated, output, "list-original-tests",
                                 stages, timeout=30, environment=environment)
        tests = {line.removesuffix(": test") for line in listed.decode().splitlines()
                 if line.endswith(": test")}
        expected = {TEST, REQUIRED_IGNORED_CHILD, *ORIGINAL_TESTS}
        need(expected <= tests, "Actual original tests are not linked: " + repr(sorted(expected - tests)))
        for index, name in enumerate(ORIGINAL_TESTS):
            result, _ = run_command([str(binary), "--exact", name, "--nocapture", "--test-threads=1"],
                isolated, output, "retained-original-" + str(index), stages,
                timeout=240, environment=environment)
            assert_test_executed(result, name)
            retained.append(name)
        original_fixtures = output / "original-fixtures"
        original_fixtures.mkdir(mode=0o700)
        actual_environment = dict(environment, TRNM_HIA_GENESIS_OWNER_CORPUS=str(corpus_path),
                                  TRNM_HIA_GENESIS_OWNER_ARTIFACT_DIR=str(original_fixtures))
        actual_raw, _ = run_command([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            isolated, output, "actual-default-genesis-corpus", stages,
            timeout=600, environment=actual_environment)
        assert_test_executed(actual_raw, TEST)
        actual = parse_original_rows(actual_raw)
        partial_original = actual
        need(len(actual) == len(admitted["inputs"]) and
             same_json([{key: row.get(key) for key in INPUT_KEYS} for row in actual], admitted["inputs"]),
             "Actual original corpus has missing, reordered, changed, or extra inputs")
        for index, (native, observed) in enumerate(zip(admitted["comparison"]["cases"], actual, strict=True)):
            try:
                differences = compare_case(native, observed)
                need(observed.get("fixture_index") == index, "Original fixture index differs")
                row = {"name": native["name"], "status": "FAIL" if differences else "PASS",
                       "differences": differences, "native": native, "original": observed}
            except BaseException as error:
                row = {"name": native["name"], "status": "FAIL", "error": repr(error),
                       "native": native, "original": observed}
            controls.append(row)
        write_json(output / "comparison.json", {
            "schema": "trnm.hia.default-genesis-original-controls.v1", "controls": controls,
            "cross_format_sqlite_compatibility_claimed": False,
            "original_error_strings_equivalent": False,
        })
        need(all(row["status"] == "PASS" for row in controls), "Actual original default-genesis differential failed")
        status = "PASS"
    except BaseException as error:
        primary_error = repr(error)
        if status != "NOT_RUN":
            status = "FAIL"
    finally:
        try:
            fence("source-and-binary-after")
        except BaseException as error:
            final_errors.append({"stage": "source-and-binary-after", "error": repr(error)})
            status = "FAIL"
        actual_path = output / "actual-default-genesis-corpus/stdout.raw"
        if actual_path.is_file() and not partial_original:
            try:
                partial_original = parse_original_rows(actual_path.read_bytes())
            except BaseException as error:
                final_errors.append({"stage": "partial-original-output", "error": repr(error)})
                status = "FAIL"
        if partial_original:
            write_json(output / "original-observations.json", {
                "observed_case_rows": len(partial_original), "cases": partial_original,
                "complete_differential_pass": status == "PASS",
            })
        for stage in stages:
            try:
                directory = output / stage["stage"]
                need(file_identity(directory / "stdout.raw") == stage["stdout"]
                     and file_identity(directory / "stderr.raw") == stage["stderr"],
                     "Actual subprocess log changed after capture")
            except BaseException as error:
                final_errors.append({"stage": stage["stage"], "error": repr(error)})
                status = "FAIL"
        report = dict(base, status=status, primary_error=primary_error, final_errors=final_errors,
                      missing_tools=missing, stages=stages, source_fences=source_fences,
                      compiler=compiler, original_tests=retained,
                      required_original_tests=list(ORIGINAL_TESTS),
                      required_original_ignored_child=REQUIRED_IGNORED_CHILD,
                      original_case_rows_observed=len(partial_original),
                      controls=len(controls), passed=sum(row["status"] == "PASS" for row in controls),
                      failed=sum(row["status"] != "PASS" for row in controls),
                      elapsed_ns=time.monotonic_ns() - started,
                      original_test_binary=None if binary is None else
                          {"path": str(binary), **binary_identity},
                      serde_json_source=serde, serde_json_artifact=serde_artifact)
        if admitted is not None:
            report.update(source_inputs=admitted["source_inputs"],
                original_sources=admitted["original_sources"],
                native_source_set_sha256=admitted["comparison"]["build"]["source_set_sha256"],
                exact_corpus=admitted["comparison"]["corpus"]["raw"],
                native_bundle_artifacts=admitted["bundle_artifacts"],
                original_store=None if original_store is None else identity(original_store),
                original_hook=None if hook is None else identity(hook),
                appended_declaration_hex=DECLARATION.hex())
        write_json(output / "report.json", report)
        print(json.dumps({"status": status, "controls": len(controls),
                          "original_case_rows_observed": len(partial_original),
                          "original_tests": len(retained), "report": str(output / "report.json")}))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
