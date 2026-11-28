"""Exact-source CI transport and readback for ordinary M06 Batch and Prefix.

This module observes actual artifacts. It never executes a consensus algorithm,
imports an external Prepared/Patch, or grants Node persistence authority.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib

from hia.platform.execution_batch import safe_io as safe
from hia.platform.execution_batch import source_graph as graph
from hia.platform.execution_batch import rust_oracle as oracle
from hia.platform.execution_batch.bundle import admit_complete, validate_bundle
from hia.platform.execution_batch.physical_evidence import validate_physical
from hia.platform.execution_batch.lifecycle import validate_report as validate_lifecycle

REPOSITORY = graph.REPOSITORY
SCHEMA = "trnm.execution-batch-ci.v1"
ARCHIVE_SCHEMA = "trnm.execution-batch-ci-archive.v1"
need, same, identity, digest = safe.need, safe.same, safe.identity, graph.digest
KIND = ("batch", "prefix", "physical", "scoped", "original-batch", "original-prefix")
SNAPSHOT = "source-capture"
INCLUDE_FILES = (
    "tests/vectors/pon/native-growth-reference-v2.json",
    "tests/fixtures/cpq1-content-v1/vectors.json",
)
STAGE_FIELDS = {
    "stage", "argv", "cwd", "wall_limit_seconds", "cleanup_limit_seconds",
    "started_monotonic_ns", "exit_code", "timed_out", "launch_error",
    "cleanup_error", "pid", "finished_monotonic_ns", "elapsed_ns", "stdout",
    "stderr", "output_files_closed", "status",
}


def natural(value, label, minimum=0):
    need(type(value) is int and value >= minimum, "Expected exact integer: " + label)
    return value


def absolute(value):
    need(isinstance(value, str), "Absolute path text required")
    path = PurePosixPath(value)
    need(path.is_absolute() and str(path) == value and
         all(part not in (".", "..") for part in path.parts[1:]) and
         "\0" not in value and "\n" not in value and "\r" not in value,
         "Noncanonical absolute path")
    return Path(value)


def relative(value):
    safe._parts(value)
    need("\n" not in value and "\r" not in value, "Line break in artifact path")
    return PurePosixPath(value)


@contextlib.contextmanager
def regular(root, name):
    """Open O_PATH first; no read operation is attempted on special files."""
    parts = safe._parts(name)
    parent = safe._directory(root)
    opened = [parent]
    try:
        for part in parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            opened.append(parent)
        admitted = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent)
        opened.append(admitted)
        before = os.fstat(admitted)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             "Regular single-link artifact required")
        fd = os.open("/proc/self/fd/" + str(admitted),
                     os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        opened.append(fd)
        need(safe._stamp(before) == safe._stamp(os.fstat(fd)),
             "Artifact changed before descriptor read")
        yield fd, before
        need(safe._stamp(before) == safe._stamp(os.fstat(fd)),
             "Artifact changed during descriptor read")
    finally:
        for fd in reversed(opened):
            os.close(fd)


def file_identity(root, name):
    total = 0
    h = hashlib.sha256()
    with regular(root, name) as (fd, before):
        while block := os.read(fd, 1 << 20):
            total += len(block)
            need(total <= before.st_size, "Artifact grew during hash")
            h.update(block)
        need(total == before.st_size, "Artifact truncated during hash")
    return {"bytes": total, "sha256": h.hexdigest()}


def copy_file(root, name, target, expected):
    need(same(file_identity(root, name), expected), "Source changed before capture")
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    total, h = 0, hashlib.sha256()
    with regular(root, name) as (fd, before), target.open("xb") as out:
        while block := os.read(fd, 1 << 20):
            out.write(block)
            total += len(block)
            h.update(block)
        need(total == before.st_size, "Source changed during capture")
    need(same({"bytes": total, "sha256": h.hexdigest()}, expected) and
         same(file_identity(target.parent, target.name), expected),
         "Captured bytes differ")
    return expected


def semantic(repository, output, profile):
    output = Path(output)
    admitted = validate_bundle(repository, output / "bundle", profile)
    r = admitted["report"]
    artifacts = admitted["bundle_artifacts"]
    expected = set(artifacts) | {"bundle/" + name for name in artifacts} | {"bundle-admission.json"}
    need(safe.roster(output) == expected, "Complete outer native artifact roster differs")
    for name, row in artifacts.items():
        need(same(file_identity(output, name), row),
             "Outer actual native bytes differ from bound bundle: " + name)
    need(same(safe.load(output, "native-report.json"), r) and
         same(safe.load(output, "bundle-admission.json"), {
             "status": "PASS", "files": len(artifacts),
             "histories": len(admitted["cases"]),
             "source_set_sha256": digest(admitted["source_inputs"]),
             "executable": admitted["executable"]}),
         "Outer native report/admission differs from exact bound artifacts")
    return admitted, {
        "profile": profile, "partition": r["partition"],
        "histories_total": r["histories_total"],
        "histories_executed": r["histories_executed"],
        "commands_planned": r["commands_planned"],
        "commands_actual": r["commands_actual"],
        "skipped_commands": r["skipped_commands"],
        "progress_records": r["progress_records"],
        "elapsed_ns": r["elapsed_ns"],
        "report": file_identity(output, "native-report.json"),
        "executable": admitted["executable"],
        "bundle_artifacts": artifacts,
    }

def actual_stages(directory, report, profile):
    definition = oracle.PROFILES[profile]
    labels = [
        ("rustc-version", 15), ("rustc-sysroot", 15),
        ("rustc-selected-version", 15), ("cargo-original-metadata", 120),
        ("cargo-original-test-build", 900), ("list-original-tests", 30),
        *(("retained-original-" + str(i), 240)
          for i in range(len(definition["tests"]))),
        (definition["stage"], 600),
    ]
    stages = report.get("stages")
    need(isinstance(stages, list) and
         [row.get("stage") for row in stages] == [name for name, _ in labels],
         "Complete actual original stage inventory differs")
    result = {}
    previous = None
    for row, (name, budget) in zip(stages, labels, strict=True):
        need(isinstance(row, dict) and set(row) == STAGE_FIELDS,
             "Unexpected original subprocess receipt shape")
        need(same(row, safe.load(directory, name + "/receipt.json")),
             "Actual original receipt differs")
        need(row["status"] == "PASS" and type(row["exit_code"]) is int and
             row["exit_code"] == 0 and row["timed_out"] is False and
             row["launch_error"] is None and row["cleanup_error"] is None and
             row["output_files_closed"] is True and
             type(row["wall_limit_seconds"]) is int and row["wall_limit_seconds"] == budget and
             type(row["cleanup_limit_seconds"]) is int and row["cleanup_limit_seconds"] == 10,
             "Unsettled original process or changed execution budget")
        natural(row["pid"], "original pid", 1)
        start = natural(row["started_monotonic_ns"], "actual start", 1)
        finish = natural(row["finished_monotonic_ns"], "actual finish", start + 1)
        need(natural(row["elapsed_ns"], "actual elapsed", 1) == finish - start,
             "Actual process interval differs")
        need(previous is None or start >= previous, "Original processes overlap or reorder")
        previous = finish
        need(isinstance(row["argv"], list) and row["argv"] and
             all(isinstance(x, str) and "\0" not in x for x in row["argv"]),
             "Actual argv is incomplete")
        absolute(row["cwd"])
        streams = {}
        for channel in ("stdout", "stderr"):
            name_in = name + "/" + channel + ".raw"
            need(same(file_identity(directory, name_in), row[channel]),
                 "Actual original raw pipe differs")
            streams[channel] = safe.read(directory, name_in)
        result[name] = (row, streams)
    return result


def actual_tools(directory, report, rows, profile):
    tools = report.get("actual_rust_tools")
    need(isinstance(tools, dict) and set(tools) == {"rustc", "cargo", "rustdoc"},
         "Exact three Rust tool identities required")
    sysroot_raw = rows["rustc-sysroot"][1]["stdout"]
    sysroot = absolute(sysroot_raw.decode().strip())
    version = rows["rustc-version"][1]["stdout"]
    need(b"host: x86_64-unknown-linux-gnu\n" in version and
         rows["rustc-selected-version"][1]["stdout"] == version,
         "Selected actual compiler differs from observed host/version")
    for name, row in tools.items():
        need(isinstance(row, dict) and set(row) == {"path", "bytes", "sha256"} and
             absolute(row["path"]) == sysroot / "bin" / name and
             type(row["bytes"]) is int and row["bytes"] > 0 and
             isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
             "Unbound actual compiler path/bytes")
    need(rows["rustc-version"][0]["argv"] == ["rustc", "-Vv"] and
         rows["rustc-sysroot"][0]["argv"] == ["rustc", "--print", "sysroot"] and
         rows["rustc-selected-version"][0]["argv"] == [tools["rustc"]["path"], "-Vv"],
         "Actual tool/version commands differ")
    cwd = absolute(rows["cargo-original-test-build"][0]["cwd"])
    need(cwd.name == "isolated-source" and
         all(row[0]["cwd"] == str(cwd) for row in rows.values()),
         "Actual original stages did not use one isolated source")
    manifest = str(cwd / "trillionnium/Cargo.toml")
    need(rows["cargo-original-metadata"][0]["argv"] == [
        tools["cargo"]["path"], "metadata", "--locked", "--format-version=1",
        "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path", manifest],
        "Actual Cargo metadata command differs")
    argv = rows["cargo-original-test-build"][0]["argv"]
    expected = [tools["cargo"]["path"], "test", "--locked", "--manifest-path", manifest,
                "-p", "trnm-mvcc-fee", "--lib", "--no-run", "--message-format=json",
                "--target-dir"]
    need(len(argv) == len(expected) + 1 and argv[:-1] == expected,
         "Actual locked original Cargo build command differs")
    target = absolute(argv[-1])
    need(target != cwd and target not in cwd.parents and cwd not in target.parents,
         "Actual Cargo target overlaps source")
    binary = report["original_test_binary"]
    need(isinstance(binary, dict) and set(binary) == {"path", "bytes", "sha256"},
         "Actual original binary identity missing")
    retained = absolute(binary["path"])
    need(retained == cwd.parent / "original-test-binary",
         "Original binary did not come from the private run")
    need(rows["list-original-tests"][0]["argv"] == [str(retained), "--list"],
         "Actual binary discovery command differs")
    definition = oracle.PROFILES[profile]
    for i, name in enumerate(definition["tests"]):
        need(rows["retained-original-" + str(i)][0]["argv"] == [
            str(retained), "--exact", name, "--nocapture", "--test-threads=1"],
            "Retained original argv differs")
    test = "pon_executor::" + definition["module"] + "::evaluate"
    need(rows[definition["stage"]][0]["argv"] == [
        str(retained), "--exact", test, "--nocapture", "--test-threads=1"],
        "Actual original corpus argv differs")
    need(same(file_identity(directory, "original-test-binary"),
              {key: binary[key] for key in ("bytes", "sha256")}),
         "Independent original binary differs")
    events = [safe.json_load(line) for line in
              rows["cargo-original-test-build"][1]["stdout"].splitlines()
              if line.startswith(b"{")]
    artifact_rows = [row for row in events if row.get("reason") == "compiler-artifact"]
    serde_rows, binaries = oracle.utility.original_artifacts(artifact_rows)
    need(len(serde_rows) == len(binaries) == 1,
         "Actual locked serde lib / original test binary inventory differs")
    artifact = binaries[0]
    actual_binary = absolute(artifact["executable"])
    need(target in actual_binary.parents and artifact["target"]["src_path"] ==
         str(cwd / "trillionnium/crates/trnm-mvcc-fee/src/lib.rs"),
         "Actual original Cargo binary path/source escaped")
    before = safe.load(directory, "original-binary-before.json")
    need(same(before, {"retained": str(retained), "source": str(actual_binary),
                      "artifact": artifact,
                      **{key: binary[key] for key in ("bytes", "sha256")}}),
         "Actual binary copy provenance differs")
    return tools, cwd, target, serde_rows[0], artifact


def expected_adaptation(repository, profile, original):
    definition = oracle.PROFILES[profile]
    hook = definition["module"] + ".rs"
    declaration = ('\n#[cfg(test)]\n#[path = "' + hook +
                   '"]\nmod ' + definition["module"] + ';\n').encode()
    base = safe.read(repository, oracle.STORE)
    hook_raw = safe.read(repository, graph.OWNED + "/" + definition["source"])
    hook_name = (PurePosixPath(oracle.STORE).parent / hook).as_posix()
    raws = {
        oracle.STORE: base + declaration, hook_name: hook_raw,
        "trillionnium/Cargo.lock": safe.read(repository, "trillionnium/Cargo.lock"),
        **{name: safe.read(repository, name) for name in INCLUDE_FILES},
    }
    expected = {**original, oracle.STORE: identity(base + declaration),
                hook_name: identity(hook_raw)}
    return raws, expected


def source_capture(directory, repository, profile, original, isolated, serde, capture):
    directory = Path(directory)
    raws, expected = expected_adaptation(repository, profile, original)
    source_map = {name: identity(raw) for name, raw in sorted(raws.items())}
    dest = directory / SNAPSHOT
    if capture and not dest.exists():
        dest.mkdir(mode=0o700)
        for name, raw in raws.items():
            need(safe.read(isolated, name) == raw,
                 "Actual production prefix/sole hook differs before capture")
            path = dest / "original" / relative(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        archive = absolute(serde["registry_archive"]["path"])
        copy_file(archive.parent, archive.name, dest / "serde_json.crate",
                  {k: serde["registry_archive"][k] for k in ("bytes", "sha256")})
        crate = absolute(serde["crate_directory"])
        for name, row in serde["crate_sources"].items():
            copy_file(crate, name, dest / "serde" / relative(name), row)
        safe.write_json(dest / "manifest.json", {
            "schema": "trnm.execution-batch-original-source-capture.v1",
            "original_source_set_sha256": digest(original),
            "sole_appended_source": source_map,
            "serde_archive": {k: serde["registry_archive"][k] for k in ("bytes", "sha256")},
            "serde_sources": serde["crate_sources"],
        })
    need(dest.is_dir(), "Actual original source/dependency capture is required")
    expected_manifest = {
        "schema": "trnm.execution-batch-original-source-capture.v1",
        "original_source_set_sha256": digest(original),
        "sole_appended_source": source_map,
        "serde_archive": {k: serde["registry_archive"][k] for k in ("bytes", "sha256")},
        "serde_sources": serde["crate_sources"],
    }
    need(same(safe.load(dest, "manifest.json"), expected_manifest),
         "Actual source capture manifest differs")
    expected_files = {"manifest.json", "serde_json.crate"}
    for name, raw in raws.items():
        need(safe.read(dest, "original/" + name) == raw,
             "Captured original production prefix/sole hook differs")
        expected_files.add("original/" + name)
    for name, row in serde["crate_sources"].items():
        need(same(file_identity(dest, "serde/" + name), row),
             "Captured actual registry source differs")
        expected_files.add("serde/" + name)
    need(safe.roster(dest) == expected_files,
         "Missing/extra original capture artifact")
    return dest, expected


def actual_serde(directory, report, rows, repository, library_row, target, capture):
    serde = report.get("serde_json_source")
    fields = {"package", "resolve_node", "locked_package", "crate_directory",
              "crate_sources", "crate_source_set_sha256", "registry_archive",
              "archive_source_files", "archive_source_set_sha256",
              "optional_cargo_generated_files", "vendor_checksum_file_required"}
    need(isinstance(serde, dict) and set(serde) == fields and
         same(safe.load(directory, "serde-json-source-before.json"), serde),
         "Actual registry source binding shape differs")
    metadata = safe.json_load(rows["cargo-original-metadata"][1]["stdout"])
    packages = [row for row in metadata["packages"] if row.get("name") == "serde_json"]
    need(same(packages, [serde["package"]]), "Actual Cargo serde metadata differs")
    package = serde["package"]
    node = [row for row in metadata["resolve"]["nodes"] if row.get("id") == package["id"]]
    need(same(node, [serde["resolve_node"]]) and
         {"default", "std"} <= set(node[0]["features"]),
         "Actual resolved serde features differ")
    lock = tomllib.loads(safe.read(repository, "trillionnium/Cargo.lock").decode())
    locked = [row for row in lock["package"] if row.get("name") == "serde_json"]
    need(same(locked, [serde["locked_package"]]) and locked[0]["version"] == "1.0.149" and
         locked[0]["source"] == package["source"] and
         package["source"].startswith("registry+"),
         "Actual registry source differs from locked original")
    crate = absolute(serde["crate_directory"])
    need(package["manifest_path"] == str(crate / "Cargo.toml") and
         library_row["target"]["src_path"] == str(crate / "src/lib.rs") and
         library_row["package_id"] == package["id"] and
         library_row["target"]["kind"] == ["lib"] and
         set(library_row["features"]) == {"default", "std"},
         "Actual serde compiler lib did not use the bound source/features")
    library = report.get("actual_serde_library")
    need(isinstance(library, dict) and set(library) ==
         {"artifact", "source_path", "retained_path", "identity"} and
         same(library, safe.load(directory, "actual-serde-library-before.json")) and
         same(library["artifact"], library_row),
         "Actual serde library copy binding differs")
    actual_path = absolute(library["source_path"])
    files = [path for path in library_row["filenames"] if path.endswith(".rlib")]
    need(files == [str(actual_path)] and target in actual_path.parents and
         absolute(library["retained_path"]) ==
         absolute(report["original_test_binary"]["path"]).parent / "actual-serde-library.rlib" and
         same(file_identity(directory, "actual-serde-library.rlib"), library["identity"]),
         "Independent actual serde library bytes/path differ")
    need(serde["vendor_checksum_file_required"] is False and
         same(serde["crate_source_set_sha256"], digest(serde["crate_sources"])) and
         same(serde["archive_source_set_sha256"], digest(serde["archive_source_files"])),
         "Complete registry source digest differs")
    archive = serde["registry_archive"]
    need(archive["sha256"] == locked[0]["checksum"], "Registry archive is not lock-bound")
    return serde, library


def check_captured_registry(capture_dir, serde):
    raw = safe.read(capture_dir, "serde_json.crate", 16 << 20)
    need(same(identity(raw), {k: serde["registry_archive"][k] for k in ("bytes", "sha256")}),
         "Captured registry archive differs")
    found = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as packed:
        for member in packed:
            parts = relative(member.name).parts
            need(member.isfile() and len(parts) >= 2 and
                 parts[0] == "serde_json-1.0.149" and
                 member.linkname == "" and 0 <= member.size <= 8 << 20,
                 "Unsafe registry archive member")
            name = "/".join(parts[1:])
            need(name not in found and name != ".cargo-ok" and len(found) < 4096,
                 "Duplicate or generated registry member")
            total += member.size
            need(total <= 64 << 20, "Registry source archive exceeds source bound")
            with packed.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            need(len(data) == member.size and
                 safe.read(capture_dir, "serde/" + name) == data,
                 "Actual captured crate differs from lock-bound archive")
            found[name] = identity(data)
    need(same(found, serde["archive_source_files"]) and
         set(found) <= set(serde["crate_sources"]) and
         set(serde["crate_sources"]) - set(found) <= {".cargo-ok"},
         "Complete actual registry source inventory differs")
    generated = {name: serde["crate_sources"][name] for name in
                 set(serde["crate_sources"]) - set(found)}
    need(same(generated, serde["optional_cargo_generated_files"]),
         "Generated Cargo marker inventory differs")
    if generated:
        need(same(safe.load(capture_dir, "serde/.cargo-ok", 1024), {"v": 1}),
             "Generated Cargo readiness marker differs")


def original_result(repository, directory, bundles, profile, capture=False):
    directory = Path(directory)
    admitted = admit_complete(repository, bundles, profile)
    report = safe.load(directory, "report.json")
    fields = {
        "schema", "status", "profile", "failure", "final_errors", "stages",
        "source_fences", "actual_rust_tools", "serde_json_source",
        "actual_serde_library", "source_inputs", "original_sources",
        "native_executable", "native_partitions", "corpus", "original_tests",
        "required_original_tests", "actual_original_context",
        "original_case_rows_observed", "controls", "passed", "failed",
        "original_test_binary", "elapsed_ns", "complete_node", "admission_persistence",
    }
    need(isinstance(report, dict) and set(report) == fields and
         report["schema"] == "trnm.execution-batch-original-qualification.v1" and
         report["status"] == "PASS" and report["profile"] == profile and
         report["failure"] is None and report["final_errors"] == [] and
         report["complete_node"] is False and report["admission_persistence"] is False,
         "Complete actual original report / authority boundary differs")
    need(same(report["source_inputs"], admitted["source_inputs"]) and
         same(report["original_sources"], admitted["original_sources"]) and
         same(report["native_executable"], admitted["executable"]) and
         same(report["corpus"], identity(admitted["corpus_raw"])) and
         safe.read(directory, "corpus.jsonl") == admitted["corpus_raw"],
         "Original run is not bound to the complete current native/source corpus")
    partitions = [{"index": part["comparison"]["partition"]["index"],
                   "build": part["comparison"]["build"],
                   "artifacts": part["bundle_artifacts"]} for part in admitted["parts"]]
    need(same(report["native_partitions"], partitions),
         "Original predecessor artifacts differ")
    rows = actual_stages(directory, report, profile)
    tools, isolated, target, serde_row, binary_row = actual_tools(directory, report, rows, profile)
    serde, library = actual_serde(directory, report, rows, repository, serde_row, target, capture)
    capture_dir, isolated_map = source_capture(
        directory, repository, profile, admitted["original_sources"], isolated, serde, capture)
    check_captured_registry(capture_dir, serde)
    definition = oracle.PROFILES[profile]
    required = list(definition["tests"])
    need(same(report["original_tests"], required) and
         same(report["required_original_tests"], required), "Original retained roster differs")
    listed = {line.removesuffix(": test") for line in
              rows["list-original-tests"][1]["stdout"].decode().splitlines()
              if line.endswith(": test")}
    test = "pon_executor::" + definition["module"] + "::evaluate"
    need(set(required + [test]) <= listed, "Actual original test discovery is incomplete")
    for i, name in enumerate(required):
        oracle.utility.assert_test_executed(rows["retained-original-" + str(i)][1]["stdout"], name)
    corpus_stdout = rows[definition["stage"]][1]["stdout"]
    oracle.utility.assert_test_executed(corpus_stdout, test)
    contexts = [safe.json_load(line.split(definition["context"], 1)[1])
                for line in corpus_stdout.splitlines() if definition["context"] in line]
    actual = [safe.json_load(line.split(definition["result"], 1)[1])
              for line in corpus_stdout.splitlines() if definition["result"] in line]
    need(len(contexts) == 1 and same(report["actual_original_context"], contexts[0]),
         "Actual original Config context differs")
    need(len(actual) == len(admitted["inputs"]) and
         [row["name"] for row in actual] == [row["name"] for row in admitted["inputs"]],
         "Complete original histories are missing/reordered")
    need(same(safe.load(directory, "original-observations.json"),
              {"cases": actual, "complete_differential_pass": True}),
         "Original observation summary differs from raw stdout")
    controls = [definition["compare"](n, o, c, contexts[0]) for n, o, c in
                zip(admitted["cases"], actual, admitted["inputs"], strict=True)]
    need(all(row["status"] == "PASS" for row in controls) and
         same(safe.load(directory, "comparison.json"), {
             "schema": "trnm.execution-batch-original-controls.v1",
             "profile": profile, "controls": controls}),
         "Actual raw original/native differential differs")
    for field, expected in (("original_case_rows_observed", len(actual)),
                            ("controls", len(controls)), ("passed", len(controls)), ("failed", 0)):
        need(type(report[field]) is int and report[field] == expected,
             "Actual original count differs: " + field)
    natural(report["elapsed_ns"], "complete original interval", 1)
    need(report["elapsed_ns"] >= sum(row[0]["elapsed_ns"] for row in rows.values()),
         "Original overall interval is shorter than actual subprocesses")
    admission = safe.load(directory, "admission.json")
    expected_admission_fields = {"status", "profile", "source_inputs", "original_sources",
                                 "native_executable", "corpus", "partitions"}
    need(set(admission) == expected_admission_fields and
         admission["status"] == "ADMITTED_NOT_ORIGINAL_EXECUTED" and
         admission["profile"] == profile and
         same(admission["source_inputs"], admitted["source_inputs"]) and
         same(admission["original_sources"], admitted["original_sources"]) and
         same(admission["native_executable"], admitted["executable"]) and
         same(admission["corpus"], identity(admitted["corpus_raw"])),
         "Actual pre-Cargo source admission differs")
    by_index = {part["comparison"]["partition"]["index"]: part for part in admitted["parts"]}
    order = []
    for part in admission["partitions"]:
        need(set(part) == {"path", "index", "artifacts"} and
             type(part["index"]) is int and part["index"] in by_index,
             "Actual original predecessor argument is invalid")
        absolute(part["path"])
        need(part["index"] not in order and
             same(part["artifacts"], by_index[part["index"]]["bundle_artifacts"]),
             "Actual original predecessor argument changed")
        order.append(part["index"])
    need(set(order) == set(by_index), "Actual original predecessor argument set differs")
    maps = [by_index[index]["bundle_artifacts"] for index in order]
    common = {
        "complete_native_source": {"status": "MATCH", "files": len(admitted["source_inputs"]),
                                   "sha256": digest(admitted["source_inputs"])},
        "actual_original_source": {"status": "MATCH", "files": len(admitted["original_sources"]),
                                   "sha256": digest(admitted["original_sources"])},
        "complete_native_artifacts_and_corpus": {
            "status": "MATCH", "partitions": len(maps),
            "files": sum(len(m) for m in maps), "sha256": digest(maps)},
    }
    copied = {"isolated_original_and_exact_hook": {
        "status": "MATCH", "files": len(isolated_map), "sha256": digest(isolated_map)}}
    compiled = {
        "actual_original_binary": {"status": "MATCH", **{
            k: report["original_test_binary"][k] for k in ("bytes", "sha256")}},
        "actual_serde_source": {"status": "MATCH", "files": len(serde["crate_sources"]),
                               "sha256": digest(serde["crate_sources"])},
        "actual_serde_library": {"status": "MATCH", **library},
        "actual_compilers": {"status": "MATCH", "tools": tools},
    }
    expected_fences = [
        {"label": "source-before", "status": "PASS", "checks": common, "errors": []},
        {"label": "isolated-source-before", "status": "PASS", "checks": {**common, **copied}, "errors": []},
        *({"label": label, "status": "PASS",
           "checks": {**common, **copied, **compiled}, "errors": []}
          for label in ("compiled-source-and-binary-before", "source-and-binary-after")),
    ]
    need(same(report["source_fences"], expected_fences), "Complete actual source/tool/binary fences differ")
    for fence in expected_fences:
        need(same(safe.load(directory, fence["label"] + ".json"), fence),
             "Actual final source receipt differs")
    graph.check_sources(admitted["source_inputs"], admitted["original_sources"], repository)
    native_reports = [part["report"] for part in admitted["parts"]]
    return admitted, {
        "profile": profile, "histories": len(actual), "retained_original_tests": required,
        "commands_planned": sum(r["commands_planned"] for r in native_reports),
        "commands_actual": sum(r["commands_actual"] for r in native_reports),
        "skipped_commands": sum(r["skipped_commands"] for r in native_reports),
        "progress_records": sum(r["progress_records"] for r in native_reports),
        "actual_stages": len(rows), "elapsed_ns": report["elapsed_ns"],
        "original_report": file_identity(directory, "report.json"),
        "original_test_binary": {k: report["original_test_binary"][k] for k in ("bytes", "sha256")},
        "actual_serde_library": library["identity"], "actual_compilers": tools,
        "executable": admitted["executable"], "source_capture": {
            name: file_identity(capture_dir, name) for name in sorted(safe.roster(capture_dir))},
    }

def validate(repository, kind, native=None, original=None, bundles=(), capture=False):
    repository = Path(repository).absolute()
    need(kind in KIND, "Unknown exact batch qualification stage")
    if kind in ("batch", "prefix"):
        admitted, summary = semantic(repository, Path(native), kind)
        sources, originals = admitted["source_inputs"], admitted["original_sources"]
    elif kind == "physical":
        report = validate_physical(repository, Path(native))
        first = report["builds"]["prefix"]
        sources, originals = first["source_inputs"], first["original_sources"]
        summary = {"controls": report["planned"], "elapsed_ns": report["elapsed_ns"],
                   "report": file_identity(native, "report.json"),
                   "executables": {name: row["executable"] for name, row in report["builds"].items()},
                   "actual_trace_required": True}
    elif kind == "scoped":
        report = validate_lifecycle(repository, Path(native))
        sources, originals = report["build"]["source_inputs"], report["build"]["original_sources"]
        summary = {name: report[name] for name in
                   ("processes", "commands", "progress_records", "full_base_reads", "elapsed_ns")}
        summary.update(report=file_identity(native, "report.json"),
                       executable=report["build"]["executable"], actual_node_source=False)
    else:
        profile = kind.removeprefix("original-")
        admitted, summary = original_result(repository, Path(original), bundles, profile, capture)
        sources, originals = admitted["source_inputs"], admitted["original_sources"]
    graph.check_sources(sources, originals, repository)
    return {
        "schema": SCHEMA, "kind": kind, "status": "PASS",
        "source_inputs": sources, "source_set_sha256": digest(sources),
        "original_source_set_sha256": digest(originals), "original_source_files": len(originals),
        "actual": summary, "complete_node": False, "admission_persistence": False,
        "persistent_commit": False, "service_deadline_qualified": False,
    }


def lineage(environment=None):
    env = os.environ if environment is None else environment
    head, run, attempt = (env.get(key) for key in
                         ("TRNM_EXPECTED_SOURCE_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    need(isinstance(head, str) and re.fullmatch("[0-9a-f]{40}", head),
         "Exact checked out source head is required")
    need(isinstance(run, str) and re.fullmatch("[1-9][0-9]*", run) and
         isinstance(attempt, str) and re.fullmatch("[1-9][0-9]*", attempt),
         "Actual same CI run and attempt are required")
    return {"git_head": head, "run_id": run, "attempt": int(attempt)}


def committed_sources(repository, sources):
    """The same streaming HEAD-blob fence used by the existing CI foundations."""
    need(isinstance(sources, dict) and sources, "Complete committed source map required")
    names = sorted(sources)
    for name in names:
        relative(name)
    with tempfile.TemporaryFile() as requests, tempfile.TemporaryFile() as errors:
        requests.write("".join("HEAD:" + name + "\n" for name in names).encode())
        requests.seek(0)
        child = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repository,
                                 stdin=requests, stdout=subprocess.PIPE, stderr=errors)
        try:
            for name in names:
                header = child.stdout.readline().split()
                need(len(header) == 3 and header[1] == b"blob" and header[2].isdigit(),
                     "Captured source is absent from actual HEAD: " + name)
                total = remaining = int(header[2])
                h = hashlib.sha256()
                while remaining:
                    block = child.stdout.read(min(remaining, 1 << 20))
                    need(block, "Truncated HEAD source blob")
                    remaining -= len(block)
                    h.update(block)
                need(child.stdout.read(1) == b"\n" and
                     same(sources[name], {"bytes": total, "sha256": h.hexdigest()}),
                     "Captured bytes differ from actual HEAD: " + name)
            need(not child.stdout.read() and child.wait(timeout=30) == 0,
                 "Actual HEAD blob reader did not finish")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            child.stdout.close()
    return len(names)


def source_pair(repository, observations, expected):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repository).decode().strip()
    need(head == expected["git_head"], "Current Git head differs from expected source head")
    result = {}
    for name in ("source-before.json", "source-after.json"):
        source = safe.load(observations, name)
        need(source.get("tested_commit") == source.get("candidate") == head and
             source.get("tested_tree") == tree and source.get("kind") == "head" and
             source.get("tracked_worktree_verified") is True and
             type(source.get("tracked_entries")) is int and source["tracked_entries"] > 0,
             "Full exact-head source observation is missing or changed")
        result[name] = file_identity(observations, name)
    return result


def bind(repository, kind, observations, native=None, original=None, bundles=(), parents=()):
    expected = lineage()
    source_observations = source_pair(repository, observations, expected)
    result = validate(repository, kind, native, original, bundles, capture=kind.startswith("original-"))
    originals = graph.original_manifest(repository)
    committed_sources(repository, {**originals, **result["source_inputs"]})
    predecessor_receipts = []
    if kind.startswith("original-"):
        profile = kind.removeprefix("original-")
        need(len(parents) == len(bundles) == (1 if profile == "batch" else 4),
             "All same-run native transfers are required")
        seen = set()
        for parent, bundle in zip(parents, bundles, strict=True):
            parent = Path(parent).absolute()
            transfer = safe.load(parent, "transfer-receipt.json")
            prior = safe.load(parent, "native-binding.json")
            need(set(transfer) == {"schema", "status", "lineage", "binding", "manifest", "archive"} and
                 transfer["schema"] == "trnm.execution-batch-ci-transfer.v1" and
                 transfer["status"] == "VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED" and
                 same(transfer["lineage"], expected) and
                 same(transfer["binding"], file_identity(parent, "native-binding.json")),
                 "Current original run did not consume a complete same-run predecessor")
            need(prior["kind"] == profile and same(prior["lineage"], expected) and
                 same(prior["source_inputs"], result["source_inputs"]) and
                 prior["original_source_set_sha256"] == result["original_source_set_sha256"] and
                 Path(bundle).absolute() == parent / "native/bundle",
                 "Original predecessor source/profile/path differs")
            index = natural(prior["actual"]["partition"]["index"], "predecessor index")
            need(index not in seen, "Repeated native predecessor")
            seen.add(index)
            admitted, summary = semantic(repository, parent / "native", profile)
            need(same(summary, prior["actual"]), "Predecessor summary differs from full raw observations")
            predecessor_receipts.append({"index": index, "receipt": file_identity(parent, "transfer-receipt.json"),
                                         "binding": file_identity(parent, "native-binding.json")})
        need(seen == set(range(1 if profile == "batch" else 4)), "Missing native predecessor")
    else:
        need(not parents and not bundles, "Unexpected predecessor for native stage")
    result.update(lineage=expected, source_observations=source_observations,
                  predecessors=predecessor_receipts)
    safe.write_json(Path(observations) / "binding.json", result)
    return result


def object_inventory(root, excluded=()):
    """List specials by lstat only. Their contents are never opened."""
    root = Path(root).absolute()
    exclusions = set(excluded)
    for path in exclusions:
        relative(path)
    result = {}
    fd = safe._directory(root)
    def visit(directory, prefix):
        before = os.fstat(directory)
        names = sorted(entry.name for entry in os.scandir(directory))
        for name in names:
            relative(name)
            key = prefix + name
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            row = {"mode": stat.S_IMODE(current.st_mode)}
            if key in exclusions:
                row.update(type="omitted-rebuildable-tree", reason="isolated original Cargo source copy")
            elif stat.S_ISDIR(current.st_mode):
                row["type"] = "directory"
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                try:
                    actual = os.fstat(child)
                    need((actual.st_dev, actual.st_ino) == (current.st_dev, current.st_ino),
                         "Directory changed during artifact inventory")
                    visit(child, key + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(current.st_mode):
                need(current.st_nlink == 1, "Hard-linked evidence is not admitted")
                row.update(type="file", **file_identity(root, key))
            elif stat.S_ISLNK(current.st_mode):
                row.update(type="symlink-metadata", target=os.readlink(name, dir_fd=directory))
            elif stat.S_ISFIFO(current.st_mode):
                row["type"] = "fifo-metadata"
            elif stat.S_ISSOCK(current.st_mode):
                row["type"] = "socket-metadata"
            else:
                row.update(type="special-metadata", file_type=stat.S_IFMT(current.st_mode),
                           device=current.st_rdev)
            result[key] = row
        after = os.fstat(directory)
        need((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
             "Artifact directory changed during inventory")
    try:
        visit(fd, "")
    finally:
        os.close(fd)
    return dict(sorted(result.items()))


class HashSink:
    def __init__(self, destination=None):
        self.destination = destination
        self.bytes = 0
        self.sha = hashlib.sha256()
    def write(self, raw):
        if self.destination is not None:
            self.destination.write(raw)
        self.bytes += len(raw)
        self.sha.update(raw)
        return len(raw)
    def flush(self):
        if self.destination is not None:
            self.destination.flush()
    def tell(self):
        return self.bytes
    def identity(self):
        return {"bytes": self.bytes, "sha256": self.sha.hexdigest()}


class DescriptorReader:
    def __init__(self, fd):
        self.fd = fd
    def read(self, size=-1):
        need(type(size) is int and size >= 0, "Bounded archive read required")
        return os.read(self.fd, size)


def write_canonical_tar(sink, roots, entries):
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.GNU_FORMAT) as archive:
        for name, row in sorted(entries.items()):
            if row["type"] != "file":
                continue
            parts = relative(name).parts
            need(parts[0] in roots and len(parts) > 1, "Unknown regular archive root")
            root, relative_name = roots[parts[0]], "/".join(parts[1:])
            info = tarfile.TarInfo(name)
            info.size = row["bytes"]
            info.mode = 0o600
            info.mtime = 0
            info.uid = info.gid = 0
            with regular(root, relative_name) as (fd, before):
                need(before.st_size == row["bytes"], "Artifact size changed before archive")
                archive.addfile(info, DescriptorReader(fd))
            need(same(file_identity(root, relative_name),
                      {k: row[k] for k in ("bytes", "sha256")}),
                 "Archived artifact changed")
    return sink.identity()


def pack(roots, destination, kind, observations, stage_status):
    """Always retain actual failure files; only a successful bound stage transfers."""
    need(kind in KIND and isinstance(roots, dict) and roots, "Known stage/roots required")
    roots = {name: Path(path).absolute() for name, path in roots.items()}
    need(all(re.fullmatch("[a-z][a-z0-9-]*", name) for name in roots), "Invalid artifact root label")
    destination = Path(destination).absolute()
    need(not destination.exists() and not destination.is_symlink(), "Fresh archive output required")
    for path in roots.values():
        need(destination != path and path not in destination.parents and
             destination not in path.parents, "Archive output overlaps its actual input")
    binding = None
    if stage_status == "success":
        binding = safe.load(observations, "binding.json")
        need(binding.get("schema") == SCHEMA and binding.get("kind") == kind and
             binding.get("status") == "PASS" and
             same(binding.get("lineage"), lineage()), "Successful stage has no actual CI binding")
    else:
        need(stage_status in ("failure", "cancelled", "skipped", "unknown"),
             "Actual stage conclusion is required")
    entries = {}
    for name, root in roots.items():
        excluded = ("isolated-source",) if name == "original" and stage_status == "success" else ()
        if name == "original" and (root / "isolated-source").exists():
            # On success, validation has already captured the complete production
            # prefix, sole hook, lock, compile-time includes and locked serde sources.
            if stage_status == "success":
                need((root / SNAPSHOT / "manifest.json").is_file(),
                     "Do not omit an uncaptured actual original source adaptation")
        for relative_name, row in object_inventory(root, excluded).items():
            entries[name + "/" + relative_name] = row
    need(len(entries) <= 100000, "Evidence transport member bound exceeded")
    destination.mkdir(mode=0o700)
    archive_path = destination / "evidence.tar.xz"
    with archive_path.open("xb") as encoded:
        with lzma.LZMAFile(encoded, "w", format=lzma.FORMAT_XZ, preset=3) as compressed:
            sink = HashSink(compressed)
            tar_identity = write_canonical_tar(sink, roots, entries)
    after = {}
    for name, root in roots.items():
        for key, row in object_inventory(root, ("isolated-source",) if name == "original" and stage_status == "success" else ()).items():
            after[name + "/" + key] = row
    need(same(entries, after), "Actual artifact tree changed while archiving")
    result = {
        "schema": ARCHIVE_SCHEMA, "status": "PACKED_COMPLETE",
        "kind": kind, "stage_status": stage_status,
        "lineage": lineage(), "binding": binding,
        "roots": sorted(roots), "entries": entries,
        "tar": tar_identity, "archive": file_identity(destination, "evidence.tar.xz"),
        "special_objects_are_metadata_only": True,
    }
    safe.write_json(destination / "manifest.json", result)
    verify_archive(destination, None)
    return result


def validate_manifest(manifest):
    need(isinstance(manifest, dict) and set(manifest) == {
        "schema", "status", "kind", "stage_status", "lineage", "binding",
        "roots", "entries", "tar", "archive", "special_objects_are_metadata_only"},
        "Complete evidence archive manifest required")
    need(manifest["schema"] == ARCHIVE_SCHEMA and manifest["status"] == "PACKED_COMPLETE" and
         manifest["kind"] in KIND and manifest["special_objects_are_metadata_only"] is True,
         "Unexpected evidence archive schema/scope")
    need(manifest["stage_status"] in ("success", "failure", "cancelled", "skipped", "unknown"),
         "Actual archive stage conclusion required")
    roots = manifest["roots"]
    need(isinstance(roots, list) and roots == sorted(set(roots)) and roots and
         all(isinstance(x, str) and re.fullmatch("[a-z][a-z0-9-]*", x) for x in roots),
         "Exact archive roots required")
    entries = manifest["entries"]
    need(isinstance(entries, dict) and len(entries) <= 100000, "Bounded archive member map required")
    total = 0
    for name, row in entries.items():
        path = relative(name)
        need(path.parts[0] in roots and len(path.parts) > 1 and isinstance(row, dict),
             "Escaping archive entry")
        natural(row.get("mode"), "artifact mode")
        need(row["mode"] <= 0o7777, "Invalid artifact mode")
        kind = row.get("type")
        fields = {"mode", "type"}
        if kind == "file":
            fields |= {"bytes", "sha256"}
            total += natural(row.get("bytes"), "artifact size")
            need(row["bytes"] <= 2 << 30 and
                 isinstance(row.get("sha256"), str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
                 "Invalid artifact identity")
        elif kind == "symlink-metadata":
            fields.add("target")
            need(isinstance(row.get("target"), str), "Invalid symlink metadata")
        elif kind == "special-metadata":
            fields |= {"file_type", "device"}
            natural(row.get("file_type"), "special type")
            natural(row.get("device"), "special device")
        elif kind == "omitted-rebuildable-tree":
            fields.add("reason")
            need(name == "original/isolated-source" and
                 row.get("reason") == "isolated original Cargo source copy",
                 "Only the source-bound original copy may be omitted")
        else:
            need(kind in ("directory", "fifo-metadata", "socket-metadata"), "Unknown artifact type")
        need(set(row) == fields, "Unexpected artifact metadata fields")
        for parent in path.parents:
            if str(parent) in (".", path.parts[0]):
                break
            need(str(parent) in entries and entries[str(parent)]["type"] == "directory",
                 "Artifact ancestor is absent or not a directory")
    need(total <= 8 << 30, "Evidence transport byte bound exceeded")
    for key in ("tar", "archive"):
        row = manifest[key]
        need(isinstance(row, dict) and set(row) == {"bytes", "sha256"} and
             type(row["bytes"]) is int and 0 < row["bytes"] <= 8 << 30 and
             isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
             "Malformed archive identity")
    if manifest["stage_status"] == "success":
        need(isinstance(manifest["binding"], dict) and
             manifest["binding"].get("kind") == manifest["kind"] and
             manifest["binding"].get("status") == "PASS" and
             same(manifest["binding"].get("lineage"), manifest["lineage"]),
             "Successful archive lacks an actual matching binding")
    else:
        need(manifest["binding"] is None, "Failed archive cannot carry a success binding")


def decode_xz(artifact, manifest, destination):
    need(same(file_identity(artifact, "evidence.tar.xz"), manifest["archive"]),
         "Compressed evidence archive changed")
    h = hashlib.sha256()
    total = 0
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=32 << 20)
    with regular(artifact, "evidence.tar.xz") as (fd, _):
        while True:
            incoming = os.read(fd, 1 << 20) if decoder.needs_input else b""
            need(incoming or not decoder.needs_input or decoder.eof, "Truncated compressed archive")
            while True:
                block = decoder.decompress(incoming, max_length=min(
                    (1 << 20), manifest["tar"]["bytes"] - total + 1))
                incoming = b""
                total += len(block)
                need(total <= manifest["tar"]["bytes"], "Archive expands beyond exact declared tar")
                destination.write(block)
                h.update(block)
                if decoder.eof:
                    need(decoder.unused_data == b"" and os.read(fd, 1) == b"",
                         "Trailing compressed stream or bytes")
                    break
                if decoder.needs_input:
                    break
            if decoder.eof:
                break
    need(same({"bytes": total, "sha256": h.hexdigest()}, manifest["tar"]),
         "Uncompressed evidence archive differs")
    destination.flush()
    destination.seek(0)


def verify_archive(artifact, destination):
    artifact = Path(artifact).absolute()
    need(safe.roster(artifact) == {"evidence.tar.xz", "manifest.json"},
         "Artifact container must contain exactly archive and manifest")
    manifest = safe.load(artifact, "manifest.json")
    validate_manifest(manifest)
    entries = manifest["entries"]
    regular_entries = {name: row for name, row in entries.items() if row["type"] == "file"}
    if destination is not None:
        destination = Path(destination).absolute()
        need(not destination.exists() and not destination.is_symlink(), "Fresh extraction path required")
        destination.mkdir(mode=0o700)
    with tempfile.TemporaryFile() as decoded:
        decode_xz(artifact, manifest, decoded)
        found = {}
        with tarfile.open(fileobj=decoded, mode="r:") as archive:
            for member in archive:
                relative(member.name)
                need(member.name not in found and member.name in regular_entries and
                     member.isfile() and member.linkname == "" and member.mode == 0o600 and
                     member.uid == member.gid == member.mtime == 0 and
                     member.uname == member.gname == "",
                     "Noncanonical, linked, duplicate or extra tar member")
                row = regular_entries[member.name]
                need(member.size == row["bytes"], "Archived member extent differs")
                total, h = 0, hashlib.sha256()
                target = None
                if destination is not None:
                    target_path = destination / relative(member.name)
                    target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    target = target_path.open("xb")
                try:
                    with archive.extractfile(member) as source:
                        while block := source.read(1 << 20):
                            total += len(block)
                            need(total <= row["bytes"], "Member exceeds declared extent")
                            h.update(block)
                            if target is not None:
                                target.write(block)
                finally:
                    if target is not None:
                        target.close()
                need(same({"bytes": total, "sha256": h.hexdigest()},
                          {k: row[k] for k in ("bytes", "sha256")}),
                     "Transferred regular bytes differ")
                found[member.name] = row
        need(same(found, regular_entries), "Missing regular evidence archive member")
        # Re-serialize just the admitted members with this canonical writer and
        # compare every tar byte, including headers/padding. Hidden trailing tar
        # records cannot be admitted merely by updating an outer checksum.
        decoded.seek(0)
        with tarfile.open(fileobj=decoded, mode="r:") as source:
            lookup = {m.name: m for m in source.getmembers()}
            sink = HashSink()
            with tarfile.open(fileobj=sink, mode="w|", format=tarfile.GNU_FORMAT) as reconstructed:
                for name, row in sorted(regular_entries.items()):
                    info = tarfile.TarInfo(name)
                    info.size = row["bytes"]
                    info.mode = 0o600
                    info.mtime = 0
                    info.uid = info.gid = 0
                    with source.extractfile(lookup[name]) as stream:
                        reconstructed.addfile(info, stream)
            need(same(sink.identity(), manifest["tar"]),
                 "Noncanonical or trailing uncompressed archive records")
    return manifest


def unpack(repository, artifact, destination, profile, part):
    manifest = verify_archive(artifact, destination)
    expected = lineage()
    need(profile in ("batch", "prefix") and manifest["kind"] == profile and
         manifest["stage_status"] == "success" and same(manifest["lineage"], expected),
         "Predecessor did not pass in this exact run/head/attempt")
    binding = manifest["binding"]
    need(binding.get("schema") == SCHEMA and binding.get("complete_node") is False and
         binding.get("persistent_commit") is False and
         binding.get("admission_persistence") is False and
         binding.get("service_deadline_qualified") is False,
         "Unexpected predecessor authority scope")
    actual = validate(repository, profile, native=Path(destination) / "native")
    need(type(part) is int and actual["actual"]["partition"]["index"] == part and
         all(same(actual[key], binding.get(key)) for key in actual),
         "Transferred source/partition/actual observation differs from binding")
    need(same(safe.load(Path(destination) / "observations", "binding.json"), binding) and
         same(source_pair(repository, Path(destination) / "observations", expected),
              binding["source_observations"]),
         "Transferred full-source observation differs")
    committed_sources(repository, {**graph.original_manifest(repository), **actual["source_inputs"]})
    safe.write_json(Path(destination) / "native-binding.json", binding)
    receipt = {
        "schema": "trnm.execution-batch-ci-transfer.v1",
        "status": "VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED",
        "lineage": expected, "binding": file_identity(destination, "native-binding.json"),
        "manifest": file_identity(artifact, "manifest.json"),
        "archive": manifest["archive"],
    }
    safe.write_json(Path(destination) / "transfer-receipt.json", receipt)
    return receipt


def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),
         "Optimized evidence admission is not allowed")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "bind"):
        p = sub.add_parser(command)
        p.add_argument("--repository", type=Path, default=REPOSITORY)
        p.add_argument("--kind", choices=KIND, required=True)
        p.add_argument("--native", type=Path)
        p.add_argument("--original", type=Path)
        p.add_argument("--bundle", action="append", type=Path, default=[])
        p.add_argument("--report", type=Path)
        if command == "validate":
            p.add_argument("--capture", action="store_true")
        else:
            p.add_argument("--observations", type=Path, required=True)
            p.add_argument("--parent", action="append", type=Path, default=[])
    p = sub.add_parser("pack")
    p.add_argument("--kind", choices=KIND, required=True)
    p.add_argument("--root", action="append", required=True)
    p.add_argument("--observations", type=Path, required=True)
    p.add_argument("--destination", type=Path, required=True)
    p.add_argument("--stage-status", required=True,
                   choices=("success", "failure", "cancelled", "skipped", "unknown"))
    p = sub.add_parser("unpack")
    p.add_argument("--repository", type=Path, default=REPOSITORY)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--destination", type=Path, required=True)
    p.add_argument("--profile", choices=("batch", "prefix"), required=True)
    p.add_argument("--part", type=int, required=True)
    args = parser.parse_args()
    if args.command == "validate":
        result = validate(args.repository, args.kind, args.native, args.original,
                          args.bundle, args.capture)
        need(args.report is not None, "A fresh explicit readback report is required")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        safe.write_json(args.report, result)
    elif args.command == "bind":
        result = bind(args.repository, args.kind, args.observations, args.native,
                      args.original, args.bundle, args.parent)
        need(args.report is None, "Bind writes its one canonical observations/binding.json")
    elif args.command == "pack":
        roots = {}
        for row in args.root:
            name, separator, path = row.partition("=")
            need(separator and name not in roots, "Unique named artifact roots required")
            roots[name] = Path(path)
        result = pack(roots, args.destination, args.kind, args.observations, args.stage_status)
    else:
        result = unpack(args.repository, args.artifact, args.destination, args.profile, args.part)
    print(json.dumps({key: result[key] for key in ("schema", "status", "kind", "lineage")
                      if key in result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
