#!/usr/bin/env python3
"""Bind and transfer actual finite-genesis CI evidence; never supply runtime authority."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import stat
import tarfile
import traceback

from hia.tools import qualify_foundation_ci as base

ROOT = base.ROOT
SCHEMA = "trnm.hia.genesis-ci-binding.v1"
PACKAGE = "trnm.hia.genesis-ci-evidence.v1"
SUITES = ("semantic", "crash", "prefix", "namespace", "corruption")
STAGES = tuple("genesis-" + name for name in SUITES) + ("genesis-original",)
TOTALS = {"semantic": (30, 62), "crash": (25, 64), "prefix": (29, 59),
          "namespace": (104, 105), "corruption": (66, 66)}
MAX_TRANSFER_BYTES = 512 << 20
MAX_TRANSFER_MEMBERS = 20000
MAX_TRANSFER_TAR_BYTES = MAX_TRANSFER_BYTES + (32 << 20)
NATIVE_SCOPE = {
    "native_runtime": True, "runtime_host_proxy": False, "full_genesis_file_reads": True,
    "physical_power_loss": False, "os_page_cache_flushed": False,
    "continuous_hostile_same_uid_safety": False, "successor_admission": False,
    "arbitrary_commit": False, "complete_node": False, "original_rust": "NOT_RUN",
}
require, read, write_new = base.require, base.read, base.write_new
identity, object_hash, lineage = base.identity, base.object_hash, base.lineage


def same(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == \
        json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def file_id(value):
    return type(value) is dict and set(value) == {"bytes", "sha256"} and \
        type(value["bytes"]) is int and value["bytes"] >= 0 and \
        isinstance(value["sha256"], str) and len(value["sha256"]) == 64 and \
        all(c in "0123456789abcdef" for c in value["sha256"])


def source_pair(observations, expected):
    before = base.check_source_observation(observations, expected)
    after = read(observations / "source-after.json")
    invariant = ("tested_commit", "candidate", "tested_tree", "kind", "tracked_entries")
    require(all(after.get(key) == before.get(key) for key in invariant)
            and after.get("tracked_worktree_verified") is True
            and type(after.get("tracked_entries")) is int and after["tracked_entries"] > 0,
            "Complete source-after observation differs or failed")
    return {"before": before, "after": after,
            "before_file": identity(observations / "source-before.json"),
            "after_file": identity(observations / "source-after.json")}


def current_sources():
    from hia.platform.genesis_store.rust_oracle import complete_source_manifest, original_manifest
    sources, originals = complete_source_manifest(ROOT), original_manifest(ROOT)
    require(all(sources[key] == originals[key] for key in set(sources) & set(originals)),
            "Overlapping source identities differ")
    base.check_committed_sources({**originals, **sources}, ROOT)
    return sources, originals


def genesis_build(build, directory):
    require(type(build) is dict and build.get("schema") == "trnm.hia.default-genesis-store-build.v1"
            and build.get("status") == "PASS" and build.get("source_inputs_stable") is True,
            "Complete successful genesis native build required")
    sources, originals = current_sources()
    require(build.get("source_inputs") == sources and build.get("source_set_sha256") == object_hash(sources)
            and build.get("original_sources") == originals, "Complete current genesis source differs")
    require(build.get("compiler_sha256") == base.COMPILER
            and build.get("compiler_qualification_binding") == read(ROOT / "hia/qualification/compiler-binding.json"),
            "Pinned native compiler qualification differs")
    require(build.get("runtime_host_proxy") is False and build.get("rust_or_interpreter_fallback") is False
            and build.get("complete_node") is False and build.get("successor_block_admission") is False
            and build.get("literal_isa_is_a_separate_trusted_boundary") is True,
            "Native build scope changed")
    for name in ("policy", "settings", "root"):
        require(file_id(build["images"][name]) and
                identity(directory / (name + ".flat")) == build["images"][name], "Actual native image differs")
    require(identity(directory / "emitter.elf") == build["emitter"]
            and identity(directory / "elf-prefix.raw") == build["elf_prefix"], "Actual writer or prefix differs")
    executable = {key: build["executable"][key] for key in ("bytes", "sha256")}
    require(file_id(executable) and identity(directory / "genesis-owner.elf") == executable,
            "Actual genesis executable differs")
    image = base.regular(directory / "genesis-owner.elf").read_bytes()
    joined = base.regular(directory / "elf-prefix.raw").read_bytes() + b"".join(
        base.regular(directory / (name + ".flat")).read_bytes() for name in ("policy", "settings", "root"))
    require(image == joined, "Actual executable does not contain the declared native images")
    return {"source_inputs": sources, "source_set_sha256": object_hash(sources),
            "original_source_set_sha256": object_hash(originals), "executable": executable}


def process_objects(value):
    if type(value) is dict:
        if {"executable", "exit_code", "path", "stdout", "stderr"} <= set(value):
            yield value
        else:
            for child in value.values():
                yield from process_objects(child)
    elif type(value) is list:
        for child in value:
            yield from process_objects(child)


def validate_process_files(report, directory, origin):
    """Cross-check captured process records and every recorded actual byte stream."""
    directory, origin = Path(directory).absolute(), Path(origin)
    require(origin.is_absolute() and str(origin) == os.path.normpath(str(origin)),
            "Noncanonical native artifact origin")
    executable = {key: report["build"]["executable"][key] for key in ("bytes", "sha256")}
    captured = {}
    for row in process_objects(report["controls"]):
        require(isinstance(row["path"], str), "Missing process path")
        path = Path(row["path"])
        require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "Unsafe process path")
        relative = path.relative_to(origin)
        require(len(relative.parts) == 1 and relative.name.startswith("process-"), "Process escaped native output")
        previous = captured.get(relative.as_posix())
        if previous is not None:
            require(same(previous, row), "Repeated process path has different observations")
            continue
        folder = directory / relative
        require(same(read(folder / "process.json"), row), "Nested process differs from complete raw receipt")
        require(row["executable"] == executable and type(row["exit_code"]) is int
                and type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0, "Process executable or outcome differs")
        require(file_id(row["stdout"]) and file_id(row["stderr"])
                and identity(folder / "stdout.raw") == row["stdout"]
                and identity(folder / "stderr.raw") == row["stderr"], "Actual process stdout/stderr bytes differ")
        if row.get("schema") == "trnm.native-genesis-process.v1":
            require(row.get("timed_out") is False and row.get("child_budget_seconds") == 240
                    and row.get("cleanup_budget_seconds") == 3, "Native process timeout or budget changed")
            require(type(row.get("stdin_actual_write_bytes")) is int
                    and 0 <= row["stdin_actual_write_bytes"] <= row["stdin"]["bytes"], "Actual stdin extent differs")
            actual = bytes.fromhex(row["stdin_hex"])
            require(identity(folder / "stdin.raw") == row["stdin"]
                    and hashlib.sha256(actual).hexdigest() == row["stdin"]["sha256"]
                    and len(actual) == row["stdin"]["bytes"]
                    and bytes.fromhex(row["stdin_actual_hex"]) == actual[:row["stdin_actual_write_bytes"]],
                    "Actual attempted/written stdin binding differs")
            require(base.regular(folder / "stderr.raw").read_bytes() == bytes.fromhex(row["stderr_hex"]),
                    "Raw diagnostic bytes differ")
            require(same(read(folder / "events.json"), row["events"])
                    and base.regular(folder / "events.raw").read_bytes() ==
                        b"".join(bytes.fromhex(event["raw_hex"]) for event in row["events"]),
                    "Actual diagnostic event bytes differ")
        else:
            require("schema" not in row and row.get("standard_streams_silently_rejected") is True
                    and row.get("namespace_unchanged") is True and row.get("native_child_budget_seconds") == 240
                    and row["exit_code"] == 64 and row["stdout"]["bytes"] == row["stderr"]["bytes"] == 0
                    and "-stdio-" in relative.name,
                    "Unknown specialized native process receipt")
            base.regular(folder / "stdin-offered.raw")
        captured[relative.as_posix()] = row
    require(len(captured) == report["real_native_processes"], "Missing or extra actual process records")
    present = {path.name for path in directory.iterdir() if path.name.startswith("process-")}
    require(present == set(captured), "Unreported native process directory")
    return len(captured)


def validate_native_results(report, suite, directory, origin):
    from hia.platform.genesis_store.rust_oracle import validate_native_verification
    require(suite in SUITES and type(report) is dict
            and report.get("schema") == "trnm.native-default-genesis-qualification.v1"
            and report.get("status") == "PASS" and report.get("suite") == suite,
            "Successful exact genesis native suite required")
    controls, processes = TOTALS[suite]
    require(type(report.get("controls_total")) is int and report["controls_total"] == controls
            and type(report.get("real_native_processes")) is int and report["real_native_processes"] == processes
            and type(report.get("controls")) is list and len(report["controls"]) == controls,
            "Complete genesis native control/process counts required")
    names = [row.get("name") for row in report["controls"] if type(row) is dict]
    require(len(names) == controls and all(isinstance(name, str) and name for name in names)
            and len(set(names)) == controls
            and all(row.get("status") == "PASS" for row in report["controls"]), "Missing duplicate or failed native control")
    require(same(report.get("scope"), NATIVE_SCOPE)
            and type(report.get("native_child_budget_seconds")) is int and report["native_child_budget_seconds"] == 240
            and type(report.get("cleanup_budget_seconds")) is int and report["cleanup_budget_seconds"] == 3,
            "Native scope or child budgets changed")
    validate_native_verification(report, {"build": report["build"]})
    validate_process_files(report, directory, origin)
    return {"native_controls": controls, "native_processes": processes}


def check_parent(value, expected):
    require(type(value) is dict and value.get("schema") == SCHEMA
            and value.get("stage") == "genesis-semantic" and value.get("status") == "PASS",
            "Successful Genesis semantic predecessor required")
    require(same(value.get("lineage"), expected), "Predecessor exact source run or attempt differs")
    require(type(value.get("native_controls")) is int and value["native_controls"] == 30
            and type(value.get("native_processes")) is int and value["native_processes"] == 62
            and type(value.get("semantic_cases")) is int and value["semantic_cases"] == 30
            and value.get("original_rust") == "NOT_RUN", "Complete semantic predecessor required")
    require(value.get("whole_node_or_successor_admission") is False
            and value.get("arbitrary_commit") is False and value.get("physical_power_loss") is False
            and value.get("continuous_hostile_same_uid_safety") is False,
            "Predecessor finite scope changed")
    sources = value.get("source_observations")
    require(type(sources) is dict and all(type(sources.get(key)) is dict for key in ("before", "after"))
            and sources["before"].get("tracked_worktree_verified") is True
            and sources["after"].get("tracked_worktree_verified") is True,
            "Predecessor complete before/after source proof missing")
    for key in ("before", "after"):
        require(sources[key].get("tested_commit") == expected["git_head"]
                and sources[key].get("candidate") == expected["git_head"]
                and sources[key].get("kind") == "head"
                and type(sources[key].get("tracked_entries")) is int and sources[key]["tracked_entries"] > 0,
                "Predecessor source observation differs")
    require(all(sources["before"].get(key) == sources["after"].get(key)
                for key in ("tested_tree", "tracked_entries")), "Predecessor source changed after execution")


def check_original_results(report, directory, parent, native):
    from hia.platform.genesis_store import rust_oracle as oracle
    require(type(report) is dict and report.get("schema") == oracle.REPORT_SCHEMA
            and report.get("status") == "PASS" and report.get("primary_error") is None
            and report.get("final_errors") == [] and report.get("missing_tools") == [],
            "Actual original Genesis execution failed or did not run")
    for field, value in (("controls", 30), ("passed", 30), ("failed", 0), ("original_case_rows_observed", 30)):
        require(type(report.get(field)) is int and report[field] == value, "Original case count differs")
    require(report.get("original_tests") == report.get("required_original_tests") == list(oracle.ORIGINAL_TESTS)
            and report.get("required_original_ignored_child") == oracle.REQUIRED_IGNORED_CHILD,
            "All three actual original retained tests and linked ignored child required")
    require(report.get("source_inputs") == parent["source_inputs"]
            and report.get("native_source_set_sha256") == parent["source_set_sha256"]
            and object_hash(report.get("original_sources")) == parent["original_source_set_sha256"]
            and report.get("native_bundle_artifacts") == parent["bundle_artifacts"]
            and report.get("exact_corpus") == parent["corpus"]["raw"], "Original run differs from semantic predecessor")
    require(report.get("original_production_function_bytes_preserved") is True
            and report.get("complete_node") is False and report.get("successor_admission") is False
            and report.get("arbitrary_commit") is False and report.get("cross_format_sqlite_compatibility_claimed") is False
            and report.get("original_error_strings_equivalent") is False and report.get("physical_power_loss") is False,
            "Original qualification scope changed")
    labels = ["source-before", "isolated-source-before", "compiled-source-and-binary-before", "source-and-binary-after"]
    fences = report.get("source_fences")
    require(type(fences) is list and [row.get("label") for row in fences] == labels
            and all(row.get("status") == "PASS" and row.get("errors") == [] for row in fences),
            "Original before/after source or executable fence failed")
    for row in fences:
        require(same(read(directory / (row["label"] + ".json")), row), "Original source fence bytes differ")
    required = ["rustc-version", "cargo-original-metadata", "cargo-original-test-build", "list-original-tests",
                "retained-original-0", "retained-original-1", "retained-original-2", "actual-default-genesis-corpus"]
    stages = report.get("stages")
    require(type(stages) is list and [row.get("stage") for row in stages] == required,
            "Required actual original processes are absent or reordered")
    for stage in stages:
        label = stage["stage"]
        require(stage.get("status") == "PASS" and type(stage.get("exit_code")) is int and stage["exit_code"] == 0
                and stage.get("timed_out") is False and stage.get("launch_error") is None
                and stage.get("cleanup_error") is None and stage.get("output_files_closed") is True,
                "Actual original stage failed or did not settle")
        require(same(read(directory / label / "receipt.json"), stage)
                and identity(directory / label / "stdout.raw") == stage["stdout"]
                and identity(directory / label / "stderr.raw") == stage["stderr"],
                "Original process receipt or raw stream changed")
    executable = report.get("original_test_binary")
    require(type(executable) is dict and identity(directory / "original-test-binary") ==
            {key: executable[key] for key in ("bytes", "sha256")}, "Actual independent original binary differs")
    binary_path = str(directory / "original-test-binary")
    listed = base.regular(directory / "list-original-tests/stdout.raw").read_bytes().decode()
    tests = {line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test")}
    require({oracle.TEST, oracle.REQUIRED_IGNORED_CHILD, *oracle.ORIGINAL_TESTS} <= tests,
            "Actual original test discovery is incomplete")
    for label, name in [(f"retained-original-{i}", name) for i, name in enumerate(oracle.ORIGINAL_TESTS)] + [
            ("actual-default-genesis-corpus", oracle.TEST)]:
        stage = stages[required.index(label)]
        require(stage["argv"] == [binary_path, "--exact", name, "--nocapture", "--test-threads=1"],
                "Actual original exact-test command differs")
        oracle.assert_test_executed(base.regular(directory / label / "stdout.raw").read_bytes(), name)
    raw = base.regular(directory / "actual-default-genesis-corpus/stdout.raw").read_bytes()
    original = oracle.parse_original_rows(raw)
    require(len(original) == len(native["cases"]) == 30, "Actual original stdout omitted a case")
    comparison = read(directory / "comparison.json")
    require(comparison.get("schema") == "trnm.hia.default-genesis-original-controls.v1"
            and comparison.get("cross_format_sqlite_compatibility_claimed") is False
            and comparison.get("original_error_strings_equivalent") is False,
            "Original comparison scope differs")
    expected_controls = []
    for index, (observed, case) in enumerate(zip(original, native["cases"], strict=True)):
        require(observed.get("fixture_index") == index and not oracle.compare_case(case, observed),
                "Actual original stdout differs from native complete logical facts")
        expected_controls.append({"name": case["name"], "status": "PASS", "differences": [],
                                  "native": case, "original": observed})
    require(same(comparison.get("controls"), expected_controls), "Original comparison does not equal actual stdout")
    serde = report.get("serde_json_source")
    artifact = report.get("serde_json_artifact")
    require(type(serde) is dict and type(artifact) is dict and
            serde["package"]["version"] == "1.0.149" and artifact["package_id"] == serde["package"]["id"]
            and set(artifact["features"]) == {"default", "std"}
            and serde["registry_archive"]["sha256"] == serde["locked_package"]["checksum"]
            and serde.get("vendor_checksum_file_required") is False,
            "Actual locked registry serde artifact is not bound")
    return {"actual_original_cases": 30, "actual_original_tests": list(oracle.ORIGINAL_TESTS),
            "original_executable": {key: executable[key] for key in ("bytes", "sha256")}}


def bind(stage, root):
    require(stage in STAGES, "Unknown Genesis stage")
    expected = lineage()
    observations = root / "hia-genesis-observations"
    source = source_pair(observations, expected)
    result = {"schema": SCHEMA, "stage": stage, "status": "PASS", "lineage": expected,
              "source_observations": source, "whole_node_or_successor_admission": False,
              "arbitrary_commit": False, "physical_power_loss": False,
              "continuous_hostile_same_uid_safety": False}
    if stage != "genesis-original":
        suite = stage.removeprefix("genesis-")
        directory = root / ("hia-genesis-" + suite)
        report = read(directory / "report.json")
        result.update(genesis_build(report["build"], directory / "build"))
        result.update(validate_native_results(report, suite, directory, directory))
        result.update(native_report=identity(directory / "report.json"),
                      native_output_directory=str(directory), original_rust="NOT_RUN")
        if suite == "semantic":
            from hia.platform.genesis_store.rust_oracle import validate_bundle
            admitted = validate_bundle(ROOT, directory / "bundle")
            require(same(read(directory / "bundle/native-report.json"), report),
                    "Semantic bundle report differs from complete native report")
            result.update(semantic_cases=30, corpus=admitted["comparison"]["corpus"],
                          bundle_artifacts=admitted["bundle_artifacts"])
    else:
        prior = root / "hia-genesis-prior"
        parent = read(prior / "native-binding.json")
        check_parent(parent, expected)
        require(all(parent["source_observations"]["before"].get(key) == source["before"].get(key)
                    for key in ("tested_tree", "tracked_entries")), "Predecessor complete Git tree differs")
        from hia.platform.genesis_store.rust_oracle import validate_bundle
        admitted = validate_bundle(ROOT, prior / "native/bundle")
        sources, originals = current_sources()
        require(sources == parent["source_inputs"] and object_hash(originals) == parent["original_source_set_sha256"]
                and admitted["bundle_artifacts"] == parent["bundle_artifacts"], "Current source/predecessor differs")
        directory = root / "hia-genesis-original"
        report = read(directory / "report.json")
        for key in ("source_inputs", "source_set_sha256", "original_source_set_sha256",
                    "executable", "native_report", "corpus", "bundle_artifacts"):
            result[key] = parent[key]
        result.update(check_original_results(report, directory, parent, admitted["comparison"]),
                      native_binding=identity(prior / "native-binding.json"),
                      stage_report=identity(directory / "report.json"))
    write_new(observations / "binding.json", result)
    return result


def validate_entries(entries):
    require(type(entries) is dict and 0 < len(entries) <= MAX_TRANSFER_MEMBERS, "Invalid transfer roster extent")
    total = 0
    files = set()
    for name, entry in entries.items():
        path = base.member_path(name)
        require(path.parts[0] in {"native", "observations", "bootstrap"}
                and "\n" not in name and "\r" not in name and "\\" not in name,
                "Unexpected or noncanonical semantic transfer root")
        require(type(entry) is dict and entry.get("type") in ("0", "5") and entry.get("linkname") == ""
                and type(entry.get("bytes")) is int and 0 <= entry["bytes"] <= MAX_TRANSFER_BYTES,
                "Unsafe semantic member metadata")
        if entry["type"] == "0":
            require(file_id({key: entry[key] for key in ("bytes", "sha256")}), "Missing regular member identity")
            files.add(name)
            total += entry["bytes"]
        else:
            require(entry["bytes"] == 0, "Directory contains data")
    require(total <= MAX_TRANSFER_BYTES, "Semantic transfer exceeds original evidence extent")
    for name in entries:
        require(not any(parent.as_posix() in files for parent in base.member_path(name).parents),
                "Regular member used as an archive directory")
    return total


def bounded_xz(path):
    """Reject oversized dictionaries, concatenation, truncation and expansion before extraction."""
    decoder = lzma.LZMADecompressor(memlimit=64 << 20)
    total = 0
    with base.regular(path).open("rb") as stream:
        while True:
            chunk = stream.read(1 << 20) if decoder.needs_input else b""
            require(chunk or not decoder.needs_input, "Truncated XZ transfer")
            while True:
                block = decoder.decompress(chunk, max_length=min(1 << 20, MAX_TRANSFER_TAR_BYTES - total + 1))
                chunk = b""
                total += len(block)
                require(total <= MAX_TRANSFER_TAR_BYTES, "Expanded archive exceeds transfer extent")
                if decoder.eof:
                    require(not decoder.unused_data and not stream.read(1), "Trailing or concatenated XZ transfer")
                    return total
                if decoder.needs_input:
                    break


def safe_extract(archive, destination, entries):
    validate_entries(entries)
    require(not destination.exists() and not destination.is_symlink(), "Fresh extraction directory required")
    before = identity(archive)
    bounded_xz(archive)
    seen = set()
    with tarfile.open(base.regular(archive), "r|xz") as packed:
        for member in packed:
            require(member.name in entries and member.name not in seen, "Extra or duplicate archive member")
            seen.add(member.name)
            require(len(seen) <= MAX_TRANSFER_MEMBERS, "Too many archive members")
            base.member_path(member.name)
            expected = entries[member.name]
            require(member.type.decode("ascii") == expected["type"] and member.size == expected["bytes"]
                    and member.linkname == "", "Actual archive metadata differs")
            if member.isfile():
                digest = hashlib.sha256()
                size = 0
                with packed.extractfile(member) as stream:
                    while block := stream.read(1 << 20):
                        size += len(block)
                        require(size <= expected["bytes"], "Archive member exceeded its extent")
                        digest.update(block)
                require({"bytes": size, "sha256": digest.hexdigest()} ==
                        {key: expected[key] for key in ("bytes", "sha256")}, "Actual archive bytes differ")
    require(seen == set(entries) and identity(archive) == before, "Missing or changing archive member")
    omitted = base.extract_regular(archive, destination, entries)
    require(not omitted and identity(archive) == before, "Transferred archive changed or restored a special file")
    return before


def unpack(root):
    expected = lineage()
    observations = root / "hia-genesis-observations"
    source_before = base.check_source_observation(observations, expected)
    download = root / "hia-genesis-download"
    package = read(download / "package-manifest.json")
    require(package.get("schema") == PACKAGE and package.get("stage") == "genesis-semantic"
            and package.get("lineage") == expected and package.get("packing_status") == "PASS"
            and package.get("qualification_status_not_changed_by_packaging") is True,
            "Downloaded package belongs to another or failed qualification")
    parent = read(download / "native-binding.json")
    check_parent(parent, expected)
    require(all(parent["source_observations"]["before"].get(key) == source_before.get(key)
                for key in ("tested_tree", "tracked_entries")), "Predecessor complete Git tree differs")
    require(identity(download / "native-binding.json") == package["binding"],
            "Predecessor binding bytes differ")
    sources, originals = current_sources()
    require(parent["source_inputs"] == sources and parent["source_set_sha256"] == object_hash(sources)
            and parent["original_source_set_sha256"] == object_hash(originals),
            "Predecessor complete source differs before transfer")
    archive = download / "complete-evidence.tar.xz"
    require(identity(archive) == package["archive"], "Downloaded archive bytes differ")
    output = root / "hia-genesis-prior"
    safe_extract(archive, output, package["entries"])
    require(identity(output / "native/report.json") == parent["native_report"]
            and same(read(output / "observations/binding.json"), parent)
            and identity(output / "observations/source-before.json") == parent["source_observations"]["before_file"]
            and identity(output / "observations/source-after.json") == parent["source_observations"]["after_file"],
            "Extracted reports or whole-source proofs differ")
    from hia.platform.genesis_store.rust_oracle import validate_bundle
    admitted = validate_bundle(ROOT, output / "native/bundle")
    require(admitted["bundle_artifacts"] == parent["bundle_artifacts"], "Extracted complete native bundle differs")
    validate_native_results(read(output / "native/report.json"), "semantic", output / "native",
                            parent["native_output_directory"])
    shutil.copyfile(base.regular(download / "native-binding.json"), output / "native-binding.json")
    write_new(output / "transfer-receipt.json", {
        "status": "VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED", "lineage": expected,
        "archive": package["archive"], "native_binding": package["binding"],
        "special_files_remain_metadata_only": package.get("special_entries", {}),
        "source_and_corpus_validated": True,
    })
    return {"lineage": expected, "regular_members": len(package["entries"])}


def pack(stage, root):
    require(stage in STAGES, "Unknown Genesis stage")
    output = root / "hia-genesis-artifact"
    output.mkdir(mode=0o700)
    observations = root / "hia-genesis-observations"
    observations.mkdir(mode=0o700, exist_ok=True)
    roots = {"observations": observations, "bootstrap": root / "hia-bootstrap"}
    if stage == "genesis-original":
        roots.update(original=root / "hia-genesis-original", download=root / "hia-genesis-download")
    else:
        roots["native"] = root / ("hia-" + stage)
    record = {"schema": PACKAGE, "stage": stage, "lineage": lineage(),
              "qualification_status_not_changed_by_packaging": True, "packing_status": "FAIL",
              "entries": {}, "special_entries": {}, "transfer_receipts": {},
              "excluded_reconstructible_isolated_source_and_cargo_target": True,
              "downloaded_package_retained_even_on_transfer_failure": stage == "genesis-original"}
    errors = []
    if stage == "genesis-original":
        for name in ("native-binding.json", "transfer-receipt.json"):
            source = root / "hia-genesis-prior" / name
            if not source.exists() and not source.is_symlink():
                record["transfer_receipts"][name] = {"status": "ABSENT"}
                continue
            try:
                target = observations / ("predecessor-" + name)
                before = identity(source)
                with base.regular(source).open("rb") as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                require(identity(source) == identity(target) == before, "Transfer receipt changed")
                record["transfer_receipts"][name] = {"status": "CAPTURED", **before}
            except (OSError, ValueError) as error:
                errors.append({"path": str(source), "error": repr(error)})
    archive = output / "complete-evidence.tar.xz"
    try:
        with tarfile.open(archive, "x:xz", preset=1) as packed:
            def retain(path, name):
                relative = base.member_path(name)
                if any(part in {"isolated-source", "cargo-target"} for part in relative.parts):
                    return
                require(name not in record["entries"] and name not in record["special_entries"], "Duplicate evidence path")
                before = path.lstat()
                if stat.S_ISDIR(before.st_mode):
                    member = tarfile.TarInfo(name)
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o700
                    packed.addfile(member)
                    record["entries"][name] = {"type": "5", "bytes": 0, "linkname": ""}
                    for child in sorted(path.iterdir()):
                        retain(child, name + "/" + child.name)
                elif stat.S_ISREG(before.st_mode):
                    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(descriptor, "rb") as stream:
                        held = os.fstat(stream.fileno())
                        require(stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino) == (before.st_dev, before.st_ino),
                                "Evidence pathname changed before capture")
                        member = tarfile.TarInfo(name)
                        member.size = held.st_size
                        member.mode = 0o600
                        digest = hashlib.sha256()
                        class HashedReader:
                            def read(self, length):
                                raw = stream.read(length)
                                digest.update(raw)
                                return raw
                        packed.addfile(member, HashedReader())
                        after = os.fstat(stream.fileno())
                    current = path.lstat()
                    require((held.st_size, held.st_mtime_ns, held.st_ctime_ns) ==
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                            "Evidence file changed during capture")
                    record["entries"][name] = {"type": "0", "bytes": held.st_size,
                                               "sha256": digest.hexdigest(), "linkname": ""}
                else:
                    kind = "symlink" if stat.S_ISLNK(before.st_mode) else "fifo" if stat.S_ISFIFO(before.st_mode) else \
                        "socket" if stat.S_ISSOCK(before.st_mode) else "other"
                    row = {"type": kind, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
                           "gid": before.st_gid, "device": before.st_dev, "inode": before.st_ino,
                           "links": before.st_nlink, "bytes": before.st_size, "opened": False}
                    if kind == "symlink":
                        row["link_text"] = os.readlink(path)
                    record["special_entries"][name] = row
            for label, directory in roots.items():
                if not directory.exists() and not directory.is_symlink():
                    continue
                require(not directory.is_symlink() and directory.is_dir(), "Aliased evidence root")
                retain(directory, label)
        record["archive"] = identity(archive)
        binding_path = observations / "binding.json"
        if binding_path.exists() or binding_path.is_symlink():
            binding = read(binding_path)
            require(binding.get("schema") == SCHEMA and binding.get("stage") == stage
                    and binding.get("status") == "PASS" and binding.get("lineage") == record["lineage"],
                    "Qualification binding changed before packaging")
            source_pair(observations, record["lineage"])
            destination = output / ("native-binding.json" if stage == "genesis-semantic" else "binding.json")
            shutil.copyfile(base.regular(binding_path), destination)
            require(identity(destination) == identity(binding_path), "Binding changed during copy")
            record["binding"] = identity(destination)
        require(not errors, "Transfer receipt capture failed")
        record["packing_status"] = "PASS"
    except BaseException as error:
        errors.append({"error": repr(error), "traceback": traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():
            record["partial_archive"] = identity(archive)
    finally:
        record["capture_errors"] = errors
        write_new(output / "package-manifest.json", record)
    require(record["packing_status"] == "PASS", "Partial evidence and packaging failure retained")
    return {"stage": stage, "regular_and_directory_members": len(record["entries"]),
            "special_metadata_entries": len(record["special_entries"]), "archive": record["archive"],
            "qualification_status_not_changed_by_packaging": True}


def main():
    require(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Genesis CI evidence refuses optimized Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bind", "pack", "unpack"))
    parser.add_argument("--stage", choices=STAGES)
    args = parser.parse_args()
    require(args.action == "unpack" or args.stage is not None, "Stage required")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    try:
        result = unpack(root) if args.action == "unpack" else globals()[args.action](args.stage, root)
    except BaseException as error:
        receipt = {"status": "FAIL", "action": args.action, "stage": args.stage,
                   "error": repr(error), "traceback": traceback.format_exc()}
        observations = root / "hia-genesis-observations"
        observations.mkdir(mode=0o700, exist_ok=True)
        try:
            write_new(observations / ("ci-" + args.action + "-failure.json"), receipt)
        except BaseException as secondary:
            receipt["diagnostic_write_error"] = repr(secondary)
        print(json.dumps(receipt, sort_keys=True))
        return 1
    print(json.dumps({key: value for key, value in result.items()
                     if key not in {"source_inputs", "entries", "source_observations"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
