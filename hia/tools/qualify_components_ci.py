#!/usr/bin/env python3
"""Read all same-run component partitions and require exact complete coverage."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.tools import qualify, sha256_word_evidence
from hia.tools.component_partition import (
    GENERAL_PLAN, LEGACY_PLAN, PLANS, SHA_WORD_GROUPS, SPLIT_PLAN, canonical, descriptor,
    flatten, groups_for, lineage, need, object_hash, same, source_bound_plan,
    validate_completion, validate_lineage,
)

SCHEMA = "trnm.hia.component-ci-readback.v6"
SPLIT_SCHEMA = "trnm.hia.component-ci-readback.v7"
GENERAL_SCHEMA = "trnm.hia.component-ci-readback.v8"
READBACK_SCHEMAS = {LEGACY_PLAN: SCHEMA, SPLIT_PLAN: SPLIT_SCHEMA,
                    GENERAL_PLAN: GENERAL_SCHEMA}
FILES = {
    "hia-observations/source.json", "hia-observations/source-after.json",
    "hia-observations/qualification.json", "hia-observations/qualification.log",
    "hia-bootstrap/bootstrap.json", "original-rust-build.jsonl",
}


def artifact_files(group):
    return FILES | (sha256_word_evidence.artifact_files() if group in SHA_WORD_GROUPS else set())


def identity(path):
    path = Path(path)
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Linked component evidence path")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
         "Component evidence must be a single regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1 << 20), b""):
            digest.update(raw)
    after = path.lstat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         "Component evidence changed during reading")
    return {"bytes": after.st_size, "sha256": digest.hexdigest()}


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("Nonfinite JSON value: " + value)


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def read(path):
    identity(path)
    return decode(Path(path).read_text(encoding="utf-8"))


def source_receipt(value, expected_head):
    need(type(value) is dict and value.get("kind") == "head"
         and value.get("candidate") == value.get("tested_commit") == expected_head,
         "Different committed component source")
    need(value.get("tracked_worktree_verified") is True
         and value.get("tests_executed_by_identity_check") is False,
         "Source identity check cannot substitute test execution")
    for key in ("tracked_entries", "tracked_bytes"):
        need(type(value.get(key)) is int and value[key] > 0, "Invalid tracked source extent")
    need(type(value.get("tested_tree")) is str
         and re.fullmatch(r"[0-9a-f]{40}", value["tested_tree"]) is not None,
         "Missing exact component Git tree")
    return value["tested_tree"]


def validate_report(value, group, expected, sources, identifiers, compiler_binding, plan=LEGACY_PLAN):
    validate_lineage(expected)
    need(type(value) is dict and value.get("schema") == "trnm.hia.native-qualification.v1",
         "Wrong native component report")
    validate_lineage(value.get("lineage"))
    need(same(value["lineage"], expected), "Different component head, run or attempt")
    need(value.get("status") == "PASS"
         and value.get("source_commit_observed") == expected["git_head"]
         and value.get("working_tree_dirty") is False
         and value.get("source_unchanged_during_tests") is True,
         "Component execution did not finish on unchanged committed source")
    need(value.get("independent_rust_oracles_required") is True,
         "Original Rust oracle gate was not required")
    need(same(value.get("source_inputs"), sources)
         and value.get("source_set_sha256") == object_hash(sources),
         "Complete component source map differs")
    tests = value.get("tests")
    need(type(tests) is dict and set(tests) == {"run", "failures", "errors", "skipped"},
         "Missing actual unittest outcomes")
    need(tests["failures"] == [] and tests["errors"] == [] and tests["skipped"] == [],
         "Failed or skipped component tests cannot qualify")
    selected = validate_completion(value.get("test_partition"), identifiers, group, tests["run"], plan)
    need(value.get("selfhost_compiler_matches_cold_qualified_image") is True
         and value.get("retained_compiler_binding_sha256") == compiler_binding["binding_sha256"],
         "Component compiler differs from the retained cold-qualified image")
    builds = value.get("builds")
    need(type(builds) is list and builds, "No actual native component builds")
    native = []
    for build in builds:
        need(type(build) is dict and type(build.get("chain_migration")) is dict,
             "Malformed actual native build")
        qualify.validate_build_provenance(build, sources)
        if build["chain_migration"].get("backend") == "selfhost":
            native.append(build)
            need(build.get("compiler_sha256") == compiler_binding["compiler_sha256"],
                 "Actual component build used a different compiler")
    need(native, "No actual self-hosted component builds")
    oracles = value.get("rust_oracles")
    need(type(oracles) is dict and set(oracles) == set(qualify.rust_oracle_names(group)),
         "Incomplete original Rust oracle roster")
    for oracle in oracles.values():
        need(type(oracle) is dict and set(oracle) == {"executable_sha256"}
             and type(oracle["executable_sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", oracle["executable_sha256"]) is not None,
             "Missing original Rust binary identity")
    pins = value.get("pinned_rust_oracles")
    expected_pins = {qualify.ML_DSA_ORACLE} if group == "ml-dsa" else set()
    need(type(pins) is dict and set(pins) == expected_pins
         and value.get("pinned_rust_oracles_unchanged") is True
         and all(type(sha) is str and oracles[key] == {"executable_sha256": sha}
                 for key, sha in pins.items()),
         "Explicit original adapter pin changed or differs from the executed binary")
    for key in ("whole_chain_native", "old_stack_can_be_removed", "production_activation"):
        need(value.get(key) is False, "Component coverage cannot expand whole-project scope")
    return selected


def verify_log(raw, value):
    text = raw.decode("utf-8")
    counts = re.findall(r"(?m)^Ran ([0-9]+) tests? in [0-9.]+s$", text)
    need(counts and int(counts[-1]) == value["tests"]["run"],
         "Complete actual unittest summary differs")
    tail = text.rsplit("Ran ", 1)[-1]
    need(re.search(r"(?m)^OK$", tail) is not None
         and not re.search(r"(?m)^(FAILED|OK \()", tail),
         "Final unittest output is incomplete, failed or skipped")
    summaries = []
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                row = decode(line)
            except ValueError:
                continue
            if type(row) is dict and {"status", "tests", "skipped", "source_set_sha256",
                                     "shared_runner_calls", "wall_seconds", "shard"} <= set(row):
                summaries.append(row)
    need(len(summaries) == 1, "One complete actual qualifier summary is required")
    row = summaries[0]
    need(row["status"] == "PASS" and type(row["tests"]) is int
         and row["tests"] == value["tests"]["run"]
         and type(row["skipped"]) is int and row["skipped"] == 0
         and row["source_set_sha256"] == value["source_set_sha256"]
         and row["shard"] == value["test_partition"]["group"],
         "Actual qualifier stdout differs from its report")


def read_bundle(directory, group, expected, sources, identifiers, compiler_binding, plan=LEGACY_PLAN):
    directory = Path(directory)
    need(directory.is_dir() and not directory.is_symlink(), "Missing downloaded component bundle")
    actual, actual_directories = set(), set()
    for parent, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs:
            need(not (Path(parent) / name).is_symlink(), "Linked component artifact directory")
            actual_directories.add((Path(parent) / name).relative_to(directory).as_posix())
        actual.update((Path(parent) / name).relative_to(directory).as_posix() for name in names)
    expected_files = artifact_files(group)
    need(actual == expected_files, "Downloaded component artifact has missing or extra files")
    expected_directories = {parent.as_posix() for name in expected_files
                            for parent in Path(name).parents if parent != Path(".")}
    need(actual_directories == expected_directories, "Downloaded component artifact has extra directories")
    before = {name: identity(directory / name) for name in sorted(expected_files)}
    value = read(directory / "hia-observations/qualification.json")
    selected = validate_report(value, group, expected, sources, identifiers, compiler_binding, plan)
    source = read(directory / "hia-observations/source.json")
    after = read(directory / "hia-observations/source-after.json")
    tree = source_receipt(source, expected["git_head"])
    source_receipt(after, expected["git_head"])
    need(same(source, after), "Whole tracked source changed around component execution")
    bootstrap = read(directory / "hia-bootstrap/bootstrap.json")
    need(bootstrap.get("status") == "PASS"
         and bootstrap.get("compiler_sha256") == compiler_binding["compiler_sha256"]
         and type(bootstrap.get("compiler")) is str and bootstrap["compiler"],
         "Actual component compiler bootstrap did not pass")
    verify_log((directory / "hia-observations/qualification.log").read_bytes(), value)
    word_evidence = None
    if group in SHA_WORD_GROUPS:
        captured = {name: (directory / name).read_bytes()
                    for name in sha256_word_evidence.artifact_files() | {"hia-observations/qualification.log"}}
        need(all(sha256_word_evidence.identity(raw) == before[name] for name, raw in captured.items()),
             "SHA component bytes changed during capture")
        word_evidence = sha256_word_evidence.validate(captured, value, sources, compiler_binding, ROOT)
    need(before == {name: identity(directory / name) for name in sorted(expected_files)},
         "Component artifact changed during readback")
    return {"group": group, "status": "PASS", "tests": len(selected),
            "selected_tests": selected, "source_tree": tree, "files": before,
            "source_set_sha256": value["source_set_sha256"],
            "original_oracles": value["rust_oracles"], "sha256_word_evidence": word_evidence}


def verify_all(bundles, expected, sources, identifiers, compiler_binding, expected_tree, plan=LEGACY_PLAN):
    groups = groups_for(plan)
    need(type(bundles) is dict and set(bundles) == set(groups),
         "Exactly all component partitions are required")
    records = {group: read_bundle(bundles[group], group, expected, sources,
                                 identifiers, compiler_binding, plan) for group in groups}
    selected = [name for group in groups for name in records[group]["selected_tests"]]
    need(len(selected) == len(set(selected)) and sorted(selected) == sorted(identifiers),
         "Missing or repeated tests across component jobs")
    need(type(expected_tree) is str and re.fullmatch(r"[0-9a-f]{40}", expected_tree) is not None,
         "Exact current consumer Git tree is required")
    need(all(record["source_tree"] == expected_tree for record in records.values()),
         "Component jobs differ from the actual consumer Git tree")
    return {"schema": READBACK_SCHEMAS[plan], "status": "PASS", "lineage": expected,
            "discovered_tests": sorted(identifiers), "tests": len(selected),
            "source_set_sha256": object_hash(sources), "partitions": records,
            "complete_disjoint_coverage": True, "actual_runtime_reexecuted": False,
            "source_tree": expected_tree, "rust_build_event_chain_revalidated": False,
            "whole_chain_native": False, "old_stack_can_be_removed": False,
            "production_activation": False}


def validate_job_results(environ, plan=LEGACY_PLAN):
    for group in groups_for(plan):
        key = "TRNM_COMPONENT_" + group.upper().replace("-", "_") + "_RESULT"
        need(environ.get(key) == "success",
             "All actual prerequisite CI jobs must succeed: " + group)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    possible_groups = tuple(dict.fromkeys(group for plan in PLANS for group in groups_for(plan)))
    for group in possible_groups:
        parser.add_argument("--" + group, type=Path)
    parser.add_argument("--partition-plan", choices=PLANS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") not in (None, "", "0"):
        parser.error("Component readback refuses optimized Python")
    if args.output.exists() or args.output.is_symlink():
        parser.error("Observation output must be new")
    report = {"schema": SCHEMA, "status": "FAIL", "actual_runtime_reexecuted": False}
    try:
        expected = lineage(required=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
        need(head == expected["git_head"], "Actual consumer Git head differs from CI lineage")
        plan = source_bound_plan(ROOT, args.partition_plan)
        groups = groups_for(plan)
        report["schema"] = READBACK_SCHEMAS[plan]
        supplied = {group: getattr(args, group.replace("-", "_")) for group in possible_groups
                    if getattr(args, group.replace("-", "_")) is not None}
        need(set(supplied) == set(groups), "Exact source requires its complete artifact set")
        validate_job_results(os.environ, plan)
        sources = qualify.sources()
        suite = unittest.defaultTestLoader.discover(str(ROOT / "hia/tests"),
                                                    pattern="test_*.py", top_level_dir=str(ROOT))
        identifiers = [case.id() for case in flatten(suite)]
        descriptor(identifiers, "all", plan)
        binding_path = ROOT / "hia/qualification/compiler-binding.json"
        binding = read(binding_path)
        compiler = {"binding_sha256": identity(binding_path)["sha256"],
                    "compiler_sha256": binding["compiler_sha256"]}
        report = verify_all(supplied, expected, sources, identifiers, compiler, tree, plan)
        need(sources == qualify.sources(), "Source changed during independent component readback")
    except BaseException as error:
        report.update(status="FAIL", failure={"error": repr(error), "traceback": traceback.format_exc()})
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            stream.write(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
        print(json.dumps({"status": report["status"], "tests": report.get("tests"),
                          "actual_runtime_reexecuted": False}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
