#!/usr/bin/env python3
"""Observe reviewed selected bytes and retain both original guard refusals.

This additional observation cannot replace either original named test roster or
make its workflow successful. The runner/account/ancestors are trusted inputs;
these local receipts are not authenticated provenance or hostile-filesystem
isolation. No source, historical contract, proof or snapshot is rewritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from types import ModuleType

PROFILE_SHA256 = "7eac13d310d91177dfbdbfd1adc70af4ccfe5eddb64821558e3fa4a109b43353"
REVIEWED_SOURCE = "0101b0ce76239832e0b2d19d0fd3f07e40fabeb4"
SCHEMA = "TRNM-W1-QROM-CURRENT-SOURCE-OBSERVATION1"
QUALIFICATION = {
    "post_quantum_soundness_qualified": False,
    "complete_w1_soundness_qualified": False,
    "quantum_work_qualified": False,
    "lifetime_bound_established": False,
    "production_qualified": False,
    "consensus_admission": False,
    "security_bits_quantum": None,
}


class ObservationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ObservationError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        output = {}
        for key, value in items:
            require(key not in output, "duplicate JSON member")
            output[key] = value
        return output

    def constant(_value):
        raise ObservationError("nonfinite JSON value")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def checked_profile(raw):
    require(len(raw) <= 65536 and digest(raw) == PROFILE_SHA256,
            "unreviewed current observation profile")
    profile = strict_json(raw)
    require(profile["schema"] == "TRNM-W1-QROM-CURRENT-SOURCE-OBSERVATION-PROFILE1"
            and profile["reviewed_source_commit"] == REVIEWED_SOURCE,
            "current observation namespace or reviewed source differs")
    require(profile["qualification"] == QUALIFICATION, "qualification scope differs")
    groups = profile["groups"]
    require({name: len(paths) for name, paths in groups.items()} == {
        "lifetime": 20, "implementation_project": 16, "implementation_helpers": 3,
    }, "original selected path groups differ")
    require(set(profile["current_files"]) == set().union(*map(set, groups.values()))
            and len(profile["current_files"]) == 37,
            "current selected path union differs")
    return profile


def bounded_regular(root, relative, limit):
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and str(rel) == relative
            and all(part not in ("", ".", "..") for part in rel.parts),
            "noncanonical selected path")
    current = root
    for part in rel.parts[:-1]:
        current = current / part
        require(stat.S_ISDIR(current.lstat().st_mode), "non-directory selected ancestor")
    path = root / relative
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "selected file type or byte bound differs")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        current_stat = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) == identity(current_stat)
                and len(raw) == before.st_size, "selected file changed during read")
        return raw
    finally:
        os.close(descriptor)


def selected_inputs(root, profile):
    result = {}
    for collection in ("current_files", "original_owner_files"):
        for relative, record in profile[collection].items():
            require(type(record["bytes"]) is int and 0 < record["bytes"] <= 2 * 1024 * 1024,
                    "selected file size is invalid")
            raw = bounded_regular(root, relative, record["bytes"])
            require(len(raw) == record["bytes"] and digest(raw) == record["sha256"],
                    "reviewed current source differs: " + relative)
            if relative in result:
                require(result[relative] == raw, "overlapping source bytes differ")
            result[relative] = raw
    return result


def original_module(root, path, raw, name):
    module = ModuleType(name)
    module.__file__ = str(root / path)
    # Execute only the original bytes just validated by the reviewed profile.
    # No constants or functions in either original owner are changed.
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def original_refusals(root, profile, inputs):
    ledger_path = "scripts/w1_lifetime_ledger.py"
    implementation_path = "scripts/w1_qrom_implementation_audit.py"
    ledger = original_module(root, ledger_path, inputs[ledger_path],
                             "trnm_original_lifetime_observation_v1")
    implementation = original_module(root, implementation_path, inputs[implementation_path],
                                     "trnm_original_implementation_observation_v1")
    require(ledger.SOURCE_BASE == profile["historical_lifetime_base"],
            "original lifetime base differs")
    require(set(ledger.SOURCE_PINS) == set(profile["groups"]["lifetime"]),
            "original lifetime selected paths differ")
    contract, _raw = implementation.load_contract(root)
    require(contract["source_base_commit"] == profile["historical_implementation_base"]
            and [row["path"] for row in contract["project_files"]] == profile["groups"]["implementation_project"]
            and [row["path"] for row in contract["audit_helpers"]] == profile["groups"]["implementation_helpers"],
            "original implementation source contract differs")
    changed = {path for path, expected in ledger.SOURCE_PINS.items()
               if digest(inputs[path]) != expected}
    for record in contract["project_files"] + contract["audit_helpers"]:
        raw = inputs[record["path"]]
        if len(raw) != record["bytes"] or digest(raw) != record["sha256"]:
            changed.add(record["path"])
    require(sorted(changed) == profile["changed_paths"],
            "historical/current difference set differs")
    observed = {}
    try:
        ledger.source_survey({path: inputs[path] for path in profile["groups"]["lifetime"]})
    except ledger.LedgerError as error:
        reason = str(error)
        require(reason == "source identity mismatch: trillionnium/crates/trnm-pon-node/src/store.rs",
                "unexpected original lifetime failure")
        observed["lifetime"] = {"source_scope_passed": False, "reason": reason}
    else:
        raise ObservationError("original lifetime scope unexpectedly passed")
    try:
        implementation.build_report(root)
    except implementation.AuditError as error:
        reason = str(error)
        require(reason == "input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs",
                "unexpected original implementation failure")
        observed["implementation"] = {"source_scope_passed": False, "reason": reason}
    else:
        raise ObservationError("original implementation scope unexpectedly passed")
    return observed, contract["lifetime_budget"]


def observe_selected_sources(root, profile_raw):
    profile = checked_profile(profile_raw)
    before = selected_inputs(root, profile)
    refusals, unknown_budget = original_refusals(root, profile, before)
    after = selected_inputs(root, profile)
    require(before == after, "selected inputs changed during observation")
    return {
        "schema": SCHEMA, "result": "CURRENT_SELECTED_SOURCE_OBSERVED_HOLD",
        "reviewed_source_commit": REVIEWED_SOURCE,
        "source_revision_binding": "fixed-reviewed-selected-file-lock-only",
        "selected_paths": 37, "groups": profile["groups"],
        "current_files": profile["current_files"],
        "changed_paths": profile["changed_paths"],
        "selected_inputs_unchanged": True,
        "historical_lifetime_base": profile["historical_lifetime_base"],
        "historical_implementation_base": profile["historical_implementation_base"],
        "original_guard_observations": refusals,
        "original_implementation_lifetime_budget": unknown_budget,
        "original_named_test_rosters_completed": False,
        "original_workflows_passed": False,
        "saved_proof_and_upstream_checks_reached": False,
        "current_binary_executed": False, "whole_repository_source_verified": False,
        "dependency_closure_complete": False, "provenance_authenticated": False,
        "qualification": dict(QUALIFICATION), "security_disposition": "HOLD_NO_GO",
    }


def selected_commit_inputs(root, expected_head, profile):
    """Bind the reviewed selected bytes to the observed Git commit, never a full tree."""
    records = dict(profile["current_files"])
    records.update(profile["original_owner_files"])
    process = subprocess.Popen(["git", "--no-replace-objects", "cat-file", "--batch"],
                               cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    observed = {}
    succeeded = False
    try:
        for relative, record in sorted(records.items()):
            process.stdin.write((expected_head + ":" + relative + "\n").encode())
            process.stdin.flush()
            header = process.stdout.readline(512)
            fields = header.split()
            require(header.endswith(b"\n") and len(fields) == 3
                    and re.fullmatch(rb"[0-9a-f]{40}", fields[0]) is not None
                    and fields[1] == b"blob" and fields[2] == str(record["bytes"]).encode(),
                    "selected current commit blob differs: " + relative)
            raw = process.stdout.read(record["bytes"])
            require(process.stdout.read(1) == b"\n" and len(raw) == record["bytes"]
                    and digest(raw) == record["sha256"],
                    "selected current commit bytes differ: " + relative)
            observed[relative] = fields[0].decode()
        process.stdin.close()
        require(process.wait(timeout=10) == 0, "selected commit reader failed")
        succeeded = True
    finally:
        if not succeeded:
            process.kill()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_head) is not None,
            "expected current head must be exact")
    root = args.root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(not output.is_relative_to(root), "output must be outside the checkout")
    def head():
        return subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "HEAD"],
                                       cwd=root, text=True).strip()
    require(head() == args.expected_head, "current head differs before observation")
    with args.profile.open("rb") as stream:
        profile_raw = stream.read(65537)
    profile = checked_profile(profile_raw)
    commit_before = selected_commit_inputs(root, args.expected_head, profile)
    report = observe_selected_sources(root, profile_raw)
    commit_after = selected_commit_inputs(root, args.expected_head, profile)
    require(commit_before == commit_after and head() == args.expected_head,
            "current head or selected commit blobs changed during observation")
    report["observed_current_commit"] = args.expected_head
    report["selected_commit_blob_ids"] = commit_after
    report["selected_current_files_match_commit"] = True
    report["current_profile_sha256"] = PROFILE_SHA256
    with output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"result": report["result"], "output": str(output),
                      "security_disposition": "HOLD_NO_GO"}))


if __name__ == "__main__":
    main()
