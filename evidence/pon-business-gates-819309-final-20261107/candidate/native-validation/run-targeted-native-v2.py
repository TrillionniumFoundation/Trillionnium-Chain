#!/usr/bin/env python3
"""Explicit future-source targeted validation; preparation alone executes no native code."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

BASE = Path("/home/qian-qi/chain-throughput-local-admin-20261107")
WORK = Path(__file__).resolve().parent
REQ_FILE = WORK / "requirements-v2.json"
REQ_SHA = "2aee4a85af649777966c2d3a57e7252e35e48ba2ea70da4608e6a0bfa7ad4f42"
BASELINE = "819309fd312298e099642e1253b1d4ba07113e98"
BASELINE_TREE = "f9d63abb9e2931fd78e26ccb87e3a7955068f267"
BASELINE_SOURCE_SHA = "5759d06c351357aa4d7b24e1b56c03607da60870788f30139a8e10460744c6b6"
BASELINE_JOB = "1a1b755c976-12894-a3a"
BASELINE_FULL = BASE / "final-native-validation-20261107/runs" / BASELINE / "full-node"
FROZEN_SOURCE = BASE / "work-final-business-20261107"
TARGET = BASE / "local-build/admission-fence-target"

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def rec(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}

def checked_json(path, expected_sha=None):
    path = Path(path)
    if expected_sha is not None and sha(path) != expected_sha:
        raise ValueError("immutable preparation/receipt hash differs: " + str(path))
    return json.loads(path.read_text())

def baseline_gate(path):
    evidence = checked_json(path)
    if evidence.get("schema") != "trnm-authoritative-native-terminal-v1":
        raise ValueError("authoritative terminal receipt schema is required")
    status = evidence.get("authoritative_status", {})
    if (status.get("job_id") != BASELINE_JOB
        or status.get("state") not in ("succeeded", "failed")
        or not status.get("terminal_publication_confirmed")
        or status.get("exit_code") is None
        or status.get("automatic_retry") is not False):
        raise ValueError("original full-node job lacks authoritative terminal status")
    if status.get("output_complete") is not True or status.get("output_durable") is not True:
        raise ValueError("original full-node output is not complete and durable")
    for stream in ("stdout", "stderr"):
        if (status.get("log_synced", {}).get(stream) is not True
            or status.get("log_truncated", {}).get(stream) is not False):
            raise ValueError("original full-node log is not fully synced and untruncated: " + stream)
    record = evidence.get("manifest", {})
    manifest_path = BASELINE_FULL / "manifest.json"
    if record.get("path") != str(manifest_path) or rec(manifest_path) != record:
        raise ValueError("original full-node final manifest binding differs")
    manifest = checked_json(manifest_path)
    if (manifest.get("commit") != BASELINE or manifest.get("tree") != BASELINE_TREE
        or manifest.get("result") == "RUNNING" or not manifest.get("finished_utc")
        or manifest.get("current_step") is not None):
        raise ValueError("original full-node manifest is not terminal")
    source = manifest.get("source_receipts", {})
    if source.get("byte_identical") is not True:
        raise ValueError("original complete source-after must match before")
    for key, name in (("before", "source-before.json"), ("after", "source-after.json")):
        p = BASELINE_FULL / name
        if rec(p) != source.get(key) or sha(p) != BASELINE_SOURCE_SHA:
            raise ValueError("original complete source receipt differs: " + key)
    return {"terminal_receipt": rec(path), "manifest": rec(manifest_path),
            "authoritative_status": status, "source_receipts": source,
            "prior_failures_retained": True}

def load_engine(req, root):
    engine_path = Path(req["engine_path"])
    if sha(engine_path) != req["engine_sha256"]:
        raise ValueError("frozen native v2 engine changed")
    original_req = engine_path.parent / "requirements.json"
    if sha(original_req) != req["engine_requirements_sha256"]:
        raise ValueError("original engine requirements changed")
    spec = importlib.util.spec_from_file_location("trnm_native_v2_engine_22e1e8df", engine_path)
    engine = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = engine
    spec.loader.exec_module(engine)
    engine.ROOT = root
    engine.PACKAGE = root / "trillionnium/crates/trnm-pon-node"
    engine.WORK = WORK
    engine.TARGET = TARGET
    engine.REQ = req
    return engine

def exact_result(engine, raw_path, artifact, expected_name, native_code, reader_code, library_count):
    lines = raw_path.read_text(errors="replace").splitlines()
    running = [m[2] for line in lines if (m := engine.RUNNING.fullmatch(line))]
    expected_binary = Path(artifact["binary"]["path"]).resolve()
    binding = (len(running) == 1
               and Path(running[0]).resolve() == expected_binary
               and rec(expected_binary) == artifact["binary"])
    summaries = []
    for i, line in enumerate(lines):
        match = engine.SUMMARY.fullmatch(line)
        if match:
            summaries.append({"line": i+1, "status": match[1], "passed": int(match[2]),
                              "failed": int(match[3]), "ignored": int(match[4]),
                              "measured": int(match[5]), "filtered": int(match[6]),
                              "seconds": float(match[7])})
    candidate = summaries[-1] if summaries else None
    abnormal = []
    for line in lines:
        process_failure = ("process didn't exit successfully" in line
                           or "could not execute process" in line
                           or "could not execute test" in line)
        match = re.search(r"exit status:\s*(-?\d+)", line)
        numeric = int(match[1]) if match else None
        if process_failure and (
            "signal:" in line or "SIGABRT" in line or "SIGKILL" in line
            or "never executed" in line or "could not execute" in line
            or (numeric is not None and numeric not in (0, 101))
        ):
            abnormal.append(line)
    supervised_interruption = native_code in (124, 137, 143) or native_code < 0
    # Match the v2 failure rule: an OK child summary cannot certify a failed outer.
    outer = candidate
    if (not binding or abnormal or supervised_interruption or candidate is None
        or (native_code != 0 and candidate["status"] == "ok")
        or candidate["passed"] + candidate["failed"] != 1
        or candidate["ignored"] != 0 or candidate["measured"] != 0
        or candidate["filtered"] != library_count - 1):
        outer = None
    passed = (native_code == 0 and reader_code == 0 and binding
              and outer is not None and outer["status"] == "ok"
              and outer["passed"] == 1 and outer["failed"] == 0)
    return {"selector": expected_name, "native_effective_exit_code": native_code,
            "required_reader_exit_code": reader_code, "actual_running_paths": running,
            "running_matches_unique_inventory_binary": binding, "all_summaries": summaries,
            "outer_summary": outer, "abnormal_process_diagnostics": abnormal,
            "supervised_interruption": supervised_interruption,
            "verified_named_pass": passed, "raw": rec(raw_path),
            "child_or_ambiguous_summaries_are_not_outer_totals": True}

def operation_class(engine, req):
    class TargetedRun(engine.Run):
        def __init__(self, args, prerequisite):
            super().__init__(args)
            self.m["schema"] = "trnm-admission-final-root-targeted-native-v1"
            self.m["engine"] = self.m["driver"]
            self.m["driver"] = rec(__file__)
            self.m["requirements"] = rec(REQ_FILE)
            self.m["prerequisite"] = prerequisite
            self.m["plan"] = rec(req["plan_path"])
            self.m["expected_tree"] = args.expected_tree
            self.m["phase_rules"] = {
                "compile_failure_stops_before_test_bodies": True,
                "exact_attempts_per_selector": 1, "declared_exact_selectors": 16,
                "exact_outer_timeout_seconds": req["exact_timeout_seconds"],
                "outer_timeout_changes_internal_deadlines": False,
                "ignored_benchmark_bodies": False, "favorable_reruns": False,
                "full_package_execution": False, "host_changes_in_scope": False}
            self.m["exact_results"] = []
            self.save()

        def prepare(self):
            self.common_before()
            if self.m["tree"] != self.args.expected_tree:
                raise ValueError("actual tree differs from explicit frozen tree")
            subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE, self.sha],
                           cwd=engine.ROOT, env=self.env, check=True)
            changed = subprocess.check_output(
                ["git", "diff", "--name-only", BASELINE, self.sha, "--", "trillionnium"],
                cwd=engine.ROOT, env=self.env, text=True).splitlines()
            self.m["native_projection_changed_paths"] = sorted(changed)
            self.save()
            if sorted(changed) != sorted(req["allowed_native_changed_paths"]):
                raise ValueError("candidate native scope differs from three reviewed source paths plus the exact generated inventory")
            self.native("locked-metadata", ["metadata", "--locked", "--offline", "--manifest-path",
                        "trillionnium/Cargo.toml", "--all-features", "--format-version", "1"])
            self.native("format-check", ["fmt", "--manifest-path", "trillionnium/Cargo.toml",
                        "--all", "--", "--check"])
            self.prepush()  # Frozen v2 strict Clippy, no-run and actual harness/CLI inventory.
            if self.m["expected_counts"] != req["expected_counts"]:
                raise ValueError("actual no-run counts differ from the declared one-test increment")
            self.save()

        def targeted(self):
            inventory = checked_json(self.out / "inventory.json")
            library = next(a for a in inventory["test_artifacts"] if "lib" in a["target_kind"])
            before = [rec(a["binary"]["path"]) for a in inventory["all_node_executables"]]
            expected = [a["binary"] for a in inventory["all_node_executables"]]
            if before != expected:
                raise ValueError("compiled binary changed before the targeted invocations")
            engine.save_json(self.out/"binary-before.json", before, exclusive=True)
            self.m["binary_before"] = rec(self.out/"binary-before.json")
            self.m["disk_before_test_bodies"] = engine.disk()
            self.save()
            try:
                for case in req["selectors"]:
                    label, name = case["label"], case["selector"]
                    if rec(library["binary"]["path"]) != library["binary"]:
                        raise ValueError("actual libtest binary changed before " + label)
                    code = self.native(label, ["test", "--locked", "--offline", "--manifest-path",
                        "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--all-features",
                        "--lib", name, "--", "--exact", "--nocapture", "--test-threads=1"],
                        timeout=req["exact_timeout_seconds"], fail_fast=False)
                    raw = self.out/"records"/(label+".log")
                    reader = self.command(label+"-required-reader", ["/usr/bin/python3",
                        "scripts/ci/check_required_native_test.py", str(raw), "--test", name],
                        timeout=120, fail_fast=False)
                    if raw.exists():
                        result = exact_result(engine, raw, library, name, code, reader,
                                              library["test_count"])
                    else:
                        result = {"selector": name, "native_effective_exit_code": code,
                                  "required_reader_exit_code": reader, "outer_summary": None,
                                  "verified_named_pass": False, "raw_missing": True}
                    result["label"] = label
                    engine.save_json(self.out/(label+"-result.json"), result, exclusive=True)
                    self.m["exact_results"].append(result)
                    self.save()
            finally:
                after = [rec(a["binary"]["path"]) for a in inventory["all_node_executables"]]
                engine.save_json(self.out/"binary-after.json", after, exclusive=True)
                self.m["binary_after"] = rec(self.out/"binary-after.json")
                self.m["all_binaries_byte_identical"] = before == after
                self.save()
            items = self.m["exact_results"]
            totals = {"passed": 0, "failed": 0, "ignored": 0}
            for item in items:
                if item.get("outer_summary") is not None:
                    for key in totals:
                        totals[key] += item["outer_summary"][key]
            self.m["verified_outer_summary_totals"] = totals
            self.m["incomplete_outer_selectors"] = [
                item["selector"] for item in items if item.get("outer_summary") is None]
            self.m["all_declared_exact_passed"] = (
                len(items) == 16 and all(item["verified_named_pass"] for item in items)
                and self.m["all_binaries_byte_identical"])
            self.save()
            return self.m["all_declared_exact_passed"]

        def finish_targeted(self, failure):
            # Same original complete-source verifier and before/after equality gate.
            try:
                self.source("source-after")
                before, after = self.out/"source-before.json", self.out/"source-after.json"
                same = before.read_bytes() == after.read_bytes()
                self.m["source_receipts"] = {"before": rec(before), "after": rec(after),
                                            "byte_identical": same}
                if not same:
                    failure = failure or "source-changed"
            except BaseException as error:
                self.m["final_source_error"] = repr(error)
                failure = failure or "final-source"
            self.m["disk_after"] = engine.disk()
            self.m["failed_step"] = failure
            self.m["finished_utc"] = engine.utc()
            self.m["finished_unix"] = time.time()
            self.m["current_step"] = None
            self.m.pop("current_step_pid", None)
            self.m["result"] = ("TARGETED_NATIVE_FAILURE_OR_INCOMPLETE_RETAINED" if failure else
                               "TARGETED_NATIVE_PASS_ORIGINAL_GATES_UNQUALIFIED")
            self.save()
            print(json.dumps({"phase": "finished", "result": self.m["result"],
                              "manifest": rec(self.destination)}), flush=True)
            return 1 if failure else 0
    return TargetedRun

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--frozen-sha", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--baseline-terminal-receipt", required=True, type=Path)
    parser.add_argument("--root-authorized-start", required=True, action="store_true")
    args = parser.parse_args()
    for name in ("frozen_sha", "expected_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", getattr(args, name)):
            raise ValueError("explicit complete future SHA/tree are required")
    if args.frozen_sha == BASELINE or args.expected_tree == BASELINE_TREE:
        raise ValueError("this driver cannot rerun the frozen baseline")
    if not args.worktree.is_absolute() or not args.worktree.is_dir():
        raise ValueError("explicit complete isolated worktree is required")
    root = args.worktree.resolve(strict=True)
    if root == FROZEN_SOURCE.resolve() or not root.is_relative_to(BASE):
        raise ValueError("future source must be isolated from the frozen full-package worktree")
    req = checked_json(REQ_FILE, REQ_SHA)
    checked_json(req["plan_path"], req["plan_sha256"])
    prerequisite = baseline_gate(args.baseline_terminal_receipt)
    engine = load_engine(req, root)
    args.phase = "targeted"
    operation = operation_class(engine, req)(args, prerequisite)
    failure = None
    try:
        operation.prepare()
        if not operation.targeted():
            failure = "one-or-more-original-targeted-invocations-failed"
    except BaseException as error:
        failure = operation.m.get("current_step") or "driver"
        operation.m["failure"] = {"step": failure, "error": repr(error)}
        operation.save()
        print(json.dumps({"phase": "failure", "step": failure, "error": repr(error)}), flush=True)
    return operation.finish_targeted(failure)

if __name__ == "__main__":
    sys.exit(main())
