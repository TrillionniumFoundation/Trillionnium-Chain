#!/usr/bin/env python3
"""Once-only independent History integration supplement, after the frozen 16-lib run."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import time

WORK = Path(__file__).resolve().parent
REQ_FILE = WORK / "requirements.json"
REQ_SHA = "4f2b1988ca8045daa3215d4e4d9311eda568d65db79c6f10100463d0772e99b0"

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def rec(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}

def checked_json(path, expected_sha=None):
    path = Path(path)
    if expected_sha is not None and sha(path) != expected_sha:
        raise ValueError("frozen input changed: " + str(path))
    return json.loads(path.read_text())

def load_main(req):
    path = Path(req["main_driver"])
    if sha(path) != req["main_driver_sha256"]:
        raise ValueError("frozen main targeted driver changed")
    checked_json(req["main_requirements"], req["main_requirements_sha256"])
    checked_json(req["plan_path"], req["plan_sha256"])
    checked_json(req["scope_path"], req["scope_sha256"])
    spec = importlib.util.spec_from_file_location("trnm_frozen_targeted_v2_2a6eccce", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # Definitions only; the main entry point is not invoked.
    return module

def main_preparation_gate(args, req, main_module, main_req):
    path = args.main_targeted_manifest.resolve(strict=True)
    expected = main_module.WORK / "runs" / args.frozen_sha / "targeted" / "manifest.json"
    if path != expected.resolve(strict=True):
        raise ValueError("main manifest must be the exact candidate's frozen targeted phase")
    m = checked_json(path)
    root = args.worktree.resolve(strict=True)
    if (m.get("schema") != "trnm-admission-final-root-targeted-native-v1"
        or m.get("commit") != args.frozen_sha or m.get("tree") != args.expected_tree
        or m.get("source_root") != str(root)
        or m.get("target_directory") != req["target_directory"]):
        raise ValueError("main candidate/source/target identity differs")
    if (m.get("result") not in ("TARGETED_NATIVE_FAILURE_OR_INCOMPLETE_RETAINED",
                               "TARGETED_NATIVE_PASS_ORIGINAL_GATES_UNQUALIFIED")
        or not m.get("finished_utc") or m.get("current_step") is not None):
        raise ValueError("main targeted phase is not terminal")
    if m.get("driver") != rec(req["main_driver"]) or m.get("requirements") != rec(req["main_requirements"]):
        raise ValueError("main targeted driver/requirements receipt differs")
    if m.get("engine") != rec(req["engine"]) or sha(req["engine"]) != req["engine_sha256"]:
        raise ValueError("main frozen native engine differs")
    if m.get("expected_counts") != main_req["expected_counts"]:
        raise ValueError("main linked inventory is absent or does not match the complete declared counts")
    for label in req["required_preparation_steps"]:
        steps = [x for x in m.get("steps", []) if x.get("label") == label]
        if len(steps) != 1:
            raise ValueError("missing or repeated main preparation step: " + label)
        step = steps[0]
        if (step.get("exit_code") != 0 or step.get("effective_exit_code") != 0
            or step.get("native_exit_code") != 0 or step.get("native_status") != "command_succeeded"
            or step.get("source_unchanged") is not True or step.get("timed_out") is not False
            or step.get("receipt_incomplete_or_invalid") or step.get("receipt_missing")):
            raise ValueError("main preparation did not complete successfully: " + label)
        for field in ("source_command_receipt", "native_log", "log"):
            r = step.get(field)
            if not r or rec(r["path"]) != r:
                raise ValueError("main preparation evidence changed: " + label + "/" + field)
        original = checked_json(step["source_command_receipt"]["path"])
        if (original.get("status") != "command_succeeded" or original.get("exit_code") != 0
            or original.get("before") is None or original.get("before") != original.get("after")):
            raise ValueError("main original source recorder is incomplete: " + label)
    source = m.get("source_receipts", {})
    if source.get("byte_identical") is not True:
        raise ValueError("main complete source-after is missing or changed")
    for key, name in (("before", "source-before.json"), ("after", "source-after.json")):
        p = path.parent / name
        if rec(p) != source.get(key):
            raise ValueError("main complete source receipt changed: " + key)
    if (path.parent/"source-before.json").read_bytes() != (path.parent/"source-after.json").read_bytes():
        raise ValueError("main complete source before and after differ")
    inventory_path = path.parent / "inventory.json"
    if rec(inventory_path) != m.get("inventory"):
        raise ValueError("main actual compiler/test inventory changed")
    inventory = checked_json(inventory_path)
    if (inventory.get("schema") != "trnm-final-linked-test-inventory-v1"
        or inventory.get("commit") != args.frozen_sha or inventory.get("tree") != args.expected_tree):
        raise ValueError("main inventory source identity differs")
    no_run = next(x for x in m["steps"] if x["label"] == "node-no-run")
    if inventory.get("source_command_receipt") != no_run["source_command_receipt"]:
        raise ValueError("inventory is not bound to the actual successful no-run command")
    artifacts = inventory.get("test_artifacts", [])
    if (m.get("inventory_targets_completed") != len(artifacts)
        or m.get("inventory_targets_total") != len(artifacts)
        or len(artifacts) != main_req["expected_counts"]["all_native_test_targets"]):
        raise ValueError("main complete harness listing is incomplete")
    for item in artifacts:
        if item.get("profile_test") is not True:
            raise ValueError("non-test executable in main test inventory")
        for kind in ("all", "ignored"):
            listing = item.get("listing_logs", {}).get(kind, {})
            if (listing.get("exit_code") != 0 or listing.get("test_bodies_executed") is not False
                or not listing.get("log") or rec(listing["log"]["path"]) != listing["log"]):
                raise ValueError("main harness listing evidence is incomplete")
    selected = [x for x in artifacts if x.get("target_name") == req["target"]
                and x.get("target_kind") == ["test"] and x.get("profile_test") is True]
    if len(selected) != 1:
        raise ValueError("expected exactly one actual native_node integration harness")
    artifact = selected[0]
    tests = artifact.get("tests", [])
    ignored = artifact.get("ignored_tests", [])
    if (artifact.get("test_count") != len(tests) or len(tests) != len(set(tests))
        or artifact.get("ignored_count") != len(ignored)
        or req["selector"] not in tests or req["selector"] in ignored):
        raise ValueError("selected original test is absent, ignored, or has an invalid actual denominator")
    expected_source = root / "trillionnium/crates/trnm-pon-node/tests/native_node.rs"
    if Path(artifact["source"]).resolve(strict=True) != expected_source.resolve(strict=True):
        raise ValueError("native_node executable is not for the actual integration source")
    actual_binary = Path(artifact["binary"]["path"]).resolve(strict=True)
    if not actual_binary.is_relative_to(Path(req["target_directory"])):
        raise ValueError("integration executable lies outside the shared frozen candidate target")
    all_expected = [x["binary"] for x in inventory["all_node_executables"]]
    if len({x["path"] for x in all_expected}) != len(all_expected):
        raise ValueError("duplicate main executable identities")
    if artifact["binary"] not in all_expected:
        raise ValueError("integration harness is absent from complete main binary inventory")
    if m.get("all_binaries_byte_identical") is not True:
        raise ValueError("main test invocations lack a complete unchanged binary fence")
    for field, name in (("binary_before", "binary-before.json"), ("binary_after", "binary-after.json")):
        p = path.parent / name
        if rec(p) != m.get(field) or checked_json(p) != all_expected:
            raise ValueError("main binary before/after evidence is incomplete or changed")
    if [rec(x["path"]) for x in all_expected] != all_expected:
        raise ValueError("current compiled binaries differ from the main tested inventory")
    if sha(root/req["required_reader"]) != req["required_reader_sha256"]:
        raise ValueError("original required-native reader changed")
    # Main exact-body failures do not become an excuse to omit this separate denominator.
    return {"manifest": rec(path), "result": m["result"], "source_receipts": source,
            "inventory": rec(inventory_path), "all_binary_identities": all_expected,
            "selected_artifact": artifact, "provider_binary": m["provider_binary"],
            "provider_exports": m["provider_exports"], "environment": m["environment"],
            "main_exact_results_retained": m.get("exact_results", []),
            "main_native_failures_permitted": True}, artifact

def operation_class(engine, main_module, req):
    class SupplementRun(engine.Run):
        def __init__(self, args, prerequisite, main_gate, artifact):
            super().__init__(args)
            self.artifact = artifact
            self.main_gate = main_gate
            self.m["schema"] = "trnm-history-integration-supplement-v1"
            self.m["engine"] = self.m["driver"]
            self.m["driver"] = rec(__file__)
            self.m["requirements"] = rec(REQ_FILE)
            self.m["original_full_prerequisite"] = prerequisite
            self.m["main_preparation"] = main_gate
            self.m["plan"] = rec(req["plan_path"])
            self.m["expected_tree"] = args.expected_tree
            self.m["phase_rules"] = {
                "integration_selector": req["selector"], "separate_outer_denominator": 1,
                "original_sixteen_lib_denominator_unchanged": True,
                "attempts": 1, "outer_timeout_seconds": 600,
                "internal_budgets_deadlines_changed": False,
                "clippy_or_no_run_repeated": False, "ignored_benchmark_bodies": False,
                "favorable_reruns": False, "full_package_execution": False}
            self.save()

        def prepare(self):
            self.common_before()
            if self.m["tree"] != self.args.expected_tree:
                raise ValueError("supplement source tree differs from explicit candidate")
            if rec(self.out/"source-before.json")["sha256"] != self.main_gate["source_receipts"]["after"]["sha256"]:
                raise ValueError("supplement full source differs from the main final complete source")
            for field in ("provider_binary", "provider_exports", "environment"):
                if self.m[field] != self.main_gate[field]:
                    raise ValueError("supplement build/runtime environment differs from main: " + field)
            if rec(self.main_gate["manifest"]["path"]) != self.main_gate["manifest"]:
                raise ValueError("main result was modified after the preparation gate")
            before = [rec(x["path"]) for x in self.main_gate["all_binary_identities"]]
            if before != self.main_gate["all_binary_identities"]:
                raise ValueError("candidate binaries changed before the independent integration invocation")
            engine.save_json(self.out/"binary-before.json", before, exclusive=True)
            self.m["binary_before"] = rec(self.out/"binary-before.json")
            self.m["actual_target_test_count"] = self.artifact["test_count"]
            self.m["actual_target_ignored_count"] = self.artifact["ignored_count"]
            self.m["actual_expected_filtered_count"] = self.artifact["test_count"] - 1
            self.m["disk_before_test_body"] = engine.disk()
            self.save()

        def run_one(self):
            label, name = req["label"], req["selector"]
            try:
                code = self.native(label, ["test", "--locked", "--offline", "--manifest-path",
                    "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--all-features",
                    "--test", req["target"], name, "--", "--exact", "--nocapture", "--test-threads=1"],
                    timeout=req["timeout_seconds"], fail_fast=False)
                raw = self.out/"records"/(label+".log")
                reader = self.command(label+"-required-reader", ["/usr/bin/python3",
                    req["required_reader"], str(raw), "--test", name],
                    timeout=req["reader_timeout_seconds"], fail_fast=False)
                if raw.exists():
                    result = main_module.exact_result(engine, raw, self.artifact, name, code,
                                                     reader, self.artifact["test_count"])
                else:
                    result = {"selector": name, "native_effective_exit_code": code,
                              "required_reader_exit_code": reader, "outer_summary": None,
                              "verified_named_pass": False, "raw_missing": True}
                engine.save_json(self.out/"integration-result.json", result, exclusive=True)
                self.m["integration_result"] = result
                self.m["integration_result_file"] = rec(self.out/"integration-result.json")
                outer = result.get("outer_summary")
                self.m["separate_verified_outer_totals"] = (
                    {key: outer[key] for key in ("passed","failed","ignored")} if outer else
                    {"passed":0,"failed":0,"ignored":0})
                self.m["outer_completion_unknown"] = outer is None
                self.save()
            finally:
                after = []
                for expected in self.main_gate["all_binary_identities"]:
                    try:
                        after.append(rec(expected["path"]))
                    except BaseException as error:
                        after.append({"path": expected["path"], "read_error": repr(error)})
                engine.save_json(self.out/"binary-after.json", after, exclusive=True)
                self.m["binary_after"] = rec(self.out/"binary-after.json")
                self.m["all_binaries_byte_identical"] = after == self.main_gate["all_binary_identities"]
                self.save()
            return (self.m.get("integration_result", {}).get("verified_named_pass") is True
                    and self.m["all_binaries_byte_identical"])

        def finish_supplement(self, failure):
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
            self.m["result"] = ("INDEPENDENT_HISTORY_FAILURE_OR_INCOMPLETE_RETAINED" if failure else
                               "INDEPENDENT_HISTORY_PASS_ORIGINAL_GATES_UNQUALIFIED")
            self.save()
            print(json.dumps({"phase":"finished","result":self.m["result"],
                              "manifest":rec(self.destination)}), flush=True)
            return 1 if failure else 0
    return SupplementRun

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--frozen-sha", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--baseline-terminal-receipt", required=True, type=Path)
    parser.add_argument("--main-targeted-manifest", required=True, type=Path)
    parser.add_argument("--root-authorized-start", required=True, action="store_true")
    args = parser.parse_args()
    for key in ("frozen_sha", "expected_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", getattr(args, key)):
            raise ValueError("explicit complete future candidate SHA/tree are required")
    req = checked_json(REQ_FILE, REQ_SHA)
    root = args.worktree.resolve(strict=True)
    if not args.worktree.is_absolute() or str(root) != req["expected_worktree"]:
        raise ValueError("explicit isolated candidate worktree differs")
    main_module = load_main(req)
    if args.frozen_sha == main_module.BASELINE or args.expected_tree == main_module.BASELINE_TREE:
        raise ValueError("supplement cannot rerun the frozen baseline")
    prerequisite = main_module.baseline_gate(args.baseline_terminal_receipt)
    main_req = checked_json(req["main_requirements"], req["main_requirements_sha256"])
    # The existing external main-phase lock is read-only here. Holding it prevents
    # overlap with another main driver; neither the source nor target is modified.
    owner = main_module.WORK/"runs"/args.frozen_sha/"driver-owner.lock"
    with owner.open("rb") as main_owner:
        fcntl.flock(main_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        gate, artifact = main_preparation_gate(args, req, main_module, main_req)
        engine = main_module.load_engine(main_req, root)
        engine.WORK = WORK
        engine.TARGET = Path(req["target_directory"])
        args.phase = "history-supplement"
        operation = operation_class(engine, main_module, req)(args, prerequisite, gate, artifact)
        failure = None
        try:
            operation.prepare()
            if not operation.run_one():
                failure = "original-independent-integration-invocation-failed"
        except BaseException as error:
            failure = operation.m.get("current_step") or "driver"
            operation.m["failure"] = {"step":failure,"error":repr(error)}
            operation.save()
            print(json.dumps({"phase":"failure","step":failure,"error":repr(error)}), flush=True)
        return operation.finish_supplement(failure)

if __name__ == "__main__":
    sys.exit(main())
