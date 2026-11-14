#!/usr/bin/env python3
"""One bounded synthetic attribution check. Never a Node test qualification."""
import hashlib
import json
from pathlib import Path
import time
import types

ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
TOOLS = ROOT / "recovery-evidence-tools"
OUT = TOOLS / "union-attribution-check-v1"
HELPER_SHA = "3add13fa42e47103c90d6e35c98c7be0accccc739963bad26aabcb8c930900cf"
UNION_SHA = "5ada449347923c1b51bd85d179e931f73a8af7cae6cfb65765d28f1fbaac4650"


def load(name, digest):
    path = TOOLS / name
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    module = types.ModuleType("synthetic_check_" + name.removesuffix(".py"))
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, {"path": str(path), "bytes": len(raw), "sha256": digest}


def write(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path = OUT / name
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    OUT.mkdir()
    helper, helper_id = load("audit_failed_node_observation_recovery_v1.py", HELPER_SHA)
    union, union_id = load("audit_node_union_coverage_recovery_v1.py", UNION_SHA)
    target = {"name": "fixture_probe", "kind": ["test"], "test": True, "harness": None,
              "source": "trillionnium/crates/trnm-pon-node/tests/fixture_probe.rs",
              "source_sha256": "a" * 64, "required_features": []}
    name = "tests/fixture_probe.rs"
    target_dir = "/synthetic-fixture-only/target"
    header = "     Running " + name + " (" + target_dir + "/debug/deps/fixture_probe-0123456789abcdef)\n"
    def summary(passed, failed=0, ignored=0, filtered=0):
        status = "FAILED" if failed else "ok"
        return ("test result: " + status + ". " + str(passed) + " passed; " + str(failed)
                + " failed; " + str(ignored) + " ignored; 0 measured; " + str(filtered)
                + " filtered out; finished in 0.01s\n")
    def parse(body):
        raw = (header + body).encode()
        return raw, union.parse_run(helper, raw, {name: target}, target_dir)
    checks = []
    def record(label, action):
        try:
            details = action()
            checks.append({"case": label, "passed": True, "details": details})
        except Exception as failure:
            checks.append({"case": label, "passed": False, "failure_type": type(failure).__name__,
                           "message": str(failure)})
    def complete_failure_and_span():
        raw, result = parse("running 2 tests\n" + summary(1, failed=1))
        row = result["coverage"][name]
        assert row["status"] == "completed_with_failures"
        assert union.sum_rows([row["summary"]]) == {
            "passed": 1, "failed": 1, "ignored": 0, "measured": 0, "filtered_out": 0}
        span = result["segments"][0]["summary_byte_span"]
        assert raw[span["start_inclusive"]:span["end_exclusive"]] == summary(1, failed=1).encode()
        return {"counted_failure": 1, "summary_span_exact": True}
    record("complete_failure_with_exact_byte_span", complete_failure_and_span)
    def nested_excluded():
        raw, result = parse("running 3 tests\nrunning 1 test\n" + summary(1, filtered=700)
                            + summary(2, ignored=1))
        row = result["coverage"][name]
        assert row["status"] == "completed_passed" and row["summary"]["passed"] == 2
        assert row["summary"]["ignored"] == 1 and row["summary"]["filtered_out"] == 0
        assert result["segments"][0]["nested_summary_candidates"][0]["filtered_out"] == 700
        return {"outer_passed": 2, "outer_ignored": 1, "child_filtered_not_counted": 700}
    record("nested_different_size_and_filtered_are_excluded", nested_excluded)
    def same_size_late_child():
        raw, result = parse("running 2 tests\nrunning 2 tests\n" + summary(2)
                            + summary(1, ignored=1))
        row = result["coverage"][name]
        assert row["status"] == "ambiguous_or_inconsistent" and row["summary"] is None
        assert any(p["code"] == "PARENT_CHILD_SUMMARY_ATTRIBUTION_AMBIGUOUS"
                   for p in result["segments"][0]["attribution_problems"])
        return {"counted_summary": None}
    record("same_size_late_child_is_refused_after_greedy_pairing", same_size_late_child)
    def duplicate_target():
        body = "running 1 test\n" + summary(1)
        raw = ((header + body) * 2).encode()
        result = union.parse_run(helper, raw, {name: target}, target_dir)
        row = result["coverage"][name]
        assert row["status"] == "duplicate_headers_unqualified" and row["summary"] is None
        assert any(p["code"] == "DUPLICATE_CARGO_TARGET" for p in result["problems"])
        return {"counted_summary": None}
    record("duplicate_cargo_header_refuses_target_count", duplicate_target)
    def interrupted_parent():
        raw, result = parse("running 3 tests\nrunning 1 test\n" + summary(1, filtered=9))
        row = result["coverage"][name]
        assert row["status"] == "incomplete_at_termination" and row["summary"] is None
        return {"counted_summary": None, "status": row["status"]}
    record("incomplete_parent_does_not_inherit_child_summary", interrupted_parent)
    def terminal_rejections():
        base = {"job_id": "synthetic-fixture-only-job", "audit_recorded": True,
                "terminal_publication_confirmed": True, "output_complete": True,
                "output_durable": True, "state": "running", "exit_code": None}
        paths = []
        for suffix, update in (("running", {}), ("boolean-exit", {"state": "succeeded", "exit_code": False})):
            value = {**base, **update}
            file = write("synthetic-terminal-" + suffix + ".json", value)
            paths.append(file)
            try:
                union.terminal(Path(file["path"]), "synthetic-fixture-only-job")
            except ValueError:
                continue
            raise AssertionError("synthetic invalid ending accepted: " + suffix)
        return {"synthetic_input_files": paths, "actual_test_logs_read": False}
    record("running_and_boolean_exit_statuses_are_refused", terminal_rejections)
    def canonical_key():
        other = {**target, "source": target["source"].replace("tests/", "examples/"),
                 "kind": ["example"]}
        assert union.target_key(target) != union.target_key(other)
        return {"same_basename_distinct_inventory_identity": True}
    record("kind_name_source_key_is_not_binary_basename", canonical_key)
    def strict_numbers():
        assert all(not union.natural(value) for value in (False, True, 0.0, -1, "0", None))
        assert union.natural(0) and union.natural(1)
        return {"bool_float_negative_string_null_rejected": True}
    record("strict_integer_count_validation", strict_numbers)
    _, own = union.read(__file__)
    result = {
        "schema": "pon-node-union-attribution-synthetic-check-v1",
        "observed_unix_seconds": time.time(), "script": own,
        "helper": helper_id, "union_auditor": union_id,
        "checks": checks, "passed": sum(row["passed"] for row in checks),
        "failed": sum(not row["passed"] for row in checks),
        "actual_node_tests_run": False, "node_live_log_read": False,
        "actual_union_auditor_entry_executed": False, "qualification": False,
        "scope": "Synthetic parser and readiness boundary checks only; no claim about actual remainder results.",
    }
    artifact = write("result.json", result)
    print(json.dumps({"artifact": artifact, "passed": result["passed"],
                      "failed": result["failed"], "qualification": False}, sort_keys=True))
    return 0 if result["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
