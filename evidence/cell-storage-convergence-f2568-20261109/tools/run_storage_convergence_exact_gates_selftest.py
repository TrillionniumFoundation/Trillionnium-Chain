#!/usr/bin/env python3
"""Fabricated parser inputs only: never execute Runner, Cargo, or Rust."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_storage_convergence_exact_gates.py"
spec = importlib.util.spec_from_file_location("storage_exact", RUNNER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks = []


def check(name, fn):
    fn()
    checks.append(name)


def refused(fn):
    try:
        fn()
    except m.GateError:
        return
    raise AssertionError("invalid synthetic input accepted")


def fixture():
    result = {}
    for label, groups in m.REQUIRED_NEW_TESTS.items():
        names = sorted(n for group in groups.values() for n in group)
        names.append("cell::retained::synthetic_prior_case" if label == "complete-da-native"
                     else "store::storage_service::tests::synthetic_prior_case")
        harnesses = [{"passed": len(names), "filtered_out": 0 if label == "complete-da-native" else 137,
                      "test_names": names}]
        if label == "complete-da-native":
            harnesses[0]["test_names"].append(m.PROCESS_DEATH_PARENT)
            harnesses[0]["passed"] += 1
            harnesses += [{"passed": 0, "filtered_out": 0, "test_names": []},
                          {"passed": 2, "filtered_out": 0,
                           "test_names": ["src/cell.rs - cell::Fixture (line 4)",
                                          "src/cell.rs - cell::Fixture (line 9) - compile fail"]}]
        result[label] = {"total_passed": sum(h["passed"] for h in harnesses),
                         "harnesses": harnesses, "new_test_roster": copy.deepcopy(groups)}
    return result


def render(rows):
    lines = []
    for h in rows:
        lines.append(f"running {len(h['test_names'])} tests")
        lines.extend(f"test {name} ... ok" for name in h["test_names"])
        lines.append(f"test result: ok. {h['passed']} passed; 0 failed; 0 ignored; 0 measured; "
                     f"{h['filtered_out']} filtered out; finished in 0.01s")
    return "\n".join(lines) + "\n"


def bad_config(change):
    e = fixture()
    change(e)
    refused(lambda: m.validate_native_expectations(e))


def bad_output(change, label="complete-da-native"):
    e = fixture()[label]
    refused(lambda: m.exact_native_execution(change(render(e["harnesses"])), e, label))


def valid():
    for label, e in m.validate_native_expectations(fixture()).items():
        actual = m.exact_native_execution(render(e["harnesses"]), e, label)
        assert actual["total_passed"] == e["total_passed"]
        assert actual["harnesses"] == e["harnesses"]
    assert sum(map(len, m.REQUIRED_NEW_TESTS["complete-da-native"].values())) == 70
    assert sum(map(len, m.REQUIRED_NEW_TESTS["node-storage-owner-native"].values())) == 13


def absent_new_case():
    def change(e):
        x = e["complete-da-native"]
        x["harnesses"][0]["test_names"].pop(0)
        x["harnesses"][0]["passed"] -= 1
        x["total_passed"] -= 1
    bad_config(change)


def duplicate_residency():
    def change(e):
        roster = e["complete-da-native"]["new_test_roster"]
        names = [n for n in roster["version_retention"] if "::residency::" in n]
        assert len(names) == 3
        roster["duplicate_residency"] = names
    bad_config(change)


check("valid complete DA/Node fixtures, empty binary and spaced doc names", valid)
check("missing mandatory group rejects", lambda: bad_config(lambda e: e["complete-da-native"]["new_test_roster"].pop("snapshot")))
check("missing new name rejects even if harness contains it", lambda: bad_config(lambda e: e["complete-da-native"]["new_test_roster"]["snapshot"].pop()))
check("new name absent from full frozen roster rejects", absent_new_case)
check("TCA3 residency cannot be counted twice", duplicate_residency)
check("zero expected total rejects", lambda: bad_config(lambda e: e["complete-da-native"].update(total_passed=0)))
check("DA cannot expect a filtered harness", lambda: bad_config(lambda e: e["complete-da-native"]["harnesses"][0].update(filtered_out=1)))
check("frozen count must equal full roster length", lambda: bad_config(lambda e: e["complete-da-native"]["harnesses"][0].update(passed=999)))
check("frozen total must equal harness counts", lambda: bad_config(lambda e: e["complete-da-native"].update(total_passed=999)))
check("Node cannot omit a new funding case", lambda: bad_config(lambda e: e["node-storage-owner-native"]["new_test_roster"]["shard"].pop()))
check("empty compile-only output is not runtime", lambda: bad_output(lambda _: ""))
empty = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
check("zero actual native execution rejects", lambda: bad_output(lambda _: empty))
check("missing case with unchanged summary rejects", lambda: bad_output(lambda t: t.replace("test cell::retained::synthetic_prior_case ... ok\n", "")))
check("same count with substituted retained name rejects", lambda: bad_output(lambda t: t.replace("cell::retained::synthetic_prior_case", "cell::retained::different_case")))
check("same count with substituted new name rejects", lambda: bad_output(lambda t: t.replace(m.REQUIRED_NEW_TESTS["complete-da-native"]["snapshot"][0], "cell::snapshot_schedule::tests::substitute")))
check("ignored case is not pass", lambda: bad_output(lambda t: t.replace(" ... ok", " ... ignored", 1)))
check("ignored summary is not pass", lambda: bad_output(lambda t: t.replace("0 ignored", "1 ignored", 1)))
check("failed case is not pass", lambda: bad_output(lambda t: t.replace(" ... ok", " ... FAILED", 1)))
check("missing harness rejects", lambda: bad_output(lambda t: t.replace(empty, "")))
check("extra empty harness rejects", lambda: bad_output(lambda t: t + empty))
check("unfinished harness rejects", lambda: bad_output(lambda t: t + "running 1 test\n"))
check("unexpected Node filtered count rejects", lambda: bad_output(lambda t: t.replace("137 filtered out", "136 filtered out"), "node-storage-owner-native"))
check("duplicate JSON configuration keys reject", lambda: refused(lambda: m.json_load(b'{"sha":"a","sha":"b"}')))

def actual_child_form():
    original = json.loads((ROOT / "storage-convergence-process-death-observation.json").read_bytes())
    at = original["lines"].index(m.PROCESS_DEATH_LINES[0])
    assert tuple(original["lines"][at:at + 3]) == m.PROCESS_DEATH_LINES
    e = fixture()["complete-da-native"]
    normal = "test " + m.PROCESS_DEATH_PARENT + " ... ok\n"
    observed = "\n".join(m.PROCESS_DEATH_LINES) + "\n"
    text = render(e["harnesses"]).replace(normal, observed)
    result = m.exact_native_execution(text, e, "complete-da-native")
    assert result["total_passed"] == e["total_passed"]
    assert len(result["nested_child_observations"]) == 1
    assert result["nested_child_observations"][0]["child_independent_results_counted"] == 0
    assert result["harnesses"][0]["test_names"].count(m.PROCESS_DEATH_PARENT) == 1
    for name, bad in (
        ("nested child under wrong parent rejects", observed.replace(m.PROCESS_DEATH_PARENT, "cell::retention::tests::wrong_parent")),
        ("duplicate nested child observation rejects", observed + observed),
        ("missing parent completion ok rejects", observed.replace("\nok\n", "\n")),
        ("unobserved blank-line variant rejects", observed.replace("\nrunning 1 test", "\n\nrunning 1 test")),
        ("different child test-count banner rejects", observed.replace("running 1 test", "running 2 tests")),
    ):
        refused(lambda bad=bad: m.exact_native_execution(text.replace(observed, bad), e, "complete-da-native"))
        checks.append(name)

check("actual retained process-death form counts parent once and child zero", actual_child_form)
check("standalone ok outside the exact retained form rejects", lambda: bad_output(lambda t: t + "ok\n"))


def actual_prefixed_child_form():
    original = json.loads((ROOT / "storage-convergence-process-death-prefixed-observation.json").read_bytes())
    assert original["sha256"] == "1ce59bde5c6802777295b4404ebb0e8ec3af3e403e264aa0c9ae31dbcd06acb2"
    assert original["bytes"] == 85158 and original["line_count"] == 831
    assert original["excerpt_start_line"] == 543 and original["excerpt_end_line"] == 545
    assert original["original_gate_state"] == "failed"
    assert tuple(original["lines"]) == m.PROCESS_DEATH_CHILD_PREFIX_LINES
    assert m.PROCESS_DEATH_FORMS == (m.PROCESS_DEATH_LINES, m.PROCESS_DEATH_CHILD_PREFIX_LINES)
    e = fixture()["complete-da-native"]
    e["harnesses"][0]["test_names"].append(m.PROCESS_DEATH_CHILD)
    e["harnesses"][0]["passed"] += 1
    e["total_passed"] += 1
    normal_parent = "test " + m.PROCESS_DEATH_PARENT + " ... ok\n"
    normal_child = "test " + m.PROCESS_DEATH_CHILD + " ... ok\n"
    observed = "\n".join(original["lines"]) + "\n"
    normal_text = render(e["harnesses"])
    text = normal_text.replace(normal_parent, observed)
    result = m.exact_native_execution(text, e, "complete-da-native")
    assert result["total_passed"] == e["total_passed"]
    assert result["harnesses"] == e["harnesses"]
    assert result["harnesses"][0]["test_names"].count(m.PROCESS_DEATH_PARENT) == 1
    assert result["harnesses"][0]["test_names"].count(m.PROCESS_DEATH_CHILD) == 1
    assert len(result["nested_child_observations"]) == 1
    assert result["nested_child_observations"][0]["observed_lines"] == original["lines"]
    assert result["nested_child_observations"][0]["child_independent_results_counted"] == 0
    assert result["nested_child_observations"][0]["parent_results_counted"] == 1
    extra_summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 713 filtered out; finished in 0.01s\n"
    for name, bad in (
        ("prefixed nested child under wrong parent rejects", observed.replace(m.PROCESS_DEATH_PARENT, "cell::retention::tests::wrong_parent")),
        ("prefixed nested form with different child rejects", observed.replace(m.PROCESS_DEATH_CHILD, "cell::retention::tests::different_child")),
        ("prefixed nested form missing parent completion ok rejects", observed.replace(" ... ok\n", " ... \n")),
        ("prefixed nested form with failed status rejects", observed.replace(" ... ok\n", " ... FAILED\n")),
        ("prefixed nested form with ignored status rejects", observed.replace(" ... ok\n", " ... ignored\n")),
        ("prefixed nested form with extra child summary rejects", observed + extra_summary),
        ("prefixed nested form with duplicated child line rejects", observed + normal_child),
        ("duplicate prefixed nested observation rejects", observed + observed),
        ("prefixed nested form with blank line rejects", observed.replace("\nrunning 1 test", "\n\nrunning 1 test")),
        ("prefixed nested form with leading child whitespace rejects", observed.replace("\ntest " + m.PROCESS_DEATH_CHILD, "\n test " + m.PROCESS_DEATH_CHILD)),
        ("prefixed nested form with trailing child whitespace rejects", observed.replace(" ... ok\n", " ... ok \n")),
        ("prefixed nested form with extra standalone ok rejects", observed + "ok\n"),
        ("prefixed nested form with different child count rejects", observed.replace("running 1 test", "running 2 tests")),
    ):
        refused(lambda bad=bad: m.exact_native_execution(text.replace(observed, bad), e, "complete-da-native"))
        checks.append(name)
    missing_normal_child = normal_text.replace(normal_child, "").replace(normal_parent, observed)
    check("nested child prefix cannot substitute for its normal roster case",
          lambda: refused(lambda: m.exact_native_execution(missing_normal_child, e, "complete-da-native")))
    check("prefixed nested form outside a running harness rejects",
          lambda: refused(lambda: m.exact_native_execution(observed + normal_text, e, "complete-da-native")))
    check("prefixed nested form is unavailable to the Node gate",
          lambda: refused(lambda: m.exact_native_execution(text, e, "node-storage-owner-native")))


check("actual child-prefix form counts parent once and separate ordinary child once", actual_prefixed_child_form)


def sealed_fixture():
    return "\n".join(
        name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + name + ") ... ok"
        for name in m.SEALED_PYTHON_REQUIRED_NAMES
    ) + "\n\n" + "-" * 70 + "\nRan 24 tests in 0.172s\n\nOK\n"


def valid_sealed():
    actual = m.exact_sealed_python_execution(sealed_fixture())
    assert actual["passed"] == 24 and actual["ignored_or_skipped"] == 0
    assert set(actual["test_names"]) == set(m.SEALED_PYTHON_REQUIRED_NAMES)


check("complete frozen Python transcript parses", valid_sealed)
good_sealed = sealed_fixture()
first_sealed = good_sealed.splitlines()[0] + "\n"
for name, bad in (
    ("empty Python output rejects", ""),
    ("zero Python execution rejects", "Ran 0 tests in 0.000s\n\nOK\n"),
    ("missing Python case rejects", good_sealed.replace(first_sealed, "", 1)),
    ("duplicate Python case rejects", good_sealed.replace(first_sealed, first_sealed * 2, 1)),
    ("substituted Python case rejects", good_sealed.replace(m.SEALED_PYTHON_REQUIRED_NAMES[0], "test_substituted", 2)),
    ("skipped Python case rejects", good_sealed.replace(" ... ok", " ... skipped 'unsupported'", 1)),
    ("failed Python case rejects", good_sealed.replace(" ... ok", " ... FAIL", 1)),
    ("failed Python summary rejects", good_sealed.replace("\nOK\n", "\nFAILED (failures=1)\n", 1)),
    ("smaller Python summary count rejects", good_sealed.replace("Ran 24 tests", "Ran 23 tests", 1)),
    ("larger Python summary count rejects", good_sealed.replace("Ran 24 tests", "Ran 25 tests", 1)),
    ("wrong Python class rejects", good_sealed.replace("SealedHandoffControls.", "AnotherClass.", 1)),
    ("unequal Python method identities reject", good_sealed.replace(m.SEALED_PYTHON_REQUIRED_NAMES[0] + ")", m.SEALED_PYTHON_REQUIRED_NAMES[1] + ")", 1)),
    ("duplicate Python harness rejects", good_sealed + good_sealed),
    ("leading standalone Python OK rejects", "OK\n" + good_sealed),
    ("trailing standalone Python OK rejects", good_sealed + "OK\n"),
    ("missing Python summary boundary rejects", good_sealed.replace("-" * 70 + "\n", "", 1)),
):
    check(name, lambda bad=bad: refused(lambda: m.exact_sealed_python_execution(bad)))


added_sealed_names = ['test_project_source_compiler_preserves_original_annotation_semantics', 'test_failed_supervisor_cancels_connector_before_handshake', 'test_failed_supervisor_cancels_ready_wait_after_sealed_handoff']
retained_only_sealed = good_sealed
for added_name in added_sealed_names + ["test_runtime_virtual_namespace_requires_exact_pinned_singleton","test_runtime_virtual_namespace_refuses_source_or_loader_drift","test_runtime_module_origin_refuses_other_relative_paths"]:
    added_line = added_name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + added_name + ") ... ok\n"
    assert retained_only_sealed.count(added_line) == 1
    retained_only_sealed = retained_only_sealed.replace(added_line, "", 1)
retained_only_sealed = retained_only_sealed.replace("Ran 24 tests", "Ran 18 tests", 1)
assert retained_only_sealed.count(" ... ok\n") == 18
check("original eighteen alone cannot satisfy the expanded Python roster",
      lambda: refused(lambda: m.exact_sealed_python_execution(retained_only_sealed)))
for added_name in added_sealed_names:
    added_line = added_name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + added_name + ") ... ok\n"
    missing_added = good_sealed.replace(added_line, "", 1).replace("Ran 24 tests", "Ran 23 tests", 1)
    check("required added Python control cannot be omitted: " + added_name,
          lambda bad=missing_added: refused(lambda: m.exact_sealed_python_execution(bad)))



runtime_origin_names = ["test_runtime_virtual_namespace_requires_exact_pinned_singleton","test_runtime_virtual_namespace_refuses_source_or_loader_drift","test_runtime_module_origin_refuses_other_relative_paths"]
previous_only_sealed = good_sealed
for added_name in runtime_origin_names:
    added_line = added_name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + added_name + ") ... ok\n"
    assert previous_only_sealed.count(added_line) == 1
    previous_only_sealed = previous_only_sealed.replace(added_line, "", 1)
previous_only_sealed = previous_only_sealed.replace("Ran 24 tests", "Ran 21 tests", 1)
assert previous_only_sealed.count(" ... ok\n") == 21
check("previous twenty-one alone cannot satisfy the expanded Python roster",
      lambda: refused(lambda: m.exact_sealed_python_execution(previous_only_sealed)))
for added_name in runtime_origin_names:
    added_line = added_name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + added_name + ") ... ok\n"
    missing_added = good_sealed.replace(added_line, "", 1).replace("Ran 24 tests", "Ran 23 tests", 1)
    check("required runtime-origin Python control cannot be omitted: " + added_name,
          lambda bad=missing_added: refused(lambda: m.exact_sealed_python_execution(bad)))


for label, group in (
    ("complete-da-native", "research_fds"),
    ("complete-da-native", "retained_shard_capacity"),
    ("node-storage-owner-native", "recovery"),
):
    check("new mandatory " + group + " group cannot be omitted",
          lambda label=label, group=group: bad_config(lambda e: e[label]["new_test_roster"].pop(group)))


def retained_nineteen():
    old_spec = importlib.util.spec_from_file_location("storage_previous_exact", ROOT / "run_exact_gates_previous.py")
    old = importlib.util.module_from_spec(old_spec)
    old_spec.loader.exec_module(old)
    old_commands = old.gate_commands(Path("/synthetic/observation"), "f" * 40)
    new_commands = m.gate_commands(Path("/synthetic/observation"), "f" * 40)
    assert len(old_commands) == 19 and len(new_commands) == 25
    selected = [(label, argv) for label, argv in new_commands if label in dict(old_commands)]
    assert selected == old_commands
    assert len(dict(new_commands)) == 25
    assert "sealed-research-python-controls" not in m.SYNTHETIC
    assert dict(new_commands)["sealed-research-python-controls"] == [
        "python3", "-B", "-m", "unittest", "discover", "-s", "scripts",
        "-p", "test_llm_cell_sealed_worker_v1.py", "-v",
    ]


check("all nineteen original argv and order remain exact within twenty-five gates", retained_nineteen)

print(json.dumps({"schema": "storage-convergence-exact-runner-synthetic-selftest-v1", "passed": True,
                  "runner_executed": False, "native_commands_executed": 0,
                  "fabricated_harness_text_is_native_evidence": False,
                  "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
                  "observed_process_death_excerpt_sha256": hashlib.sha256((ROOT / "storage-convergence-process-death-observation.json").read_bytes()).hexdigest(),
                  "observed_prefixed_process_death_excerpt_sha256": hashlib.sha256((ROOT / "storage-convergence-process-death-prefixed-observation.json").read_bytes()).hexdigest(),
                  "previous_runner_sha256_unchanged": hashlib.sha256((ROOT / "run_exact_gates_previous.py").read_bytes()).hexdigest(),
                  "checks": checks}, indent=2))
