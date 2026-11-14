#!/usr/bin/env python3
"""Collect actual Python controls and retrospective original-material readbacks.

This adds no training, payment, execution authority or qualification. The
bindings pin comes from the committed retrospective file, not preregistration.
Whole-checkout identity is checked separately by the original CI source reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
CI_CONTRACT_METHODS = (
    'test_actual_merged_lanes_keep_all_original_controls',
    'test_independent_literals_keep_original_neighbors_and_unique_commands',
    'test_credit_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_pq_effect_root_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_native_observation_guard_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_partial_campaign_reader_cannot_skip_duplicate_move_or_swallow_failure',
    'test_current_mapping_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_upstream_security_controls_cannot_be_skipped_or_suppressed',
    'test_posterior_policy_controls_cannot_be_skipped_or_suppressed',
    'test_hash_use_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_stark_route_field_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_conditional_sampler_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_current_lifetime_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_fixed_probability_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_joint_consensus_qualification_commands_cannot_be_omitted_moved_or_skipped',
    'test_joint_resource_commands_cannot_be_omitted_moved_or_skipped',
    'test_completion_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_learning_business_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_system_security_commands_cannot_change_position_multiplicity_or_failure_policy',
    'test_complete_groups_cannot_reorder_duplicate_or_hide_in_shell_conditions',
    'test_whole_repository_and_external_lanes_cannot_suppress_failures',
)
TESTS = (
    ("adoption-controls", "scripts/test_cell_adoption_readback.py", 26, ()),
    ("iteration-controls", "scripts/test_cell_learning_iteration_join.py", 25, ()),
    ("completion-controls", "scripts/test_cell_learning_completion_join.py", 13, ()),
    ("economics-controls", "scripts/test_cell_learning_business_economics.py", 29, ()),
    ("business-controls", "scripts/test_cell_learning_business_join.py", 24, ()),
    ("trainer-no-update-controls", "scripts/test_cell_learning_training_no_update_join.py", 17, ()),
    ("ci-contract-controls", "scripts/ci/test_ci_contract.py", len(CI_CONTRACT_METHODS),
     ("MergedQualificationLaneTests",)),
)
SOURCE_FILES = (
    "scripts/cell_adoption_readback.py", "scripts/cell_learning_iteration_join.py",
    "scripts/cell_learning_completion_join.py", "scripts/cell_learning_business_economics.py",
    "scripts/cell_learning_scope_join.py", "evidence/heplcp03-interop-20261111/native-fixture.json",
    "scripts/cell_learning_business_join.py", *(item[1] for item in TESTS),
    "scripts/ci/check_ci_contract.py", "scripts/ci/ci_job.sh",
    "scripts/ci/verify_ci_source.py", "scripts/ci/run_cell_learning_business_readback.py",
    ".github/workflows/cell-learning-business-readback.yml",
)
ORIGINAL = Path("evidence/hepta-real-native-adoption-20261108/chain-reader")
BINDINGS = Path("evidence/cell-learning-business-readback-20261109/bindings")
FALSE_FLAGS = (
    "source_execution_authenticated", "root_envelope_verified",
    "pre_dispatch_freeze_authenticated", "complete_version_custody_verified",
    "physical_installation_accepted", "independent_consumer_verified",
    "funded_mapping_authenticated", "cost_completeness_verified", "physical_costs_verified",
    "full_learning_iteration_completed", "real_model_training_verified",
    "independent_control_accepted", "settlement_verified", "hepta_final_use_accepted",
    "production_activation",
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def write_json(path, value):
    path.write_bytes(encoded(value))


def digest(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def selected_sources():
    return {name: digest(ROOT / name) for name in SOURCE_FILES}


def replay_command(case):
    bindings = BINDINGS / (case + ".json")
    command = [sys.executable, "scripts/cell_learning_business_join.py", "--bindings", str(bindings),
               "--bindings-sha256", digest(ROOT / bindings)["sha256"]]
    paths = [bindings, ORIGINAL / case / "stdout.json"]
    for name in ("selection", "completed", "readback", "freeze", "expected"):
        path = ORIGINAL / case / (name + (".bin" if name in ("selection", "completed") else ".json"))
        command.extend(("--" + name, str(path)))
        paths.append(path)
    return command, {str(path): digest(ROOT / path) for path in paths}


def check_replay(raw, case, directory):
    report = json.loads(raw)
    if report.get("schema") != "trnm-cell-learning-business-review-v2":
        raise ValueError("business report schema differs")
    if (report.get("authority"), report.get("current_permission"), report.get("qualification")) != (
            "DENY_ALL", "NOT_EXPORTED", "HOLD_NO_GO"):
        raise ValueError("readback authority or qualification changed")
    if any(report.get(name) is not False for name in FALSE_FLAGS):
        raise ValueError("readback promoted a qualification flag")
    if (report.get("capture_basis") != "retrospective-research-readback" or
            report.get("economic_observations") != [] or
            report.get("funded_mapping_observed") is not False or
            report.get("declared_root_envelope_schema") is not None):
        raise ValueError("retrospective readback scope changed")
    if (report.get("decision"), report.get("receipt_count")) != (
            ("Selection", 7) if case == "adopt-v1" else ("NoUpdate", 6)):
        raise ValueError("original decision or receipt count changed")
    provenance = report["next_use_provenance"]
    if (provenance.get("status") != "SAME_ORIGINAL_ACTOR_DISTINCT_RUN_ONLY" or
            provenance.get("scope") != "decoded-checkpoint-actor-and-run-identifiers-only" or
            provenance.get("authenticated") is not False or
            any(provenance.get(name) is not True for name in
                ("same_principal", "same_agent", "same_cell", "distinct_run"))):
        raise ValueError("original actor/run provenance changed")
    source_actor, next_actor = provenance["source_actor"], provenance["next_use_actor"]
    if (any(source_actor[name] != next_actor[name] for name in
            ("principal_id", "agent_id", "cell_id")) or
            source_actor["source_run_id"] == next_actor["run_id"] or
            next_actor != report["completion_review"]["final_observation"]["state_partition"] or
            provenance["completed_checkpoint_sha256"] != digest(
                ROOT / ORIGINAL / case / "completed.bin")["sha256"]):
        raise ValueError("original actor/run identifiers or checkpoint bytes differ")
    if report.get("independent_consumer_gate") != dict(
            status="MISSING_ORIGINAL_INDEPENDENT_CONSUMER_RECEIPT", verified=False):
        raise ValueError("missing independent consumer receipt was promoted")
    completion = encoded(report["completion_review"])
    (directory / "completion-review.json").write_bytes(completion)
    archived = (ROOT / ORIGINAL / case / "stdout.json").read_bytes()
    if completion != archived:
        raise ValueError("completion subreport differs from original archived stdout bytes")
    (directory / "report.json").write_bytes(raw)
    return dict(original_completion_bytes_equal=True, retrospective_bindings_only=True,
                source_execution_authenticated=False, qualification="HOLD_NO_GO")


def validate_test_completion(log, expected_tests, required_methods=()):
    counts = re.findall(r"^Ran ([0-9]+) tests? in [0-9.]+s$", log, re.M)
    outcomes = re.findall(r"^(?:OK(?: \(.*\))?|FAILED(?: \(.*\))?)$", log, re.M)
    if counts != [str(expected_tests)] or outcomes != ["OK"]:
        raise ValueError("test count, skip policy or final outcome differs")
    if required_methods:
        expected = [f"{name} (__main__.MergedQualificationLaneTests.{name}) ... ok"
                    for name in required_methods]
        lines = [line for line in log.splitlines() if line]
        if (len(required_methods) != expected_tests or
                len(set(required_methods)) != expected_tests or
                len(lines) != expected_tests + 3 or
                sorted(lines[:-3]) != sorted(expected) or
                lines[-3] != "-" * 70 or lines[-1] != "OK" or
                re.fullmatch(r"Ran " + str(expected_tests) + r" tests? in [0-9.]+s",
                             lines[-2]) is None):
            raise ValueError("exact ci-contract verbose roster or terminal records differ")


def run_one(output, label, command, source_commit, expected_tests=None, case=None, inputs=None):
    directory = output / label
    directory.mkdir()
    record = dict(label=label, argv=command, source_commit=source_commit,
                  inputs=inputs or {}, launched=False, returncode=None, passed=False)
    write_json(directory / "command.json", record)
    start = time.monotonic()
    try:
        with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
            process = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                                     env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), timeout=180)
        record["launched"] = True
        record["returncode"] = process.returncode
        if process.returncode:
            raise ValueError("command returned nonzero")
        if expected_tests is not None:
            log = (directory / "stderr.log").read_text()
            validate_test_completion(
                log, expected_tests,
                CI_CONTRACT_METHODS if label == "ci-contract-controls" else ())
            record["tests_passed"] = expected_tests
        if case is not None:
            record["readback_checks"] = check_replay((directory / "stdout.log").read_bytes(), case, directory)
        record["passed"] = True
    except subprocess.TimeoutExpired as error:
        record["launched"] = True
        record["error"] = type(error).__name__ + ": " + str(error)
    except (OSError, ValueError, KeyError, TypeError) as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    record["elapsed_seconds"] = time.monotonic() - start
    record["outputs"] = {name: digest(directory / name) for name in
                         ("stdout.log", "stderr.log", "report.json", "completion-review.json")
                         if (directory / name).is_file()}
    write_json(directory / "command.json", record)
    print(json.dumps(dict(label=label, passed=record["passed"], returncode=record["returncode"])), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT.resolve()):
        raise ValueError("output must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if commit != args.expected_head or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("collector source differs from expected head")
    source_files = selected_sources()
    summary = dict(schema="trnm-cell-learning-business-readback-run-v1",
                   scope="python-controls-and-retrospective-original-material-readbacks-only",
                   source_commit=commit, source_tree=subprocess.check_output(
                       ["git", "--no-replace-objects", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
                   source_files=source_files, python_executable=sys.executable, python_version=sys.version,
                   event=os.environ.get("GITHUB_EVENT_NAME"), run_id=os.environ.get("GITHUB_RUN_ID"),
                   run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"), commands=[],
                   authority="DENY_ALL", production_activation=False, qualification="HOLD_NO_GO")
    write_json(output / "summary.json", summary)
    for label, script, expected_tests, extra in TESTS:
        command = [sys.executable, script, *extra, "-v"]
        summary["commands"].append(run_one(output, label, command, commit, expected_tests=expected_tests,
                                          inputs={script: source_files[script]}))
        write_json(output / "summary.json", summary)
    for case in ("adopt-v1", "no-update-v9"):
        try:
            command, inputs = replay_command(case)
            record = run_one(output, "original-" + case, command, commit, case=case, inputs=inputs)
        except (OSError, ValueError) as error:
            record = dict(label="original-" + case, launched=False, returncode=None, passed=False,
                          error=type(error).__name__ + ": " + str(error))
        summary["commands"].append(record)
        write_json(output / "summary.json", summary)
    try:
        summary["selected_source_bytes_unchanged"] = selected_sources() == source_files
    except OSError as error:
        summary["selected_source_bytes_unchanged"] = False
        summary["source_after_error"] = type(error).__name__ + ": " + str(error)
    summary["passed"] = (all(item["passed"] for item in summary["commands"])
                         and summary["selected_source_bytes_unchanged"])
    summary["tests_passed"] = sum(item.get("tests_passed", 0) for item in summary["commands"])
    summary["readbacks_passed"] = sum(item["passed"] for item in summary["commands"] if item["label"].startswith("original-"))
    write_json(output / "summary.json", summary)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
