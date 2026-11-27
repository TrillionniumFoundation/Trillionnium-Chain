"""Exact, disjoint inventories for the finite native component suite."""
from __future__ import annotations

import hashlib
import json
import os
import re
import unittest

GROUPS = ("general", "crypto-types", "state-root", "oracle", "ml-dsa", "research")
RESEARCH_MODULE_PREFIX = "hia.tests.test_research_"
ROOT_TEST_MODULE = "hia.tests.test_state_root_adversarial."
ORACLE_MODULES = ("hia.tests.test_oracle.", "hia.tests.test_oracle_preflight.")
ML_DSA_MODULES = ("hia.tests.test_ml_dsa.", "hia.tests.test_ml_dsa_qualification.")
CRYPTO_TYPES_MODULES = tuple("hia.tests." + name + "." for name in (
    "test_crypto", "test_ed25519", "test_ed25519_adversarial",
    "test_sha512", "test_sha512_stream", "test_request_status",
    "test_transfer", "test_transcript", "test_keccak", "test_ml_dsa_poly",
))
SCHEMA = "trnm.hia.component-test-partition.v5"
LEGACY_PLAN = "legacy-six-v1"
SPLIT_PLAN = "split-bench-v1"
GENERAL_PLAN = "split-general-v1"
SETTLEMENT_PLAN = "split-general-settlement-v1"
STATE_IMPORT_PLAN = "split-general-state-import-v1"
PLANS = (LEGACY_PLAN, SPLIT_PLAN, GENERAL_PLAN, SETTLEMENT_PLAN, STATE_IMPORT_PLAN)
SPLIT_GROUPS = (*GROUPS, "bench")
SPLIT_SCHEMA = "trnm.hia.component-test-partition.v6"
GENERAL_SHARDS = ("general-a", "general-b", "general-c")
GENERAL_GROUPS = (*GENERAL_SHARDS, *SPLIT_GROUPS[1:])
GENERAL_SCHEMA = "trnm.hia.component-test-partition.v7"
SETTLEMENT_SHARDS = (*GENERAL_SHARDS, "general-settlement")
SETTLEMENT_GROUPS = (*SETTLEMENT_SHARDS, *SPLIT_GROUPS[1:])
SETTLEMENT_SCHEMA = "trnm.hia.component-test-partition.v8"
STATE_IMPORT_SHARDS = (*SETTLEMENT_SHARDS, "general-state-import")
STATE_IMPORT_GROUPS = (*STATE_IMPORT_SHARDS, *SPLIT_GROUPS[1:])
STATE_IMPORT_SCHEMA = "trnm.hia.component-test-partition.v9"
PLAN_TRACKED_PREFIX = "# HIA component coverage plan:"
PLAN_TRACKED_LINE = f"{PLAN_TRACKED_PREFIX} {SPLIT_PLAN}"
GENERAL_TRACKED_LINE = f"{PLAN_TRACKED_PREFIX} {GENERAL_PLAN}"
SETTLEMENT_TRACKED_LINE = f"{PLAN_TRACKED_PREFIX} {SETTLEMENT_PLAN}"
STATE_IMPORT_TRACKED_LINE = f"{PLAN_TRACKED_PREFIX} {STATE_IMPORT_PLAN}"

# Keep complete unittest modules together, including their shared fixtures.
GENERAL_A_LAST = "test_control_guard"
GENERAL_B_LAST = "test_release_file_descriptor"
# Relieve the measured expensive early Settlement block without moving the
# tail's SHA-word and Task evidence owners or the rest of the general suite.
SETTLEMENT_PREFIX = "test_settlement_"
SETTLEMENT_LAST = "test_settlement_held_variable_stream_replay"
# The entire actual General C family, not the separate maximal State-root job.
STATE_IMPORT_PREFIX = "test_state_import_"
SHA_WORD_GROUPS = frozenset(("general", "general-c"))


def groups_for(plan):
    need(plan in PLANS, "Unknown component coverage plan")
    return {LEGACY_PLAN: GROUPS, SPLIT_PLAN: SPLIT_GROUPS,
            GENERAL_PLAN: GENERAL_GROUPS, SETTLEMENT_PLAN: SETTLEMENT_GROUPS,
            STATE_IMPORT_PLAN: STATE_IMPORT_GROUPS}[plan]


def source_plan(root):
    """Select from the tracked source contract, never from downloaded artifacts."""
    path = root / ".github/workflows/hia-native-migration.yml"
    need(path.is_file() and not path.is_symlink(), "Missing exact component workflow")
    lines = [line.strip() for line in path.read_text().splitlines()
             if line.strip().startswith(PLAN_TRACKED_PREFIX)]
    need(lines in ([], [PLAN_TRACKED_LINE], [GENERAL_TRACKED_LINE], [SETTLEMENT_TRACKED_LINE],
                   [STATE_IMPORT_TRACKED_LINE]),
         "Invalid component coverage plan in source")
    return {(): LEGACY_PLAN, (PLAN_TRACKED_LINE,): SPLIT_PLAN,
            (GENERAL_TRACKED_LINE,): GENERAL_PLAN,
            (SETTLEMENT_TRACKED_LINE,): SETTLEMENT_PLAN,
            (STATE_IMPORT_TRACKED_LINE,): STATE_IMPORT_PLAN}[tuple(lines)]


def source_bound_plan(root, requested):
    observed = source_plan(root)
    need(requested is None or requested == observed, "Requested component plan differs from tracked source")
    return observed


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def object_hash(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def same(left, right):
    return canonical(left) == canonical(right)


def group_for(identifier, plan=LEGACY_PLAN):
    groups_for(plan)
    need(type(identifier) is str and identifier.startswith("hia.tests.")
         and all(part.isidentifier() for part in identifier.split(".")),
         "Noncanonical component test identity")
    if identifier.startswith(ROOT_TEST_MODULE):
        return "state-root"
    if identifier.startswith(CRYPTO_TYPES_MODULES):
        return "crypto-types"
    if identifier.startswith(ORACLE_MODULES):
        return "oracle"
    if identifier.startswith(ML_DSA_MODULES):
        return "ml-dsa"
    # Own the complete test_research_* family, including new command/owner
    # modules. Discovery and actual start/finish records remain mandatory.
    if identifier.startswith(RESEARCH_MODULE_PREFIX):
        return "research"
    module = identifier.split(".")[2]
    if plan != LEGACY_PLAN and module.startswith("test_bench_"):
        return "bench"
    if plan in (GENERAL_PLAN, SETTLEMENT_PLAN, STATE_IMPORT_PLAN):
        if module <= GENERAL_A_LAST:
            return "general-a"
        if module <= GENERAL_B_LAST:
            return "general-b"
        if (plan in (SETTLEMENT_PLAN, STATE_IMPORT_PLAN)
                and module.startswith(SETTLEMENT_PREFIX) and module <= SETTLEMENT_LAST):
            return "general-settlement"
        if plan == STATE_IMPORT_PLAN and module.startswith(STATE_IMPORT_PREFIX):
            return "general-state-import"
        return "general-c"
    return "general"


def descriptor(identifiers, group, plan=LEGACY_PLAN):
    groups = groups_for(plan)
    need(group in (*groups, "all"), "Unknown component shard")
    need(type(identifiers) is list and identifiers, "Empty component discovery")
    for identifier in identifiers:
        group_for(identifier, plan)
    need(len(identifiers) == len(set(identifiers)), "Duplicate discovered component test")
    ordered = sorted(identifiers)
    need({group_for(identifier, plan) for identifier in ordered} == set(groups),
         "All complete component partitions are required")
    selected = [identifier for identifier in ordered
                if group == "all" or group_for(identifier, plan) == group]
    return {"schema": {LEGACY_PLAN: SCHEMA, SPLIT_PLAN: SPLIT_SCHEMA,
                       GENERAL_PLAN: GENERAL_SCHEMA, SETTLEMENT_PLAN: SETTLEMENT_SCHEMA,
                       STATE_IMPORT_PLAN: STATE_IMPORT_SCHEMA}[plan],
            "group": group, "groups": list(groups),
            "discovered_tests": ordered, "discovered_sha256": object_hash(ordered),
            "selected_tests": selected, "selected_sha256": object_hash(selected)}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            need(isinstance(item, unittest.TestCase), "Unexpected discovered test object")
            need(type(item).__module__ != "unittest.loader",
                 "Failed test import cannot be removed by partitioning")
            yield item


def select_suite(suite, group="all", plan=LEGACY_PLAN):
    cases = list(flatten(suite))
    partition = descriptor([case.id() for case in cases], group, plan)
    selected = set(partition["selected_tests"])
    return unittest.TestSuite(case for case in cases if case.id() in selected), partition


class ObservedResult(unittest.TextTestResult):
    """Record actual start/finish callbacks, including unsuccessful tests."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_tests = []
        self.finished_tests = []

    def startTest(self, test):
        self.started_tests.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished_tests.append(test.id())
        super().stopTest(test)


def record_completion(partition, result):
    selected = partition["selected_tests"]
    started = list(result.started_tests)
    finished = list(result.finished_tests)
    complete = (type(result.testsRun) is int and result.testsRun == len(selected)
                and len(started) == len(finished) == len(selected)
                and sorted(started) == sorted(finished) == selected)
    return {**partition, "started_tests": started, "finished_tests": finished,
            "all_selected_completed": complete}


def validate_completion(value, identifiers, group, tests_run, plan=LEGACY_PLAN):
    need(type(value) is dict, "Missing actual component partition")
    expected = descriptor(identifiers, group, plan)
    need(set(value) == set(expected) | {
        "started_tests", "finished_tests", "all_selected_completed"},
        "Unexpected component partition fields")
    need(same({key: value[key] for key in expected}, expected),
         "Discovered or selected component roster differs")
    selected = expected["selected_tests"]
    for key in ("started_tests", "finished_tests"):
        observed = value[key]
        need(type(observed) is list and all(type(item) is str for item in observed)
             and len(observed) == len(selected) and sorted(observed) == selected,
             "Missing, repeated or unassigned actual component execution")
    need(value["all_selected_completed"] is True and type(tests_run) is int
         and tests_run == len(selected), "Incomplete actual component execution")
    return selected


def validate_lineage(value):
    need(type(value) is dict and set(value) == {"git_head", "run_id", "attempt"},
         "Incomplete component CI lineage")
    need(type(value["git_head"]) is str
         and re.fullmatch(r"[0-9a-f]{40}", value["git_head"]) is not None,
         "Invalid component commit")
    need(type(value["run_id"]) is str
         and re.fullmatch(r"[1-9][0-9]*", value["run_id"]) is not None,
         "Invalid component run")
    need(type(value["attempt"]) is int and value["attempt"] > 0,
         "Invalid component run attempt")
    return value


def lineage(environ=None, *, required=False):
    env = os.environ if environ is None else environ
    keys = ("TRNM_EXPECTED_SOURCE_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    if not any(env.get(key) for key in keys) and not required:
        return None
    need(all(type(env.get(key)) is str and env[key] for key in keys),
         "Partial component CI lineage")
    need(re.fullmatch(r"[1-9][0-9]*", env[keys[2]]) is not None,
         "Invalid actual component attempt")
    return validate_lineage({"git_head": env[keys[0]], "run_id": env[keys[1]],
                             "attempt": int(env[keys[2]])})
