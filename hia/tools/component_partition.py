"""Exact, disjoint inventories for the finite native component suite."""
from __future__ import annotations

import hashlib
import json
import os
import re
import unittest

GROUPS = ("general", "state-root")
ROOT_TEST_MODULE = "hia.tests.test_state_root_adversarial."
SCHEMA = "trnm.hia.component-test-partition.v1"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def object_hash(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def same(left, right):
    return canonical(left) == canonical(right)


def group_for(identifier):
    need(type(identifier) is str and identifier.startswith("hia.tests.")
         and all(part.isidentifier() for part in identifier.split(".")),
         "Noncanonical component test identity")
    return "state-root" if identifier.startswith(ROOT_TEST_MODULE) else "general"


def descriptor(identifiers, group):
    need(group in (*GROUPS, "all"), "Unknown component shard")
    need(type(identifiers) is list and identifiers, "Empty component discovery")
    for identifier in identifiers:
        group_for(identifier)
    need(len(identifiers) == len(set(identifiers)), "Duplicate discovered component test")
    ordered = sorted(identifiers)
    need({group_for(identifier) for identifier in ordered} == set(GROUPS),
         "Both complete component partitions are required")
    selected = [identifier for identifier in ordered
                if group == "all" or group_for(identifier) == group]
    return {"schema": SCHEMA, "group": group, "groups": list(GROUPS),
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


def select_suite(suite, group="all"):
    cases = list(flatten(suite))
    partition = descriptor([case.id() for case in cases], group)
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


def validate_completion(value, identifiers, group, tests_run):
    need(type(value) is dict, "Missing actual component partition")
    expected = descriptor(identifiers, group)
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
