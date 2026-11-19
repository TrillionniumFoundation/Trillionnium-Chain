"""Controls for shard coverage and same-run component result admission."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from hia.tools import component_partition as part
from hia.tools import qualify_components_ci as ci

IDS = ["hia.tests.test_example.Example.test_one",
       "hia.tests.test_example.Example.test_two",
       "hia.tests.test_state_root_adversarial.Example.test_maximum"]
LINEAGE = {"git_head": "a" * 40, "run_id": "42", "attempt": 1}
SOURCES = {"hia/src/fixture.hepta": "d" * 64}
COMPILER = {"binding_sha256": "b" * 64, "compiler_sha256": "c" * 64}


def fixture_case(identifier):
    class Fixture(unittest.TestCase):
        def id(self):
            return identifier

        def runTest(self):
            self.assertEqual(2 + 2, 4)
    return Fixture()


def complete_report(group):
    selection = part.descriptor(IDS, group)
    selected = selection["selected_tests"]
    return {"schema": "trnm.hia.native-qualification.v1", "status": "PASS",
            "lineage": copy.deepcopy(LINEAGE), "source_commit_observed": LINEAGE["git_head"],
            "working_tree_dirty": False, "source_unchanged_during_tests": True,
            "independent_rust_oracles_required": True,
            "source_inputs": SOURCES, "source_set_sha256": part.object_hash(SOURCES),
            "tests": {"run": len(selected), "failures": [], "errors": [], "skipped": []},
            "test_partition": {**selection, "started_tests": selected,
                               "finished_tests": selected, "all_selected_completed": True},
            "selfhost_compiler_matches_cold_qualified_image": True,
            "retained_compiler_binding_sha256": COMPILER["binding_sha256"],
            "builds": [{"chain_migration": {"backend": "selfhost"},
                        "compiler_sha256": COMPILER["compiler_sha256"]}],
            "rust_oracles": {key: {"executable_sha256": "e" * 64}
                             for key in ci.qualify.RUST_ORACLES},
            "whole_chain_native": False, "old_stack_can_be_removed": False,
            "production_activation": False}


def log_for(value):
    count = value["tests"]["run"]
    summary = {"status": "PASS", "tests": count, "skipped": 0,
               "source_set_sha256": value["source_set_sha256"],
               "shared_runner_calls": 7, "wall_seconds": 0.01,
               "shard": value["test_partition"]["group"]}
    return ("Ran " + str(count) + " tests in 0.01s\n\nOK\n"
            + json.dumps(summary, sort_keys=True) + "\n").encode()


class ComponentPartitions(unittest.TestCase):
    def test_both_partitions_execute_every_fixture_exactly_once(self):
        observed = []
        for group in part.GROUPS:
            suite = unittest.TestSuite([unittest.TestSuite(
                fixture_case(identifier) for identifier in IDS)])
            selected, inventory = part.select_suite(suite, group)
            result = unittest.TextTestRunner(stream=io.StringIO(),
                                             resultclass=part.ObservedResult).run(selected)
            value = part.record_completion(inventory, result)
            observed.extend(part.validate_completion(value, IDS, group, result.testsRun))
        self.assertEqual(sorted(observed), sorted(IDS))
        self.assertEqual(len(observed), len(set(observed)))
        self.assertEqual(part.descriptor(IDS, "all")["selected_tests"], sorted(IDS))

    def test_invalid_discovery_never_silently_drops_a_test(self):
        variants = [[], IDS + [IDS[0]], IDS[:-1],
                    ["unittest.loader._FailedTest.test_missing"], IDS + ["bad identity"]]
        for identifiers in variants:
            with self.subTest(identifiers=identifiers), self.assertRaises(ValueError):
                part.descriptor(identifiers, "general")
        with self.assertRaises(ValueError):
            part.select_suite(unittest.defaultTestLoader.loadTestsFromName(
                "hia.tests.module_that_does_not_exist"), "general")
        with self.assertRaises(ValueError):
            part.descriptor(IDS, "unregistered-shard")

    def test_actual_start_finish_rosters_cannot_be_inferred_from_count(self):
        baseline = complete_report("general")["test_partition"]
        variants = []
        for key in ("started_tests", "finished_tests"):
            for names in ([], [IDS[0], IDS[0]], [IDS[0], IDS[2]], [False, IDS[1]]):
                wrong = copy.deepcopy(baseline)
                wrong[key] = names
                variants.append(wrong)
        for key, value in (("all_selected_completed", 1), ("selected_sha256", "0" * 64),
                           ("discovered_tests", IDS[:2]), ("group", "all")):
            wrong = copy.deepcopy(baseline)
            wrong[key] = value
            variants.append(wrong)
        for wrong in variants:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                part.validate_completion(wrong, IDS, "general", 2)
        for count in (True, 2.0, 1, 3):
            with self.subTest(count=count), self.assertRaises(ValueError):
                part.validate_completion(baseline, IDS, "general", count)

    def test_actual_lineage_has_no_partial_or_numeric_coercion(self):
        self.assertIsNone(part.lineage({}))
        self.assertEqual(part.lineage({"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                                      "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"}),
                         LINEAGE)
        for env in ({}, {"GITHUB_RUN_ID": "42"},
                    {"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                     "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1.0"},
                    {"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                     "GITHUB_RUN_ID": "0", "GITHUB_RUN_ATTEMPT": "1"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                part.lineage(env, required=True)
        for field, value in (("attempt", True), ("attempt", 1.0), ("run_id", 42),
                              ("git_head", "A" * 40)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                part.validate_lineage({**LINEAGE, field: value})


class ComponentReadback(unittest.TestCase):
    def validate(self, value):
        return ci.validate_report(value, "general", LINEAGE, SOURCES, IDS, COMPILER)

    def test_report_rejects_source_run_status_skips_and_scope_mutants(self):
        good = complete_report("general")
        self.assertEqual(self.validate(good), IDS[:2])
        variants = []
        for field, value in (("status", "PASS_WITH_SKIPS"), ("working_tree_dirty", 0),
                              ("source_unchanged_during_tests", 1),
                              ("independent_rust_oracles_required", False),
                              ("whole_chain_native", True), ("old_stack_can_be_removed", True),
                              ("production_activation", True), ("builds", []),
                              ("rust_oracles", {}), ("source_inputs", {}),
                              ("retained_compiler_binding_sha256", "0" * 64)):
            variants.append({**copy.deepcopy(good), field: value})
        for field, value in (("attempt", 2), ("run_id", "43"), ("git_head", "f" * 40)):
            wrong = copy.deepcopy(good)
            wrong["lineage"][field] = value
            variants.append(wrong)
        for field, value in (("run", 2.0), ("run", True), ("failures", ["actual failure"]),
                              ("errors", ["actual error"]), ("skipped", ["actual skip"])):
            wrong = copy.deepcopy(good)
            wrong["tests"][field] = value
            variants.append(wrong)
        wrong = copy.deepcopy(good)
        wrong["builds"][0]["compiler_sha256"] = "0" * 64
        variants.append(wrong)
        for wrong in variants:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                self.validate(wrong)

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in ('{"a":1,"a":2}', '{"nested":{"x":1,"x":1}}',
                    '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ci.decode(raw)

    def test_complete_raw_summary_cannot_be_missing_changed_or_skipped(self):
        value = complete_report("general")
        raw = log_for(value)
        ci.verify_log(raw, value)
        variants = [b"", raw.replace(b"Ran 2 tests", b"Ran 1 tests"),
                    raw.replace(b"\nOK\n", b"\nOK (skipped=1)\n"),
                    raw.replace(b"\nOK\n", b"\nFAILED (errors=1)\n"),
                    raw.replace(b'"tests": 2', b'"tests": 2.0'),
                    raw.replace(b'"skipped": 0', b'"skipped": false'),
                    raw.replace(b'"shard": "general"', b'"shard": "state-root"'),
                    raw + raw.splitlines()[-1] + b"\n"]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ci.verify_log(changed, value)

    def make_bundle(self, root, group):
        directory = root / group
        value = complete_report(group)
        source = {"kind": "head", "candidate": "a" * 40, "tested_commit": "a" * 40,
                  "tested_tree": "f" * 40, "tracked_worktree_verified": True,
                  "tests_executed_by_identity_check": False,
                  "tracked_entries": 3, "tracked_bytes": 99}
        files = {
            "hia-observations/source.json": json.dumps(source).encode(),
            "hia-observations/source-after.json": json.dumps(source).encode(),
            "hia-observations/qualification.json": json.dumps(value).encode(),
            "hia-observations/qualification.log": log_for(value),
            "hia-bootstrap/bootstrap.json": json.dumps({
                "status": "PASS", "compiler_sha256": COMPILER["compiler_sha256"],
                "compiler": "/tmp/fixture-compiler"}).encode(),
            "original-rust-build.jsonl": b'{"fixture":true}\n',
        }
        for name, raw in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return directory

    def test_two_complete_artifacts_cover_full_roster_and_keep_scope_finite(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundles = {group: self.make_bundle(Path(tmp), group) for group in part.GROUPS}
            result = ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            self.assertIs(result["complete_disjoint_coverage"], True)
            self.assertEqual(result["tests"], 3)
            self.assertIs(result["actual_runtime_reexecuted"], False)
            self.assertIs(result["old_stack_can_be_removed"], False)
            with self.assertRaises(ValueError):
                ci.verify_all({"general": bundles["general"]}, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            with self.assertRaises(ValueError):
                ci.verify_all({"general": bundles["general"], "state-root": bundles["general"]},
                              LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)

    def test_two_coherent_wrong_producer_trees_cannot_replace_consumer_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundles = {group: self.make_bundle(Path(tmp), group) for group in part.GROUPS}
            ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            for directory in bundles.values():
                for name in ("source.json", "source-after.json"):
                    path = directory / "hia-observations" / name
                    value = json.loads(path.read_text())
                    value["tested_tree"] = "0" * 40
                    path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "actual consumer Git tree"):
                ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)

    def test_artifact_bytes_roster_and_source_fences_are_independently_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_bundle(Path(tmp), "general")
            def verify():
                return ci.read_bundle(directory, "general", LINEAGE, SOURCES, IDS, COMPILER)
            verify()
            extra = directory / "unbound"
            extra.write_bytes(b"x")
            with self.assertRaises(ValueError):
                verify()
            extra.unlink()
            path = directory / "hia-observations/source-after.json"
            original = path.read_bytes()
            value = json.loads(original)
            value["tested_tree"] = "0" * 40
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                verify()
            path.write_bytes(original)
            path.unlink()
            path.symlink_to(directory / "hia-observations/source.json")
            with self.assertRaises(ValueError):
                verify()


if __name__ == "__main__":
    unittest.main()
