#!/usr/bin/env python3
"""Control tests for the extra runner, not native execution or qualification."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

RUNNER_PATH = Path(__file__).with_name("run-extra-native.py")
module_spec = importlib.util.spec_from_file_location("extra_native", RUNNER_PATH)
runner = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(runner)

NODE_TESTS = (
    "native_full_relation_context", "work_header_binding", "growth_persistence_cancellation",
    "work_fuzz_semantics", "daa_joint_consensus", "daa_adversarial_schedule",
    "native_owner_journal", "native_owner_observation", "native_risk_ledger", "native_node",
)


class Base:
    CARGO = "/fixture/toolchain/bin/cargo"
    PYTHON = "/usr/bin/python3"
    TOOLCHAIN = Path("/fixture/toolchain")
    PROVIDER = Path("/fixture/provider")

    @staticmethod
    def validate_output(kind, stdout, stderr, repo):
        if kind == "json":
            return json.loads(stdout)
        return {"kind": kind}


def fixture(*, omit=None, empty=None, failed=None, filtered=None, extra_summary=False):
    declarations = [("node", "trnm-pon-node", "test", name, [("case_" + name, "ok")])
                    for name in NODE_TESTS if name != omit]
    declarations += [
        ("node", "trnm-pon-node", "lib", "trnm_pon_node", [
            ("consensus::tests::chain_weight", "ok"),
            ("store::legacy_reorg_root_tests::undo", "ok"),
            ("store::reorg_readback_tests::reopen", "ok")]),
        ("crypto", "trnm-crypto-primitives", "lib", "trnm_crypto_primitives", [
            ("pon_work::tests::full_relation", "ok")]),
        ("node", "trnm-pon-node", "example", "native_fullpath_v1", []),
    ]
    build, test_output, executed = [], [], []
    for package_id, package, kind, target, tests in declarations:
        tests = [] if target == empty else tests[:]
        if target == failed:
            tests = [(name, "FAILED") for name, _ in tests] + [("owned_child_helper", "ignored, owned helper")]
        binary = "/fixture/target/debug/deps/" + target + "-0123456789abcdef"
        build.append(json.dumps({"reason": "compiler-artifact", "package_id": package_id,
            "target": {"name": target, "kind": [kind]}, "profile": {"test": True},
            "fresh": False, "executable": binary}))
        executed.append({"path": binary, "bytes": 100, "sha256": "a" * 64})
        passed = sum(outcome == "ok" for _, outcome in tests)
        failures = sum(outcome == "FAILED" for _, outcome in tests)
        ignored = sum(outcome.startswith("ignored") for _, outcome in tests)
        text = "\nrunning " + str(len(tests)) + " tests\n"
        text += "".join("test " + name + " ... " + outcome + "\n" for name, outcome in tests)
        text += ("\ntest result: " + ("FAILED" if failures else "ok") + ". " + str(passed) + " passed; "
                 + str(failures) + " failed; " + str(ignored) + " ignored; 0 measured; "
                 + ("1" if target == filtered else "0") + " filtered out; finished in 0.01s\n")
        test_output.append(text)
    if extra_summary:
        test_output.append("\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0s\n")
    metadata = {"workspace_members": ["node", "crypto"],
                "packages": [{"id": "node", "name": "trnm-pon-node"},
                             {"id": "crypto", "name": "trnm-crypto-primitives"}]}
    return "\n".join(build + test_output), executed, metadata


class WorkspaceReadbackTests(unittest.TestCase):
    def validate(self, observed):
        return runner.validate_readback(Base, {"kind": "rust-workspace"}, "", "", Path("/fixture/repo"), observed, None)

    def test_complete_roster_binds_native_targets_and_unit_groups(self):
        observed = runner.workspace_observations(*fixture())
        self.assertTrue(observed["execution_order_unambiguous"])
        self.assertTrue(observed["workspace_harness_inventory_covered"])
        self.assertTrue(observed["required_roster_complete"])
        self.assertEqual(len(observed["required_roster"]), 14)
        self.validate(observed)

    def test_example_with_zero_tests_is_not_marked_pass(self):
        observed = runner.workspace_observations(*fixture())
        empty = observed["harnesses"][-1]
        self.assertEqual(empty["status"], "NO_TESTS")
        self.assertEqual(empty["executed_tests"], 0)
        self.assertEqual(observed["zero_test_harnesses"], [12])

    def test_should_panic_annotation_preserves_actual_test_identity(self):
        stdout, executed, metadata = fixture()
        stdout = stdout.replace("test pon_work::tests::full_relation ... ok", "test pon_work::tests::full_relation - should panic ... ok")
        observed = runner.workspace_observations(stdout, executed, metadata)
        self.assertTrue(observed["required_roster_complete"])
        row = observed["required_roster"]["unit-group:kernel-pon-work"]["tests"][0]
        self.assertIs(row["expected_panic"], True)
        self.validate(observed)

    def test_namespace_prefix_alias_cannot_replace_required_unit_group(self):
        stdout, executed, metadata = fixture()
        stdout = stdout.replace("consensus::tests::chain_weight", "consensus::tests_alias::chain_weight")
        observed = runner.workspace_observations(stdout, executed, metadata)
        self.assertFalse(observed["required_roster_complete"])

    def test_missing_required_target_cannot_hide_behind_other_passes(self):
        observed = runner.workspace_observations(*fixture(omit="native_node"))
        self.assertFalse(observed["required_roster_complete"])
        with self.assertRaisesRegex(ValueError, "required native"):
            self.validate(observed)

    def test_zero_required_target_cannot_pass(self):
        observed = runner.workspace_observations(*fixture(empty="native_node"))
        self.assertGreater(observed["totals"]["passed"], 0)
        self.assertFalse(observed["required_roster_complete"])
        with self.assertRaisesRegex(ValueError, "required native"):
            self.validate(observed)

    def test_native_failures_and_ignored_helper_are_retained(self):
        observed = runner.workspace_observations(*fixture(failed="native_node"))
        self.assertEqual(observed["totals"]["failed"], 1)
        self.assertEqual(observed["totals"]["ignored"], 1)
        target = next(row for row in observed["harnesses"] if row["artifact"]["target"]["name"] == "native_node")
        self.assertEqual(target["status"], "FAIL")
        self.assertTrue(any(row["outcome"].startswith("ignored") for row in target["tests"]))
        with self.assertRaisesRegex(ValueError, "actual failures"):
            self.validate(observed)

    def test_filtered_tests_remain_visible_and_are_refused(self):
        observed = runner.workspace_observations(*fixture(filtered="native_node"))
        self.assertEqual(observed["totals"]["filtered_out"], 1)
        with self.assertRaisesRegex(ValueError, "filter tests"):
            self.validate(observed)

    def test_missing_dispatched_binary_cannot_supply_execution(self):
        stdout, executed, metadata = fixture()
        observed = runner.workspace_observations(stdout, executed[:-1], metadata)
        self.assertFalse(observed["execution_order_unambiguous"])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.validate(observed)

    def test_nested_or_extra_success_summary_is_ambiguous(self):
        observed = runner.workspace_observations(*fixture(extra_summary=True))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.validate(observed)

    def test_unattributed_trailing_failure_or_pass_cannot_hide_after_summary(self):
        for suffix in ("\nrunning 1 test\ntest late_failure ... FAILED\n",
                       "\nrunning 1 test\ntest late_pass ... ok\n",
                       "\ntest late_failure ... FAILED\n", "\nrunning 0 tests\n"):
            with self.subTest(suffix=suffix):
                stdout, executed, metadata = fixture()
                observed = runner.workspace_observations(stdout + suffix, executed, metadata)
                self.assertFalse(observed["stdout_control_flow_conserved"])
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    self.validate(observed)

    def test_member_inventory_records_actual_executed_counts(self):
        observed = runner.workspace_observations(*fixture())
        members = {row["package"]: row for row in observed["workspace_members"]}
        self.assertEqual(members["trnm-pon-node"]["executed_tests"], 13)
        self.assertEqual(members["trnm-pon-node"]["zero_test_harnesses"], 1)
        self.assertEqual(members["trnm-crypto-primitives"]["executed_tests"], 1)

    def test_changed_artifact_package_cannot_replace_node_execution(self):
        stdout, executed, metadata = fixture()
        stdout = stdout.replace('"package_id": "node"', '"package_id": "external-package"', 1)
        observed = runner.workspace_observations(stdout, executed, metadata)
        self.assertFalse(observed["required_roster_complete"])

    def test_missing_workspace_member_remains_uncovered(self):
        stdout, executed, metadata = fixture()
        metadata["workspace_members"].append("data-availability")
        observed = runner.workspace_observations(stdout, executed, metadata)
        self.assertFalse(observed["workspace_harness_inventory_covered"])
        with self.assertRaisesRegex(ValueError, "workspace member"):
            self.validate(observed)

    def test_extra_compiled_test_without_dispatch_is_not_coverage(self):
        stdout, executed, metadata = fixture()
        artifact = json.loads(stdout.splitlines()[0])
        artifact["executable"] = "/fixture/target/debug/deps/never-dispatched"
        stdout = json.dumps(artifact) + "\n" + stdout
        observed = runner.workspace_observations(stdout, executed, metadata)
        self.assertEqual(len(observed["compiled_but_not_dispatched"]), 1)
        self.assertFalse(observed["workspace_harness_inventory_covered"])


class PythonReadbackTests(unittest.TestCase):
    def test_failed_python_terminal_cannot_hide_before_or_after_ok(self):
        for endings in ("FAILED (failures=1)\nOK", "OK\nFAILED (failures=1)",
                        "OK\nOK", "FAILED (errors=1)"):
            with self.subTest(endings=endings):
                text = "Ran 2 tests in 0.01s\n\n" + endings + "\n"
                observed = runner.test_observations("unittest", "", text)
                with self.assertRaisesRegex(ValueError, "successful Python terminal"):
                    runner.validate_readback(Base, {"kind": "unittest"}, "", text, Path("/fixture/repo"), observed, None)

    def test_ok_terminal_cannot_carry_failure_counts_or_duplicate_counters(self):
        for suffix in ("failures=1", "errors=1", "unexpected successes=1", "skipped=1, skipped=0",
                       "failures=1, failures=0", "unknown=0"):
            with self.subTest(suffix=suffix):
                text = "Ran 2 tests in 0.01s\n\nOK (" + suffix + ")\n"
                observed = runner.test_observations("unittest", "", text)
                with self.assertRaisesRegex(ValueError, "successful Python terminal"):
                    runner.validate_readback(Base, {"kind": "unittest"}, "", text, Path("/fixture/repo"), observed, None)

    def test_multiple_summaries_cannot_hide_an_earlier_zero_suite(self):
        text = "Ran 0 tests in 0.001s\n\nOK\nRan 1 test in 0.001s\n\nOK\n"
        observed = runner.test_observations("unittest", "", text)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            runner.validate_readback(Base, {"kind": "unittest"}, "", text, Path("/fixture/repo"), observed, None)

    def test_zero_test_unittest_cannot_pass(self):
        text = "Ran 0 tests in 0.001s\n\nOK\n"
        observed = runner.test_observations("unittest", "", text)
        with self.assertRaisesRegex(ValueError, "zero executed"):
            runner.validate_readback(Base, {"kind": "unittest"}, "", text, Path("/fixture/repo"), observed, None)

    def test_all_skipped_cannot_pass(self):
        text = "test_profile ... skipped 'scope'\nRan 1 test in 0.001s\n\nOK (skipped=1)\n"
        observed = runner.test_observations("unittest", "", text)
        self.assertEqual(observed["outcome_counts"]["skipped"], 1)
        self.assertEqual(len(observed["raw_skipped_lines"]), 1)
        with self.assertRaisesRegex(ValueError, "zero executed"):
            runner.validate_readback(Base, {"kind": "unittest"}, "", text, Path("/fixture/repo"), observed, None)

    def test_python_failed_counts_survive_nonzero_output(self):
        observed = runner.test_observations("unittest", "", "Ran 4 tests in 1.0s\n\nFAILED (failures=1, errors=2)\n")
        self.assertEqual(observed["outcome_counts"], {"failures": 1, "errors": 2})
        self.assertEqual(observed["reported_test_counts"], [4])


class ReaderBindingTests(unittest.TestCase):
    def input(self):
        files = {"packets/" + format(index, "064x") + ".pnk": {"bytes": 10, "sha256": "b" * 64}
                 for index in range(84)}
        exported = {"directory": "/fixture/out/native-daa", "packet_count": 84,
                    "report": {"sha256": "c" * 64}, "files": files}
        result = {"schema": "pon-native-daa-bounds-reader-v1", "record_and_oracle_consistency": "PASS",
                  "full_python_transcript_and_product_recomputed": True,
                  "reader_performed_native_admission": False, "reader_reopened_native_database": False,
                  "host_and_source_provenance_checked_by_reader": False, "public_network_qualification": False,
                  "proof_hardness_or_timestamp_attack_profitability_qualified": False,
                  "unique_full_python_verified_proofs": 84, "report_sha256": "c" * 64,
                  "packet_identities": {name: dict(row) for name, row in files.items()}}
        return exported, result

    def check(self, exported, result):
        return runner.validate_readback(Base, {"kind": "reader", "export": "daa"}, json.dumps(result), "",
                                        Path("/fixture/repo"), {}, exported)

    def test_reader_must_bind_exact_fresh_packet_inventory(self):
        exported, result = self.input()
        self.check(exported, result)
        result["packet_identities"].pop(next(iter(result["packet_identities"])))
        with self.assertRaisesRegex(ValueError, "packet identity"):
            self.check(exported, result)

    def test_wrong_report_digest_or_schema_cannot_pass(self):
        for field, value in (("report_sha256", "d" * 64), ("schema", "historic-or-normalized-summary")):
            with self.subTest(field=field):
                exported, result = self.input();result[field] = value
                with self.assertRaises(ValueError):
                    self.check(exported, result)

    def test_numeric_false_alias_and_production_escalation_are_refused(self):
        for field, value in (("public_network_qualification", 0), ("production_activation", True),
                             ("production_activation", 0)):
            with self.subTest(field=field, value=value):
                exported, result = self.input();result[field] = value
                with self.assertRaises(ValueError):
                    self.check(exported, result)

    def test_zero_or_boolean_proof_count_cannot_pass(self):
        for value in (0, True):
            with self.subTest(value=value):
                exported, result = self.input();result["unique_full_python_verified_proofs"] = value
                with self.assertRaises(ValueError):
                    self.check(exported, result)


class PlanAndPathTests(unittest.TestCase):
    def test_workspace_runs_once_without_separate_target_reruns(self):
        commands = runner.command_list(Base, "a" * 40, Path("/fixture/out"))
        native_tests = [row for row in commands if row["kind"] == "rust-workspace"]
        self.assertEqual(len(native_tests), 1)
        self.assertFalse(any("--test" in row["argv"] or "--lib" in row["argv"] for row in commands))
        argv = native_tests[0]["argv"]
        for required in ("--workspace", "--all-targets", "--all-features", "--no-fail-fast", "--locked", "--offline"):
            self.assertIn(required, argv)
        self.assertEqual(argv[-3:], ["--", "--show-output", "--test-threads=1"])

    def test_fresh_export_variables_are_only_on_workspace_execution(self):
        commands = runner.command_list(Base, "a" * 40, Path("/fixture/out"))
        rows = [row for row in commands if row.get("env")]
        self.assertEqual([row["label"] for row in rows], ["workspace-all-targets"])
        self.assertEqual(set(rows[0]["env"]), {"TRNM_DAA_EVIDENCE_DIR", "TRNM_JOINT_DAA_EVIDENCE_DIR"})
        for row in commands:
            if row.get("export"):
                self.assertIn("--raw-dir", row["argv"])
                self.assertNotIn("evidence/pon-joint-consensus-daa-20261108", " ".join(row["argv"]))

    def test_non_test_plans_never_grant_production_or_performance(self):
        plan = runner.fullpath_plan(Base, Path("/fixture/repo"), "a" * 40, Path("/fixture/target"), Path("/fixture/out"))
        self.assertIs(plan["executed"], False)
        self.assertEqual(plan["adapter_normal_exit"], 1)
        self.assertIs(plan["scope"]["production_activation"], False)
        self.assertIs(plan["scope"]["throughput_improvement_demonstrated"], False)
        self.assertIn("disk IO cost attribution", plan["unknown_cost_fields"])

    def test_existing_output_and_source_nested_output_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve();repo = root / "repo";repo.mkdir()
            out = root / "out";out.mkdir()
            with self.assertRaisesRegex(ValueError, "fresh"):
                runner.validate_paths(repo, root / "target", out)
            with self.assertRaisesRegex(ValueError, "disjoint"):
                runner.validate_paths(repo, root / "target", repo / "out")

    def test_out_parent_of_source_is_also_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve();repo = root / "repo";repo.mkdir()
            with self.assertRaisesRegex(ValueError, "disjoint"):
                runner.validate_paths(repo, root.parent / "other-target", root)

    def test_symlink_ancestor_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve();repo = root / "repo";repo.mkdir()
            alias = root / "alias";alias.symlink_to(repo, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "canonical"):
                runner.validate_paths(alias, root / "target", root / "new")

    def test_base_runner_modification_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve();path = root / runner.BASE_RUNNER;path.parent.mkdir(parents=True)
            path.write_text("raise AssertionError('must never execute changed helper')\n")
            with self.assertRaisesRegex(ValueError, "bytes changed"):
                runner.load_base(root)

    def test_missing_fresh_daa_export_is_error_without_historical_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "fresh native export directory missing"):
                runner.export_manifest(Base, Path(tmp).resolve(), "daa")

    def test_list_commands_spawns_no_process_and_writes_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve();out = root / "out"
            argv = [str(RUNNER_PATH), "--repo", str(root / "repo"), "--target", str(root / "target"),
                    "--out", str(out), "--expected-head", "a" * 40, "--list-commands"]
            with patch.object(runner, "load_base", return_value=Base), patch.object(runner.sys, "argv", argv), \
                 patch.object(runner.subprocess, "Popen", side_effect=AssertionError("no process authorized")), \
                 contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(runner.main(), 0)
            self.assertIs(json.loads(captured.getvalue())["executed"], False)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
