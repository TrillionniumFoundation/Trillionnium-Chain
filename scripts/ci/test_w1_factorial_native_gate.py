#!/usr/bin/env python3
"""Check W1's actual completion gate against source names and false successes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from w1_native_controls import GROUPS, NativeControlError, SUITES, validate_log
from check_w1_native_roster import ROSTERS

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pon-w1-work-security.yml"
GATE = ROOT / "scripts/ci/w1_native_controls.py"
CRYPTO = "trillionnium/crates/trnm-crypto-primitives/"
NODE = "trillionnium/crates/trnm-pon-node/"
COUNTS = {
    "legal-native-controls": (13, 0),
    "factorial-kernel-tests": (14, 0), "factorial-example-tests": (11, 0),
    "header-binding-tests": (1, 0), "history-w1-tests": (5, 0),
    "history-import-tests": (40, 1), "cpu-completion-tests": (11, 0),
}
HISTORY = [
    "deadline_controls::final_resource_completion_preserves_error_priority_and_original_deadline",
    "deadline_controls::final_resource_expiry_keeps_committed_history_and_settled_cpu",
    "history_codec_snapshot_preserves_legacy_bytes_identity_and_deferred_profile_errors",
    "deadline_controls::history_control_keeps_original_timely_single_resource_observation",
    "deadline_controls::history_control_preexpired_does_not_invoke_resource",
    "deadline_controls::history_control_resource_expiry_refuses_late_success",
    "deadline_controls::history_control_resource_expiry_keeps_original_resource_error",
    "deadline_controls::history_owner_resource_expiry_never_invokes_exclusive_or_shared_action",
    "detached_budget_controls::shared_detached_history_continues_from_real_deficit_without_new_credit",
    "detached_budget_controls::shared_detached_history_refill_keeps_original_resource_cancellation",
    "detached_budget_controls::shared_detached_history_refill_cannot_renew_original_deadline",
]


def fixture(suite):
    passed, ignored = COUNTS[suite]
    rows = [f"running {passed + ignored} tests"]
    rows.extend(f"test {name} ... ok" for name in SUITES[suite]["passed"])
    rows.extend(f"test {name} ... ignored, {reason}"
                for name, reason in SUITES[suite]["ignored"].items())
    rows.append(f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; "
                "0 measured; 0 filtered out; finished in 0.01s")
    return "\n".join(rows) + "\n"


def source_names(path, prefix):
    names = re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn (\w+)",
                       (ROOT / path).read_text())
    return {prefix + name for name in names}


def example_names(version):
    return sorted(source_names(NODE + f"examples/pon_w1_legal_strategy_{version}.rs", "tests::")
                  | source_names(NODE + "examples/support/w1_cost_producers.rs",
                                 "w1_cost_producers::observed_search_tests::")
                  | source_names(CRYPTO + "examples/support/w1_material.rs", "w1_material::tests::"))


def summary(passed, ignored=0):
    return (f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; "
            "0 measured; 0 filtered out; finished in 0.01s\n")


class NativeGateTests(unittest.TestCase):
    def setUp(self):
        self.logs = {name: fixture(name) for name in COUNTS}
        self.names = SUITES["factorial-kernel-tests"]["passed"]
        self.example_names = example_names("v3")
        self.assertEqual(len(self.example_names), 11)

    def run_gate(self, group="factorial"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in self.logs.items():
                (root / (name + ".log")).write_text(content)
            result = subprocess.run(
                [sys.executable, "-B", str(GATE), "--group", group, "--logs", directory,
                 "--output", str(root / "completion.json")], capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                report = json.loads((root / "completion.json").read_text())
                self.assertEqual([x["suite"] for x in report["suites"]], list(GROUPS[group]))
                for row in report["suites"]:
                    raw = self.logs[row["suite"]].encode()
                    self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(row["bytes"], len(raw))
            else:
                self.assertFalse((root / "completion.json").exists())
            return result.returncode

    def rejects(self, suite, raw):
        with self.assertRaises(NativeControlError):
            validate_log(suite, raw)

    def test_fixture_counts_match_frozen_complete_named_rosters(self):
        for suite, profile in [('factorial-example-tests', 'factorial-example'),
                               ('history-import-tests', 'history-import')]:
            roster = ROSTERS[profile]
            ignored = len(roster['ignored'])
            self.assertEqual(COUNTS[suite], (len(roster['names']) - ignored, ignored))
        # Current source declares 41 cases, including the original child fixture.
        history = ROSTERS['history-import']
        self.assertEqual(len(history['names']), 41)
        self.assertEqual(history['ignored'], [
            'ingress::history_import::tests::history_kill_cut_child'])
        for name in (
                'ingress::history_import::tests::detached_budget_controls::shared_detached_history_before_native_completion_keeps_sticky_budget_refusal',
                'ingress::history_import::tests::detached_budget_controls::shared_detached_history_continues_from_real_deficit_without_new_credit',
                'ingress::history_import::tests::detached_budget_controls::shared_detached_history_refill_cannot_renew_original_deadline',
                'ingress::history_import::tests::detached_budget_controls::shared_detached_history_refill_keeps_original_resource_cancellation',
                'ingress::history_import::tests::shared_history_native_completion_handoff_settles_before_next_packet',
                'ingress::history_import::tests::history_shared_owner_busy_retry_keeps_fresh_host_refusal',
                'ingress::history_import::tests::history_shared_owner_checks_host_once_before_each_uncontended_action',
        ):
            self.assertEqual(history['names'].count(name), 1)


    def test_previous_incomplete_positive_fixture_is_refused(self):
        for suite, old_passes, ignored in [('factorial-example-tests', 6, 0),
                                          ('history-import-tests', 28, 1)]:
            original = self.logs[suite]
            self.logs[suite] = original.replace(
                f'test result: ok. {COUNTS[suite][0]} passed;',
                f'test result: ok. {old_passes} passed;', 1)
            self.assertNotEqual(self.run_gate(), 0)
            self.logs[suite] = original


    def test_complete_roster_passes(self):
        self.assertEqual(self.run_gate(), 0)
        self.assertEqual(self.run_gate("legal"), 0)

    def test_frozen_names_equal_current_native_source_and_retained_counts(self):
        shared = source_names(NODE + "examples/support/w1_cost_producers.rs",
                              "w1_cost_producers::observed_search_tests::")
        shared |= source_names(CRYPTO + "examples/support/w1_material.rs", "w1_material::tests::")
        history = source_names(NODE + "src/ingress/history_import_tests.rs",
                               "ingress::history_import::tests::")
        deadline = source_names(NODE + "src/ingress/history_import_deadline_tests.rs",
                                "ingress::history_import::tests::deadline_controls::")
        detached = source_names(NODE + "src/ingress/history_import_detached_budget_tests.rs",
                                "ingress::history_import::tests::detached_budget_controls::")
        expected = {
            "legal-native-controls": shared | source_names(
                NODE + "examples/pon_w1_legal_strategy_v1.rs", "tests::"),
            "factorial-example-tests": shared | source_names(
                NODE + "examples/pon_w1_legal_strategy_v3.rs", "tests::"),
            "factorial-kernel-tests": source_names(CRYPTO + "src/pon_work/legal_attempt.rs",
                                                    "pon_work::legal_attempt::tests::")
            | source_names(CRYPTO + "src/pon_work/legal_attempt/low_rank.rs",
                           "pon_work::legal_attempt::low_rank::tests::"),
            "header-binding-tests": source_names(NODE + "tests/work_header_binding.rs", ""),
            "history-w1-tests": {name for name in history if name.split("::")[-1].startswith("history_w1_")},
            "history-import-tests": history | deadline | detached,
            "cpu-completion-tests": source_names(
                NODE + "src/ingress/public_v3/scalar_cpu_completion_tests.rs",
                "ingress::public_v3::scalar_cpu::completion_tests::"),
        }
        self.assertEqual(set(SUITES), set(COUNTS))
        for suite, names in expected.items():
            with self.subTest(suite=suite):
                roster = SUITES[suite]
                self.assertEqual((len(roster["passed"]), len(roster["ignored"])), COUNTS[suite])
                self.assertEqual(set(roster["passed"]) | set(roster["ignored"]), names)

    def test_every_suite_rejects_wrong_count_failure_ignored_and_duplicate_summary(self):
        for name, original in self.logs.items():
            summary = original.splitlines()[-1]
            mutations = [
                original.replace(summary, summary.replace(" passed;", "0 passed;", 1)),
                original.replace("0 failed;", "1 failed;", 1),
                original.replace(" ignored;", "0 ignored;", 1),
                original + summary + "\n", "",
                original + summary.replace("ok.", "FAILED.", 1) + "\n",
                original.replace(summary, ""),
                original.replace("running ", "running 0", 1),
                original + original.splitlines()[0] + "\n",
            ]
            for mutant in mutations:
                with self.subTest(suite=name, mutant=mutant[:80]):
                    self.rejects(name, mutant)

    def test_kernel_rejects_missing_duplicate_or_replaced_named_control(self):
        original = self.logs["factorial-kernel-tests"]
        for name in self.names:
            line = f"test {name} ... ok\n"
            for mutant in (original.replace(line, ""), original + line,
                           original.replace(name, "pon_work::legal_attempt::tests::unexpected")):
                with self.subTest(control=name):
                    self.rejects("factorial-kernel-tests", mutant)

    def test_history_named_controls_remain_required_once(self):
        original = self.logs["history-import-tests"]
        for name in HISTORY:
            line = f"test ingress::history_import::tests::{name} ... ok\n"
            for mutant in (original.replace(line, ""), original + line):
                self.rejects("history-import-tests", mutant)

    def test_every_named_control_requires_one_successful_terminal(self):
        for suite, original in self.logs.items():
            for name in SUITES[suite]["passed"]:
                line = f"test {name} ... ok\n"
                mutations = [original.replace(line, ""), original + line,
                             original.replace(name, "unexpected::substitute"),
                             original.replace(line, f"test {name} ... FAILED\n"),
                             original.replace(line, f"test {name} ... ignored\n")]
                for mutant in mutations:
                    with self.subTest(suite=suite, name=name):
                        self.rejects(suite, mutant)

    def test_nocapture_retains_name_until_its_serial_success_terminal(self):
        for suite, original in self.logs.items():
            name = SUITES[suite]["passed"][0]
            line = f"test {name} ... ok\n"
            split = f"test {name} ... {{\"original_observation\":true}}\nmore observation\nok\n"
            valid = original.replace(line, split)
            self.assertIn(name, validate_log(suite, valid)["passed"])
            for mutant in (valid.replace("\nok\n", "\n", 1),
                           valid.replace("\nok\n", "\nFAILED\n", 1),
                           valid.replace("\nok\n", "\nok\nok\n", 1),
                           "ok\n" + valid):
                self.rejects(suite, mutant)

    def test_ignored_child_is_exact_and_parent_still_must_pass(self):
        suite = "history-import-tests"
        original = self.logs[suite]
        child, reason = next(iter(SUITES[suite]["ignored"].items()))
        line = f"test {child} ... ignored, {reason}\n"
        for mutant in (original.replace(line, ""), original + line,
                       original.replace(line, f"test {child} ... ok\n"),
                       original.replace(reason, "different skip reason"),
                       original.replace("real_sigkill_history_cuts_preserve_debt_fence_and_committed_blocks ... ok",
                                        "real_sigkill_history_cuts_preserve_debt_fence_and_committed_blocks ... ignored")):
            self.rejects(suite, mutant)

    def test_original_old_counts_cannot_certify_the_current_roster(self):
        for suite, old, current in (("legal-native-controls", 8, 13),
                                    ("factorial-example-tests", 6, 11),
                                    ("history-import-tests", 28, 40),
                                    ("history-import-tests", 33, 40),
                                    ("history-import-tests", 38, 40)):
            self.rejects(suite, self.logs[suite].replace(f"{current} passed;", f"{old} passed;"))

    def test_factorial_example_rejects_missing_duplicate_replaced_or_failed_named_control(self):
        original = self.logs['factorial-example-tests']
        for name in self.example_names:
            line = f'test {name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line,
                           original.replace(name, 'tests::unexpected'),
                           original.replace(line, line.replace('... ok', '... FAILED')),
                           original.replace(line, line.replace('... ok', '... ignored'))]:
                with self.subTest(control=name):
                    self.logs['factorial-example-tests'] = mutant
                    self.assertNotEqual(self.run_gate(), 0)
        self.logs['factorial-example-tests'] = original

    def test_factorial_example_does_not_accept_filtered_or_measured_tests(self):
        original = self.logs['factorial-example-tests']
        for field in ('measured', 'filtered out'):
            self.logs['factorial-example-tests'] = original.replace(f'0 {field};', f'1 {field};')
            self.assertNotEqual(self.run_gate(), 0)
        self.logs['factorial-example-tests'] = original

    def test_selected_native_suites_keep_nonzero_filtered_observations(self):
        for suite in ("factorial-kernel-tests", "history-w1-tests",
                      "history-import-tests", "cpu-completion-tests"):
            with self.subTest(suite=suite):
                original = self.logs[suite]
                filtered = original.replace("0 filtered out;", "1325 filtered out;")
                self.assertEqual(validate_log(suite, filtered), validate_log(suite, original))

    def test_actual_workflow_uses_both_strict_gates_without_changing_native_selectors(self):
        workflow = WORKFLOW.read_text()
        for group, report in (("legal", "legal-native-controls"), ("factorial", "factorial-native-controls")):
            command = ('          python3 -B scripts/ci/w1_native_controls.py --group ' + group
                       + ' --logs "$OUT" --output "$OUT/' + report + '-completion.json"')
            self.assertEqual(workflow.splitlines().count(command), 1)
        commands = (
            "-p trnm-pon-node --example pon_w1_legal_strategy_v1 -- --test-threads=1",
            "-p trnm-crypto-primitives --lib pon_work::legal_attempt:: -- --test-threads=1",
            "-p trnm-pon-node --example pon_w1_legal_strategy_v3 -- --test-threads=1",
            "-p trnm-pon-node --test work_header_binding -- --test-threads=1",
            "-p trnm-pon-node --lib history_w1_ -- --test-threads=1 --nocapture",
            "-p trnm-pon-node --lib ingress::history_import::tests:: -- --test-threads=1 --nocapture",
            "-p trnm-pon-node --lib ingress::public_v3::scalar_cpu::completion_tests:: -- --test-threads=1 --nocapture",
        )
        for command in commands:
            self.assertIn("cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml "
                          + command + " 2>&1 | tee ", workflow)
        self.assertEqual(workflow.count("python3 -B scripts/ci/test_w1_factorial_native_gate.py"), 1)
        self.assertEqual(workflow.count("python3 scripts/ci/test_w1_factorial_native_gate.py"), 1)

    def test_cli_failure_never_writes_success_report(self):
        self.logs["legal-native-controls"] = ""
        self.assertNotEqual(self.run_gate("legal"), 0)

    def test_cli_fifo_and_symlink_log_refuse_without_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "legal-native-controls.log"
            command = [sys.executable, "-B", str(GATE), "--group", "legal", "--logs", directory,
                       "--output", str(root / "completion.json")]
            os.mkfifo(path)
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=2).returncode, 2)
            path.unlink()
            (root / "valid.log").write_text(self.logs["legal-native-controls"])
            path.symlink_to("valid.log")
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=2).returncode, 2)
            self.assertFalse((root / "completion.json").exists())


class LegalGateTests(unittest.TestCase):
    def setUp(self):
        workflow = WORKFLOW.read_text()
        command = ('python3 -B scripts/ci/w1_native_controls.py --group legal --logs "$OUT" '
                   '--output "$OUT/legal-native-controls-completion.json"')
        self.assertEqual(workflow.count(command), 1)
        self.names = example_names('v1')
        self.assertEqual(len(self.names), 13)
        self.assertEqual(set(self.names), set(SUITES['legal-native-controls']['passed']))
        self.log = (f'running {len(self.names)} tests\n'
                    + ''.join(f'test {name} ... ok\n' for name in self.names)
                    + summary(len(self.names)))

    def run_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'legal-native-controls.log'
            path.write_text(self.log)
            output = root / 'completion.json'
            result = subprocess.run(
                [sys.executable, '-B', str(GATE), '--group', 'legal', '--logs', directory,
                 '--output', str(output)], capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                report = json.loads(output.read_text())
                self.assertEqual([row['suite'] for row in report['suites']], ['legal-native-controls'])
                row = report['suites'][0]
                self.assertEqual(row['passed'], sorted(self.names))
                self.assertEqual(row['bytes'], len(self.log.encode()))
                self.assertEqual(row['sha256'], hashlib.sha256(self.log.encode()).hexdigest())
            else:
                self.assertFalse(output.exists())
            return result.returncode

    def test_complete_current_native_roster_passes(self):
        self.assertEqual(self.run_gate(), 0)

    def test_every_retained_versioned_material_and_observer_control_executes_once(self):
        original = self.log
        for name in self.names:
            line = f'test {name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line,
                           original.replace(name, 'tests::unexpected'),
                           original.replace(line, line.replace('... ok', '... FAILED')),
                           original.replace(line, line.replace('... ok', '... ignored'))]:
                with self.subTest(control=name):
                    self.log = mutant
                    self.assertNotEqual(self.run_gate(), 0)
        self.log = original

    def test_summary_only_stale_filtered_duplicate_or_failed_summaries_are_refused(self):
        original = self.log
        mutants = [summary(13), original.replace('13 passed;', '8 passed;'),
                   original.replace('0 failed;', '1 failed;'),
                   original.replace('0 ignored;', '1 ignored;'),
                   original.replace('0 measured;', '1 measured;'),
                   original.replace('0 filtered out;', '1 filtered out;'),
                   original + summary(13),
                   original + summary(13).replace('ok.', 'FAILED.'), '']
        for mutant in mutants:
            with self.subTest(mutant=mutant):
                self.log = mutant
                self.assertNotEqual(self.run_gate(), 0)
        self.log = original


if __name__ == "__main__":
    unittest.main()
