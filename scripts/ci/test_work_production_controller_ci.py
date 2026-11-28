"""Offline structure and fail-closed controls for the Work test receipt."""
import contextlib
import io
from pathlib import Path
import unittest

from scripts.ci import check_work_production_controller as q


class Fixture(unittest.TestCase):
    def __init__(self, name, outcome="pass"):
        super().__init__("runTest")
        self._name = name
        self._scenario = outcome

    def id(self):
        return self._name

    def runTest(self):
        if self._scenario == "skip":
            self.skipTest("synthetic skip")
        if self._scenario == "fail":
            self.fail("synthetic failure")
        if self._scenario == "error":
            raise RuntimeError("synthetic error")

    @unittest.expectedFailure
    def expected_failure(self):
        self.fail("synthetic expected failure")

    @unittest.expectedFailure
    def unexpected_success(self):
        pass


def fake_suite(last="pass"):
    children = [Fixture(name) for name in q.REQUIRED[:-1]]
    node = Fixture(q.REQUIRED[-1], last)
    if last in ("expected_failure", "unexpected_success"):
        node._testMethodName = last
    return unittest.TestSuite([unittest.TestSuite(children), node])


def run(suite):
    with contextlib.redirect_stderr(io.StringIO()):
        return q.run_controls(suite)


class WorkControllerCI(unittest.TestCase):
    def test_exact_real_discovery_preserves_both_observation_methods(self):
        from hia.platform.work_owner import test_production
        suite = unittest.defaultTestLoader.loadTestsFromModule(test_production)
        q.require_roster(q.suite_ids(suite))
        self.assertEqual(q.REQUIRED[-2:], (
            "hia.platform.work_owner.test_production.ProductionControls.test_23_disappearing_worker_never_supplies_missing_proof",
            "hia.platform.work_owner.test_production.ProductionControls.test_24_observer_service_and_attribution_failures_remain_fatal",
        ))

    def test_old_missing_extra_duplicate_substitution_and_order_refused(self):
        ids = list(q.REQUIRED)
        for row in (ids[:22], ids[:-1], ids + ["extra"], ids[:-1] + [ids[0]],
                    ids[:-1] + ["substitute"], [ids[1], ids[0], *ids[2:]]):
            with self.subTest(count=len(row), last=row[-1]), self.assertRaisesRegex(
                    ValueError, "Complete production controller discovery"):
                run(unittest.TestSuite([Fixture(name, "fail") for name in row]))
        q.require_roster(ids)

    def test_completed_receipt_requires_the_exact_start_sequence_and_counts(self):
        valid = run(fake_suite())
        self.assertTrue(q.report_is_exact_pass(valid))
        self.assertEqual(valid["executed"], 24)
        for key, value in (("required", list(q.REQUIRED[:-1])), ("started", list(q.REQUIRED[:-1])),
                           ("started", [q.REQUIRED[0], *q.REQUIRED[:-1]]), ("executed", 23),
                           ("executed", 24.0), ("skipped", False), ("errors", 1), ("failures", 1),
                           ("status", "FAIL"), ("actual_production_positive", 0),
                           ("actual_production_positive", True)):
            with self.subTest(field=key, value=value):
                self.assertFalse(q.report_is_exact_pass({**valid, key: value}))
        self.assertFalse(q.report_is_exact_pass({**valid, "undeclared": True}))

    def test_only_full_success_not_skip_error_or_expected_failure(self):
        for terminal in ("skip", "error", "fail", "expected_failure", "unexpected_success"):
            with self.subTest(terminal=terminal):
                report = run(fake_suite(terminal))
                self.assertEqual(report["started"], list(q.REQUIRED))
                self.assertEqual(report["status"], "FAIL")
                self.assertFalse(q.report_is_exact_pass(report))

    def test_workflow_preserves_guard_position_receipts_and_pipefail(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/hia-native-migration.yml").read_text()
        start = workflow.index("      - name: Require all production Work controller rejection groups\n")
        end = workflow.index("\n      - name:", start + 1)
        self.assertEqual(workflow[start:end].splitlines()[1:], [
            "        run: |",
            "          set -euo pipefail",
            '          python3 -B -m scripts.ci.check_work_production_controller "$RUNNER_TEMP/hia-observations/work-production-controller.json" 2>&1 | tee "$RUNNER_TEMP/hia-observations/work-production-controller.log"',
        ])
        self.assertTrue(workflow[end:].startswith(
            "\n      - name: Execute fresh native Host checkpoints with independent syscall tracing\n"))



def load_tests(loader, _suite, _pattern):
    return loader.loadTestsFromTestCase(WorkControllerCI)
