#!/usr/bin/env python3
"""Exercise current CI evidence gates; no native proofs or security qualification.

The real current map is the positive report input. Inert cases carrying exact
names exercise the named-runner boundary without recursively running this suite.
"""
from __future__ import annotations

from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_qrom_current_ci as ci

ROOT = Path(__file__).resolve().parents[2]
HEAD, BASE, MERGE = 'a' * 40, 'b' * 40, 'c' * 40


def inert_case(name, skipped=False):
    class NamedFixture(unittest.TestCase):
        def id(self):
            return name

        def runTest(self):
            if skipped:
                self.skipTest('isolated named-runner control')

    return NamedFixture()


class CurrentCiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current, cls.audit, cls.contract, cls.raw = ci.load_current(ROOT)
        cls.legacy, _ = cls.audit.load_contract(ROOT)
        cls.mapping = cls.current.build_report(ROOT)
        cls.roster, cls.roster_raw = ci.load_roster(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cls.drift = ci.observe_drift(ROOT, root)
            cls.stdout = (root / 'historical-on-current.stdout.log').read_bytes()
            cls.stderr = (root / 'historical-on-current.stderr.log').read_bytes()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp = Path(self.temporary.name)
        self.counter = 0

    def execute_fixture(self, mode='success'):
        names = ['fixture_cases.FixedCase.test_one', 'fixture_cases.FixedCase.test_two']
        roster = {'expected_tests': 2, 'suites': [
            {'module': 'fixture_cases', 'expected_tests': 2, 'tests': names}]}
        actual = list(names)
        if mode == 'missing':
            actual.pop()
        elif mode == 'duplicate':
            actual.append(actual[0])
        suite = unittest.TestSuite(inert_case(name, mode == 'skip' and i == 0)
                                  for i, name in enumerate(actual))
        output = io.StringIO()
        with mock.patch.object(unittest.TestLoader, 'discover', return_value=suite):
            report = ci.execute_named(self.temp, roster, output)
        return report, roster

    def source(self, merge=False):
        return {'schema': 'trnm-ci-source-v1', 'kind': 'prospective-merge' if merge else 'head',
            'tested_commit': MERGE if merge else HEAD, 'tested_tree': 'd' * 40,
            'candidate': HEAD, 'base': BASE if merge else None,
            'prospective_merge': MERGE if merge else None, 'tracked_worktree_verified': True,
            'tracked_entries': 1, 'tracked_bytes': 1, 'tests_executed_by_identity_check': False}

    def baseline(self):
        self.counter += 1
        out = self.temp / str(self.counter)
        out.mkdir()
        (out / 'required-tests.json').write_bytes(self.roster_raw)
        (out / 'historical-on-current.stdout.log').write_bytes(self.stdout)
        (out / 'historical-on-current.stderr.log').write_bytes(self.stderr)
        rows = []
        for required in self.roster['suites']:
            names = required['tests']
            rows.append({'module': required['module'], 'expected_ids': names,
                'registered_ids': names, 'started_ids': names, 'success_ids': names,
                'tests_run': len(names), 'passed': True, 'loader_errors': [], 'skipped': [],
                'failures': [], 'errors': [], 'expected_failures': [], 'unexpected_successes': []})
        named = {'schema': 'TRNM-W1-QROM-CURRENT-NAMED-OBSERVATION1',
            'roster_sha256': ci.ROSTER_SHA256, 'required_tests': self.roster['expected_tests'],
            'suites': rows, 'all_named_controls_passed': True, 'qualification': ci.scope()}
        for name, report in [('named-tests.json', named), ('source-before.json', self.source()),
                             ('source-after.json', self.source()), ('implementation.json', self.mapping),
                             ('historical-drift.json', self.drift)]:
            ci.write_once(out / name, report)
        # Isolated named cases create fixture receipts only; the real workflow
        # executes the original eight historical and fourteen current controls.
        supplemental_out = out / 'supplemental'
        supplemental_out.mkdir()
        manifest, retained = ci.supplemental.load_roster(ROOT)
        (supplemental_out / ci.supplemental.RETAINED_ROSTER).write_bytes(retained)
        by_module = {row['module']: row for row in manifest['suites']}
        def isolated_discovery(loader, start_dir, pattern='test*.py', top_level_dir=None):
            row = by_module[Path(pattern).stem]
            return unittest.TestSuite(inert_case(name) for name in row['tests'])
        with mock.patch.object(unittest.TestLoader, 'discover', isolated_discovery):
            for row in manifest['suites']:
                receipt = ci.supplemental.run_suite(ROOT, row['suite'], stream=io.StringIO())
                self.assertIs(receipt['all_named_controls_passed'], True)
                ci.write_once(supplemental_out / ci.supplemental.OUTPUTS[row['suite']], receipt)
        steps = {name: {'outcome': 'success', 'conclusion': 'success'} for name in ci.REQUIRED_STAGES}
        return out, steps

    def test_actual_current_mapping_and_original_refusal_are_separate(self):
        ci.validate_historical_job(
            (ROOT / '.github/workflows/pon-w1-qrom-implementation.yml').read_text())
        workflow = (ROOT / '.github/workflows/pon-w1-qrom-implementation.yml').read_text()
        historical_job, current_job = workflow.split('  qrom-historical-implementation:\n', 1)[1].split(
            '  qrom-current-implementation:\n', 1)
        self.assertNotIn('w1_qrom_historical_fixture.py', historical_job)
        self.assertNotIn('w1_qrom_supplemental_controls.py', historical_job)
        expected_supplemental = {
            'supplemental_historical_controls', 'supplemental_historical_mapping',
            'supplemental_current_mapping', 'supplemental_budget_unknown',
            'supplemental_budget_hypothetical', 'supplemental_report_scopes',
        }
        self.assertTrue(expected_supplemental <= set(ci.REQUIRED_STAGES))
        for stage in expected_supplemental:
            self.assertEqual(current_job.count('        id: ' + stage + '\n'), 1)
        self.assertIn('--output-dir "$W1_QROM_SUPPLEMENTAL_OUT"', current_job)
        ci.validate_mapping(self.mapping, self.current, self.audit, self.contract, self.raw, ROOT)
        ci.validate_drift(self.drift, self.contract, self.legacy)
        self.assertIs(self.mapping['historical_v1']['workflow_passed'], False)
        self.assertEqual(self.drift['historical_exit_code'], 2)
        self.assertEqual(
            [(row['path'], row['observed_bytes'], row['observed_sha256'])
             for row in self.drift['selected_source_differences']],
            [('formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs', 11172,
              '5e102fcbe4881e3d163c7a8b65364304b14d080ae64f23b0d5032daa84208aa7'),
             ('formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock', 46018,
              '93a68edce98e5c61e0cba33ebfbe392ff52df24633347da5a214ac8eb6eae24b'),
             ('trillionnium/crates/trnm-protocol/src/pon_wire.rs', 32654,
              'ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b')])

    def test_named_runner_records_every_real_start_and_success(self):
        report, roster = self.execute_fixture()
        ci.validate_named(report, roster)
        self.assertEqual(report['suites'][0]['tests_run'], 2)

    def test_named_runner_refuses_missing_duplicate_and_skipped_cases(self):
        for mode in ('missing', 'duplicate', 'skip'):
            with self.subTest(mode=mode):
                report, roster = self.execute_fixture(mode)
                self.assertIs(report['all_named_controls_passed'], False)
                with self.assertRaises(ci.ObservationError):
                    ci.validate_named(report, roster)

    def test_named_import_exit_zero_is_not_completion(self):
        roster = {'expected_tests': 1, 'suites': [{'module': 'fixture_cases',
            'expected_tests': 1, 'tests': ['fixture_cases.FixedCase.test_one']}]}
        with mock.patch.object(unittest.TestLoader, 'discover', side_effect=SystemExit(0)):
            result = ci.execute_named(self.temp, roster, io.StringIO())
        self.assertIs(result['all_named_controls_passed'], False)

    def test_named_completion_rechecks_ids_counts_and_boolean_types(self):
        for mutation in ('success_ids', 'started_ids', 'count', 'passed', 'scope'):
            with self.subTest(mutation=mutation):
                report, roster = self.execute_fixture()
                if mutation in ('success_ids', 'started_ids'):
                    report['suites'][0][mutation].pop()
                elif mutation == 'count':
                    report['suites'][0]['tests_run'] = True
                elif mutation == 'passed':
                    report['all_named_controls_passed'] = 1
                else:
                    report['qualification']['production_qualified'] = 0
                with self.assertRaises(ci.ObservationError):
                    ci.validate_named(report, roster)

    def test_mapping_rejects_scope_escalation_and_unknown_budget_changes(self):
        for mutation in ('qualification', 'budget', 'budget_bool', 'native', 'historical',
                         'historical_bool', 'closure'):
            with self.subTest(mutation=mutation):
                report = deepcopy(self.mapping)
                if mutation == 'qualification':
                    report['qualification']['post_quantum_soundness_qualified'] = 0
                elif mutation == 'budget':
                    report['lifetime_budget']['quantum_queries_lifetime'] = 0
                elif mutation == 'budget_bool':
                    report['lifetime_budget']['policy_adopted'] = 0
                elif mutation == 'native':
                    report['native_binary_executed'] = True
                elif mutation == 'historical':
                    report['historical_v1']['workflow_passed'] = True
                elif mutation == 'historical_bool':
                    report['historical_v1']['workflow_passed'] = 0
                else:
                    report['local_path_closure']['source_files_checked'] -= 1
                with self.assertRaises(ci.ObservationError):
                    ci.validate_mapping(report, self.current, self.audit, self.contract, self.raw, ROOT)

    def test_drift_rejects_missing_changes_and_unrelated_process_failures(self):
        bad = deepcopy(self.drift['historical_result'])
        bad['reason'] = 'unrelated helper input drift'
        fake = type('Result', (), {'stdout': b'', 'stderr': json.dumps(bad).encode(),
                                  'returncode': 2})()
        with mock.patch.object(ci.subprocess, 'run', return_value=fake):
            with self.assertRaises(ci.ObservationError):
                ci.observe_drift(ROOT, self.temp)
        failed = json.loads((self.temp / 'historical-drift.json').read_bytes())
        self.assertEqual(failed['classification'], 'UNCLASSIFIED_HISTORICAL_RESULT')
        self.assertEqual((self.temp / 'historical-on-current.stderr.log').read_bytes(), fake.stderr)
        for mutation in ('missing', 'duplicate', 'lock_digest', 'wrong_reason',
                         'exit_zero', 'old_source', 'scope'):
            with self.subTest(mutation=mutation):
                report = deepcopy(self.drift)
                if mutation == 'missing':
                    report['selected_source_differences'].pop()
                elif mutation == 'duplicate':
                    report['selected_source_differences'].append(
                        deepcopy(report['selected_source_differences'][0]))
                elif mutation == 'lock_digest':
                    lock = next(row for row in report['selected_source_differences']
                                if row['path'].endswith('/w1_v2_verifier/Cargo.lock'))
                    lock['observed_sha256'] = '0' * 64
                elif mutation == 'wrong_reason':
                    report['historical_result']['reason'] = 'unrelated missing file'
                elif mutation == 'exit_zero':
                    report['historical_exit_code'] = 0
                elif mutation == 'old_source':
                    report['historical_replay_commit'] = HEAD
                else:
                    report['historical_result']['qualification']['security_bits_quantum'] = 128
                with self.assertRaises(ci.ObservationError):
                    ci.validate_drift(report, self.contract, self.legacy)
        # Even mutually consistent metadata/report edits cannot hide the new
        # reviewed lock delta and restore the obsolete two-change allowance.
        current = deepcopy(self.contract)
        lock_path = 'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock'
        original = next(row for row in self.legacy['project_files'] if row['path'] == lock_path)
        current['project_files'] = [deepcopy(original) if row['path'] == lock_path else row
                                    for row in current['project_files']]
        report = deepcopy(self.drift)
        report['selected_source_differences'] = [
            row for row in report['selected_source_differences'] if row['path'] != lock_path]
        with self.assertRaisesRegex(ci.ObservationError, 'selected-byte differences lost'):
            ci.validate_drift(report, current, self.legacy)

    def test_source_checks_keep_candidate_and_historical_identities_separate(self):
        workflow = (ROOT / '.github/workflows/pon-w1-qrom-implementation.yml').read_text()
        for changed in (workflow.replace(ci.HISTORICAL_SOURCE, HEAD),
                        workflow.replace("actual complete module registry differs", "weakened registry")):
            with self.assertRaises(ci.ObservationError):
                ci.validate_historical_job(changed)
        for merge in (False, True):
            before = self.source(merge)
            kind, source = before['kind'], before['tested_commit']
            ci.validate_source(before, deepcopy(before), kind, source, HEAD, BASE)
            after = deepcopy(before)
            after['tested_commit'] = ci.HISTORICAL_SOURCE
            with self.assertRaises(ci.ObservationError):
                ci.validate_source(before, after, kind, source, HEAD, BASE)
            before['candidate'] = ci.HISTORICAL_SOURCE
            with self.assertRaises(ci.ObservationError):
                ci.validate_source(before, deepcopy(before), kind, source, HEAD, BASE)

    def test_final_gate_accepts_complete_current_scope_without_qualifying_security(self):
        out, steps = self.baseline()
        result = ci.verify(ROOT, out, 'head', HEAD, HEAD, BASE, steps)
        self.assertIs(result['all_required_current_observations_passed'], True)
        self.assertIs(result['historical_v1_on_current_passed'], False)
        self.assertEqual(result['qualification'], ci.scope())

    def test_final_gate_retains_every_failed_or_skipped_stage(self):
        for stage in ci.REQUIRED_STAGES:
            for field, value in [('outcome', 'failure'), ('conclusion', 'skipped')]:
                with self.subTest(stage=stage, field=field):
                    out, steps = self.baseline()
                    steps[stage][field] = value
                    with self.assertRaises(ci.ObservationError):
                        ci.verify(ROOT, out, 'head', HEAD, HEAD, BASE, steps)
                    result = json.loads((out / 'current-ci-status.json').read_bytes())
                    self.assertIs(result['all_required_current_observations_passed'], False)
                    self.assertIn(stage, result['failed_or_skipped_stages'])

    def test_final_gate_refuses_missing_completion_and_changed_original_output(self):
        for mutation in ('completion', 'output', 'roster',
                         'supplemental_roster', 'supplemental_historical', 'supplemental_current'):
            with self.subTest(mutation=mutation):
                out, steps = self.baseline()
                if mutation == 'completion':
                    (out / 'named-tests.json').unlink()
                elif mutation == 'output':
                    (out / 'historical-on-current.stderr.log').write_bytes(b'{}\n')
                elif mutation == 'roster':
                    (out / 'required-tests.json').write_bytes(b'{}\n')
                elif mutation == 'supplemental_roster':
                    (out / 'supplemental' / ci.supplemental.RETAINED_ROSTER).write_bytes(b'{}\n')
                else:
                    suite = mutation.removeprefix('supplemental_')
                    (out / 'supplemental' / ci.supplemental.OUTPUTS[suite]).unlink()
                with self.assertRaises(ci.ObservationError):
                    ci.verify(ROOT, out, 'head', HEAD, HEAD, BASE, steps)
                result = json.loads((out / 'current-ci-status.json').read_bytes())
                self.assertIs(result['all_required_current_observations_passed'], False)

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}'):
            with self.assertRaises(ci.ObservationError):
                ci.strict_json(raw)

    def test_existing_observation_is_never_replaced(self):
        path = self.temp / 'retained.json'
        path.write_bytes(b'original failure\n')
        with self.assertRaises(FileExistsError):
            ci.write_once(path, {'passed': True})
        self.assertEqual(path.read_bytes(), b'original failure\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
