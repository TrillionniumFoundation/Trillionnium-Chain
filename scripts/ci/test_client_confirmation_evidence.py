#!/usr/bin/env python3
"""Reject altered client qualification receipts, including self-consistent rehashes."""
from __future__ import annotations
import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from check_client_confirmation_evidence import ROOT, RUNNER, TEST_FILE, client_selectors, validate


class ClientSelectorBindingTests(unittest.TestCase):
    def test_nested_callbacks_are_not_independent_unittest_cases(self):
        source = 'class VerifiedHistoryTests:\n    def test_recovery(self):\n        def cancel(): pass\n    def setUp(self): pass\n'
        self.assertEqual(client_selectors(source), [TEST_FILE + '::VerifiedHistoryTests.test_recovery'])

    def test_all_direct_cases_remain_required(self):
        source = 'class VerifiedHistoryTests:\n    def test_b(self): pass\n    def test_a(self): pass\nclass OtherTests:\n    def test_a(self): pass\n'
        self.assertEqual(client_selectors(source), [TEST_FILE + '::VerifiedHistoryTests.test_a', TEST_FILE + '::VerifiedHistoryTests.test_b'])


class ClientEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = ROOT / 'evidence/pon-client-confirmation-v1'
        cls.baseline = validate()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pon-client-evidence-test-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'evidence'
        shutil.copytree(self.original, self.folder)
        self.manifest = json.loads((self.folder / 'manifest.json').read_text())
        self.qualification = json.loads((self.folder / 'qualification.json').read_text())

    def write_json(self, name, value):
        (self.folder / name).write_text(json.dumps(value, indent=2) + '\n')

    def reject_rehashed(self, pattern):
        self.write_json('qualification.json', self.qualification)
        for name in self.manifest['files']:
            self.manifest['files'][name] = hashlib.sha256((self.folder / name).read_bytes()).hexdigest()
        self.write_json('manifest.json', self.manifest)
        with self.assertRaisesRegex(ValueError, pattern):
            validate(evidence=self.folder)

    def row(self, name):
        return next(row for row in self.qualification['results'] if row['name'] == name)

    def test_unchanged_complete_package_passes(self):
        self.assertEqual(validate(evidence=self.folder), self.baseline)

    def test_edited_log_without_rehash_rejects(self):
        path = self.folder / self.row('test_client_confirmation')['log']
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaisesRegex(ValueError, 'changed artifact'):
            validate(evidence=self.folder)

    def test_public_acceptance_cannot_be_rehashed(self):
        self.manifest['public_network_ready'] = True
        self.reject_rehashed('unsupported authority')

    def test_independent_acceptance_cannot_be_rehashed(self):
        self.qualification['independent_accepted'] = True
        self.reject_rehashed('qualification authority')

    def test_old_model_measurement_is_not_rerun(self):
        self.qualification['model_experiments_rerun'] = True
        self.reject_rehashed('wrong experiment scope')

    def test_missing_measured_runner_rejects(self):
        self.qualification['source_files_sha256'].pop(RUNNER)
        self.reject_rehashed('missing measured qualification runner')

    def test_missing_client_runtime_input_rejects(self):
        self.qualification['source_files_sha256'].pop('formal/pon-nakamoto-v1/client_confirmation.py')
        self.reject_rehashed('current runtime inventory')

    def test_fabricated_source_digest_rejects(self):
        self.qualification['source_files_sha256'][TEST_FILE] = '0' * 64
        self.reject_rehashed('false source digest')

    def test_historical_inventory_cannot_be_dropped(self):
        self.qualification['historical_evidence_sha256'].pop('evidence/pon-v4/manifest.json')
        self.reject_rehashed('historical inventory')

    def test_old_evidence_cannot_be_repinned(self):
        self.qualification['historical_evidence_sha256']['evidence/pon-v4/manifest.json'] = '0' * 64
        self.reject_rehashed('historical evidence changed')

    def test_one_backend_cannot_replace_two(self):
        self.qualification['results'].remove(self.row('native-client-confirmation'))
        self.reject_rehashed('execution matrix')

    def test_duplicate_named_result_rejects(self):
        self.qualification['results'].append(copy.deepcopy(self.row('test_client_confirmation')))
        self.reject_rehashed('execution matrix')

    def test_failed_execution_cannot_be_hidden(self):
        self.row('native-client-confirmation')['returncode'] = 1
        self.reject_rehashed('failed execution')

    def test_unmeasured_network_throughput_rejects(self):
        self.row('native-client-confirmation')['client_confirmed_transactions'] = 1
        self.reject_rehashed('unmeasured network metric')

    def test_rehashed_log_cannot_drop_actual_client_selectors(self):
        row = self.row('native-client-confirmation')
        path = self.folder / row['log']
        path.write_text(path.read_text().replace('test_', 'removed_'))
        self.reject_rehashed('unobserved client selector')

    def test_native_backend_must_be_explicit(self):
        self.row('native-client-confirmation')['environment_overrides'].pop('TRNM_NATIVE_EXECUTOR')
        self.reject_rehashed('missing actual native client selection')

    def test_native_suite_count_cannot_be_inflated(self):
        self.row('native-suite')['native_passed'] += 1
        self.reject_rehashed('native result count')

    def test_native_build_cannot_drop_work_verifier(self):
        command = self.row('native-build')['command']
        command.remove('trnm-crypto-primitives')
        self.reject_rehashed('native build scope')

    def test_native_suite_cannot_drop_locked_dependencies(self):
        self.row('native-suite')['command'].remove('--locked')
        self.reject_rehashed('native invocation')

    def test_physical_power_loss_is_not_inferred(self):
        self.qualification['environment']['physical_power_loss'] = True
        self.reject_rehashed('environment scope')

    def test_client_navigation_uses_new_receipt_not_historical_model_evidence(self):
        from report_module_evidence import report
        value = report(module='M14')
        queried = [r for r in value['responsibilities'] if any(TEST_FILE in s for s in r['evidence_selectors'])]
        self.assertTrue(queried)
        for row in queried:
            current = row['packages']['client_confirmation']
            self.assertTrue(current['current_regression_support'])
            self.assertEqual(current['unobserved_selectors'], [])
            self.assertFalse(row['packages']['e3']['current_regression_support'])
        self.assertFalse(value['ordinary_product_integration_granted'])
        self.assertFalse(value['independent_acceptance_granted'])
        self.assertFalse(value['production_activation'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
