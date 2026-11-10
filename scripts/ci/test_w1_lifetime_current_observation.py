#!/usr/bin/env python3
"""Current-source provenance and unknown-bound controls, not security tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import w1_lifetime_current_observation as current


class CurrentLifetimeObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy, cls.contract, cls.sources, cls.pins = current.load(ROOT)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in [current.LEGACY, current.CONTRACT, *self.sources]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_current_selected_source_observation_preserves_unknown_security(self):
        result = current.report(self.root)
        self.assertEqual(result['schema'], 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2')
        self.assertEqual(result['status'], 'CURRENT_SELECTED_SOURCE_OBSERVED_SECURITY_HOLD')
        self.assertEqual(result['selected_source_survey']['base_commit'], current.CURRENT)
        self.assertFalse(result['selected_source_survey']['whole_repository_build_or_behavior_verified'])
        self.assertIsNone(result['lifetime_ledger']['conditional_union']['project_total_error_upper'])
        self.assertIsNone(result['lifetime_ledger']['sum_of_group_adversary_query_envelopes'])
        self.assertTrue(all(value is False or value is None for value in result['qualification'].values()))
        for line in result['independent_acceptance']['lines'].values():
            self.assertFalse(line['qualified'])
            self.assertIsNone(line['security_bits'])

    def test_historical_reader_still_rejects_current_source(self):
        child = subprocess.run([sys.executable, str(ROOT / current.LEGACY), '--root', str(self.root)],
                               capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stdout, '')
        self.assertEqual(json.loads(child.stderr), {
            'status': 'REFUSED', 'error': 'source identity mismatch: ' + current.CHANGED[0]})

    def test_private_current_context_does_not_change_legacy_function_or_pins(self):
        legacy, contract, sources, pins = current.load(self.root)
        original_pins = dict(legacy.SOURCE_PINS)
        original_context = legacy.source_survey.__globals__
        with patch.object(current, 'load', return_value=(legacy, contract, sources, pins)):
            report = current.report(self.root)
        self.assertEqual(legacy.SOURCE_PINS, original_pins)
        self.assertEqual(legacy.SOURCE_BASE, current.HISTORICAL)
        self.assertIs(legacy.source_survey.__globals__, original_context)
        with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
            legacy.source_survey(sources)
        self.assertFalse(report['historical_reader_or_pin_bytes_changed'])

    def test_only_the_reviewed_store_source_delta_is_present(self):
        changed = [row['path'] for row in self.contract['sources']
                   if row['historical_sha256'] != row['current_sha256']]
        self.assertEqual(changed, list(current.CHANGED))
        self.assertEqual(len(self.sources), 20)
        self.assertEqual(self.contract['sources'][7]['current_sha256'],
                         '108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554')
        self.assertEqual(self.contract['sources'][7]['historical_sha256'],
                         'b712a86b9997a098df5e8257f309d22445b2c749c9aa474457e958a0f65f5153')

    def test_historical_reader_and_contract_hashes_are_independently_frozen(self):
        self.assertEqual(hashlib.sha256((ROOT / current.LEGACY).read_bytes()).hexdigest(),
                         current.LEGACY_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / current.CONTRACT).read_bytes()).hexdigest(),
                         current.CONTRACT_SHA256)
        self.assertNotEqual(current.CURRENT, current.HISTORICAL)

    def test_ledger_arithmetic_and_input_semantics_are_not_rewritten(self):
        raw = self.legacy.template()
        result = current.report(self.root, raw)
        expected = self.legacy.serializable(self.legacy.evaluate(raw))
        self.assertEqual(result['lifetime_ledger'], expected)
        self.assertEqual(result['counterexamples'], self.legacy.serializable(self.legacy.counterexamples()))
        raw['whole_chain_post_quantum_qualified'] = True
        with self.assertRaises(ValueError):
            current.report(self.root, raw)

    def test_store_source_mutation_is_refused(self):
        path = self.root / current.CHANGED[0]
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            current.report(self.root)

    def test_other_selected_source_mutation_is_refused(self):
        path = self.root / 'trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            current.report(self.root)

    def test_source_and_manifest_changed_together_do_not_repin_the_reader(self):
        path = self.root / current.CHANGED[0]
        data = path.read_bytes() + b'\n'
        path.write_bytes(data)
        contract = deepcopy(self.contract)
        row = next(row for row in contract['sources'] if row['path'] == current.CHANGED[0])
        row.update(bytes=len(data), current_sha256=hashlib.sha256(data).hexdigest())
        (self.root / current.CONTRACT).write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, 'unreviewed current source contract'):
            current.report(self.root)

    def test_historical_reader_mutation_is_refused(self):
        path = self.root / current.LEGACY
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'historical reader bytes changed'):
            current.report(self.root)

    def test_missing_file_and_symlink_do_not_count_as_source_observations(self):
        path = self.root / current.CHANGED[0]
        path.unlink()
        with self.assertRaises(OSError):
            current.report(self.root)
        path.symlink_to(ROOT / current.CHANGED[0])
        with self.assertRaises(OSError):
            current.report(self.root)

    def test_noncanonical_paths_and_symlink_roots_are_refused(self):
        for name in ('../store.rs', '/etc/passwd', 'scripts/../scripts/w1_lifetime_ledger.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                current.read_regular(self.root, name)
        alias = self.root / 'alias'
        alias.symlink_to(ROOT, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'alias'):
            current.report(alias)

    def test_cli_reports_new_schema_without_historical_comparison(self):
        child = subprocess.run([sys.executable, str(ROOT / 'scripts/w1_lifetime_current_observation.py'),
                                '--root', str(self.root)], capture_output=True, text=True,
                               timeout=30, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['schema'], 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2')
        self.assertFalse(result['historical_positive_replay_established'])
        self.assertFalse(result['current_source_observation_is_historical_reproduction'])

    def test_cli_rejects_changed_source_without_success_report(self):
        (self.root / current.LEGACY).write_bytes(b'changed')
        child = subprocess.run([sys.executable, str(ROOT / 'scripts/w1_lifetime_current_observation.py'),
                                '--root', str(self.root)], capture_output=True, text=True,
                               timeout=30, check=False)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stdout, '')
        failure = json.loads(child.stderr)
        self.assertEqual(failure['status'], 'REFUSED')
        self.assertTrue(all(value is False or value is None for value in failure['qualification'].values()))


if __name__ == '__main__':
    unittest.main()
