#!/usr/bin/env python3
"""Reader counterexamples using an explicitly supplied real retained artifact.

Copied metadata/report mutations are parser tests, never new execution or
performance observations. Originals are read-only; temporary hard links are
replaced atomically before a mutation, never written through.
"""
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import read_original_native_campaign as reader

ARTIFACT = HEAD = TREE = MANIFEST = None
SUBSET = False


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


class ActualArtifactReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes = (ARTIFACT / 'artifact-files.json').read_bytes()
        cls.manifest = reader.strict_json(cls.manifest_bytes)
        cls.valid = reader.read_campaign(ARTIFACT, MANIFEST, HEAD, TREE, retained_subset=SUBSET)
        cls.retention = (reader.strict_json((ARTIFACT / 'retention.json').read_bytes()) if SUBSET else None)
        bundle = (reader.SubsetBundle if SUBSET else reader.Bundle)(ARTIFACT, MANIFEST)
        try:
            cls.report = bundle.json('run-1-raw/report.json')
        finally:
            bundle.close()

    @classmethod
    def tearDownClass(cls):
        if (ARTIFACT / 'artifact-files.json').read_bytes() != cls.manifest_bytes:
            raise ValueError('original artifact manifest was modified')
        for name in ('results.json', *(() if SUBSET else ('run-1-raw/report.json', 'public_v3_multiprocess.bin'))):
            entry = next(row for row in cls.manifest['files'] if row['path'] == name)
            if hashlib.sha256((ARTIFACT / name).read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('original native input was modified: ' + name)

    def clone(self):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-native-reader-counterexample-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        paths = ([row['retained_path'] for row in self.retention['files']] if SUBSET else
                 [row['path'] for row in self.manifest['files']])
        for name in paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            os.link(ARTIFACT / name, path)
        (root / 'artifact-files.json').write_bytes(self.manifest_bytes)
        if SUBSET:
            (root / 'retention.json').write_bytes(encoded(self.retention))
        return root

    def set_manifest(self, root, manifest):
        raw = encoded(manifest)
        (root / 'artifact-files.json').write_bytes(raw)
        if SUBSET:
            retention = reader.strict_json((root / 'retention.json').read_bytes())
            retention['original_manifest'].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (root / 'retention.json').write_bytes(encoded(retention))

    def write(self, root, name, raw):
        retention = reader.strict_json((root / 'retention.json').read_bytes()) if SUBSET else None
        mapping = next(row for row in retention['files'] if row['original_path'] == name) if SUBSET else None
        path = root / (mapping['retained_path'] if SUBSET else name)
        wire = gzip.compress(raw, mtime=0) if SUBSET and mapping['encoding'] == 'gzip' else raw
        temporary = path.with_name(path.name + '.counterexample-new')
        temporary.write_bytes(wire)
        os.replace(temporary, path)
        manifest = reader.strict_json((root / 'artifact-files.json').read_bytes())
        row = next(item for item in manifest['files'] if item['path'] == name)
        row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if SUBSET:
            mapping.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           retained_bytes=len(wire), retained_sha256=hashlib.sha256(wire).hexdigest())
            (root / 'retention.json').write_bytes(encoded(retention))
        self.set_manifest(root, manifest)

    def change_json(self, root, name, change):
        value = reader.strict_json((root / name).read_bytes())
        change(value)
        self.write(root, name, encoded(value))

    def read(self, root):
        pin = hashlib.sha256((root / 'artifact-files.json').read_bytes()).hexdigest()
        return reader.read_campaign(root, pin, HEAD, TREE, retained_subset=SUBSET)

    def test_real_input_preserves_cohorts_and_explicit_unknowns(self):
        counts = self.valid['denominators']
        self.assertEqual(counts, {'complete_runs': 3, 'phases': 9,
            'submitted_block_observations': 189, 'confirmation_round_observations': 27,
            'hostile_round_observations': 18,
            'hostile_rounds_with_observed_depletion_overlap': 9,
            'all_hostile_rounds_depletion_overlapped': False,
            'unique_observed_transaction_ids': 3})
        self.assertFalse(self.valid['scope']['reader_executes_native_test'])
        self.assertFalse(self.valid['scope']['cryptographic_hardness_qualified'])
        self.assertFalse(self.valid['scope']['independent_operators_qualified'])
        self.assertFalse(self.valid['scope']['wan_qualified'])
        self.assertIsNone(self.valid['scope']['sustainable_business_tps'])

    def test_manifest_pin_paths_duplicates_and_limits_cannot_be_repaired_by_self_report(self):
        with self.assertRaisesRegex(ValueError, 'file-list SHA256'):
            reader.read_campaign(ARTIFACT, '0' * 64, HEAD, TREE, retained_subset=SUBSET)
        controls = (
            lambda value: value['files'][0].update(path='../results.json'),
            lambda value: value['files'][0].update(path='/tmp/results.json'),
            lambda value: value['files'][0].update(path='run-1-raw/./report.json'),
            lambda value: value['files'].append(copy.deepcopy(value['files'][0])),
            lambda value: value['files'][0].update(bytes=reader.MAX_FILE_BYTES + 1),
            lambda value: value['files'][0].update(bytes=True),
        )
        for change in controls:
            with self.subTest(control=change):
                root = self.clone()
                manifest = copy.deepcopy(self.manifest)
                change(manifest)
                self.set_manifest(root, manifest)
                with self.assertRaises(ValueError):
                    self.read(root)

    def test_changed_file_symlink_and_nonregular_input_refuse(self):
        root = self.clone()
        (root / 'results.json').unlink()
        (root / 'results.json').symlink_to(ARTIFACT / 'results.json')
        with self.assertRaises(OSError):
            self.read(root)
        root = self.clone()
        raw = (root / 'results.json').read_bytes()
        temporary = root / 'replacement'
        temporary.write_bytes(raw.replace(b'release', b'debugXX', 1))
        os.replace(temporary, root / 'results.json')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.read(root)
        root = self.clone()
        (root / 'build.stderr.log').unlink()
        os.mkfifo(root / 'build.stderr.log')
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.read(root)

    def test_source_profile_resource_and_missing_binary_refuse(self):
        controls = (
            ('source-before-campaigns.json', lambda v: v.update(tested_tree='0' * 40)),
            ('run-3-resource-after.json', lambda v: v['limits'][0].update({'cpu.max': '800000 100000'})),
            ('results.json', lambda v: v['binary']['actual_compiler_artifact_profile'].update(opt_level='0')),
            ('results.json', lambda v: v.update(original_inputs={**v['original_inputs'], 'seed_transfers': 256})),
            ('results.json', lambda v: v.update(attempts=v['attempts'][:2])),
            ('run-1-phase-readback.json', lambda v: v['phases'][0].update(confirmed_rounds=2)),
        )
        for name, change in controls:
            with self.subTest(name=name):
                root = self.clone()
                self.change_json(root, name, change)
                with self.assertRaises(ValueError):
                    self.read(root)
        if not SUBSET:
            root = self.clone()
            (root / 'public_v3_multiprocess.bin').unlink()
            with self.assertRaises(OSError):
                self.read(root)

    def test_zero_test_output_cannot_pass_even_with_updated_metadata_hashes(self):
        root = self.clone()
        raw = (root / 'run-1.stdout.log').read_bytes().replace(b'1 passed', b'0 passed')
        self.write(root, 'run-1.stdout.log', raw)
        digest = hashlib.sha256(raw).hexdigest()
        def update_step(value):
            value.update(stdout_bytes=len(raw), stdout_sha256=digest)
        self.change_json(root, 'run-1.step.json', update_step)
        self.change_json(root, 'run-1-result.json', lambda v: update_step(v['step']))
        self.change_json(root, 'results.json', lambda v: update_step(v['attempts'][0]['step']))
        with self.assertRaisesRegex(ValueError, 'exactly one original native test'):
            self.read(root)

    def test_boolean_exit_status_is_not_integer_success(self):
        root = self.clone()
        self.change_json(root, 'run-1.step.json', lambda v: v.update(returncode=False))
        self.change_json(root, 'run-1-result.json', lambda v: v['step'].update(returncode=False))
        self.change_json(root, 'results.json', lambda v: v['attempts'][0]['step'].update(returncode=False))
        with self.assertRaisesRegex(ValueError, 'step did not complete'):
            self.read(root)

    def test_runtime_executable_cannot_differ_from_built_artifact(self):
        root = self.clone()
        raw = (root / 'run-1.stderr.log').read_bytes().replace(
            b'/release/deps/public_v3_multiprocess-', b'/debug/deps/public_v3_multiprocess-')
        self.write(root, 'run-1.stderr.log', raw)
        digest = hashlib.sha256(raw).hexdigest()
        def update_step(value):
            value.update(stderr_bytes=len(raw), stderr_sha256=digest)
        self.change_json(root, 'run-1.step.json', update_step)
        self.change_json(root, 'run-1-result.json', lambda v: update_step(v['step']))
        self.change_json(root, 'results.json', lambda v: update_step(v['attempts'][0]['step']))
        with self.assertRaisesRegex(ValueError, 'runtime executable'):
            self.read(root)

    def test_duplicate_json_and_nonfinite_numbers_refuse(self):
        for raw in (b'{"schema":"a","schema":"b"}', b'{"elapsed_seconds":NaN}'):
            root = self.clone()
            self.write(root, 'results.json', raw)
            with self.assertRaises(ValueError):
                self.read(root)

    def test_report_round_counters_and_authority_cannot_replace_observations(self):
        controls = (
            lambda p: p['confirmations'][0].update(paid_credit_depletion_observed_during_round=True),
            lambda p: p['confirmations'][0]['observation'].update(execution_authority=True),
            lambda p: p['confirmations'][0]['observation'].update(depth=7),
            lambda p: p['confirmations'][0]['receiver_hostile_after'].update(
                work_rejected=p['confirmations'][0]['receiver_hostile_before']['work_rejected']),
            lambda p: p['receiver_observation'].update(measurement_failures=1),
            lambda p: [row.update(public_request_body_digest=None) for child in p['children']
                       for row in child['report']['result']['calls']],
            lambda p: p['submissions'].pop(),
            lambda p: p['confirmations'].pop(),
        )
        for change in controls:
            with self.subTest(control=change):
                phase = copy.deepcopy(self.report['phases'][1])
                change(phase)
                with self.assertRaises(ValueError):
                    reader.phase(phase)

    def test_booked_principal_cannot_become_paid_cpu_depletion(self):
        original = self.report['phases'][1]['depletion_meter']
        self.assertTrue(reader.depletion(original))
        value = copy.deepcopy(original)
        flow = value['actual_flow']
        flow.update(paid_cpu_debit_ns=0, live_debited_cpu_ns=0,
                    settlement_residual_cpu_ns=0, settled_full_cpu_ns=0,
                    unsettled_known_live_cpu_ns=0, live_owners=20, booked_reservation_ns=2_000_000_000)
        flow['remaining_paid_credit_ns'] = flow['initial_credit_ns'] + flow['credited_refill_ns'] - flow['settlement_discard_ns']
        flow['stored_credit_ns'] = flow['remaining_paid_credit_ns'] - flow['booked_reservation_ns']
        with self.assertRaisesRegex(ValueError, 'reported depletion'):
            reader.depletion(value)
        value = copy.deepcopy(original)
        value['actual_flow']['paid_cpu_debit_ns'] += 1
        with self.assertRaisesRegex(ValueError, 'balance identity'):
            reader.depletion(value)

    def test_economics_requires_all_observed_samples_and_real_winners(self):
        for change in (
                lambda v: v['economics'].pop(),
                lambda v: v['economics'][0]['report']['result']['modes'][0]['samples'][0].update(errors=['retained failure']),
                lambda v: v.update(best_observed_cold_legal_method='prepared-generic')):
            value = copy.deepcopy(self.report)
            change(value)
            with self.assertRaises(ValueError):
                reader.economics(value)

    def test_subset_requires_explicit_mode_and_does_not_claim_omitted_binary(self):
        if SUBSET:
            self.assertEqual(self.valid['coverage'], 'retained-subset')
            self.assertFalse(self.valid['binary_payload_hash_verified'])
            self.assertLess(self.valid['verified_original_file_count'], self.valid['original_manifest_file_count'])
            with self.assertRaises(OSError):
                reader.read_campaign(ARTIFACT, MANIFEST, HEAD, TREE)
        else:
            self.assertEqual(self.valid['coverage'], 'full-artifact')
            self.assertTrue(self.valid['binary_payload_hash_verified'])
            self.assertEqual(self.valid['verified_original_file_count'], 910)

    def test_subset_mapping_and_gzip_decode_are_checked_against_original_hash(self):
        if not SUBSET:
            self.skipTest('gzip counterexamples require the explicit retained-subset invocation')
        root = self.clone()
        retention = reader.strict_json((root / 'retention.json').read_bytes())
        mapping = next(row for row in retention['files'] if row['encoding'] == 'gzip')
        path = root / mapping['retained_path']
        raw = gzip.decompress(path.read_bytes()) + b'counterexample-only extra decoded byte'
        wire = gzip.compress(raw, mtime=0)
        replacement = path.with_name(path.name + '.counterexample-new')
        replacement.write_bytes(wire)
        os.replace(replacement, path)
        mapping.update(retained_bytes=len(wire), retained_sha256=hashlib.sha256(wire).hexdigest())
        (root / 'retention.json').write_bytes(encoded(retention))
        with self.assertRaisesRegex(ValueError, 'decoded retention'):
            self.read(root)
        root = self.clone()
        retention = reader.strict_json((root / 'retention.json').read_bytes())
        retention['files'][0]['sha256'] = '0' * 64
        (root / 'retention.json').write_bytes(encoded(retention))
        with self.assertRaisesRegex(ValueError, 'contradicts original'):
            self.read(root)
        bundle = reader.SubsetBundle(ARTIFACT, MANIFEST)
        try:
            with self.assertRaisesRegex(ValueError, 'decoded retention exceeds'):
                bundle.raw('run-1-raw/report.json', 1024)
        finally:
            bundle.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--retained-subset', action='store_true')
    args, remaining = parser.parse_known_args()
    ARTIFACT, HEAD, TREE, MANIFEST = (args.artifact_dir, args.expected_head,
                                      args.expected_tree, args.expected_manifest_sha256)
    SUBSET = args.retained_subset
    unittest.main(argv=[sys.argv[0], *remaining])
