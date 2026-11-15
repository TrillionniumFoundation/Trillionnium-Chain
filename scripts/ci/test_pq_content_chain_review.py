#!/usr/bin/env python3
"""Offline consistency controls; no native execution or security qualification."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from pq_content_chain_review import INPUT, PINS, ReviewError, evaluate, inspect, strict_json
from pq_source_reader import SourceReadError

ROOT = Path(__file__).resolve().parents[2]
READER = ROOT / 'scripts/ci/pq_content_chain_review.py'


class ContentChainReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = {name: (ROOT / INPUT / name).read_bytes() for name in PINS}
        cls.original = {name: strict_json(raw) for name, raw in cls.raw.items()}

    def changed(self, path, value):
        documents = deepcopy(self.original)
        target = documents
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        # Keep the independently published duplicate equal, so deeper joins
        # rather than only the outer nested-record equality are exercised.
        if path[0] == 'next-use-result.json':
            documents['native-result.json']['actual_next_use'] = deepcopy(
                documents['next-use-result.json'])
        return documents

    def refuses(self, path, value):
        with self.assertRaises(ReviewError):
            evaluate(self.changed(path, value))

    def stage(self, root):
        for name, raw in self.raw.items():
            path = root / INPUT / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def test_original_cohort_is_consistent_without_authority_or_security_promotion(self):
        result = inspect(ROOT)
        self.assertEqual(result['status'], 'HOLD_NO_GO')
        self.assertIs(result['evidence_consistent'], True)
        self.assertEqual(result['observed']['recorded_actions'], ['yes', 'yes'])
        self.assertEqual(result['observed']['payload_bytes'], 280269602)
        self.assertEqual(result['observed']['members'], 30)
        self.assertEqual(result['observed']['restored_chunks'], 95)
        self.assertEqual(result['observed']['recorded_forwards'], 2)
        for key in ('ordinary_hepta_use_proved', 'whole_chain_pq_qualified',
                    'installation_authorized', 'hepta_final_use',
                    'model_efficacy_accepted', 'production_activation'):
            self.assertIs(result[key], False, key)
        self.assertIsNone(result['actual_lifetime_failure_bound'])
        self.assertIsNone(result['security_bits'])
        self.assertIs(result['provenance']['execution_authenticated'], False)
        self.assertIs(result['provenance']['source_or_authority_authenticated'], False)

    def test_five_input_copies_match_independent_fixed_lengths_and_digests(self):
        expected = {
            'native-result.json': (18354, 'b6f25ae1ee224ab9a619b7d7993635284495f43bc28f05f7c2b1bd8eacd4dc4b'),
            'next-use-result.json': (1697, 'a1d4948b0a904ac9d12da251222907c6cbe936f3b62fbf17a2412aa98043871a'),
            'next-use-observations.json': (2354, '8b3c438eea2d1199aa0d753c36e5d64506f042dd6984f9f819b02273d840e242'),
            'independent-execution-inputs.json': (3538, 'f8814c99415b552c3664318dadb7dd1b692ea63e6171fa8ad9df5854872db00b'),
            'worker/ready.json': (4247, 'cfd0380d9f66c025bbf0bd4da3d6a4d00594684e70c3ada5e163eae408b2911c'),
        }
        self.assertEqual(set(self.raw), set(expected))
        for name, (size, digest) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(len(self.raw[name]), size)
                self.assertEqual(hashlib.sha256(self.raw[name]).hexdigest(), digest)

    def test_missing_extra_and_wrong_record_containers_refuse(self):
        cases = [None, [], {**self.original, 'unexpected.json': {}},
                 {k: v for k, v in self.original.items() if k != 'worker/ready.json'}]
        for documents in cases:
            with self.subTest(kind=type(documents).__name__):
                with self.assertRaises(ReviewError):
                    evaluate(documents)
        self.refuses(('worker/ready.json',), [])
        self.refuses(('next-use-observations.json',), {})

    def test_schema_and_nested_next_use_drift_refuse(self):
        self.refuses(('native-result.json', 'actual_next_use', 'observations'), 1)
        for name in self.original:
            if name != 'next-use-observations.json':
                with self.subTest(name=name):
                    self.refuses((name, 'schema'), 'unknown-schema')

    def test_operation_content_version_descriptor_snapshot_and_plan_grafts_refuse(self):
        cases = [
            (('independent-execution-inputs.json', 'operation'), '0' * 64),
            (('independent-execution-inputs.json', 'descriptor'), '0' * 128),
            (('worker/ready.json', 'content'), '0' * 128),
            (('worker/ready.json', 'version'), '0' * 128),
            (('native-result.json', 'snapshot', 'cts1'), '0' * 128),
            (('native-result.json', 'bep52', 'plan'), '0' * 128),
        ]
        for path, value in cases:
            with self.subTest(path=path):
                self.refuses(path, value)

    def test_worker_parent_environment_and_all_material_profile_grafts_refuse(self):
        for path in (
                ('worker/ready.json', 'worker_sha256'),
                ('worker/ready.json', 'actual_loaded_parent'),
                ('worker/ready.json', 'contract'),
                ('worker/ready.json', 'file_sha256'),
                ('worker/ready.json', 'environment_pins', 'scripts/llm_cell_sealed_worker_v1.py')):
            with self.subTest(path=path):
                self.refuses(path, '0' * 64)
        for path in (('independent-execution-inputs.json', 'material_profile'),
                     ('worker/ready.json', 'material_profile'),
                     ('worker/ready.json', 'material_runtime_bridge', 'profile')):
            with self.subTest(path=path):
                self.refuses(path, 'different-profile')

    def test_request_identity_hash_prompt_order_and_uniqueness_refuse(self):
        for path, value in (
                (('independent-execution-inputs.json', 'requests', 0, 'request_id'), 'another-request'),
                (('independent-execution-inputs.json', 'requests', 0, 'prompt'), 'different prompt'),
                (('next-use-observations.json', 0, 'input_sha256'), '0' * 64),
                (('next-use-observations.json', 0, 'descriptor'), '0' * 128),
                (('next-use-observations.json', 0, 'artifact'), '0' * 64)):
            with self.subTest(path=path):
                self.refuses(path, value)
        requests = self.original['independent-execution-inputs.json']['requests']
        self.refuses(('independent-execution-inputs.json', 'requests', 1, 'request_id'),
                     requests[0]['request_id'])
        self.refuses(('next-use-observations.json',),
                     list(reversed(self.original['next-use-observations.json'])))

    def test_missing_duplicated_and_reordered_transport_members_refuse(self):
        members = self.original['native-result.json']['bep52']['members']
        duplicate = deepcopy(members)
        duplicate[1]['manifest'] = duplicate[0]['manifest']
        for value in (members[:-1], members + [members[0]], duplicate, list(reversed(members))):
            with self.subTest(size=len(value)):
                self.refuses(('native-result.json', 'bep52', 'members'), value)

    def test_download_readback_restore_and_handoff_accounting_refuse(self):
        for path, value in (
                (('native-result.json', 'bep52', 'members', 0, 'downloaded_bytes'), 654),
                (('native-result.json', 'bep52', 'members', 0, 'cached_chunks'), 1),
                (('native-result.json', 'bep52', 'consumer_usage', 'completed_fetches'), 29),
                (('native-result.json', 'bep52', 'consumer_usage', 'readback_completed'), 0),
                (('native-result.json', 'bep52', 'consumer_usage', 'readback_reserved_bytes'), 280269601),
                (('native-result.json', 'bep52', 'consumer_usage', 'readback_reserved_chunks'), 94),
                (('native-result.json', 'cold_restore', 'consumer_chunks'), 94),
                (('native-result.json', 'handoff', 'kernel_descriptors'), 29),
                (('native-result.json', 'handoff', 'environment_bytes'), 0)):
            with self.subTest(path=path):
                self.refuses(path, value)

    def test_original_deadlines_process_outcomes_and_rss_budgets_refuse(self):
        for path, value in (
                (('independent-execution-inputs.json', 'max_snapshot_bytes'), 1),
                (('native-result.json', 'process', 'elapsed_ms'), 300001),
                (('native-result.json', 'process', 'exit_code'), 1),
                (('native-result.json', 'process', 'termination_requested'), True),
                (('next-use-result.json', 'supervisor', 'observed_wall_ns'), 38000000000),
                (('next-use-result.json', 'supervisor', 'waited_child_peak_rss_bytes'), 8589934593),
                (('next-use-observations.json', 0, 'observed_rss_bytes'), 8589934593),
                (('next-use-result.json', 'supervisor', 'waited_child_reaped'), False),
                (('next-use-result.json', 'supervisor', 'waited_child_observation_error'), 'missing wait4')):
            with self.subTest(path=path):
                self.refuses(path, value)

    def test_authority_promotion_and_numeric_false_aliases_refuse(self):
        paths = [('next-use-result.json', 'authority'), ('worker/ready.json', 'authority'),
                 ('next-use-observations.json', 0, 'authority')]
        for path in paths:
            for value in (True, 0, None, 'false'):
                with self.subTest(path=path, value=value):
                    self.refuses((*path, 'hepta_final_use'), value)
        self.refuses(('worker/ready.json', 'authority'), {})
        self.refuses(('worker/ready.json', 'authority'),
                     {**self.original['worker/ready.json']['authority'], 'activation': False})

    def test_research_scope_cannot_be_promoted_by_summary_flags(self):
        for path in (
                ('native-result.json', 'installation_authorized'),
                ('native-result.json', 'original_hepta_owner_used'),
                ('native-result.json', 'production_activation'),
                ('native-result.json', 'independent_operators'),
                ('native-result.json', 'bep52', 'independent_failure_domains'),
                ('native-result.json', 'bep52', 'transport_plan_includes_cts1'),
                ('native-result.json', 'snapshot', 'compatibility_from_hashes_alone'),
                ('native-result.json', 'cold_restore', 'm12_funding_admitted')):
            with self.subTest(path=path):
                self.refuses(path, True)
        self.refuses(('next-use-result.json', 'interpreter_and_native_dependencies'),
                     'fully sealed whole runtime')

    def test_numeric_booleans_and_malformed_dimensions_refuse(self):
        for path in (
                ('native-result.json', 'input', 'manifest_count'),
                ('native-result.json', 'process', 'exit_code'),
                ('native-result.json', 'handoff', 'kernel_descriptors'),
                ('worker/ready.json', 'generation'),
                ('next-use-observations.json', 0, 'input_tokens'),
                ('next-use-observations.json', 0, 'execution_ns'),
                ('next-use-observations.json', 0, 'scores_q32', 0)):
            with self.subTest(path=path):
                self.refuses(path, True)
        self.refuses(('next-use-observations.json', 0, 'scores_q32'), [1])
        self.refuses(('next-use-observations.json', 0, 'action_ids'), ['yes', 'no'])

    def test_strict_json_rejects_duplicates_numbers_and_invalid_unicode(self):
        for raw in (b'{"a":1,"a":2}', b'[1.5]', b'[NaN]', b'[Infinity]',
                    b'["\xff"]', b'["\\ud800"]', b'not-json', b'[123456789012345678901]'):
            with self.subTest(raw=raw):
                with self.assertRaises(ReviewError):
                    strict_json(raw)

    def test_json_byte_depth_and_string_escape_boundaries(self):
        for raw in (b' ' * 65537, b'[' * 65 + b'0' + b']' * 65,
                    b'[' * 32000 + b'0' + b']' * 32000):
            with self.subTest(size=len(raw)):
                with self.assertRaises(ReviewError):
                    strict_json(raw)
        self.assertEqual(strict_json(b'{"brackets":"[{}]","escaped":"\\\"["}'),
                         {'brackets': '[{}]', 'escaped': '"['})
        self.assertEqual(strict_json(b'["\\u03b8"]'), ['θ'])

    def test_inspect_refuses_modified_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.stage(root)
            path = root / INPUT / 'native-result.json'
            raw = path.read_bytes()
            changed = raw.replace(b'observed_two_forwards', b'Observed_two_forwards', 1)
            self.assertEqual(len(raw), len(changed))
            self.assertNotEqual(raw, changed)
            path.write_bytes(changed)
            with self.assertRaises((ReviewError, SourceReadError)):
                inspect(root)

    def test_inspect_refuses_missing_files_and_symlinked_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.stage(root)
            path = root / INPUT / 'worker/ready.json'
            raw = path.read_bytes()
            path.unlink()
            with self.assertRaises((ReviewError, SourceReadError)):
                inspect(root)
            backing = root / 'backing.json'
            backing.write_bytes(raw)
            path.symlink_to(backing)
            with self.assertRaises((ReviewError, SourceReadError)):
                inspect(root)
            path.unlink()
            path.parent.rmdir()
            elsewhere = root / 'elsewhere'
            elsewhere.mkdir()
            (elsewhere / 'ready.json').write_bytes(raw)
            path.parent.symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaises((ReviewError, SourceReadError)):
                inspect(root)

    def test_cli_success_is_a_scoped_hold_report(self):
        process = subprocess.run([sys.executable, '-B', str(READER)], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'HOLD_NO_GO')
        self.assertIs(result['installation_authorized'], False)
        self.assertIsNone(result['security_bits'])

    def test_cli_missing_or_changed_inputs_fail_without_stdout_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, '-B', str(READER), '--root', str(root)]
            missing = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            self.assertEqual(missing.stdout, '')
            self.stage(root)
            path = root / INPUT / 'next-use-result.json'
            path.write_bytes(path.read_bytes() + b'\n')
            changed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(changed.returncode, 2)
            self.assertEqual(changed.stdout, '')

    def test_only_recorded_action_profile_and_complete_forward_observations_are_accepted(self):
        self.refuses(('next-use-observations.json', 0, 'profile'), 'independent-efficacy-result')
        self.refuses(('next-use-observations.json',), self.original['next-use-observations.json'][:1])
        self.refuses(('next-use-result.json', 'failures'), ['forward failed'])
        self.refuses(('next-use-result.json', 'observations'), 1)
        self.refuses(('worker/ready.json', 'runtime_snapshot_sha256'), '0' * 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
