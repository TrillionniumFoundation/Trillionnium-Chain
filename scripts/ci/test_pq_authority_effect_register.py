"""Adversarial controls using real pinned source bytes, not successful stubs.

These tests exercise the source register. They do not run the native tests whose
source files are retained in the register, or establish runtime reachability.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_authority_effect_register as register

REPO = Path(__file__).resolve().parents[2]
EXPECTED_SCOPES = {
    'compat_transfer_type_v1': 'validation-result-only',
    'native_pnx1_account_transfer': 'native-account-state-and-node-persistence',
    'portable_consumption_settlement_v1': 'portable-settlement-store-only',
    'research_command_state_v1': 'research-protocol-state-only',
    'hepta_admission_compare_v1': 'owner-context-comparison-only',
    'cell_discovery_v1_fetch_cache': 'provider-directory-and-content-cache-only',
    'reference_release_finality_v2_observer': 'read-only-certificate-facts',
}


class AuthorityEffectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = register.strict_json((REPO / register.DEFAULT_MANIFEST).read_bytes())
        cls.sources = {path: (REPO / path).read_bytes()
                       for path in cls.original['source_files_sha256']}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = deepcopy(self.original)
        for path, raw in self.sources.items():
            self.put(path, raw)
        self.save()

    def put(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return target

    def save(self):
        return self.put(register.DEFAULT_MANIFEST,
                        (json.dumps(self.data, indent=2) + '\n').encode())

    def row(self, rid):
        return next(row for row in self.data['routes'] if row['id'] == rid)

    def refused(self, reason=None):
        self.save()
        with self.assertRaisesRegex(register.RegisterError, reason or '.'):
            register.inspect(self.root)

    def test_real_locked_files_have_exact_scopes_and_never_qualify(self):
        result = register.inspect(self.root)
        self.assertEqual(result['status'], 'HOLD')
        self.assertEqual(result['source_consistency'], 'PASS')
        self.assertEqual(result['curated_routes_checked'], 7)
        self.assertEqual({row['id']: row['effect_scope'] for row in result['routes']},
                         EXPECTED_SCOPES)
        self.assertEqual(result['source_revision'],
                         '0f0592ace4b08a1d39e1ffad31beee76ddc4fd66')
        self.assertEqual(result['source_files_sha256'], self.original['source_files_sha256'])
        for name in ('coverage_complete', 'whole_chain_pq_qualified', 'production_activation',
                     'provenance_authenticated', 'call_graph_proved',
                     'runtime_reachability_proved', 'native_tests_executed'):
            self.assertIs(result[name], False, name)

    def test_reordered_rows_paths_and_hash_map_do_not_change_the_contract(self):
        self.data['routes'].reverse()
        for row in self.data['routes']:
            for field in register.SOURCE_FIELDS:
                row[field].reverse()
        self.data['source_files_sha256'] = dict(reversed(list(self.data['source_files_sha256'].items())))
        self.save()
        self.assertEqual(register.inspect(self.root)['source_consistency'], 'PASS')

    def test_every_actual_source_file_is_required_even_when_its_pin_remains(self):
        for path, original in self.sources.items():
            with self.subTest(path=path):
                target = self.root / path
                target.unlink()
                try:
                    with self.assertRaisesRegex(register.RegisterError, 'missing source'):
                        register.inspect(self.root)
                finally:
                    target.write_bytes(original)

    def test_every_nonempty_route_source_category_is_required(self):
        for original in self.original['routes']:
            for field in register.SOURCE_FIELDS:
                if not original[field]:
                    continue
                with self.subTest(route=original['id'], field=field):
                    self.data = deepcopy(self.original)
                    self.row(original['id'])[field].pop()
                    self.refused('curated source set mismatch')

    def test_removing_both_real_native_path_and_pin_cannot_hide_it(self):
        path = 'trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs'
        for row in self.data['routes']:
            for field in register.SOURCE_FIELDS:
                row[field] = [item for item in row[field] if item != path]
        self.data['source_files_sha256'].pop(path)
        (self.root / path).unlink()
        self.assertTrue((self.root / register.TRANSFER).is_file())
        self.refused('curated source set mismatch')

    def test_changed_source_refuses_and_rehashing_manifest_is_not_provenance(self):
        path = 'trillionnium/crates/trnm-pon-node/src/store.rs'
        changed = self.sources[path] + b'\n// changed source after the reviewed revision\n'
        self.put(path, changed)
        self.refused('source lock hash mismatch')
        self.data['source_files_sha256'][path] = hashlib.sha256(changed).hexdigest()
        self.refused('fixed reviewed lock')

    def test_scope_promotion_of_validator_comparator_cache_or_finality_refuses(self):
        cases = (
            ('compat_transfer_type_v1', 'native-account-state-and-node-persistence'),
            ('hepta_admission_compare_v1', 'hepta-final-use-authority'),
            ('cell_discovery_v1_fetch_cache', 'payment-custody-and-install-authority'),
            ('reference_release_finality_v2_observer', 'production-consensus-finality'),
            ('research_command_state_v1', 'model-installation-authority'),
        )
        for rid, scope in cases:
            with self.subTest(route=rid):
                self.data = deepcopy(self.original)
                self.row(rid)['effect_scope'] = scope
                self.refused('unreviewed effect/context')

    def test_other_real_settlement_module_is_not_this_bilateral_owner(self):
        path = 'trillionnium/crates/trnm-service-settlement/src/native_budget.rs'
        raw = (REPO / path).read_bytes()
        self.put(path, raw)
        self.data['source_files_sha256'][path] = hashlib.sha256(raw).hexdigest()
        self.row('portable_consumption_settlement_v1')['state_or_effect_sources'] = [path]
        self.refused('curated source set mismatch')

    def test_source_revision_schema_purpose_and_route_context_drift_refuse(self):
        for field, value in (('source_revision', '0' * 40), ('schema', 'future-schema'),
                             ('purpose', 'production-qualification')):
            with self.subTest(field=field):
                self.data = deepcopy(self.original)
                self.data[field] = value
                self.refused()
        for field in ('profile_boundary', 'reachability_observation'):
            with self.subTest(field=field):
                self.data = deepcopy(self.original)
                self.row('native_pnx1_account_transfer')[field] = 'all-runtime-paths-qualified'
                self.refused('unreviewed effect/context')

    def test_false_claims_must_be_boolean_false_not_zero(self):
        for field in ('coverage_complete', 'whole_chain_pq_qualified', 'production_activation'):
            for value in (True, 0, None, 'false'):
                with self.subTest(field=field, value=value):
                    self.data = deepcopy(self.original)
                    self.data[field] = value
                    self.refused('cannot qualify')

    def test_unknown_missing_duplicate_and_malformed_route_fields_refuse(self):
        for mutate in (
            lambda data: data.update(runtime_receipt='another-branch-pass'),
            lambda data: data.pop('source_revision'),
            lambda data: data['routes'][0].update(native_tests_executed=True),
            lambda data: data['routes'][0].pop('state_or_effect_sources'),
            lambda data: data['routes'].pop(),
            lambda data: data['routes'].append(deepcopy(data['routes'][0])),
            lambda data: data['routes'][0].update(id=data['routes'][1]['id']),
            lambda data: data['routes'][0].update(id=[]),
            lambda data: data['routes'][0].update(authentication_sources=[{}]),
            lambda data: data['routes'][0].update(authentication_sources=None),
            lambda data: data['routes'][0]['entry_sources'].append(data['routes'][0]['entry_sources'][0]),
        ):
            self.data = deepcopy(self.original)
            mutate(self.data)
            self.refused()

    def test_source_lock_missing_extra_invalid_and_changed_hashes_refuse(self):
        path = register.TRANSFER
        for value in ('0' * 64, 'A' * 64, 'a' * 63, 0, None):
            with self.subTest(value=value):
                self.data = deepcopy(self.original)
                self.data['source_files_sha256'][path] = value
                self.refused()
        self.data = deepcopy(self.original)
        self.data['source_files_sha256'].pop(path)
        self.refused('exactly the curated source paths')
        self.data = deepcopy(self.original)
        self.data['source_files_sha256']['unreviewed/source.rs'] = '0' * 64
        self.refused('exactly the curated source paths')

    def test_unreviewed_files_do_not_make_the_partial_register_complete(self):
        self.put('unreviewed/authority.rs', b'// An unreviewed additional entrypoint.\n')
        result = register.inspect(self.root)
        self.assertEqual(result['source_consistency'], 'PASS')
        self.assertIs(result['coverage_complete'], False)
        self.assertIs(result['runtime_reachability_proved'], False)

    def test_duplicate_json_fields_refuse_at_manifest_route_and_hash_levels(self):
        raw = json.dumps(self.original)
        key = json.dumps(register.TRANSFER)
        cases = (
            '{"schema": "duplicate", ' + raw[1:],
            raw.replace('"id": ', '"id": "duplicate", "id": ', 1),
            raw.replace(key + ': ', key + ': "duplicate", ' + key + ': ', 1),
        )
        for malformed in cases:
            with self.subTest(raw=malformed[:80]):
                self.put(register.DEFAULT_MANIFEST, malformed.encode())
                with self.assertRaisesRegex(register.RegisterError, 'duplicate JSON field'):
                    register.inspect(self.root)

    def test_json_syntax_numbers_unicode_and_size_are_bounded(self):
        cases = (b'{', b'[]', b'{"a": 1.0}', b'{"a": NaN}', b'{"a": Infinity}',
                 b'{"a": 1234567890123456789}', b'{"a":"\\ud800"}',
                 b'\xff', b'{} trailing', b' ' * (register.MAX_BYTES + 1))
        for malformed in cases:
            with self.subTest(raw=malformed[:60]):
                self.put(register.DEFAULT_MANIFEST, malformed)
                with self.assertRaises(register.RegisterError):
                    register.inspect(self.root)

    def test_manifest_source_and_directory_symlinks_refuse(self):
        for relative in (register.DEFAULT_MANIFEST, register.TRANSFER):
            path = self.root / relative
            original = path.read_bytes()
            donor = self.put('link-donor', original)
            path.unlink()
            path.symlink_to(donor)
            with self.assertRaisesRegex(register.RegisterError, 'symlink'):
                register.inspect(self.root)
            path.unlink()
            path.write_bytes(original)
        directory = self.root / 'trillionnium'
        moved = self.root / 'moved-trillionnium'
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(register.RegisterError, 'symlink'):
            register.inspect(self.root)

    def test_oversize_source_and_unsafe_manifest_path_refuse(self):
        self.put(register.TRANSFER, b'x' * (register.MAX_BYTES + 1))
        self.refused('nonregular/oversize source')
        for path in ('../escape.json', '/absolute.json', 'a//b', 'a\\b', 'bad\x00name'):
            with self.subTest(path=path), self.assertRaises(register.RegisterError):
                register.inspect(self.root, path)

    def test_cli_hold_and_fifo_refusal_have_machine_readable_exit_status(self):
        command = [sys.executable, str(REPO / 'scripts/ci/pq_authority_effect_register.py'),
                   '--root', str(self.root)]
        positive = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        self.assertEqual(json.loads(positive.stdout)['status'], 'HOLD')
        path = self.root / register.TRANSFER
        path.unlink()
        os.mkfifo(path)
        refused = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(json.loads(refused.stderr)['status'], 'REFUSE')
        self.assertEqual(refused.stdout, '')


if __name__ == '__main__':
    unittest.main()
