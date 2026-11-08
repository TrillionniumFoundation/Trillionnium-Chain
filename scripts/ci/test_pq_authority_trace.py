"""Identity and claim-boundary adversaries for incomplete authority traces."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pq_authority_surface_scan import AuditError, CRITICAL, MAX_SOURCE_BYTES, inspect
from pq_authority_trace import (
    REQUIRED_TRACES, SCHEMA, build_inputs, build_inputs_sha256, load_manifest,
    read_rooted, validate,
)
from test_pq_chain_claim_guard import DescriptorReaderControls


class TraceReaderRaceTests(DescriptorReaderControls, unittest.TestCase):
    reader = staticmethod(read_rooted)
    reader_error = AuditError
    byte_limit = MAX_SOURCE_BYTES


class TestPqAuthorityTrace(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in CRITICAL:
            self.put(name, 'pub fn support() {}\n')
        self.put('rust-toolchain.toml', '[toolchain]\nchannel = "stable"\n')
        self.put('trillionnium/Cargo.toml', '[workspace]\nmembers = []\n')
        self.put('trillionnium/Cargo.lock', 'version = 4\n')
        self.put('trillionnium/crates/trnm-types/Cargo.toml',
                 '[package]\nname = "fixture"\nversion = "0.0.0"\n')
        records = []
        for record_id, (name, classification) in REQUIRED_TRACES.items():
            function = record_id.replace('-', '_')
            anchor = f'pub fn {function}()'
            guard = f'fn check_{function}()'
            data = anchor + ' {}\n' + guard + ' { verify_strict(); }\n'
            self.put(name, data)
            source_sha = hashlib.sha256(data.encode()).hexdigest()
            records.append({
                'id': record_id,
                'classification': classification,
                'selected_profile': 'Fixture profile; no deployment selection established.',
                'observation': 'Two exact source anchors exist in this fixture.',
                'authority_effect': 'No runtime authority effect has been established.',
                'status': 'INCOMPLETE',
                'runtime_validation': 'NOT_RECORDED',
                'sources': [
                    {'role': 'entrypoint', 'path': name, 'sha256': source_sha,
                     'anchor': anchor},
                    {'role': 'verifier', 'path': name, 'sha256': source_sha,
                     'anchor': guard},
                ],
                'unresolved_obligations': ['Trace actual callers and effects.'],
            })
        self.manifest = {
            'schema': SCHEMA,
            'source_inventory_sha256': inspect(self.root)['source_inventory_sha256'],
            'build_inputs_sha256': build_inputs_sha256(build_inputs(self.root)),
            'whole_chain_pq_qualified': False,
            'records': records,
            'untraced_scope': ['Unselected paths and non-Rust implementations remain untraced.'],
        }

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def refresh_inventory(self, manifest):
        manifest['source_inventory_sha256'] = inspect(self.root)['source_inventory_sha256']

    def repin_sources(self, manifest, path):
        sha = hashlib.sha256((self.root / path).read_bytes()).hexdigest()
        for record in manifest['records']:
            for source in record['sources']:
                if source['path'] == path:
                    source['sha256'] = sha
        self.refresh_inventory(manifest)

    def test_source_bindings_pass_but_never_qualify_authority_or_runtime(self):
        report = validate(self.root, self.manifest)
        self.assertTrue(report['source_trace_integrity_passed'])
        self.assertEqual(report['status'], 'HOLD_INCOMPLETE_AUTHORITY_TRACING')
        self.assertEqual(report['selected_source_trace_records'], len(REQUIRED_TRACES))
        self.assertFalse(report['whole_chain_pq_qualified'])
        self.assertFalse(report['all_authority_paths_traced'])
        self.assertEqual(report['completed_authority_traces'], 0)
        self.assertEqual(report['runtime_tests_executed'], 0)
        self.assertEqual(report['mapped_role_hints'], len(CRITICAL))

    def test_changed_unflagged_bytes_with_same_count_invalidates_all_traces(self):
        name = 'trillionnium/crates/new-owner/src/effect.rs'
        path = self.put(name, 'pub fn apply() { debit(); }\n')
        self.refresh_inventory(self.manifest)
        before = inspect(self.root)
        path.write_text('pub fn apply() { grant(); }\n')
        after = inspect(self.root)
        self.assertEqual(before['source_files_read'], after['source_files_read'])
        self.assertEqual(before['findings'], after['findings'])
        with self.assertRaisesRegex(AuditError, 'stale full Rust source inventory'):
            validate(self.root, self.manifest)

    def test_new_unknown_crypto_file_is_not_exempted_by_selected_traces(self):
        self.put('trillionnium/crates/new-owner/src/effect.rs', 'verify_strict(message);\n')
        with self.assertRaisesRegex(AuditError, 'stale full Rust source inventory'):
            validate(self.root, self.manifest)
        self.refresh_inventory(self.manifest)
        report = validate(self.root, self.manifest)
        self.assertEqual(report['unreviewed_indicator_files'], 1)
        self.assertEqual(report['completed_authority_traces'], 0)
        self.assertFalse(report['all_authority_paths_traced'])

    def test_dropping_indicators_from_curated_file_still_invalidates_identity(self):
        name = self.manifest['records'][0]['sources'][0]['path']
        path = self.root / name
        path.write_text(path.read_text().replace('verify_strict()', 'alias_verify()'))
        self.assertEqual(inspect(self.root)['reviewed_roles_mapped'], len(CRITICAL))
        with self.assertRaisesRegex(AuditError, 'stale full Rust source inventory'):
            validate(self.root, self.manifest)

    def test_new_corpus_digest_does_not_repin_old_trace_dependencies(self):
        name = self.manifest['records'][0]['sources'][0]['path']
        path = self.root / name
        path.write_text(path.read_text() + '// changed dependency\n')
        self.refresh_inventory(self.manifest)
        with self.assertRaisesRegex(AuditError, 'stale source anchor digest'):
            validate(self.root, self.manifest)

    def test_repinning_bytes_does_not_accept_a_missing_anchor(self):
        source = self.manifest['records'][0]['sources'][1]
        path = self.root / source['path']
        path.write_text(path.read_text().replace(source['anchor'], 'fn deleted_guard()'))
        self.repin_sources(self.manifest, source['path'])
        with self.assertRaisesRegex(AuditError, 'missing or nonunique source anchor'):
            validate(self.root, self.manifest)

    def test_ambiguous_anchor_refuses_even_with_updated_hashes(self):
        source = self.manifest['records'][0]['sources'][1]
        path = self.root / source['path']
        path.write_text(path.read_text() + '// ' + source['anchor'] + '\n')
        self.repin_sources(self.manifest, source['path'])
        with self.assertRaisesRegex(AuditError, 'missing or nonunique source anchor'):
            validate(self.root, self.manifest)

    def test_removed_high_risk_record_or_duplicate_replacement_refuses(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['records'].pop()
        with self.assertRaisesRegex(AuditError, 'all selected high-risk'):
            validate(self.root, manifest)
        manifest['records'].append(copy.deepcopy(manifest['records'][0]))
        with self.assertRaisesRegex(AuditError, 'unknown or duplicate selected'):
            validate(self.root, manifest)

    def test_selected_effect_owner_cannot_be_relabelled_test_support(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['records'][0]['classification'] = 'test-support'
        with self.assertRaisesRegex(AuditError, 'cannot be reclassified'):
            validate(self.root, manifest)

    def test_wildcard_absolute_parent_and_noncanonical_paths_refuse(self):
        for path in ('trillionnium/crates/*/src/lib.rs', '/tmp/effect.rs',
                     'trillionnium/crates/../effect.rs',
                     'trillionnium//crates/trnm-types/src/transfer.rs'):
            with self.subTest(path=path):
                manifest = copy.deepcopy(self.manifest)
                manifest['records'][0]['sources'][0]['path'] = path
                with self.assertRaises(AuditError):
                    validate(self.root, manifest)

    def test_missing_obligations_or_unsupported_qualification_refuses(self):
        changes = (
            ('status', 'CLOSED'),
            ('runtime_validation', 'PASS'),
            ('unresolved_obligations', []),
        )
        for key, value in changes:
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.manifest)
                manifest['records'][0][key] = value
                with self.assertRaises(AuditError):
                    validate(self.root, manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest['whole_chain_pq_qualified'] = True
        with self.assertRaisesRegex(AuditError, 'cannot qualify'):
            validate(self.root, manifest)

    def test_build_change_or_new_manifest_invalidates_source_trace(self):
        path = self.root / 'trillionnium/Cargo.toml'
        original = path.read_text()
        path.write_text(original + '[profile.release]\nopt-level = 1\n')
        with self.assertRaisesRegex(AuditError, 'stale Cargo/toolchain'):
            validate(self.root, self.manifest)
        path.write_text(original)
        self.put('trillionnium/crates/new-owner/Cargo.toml',
                 '[package]\nname = "new-owner"\nversion = "0.1.0"\n')
        with self.assertRaisesRegex(AuditError, 'stale Cargo/toolchain'):
            validate(self.root, self.manifest)

    def test_deleted_fixed_build_input_refuses(self):
        (self.root / 'trillionnium/Cargo.lock').unlink()
        with self.assertRaisesRegex(AuditError, 'missing source'):
            validate(self.root, self.manifest)

    def test_unknown_json_fields_and_duplicate_keys_refuse(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['records'][0]['qualified'] = True
        with self.assertRaisesRegex(AuditError, 'trace record fields'):
            validate(self.root, manifest)
        path = self.put('duplicate.json', '{"schema":"one","schema":"two"}')
        with self.assertRaisesRegex(AuditError, 'duplicate JSON key'):
            load_manifest(path)

    def test_symlink_manifest_or_build_ancestor_refuses(self):
        path = self.put('manifest.json', json.dumps(self.manifest))
        alias = self.root / 'alias.json'
        alias.symlink_to(path)
        with self.assertRaises(AuditError):
            load_manifest(alias)
        external = self.root / 'cargo-alias-source'
        external.mkdir()
        (external / 'config.toml').write_text('[build]\njobs = 1\n')
        (self.root / '.cargo').symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(AuditError, 'symlink source refused'):
            validate(self.root, self.manifest)

    def test_summary_cli_emits_hold_and_stale_cli_returns_nonzero(self):
        path = self.put('manifest.json', json.dumps(self.manifest))
        command = [sys.executable, str(Path(__file__).with_name('pq_authority_trace.py')),
                   '--root', str(self.root), '--manifest', str(path), '--summary-only']
        child = subprocess.run(command, capture_output=True, text=True, check=True)
        report = json.loads(child.stdout)
        self.assertEqual(report['status'], 'HOLD_INCOMPLETE_AUTHORITY_TRACING')
        self.assertNotIn('records', report)
        self.assertEqual(report['completed_authority_traces'], 0)
        self.put('trillionnium/crates/new-owner/src/changed.rs', 'pub fn changed() {}\n')
        child = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(child.returncode, 2)
        refusal = json.loads(child.stderr)
        self.assertEqual(refusal['status'], 'REFUSE')
        self.assertFalse(refusal['whole_chain_pq_qualified'])


if __name__ == '__main__':
    # The CI entry is this script, not discovery's success status alone:
    # unittest regards skipped/expected-failure controls as a successful run.
    program = unittest.main(exit=False)
    result = program.result
    complete = (
        result.wasSuccessful() and result.testsRun == 30
        and not result.skipped and not result.expectedFailures
        and not result.unexpectedSuccesses
    )
    if not complete:
        print('REFUSE: all 30 authority trace controls must execute and pass; '
              'no skipped or expected-failure controls', file=sys.stderr)
    raise SystemExit(0 if complete else 1)
