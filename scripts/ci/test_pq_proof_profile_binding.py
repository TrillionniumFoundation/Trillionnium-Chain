#!/usr/bin/env python3
"""Profile-scope controls over the retained declarations and exact input bytes."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import pq_proof_profile_binding as binding


ROOT = Path(__file__).resolve().parents[2]


class ProofProfileBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads((ROOT / binding.DEFAULT_MANIFEST).read_bytes())
        cls.mapping = json.loads((ROOT / binding.MAPPING).read_bytes())
        cls.system = json.loads((ROOT / binding.lifetime.DEFAULT_MANIFEST).read_bytes())
        cls.paths = {binding.DEFAULT_MANIFEST, binding.MAPPING,
                     binding.lifetime.DEFAULT_MANIFEST, binding.upstream.DEFAULT_MANIFEST}
        cls.paths.update(row['path'] for group in ('project_files', 'saved_v2_files', 'audit_helpers')
                         for row in cls.mapping[group])
        cls.paths.add(cls.mapping['upstream_snapshot']['path'])
        cls.paths.update(row['source']['path'] for row in cls.contract['excluded_profile_sources'])
        cls.paths.add(cls.contract['theorem_reference']['evaluator_source']['path'])

    def declarations(self, contract=None, mapping=None, system=None):
        return binding.validate_declarations(
            copy.deepcopy(self.contract if contract is None else contract),
            copy.deepcopy(self.mapping if mapping is None else mapping),
            copy.deepcopy(self.system if system is None else system),
        )

    def checkout(self):
        temporary = tempfile.TemporaryDirectory(prefix='pq-profile-binding-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for path in self.paths:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        return root

    @staticmethod
    def write(root, path, data):
        (root / path).write_text(json.dumps(data, indent=2) + '\n')

    def test_actual_selected_profile_is_bound_without_security_promotion(self):
        result = binding.inspect(ROOT)
        self.assertEqual(result['schema'], 'trnm-pq-proof-profile-binding-result-v2')
        self.assertEqual(result['status'], 'PROFILE_BOUND_UPSTREAM_REVOKED_HOLD')
        self.assertEqual(result['selected_profile_id'], binding.PROFILE)
        self.assertEqual(result['selected_identity']['sdk'], '3.0.6')
        self.assertEqual(result['selected_identity']['image_id'][0], 1958252411)
        self.assertEqual(result['selected_identity']['field'], {
            'base_modulus': '2013265921', 'extension_degree': 4,
            'extension_polynomial': 'X^4 + 11',
        })
        self.assertEqual(result['selected_identity']['fri'], {
            'queries': 50, 'inverse_rate': 4, 'folding_factor': 16, 'final_min_degree': 256,
        })
        self.assertIs(result['candidate_profile_identity_matched'], False)
        self.assertEqual(len(result['open_obligations']), 15)
        self.assertTrue(all(row['state'] == 'UNRESOLVED' for row in result['open_obligations']))
        self.assertIsNone(result['actual_lifetime_failure_bound'])
        for key in ('whole_chain_pq_qualified', 'composition_coverage_proved',
                    'production_activation', 'whole_chain_hash_query_scope_closed',
                    'native_proof_verification_performed', 'compiled_or_loaded_identity_verified',
                    'complete_dependency_closure_verified', 'current_proof_use_eligible'):
            self.assertIs(result[key], False)

    def test_composed_current_mapping_has_one_fixed_identity_and_no_approval(self):
        # Fixed review values from the AM standalone-lock source review, independent of
        # constants or pin values supplied by the implementation under test.
        expected = {
            'path': 'config/pon/w1-qrom-implementation-current-v2.json',
            'bytes': 47960,
            'sha256': '6884d8edf7415f0141a6bacd991d49cfb672692ab24d9ba88b031ddd135038ef',
        }
        security = json.loads((ROOT / binding.upstream.DEFAULT_MANIFEST).read_bytes())
        self.assertEqual(self.contract['mapping_contract'], expected)
        self.assertEqual(security['mapping_contract'], expected)
        self.assertEqual(security['approved_current_profile_ids'], [])
        result = binding.inspect(ROOT)
        self.assertEqual(result['status'], 'PROFILE_BOUND_UPSTREAM_REVOKED_HOLD')
        self.assertIs(result['current_proof_use_eligible'], False)

    def test_upstream_withdrawal_uses_the_same_real_profile_and_artifact_bytes(self):
        result = binding.inspect(ROOT)
        upstream = result['upstream_security']
        self.assertEqual(upstream['schema'], binding.upstream.RESULT_SCHEMA)
        self.assertEqual(upstream['status'], 'KNOWN_AFFECTED_SELECTED_PROFILE')
        self.assertEqual(upstream['selected_identity']['profile_id'], result['selected_profile_id'])
        self.assertEqual(upstream['selected_identity']['guest_image_id'],
                         result['selected_identity']['image_id'])
        self.assertEqual(len(upstream['affected_locked_packages']), 15)
        for path, digest in upstream['source_files_sha256'].items():
            with self.subTest(source=path):
                self.assertEqual(result['source_files_sha256'][path], digest)
        self.assertIs(upstream['actual_w1_exploit_reproduced'], False)
        self.assertIs(upstream['groth16_use_inferred_from_lock_presence'], False)
        self.assertIsNone(upstream['actual_lifetime_failure_bound'])

    def test_missing_security_register_cannot_fall_back_to_historical_binding(self):
        root = self.checkout()
        (root / binding.upstream.DEFAULT_MANIFEST).unlink()
        with self.assertRaisesRegex(binding.SourceReadError, 'missing source'):
            binding.inspect(root)

    def test_omitting_succinct_from_upstream_withdrawal_is_refused(self):
        root = self.checkout()
        register = json.loads((root / binding.upstream.DEFAULT_MANIFEST).read_bytes())
        register['release']['affected_receipt_formats'].remove('succinct')
        self.write(root, binding.upstream.DEFAULT_MANIFEST, register)
        with self.assertRaisesRegex(binding.upstream.UpstreamSecurityError, 'unreviewed upstream policy'):
            binding.inspect(root)

    def test_self_approving_the_historical_profile_cannot_reinstate_it(self):
        root = self.checkout()
        register = json.loads((root / binding.upstream.DEFAULT_MANIFEST).read_bytes())
        register['approved_current_profile_ids'] = [binding.PROFILE]
        self.write(root, binding.upstream.DEFAULT_MANIFEST, register)
        with self.assertRaisesRegex(binding.upstream.UpstreamSecurityError, 'self-promotion'):
            binding.inspect(root)

    def test_cli_preserves_historical_diagnostic_but_refuses_current_use(self):
        root = self.checkout()
        command = [sys.executable, str(ROOT / 'scripts/ci/pq_proof_profile_binding.py'),
                   '--root', str(root)]
        diagnostic = subprocess.run(command, capture_output=True, timeout=15, check=False)
        current = subprocess.run(command + ['--require-current'], capture_output=True,
                                 timeout=15, check=False)
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        self.assertEqual(current.returncode, 2, current.stderr)
        self.assertEqual(diagnostic.stdout, current.stdout)
        self.assertEqual(json.loads(current.stdout)['status'], 'PROFILE_BOUND_UPSTREAM_REVOKED_HOLD')
        refusal = json.loads(current.stderr)
        self.assertEqual(refusal['schema'], binding.RESULT_SCHEMA)
        self.assertEqual(refusal['status'], 'REFUSE')
        self.assertIs(refusal['current_proof_use_eligible'], False)

    def test_native_system_experiment_is_reported_as_not_covering_risc0(self):
        result = binding.inspect(ROOT)
        register = result['system_lifetime_register']
        self.assertEqual(register['profile_id'], binding.NATIVE_PROFILE)
        self.assertEqual(register['unknown_term_count'], 8)
        self.assertIs(register['selected_proof_profile_covered'], False)
        self.assertIs(register['arithmetic_imported'], False)
        self.assertIs(register['source_revision_bound'], False)
        self.assertEqual(result['unregistered_selected_primitive_identities'],
                         ['risc0-3.0.6/Poseidon2/BabyBear'])

    def test_declared_audit_helpers_are_observed_without_changing_profile_identity(self):
        result = binding.inspect(ROOT, expected_profile_descriptor_sha256=
                                 'd915eab9971289b08ed21615058dd26a2b71d878baa027c6896480dc81b13976')
        for row in self.mapping['audit_helpers']:
            self.assertEqual(result['source_files_sha256'][row['path']], row['sha256'])
        self.assertEqual(result['selected_input_observation_count'], len(self.paths))
        self.assertIs(result['native_proof_verification_performed'], False)
        self.assertIsNone(result['actual_lifetime_failure_bound'])

    def test_missing_declared_audit_helper_has_no_fallback(self):
        for row in self.mapping['audit_helpers']:
            with self.subTest(path=row['path']):
                root = self.checkout()
                (root / row['path']).unlink()
                with self.assertRaisesRegex(binding.SourceReadError, 'missing source'):
                    binding.inspect(root)

    def test_changed_declared_audit_helper_is_refused(self):
        for row in self.mapping['audit_helpers']:
            with self.subTest(path=row['path']):
                root = self.checkout()
                path = root / row['path']
                raw = path.read_bytes()
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                with self.assertRaisesRegex(binding.ProfileError, 'source pin differs'):
                    binding.inspect(root)

    def test_incomplete_or_duplicate_audit_helper_roster_is_refused(self):
        omitted = copy.deepcopy(self.mapping)
        omitted['audit_helpers'].pop()
        duplicated = copy.deepcopy(self.mapping)
        duplicated['audit_helpers'][-1] = duplicated['audit_helpers'][0]
        for changed in (omitted, duplicated):
            with self.subTest(paths=[row['path'] for row in changed['audit_helpers']]), \
                    self.assertRaisesRegex(binding.ProfileError, 'audit helper roster differs'):
                self.declarations(mapping=changed)

    def test_p3_goldilocks_and_tagged_sha3_remain_distinct_exclusions(self):
        result = binding.inspect(ROOT)
        profiles = {row['profile_id']: row for row in result['excluded_proof_profiles']}
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles['TRNM-W1-P3-SHA3-512-TAGGED-R1']['shared_primitive_identity'],
                         'FIPS202/SHA3-512')
        self.assertEqual(profiles['TRNM-W1-FULL-PUBLIC-STARK-RESEARCH-P3-0.8.0-R1']
                         ['shared_primitive_identity'], 'poseidon2-goldilocks-p3-0.8.0')
        self.assertTrue(all(row['parameters_or_bound_imported'] is False for row in profiles.values()))

    def test_reused_v1_library_does_not_replace_the_v2_entry_image(self):
        path = 'formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs'
        self.assertEqual(binding.text_constant((ROOT / path).read_bytes(), 'PROFILE_ID'),
                         'trnm-w1-risc0-3.0.6-poseidon2-join-v1')
        result = binding.inspect(ROOT)
        self.assertNotEqual(result['selected_identity']['image_id'][0], 4203990569)
        self.assertEqual(result['selected_profile_id'], binding.PROFILE)

    def test_p3_cannot_replace_selected_profile_label(self):
        changed = copy.deepcopy(self.contract)
        changed['selected_profile_id'] = 'TRNM-W1-P3-SHA3-512-TAGGED-R1'
        with self.assertRaisesRegex(binding.ProfileError, 'unsupported selected'):
            self.declarations(contract=changed)

    def test_foreign_qrom_contract_cannot_replace_selected_mapping(self):
        changed = copy.deepcopy(self.mapping)
        changed['profile_id'] = 'TRNM-W1-P3-SHA3-512-TAGGED-R1'
        with self.assertRaisesRegex(binding.ProfileError, 'mapping profile mismatch'):
            self.declarations(mapping=changed)

    def test_native_register_cannot_be_relabelled_as_selected_budget(self):
        changed = copy.deepcopy(self.contract)
        changed['system_lifetime_register']['profile_id'] = binding.PROFILE
        changed['system_lifetime_register']['relationship'] = 'selected-proof-budget'
        with self.assertRaisesRegex(binding.ProfileError, 'cannot supply'):
            self.declarations(contract=changed)

    def test_jointly_relabelled_system_terms_still_do_not_cover_selected_profile(self):
        changed = copy.deepcopy(self.system)
        changed['experiment']['profile'] = binding.PROFILE
        for row in changed['terms']:
            row['profile'] = binding.PROFILE
        with self.assertRaisesRegex(binding.ProfileError, 'experiment profile mismatch'):
            self.declarations(system=changed)

    def test_arithmetic_example_cannot_be_used_as_research_register(self):
        changed = copy.deepcopy(self.system)
        changed['purpose'] = 'arithmetic-example'
        with self.assertRaisesRegex(binding.ProfileError, 'arithmetic example'):
            self.declarations(system=changed)

    def test_numeric_native_bounds_do_not_become_risc0_bounds(self):
        root = self.checkout()
        changed = copy.deepcopy(self.system)
        for row in changed['terms']:
            row['status'] = 'declared-model-bound'
            row['bound'] = {'numerator': '0', 'denominator': '1'}
            row['theorem'] = {'reference': 'test-only declaration', 'locator': 'test',
                              'applicability': 'Unproved declaration used only to check scope isolation.'}
        self.write(root, binding.lifetime.DEFAULT_MANIFEST, changed)
        result = binding.inspect(root)
        self.assertEqual(result['system_lifetime_register']['unknown_term_count'], 0)
        self.assertIs(result['system_lifetime_register']['arithmetic_imported'], False)
        self.assertIsNone(result['actual_lifetime_failure_bound'])
        self.assertIsNone(result['selected_lifetime_budget']['adaptive_composition_bound'])

    def test_missing_selected_obligation_is_refused(self):
        changed = copy.deepcopy(self.mapping)
        changed['proof_obligations'].remove('latest_theorem_version_equivalence')
        with self.assertRaisesRegex(binding.ProfileError, 'obligations differ'):
            self.declarations(mapping=changed)

    def test_duplicate_selected_obligation_is_refused(self):
        changed = copy.deepcopy(self.mapping)
        changed['proof_obligations'][-1] = changed['proof_obligations'][0]
        with self.assertRaisesRegex(binding.ProfileError, 'obligations differ'):
            self.declarations(mapping=changed)

    def test_selected_numeric_budget_requires_a_separate_reviewed_schema(self):
        changed = copy.deepcopy(self.mapping)
        changed['lifetime_budget']['quantum_queries_lifetime'] = '0'
        with self.assertRaisesRegex(binding.ProfileError, 'promotion schema'):
            self.declarations(mapping=changed)

    def test_mapping_cannot_self_promote(self):
        changed = copy.deepcopy(self.mapping)
        changed['qualification']['post_quantum_soundness_qualified'] = True
        with self.assertRaisesRegex(binding.ProfileError, 'qualification escalation'):
            self.declarations(mapping=changed)

    def test_changed_guest_pin_is_refused(self):
        root = self.checkout()
        path = root / 'formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'
        path.write_bytes(path.read_bytes().replace(b'1958252411', b'1958252412'))
        with self.assertRaisesRegex(binding.ProfileError, 'source pin differs'):
            binding.inspect(root)

    def test_grown_mapping_retains_the_exact_original_byte_bound(self):
        root = self.checkout()
        path = root / binding.MAPPING
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(binding.SourceReadError, 'nonregular/oversize source'):
            binding.inspect(root)

    def test_shrunken_mapping_is_refused_without_a_pin_refresh(self):
        root = self.checkout()
        path = root / binding.MAPPING
        original = path.read_bytes()
        self.assertTrue(original.endswith(b'\n'))
        path.write_bytes(original[:-1])
        with self.assertRaisesRegex(binding.ProfileError, 'source pin differs'):
            binding.inspect(root)

    def test_same_length_mapping_substitution_is_refused(self):
        root = self.checkout()
        path = root / binding.MAPPING
        original = path.read_bytes()
        changed = original.replace(b'Offline research mapping only.',
                                   b'offline research mapping only.', 1)
        self.assertNotEqual(changed, original)
        self.assertEqual(len(changed), len(original))
        path.write_bytes(changed)
        with self.assertRaisesRegex(binding.ProfileError, 'source pin differs'):
            binding.inspect(root)

    def test_expected_v1_guest_cannot_replace_v2_identity(self):
        root = self.checkout()
        changed = copy.deepcopy(self.contract)
        changed['expected_identity']['image_id'][0] = 4203990569
        self.write(root, binding.DEFAULT_MANIFEST, changed)
        with self.assertRaisesRegex(binding.ProfileError, 'parameters differ'):
            binding.inspect(root)

    def test_missing_saved_receipt_has_no_source_or_git_fallback(self):
        root = self.checkout()
        (root / 'evidence/pon-w1-full-v2-20261105/succinct.bin').unlink()
        with self.assertRaisesRegex(binding.SourceReadError, 'missing source'):
            binding.inspect(root)

    def test_excluded_profile_must_keep_its_actual_source_identifier(self):
        root = self.checkout()
        changed = copy.deepcopy(self.contract)
        changed['excluded_profile_sources'][0]['profile_id'] = binding.PROFILE
        self.write(root, binding.DEFAULT_MANIFEST, changed)
        with self.assertRaisesRegex(binding.ProfileError, 'unknown or duplicate excluded'):
            binding.inspect(root)

    def test_paper_metadata_does_not_verify_revision_equivalence(self):
        result = binding.inspect(ROOT)
        theorem = result['theorem_version']
        self.assertEqual(theorem['evaluator_revision'], '2026-01-01')
        self.assertEqual(theorem['official_latest_revision_observed'], '2026-03-02')
        self.assertIs(theorem['version_equivalence_verified'], False)
        root = self.checkout()
        changed = copy.deepcopy(self.contract)
        changed['theorem_reference']['version_equivalence_verified'] = True
        self.write(root, binding.DEFAULT_MANIFEST, changed)
        with self.assertRaisesRegex(binding.ProfileError, 'revision promotion'):
            binding.inspect(root)

    def test_unknown_activation_field_is_refused(self):
        root = self.checkout()
        changed = copy.deepcopy(self.contract)
        changed['production_activation'] = True
        self.write(root, binding.DEFAULT_MANIFEST, changed)
        with self.assertRaisesRegex(binding.ProfileError, 'unexpected or missing fields'):
            binding.inspect(root)

    def test_candidate_can_require_one_exact_profile_descriptor(self):
        first = binding.inspect(ROOT)
        workflow = (ROOT / '.github/workflows/chain-hepta-closure-candidate.yml').read_text()
        pins = re.findall(r'--expected-profile-descriptor-sha256\s+([0-9a-f]{64})', workflow)
        self.assertEqual(pins, [first['selected_profile_descriptor_sha256']])
        bound = binding.inspect(ROOT, expected_profile_descriptor_sha256=
                                pins[0])
        self.assertIs(bound['candidate_profile_identity_matched'], True)
        self.assertIs(bound['whole_chain_pq_qualified'], False)

    def test_wrong_candidate_profile_descriptor_is_refused(self):
        for digest in ('0' * 64,
                       'da0c97f1c549e10ecfc066f6b0a9721147dc3d430eab6f53d502cbc7b91dd48c',
                       '89e80683454b5b5e0152c0454602f0cf631e88ab1da62aaac18a350391fdaf69'):
            with self.subTest(digest=digest), self.assertRaisesRegex(
                    binding.ProfileError, 'candidate proof profile descriptor mismatch'):
                binding.inspect(ROOT, expected_profile_descriptor_sha256=digest)

    def test_boolean_is_not_a_descriptor_digest(self):
        with self.assertRaisesRegex(binding.ProfileError, 'full lowercase SHA-256'):
            binding.inspect(ROOT, expected_profile_descriptor_sha256=True)

    def test_boolean_is_not_an_input_byte_count(self):
        root = self.checkout()
        changed = copy.deepcopy(self.contract)
        changed['mapping_contract']['bytes'] = True
        self.write(root, binding.DEFAULT_MANIFEST, changed)
        with self.assertRaisesRegex(binding.ProfileError, 'invalid source byte limit'):
            binding.inspect(root)

    def test_duplicate_selected_profile_key_is_refused(self):
        root = self.checkout()
        path = root / binding.DEFAULT_MANIFEST
        original = path.read_text()
        path.write_text(original.replace('"selected_profile_id":',
                        '"selected_profile_id": "TRNM-W1-P3-SHA3-512-TAGGED-R1", '
                        '"selected_profile_id":', 1))
        with self.assertRaisesRegex(binding.lifetime.BudgetError, 'duplicate JSON field'):
            binding.inspect(root)

    def test_truncated_recorded_snapshot_has_a_structured_reader_error(self):
        raw = (ROOT / self.mapping['upstream_snapshot']['path']).read_bytes()
        with self.assertRaisesRegex(binding.ProfileError, 'invalid or truncated upstream snapshot'):
            binding.upstream_parameters(raw[:-8], self.mapping['upstream_commit'])


if __name__ == '__main__':
    unittest.main()
