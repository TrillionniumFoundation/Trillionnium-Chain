#!/usr/bin/env python3
"""Retained validator mutants; fixture tests are not repository/domain acceptance."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import check_documentation_contracts_v1 as gate


def load_fixture() -> tuple[dict, dict]:
    data = json.loads((gate.ROOT/gate.REGISTRY).read_text(encoding='utf-8'))
    # Freeze a separate ownership view before mutating the navigation registry.
    # This is intentionally a synthetic unit-test fixture, not a source snapshot.
    coverage = {
        'module_coverage': [{'id': x['id'], 'primary_crates': list(x['primary_crates'])} for x in data['modules']],
        'auxiliary_units': [{'id': x['id'], 'primary_module': x['primary_module']} for x in data['auxiliary_trace']],
    }
    return data, coverage


class RegistryMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.coverage = load_fixture()

    def rejects(self, code: str) -> None:
        with self.assertRaises(gate.DocumentationError) as caught:
            gate.validate_structure(self.data, self.coverage)
        self.assertEqual(caught.exception.code, code)

    def test_positive_navigation_structure(self) -> None:
        gate.validate_structure(self.data, self.coverage)
        self.assertEqual(len(self.data['modules']), 18)
        self.assertEqual(sum(len(x['primary_crates']) for x in self.data['modules']), 62)
        self.assertEqual(sum(len(x['requirement_ids']) for x in self.data['modules']), 90)

    def test_missing_module(self) -> None:
        self.data['modules'].pop()
        self.rejects('DOC-MODULES')

    def test_duplicate_module(self) -> None:
        self.data['modules'][1]['id'] = 'M00'
        self.rejects('DOC-MODULES')

    def test_reordered_modules(self) -> None:
        self.data['modules'].reverse()
        self.rejects('DOC-MODULES')

    def test_unknown_top_level_promotion_field(self) -> None:
        self.data['release_ready'] = True
        self.rejects('DOC-SCHEMA')

    def test_unknown_row_field(self) -> None:
        self.data['modules'][0]['approved'] = True
        self.rejects('DOC-SCHEMA')

    def test_boolean_cannot_be_integer_zero(self) -> None:
        self.data['production_authority'] = 0
        self.rejects('DOC-PROMOTION')

    def test_semantic_promotion(self) -> None:
        self.data['semantic_design_accepted'] = True
        self.rejects('DOC-PROMOTION')

    def test_implementation_promotion(self) -> None:
        self.data['implementation_accepted'] = True
        self.rejects('DOC-PROMOTION')

    def test_profile_activation_claim(self) -> None:
        self.data['profile_status']['ai-v1'] = 'activated'
        self.rejects('DOC-PROFILE')

    def test_unknown_profile_fallback(self) -> None:
        self.data['modules'][8]['profiles'].append('legacy-qc-is-finality')
        self.rejects('DOC-PROFILE')

    def test_frozen_import_repin(self) -> None:
        path = next(iter(self.data['pcc1_v0_imports']))
        self.data['pcc1_v0_imports'][path] = '0'*40
        self.rejects('DOC-IMPORT')

    def test_missing_frozen_import(self) -> None:
        self.data['pcc1_v0_imports'].pop(next(iter(self.data['pcc1_v0_imports'])))
        self.rejects('DOC-IMPORT')

    def test_orphan_crate(self) -> None:
        self.data['modules'][0]['primary_crates'].pop()
        self.rejects('DOC-OWNERSHIP')

    def test_duplicate_crate(self) -> None:
        self.data['modules'][0]['primary_crates'].append(self.data['modules'][0]['primary_crates'][0])
        self.rejects('DOC-DUPLICATE')

    def test_new_coverage_crate_needs_contract_update(self) -> None:
        self.coverage['module_coverage'][0]['primary_crates'].append('trnm-undocumented-unit')
        self.rejects('DOC-OWNERSHIP')

    def test_codeowner_is_not_specialist(self) -> None:
        self.data['modules'][2]['implementation_owner_scope'] = 'independent-reviewer'
        self.rejects('DOC-OWNER-ROLE')

    def test_two_fallback_accounts_cannot_self_certify(self) -> None:
        self.data['independent_review_assignments'] = ['fallback-owner-a', 'fallback-owner-b']
        self.rejects('DOC-SELF-ACCEPTANCE')

    def test_local_accepted_state(self) -> None:
        self.data['modules'][3]['independent_review_status'] = 'accepted'
        self.rejects('DOC-SELF-ACCEPTANCE')

    def test_missing_consensus_expertise(self) -> None:
        self.data['modules'][2]['review_domains'] = ['release-supply-chain']
        self.rejects('DOC-REVIEW-DOMAIN')

    def test_missing_economics_expertise(self) -> None:
        self.data['modules'][12]['review_domains'].remove('economics')
        self.rejects('DOC-REVIEW-DOMAIN')

    def test_missing_storage_expertise(self) -> None:
        self.data['modules'][3]['review_domains'].remove('storage-recovery')
        self.rejects('DOC-REVIEW-DOMAIN')

    def test_missing_cryptography_expertise(self) -> None:
        self.data['modules'][1]['review_domains'].remove('cryptography')
        self.rejects('DOC-REVIEW-DOMAIN')

    def test_generic_security_domain_not_substitute(self) -> None:
        self.data['modules'][0]['review_domains'].append('generic-security-approved')
        self.rejects('DOC-REVIEW-DOMAIN')

    def test_missing_regression_reference(self) -> None:
        self.data['modules'][8]['regression_refs'] = []
        self.rejects('DOC-LIST')

    def test_regression_source_is_not_independent_golden_acceptance(self) -> None:
        self.data['modules'][0]['regression_scope'] = 'independent-golden-accepted'
        self.rejects('DOC-VECTOR-CLAIM')

    def test_missing_requirement(self) -> None:
        self.data['modules'][4]['requirement_ids'].pop()
        self.rejects('DOC-REQUIREMENTS')

    def test_requirement_belongs_to_its_module(self) -> None:
        self.data['modules'][4]['requirement_ids'][0] = 'M03-FRAME'
        self.rejects('DOC-REQUIREMENTS')

    def test_duplicate_requirement(self) -> None:
        self.data['modules'][4]['requirement_ids'].append(self.data['modules'][4]['requirement_ids'][0])
        self.rejects('DOC-DUPLICATE')

    def test_missing_auxiliary(self) -> None:
        self.data['auxiliary_trace'].pop()
        self.rejects('DOC-AUXILIARY')

    def test_wrong_auxiliary_owner(self) -> None:
        self.data['auxiliary_trace'][0]['primary_module'] = 'M17'
        self.rejects('DOC-AUXILIARY')

    def test_disconnected_observed_stack(self) -> None:
        self.data['integration_observation']['stack'][2]['base_ref'] = 'main'
        self.rejects('DOC-LINEAGE')

    def test_child_is_not_selected_successor(self) -> None:
        self.data['integration_observation']['selected_successor_pr'] = 86
        self.rejects('DOC-LINEAGE')

    def test_historical_source_is_not_mutable_current_tip(self) -> None:
        self.data['integration_observation']['current_identity'] = 'use-observed-source-as-current-head'
        self.rejects('DOC-LINEAGE')

    def test_duplicate_json_fields(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            json.loads('{"accepted":false,"accepted":true}', object_pairs_hook=gate.strict_object)


class GuideAndPathMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.data, _ = load_fixture()
        self.guide = (gate.ROOT/gate.GUIDE).read_text(encoding='utf-8')

    def test_positive_guide_index_match(self) -> None:
        gate.validate_guide(self.data, self.guide)

    def test_missing_state_algorithm(self) -> None:
        text = self.guide.replace('**State/admission algorithm.**', '**Overview.**', 1)
        with self.assertRaises(gate.DocumentationError):
            gate.validate_guide(self.data, text)

    def test_deleted_requirement_text(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.validate_guide(self.data, self.guide.replace('`M12-DOUBLE`', '`UNSCOPED`'))

    def test_vote_receipt_lifecycle_laundering(self) -> None:
        with self.assertRaises(gate.DocumentationError) as caught:
            gate.validate_guide(self.data, self.guide.replace('VotePublished', 'OutboundPublished'))
        self.assertEqual(caught.exception.code, 'DOC-LIFECYCLE')

    def test_module_scope_swap(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.validate_guide(self.data, self.guide.replace('`M02-TC`', '`M03-TC`'))

    def test_real_guide_anchor(self) -> None:
        _, path = gate.file_ref(gate.ROOT, gate.GUIDE+'#m08')
        self.assertEqual(path, gate.GUIDE)

    def test_missing_guide_anchor(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.file_ref(gate.ROOT, gate.GUIDE+'#no-such-module')

    def test_missing_file(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.file_ref(gate.ROOT, 'docs/modules/no-such-contract.md')

    def test_directory_is_not_concrete_reference(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.file_ref(gate.ROOT, 'docs/modules')

    def test_parent_path_escape(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.file_ref(gate.ROOT, '../outside.md')

    def test_absolute_path(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.file_ref(gate.ROOT, '/etc/hosts')

    def test_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'source'
            root.mkdir()
            outside = Path(temp)/'outside'
            outside.write_text('fixture only')
            (root/'escape').symlink_to(outside)
            with self.assertRaises(gate.DocumentationError):
                gate.file_ref(root, 'escape')

    def test_exact_blob_and_mutated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'fixture'
            original = b'fixture-only frozen input\n'
            path.write_bytes(original)
            expected = gate.blob_id(original)
            gate.check_pin(path, expected)
            path.write_bytes(original+b'x')
            with self.assertRaises(gate.DocumentationError):
                gate.check_pin(path, expected)


class SourceBindingMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run_git('init', '-q')
        (self.root/'fixture').write_text('synthetic source-identity unit test; not repository evidence\n')
        self.run_git('add', 'fixture')
        self.run_git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')

    def run_git(self, *args: str) -> str:
        return subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True, text=True).stdout.strip()

    def test_clean_identity(self) -> None:
        head, tree = gate.source_identity(self.root)
        self.assertEqual(head, self.run_git('rev-parse', 'HEAD'))
        self.assertEqual(tree, self.run_git('rev-parse', 'HEAD^{tree}'))

    def test_wrong_expected_source(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.source_identity(self.root, '0'*40)

    def test_dirty_tracked_source(self) -> None:
        (self.root/'fixture').write_text('changed')
        with self.assertRaises(gate.DocumentationError):
            gate.source_identity(self.root)

    def test_untracked_source(self) -> None:
        (self.root/'untracked').write_text('untracked')
        with self.assertRaises(gate.DocumentationError):
            gate.source_identity(self.root)


class OperationTraceMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.coverage = load_fixture()

    def rejected(self) -> None:
        with self.assertRaises(gate.DocumentationError):
            gate.validate_structure(self.data, self.coverage)

    def test_missing_operation_trace(self) -> None:
        self.data['modules'][0].pop('operation_trace')
        self.rejected()

    def test_wrong_trace_requirement(self) -> None:
        self.data['modules'][0]['operation_trace']['requirement_id'] = 'M01-KEY'
        self.rejected()

    def test_wrong_trace_profile(self) -> None:
        self.data['modules'][0]['operation_trace']['profile'] = 'automatic-fallback'
        self.rejected()

    def test_trace_is_not_complete_acceptance(self) -> None:
        self.data['modules'][0]['operation_trace']['scope'] = 'all-operations-independently-accepted'
        self.rejected()

    def test_trace_missing_error_meaning(self) -> None:
        self.data['modules'][0]['operation_trace']['error_symbol_or_literal'] = ''
        self.rejected()

    def test_trace_unbound_implementation(self) -> None:
        self.data['modules'][0]['operation_trace']['implementation_path'] = 'elsewhere.rs'
        self.rejected()

    def test_trace_unknown_promotion(self) -> None:
        self.data['modules'][0]['operation_trace']['accepted'] = True
        self.rejected()

    def test_function_mention_is_not_definition(self) -> None:
        self.assertFalse(gate.has_function_definition('// fn claimed();\nlet s = "claimed";', 'claimed'))

    def test_actual_rust_and_python_definitions(self) -> None:
        self.assertTrue(gate.has_function_definition('pub(crate) fn checked<T>() {}', 'checked'))
        self.assertTrue(gate.has_function_definition('    def test_checked(self): pass', 'test_checked'))

    def test_stale_regression_symbol_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'source.rs').write_text('pub fn accepted() {}\nenum Error { Reject }\n')
            (root/'tests.rs').write_text('#[test]\nfn actual_test() {}\n')
            trace = {'implementation_path': 'source.rs', 'implementation_symbol': 'accepted',
                     'error_path': 'source.rs', 'error_symbol_or_literal': 'Error',
                     'regression_path': 'tests.rs', 'regression_symbol': 'actual_test'}
            gate.validate_trace_symbols(root, trace)
            trace['regression_symbol'] = 'invented_test'
            with self.assertRaises(gate.DocumentationError):
                gate.validate_trace_symbols(root, trace)


if __name__ == '__main__':
    unittest.main(verbosity=2)
