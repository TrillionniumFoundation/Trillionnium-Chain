"""Adversarial composition controls; all owners and receipts are test fixtures.

These tests establish deterministic reader behavior, not actual independent
operators, public completeness, native authority, real meters or paid demand.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import grouped_work_composition_v1 as C
import grouped_work_profile_v1 as P
from test_grouped_work_profile_v1 import controlled_fixture, identity, independent_trace


def composition_fixture(*, owners=('A', 'B')):
    """Two reporting owners replay one challenge; consumer use stays one."""
    sources, expected, operations, participants = [], [], set(), set()
    campaign = None
    for index, label in enumerate(owners):
        policy, evidence = controlled_fixture()
        campaign = policy['campaign']
        bindings = {row['id']: identity('participant-' + row['id']) for row in policy['actors']}
        bindings['miner'] = identity('participant-miner-' + label)
        source_id = identity('source-' + str(index))
        participants.update(bindings.values())
        operations.update((bindings[row['actor']], row['id']) for row in policy['operations'])
        sources.append(dict(id=source_id, policy=policy, evidence=evidence,
                            carrier_sha256=identity('carrier-' + str(index))))
        expected.append(dict(id=source_id, owner=bindings['miner'],
            policy_sha256=P.policy_digest(policy),
            actor_owners=[dict(actor=actor, owner=owner) for actor, owner in sorted(bindings.items())]))
    manifest = dict(schema=C.MANIFEST_SCHEMA, campaign=campaign,
        profile=P.PROFILE, denomination=P.DENOMINATION,
        participants=sorted(participants),
        operations=[dict(owner=owner, id=op) for owner, op in sorted(operations)],
        sources=expected)
    collection = dict(schema=C.EVIDENCE_SCHEMA, manifest_sha256=C.manifest_digest(manifest),
                      sources=sources)
    return manifest, collection


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.evidence = composition_fixture()

    def compose(self):
        return C.compose(self.evidence, expected_manifest=self.manifest,
                         expected_manifest_sha256=C.manifest_digest(self.manifest))

    def repin(self, *, replan=False):
        """Deliberately change ONLY synthetic expected declarations in tests."""
        operations = set()
        for expected in self.manifest['sources']:
            matching = [row for row in self.evidence['sources'] if row['id'] == expected['id']]
            if not matching:
                continue
            source = matching[0]
            pin = P.policy_digest(source['policy'])
            expected['policy_sha256'] = source['evidence']['policy_sha256'] = pin
            aliases = {row['actor']: row['owner'] for row in expected['actor_owners']}
            operations.update((aliases[row['actor']], row['id']) for row in source['policy']['operations'])
        if replan:
            self.manifest['operations'] = [dict(owner=owner, id=op) for owner, op in sorted(operations)]
        self.evidence['manifest_sha256'] = C.manifest_digest(self.manifest)

    def same_owner_sources(self):
        self.manifest, self.evidence = composition_fixture(owners=('A', 'A'))

    def test_same_native_inputs_across_two_owners_keep_both_execution_costs(self):
        report = self.compose()
        self.assertEqual(report['observation_status'], 'COMPLETE_DECLARED_COMPOSITION')
        self.assertEqual(report['queries']['unique_declared_execution_events'], 128)
        self.assertEqual(report['queries']['distinct_native_inputs'], 64)
        self.assertEqual(report['queries']['repeated_input_executions'], 64)
        self.assertEqual(report['queries']['native_inputs_by_declared_owner_count'], {'2': 64})
        self.assertEqual(report['queries']['distinct_complete_trace_opportunities'], 1)
        self.assertEqual(report['queries']['source_complete_trace_occurrences'], 2)
        counters = report['resources']['step_counters_by_operation']
        self.assertEqual(sorted(row['total'] for row in counters), [64, 64])
        self.assertNotEqual(counters[0]['operation']['owner'], counters[1]['operation']['owner'])
        self.assertEqual(report['resources']['unique_cost_observations'], 7)
        self.assertEqual(report['demand']['unique_consumer_operations'], 1)
        self.assertIsNone(report['resources']['cross_owner_additive_physical_totals'])

    def test_same_owner_carried_by_two_sources_is_one_execution_and_cost_scope(self):
        self.same_owner_sources()
        report = self.compose()
        self.assertEqual(report['queries']['unique_declared_execution_events'], 64)
        self.assertEqual(report['queries']['event_carrier_replays'], 64)
        self.assertEqual(report['resources']['unique_cost_observations'], 4)
        self.assertEqual(report['resources']['record_carrier_replays'], 4)
        self.assertEqual(report['attempts']['unique_owner_operations'], 2)
        self.assertEqual(report['attempts']['terminal_carrier_replays'], 2)
        self.assertEqual(report['queries']['distinct_complete_trace_opportunities'], 1)

    def test_whole_source_carrier_replay_does_not_reexecute_or_double_assess(self):
        duplicate = copy.deepcopy(self.evidence['sources'][0])
        duplicate['carrier_sha256'] = identity('another-carrier')
        self.evidence['sources'].append(duplicate)
        with patch.object(P, 'assess', wraps=P.assess) as inspect:
            report = self.compose()
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(report['coverage']['source_carrier_replays'], 1)
        self.assertEqual(report['queries']['unique_declared_execution_events'], 128)

    def test_source_id_cannot_be_rebound_to_different_original_evidence(self):
        duplicate = copy.deepcopy(self.evidence['sources'][0])
        duplicate['evidence']['terminals'][0]['receipt_sha256'] = identity('changed-terminal')
        self.evidence['sources'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'SOURCE_ID_REBINDING'):
            self.compose()

    def test_missing_expected_owner_source_and_operation_are_visible(self):
        missing_source = self.evidence['sources'].pop()
        missing_owner = self.manifest['sources'][1]['owner']
        report = self.compose()
        self.assertEqual(report['observation_status'], 'INCOMPLETE')
        self.assertEqual(report['coverage']['missing_sources'], [missing_source['id']])
        self.assertEqual(report['coverage']['missing_reporting_owners'], [missing_owner])
        self.assertEqual(report['coverage']['missing_operations'], [
            dict(owner=missing_owner, id=identity('compute'))])
        self.assertEqual(report['queries']['unique_declared_execution_events'], 64)
        self.assertEqual(report['resources']['unique_cost_observations'], 4)

    def test_missing_all_expected_sources_is_not_vacuously_complete(self):
        self.evidence['sources'] = []
        report = self.compose()
        self.assertEqual(report['observation_status'], 'INCOMPLETE')
        self.assertEqual(report['coverage']['observed_sources'], 0)
        self.assertEqual(len(report['coverage']['missing_operations']), 3)
        self.assertEqual(report['queries']['distinct_native_inputs'], 0)

    def test_missing_operation_cannot_be_removed_with_a_report_summary(self):
        owner = self.manifest['sources'][0]['owner']
        self.manifest['operations'].append(dict(owner=owner, id=identity('missing-operation')))
        self.repin()
        report = self.compose()
        self.assertIn(dict(owner=owner, id=identity('missing-operation')),
                      report['coverage']['missing_operations'])
        self.assertEqual(report['observation_status'], 'INCOMPLETE')

    def test_no_sources_beyond_the_independent_manifest_are_accepted(self):
        self.evidence['sources'][1]['id'] = identity('unlisted-source')
        with self.assertRaisesRegex(ValueError, 'UNEXPECTED_SOURCE'):
            self.compose()

    def test_same_challenge_cannot_be_repriced_under_another_pinned_policy(self):
        source = self.evidence['sources'][1]
        source['policy']['candidates'][0]['target'] = 'fe' * 32
        self.repin()
        # Each local inspector accepts its own externally supplied fixture pin.
        P.assess(source['evidence'], expected_policy=source['policy'],
                 expected_policy_sha256=source['evidence']['policy_sha256'])
        with self.assertRaisesRegex(ValueError, 'NATIVE_CHALLENGE_REBINDING'):
            self.compose()

    def test_same_challenge_cannot_change_task_material_or_authorization_window(self):
        for field in ('task', 'material', 'expires_at'):
            with self.subTest(field=field):
                self.manifest, self.evidence = composition_fixture()
                source = self.evidence['sources'][1]
                value = 999 if field == 'expires_at' else identity('different-' + field)
                source['policy']['candidates'][0][field] = value
                if field != 'expires_at':
                    source['policy']['demands'][0][field] = value
                self.repin()
                with self.assertRaisesRegex(ValueError, 'NATIVE_CHALLENGE_REBINDING'):
                    self.compose()

    def test_changing_a_local_candidate_id_does_not_create_another_opportunity(self):
        self.same_owner_sources()
        source = self.evidence['sources'][1]
        renamed = identity('another-local-candidate-id')
        source['policy']['candidates'][0]['id'] = renamed
        for op in source['policy']['operations']:
            op['candidates'] = [renamed]
        for row in source['evidence']['queries'] + source['evidence']['uses']:
            row['candidate'] = renamed
        self.repin()
        report = self.compose()
        self.assertEqual(report['queries']['unique_declared_execution_events'], 64)
        self.assertEqual(report['queries']['distinct_complete_trace_opportunities'], 1)

    def test_distinct_challenges_are_not_collapsed_by_same_local_candidate_name(self):
        source = self.evidence['sources'][1]
        source['policy']['candidates'][0]['challenge'] = '37' * 32
        for row, trace in zip(source['evidence']['queries'], independent_trace('37' * 32, '27' * 32)):
            row.update(trace)
        old_consume, new_consume = identity('consume'), identity('consume-b')
        source['policy']['operations'][1]['id'] = new_consume
        for row in source['evidence']['terminals']:
            if row['id'] == old_consume:
                row['id'] = new_consume
        for row in source['evidence']['costs']:
            if row['operation'] == old_consume:
                row.update(operation=new_consume, id=identity('consume-b-cost'),
                           coverage=[identity('consume-b-coverage')])
        source['evidence']['uses'][0].update(operation=new_consume, id=identity('consume-b-use'))
        self.repin(replan=True)
        report = self.compose()
        self.assertEqual(report['queries']['distinct_native_inputs'], 128)
        self.assertEqual(report['queries']['distinct_complete_trace_opportunities'], 2)

    def test_same_owner_operation_cannot_change_deadline_between_policy_pins(self):
        self.same_owner_sources()
        self.evidence['sources'][1]['policy']['operations'][0]['deadline'] = 999
        self.repin()
        with self.assertRaisesRegex(ValueError, 'OWNER_OPERATION_REBINDING'):
            self.compose()

    def test_query_event_receipt_cannot_be_rebound_to_another_order(self):
        self.same_owner_sources()
        self.evidence['sources'][1]['evidence']['queries'][0]['at'] = 75
        with self.assertRaisesRegex(ValueError, 'OWNER_QUERY_EVENT_REBINDING'):
            self.compose()

    def test_renaming_events_at_same_owner_operation_coordinate_cannot_add_execution(self):
        self.same_owner_sources()
        for i, row in enumerate(self.evidence['sources'][1]['evidence']['queries']):
            row['id'] = identity('renamed-query-' + str(i))
        with self.assertRaisesRegex(ValueError, 'OWNER_QUERY_COORDINATE_ALIAS'):
            self.compose()

    def test_terminal_receipt_is_immutable_for_same_owner_operation(self):
        self.same_owner_sources()
        self.evidence['sources'][1]['evidence']['terminals'][0]['receipt_sha256'] = identity('new-receipt')
        with self.assertRaisesRegex(ValueError, 'OWNER_TERMINAL_RECEIPT_REBINDING'):
            self.compose()

    def test_new_use_row_id_keeps_one_consumer_operation(self):
        self.evidence['sources'][1]['evidence']['uses'][0]['id'] = identity('renamed-use-event')
        report = self.compose()
        self.assertEqual(report['demand']['unique_consumer_operations'], 1)
        self.assertEqual(report['demand']['observed_use_event_identities'], 2)
        self.assertEqual(report['demand']['operation_replays'], 1)

    def test_consumer_receipt_rebinding_across_owners_is_rejected(self):
        self.evidence['sources'][1]['evidence']['uses'][0]['output_sha256'] = identity('different-output')
        with self.assertRaisesRegex(ValueError, 'OWNER_USE_EVENT_REBINDING'):
            self.compose()

    def test_cost_receipt_rebinding_cannot_change_same_owner_charge(self):
        self.same_owner_sources()
        self.evidence['sources'][1]['evidence']['costs'][0]['receipt_sha256'] = identity('new-meter-receipt')
        with self.assertRaisesRegex(ValueError, 'OWNER_COST_RECEIPT_REBINDING'):
            self.compose()

    def test_two_partial_owner_traces_can_supply_one_complete_native_chain(self):
        for i, source in enumerate(self.evidence['sources']):
            source['evidence']['queries'] = source['evidence']['queries'][32 * i:32 * (i + 1)]
            source['evidence']['costs'][0]['amount'] = 32
        report = self.compose()
        self.assertEqual(report['observation_status'], 'COMPLETE_DECLARED_COMPOSITION')
        self.assertEqual(report['queries']['source_complete_trace_occurrences'], 0)
        self.assertEqual(report['queries']['distinct_complete_trace_opportunities'], 1)
        self.assertEqual(report['queries']['distinct_native_inputs'], 64)
        self.assertEqual(len(report['queries']['complete_seal_traces'][0]['contributing_owner_namespaces']), 2)
        self.assertFalse(report['coverage']['global_inter_owner_order_established'])

    def test_disjoint_partial_reports_cannot_reuse_one_insufficient_owner_counter(self):
        self.same_owner_sources()
        for i, source in enumerate(self.evidence['sources']):
            source['evidence']['queries'] = source['evidence']['queries'][32 * i:32 * (i + 1)]
            source['evidence']['costs'][0]['amount'] = 32
            local = P.assess(source['evidence'], expected_policy=source['policy'],
                             expected_policy_sha256=source['evidence']['policy_sha256'])
            self.assertEqual(local['observation_status'], 'COMPLETE_DECLARED_PLAN')
        with self.assertRaisesRegex(ValueError, 'COMPOSED_OPERATION_QUERY_UNDERCHARGE'):
            self.compose()

    def test_cross_source_cost_children_must_together_fit_one_owner_aggregate(self):
        self.same_owner_sources()
        atoms = [identity('cpu-A'), identity('cpu-B')]
        for index, source in enumerate(self.evidence['sources']):
            parent = source['evidence']['costs'][1]
            parent['coverage'] = atoms.copy()
            child = copy.deepcopy(parent)
            child.update(id=identity('cpu-child-' + str(index)), amount=1000,
                         coverage=[atoms[index]], included_in=parent['id'])
            source['evidence']['costs'].append(child)
            P.assess(source['evidence'], expected_policy=source['policy'],
                     expected_policy_sha256=source['evidence']['policy_sha256'])
        with self.assertRaisesRegex(ValueError, 'COMPOSED_COST_DESCENDANTS_EXCEED_BOUND'):
            self.compose()

    def test_renamed_owner_root_cost_cannot_double_charge_same_declared_atoms(self):
        self.same_owner_sources()
        self.evidence['sources'][1]['evidence']['costs'][0]['id'] = identity('renamed-cost')
        with self.assertRaisesRegex(ValueError, 'COMPOSED_OWNER_RESOURCE_OVERLAP'):
            self.compose()

    def test_owner_cost_hidden_in_another_owner_aggregate_cannot_reappear_as_root(self):
        first, second = self.evidence['sources']
        parent = first['evidence']['costs'][1]
        child = copy.deepcopy(parent)
        child.update(id=identity('consumer-included-cpu'), operation=identity('consume'),
                     stage='consume', amount=50, included_in=parent['id'], meter='consumer')
        first['evidence']['costs'] = [row for row in first['evidence']['costs']
                                      if row['stage'] != 'consume'] + [child]
        second['evidence']['costs'][1]['coverage'] = [identity('separate-B-cpu')]
        second['evidence']['costs'][3]['coverage'] = parent['coverage'].copy()
        for source in (first, second):
            result = P.assess(source['evidence'], expected_policy=source['policy'],
                              expected_policy_sha256=source['evidence']['policy_sha256'])
            self.assertEqual(result['observation_status'], 'COMPLETE_DECLARED_PLAN')
        with self.assertRaisesRegex(ValueError, 'COMPOSED_OWNER_RESOURCE_OVERLAP'):
            self.compose()

    def test_same_owner_atom_may_repeat_as_explicit_nested_diagnostics(self):
        self.same_owner_sources()
        parent = self.evidence['sources'][0]['evidence']['costs'][1]
        for index, source in enumerate(self.evidence['sources']):
            middle = copy.deepcopy(parent)
            middle.update(id=identity('shared-cpu-middle'), amount=1000, included_in=parent['id'])
            source['evidence']['costs'].append(middle)
            if index == 1:
                leaf = copy.deepcopy(middle)
                leaf.update(id=identity('deep-cpu-diagnostic'), amount=500, included_in=middle['id'])
                source['evidence']['costs'].append(leaf)
        report = self.compose()
        self.assertEqual(report['observation_status'], 'COMPLETE_DECLARED_COMPOSITION')
        self.assertEqual(report['resources']['unique_cost_observations'], 6)
        self.assertEqual(len(report['resources']['declared_root_observations']), 4)

    def test_unknown_machine_costs_and_failed_operations_are_retained(self):
        for source in self.evidence['sources']:
            source['evidence']['costs'][1].update(amount=None, upper_bound=2000, payer=None)
            source['evidence']['terminals'][0]['outcome'] = 'unknown'
        report = self.compose()
        self.assertEqual(report['observation_status'], 'INCOMPLETE')
        unknown = [row for row in report['resources']['observations'] if row['amount'] is None]
        self.assertEqual(len(unknown), 2)
        self.assertTrue(all(row['upper_bound'] == 2000 and row['payer'] is None for row in unknown))
        self.assertEqual(report['attempts']['outcomes']['unknown'], 2)
        self.assertEqual(report['queries']['unique_declared_execution_events'], 128)

    def test_declared_preprocessing_and_verifier_roles_do_not_authenticate_public_coverage(self):
        for source, role in zip(self.evidence['sources'], ('preprocessing', 'verifier')):
            source['policy']['operations'][0]['role'] = role
        self.repin()
        report = self.compose()
        self.assertEqual(report['queries']['events_by_declared_role'], {'preprocessing': 64, 'verifier': 64})
        self.assertEqual(report['observation_status'], 'COMPLETE_DECLARED_COMPOSITION')
        self.assertFalse(report['coverage']['public_coverage_complete'])
        self.assertFalse(report['coverage']['undeclared_owner_or_role_absence_established'])
        self.assertFalse(report['coverage']['independent_owner_control_established'])
        self.assertIsNone(report['coverage']['public_query_total'])
        self.assertIsNone(report['coverage']['coalition_query_total'])
        self.assertEqual(report['qualification'], 'HOLD')
        self.assertEqual(report['actual_chainwork'], 0)
        self.assertFalse(report['consensus_weight_eligible'])
        self.assertFalse(report['physical_resource_lower_bound_proved'])
        self.assertFalse(report['fresh_neural_mac_floor_proved'])
        self.assertFalse(report['production_activation'])

    def test_every_local_actor_needs_an_independently_pinned_namespace_binding(self):
        self.manifest['sources'][1]['actor_owners'].pop()
        self.evidence['manifest_sha256'] = C.manifest_digest(self.manifest)
        with self.assertRaisesRegex(ValueError, 'SOURCE_ACTOR_NAMESPACE_COVERAGE'):
            self.compose()

    def test_namespace_fields_reject_non_string_or_unknown_owners(self):
        for value in ({'forged': 'owner'}, identity('unlisted-owner')):
            with self.subTest(value=value):
                self.manifest, self.evidence = composition_fixture()
                self.manifest['sources'][0]['owner'] = value
                self.evidence['manifest_sha256'] = C.manifest_digest(self.manifest)
                with self.assertRaisesRegex(ValueError, 'EXPECTED_SOURCE_OWNER'):
                    self.compose()

    def test_original_evidence_is_required_instead_of_a_summary(self):
        source = self.evidence['sources'][0]
        source['evidence'] = P.assess(source['evidence'], expected_policy=source['policy'],
                                    expected_policy_sha256=source['evidence']['policy_sha256'])
        # A report contains booleans and is not accepted as observation input.
        with self.assertRaises(ValueError):
            self.compose()

    def test_aggregate_record_limit_is_enforced_before_any_per_source_assessment(self):
        with patch.object(C, 'MAX_TOTAL_RECORDS', 20), patch.object(P, 'assess') as inspect:
            with self.assertRaisesRegex(ValueError, 'COMPOSITION_RECORDS'):
                self.compose()
        inspect.assert_not_called()

    def test_aggregate_byte_limit_is_not_multiplied_by_source_count(self):
        with patch.object(C, 'MAX_BYTES', 1000), patch.object(P, 'assess') as inspect:
            with self.assertRaisesRegex(ValueError, 'COMPOSITION_BYTES'):
                self.compose()
        inspect.assert_not_called()

    def test_source_count_limit_applies_even_to_duplicate_carriers(self):
        self.evidence['sources'] = [copy.deepcopy(self.evidence['sources'][0])
                                    for _ in range(C.MAX_SOURCES + 1)]
        with self.assertRaisesRegex(ValueError, 'SOURCE_ROWS'):
            self.compose()

    def test_collection_cannot_replace_its_independent_manifest_pin(self):
        self.evidence['manifest_sha256'] = identity('different-pin')
        with self.assertRaisesRegex(ValueError, 'COMPOSITION_MANIFEST_SUBSTITUTION'):
            self.compose()

    def test_input_cannot_enable_weight_with_a_self_attestation_field(self):
        self.evidence['public_coverage_complete'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'COMPOSITION_FIELDS'):
            self.compose()

    def test_composition_does_not_mutate_original_source_evidence(self):
        before = copy.deepcopy((self.manifest, self.evidence))
        self.compose()
        self.assertEqual((self.manifest, self.evidence), before)

    def test_cli_is_read_only_and_requires_the_external_manifest_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, evidence = root / 'manifest.json', root / 'evidence.json'
            manifest.write_text(json.dumps(self.manifest))
            evidence.write_text(json.dumps(self.evidence))
            before = manifest.read_bytes(), evidence.read_bytes()
            result = subprocess.run([sys.executable, str(Path(C.__file__)),
                '--evidence', str(evidence), '--expected-manifest', str(manifest),
                '--expected-manifest-sha256', C.manifest_digest(self.manifest)],
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['qualification'], 'HOLD')
            self.assertEqual(report['queries']['distinct_native_inputs'], 64)
            self.assertEqual((manifest.read_bytes(), evidence.read_bytes()), before)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ['evidence.json', 'manifest.json'])


if __name__ == '__main__':
    unittest.main()
