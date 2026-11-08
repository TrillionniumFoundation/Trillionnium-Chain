"""Adversarial controls for the observational grouped profile contract.

All actors, demands, receipts and meters below are explicitly synthetic fixtures.
The SHA-256 inputs are independently framed; passing these tests grants no
public-network, independent-customer or consensus qualification.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import grouped_work_profile_v1 as P


def identity(label):
    return hashlib.sha256(label.encode()).hexdigest()


def independent_hash(tag, fields):
    raw = b'TRNM-GROUPED-FRESH-SEAL0\0' + len(tag).to_bytes(2, 'big') + tag
    for field in fields:
        raw += len(field).to_bytes(4, 'big') + field
    return hashlib.sha256(raw).digest()


def independent_trace(challenge, statement):
    profile = independent_hash(b'profile', [
        b'pon-grouped-int257-sealed-research-v0',
        b'pon-routed-int257-grouped-research-v0',
        b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', b'\x00\x40', b'\x00\x10'])
    state = independent_hash(b'seed', [profile, bytes.fromhex(challenge), bytes.fromhex(statement)])
    result = []
    for index in range(1, 65):
        predecessor = state
        state = independent_hash(b'step', [profile, bytes.fromhex(challenge),
                                          index.to_bytes(2, 'big'), predecessor])
        result.append(dict(index=index, predecessor=predecessor.hex(), answer=state.hex()))
    return result


def controlled_fixture():
    """Reusable schema example; explicitly no genuine demand or signed meters."""
    c, task, material = map(identity, ('candidate', 'task', 'cached-material'))
    compute, consume, demand = map(identity, ('compute', 'consume', 'demand'))
    policy = dict(schema=P.POLICY_SCHEMA, campaign=identity('controlled-campaign'),
        profile=P.PROFILE, denomination=P.DENOMINATION,
        actors=[dict(id=name, control_group=group) for name, group in (
            ('miner', 'miner-group'), ('verifier', 'verifier-group'),
            ('requester', 'customer-group'), ('consumer', 'customer-group'),
            ('task-owner', 'issuer-group'), ('target-owner', 'issuer-group'))],
        candidates=[dict(id=c, task=task, material=material, challenge='13' * 32,
            statement='27' * 32, target='ff' * 32, task_authority='task-owner',
            target_authority='target-owner', authorized_at=1, expires_at=1000)],
        demands=[dict(id=demand, task=task, material=material, requester='requester',
            consumer='consumer', authorized_at=1, expires_at=1000)],
        operations=[dict(id=compute, actor='miner', role='producer', candidates=[c],
            authorized_at=2, deadline=1000, required_costs=[
                dict(stage='seal', unit='step_query'), dict(stage='cpu', unit='cpu_ns'),
                dict(stage='relation', unit='business_mac')]),
            dict(id=consume, actor='consumer', role='consumer', candidates=[c],
                 authorized_at=2, deadline=1000,
                 required_costs=[dict(stage='consume', unit='cpu_ns')])])
    queries = [dict(id=identity('query-' + str(i)), operation=compute, candidate=c,
        at=10 + i, carrier_sha256=identity('trace-carrier'), **row)
        for i, row in enumerate(independent_trace('13' * 32, '27' * 32), 1)]
    costs = []
    for label, operation, stage, unit, amount, payer in (
            ('seal', compute, 'seal', 'step_query', 64, 'miner'),
            ('cpu', compute, 'cpu', 'cpu_ns', 1500, 'miner'),
            ('cached-relation', compute, 'relation', 'business_mac', 0, 'miner'),
            ('consume', consume, 'consume', 'cpu_ns', 50, 'consumer')):
        costs.append(dict(id=identity('cost-' + label), operation=operation,
            stage=stage, unit=unit, amount=amount, upper_bound=None,
            meter=payer, payer=payer, beneficiary=payer, receipt_sha256=identity('meter-' + label),
            coverage=[identity('coverage-' + label)], included_in=None,
            carrier_sha256=identity('cost-carrier')))
    evidence = dict(schema=P.EVIDENCE_SCHEMA, policy_sha256=P.policy_digest(policy),
        queries=queries, costs=costs,
        terminals=[dict(id=operation, at=at, outcome='completed',
            receipt_sha256=identity('terminal-' + operation),
            carrier_sha256=identity('terminal-carrier'))
            for operation, at in ((compute, 90), (consume, 110))],
        uses=[dict(id=identity('consumer-effect-operation'), operation=consume,
            candidate=c, demand=demand, at=100, output_sha256=identity('output'),
            receipt_sha256=identity('consumer-receipt'), carrier_sha256=identity('use-carrier'))])
    return policy, evidence


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.evidence = controlled_fixture()
        self.pin = self.evidence['policy_sha256']

    def assess(self):
        return P.assess(self.evidence, expected_policy=self.policy,
                        expected_policy_sha256=self.pin)

    def repin_controlled_plan(self):
        # Only test code deliberately creates a different expected fixture.
        self.pin = self.evidence['policy_sha256'] = P.policy_digest(self.policy)

    def test_exact_64_step_trace_is_not_neural_work_or_actual_chainwork(self):
        report = self.assess()
        self.assertEqual(report['observation_status'], 'COMPLETE_DECLARED_PLAN')
        self.assertEqual(report['denomination'], 'classical-seal-step-oracle-query')
        self.assertEqual(report['queries']['distinct_native_inputs'], 64)
        chain = report['queries']['complete_seal_traces'][0]
        self.assertEqual(chain['endpoint'], self.evidence['queries'][-1]['answer'])
        self.assertTrue(chain['target_hit'])
        self.assertEqual(chain['hypothetical_award_per_hit'], '64')
        self.assertEqual(report['resources']['totals_by_unit']['business_mac']['total'], 0)
        self.assertEqual(report['qualification'], 'HOLD')
        self.assertEqual(report['actual_chainwork'], 0)
        self.assertIsNone(report['queries']['public_query_total'])
        self.assertIsNone(report['queries']['coalition_query_total'])
        self.assertFalse(report['fresh_neural_mac_floor_proved'])
        self.assertFalse(report['physical_resource_lower_bound_proved'])
        self.assertFalse(report['demand']['genuine_independent_demand_established'])

    def test_new_carrier_cannot_duplicate_query_or_cost_events(self):
        for field in ('queries', 'costs', 'uses', 'terminals'):
            replay = copy.deepcopy(self.evidence[field][0])
            replay['carrier_sha256'] = identity('new-wrapper-' + field)
            self.evidence[field].append(replay)
        report = self.assess()
        self.assertEqual(report['queries']['observed_execution_events'], 64)
        self.assertEqual(report['queries']['carrier_replays'], 1)
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)
        self.assertEqual(report['resources']['carrier_replays'], 1)
        self.assertEqual(report['demand']['observed_consumer_operation_references'], 1)
        self.assertEqual(report['attempts']['observed_terminals'], 2)

    def test_real_repeated_execution_costs_more_without_new_distinct_input(self):
        repeated = copy.deepcopy(self.evidence['queries'][0])
        repeated.update(id=identity('new-execution'), at=85)
        self.evidence['queries'].append(repeated)
        self.evidence['costs'][0]['amount'] = 65
        report = self.assess()
        self.assertEqual(report['queries']['observed_execution_events'], 65)
        self.assertEqual(report['queries']['distinct_native_inputs'], 64)
        self.assertEqual(report['queries']['repeated_input_executions'], 1)
        self.assertEqual(report['resources']['totals_by_unit']['step_query']['total'], 65)

    def test_event_identity_rebinding_rejected(self):
        row = copy.deepcopy(self.evidence['queries'][0])
        row['at'] += 1
        self.evidence['queries'].append(row)
        with self.assertRaisesRegex(ValueError, 'QUERY_ID_REBINDING'):
            self.assess()

    def test_target_rebinding_cannot_replace_external_pin(self):
        self.policy['candidates'][0]['target'] = '00' * 31 + '01'
        # Updating both downloaded objects still cannot replace the caller's pin.
        self.evidence['policy_sha256'] = P.policy_digest(self.policy)
        with self.assertRaisesRegex(ValueError, 'EXPECTED_POLICY_PIN'):
            self.assess()

    def test_evidence_cannot_substitute_another_expected_policy_digest(self):
        self.evidence['policy_sha256'] = identity('attacker-policy')
        with self.assertRaisesRegex(ValueError, 'EVIDENCE_POLICY_SUBSTITUTION'):
            self.assess()

    def test_even_speculative_final_probe_requires_prior_authorization(self):
        self.evidence['queries'][-1]['at'] = 1
        with self.assertRaisesRegex(ValueError, 'AUTHORIZATION_AFTER_QUERY'):
            self.assess()

    def test_same_challenge_cannot_be_repriced_as_another_candidate(self):
        other = copy.deepcopy(self.policy['candidates'][0])
        other.update(id=identity('relabelled-candidate'), target='00' * 31 + '01')
        self.policy['candidates'].append(other)
        self.repin_controlled_plan()
        with self.assertRaisesRegex(ValueError, 'CHALLENGE_ALIAS'):
            self.assess()

    def test_wrong_step_hash_and_ambiguous_order_rejected(self):
        original = copy.deepcopy(self.evidence)
        self.evidence['queries'][0]['answer'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'QUERY_HASH_MISMATCH'):
            self.assess()
        self.evidence = original
        self.evidence['queries'][1]['at'] = self.evidence['queries'][0]['at']
        with self.assertRaisesRegex(ValueError, 'AMBIGUOUS_QUERY_ORDER'):
            self.assess()

    def test_partial_or_counter_only_evidence_does_not_invent_observed_queries(self):
        self.evidence['queries'] = []
        report = self.assess()
        self.assertEqual(report['queries']['observed_execution_events'], 0)
        self.assertEqual(report['queries']['complete_seal_traces'], [])
        self.assertEqual(report['resources']['totals_by_unit']['step_query']['total'], 64)
        self.assertIn('STEP_COUNTERS_WITHOUT_EXACT_QUERY_TRACE_COVERAGE', report['local_issues'])

    def test_delegated_and_verifier_work_stay_in_their_payer_scopes(self):
        verifier = copy.deepcopy(self.policy['operations'][0])
        verifier.update(id=identity('verifier-operation'), actor='verifier', role='verifier')
        self.policy['operations'].append(verifier)
        self.policy['operations'][0]['role'] = 'delegate'
        self.repin_controlled_plan()
        for row in list(self.evidence['queries']):
            other = copy.deepcopy(row)
            other.update(id=identity('verifier-' + row['id']), operation=verifier['id'], at=row['at'] + 200)
            self.evidence['queries'].append(other)
        for row in list(self.evidence['costs'][:3]):
            other = copy.deepcopy(row)
            other.update(id=identity('verifier-' + row['id']), operation=verifier['id'],
                meter='verifier', payer='verifier', beneficiary='miner', coverage=[identity('verifier-' + row['coverage'][0])])
            self.evidence['costs'].append(other)
        self.evidence['terminals'].append(dict(id=verifier['id'], at=290,
            outcome='rejected', receipt_sha256=identity('verifier-terminal'),
            carrier_sha256=identity('verifier-carrier')))
        report = self.assess()
        self.assertEqual(report['queries']['events_by_declared_role'], {'delegate': 64, 'verifier': 64})
        self.assertEqual(report['queries']['distinct_native_inputs'], 64)
        self.assertEqual(report['resources']['totals_by_unit']['step_query']['total'], 128)
        subsidy = [r for r in report['resources']['transfers'] if r['role'] == 'verifier']
        self.assertTrue(all(r['payer'] == 'verifier' and r['beneficiary'] == 'miner' for r in subsidy))
        self.assertEqual(report['attempts']['outcomes']['rejected'], 1)

    def test_missing_terminal_and_failed_attempt_costs_remain(self):
        self.evidence['terminals'].pop()
        self.evidence['terminals'][0]['outcome'] = 'canceled'
        report = self.assess()
        self.assertEqual(report['attempts']['planned'], 2)
        self.assertEqual(report['attempts']['missing_terminals'], 1)
        self.assertEqual(report['attempts']['outcomes'], {'canceled': 1})
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)
        self.assertTrue(any(i.startswith('OPERATION_TERMINAL_MISSING:') for i in report['local_issues']))

    def test_unknown_started_work_retains_upper_bound_not_a_zero(self):
        self.evidence['terminals'][0]['outcome'] = 'unknown'
        self.evidence['costs'][0].update(amount=None, upper_bound=64)
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['step_query'],
                         dict(known=0, total=None, upper_bound=64, unknown_records=1,
                              missing_required_records=0))
        self.assertTrue(any(i.startswith('OPERATION_TERMINAL_UNKNOWN:') for i in report['local_issues']))

    def test_missing_cost_does_not_silently_become_zero(self):
        del self.evidence['costs'][0]
        report = self.assess()
        missing = report['resources']['totals_by_unit']['step_query']
        self.assertIsNone(missing['total'])
        self.assertIsNone(missing['upper_bound'])
        self.assertEqual(missing['missing_required_records'], 1)
        self.assertTrue(any(i.startswith('COST_REQUIRED_MISSING:') for i in report['local_issues']))
        self.assertTrue(any(i.startswith('QUERY_COST_MISSING:') for i in report['local_issues']))

    def test_retained_queries_cannot_exceed_recorded_complete_cost(self):
        self.evidence['costs'][0]['amount'] = 63
        with self.assertRaisesRegex(ValueError, 'QUERY_COUNT_EXCEEDS_REPORTED_COST'):
            self.assess()

    def test_other_verifier_budget_cannot_mask_zero_producer_charge(self):
        verifier = copy.deepcopy(self.policy['operations'][0])
        verifier.update(id=identity('counter-only-verifier'), actor='verifier', role='verifier',
                        required_costs=[dict(stage='seal', unit='step_query')])
        self.policy['operations'].append(verifier)
        self.repin_controlled_plan()
        charge = copy.deepcopy(self.evidence['costs'][0])
        charge.update(id=identity('verifier-counter'), operation=verifier['id'],
            meter='verifier', payer='verifier', beneficiary='miner',
            coverage=[identity('other-verifier-coverage')])
        self.evidence['costs'].append(charge)
        self.evidence['costs'][0]['amount'] = 0
        # Aggregate counters are still 64. Only per-operation reconciliation
        # catches the attempt to pay the producer's transcript with this meter.
        with self.assertRaisesRegex(ValueError, 'OPERATION_QUERY_COUNT_EXCEEDS_REPORTED_COST'):
            self.assess()

    def test_step_counter_subset_cannot_increase_operation_allowance(self):
        root = self.evidence['costs'][0]
        subset = copy.deepcopy(root)
        subset.update(id=identity('step-subset'), included_in=root['id'])
        self.evidence['costs'].append(subset)
        report = self.assess()
        counter = report['resources']['step_counters_by_operation'][root['operation']]
        self.assertEqual(counter['total'], 64)
        repeated = copy.deepcopy(self.evidence['queries'][0])
        repeated.update(id=identity('unpaid-extra-query'), at=85)
        self.evidence['queries'].append(repeated)
        with self.assertRaisesRegex(ValueError, 'OPERATION_QUERY_COUNT_EXCEEDS_REPORTED_COST'):
            self.assess()

    def test_aggregate_and_subset_are_not_added_twice(self):
        parent = self.evidence['costs'][1]
        subset = copy.deepcopy(parent)
        subset.update(id=identity('cpu-subset'), amount=500, included_in=parent['id'])
        self.evidence['costs'].append(subset)
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)
        self.assertEqual(report['resources']['included_subset_records'], 1)

    def test_overlapping_independent_charges_are_rejected(self):
        doubled = copy.deepcopy(self.evidence['costs'][1])
        doubled['id'] = identity('renamed-double-charge')
        self.evidence['costs'].append(doubled)
        with self.assertRaisesRegex(ValueError, 'OVERLAPPING_RESOURCE_CHARGE'):
            self.assess()

    def test_cost_subset_cycle_and_out_of_range_rejected(self):
        parent = self.evidence['costs'][1]
        subset = copy.deepcopy(parent)
        subset.update(id=identity('cpu-cycle'), included_in=parent['id'])
        parent['included_in'] = subset['id']
        self.evidence['costs'].append(subset)
        with self.assertRaisesRegex(ValueError, 'COST_CYCLE'):
            self.assess()
        parent['included_in'] = None
        subset['amount'] = parent['amount'] + 1
        with self.assertRaisesRegex(ValueError, 'COST_SUBSET_EXCEEDS_PARENT'):
            self.assess()

    def test_disjoint_children_must_fit_aggregate_cost(self):
        parent = self.evidence['costs'][1]
        parent['coverage'] = [identity('cpu-region-A'), identity('cpu-region-B')]
        for atom in parent['coverage']:
            child = copy.deepcopy(parent)
            child.update(id=identity('child-' + atom), amount=1000,
                         coverage=[atom], included_in=parent['id'])
            self.evidence['costs'].append(child)
        with self.assertRaisesRegex(ValueError, 'COST_DESCENDANTS_EXCEED_BOUND'):
            self.assess()

    def test_known_descendant_must_fit_unknown_parent_upper_bound(self):
        parent = self.evidence['costs'][1]
        parent.update(amount=None, upper_bound=1000)
        middle = copy.deepcopy(parent)
        middle.update(id=identity('unknown-middle'), upper_bound=None, included_in=parent['id'])
        child = copy.deepcopy(middle)
        child.update(id=identity('known-child'), amount=1500, included_in=middle['id'])
        self.evidence['costs'].extend([middle, child])
        with self.assertRaisesRegex(ValueError, 'COST_DESCENDANTS_EXCEED_BOUND'):
            self.assess()

    def test_known_subset_survives_unknown_aggregate_without_becoming_total(self):
        parent = self.evidence['costs'][1]
        parent.update(amount=None, upper_bound=2000)
        child = copy.deepcopy(parent)
        child.update(id=identity('known-child'), amount=1500,
                     upper_bound=None, included_in=parent['id'])
        self.evidence['costs'].append(child)
        cpu = self.assess()['resources']['totals_by_unit']['cpu_ns']
        self.assertEqual(cpu['known'], 1550)
        self.assertIsNone(cpu['total'])
        self.assertEqual(cpu['upper_bound'], 2050)

    def test_overlapping_diagnostics_require_explicit_nesting(self):
        parent = self.evidence['costs'][1]
        for name in ('phase', 'native-subset'):
            child = copy.deepcopy(parent)
            child.update(id=identity(name), amount=500, included_in=parent['id'])
            self.evidence['costs'].append(child)
        with self.assertRaisesRegex(ValueError, 'COST_AMBIGUOUS_SUBSET_OVERLAP'):
            self.assess()
        self.evidence['costs'][-1]['included_in'] = self.evidence['costs'][-2]['id']
        self.assertEqual(self.assess()['resources']['totals_by_unit']['cpu_ns']['total'], 1550)

    def test_unknown_payer_and_beneficiary_are_not_attributed_to_miner(self):
        self.evidence['costs'][1].update(payer=None, beneficiary=None)
        report = self.assess()
        self.assertTrue(any(i.startswith('COST_PAYER_UNKNOWN:') for i in report['local_issues']))
        transfer = next(r for r in report['resources']['transfers'] if r['cost'] == identity('cost-cpu'))
        self.assertIsNone(transfer['payer'])
        self.assertIsNone(transfer['beneficiary'])
        self.assertEqual(transfer['executor'], 'miner')

    def test_known_transfer_identity_cannot_cross_unknown_ancestors(self):
        original = copy.deepcopy(self.evidence)
        for field in ('payer', 'beneficiary'):
            for depth in (1, 3):
                with self.subTest(field=field, unknown_depth=depth):
                    self.evidence = copy.deepcopy(original)
                    root = self.evidence['costs'][1]
                    parent = root
                    for index in range(depth):
                        middle = copy.deepcopy(root)
                        middle.update(id=identity(f'unknown-{field}-{index}'),
                                      amount=1000, included_in=parent['id'])
                        middle[field] = None
                        self.evidence['costs'].append(middle)
                        parent = middle
                    leaf = copy.deepcopy(root)
                    leaf.update(id=identity('conflicting-transfer-leaf'), amount=500,
                                included_in=parent['id'])
                    leaf[field] = 'consumer'
                    self.evidence['costs'].append(leaf)
                    # Evidence order must not determine which ancestor binds.
                    self.evidence['costs'].reverse()
                    with self.assertRaisesRegex(ValueError, 'COST_SUBSET_TRANSFER_CONFLICT'):
                        self.assess()

    def test_consistent_ancestor_does_not_fill_unknown_transfer_observation(self):
        root = self.evidence['costs'][1]
        middle = copy.deepcopy(root)
        middle.update(id=identity('unknown-transfer-middle'), amount=1000,
                      included_in=root['id'], payer=None, beneficiary=None)
        leaf = copy.deepcopy(root)
        leaf.update(id=identity('consistent-transfer-leaf'), amount=500,
                    included_in=middle['id'])
        self.evidence['costs'].extend([middle, leaf])
        before = copy.deepcopy(self.evidence)
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)
        self.assertEqual(report['observation_status'], 'INCOMPLETE')
        for field in ('PAYER', 'BENEFICIARY'):
            self.assertIn('COST_' + field + '_UNKNOWN:' + middle['id'], report['local_issues'])
        self.assertEqual(self.evidence, before)

    def test_unknown_root_preserves_distinct_disjoint_transfer_branches(self):
        root = self.evidence['costs'][1]
        root.update(payer=None, beneficiary=None,
                    coverage=[identity('transfer-branch-A'), identity('transfer-branch-B')])
        for atom, owner in zip(root['coverage'], ('miner', 'consumer')):
            child = copy.deepcopy(root)
            child.update(id=identity('transfer-child-' + atom), amount=500,
                         coverage=[atom], included_in=root['id'],
                         payer=owner, beneficiary=owner)
            self.evidence['costs'].append(child)
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)
        transfer = next(row for row in report['resources']['transfers'] if row['cost'] == root['id'])
        self.assertIsNone(transfer['payer'])
        self.assertIsNone(transfer['beneficiary'])
        self.assertEqual(report['qualification'], 'HOLD')

    def test_nonroot_known_transfer_identity_binds_its_own_descendants(self):
        root = self.evidence['costs'][1]
        root.update(payer=None, beneficiary=None)
        known = copy.deepcopy(root)
        known.update(id=identity('known-nonroot-transfer'), amount=1000,
                     included_in=root['id'], payer='miner', beneficiary='miner')
        middle = copy.deepcopy(root)
        middle.update(id=identity('unknown-nonroot-transfer'), amount=750,
                      included_in=known['id'])
        leaf = copy.deepcopy(root)
        leaf.update(id=identity('conflicting-nonroot-transfer'), amount=500,
                    included_in=middle['id'], payer='consumer', beneficiary='consumer')
        self.evidence['costs'].extend([known, middle, leaf])
        with self.assertRaisesRegex(ValueError, 'COST_SUBSET_TRANSFER_CONFLICT'):
            self.assess()

    def test_unknown_meter_stays_unresolved_even_with_known_amount(self):
        self.evidence['costs'][1]['meter'] = None
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['known'], 1550)
        self.assertTrue(any(i.startswith('COST_METER_UNKNOWN:') for i in report['local_issues']))
        self.assertIn('AUTHENTICATED_METERS_AND_COMPLETE_RESOURCE_TRANSFER', report['unresolved_predicates'])

    def test_required_but_absent_gpu_dimension_is_unknown(self):
        self.policy['operations'][0]['required_costs'].append(dict(stage='gpu', unit='gpu_ns'))
        self.repin_controlled_plan()
        report = self.assess()
        gpu = report['resources']['totals_by_unit']['gpu_ns']
        self.assertEqual(gpu['known'], 0)
        self.assertIsNone(gpu['total'])
        self.assertIsNone(gpu['upper_bound'])
        self.assertEqual(gpu['missing_required_records'], 1)

    def test_resource_units_are_never_added_together(self):
        energy = copy.deepcopy(self.evidence['costs'][1])
        energy.update(id=identity('energy'), unit='energy_nj', amount=9000)
        self.evidence['costs'].append(energy)
        report = self.assess()
        self.assertEqual(report['resources']['totals_by_unit']['energy_nj']['total'], 9000)
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['total'], 1550)

    def test_new_use_row_id_does_not_manufacture_another_consumer_operation(self):
        another = copy.deepcopy(self.evidence['uses'][0])
        another['id'] = identity('second-use-row')
        self.evidence['uses'].append(another)
        report = self.assess()
        self.assertEqual(report['demand']['observed_consumer_operation_references'], 1)
        self.assertEqual(report['demand']['observed_consumer_receipt_rows'], 2)
        self.assertEqual(report['demand']['operation_identity_replays'], 1)
        self.assertEqual(report['demand']['distinct_observed_demand_references'], 1)
        self.assertEqual(report['demand']['repeated_demand_uses'], 0)

    def test_new_row_id_cannot_rebind_one_consumer_operation(self):
        another = copy.deepcopy(self.evidence['uses'][0])
        another.update(id=identity('new-use-row'), receipt_sha256=identity('different-use-receipt'))
        self.evidence['uses'].append(another)
        with self.assertRaisesRegex(ValueError, 'CONSUMER_OPERATION_REBINDING'):
            self.assess()

    def test_same_material_does_not_collapse_two_pinned_demands(self):
        other = copy.deepcopy(self.policy['demands'][0])
        other['id'] = identity('second-demand')
        self.policy['demands'].append(other)
        op = copy.deepcopy(self.policy['operations'][1])
        op['id'] = identity('second-consume-operation')
        self.policy['operations'].append(op)
        self.repin_controlled_plan()
        use = copy.deepcopy(self.evidence['uses'][0])
        use.update(id=identity('second-use'), operation=op['id'], demand=other['id'], at=101)
        self.evidence['uses'].append(use)
        report = self.assess()
        self.assertEqual(report['demand']['distinct_observed_demand_references'], 2)
        self.assertEqual(report['demand']['distinct_used_materials'], 1)
        self.assertFalse(report['demand']['genuine_independent_demand_established'])

    def test_consumer_replay_conflict_and_forged_demand_rejected(self):
        other = copy.deepcopy(self.evidence['uses'][0])
        other['output_sha256'] = identity('forged-output')
        self.evidence['uses'].append(other)
        with self.assertRaisesRegex(ValueError, 'USE_ID_REBINDING'):
            self.assess()
        self.evidence['uses'].pop()
        self.evidence['uses'][0]['demand'] = identity('fake-demand')
        with self.assertRaisesRegex(ValueError, 'UNPINNED_DEMAND'):
            self.assess()

    def test_late_observations_retained_without_eligibility(self):
        self.evidence['uses'][0]['at'] = 1100
        self.evidence['terminals'][1]['at'] = 1110
        report = self.assess()
        self.assertEqual(report['demand']['observed_consumer_operation_references'], 1)
        self.assertTrue(any(i.startswith('USE_OUTSIDE_WINDOW:') for i in report['local_issues']))
        self.assertTrue(any(i.startswith('OPERATION_TERMINAL_LATE:') for i in report['local_issues']))
        self.assertEqual(report['actual_chainwork'], 0)

    def test_exact_expiry_is_outside_native_half_open_window(self):
        self.evidence['queries'][-1]['at'] = 1000
        self.evidence['terminals'][0]['at'] = 1000
        self.evidence['uses'][0]['at'] = 1000
        self.evidence['terminals'][1]['at'] = 1000
        report = self.assess()
        self.assertTrue(any(i.startswith('QUERY_OUTSIDE_WINDOW:') for i in report['local_issues']))
        self.assertTrue(any(i.startswith('USE_OUTSIDE_WINDOW:') for i in report['local_issues']))
        self.assertTrue(any(i.startswith('OPERATION_TERMINAL_LATE:') for i in report['local_issues']))
        self.assertEqual(report['queries']['observed_execution_events'], 64)
        self.assertEqual(report['resources']['totals_by_unit']['cpu_ns']['known'], 1550)

    def test_pin_does_not_authenticate_independent_control_or_current_use(self):
        for row in self.policy['actors']:
            row['control_group'] = 'one-owner'
        self.repin_controlled_plan()
        report = self.assess()
        self.assertIn('AUTHENTICATED_POLICY_TASK_AND_TARGET_ISSUERS', report['unresolved_predicates'])
        self.assertIn('GENUINE_DEMAND_CURRENT_CONSUMER_USE_AND_SETTLEMENT', report['unresolved_predicates'])
        self.assertEqual(report['qualification'], 'HOLD')
        self.assertFalse(report['production_activation'])

    def test_input_cannot_supply_qualification_or_self_certification_flags(self):
        self.evidence['public_queries_complete'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'EVIDENCE_FIELDS'):
            self.assess()
        del self.evidence['public_queries_complete']
        self.evidence['costs'][0]['amount'] = True
        with self.assertRaisesRegex(ValueError, 'JSON_TYPE'):
            self.assess()

    def test_strict_json_parser(self):
        for raw in (b'{"id":1,"id":2}', b'{"amount":1.0}', b'{"amount":NaN}',
                    b'{"amount":true}', b'{"amount":-1}', b'{"amount":18446744073709551616}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                P.parse_json(raw)

    def test_direct_api_rejects_shared_container_expansion_and_cycles(self):
        shared = [0]
        for _ in range(4):
            shared = [shared] * 4
        with self.assertRaisesRegex(ValueError, 'JSON_CONTAINER_ALIAS_OR_CYCLE'):
            P.canonical_bytes(shared)
        cycle = []
        cycle.append(cycle)
        with self.assertRaisesRegex(ValueError, 'JSON_CONTAINER_ALIAS_OR_CYCLE'):
            P.canonical_bytes(cycle)

    def test_direct_api_byte_budget_precedes_full_serialization(self):
        # Only 4096 references to one small immutable string are allocated here.
        # Its expanded JSON exceeds MAX_BYTES and must be rejected while walking.
        with self.assertRaisesRegex(ValueError, 'JSON_BYTES'):
            P.canonical_bytes(['x' * 4096] * 4096)

    def test_assessment_does_not_mutate_inputs(self):
        before = copy.deepcopy((self.policy, self.evidence))
        left, right = self.assess(), self.assess()
        self.assertEqual(left, right)
        self.assertEqual(before, (self.policy, self.evidence))

    def test_read_only_cli_uses_stdlib_and_requires_independent_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'policy.json').write_bytes(P.canonical_bytes(self.policy))
            (root / 'evidence.json').write_bytes(P.canonical_bytes(self.evidence))
            command = [sys.executable, '-S', str(Path(P.__file__).resolve()),
                '--evidence', str(root / 'evidence.json'),
                '--expected-policy', str(root / 'policy.json'),
                '--expected-policy-sha256', self.pin]
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)['qualification'], 'HOLD')
            self.assertEqual(set(p.name for p in root.iterdir()), {'policy.json', 'evidence.json'})
            command[-1] = identity('substituted-pin')
            rejected = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, '')
            self.assertEqual(json.loads(rejected.stderr)['status'], 'REJECTED')


if __name__ == '__main__':
    unittest.main()
