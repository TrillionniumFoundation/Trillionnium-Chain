"""Independent semantics and bounded real native transport tests for research v0."""
from __future__ import annotations
import copy
import os
from pathlib import Path
import unittest
from bounded_process import run_bounded
from contract_wire import H, ROOT, canonical
from evaluation_bundle import artifact_id
from experiments.grouped_cell_operator_v0 import (
    PROFILE, NATIVE_SCHEMA, PHASES, SELECTED_PHASES, SELECTED_PRODUCER_SCOPE,
    NATIVE_HOT_ORDER, FIRST_CALL_SCOPE,
    make_commands, encode_frames, decode_frames, kernel_comparison,
    model_commitment, input_commitment, statement_commitment, scalar_product,
    validate_prepared, validate_result)
from test_model_attribution import fixture_parent


def fixture(n=64):
    model = fixture_parent()
    for e in range(3):
        model['router'][e][e] = 1
        for r in range(3):
            model['deltas'][e][r] = [((e * 7 + r * 5 + k * 3) % 13) - 6 for k in range(257)]
    rows = []
    for i in range(n):
        x = [0] * 257
        x[i % 3] = 8
        x[256] = 8
        rows.append({'id': H('grouped-unit-row', str(i).encode()).hex(), 'file': f'fixture/{i}.rs',
                     'source_content_sha256': H('grouped-unit-content', str(i).encode()).hex(),
                     'label': i % 3, 'x': x})
    provenance = {'model_artifact': artifact_id(model), 'scope': 'unit-fixture-not-demand',
                  'source_commit': 'a' * 40, 'evaluation_bundle': 'b' * 64, 'batch_offset': 0}
    return model, rows, provenance


def unit_claim(model, rows, init, command):
    """Test input for the Python checker; never used as measured native evidence."""
    m = model_commitment(init)
    inputs = input_commitment(m, command)
    product = scalar_product(model, rows)
    return dict(type='batch', schema=NATIVE_SCHEMA, profile=PROFILE,
        model_commitment=m, input_commitment=inputs,
        statement_commitment=statement_commitment(m, inputs, command['context'], product),
        selected_statement_commitment=statement_commitment(m, inputs, command['context'], product),
        selected_statement_matches_packed=True, selected_semantic_verified=True,
        **product, semantic_verified=True, benchmark_only=True, distinct_application_batches=None,
        response_deadline_checked_before_write=True,
        pow_qualified=False, production_activation=False, public_reward_eligible=False,
        real_demand_verified=False, model_reward=0, business_credit=0,
        new_request_ids_in_session=len(rows), unique_request_ids_in_session=len(rows),
        phase_ns={phase: 1 for phase in PHASES}, cold_baseline_ns=1, cold_grouped_ns=1,
        selected_phase_ns={phase: 1 for phase in SELECTED_PHASES}, cold_selected_with_statement_ns=1,
        selected_producer_with_verify_wall_ns=6, selected_producer_with_verify_cpu_ns=6,
        selected_producer_with_verify_scope=SELECTED_PRODUCER_SCOPE,
        handler_wall_ns=1, handler_cpu_ns=1, completion_now_ns=4, verified_product_ready_now_ns=2,
        selected_verified_product_ready_now_ns=3, first_call_scope=FIRST_CALL_SCOPE,
        kernel_sample_order_cycle=copy.deepcopy(NATIVE_HOT_ORDER),
        kernel_sample_complete_cycles=command['samples'] // len(NATIVE_HOT_ORDER),
        kernel_sample_partial_cycle_samples=command['samples'] % len(NATIVE_HOT_ORDER),
        baseline_ns=[1] * command['samples'], selected_ns=[1] * command['samples'],
        grouped_ns=[1] * command['samples'])


class GroupedResultCheckerTests(unittest.TestCase):
    def setUp(self):
        self.model, self.rows, provenance = fixture(4)
        self.init, commands = make_commands(self.model, self.rows, provenance, [4], 3, 0)
        self.command = commands[0]
        self.claim = unit_claim(self.model, self.rows, self.init, self.command)

    def validate(self, claim=None, command=None):
        return validate_result(self.claim if claim is None else claim, self.init,
                               self.command if command is None else command,
                               self.model, self.rows, prior_ids=set())

    def test_unit_claim_matches_full_independent_checks(self):
        self.assertEqual(self.validate(), {r['id'] for r in self.rows})
        self.assertEqual(self.claim['useful_dense_macs'], 4 * 1542)
        self.assertEqual(self.claim['groups'], [[0, 3], [1], [2]])

    def test_rehashed_wrong_routes_groups_logits_accounting_are_rejected(self):
        for key in ('router_outputs', 'routes', 'groups', 'logits', 'predictions',
                    'useful_dense_macs', 'padded_macs', 'nonempty_expert_groups'):
            claim = copy.deepcopy(self.claim)
            if key in ('router_outputs', 'logits'):
                claim[key][0][0] += 1
            elif key == 'groups':
                claim[key][0].reverse()
            elif key in ('routes', 'predictions'):
                claim[key][0] = (claim[key][0] + 1) % 3
            else:
                claim[key] += 1
            claim['statement_commitment'] = statement_commitment(claim['model_commitment'],
                claim['input_commitment'], self.command['context'], claim)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'PRODUCT_'):
                self.validate(claim)

    def test_context_request_order_scope_deadline_and_input_are_bound(self):
        for field in ('chain', 'parent', 'challenge', 'batch_id', 'scope', 'arrival_ns', 'deadline_ns', 'x', 'order'):
            command = copy.deepcopy(self.command)
            if field in command['context']:
                command['context'][field] = 'c' * 64
            elif field == 'order':
                command['requests'].reverse()
            elif field == 'scope':
                command['requests'][0][field] = 'c' * 64
            elif field == 'x':
                command['requests'][0]['x'][5] = 1
            else:
                command['requests'][0][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'INPUT_BINDING'):
                self.validate(command=command)

    def test_qualifications_sample_counts_and_numeric_aliases_refuse(self):
        for field, bad in (('semantic_verified', False), ('pow_qualified', True),
                           ('public_reward_eligible', True), ('model_reward', True),
                           ('business_credit', 1), ('new_request_ids_in_session', 5),
                           ('unique_request_ids_in_session', 5), ('baseline_ns', [1]),
                           ('grouped_ns', [True] * 3), ('selected_ns', [1]),
                           ('selected_producer_with_verify_wall_ns', True),
                           ('selected_producer_with_verify_cpu_ns', -1),
                           ('cold_selected_with_statement_ns', None),
                           ('completion_now_ns', 3_600_000_000_000),
                           ('useful_dense_macs', True)):
            claim = copy.deepcopy(self.claim)
            claim[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(claim)

    def test_selected_statement_and_full_cost_scope_are_independently_checked(self):
        for field, value, code in (
                ('selected_statement_commitment', '0' * 64, 'SELECTED_STATEMENT_BINDING'),
                ('selected_statement_matches_packed', False, 'SELECTED_SEMANTIC_VERIFICATION'),
                ('selected_semantic_verified', False, 'SELECTED_SEMANTIC_VERIFICATION'),
                ('selected_producer_with_verify_scope', 'kernel-only', 'SELECTED_PRODUCER_SCOPE'),
                ('selected_phase_ns', {'execution': 1}, 'SELECTED_PHASES')):
            claim = copy.deepcopy(self.claim)
            claim[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, code):
                self.validate(claim)
        claim = copy.deepcopy(self.claim)
        del claim['selected_statement_commitment']
        with self.assertRaisesRegex(ValueError, 'SELECTED_STATEMENT_BINDING'):
            self.validate(claim)
        claim = copy.deepcopy(self.claim)
        del claim['selected_producer_with_verify_cpu_ns']
        with self.assertRaisesRegex(ValueError, 'SELECTED_CPU_OBSERVATION'):
            self.validate(claim)
        claim = copy.deepcopy(self.claim)
        claim['selected_producer_with_verify_cpu_ns'] = None  # Explicitly unavailable is legal.
        self.validate(claim)

    def test_native_order_and_selected_readiness_metadata_cannot_be_fabricated_or_omitted(self):
        for field, value, code in (
                ('kernel_sample_order_cycle', [], 'KERNEL_SAMPLE_ORDER'),
                ('kernel_sample_order_cycle', list(reversed(NATIVE_HOT_ORDER)), 'KERNEL_SAMPLE_ORDER'),
                ('kernel_sample_complete_cycles', 1, 'KERNEL_SAMPLE_CYCLES'),
                ('kernel_sample_complete_cycles', False, 'KERNEL_SAMPLE_CYCLES'),
                ('kernel_sample_partial_cycle_samples', 0, 'KERNEL_SAMPLE_REMAINDER'),
                ('selected_verified_product_ready_now_ns', True, 'BATCH_TIMING'),
                ('selected_verified_product_ready_now_ns', 1, 'FIXTURE_COMPLETION'),
                ('selected_verified_product_ready_now_ns', 5, 'FIXTURE_COMPLETION'),
                ('first_call_scope', 'isolated cold process', 'FIRST_CALL_SCOPE')):
            claim = copy.deepcopy(self.claim)
            claim[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, code):
                self.validate(claim)
        for field in ('kernel_sample_order_cycle', 'kernel_sample_complete_cycles',
                      'kernel_sample_partial_cycle_samples', 'selected_verified_product_ready_now_ns'):
            claim = copy.deepcopy(self.claim)
            del claim[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.validate(claim)

    def test_comparison_retains_ordinary_and_packed_negative_without_cross_scope_ratio(self):
        claim = copy.deepcopy(self.claim)
        claim.update(baseline_ns=[2] * 6, selected_ns=[3] * 6, grouped_ns=[9] * 6,
                     selected_producer_with_verify_wall_ns=500,
                     kernel_sample_complete_cycles=1, kernel_sample_partial_cycle_samples=0)
        observed = kernel_comparison(claim)
        self.assertEqual(observed['grouped_over_ordinary_hot_kernel_median'], 4.5)
        self.assertEqual(observed['selected_over_ordinary_hot_kernel_median'], 1.5)
        self.assertEqual(observed['packed_over_selected_hot_kernel_median'], 3)
        self.assertEqual(observed['kernel_candidate_for_this_fixture']['candidate'], 'selected_direct')
        self.assertFalse(observed['kernel_candidate_for_this_fixture']['runtime_policy_changed'])
        self.assertFalse(observed['kernel_candidate_for_this_fixture']['performance_qualified'])
        self.assertEqual(observed['hot_sampling_order']['complete_cycles'], 1)
        self.assertEqual(observed['hot_sampling_order']['remaining_orders'], [])
        # Reversing the measured outcome changes the research candidate; no arm
        # is selected unconditionally, and the ordinary control is still present.
        claim['selected_ns'] = [10] * 6
        self.assertEqual(kernel_comparison(claim)['kernel_candidate_for_this_fixture']['candidate'], 'packed_grouped')
        claim['selected_ns'] = claim['grouped_ns']
        self.assertEqual(kernel_comparison(claim)['kernel_candidate_for_this_fixture']['candidate'], 'tied')
        claim['selected_ns'] = [0] * 6
        self.assertEqual(kernel_comparison(claim)['kernel_candidate_for_this_fixture']['candidate'],
                         'undetermined_timer_resolution')

    def test_output_duplicate_keys_missing_frames_and_unknown_schema_refuse(self):
        for raw, count in ((b'{"a":1,"a":2}\n', 1), (b'{}', 1), (b'{}\n{}\n', 1), (b'[]\n', 1)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_frames(raw, count)
        prepared = dict(type='prepared', schema=NATIVE_SCHEMA, profile=PROFILE,
                        model_commitment=model_commitment(self.init), preparation_ns=0,
                        production_activation=False, pow_qualified=False)
        validate_prepared(prepared, self.init)
        prepared['model_commitment'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'MODEL_COMMITMENT'):
            validate_prepared(prepared, self.init)

    def test_ties_and_empty_groups_use_lowest_index_without_fake_work(self):
        self.model['router'] = [[0] * 257 for _ in range(3)]
        product = scalar_product(self.model, self.rows)
        self.assertEqual(product['routes'], [0] * 4)
        self.assertEqual(product['groups'], [[0, 1, 2, 3], [], []])
        self.assertEqual(product['nonempty_expert_groups'], 1)
        self.assertEqual(product['padded_macs'], 0)


@unittest.skipUnless(os.environ.get('TRNM_GROUPED_NATIVE'),
                     'TRNM_GROUPED_NATIVE is unset: actual native integration not executed')
class GroupedNativeIntegrationTests(unittest.TestCase):
    def run_native(self, raw):
        runner = Path(os.environ['TRNM_GROUPED_NATIVE']).resolve()
        self.assertTrue(runner.is_file(), f'configured native runner missing: {runner}')
        return run_bounded([str(runner), '--grouped-research-v0'], raw, timeout=10,
                           stdout_limit=2 * 1024 * 1024, stderr_limit=65536, cwd=ROOT)

    def test_one_real_process_init_all_shapes_full_scalar_and_numpy_differential(self):
        model, rows, provenance = fixture()
        init, commands = make_commands(model, rows, provenance, [1, 4, 16, 64], 6, 1)
        result = self.run_native(encode_frames([init, *commands]))
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        frames = decode_frames(result.stdout, 5)
        validate_prepared(frames[0], init)
        seen = set()
        for command, frame in zip(commands, frames[1:]):
            seen = validate_result(frame, init, command, model, rows[:len(command['requests'])], prior_ids=seen)
        self.assertEqual(len(seen), 64)
        self.assertEqual(frames[-1]['useful_dense_macs'], 98688)
        self.assertEqual(frames[-1]['selected_statement_commitment'], frames[-1]['statement_commitment'])
        self.assertEqual(len(frames[-1]['selected_ns']), 6)
        self.assertEqual(frames[-1]['selected_producer_with_verify_scope'], SELECTED_PRODUCER_SCOPE)

    def test_real_process_hostile_frames_reject_without_success_fallback(self):
        model, rows, provenance = fixture(4)
        init, commands = make_commands(model, rows, provenance, [4], 1, 0)
        command = commands[0]
        bad_bias = copy.deepcopy(command)
        bad_bias['requests'][0]['x'][-1] = 1
        duplicate = copy.deepcopy(command)
        duplicate['requests'][1]['id'] = duplicate['requests'][0]['id']
        expired = copy.deepcopy(command)
        expired['now_ns'] = expired['requests'][0]['deadline_ns']
        rebound = copy.deepcopy(command)
        rebound['context']['batch_id'] = 'd' * 64
        rebound['requests'][0]['deadline_ns'] += 1
        cases = [encode_frames([init, bad_bias]), encode_frames([init, duplicate]),
                 encode_frames([init, expired]), encode_frames([init, command, command]),
                 encode_frames([init, command, rebound]),
                 canonical(init).replace(b'"type":"init"', b'"type":"init","type":"init"') + b'\n',
                 b' ' + encode_frames([init]), canonical(init)]
        for i, raw in enumerate(cases):
            with self.subTest(case=i):
                result = self.run_native(raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'grouped research refused:', result.stderr)


if __name__ == '__main__':
    unittest.main()
