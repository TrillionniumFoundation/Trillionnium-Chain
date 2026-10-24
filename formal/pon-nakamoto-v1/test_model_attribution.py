"""Exact-factor, copy-splitting and complementary-update attack regressions."""
from __future__ import annotations
import copy
import json
import unittest
from contract_wire import H, canonical
from ledger import FAMILY
from model_attribution import *


def identity(value):
    return H('attribution-test-identity', value.encode()).hex()


def fixture_parent():
    base = [[0]*257 for _ in range(3)]; base[0][-1] = 1
    return dict(schema='hepta-source-owner-linear-256-v1', family=FAMILY.hex(), scale=1024,
                source='controlled-attribution-fixture', feature='signed-token-hash-256-clipped8-plus-bias-v1',
                classes=['M00', 'M04', 'M10'], base=base, router=[[0]*257 for _ in range(3)],
                deltas=[[[0]*257 for _ in range(3)] for _ in range(3)])


def fixture_rows(prefix='evaluation', count=24):
    return [dict(id=identity(prefix+str(i)), file=prefix+'/'+str(i)+'.rs', label=1,
                 source_content_sha256=identity('content'+prefix+str(i)), x=[1,1]+[0]*254+[8])
            for i in range(count)]


def adapter(contract, coordinate, weight=5, alternate=False):
    a = [0]*257; a[coordinate] = weight if alternate else 1
    return {'schema': 'pon-integer-linear-adapter-v1', 'contract': contract_id(contract),
            'A': [a], 'B': [[0], [1 if alternate else weight], [0]]}


class BoundedAttributionTests(unittest.TestCase):
    def setUp(self):
        self.parent = fixture_parent(); self.rows = fixture_rows()
        self.contract = integer_linear_contract(self.parent)
        self.bundle = identity('existing-evaluation-bundle')

    def freeze(self, variants, origins=None, perturbation=0, caps=None):
        submissions = [{'id': identity(name), 'adapter': value} for name, value in variants.items()]
        if origins is None:
            origins = {identity(name): identity('source'+name) for name in variants}
        if caps is None:
            caps = {source: 100 for source in origins.values()}
        return freeze_attribution_plan(parent=self.parent, evaluation_bundle=self.bundle,
            partition='evaluation', rows=self.rows, submissions=submissions,
            admitted_sources=origins, source_caps=caps, perturbation_linf=perturbation)

    def evaluate(self, raw, digest, **kwargs):
        return evaluate_attribution_plan(raw, digest, self.rows,
            expected_parent=artifact_id(self.parent), expected_bundle=self.bundle, **kwargs)

    def test_distinct_factorizations_equal_full_BA_for_every_input(self):
        first = adapter(self.contract, 0); other = adapter(self.contract, 0, alternate=True)
        self.assertNotEqual(canonical(first), canonical(other))
        self.assertTrue(exact_linear_equivalent(first, other, self.contract))
        self.assertEqual(normalize_adapter(first, self.contract)['function_fingerprint'],
                         normalize_adapter(other, self.contract)['function_fingerprint'])

    def test_zero_rank_padding_also_collapses(self):
        first = adapter(self.contract, 0); padded = copy.deepcopy(first)
        padded['A'].append([7]*257)
        for row in padded['B']: row.append(0)
        self.assertTrue(exact_linear_equivalent(first, padded, self.contract))

    def test_same_probe_predictions_do_not_prove_function_equivalence(self):
        first = adapter(self.contract, 0); different = adapter(self.contract, 1)
        self.assertFalse(exact_linear_equivalent(first, different, self.contract))
        # On this dataset both updates make the same predictions; the matrices
        # remain distinct and become complementary as an admitted bundle.
        raw, digest = self.freeze({'first': first, 'different': different})
        result = self.evaluate(raw, digest)
        self.assertEqual(result['bounded_optimum']['table'][1]['value'], ['0','1'])
        self.assertEqual(result['bounded_optimum']['table'][2]['value'], ['0','1'])
        self.assertEqual(result['joint_gain'], ['1','1'])

    def test_copy_under_new_identity_cannot_double_update_or_budget(self):
        raw, digest = self.freeze({'first': adapter(self.contract, 0),
                                   'copy': adapter(self.contract, 0, alternate=True)})
        plan = verify_attribution_plan(raw, digest)
        self.assertEqual(len(plan['groups']), 1)
        self.assertEqual(plan['groups'][0]['credit_cap'], 100)
        self.assertEqual(plan['groups'][0]['collapsed_aliases'], 1)
        self.assertEqual(self.evaluate(raw, digest)['joint_gain'], ['0','1'])

    def test_known_source_split_keeps_one_cap_but_retains_distinct_complementary_components(self):
        origins = {identity(name): identity('same-owner-admitted-lineage') for name in ('a', 'b')}
        raw, digest = self.freeze({'a': adapter(self.contract, 0), 'b': adapter(self.contract, 1)}, origins)
        plan = verify_attribution_plan(raw, digest)
        self.assertEqual(len(plan['groups']), 1)
        self.assertEqual(len(plan['groups'][0]['components']), 2)
        self.assertEqual(plan['groups'][0]['credit_cap'], 100)
        self.assertEqual(self.evaluate(raw, digest)['joint_gain'], ['1','1'])

    def test_declared_duplicate_perturbation_cannot_manufacture_bundle_gain(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0, weight=5),
                                   'near-copy': adapter(self.contract, 0, weight=6)}, perturbation=1)
        plan = verify_attribution_plan(raw, digest)
        self.assertEqual(len(plan['groups']), 1)
        self.assertEqual(plan['groups'][0]['collapsed_aliases'], 1)
        self.assertEqual(self.evaluate(raw, digest)['joint_gain'], ['0','1'])
        # Epsilon zero does not pretend to solve arbitrary semantic copying.
        zero_raw, zero_digest = self.freeze({'a': adapter(self.contract, 0, weight=5),
                                             'near-copy': adapter(self.contract, 0, weight=6)})
        self.assertEqual(len(verify_attribution_plan(zero_raw, zero_digest)['groups']), 2)

    def test_complementarity_receives_bounded_group_credit_without_standalone_gain(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0), 'b': adapter(self.contract, 1)})
        result = self.evaluate(raw, digest)
        self.assertTrue(result['candidate_gate']['cluster_gate'])
        self.assertEqual(result['joint_gain'], ['1','1'])
        self.assertEqual(result['complementarity'], ['1','1'])
        self.assertEqual([group['standalone_gain'] for group in result['attribution']], [['0','1']]*2)
        self.assertEqual([group['finite_group_shapley'] for group in result['attribution']], [['1','2']]*2)
        self.assertFalse(result['public_reward_eligible'])

    def test_finite_optimum_is_replayed_not_candidate_rank_or_returned_bound(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0), 'b': adapter(self.contract, 1)})
        result = self.evaluate(raw, digest, candidate_mask=1)
        self.assertEqual(result['bounded_optimum']['candidate_gap'], ['1','1'])
        self.assertFalse(result['bounded_optimum']['exact_in_this_set'])
        result['bounded_optimum']['maximum'] = ['0','1']
        with self.assertRaisesRegex(ValueError, 'ATTRIBUTION_RESULT_BINDING'):
            verify_attribution_result(raw, digest, self.rows, result, candidate_mask=1)

    def test_group_shapley_efficiency_and_all_subset_costs(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0), 'b': adapter(self.contract, 1)})
        result = self.evaluate(raw, digest)
        total = sum((Fraction(*map(int, g['finite_group_shapley'])) for g in result['attribution']), Fraction())
        self.assertEqual(total, Fraction(*map(int, result['joint_gain'])))
        self.assertEqual(result['verification_cost']['prediction_rows'], len(self.rows)*4)
        self.assertEqual(result['verification_cost']['inference_multiplications'], len(self.rows)*4*9*257)

    def test_admission_grouping_is_permutation_invariant(self):
        variants = {'a': adapter(self.contract, 0), 'b': adapter(self.contract, 1),
                    'copy': adapter(self.contract, 0, alternate=True)}
        first = self.freeze(variants)
        self.assertEqual(first, self.freeze(dict(reversed(list(variants.items())))))

    def test_changed_parent_slot_and_factor_fields_reject(self):
        value = adapter(self.contract, 0)
        for field, replacement in [('contract', identity('other-parent')), ('schema', 'float-lora')]:
            altered = copy.deepcopy(value); altered[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ADAPTER_CONTEXT'):
                normalize_adapter(altered, self.contract)
        altered = copy.deepcopy(value); altered['A'][0][0] = True
        with self.assertRaisesRegex(ValueError, 'ADAPTER_FACTOR'): normalize_adapter(altered, self.contract)
        altered['A'][0][0] = 32767; altered['B'][1][0] = 32767
        with self.assertRaisesRegex(ValueError, 'ADAPTER_DELTA'): normalize_adapter(altered, self.contract)

    def test_missing_admission_cannot_self_assert_source_or_mint_cap(self):
        with self.assertRaisesRegex(ValueError, 'ADMITTED_SOURCES'):
            self.freeze({'a': adapter(self.contract, 0)}, origins={})
        origin = identity('source')
        with self.assertRaisesRegex(ValueError, 'SOURCE_CAP'):
            self.freeze({'a': adapter(self.contract, 0)}, origins={identity('a'): origin}, caps={origin: True})

    def test_source_alias_with_larger_cap_does_not_raise_shared_cap(self):
        origins = {identity('a'): identity('honest'), identity('copy'): identity('claimed-other')}
        raw, digest = self.freeze({'a': adapter(self.contract, 0), 'copy': adapter(self.contract, 0)}, origins,
                                  caps={identity('honest'): 100, identity('claimed-other'): 100000})
        self.assertEqual(verify_attribution_plan(raw, digest)['groups'][0]['credit_cap'], 100)

    def test_matrix_hash_is_not_used_as_equality_oracle(self):
        from unittest.mock import patch
        with patch('model_attribution.H', return_value=bytes(32)):
            c = integer_linear_contract(self.parent)
            self.assertFalse(exact_linear_equivalent(adapter(c, 0), adapter(c, 1), c))

    def test_group_summary_tampering_rejects_even_after_rehash(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0)})
        plan = json.loads(raw); plan['groups'][0]['credit_cap'] += 1
        changed = canonical(plan)
        with self.assertRaisesRegex(ValueError, 'ATTRIBUTION_GROUP_BINDING'):
            verify_attribution_plan(changed, H('bounded-model-attribution-plan-v1', changed).hex())

    def test_expected_plan_parent_bundle_and_task_roots_are_external_bindings(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0)})
        for kwargs in ({'expected_parent': identity('wrong')}, {'expected_bundle': identity('wrong')}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): verify_attribution_plan(raw, digest, **kwargs)
        rows = copy.deepcopy(self.rows); rows[0]['label'] = 2
        with self.assertRaisesRegex(ValueError, 'ATTRIBUTION_TASKS'): evaluate_attribution_plan(raw, digest, rows)
        with self.assertRaisesRegex(ValueError, 'ATTRIBUTION_PLAN_IDENTITY'): self.evaluate(raw+b' ', digest)

    def test_work_and_group_bounds_reject_unbounded_search(self):
        variants = {str(i): adapter(self.contract, i, weight=i+1) for i in range(9)}
        with self.assertRaisesRegex(ValueError, 'ATTRIBUTION_GROUP_LIMIT'): self.freeze(variants)
        value = adapter(self.contract, 0); value['A'] *= 9
        with self.assertRaisesRegex(ValueError, 'ADAPTER_RANK'): normalize_adapter(value, self.contract)
        with self.assertRaisesRegex(ValueError, 'PERTURBATION_BOUND'):
            self.freeze({'a': adapter(self.contract, 0)}, perturbation=True)

    def test_all_subsets_must_be_feasible_no_silent_skipping(self):
        raw, digest = self.freeze({'a': adapter(self.contract, 0, weight=20000),
                                   'b': adapter(self.contract, 0, weight=20001)})
        with self.assertRaisesRegex(ValueError, 'NUMERIC'): self.evaluate(raw, digest)


class OptionalLLMDeclarationTests(unittest.TestCase):
    def declaration(self):
        return dict(schema='pon-llm-adapter-declaration-v1', base_model=identity('base'),
                    tokenizer=identity('tokenizer'), architecture=identity('architecture'), license='declared-license-reference',
                    target_modules=[dict(name='layer.0.query', rows=64, columns=64, rank=8, scale=1024)],
                    numeric='declared-exact-integer-linear-BA-only', runtime_status='required-not-executed')

    def test_optional_declaration_does_not_assert_executed_LLM_or_prospective_independence(self):
        self.assertEqual(validate_optional_llm_declaration(self.declaration()), self.declaration())
        for mutation in [lambda d: d.update(runtime_status='qualified'), lambda d: d.update(future_accepted=True),
                         lambda d: d['target_modules'][0].update(rank=True)]:
            value = self.declaration(); mutation(value)
            with self.assertRaises(ValueError): validate_optional_llm_declaration(value)

    def test_explicit_new_manifest_recomputes_exact_BA_and_keeps_optional_LLM_unexecuted(self):
        contract = integer_linear_contract(fixture_parent())
        value = adapter(contract, 0)
        raw, digest = freeze_adapter_manifest(value, contract, optional_llm_declaration=self.declaration())
        manifest = verify_adapter_manifest(raw, digest)
        self.assertEqual(manifest['normalized_update']['delta'][1][0], 5)
        self.assertEqual(manifest['optional_llm_declaration']['runtime_status'], 'required-not-executed')
        forged = json.loads(raw); forged['normalized_update']['delta'][1][0] = 6
        changed = canonical(forged)
        with self.assertRaisesRegex(ValueError, 'ADAPTER_MANIFEST_BINDING'):
            verify_adapter_manifest(changed, H('adapter-contribution-manifest-v1', changed).hex())
        with self.assertRaisesRegex(ValueError, 'ADAPTER_MANIFEST_IDENTITY'): verify_adapter_manifest(raw+b' ', digest)


if __name__ == '__main__':
    unittest.main()
