"""Actual native/Python V4 differential. Missing or stale native input is failure.

Native test collectors emit full model bytes and actual results. The independent
oracle recomputes all counts, omitted models, weights, payouts and record digests;
it does not use native scores or self-generated fixtures as expected answers.
This is scoped numerical/model-contract conformance, not a second full ledger.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from contract_wire import canonical, tx_decode, unique
import model_composition_oracle as oracle

RELEASE_NAMES = {'asymmetric', 'first-generation', 'nonzero-parent', 'source-cap',
                 'unrelated-accurate', 'exact-but-weaker', 'zero-marginals',
                 'precommitted-score-as-weight', 'exact-cancelling-subset'}
ACCEPTED = {'asymmetric', 'first-generation', 'nonzero-parent'}
RELEASE_REFUSALS = {
    'source-cap': 'MODEL_EVIDENCE_SOURCE_BUDGET',
    'unrelated-accurate': 'MODEL_COMPOSITION_DERIVATION',
    'exact-but-weaker': 'MODEL_COMPOSITION_GAIN',
    'zero-marginals': 'MODEL_COMPOSITION_MARGINAL',
    'precommitted-score-as-weight': 'MODEL_COMPOSITION_WEIGHT',
    'exact-cancelling-subset': 'MODEL_COMPOSITION_REDUNDANT_SUBSET',
}
ARITHMETIC_CASES = (
    {('decode', name) for name in ('valid', 'truncated', 'trailing', 'version', 'family',
                                 'dimensions', 'minimum-i16')}
    | {('derive', name) for name in ('parent-once', 'omit-first', 'omit-second', 'wide-positive',
                                   'wide-negative', 'omit-overflow', 'positive-overflow', 'negative-overflow')}
    | {('subsets', name) for name in ('two-distinct', 'four-distinct', 'cancel-pair',
                                    'cancel-all-four', 'too-few', 'too-many')}
    | {('inference', name) for name in ('all-zero', 'router-tie', 'class-tie', 'base-plus-delta')}
    | {('inference', f'expert-{expert}-class-{label}') for expert in range(3) for label in range(3)}
    | {('inference', f'full-model-{seed}') for seed in range(8)}
)
ARITHMETIC_REFUSALS = {
    ('decode', 'truncated'): 'FACTOR_MODEL_LENGTH',
    ('decode', 'trailing'): 'FACTOR_MODEL_LENGTH',
    ('decode', 'version'): 'FACTOR_MODEL_VERSION',
    ('decode', 'family'): 'FACTOR_MODEL_CONTEXT',
    ('decode', 'dimensions'): 'FACTOR_MODEL_CONTEXT',
    ('decode', 'minimum-i16'): 'FACTOR_MODEL_RANGE',
    **{('derive', name): 'MODEL_COMPOSITION_RANGE' for name in
       ('omit-overflow', 'positive-overflow', 'negative-overflow')},
    **{('subsets', name): 'MODEL_COMPOSITION_REDUNDANT_SUBSET' for name in
       ('cancel-pair', 'cancel-all-four')},
    **{('subsets', name): 'MODEL_COMPOSITION_COUNT' for name in ('too-few', 'too-many')},
}


def check_arithmetic_inventory(cases):
    identities = {(case['kind'], case['name']) for case in cases}
    if len(cases) != len(ARITHMETIC_CASES) or identities != ARITHMETIC_CASES:
        raise ValueError('Missing, duplicated or renamed arithmetic boundary observation')
    for case in cases:
        if case['native']['error'] != ARITHMETIC_REFUSALS.get((case['kind'], case['name'])):
            raise ValueError('Arithmetic observation does not exercise its required outcome class')


def read_observations():
    location = os.environ.get('TRNM_MODEL_COMPOSITION_VECTORS')
    run_id = os.environ.get('TRNM_MODEL_COMPOSITION_RUN_ID')
    if not location or not run_id:
        raise RuntimeError('Actual fresh native observations are required; absence is not a skip')
    directory = Path(location)
    if not directory.is_dir():
        raise RuntimeError('Actual fresh native observations are required; absence is not a skip')
    expected = ({'arithmetic-production.json'}
                | {f'release-{name}.json' for name in RELEASE_NAMES}
                | {f'claims-{name}.json' for name in ACCEPTED})
    if {p.name for p in directory.iterdir()} != expected:
        raise RuntimeError('Missing, extra or stale native observation files')
    observations = {}
    for name in sorted(expected):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('Bounded regular native observation file required')
        value = json.loads(path.read_bytes(), object_pairs_hook=unique)
        # Reject floats, NaN/Infinity and integers outside the wire domain, even
        # where Python would otherwise compare 0.0 equal to an observed integer.
        canonical(value)
        fields = {'schema', 'run_id', 'kind', 'name', 'input', 'native', 'scope',
                  'economic_accepted', 'independent_operators_accepted', 'public_reward_eligible'}
        if (set(value) != fields or value['schema'] != 'model-composition-native-observation-v1'
                or value['run_id'] != run_id
                or value['scope'] != 'native-observation-for-independent-model-conformance-only'
                or any(value[flag] is not False for flag in
                       ('economic_accepted', 'independent_operators_accepted', 'public_reward_eligible'))
                or name != f"{value['kind']}-{value['name']}.json"):
            raise RuntimeError('Observation scope, identity or run binding differs')
        if value['kind'] == 'arithmetic':
            check_arithmetic_inventory(value['native']['cases'])
        observations[name] = value
    return observations


class NativeModelCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observations = read_observations()

    def test_full_signed_native_release_results_match_independent_computation(self):
        for name in sorted(RELEASE_NAMES):
            with self.subTest(name=name):
                observation = self.observations[f'release-{name}.json']
                value, native = observation['input'], observation['native']
                # The existing Python wire decoder binds this observation to the
                # supplied signed envelope fields. Signature/roster authority is
                # still established only by the actual native execution path.
                transaction = tx_decode(bytes.fromhex(value['signed_release_hex']))
                self.assertEqual(transaction['tag'], 8)
                self.assertEqual(transaction['network'].hex(), value['context']['network'])
                self.assertEqual(transaction['fields'], dict(
                    release=bytes.fromhex(value['release']),
                    parent_release=bytes.fromhex(value['parent_ref']),
                    bundle=bytes.fromhex(value['bundle']['id']), budget=value['budget'],
                    allocation_root=bytes.fromhex(value['bundle']['contribution']['components_root']),
                    total_score=sum(row['weight'] for row in value['components']),
                    allocations=[(bytes.fromhex(row['id']), row['weight']) for row in value['components']]))
                # Recompute and compare each previously admitted empirical record
                # before checking the bundle; native counts are not oracle inputs.
                family = oracle.hash_bytes(value['context']['family'])
                parent = oracle.decode_model(bytes.fromhex(value['parent_model_hex']), family)
                for candidate in [value['bundle'], *value['components']]:
                    model = oracle.decode_model(bytes.fromhex(candidate['model_hex']), family)
                    expected = oracle.empirical_record(value['context'], candidate['id'], model, parent)
                    self.assertEqual(canonical(candidate['native_evidence']), canonical(expected))
                    self.assertEqual(canonical(candidate['contribution']['score']), canonical(expected['score']))
                    self.assertEqual(candidate['contribution']['model_evidence_v4']['digest'], expected['digest'])
                if name not in ACCEPTED:
                    self.assertEqual(native['error'], RELEASE_REFUSALS[name])
                    with self.assertRaises(ValueError) as rejected:
                        oracle.composition_release(value)
                    self.assertEqual(str(rejected.exception), native['error'])
                    continue
                expected = oracle.composition_release(value)
                self.assertIsNone(native['error'])
                self.assertEqual(canonical(native['release']['model_composition_v4']), canonical(expected['composition']))
                self.assertEqual(canonical(native['source_reserved']), canonical(expected['source_reserved']))
                self.assertEqual(native['release']['budget'], value['budget'])
                self.assertEqual(native['release']['total'], expected['composition']['total_weight'])
                self.assertEqual(native['release']['root'], expected['root'])
                self.assertEqual(native['release']['components_root'], expected['root'])
                self.assertEqual(native['release']['remaining'], value['budget'])
                claims = self.observations[f'claims-{name}.json']
                self.assertEqual(claims['input']['release'], value['release'])
                self.assertEqual(canonical(claims['native']['claims']), canonical(expected['payouts']))
                self.assertEqual(canonical(claims['native']['remaining']), canonical(expected['dust']))

    def test_observed_receipts_scores_and_weights_do_not_supply_expected_answers(self):
        original = self.observations['release-asymmetric.json']['input']
        expected = oracle.composition_release(original)
        changed = copy.deepcopy(original)
        changed['bundle']['native_evidence']['candidate_correct'] = 0
        changed['bundle']['contribution']['score'] = 0
        for component in changed['components']:
            component['native_evidence']['candidate_correct'] = 0
            component['contribution']['model_evidence_v4']['score'] = 0
        self.assertEqual(oracle.composition_release(changed), expected)
        changed['components'][0]['weight'] += 1
        with self.assertRaisesRegex(ValueError, '^MODEL_COMPOSITION_WEIGHT$'):
            oracle.composition_release(changed)
        # Reference-side mutation test, explicitly not a new native observation.
        changed = copy.deepcopy(original)
        changed['parent_ref'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError, '^MODEL_COMPOSITION_PARENT$'):
            oracle.composition_release(changed)

    def test_actual_native_codec_composition_inference_and_subset_boundaries(self):
        observation = self.observations['arithmetic-production.json']
        family = oracle.hash_bytes(observation['input']['family'])
        cases = observation['native']['cases']
        self.assertEqual(len(cases), 42)
        self.assertEqual({(case['kind'], case['name']) for case in cases}, ARITHMETIC_CASES)
        for case in cases:
            with self.subTest(kind=case['kind'], name=case['name']):
                try:
                    kind = case['kind']
                    if kind == 'decode':
                        model = oracle.decode_model(bytes.fromhex(case['raw_hex']), family)
                        expected = dict(error=None, model_hex=oracle.encode_model(family, model).hex(),
                                        artifact=oracle.artifact(family, model))
                    elif kind == 'inference':
                        model = oracle.decode_model(bytes.fromhex(case['model_hex']), family)
                        expected = dict(error=None, correct=oracle.correct(model),
                                        artifact=oracle.artifact(family, model))
                    elif kind in ('derive', 'subsets'):
                        parent = oracle.decode_model(bytes.fromhex(case['parent_hex']), family)
                        components = [oracle.decode_model(bytes.fromhex(raw), family)
                                      for raw in case['components_hex']]
                        if kind == 'subsets':
                            expected = dict(error=None, count=oracle.reject_redundant_subsets(parent, components))
                        else:
                            model = oracle.derive(parent, components, case['omit'])
                            expected = dict(error=None, model_hex=oracle.encode_model(family, model).hex(),
                                            artifact=oracle.artifact(family, model))
                    else:
                        self.fail(f'Unknown native vector kind {kind}')
                except ValueError as error:
                    expected = dict(error=str(error))
                self.assertEqual(canonical(case['native']), canonical(expected))

    def test_nonzero_parent_and_floored_source_limit_are_observed(self):
        value = self.observations['release-nonzero-parent.json']['input']
        family = oracle.hash_bytes(value['context']['family'])
        parent = oracle.decode_model(bytes.fromhex(value['parent_model_hex']), family)
        first_generation = self.observations['release-first-generation.json']['input']
        self.assertEqual(value['parent_ref'], first_generation['release'])
        self.assertEqual(value['parent_model_hex'], first_generation['bundle']['model_hex'])
        self.assertTrue(any(parent))
        self.assertEqual(oracle.correct(parent), 24)
        result = oracle.composition_release(value)
        self.assertEqual(result['composition']['correct'], 25)
        self.assertEqual([row['weight'] for row in result['composition']['components']], [80000, 80000])
        self.assertEqual([row['native_evidence']['score'] for row in value['components']], [0, 0])
        first = oracle.composition_release(self.observations['release-asymmetric.json']['input'])
        self.assertEqual(sorted(first['payouts'].values()), [33333, 66667])
        self.assertEqual(first['dust'], 1)
        self.assertIn(100000, first['source_reserved'].values())
        cap = self.observations['release-source-cap.json']
        self.assertEqual(cap['input']['budget'], 100002)
        self.assertEqual(cap['native']['error'], 'MODEL_EVIDENCE_SOURCE_BUDGET')

    def test_stale_incomplete_or_noninteger_observations_are_rejected(self):
        source = Path(os.environ['TRNM_MODEL_COMPOSITION_VECTORS'])
        for alteration in ('stale', 'promoted', 'extra-field', 'float', 'duplicate', 'directory',
                           'missing', 'missing-case', 'renamed-case', 'wrong-outcome'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / 'observations'
                shutil.copytree(source, target)
                path = target / 'arithmetic-production.json'
                if alteration == 'missing':
                    path.unlink()
                elif alteration == 'directory':
                    path.unlink()
                    path.mkdir()
                elif alteration == 'duplicate':
                    path.write_bytes(path.read_bytes().replace(
                        b'"schema":', b'"schema":"duplicate","schema":', 1))
                else:
                    value = json.loads(path.read_bytes())
                    if alteration == 'stale':
                        value['run_id'] += '-stale'
                    elif alteration == 'promoted':
                        value['economic_accepted'] = True
                    elif alteration == 'extra-field':
                        value['unrecognized'] = True
                    elif alteration == 'missing-case':
                        value['native']['cases'].pop()
                    elif alteration == 'renamed-case':
                        value['native']['cases'][0]['name'] += '-unrequired'
                    elif alteration == 'wrong-outcome':
                        value['native']['cases'][0]['native']['error'] = 'UNEXERCISED_CASE'
                    else:
                        value['input']['invalid_float'] = 0.0
                    path.write_text(json.dumps(value))
                with patch.dict(os.environ, TRNM_MODEL_COMPOSITION_VECTORS=str(target)):
                    with self.assertRaises((ValueError, RuntimeError)):
                        read_observations()


if __name__ == '__main__':
    unittest.main(verbosity=2)
