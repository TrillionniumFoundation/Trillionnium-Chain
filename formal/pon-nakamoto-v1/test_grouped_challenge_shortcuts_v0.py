"""Exact arithmetic, independent verification and honest probe accounting."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grouped_challenge_shortcuts_v0 import (
    BATCH, DIM, INTERNAL_INPUT_BOUNDS, PRODUCERS, PreparedProbe, cost, verify)
from grouped_legal_strategy_v0 import REPRESENTATION, independent_reference
from experiments import grouped_challenge_shortcuts_v0 as campaign


def fixture():
    matrix = lambda shift: [[((r * 7 + k * 11 + shift) % 23) - 11 for k in range(DIM)] for r in range(3)]
    model = {'base': matrix(1), 'router': matrix(3), 'deltas': [matrix(e + 5) for e in range(3)]}
    rows = []
    for i in range(BATCH):
        x = [0] * 256 + [8]
        x[i], x[(i + 41) % 256] = (i % 8) + 1, -(i % 7) - 1
        rows.append({'id': f'row-{i}', 'scope': 'test-scope', 'generation': 'test-generation',
                     'representation': REPRESENTATION, 'x': x})
    return model, rows


def challenge(i):
    return hashlib.sha256(f'probe-test/{i}'.encode()).digest()


class ChallengeShortcutTests(unittest.TestCase):
    def test_all_lawful_producers_equal_fresh_original_coefficient_reference(self):
        model, rows = fixture()
        original, _ = independent_reference(model, rows)
        for kind, arms in PRODUCERS.items():
            producers = [PreparedProbe(model, rows, kind, arm) for arm in arms]
            for i in range(3):
                results = []
                for prepared in producers:
                    claim, _ = prepared.produce(challenge(i))
                    _, maximum = verify(model, rows, kind, challenge(i), claim)
                    self.assertLessEqual(maximum, INTERNAL_INPUT_BOUNDS[kind])
                    self.assertEqual(claim['business'], original)
                    results.append(claim)
                self.assertTrue(all(value == results[0] for value in results))

    def test_rank_one_reuses_business_and_counts_actual_response_work(self):
        model, rows = fixture()
        direct, cached = [PreparedProbe(model, rows, 'rank1_blinded', arm) for arm in ('direct', 'cached')]
        a, ac = direct.produce(challenge(0))
        b, bc = cached.produce(challenge(0))
        self.assertEqual(a, b)
        groups = len(set(b['business']['routes']))
        self.assertEqual(bc['macs'], 3 * DIM * (1 + groups) + 6 * BATCH)
        self.assertEqual(ac['macs'] - bc['macs'], DIM * BATCH + 6 * DIM * BATCH)
        self.assertEqual(cached.preparation['macs'], 6 * DIM * BATCH)
        self.assertNotEqual(b['auxiliary'], cached.produce(challenge(1))[0]['auxiliary'])

    def test_full_rank_mixing_caches_every_operator_including_router(self):
        model, rows = fixture()
        direct, cached = [PreparedProbe(model, rows, 'batch_mix', arm) for arm in ('direct', 'cached')]
        a, ac = direct.produce(challenge(0))
        b, bc = cached.produce(challenge(0))
        self.assertEqual(a, b)
        self.assertEqual(bc['macs'], 6 * BATCH * BATCH)
        self.assertEqual(ac['macs'], DIM * BATCH * BATCH + 6 * DIM * BATCH)
        self.assertEqual(cached.preparation['macs'], 12 * DIM * BATCH)
        mixing = cached.randomness(challenge(0), cost())
        self.assertTrue(all(abs(row[i]) > sum(abs(v) for j, v in enumerate(row) if i != j)
                            for i, row in enumerate(mixing)))
        _, maximum = verify(model, rows, 'batch_mix', challenge(0), b)
        self.assertGreater(maximum, 8)  # Explicit auxiliary semantics, never a changed user input.

    def test_lut_is_bounded_scope_sensitive_and_has_no_online_multiplications(self):
        model, rows = fixture()
        prepared = PreparedProbe(model, rows, 'dropout', 'lut')
        claim, counts = prepared.produce(challenge(0))
        verify(model, rows, 'dropout', challenge(0), claim)
        self.assertEqual(counts['macs'], 0)
        self.assertEqual(counts['mask_bits_examined'], 2 * BATCH)
        self.assertEqual(counts['table_lookups'], 6 * 2 * BATCH)
        self.assertLessEqual(prepared.preparation['table_entries'] * 8, 12 * BATCH * 32 * 256 * 8)
        same = copy.deepcopy(rows)
        for row in same:
            row['x'] = list(rows[0]['x'])
        self.assertEqual(len(PreparedProbe(model, same, 'dropout', 'lut').tables), 1)
        for i, row in enumerate(same):
            row['scope'] = f'owner-{i}'
        self.assertEqual(len(PreparedProbe(model, same, 'dropout', 'lut').tables), BATCH)

    def test_corrupted_cached_projection_and_numerically_equal_wrong_types_reject(self):
        model, rows = fixture()
        prepared = PreparedProbe(model, rows, 'batch_mix', 'cached')
        claim, _ = prepared.produce(challenge(0))
        wrong = copy.deepcopy(claim)
        wrong['business']['logits'][0][0] = float(wrong['business']['logits'][0][0])
        with self.assertRaisesRegex(ValueError, 'BUSINESS_OUTPUT'):
            verify(model, rows, 'batch_mix', challenge(0), wrong)
        prepared.projections[0][0][0] += 1
        altered, _ = prepared.produce(challenge(0))
        with self.assertRaisesRegex(ValueError, 'BUSINESS_OUTPUT'):
            verify(model, rows, 'batch_mix', challenge(0), altered)
        # Even restoring the correct business receipt cannot hide a wrong
        # challenge-dependent projection in the auxiliary statement.
        altered['business'] = claim['business']
        with self.assertRaisesRegex(ValueError, 'AUXILIARY_OUTPUT'):
            verify(model, rows, 'batch_mix', challenge(0), altered)

    def test_zero_control_skips_even_mask_expansion_without_changing_relation(self):
        model, rows = fixture()
        with self.assertRaisesRegex(ValueError, 'ZERO_MODEL_REQUIRED'):
            PreparedProbe(model, rows, 'rank1_blinded', 'zero_skip')
        zero = [[0] * DIM for _ in range(3)]
        model = {'base': zero, 'router': zero, 'deltas': [zero, zero, zero]}
        prepared = PreparedProbe(model, rows, 'rank1_blinded', 'zero_skip')
        for i in range(3):
            claim, counts = prepared.produce(challenge(i))
            self.assertEqual(counts['macs'], 0)
            self.assertEqual(counts['expanded_bytes'], 0)
            verify(model, rows, 'rank1_blinded', challenge(i), claim)

    def test_original_extremes_and_bias_contract_remain_exact(self):
        _, rows = fixture()
        for row in rows:
            row['x'] = [8] * DIM
        model = {'base': [[32767] * DIM for _ in range(3)],
                 'router': [[-32767] * DIM for _ in range(3)],
                 'deltas': [[[32767] * DIM for _ in range(3)] for _ in range(3)]}
        snapshot = copy.deepcopy(rows)
        prepared = PreparedProbe(model, rows, 'batch_mix', 'cached')
        claim, _ = prepared.produce(challenge(0))
        verify(model, rows, 'batch_mix', challenge(0), claim)
        self.assertEqual(claim['business']['logits'][0], [134737904] * 3)
        self.assertEqual(rows, snapshot)
        for feature in (True, 9):
            bad = copy.deepcopy(rows)
            bad[0]['x'][0] = feature
            with self.assertRaisesRegex(ValueError, 'INPUT_RANGE'):
                PreparedProbe(model, bad, 'batch_mix', 'cached')
        bad = copy.deepcopy(rows)
        bad[0]['x'][-1] = 0
        with self.assertRaisesRegex(ValueError, 'INPUT_BIAS'):
            PreparedProbe(model, bad, 'rank1_blinded', 'cached')
        with self.assertRaisesRegex(ValueError, 'CHALLENGE'):
            prepared.produce(bytes(31))

    def test_preparation_and_verifier_failures_keep_plan_and_unknown_costs(self):
        model, rows = fixture()
        spec = campaign.plan_for(3)[0]
        with patch.object(campaign, 'PreparedProbe', side_effect=RuntimeError('prep-failure')):
            result = campaign.observe(model, rows, spec)
        self.assertEqual(result['attempts'][0]['stage'], 'preparation')
        self.assertIsNone(result['attempts'][0]['cost'])
        self.assertEqual(result['not_started'], [1, 2])
        with patch.object(campaign, 'verify', side_effect=RuntimeError('reference-failure')):
            result = campaign.observe(model, rows, spec)
        self.assertEqual(len(result['attempts']), 3)
        self.assertTrue(all(a['query_cost'] is not None and a['reference_cost'] is None and
                            a['status'] == 'rejected' for a in result['attempts']))

    def test_plan_exists_before_failed_load_and_keeps_complete_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            args = campaign.parser().parse_args(['--out', str(Path(directory) / 'run'), '--rounds', '2'])
            def fail(*unused, **keywords):
                plan = json.loads((args.out / 'plan.json').read_text())
                self.assertEqual(len(plan['observations']), 13)
                raise RuntimeError('input-load-failure')
            with patch.object(campaign, 'load_inputs', side_effect=fail):
                result = campaign.run(args)
            self.assertEqual(result['planned_rounds'], 26)
            self.assertEqual(result['actual_attempts'], 0)
            self.assertEqual(result['not_started_rounds'], 26)
            self.assertTrue(result['round_accounting_complete'])
            self.assertEqual(result['measurement_mode'], 'development_unqualified')


if __name__ == '__main__':
    unittest.main()
