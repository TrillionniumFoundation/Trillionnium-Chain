#!/usr/bin/env python3
"""Campaign outcome controls; synthetic records are not native work evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import run_shared_material_campaign_v2 as campaign


class CampaignOutcomeTests(unittest.TestCase):
    def test_planned_denominator_is_fixed_before_any_outcome(self):
        rows = campaign.cases(3)
        self.assertEqual(len(rows), 31)
        self.assertEqual(len({row['name'] for row in rows}), 31)
        self.assertEqual(sum(row['expected_exit'] == 2 for row in rows), 1)
        self.assertEqual(rows[0]['preparation'], 'dense')
        self.assertEqual(rows[8]['preparation'], 'sparse')

    def test_exit_two_requires_the_original_native_exhaustion_kind(self):
        case = campaign.cases(1)[-1]
        failure = {'status': 'failed', 'error': 'NATIVE_RUN_FAILED', 'tile_states': [
            {'index': index, 'state': 'process_finished_unaccepted' if index == 0 else 'not_started'}
            for index in range(5)]}
        rows = [dict(kind='material', max_attempts=1, target_index=1), dict(kind='setup'),
                dict(kind='search', status='exhausted', error=None, attempts=[
                    dict(nonce=0, target_hit=False, proof_materialized=False, error=None)]),
                dict(kind='summary', status='failed', exhausted=1, winners=0, failed_searches=0,
                     attempts=1, measurement_incomplete=[])]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tile = root / 'tile-0'
            tile.mkdir()
            (root / 'failure.json').write_text(json.dumps(failure))
            (tile / 'process.json').write_text(json.dumps({'returncode': 2}))
            (tile / 'native.stdout.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            self.assertEqual(campaign.observed_outcome(root, case, 2, None),
                             'expected_bounded_search_exhaustion')
            wrong = copy.deepcopy(rows)
            wrong[-1]['measurement_incomplete'] = ['clock_unavailable']
            (tile / 'native.stdout.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in wrong))
            self.assertNotEqual(campaign.observed_outcome(root, case, 2, None),
                                'expected_bounded_search_exhaustion')
            failure['error'] = 'NATIVE_VERIFIER_SCOPE'
            (root / 'failure.json').write_text(json.dumps(failure))
            self.assertEqual(campaign.observed_outcome(root, case, 2, None), 'unexpected_failure_kind')
            self.assertEqual(campaign.observed_outcome(root, case, 2, 'timeout'), 'unexpected_process_outcome')


if __name__ == '__main__':
    unittest.main()
