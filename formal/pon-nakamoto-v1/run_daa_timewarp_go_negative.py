"""Opt-in Go/Python process differential. Requires Go, fails if absent.

Research-only: injected malformed report is an input mutation; no network/W1 work.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from daa_timewarp_beam_research import find_high_target, Settings, ALGOS

BASE = Path(__file__).resolve().parent


def signed_case_digest(case):
    case = dict(case)
    case.pop('case_sha256', None)
    return hashlib.sha256(json.dumps(case, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class IndependentGoReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('go') is None:
            raise AssertionError('Go toolchain is required for independent process replay')
        cls.owned = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.owned.name) / 'daa-timewarp-verify'
        subprocess.run(['go', 'build', '-o', str(cls.binary), str(BASE / 'daa_timewarp_go/main.go')],
                       check=True, timeout=60, capture_output=True)
        cls.original = {
            'schema': 'pon-daa-timewarp-screen-v1',
            'cases': [find_high_target(Settings(algorithm=a, blocks=48, beam_width=24)) for a in ALGOS],
            'actual_W1': False, 'production_acceptance': False,
        }

    @classmethod
    def tearDownClass(cls):
        cls.owned.cleanup()

    def replay(self, value):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'report.json'
            p.write_text(json.dumps(value, sort_keys=True), encoding='utf8')
            return subprocess.run([str(self.binary), str(p)], capture_output=True, text=True, timeout=15)

    def mutate(self, action):
        report = copy.deepcopy(self.original)
        action(report)
        for case in report['cases']:
            case['case_sha256'] = signed_case_digest(case)
        return report

    def test_clean_go_process_replays_python_legacy_raw_and_mtp(self):
        r = self.replay(self.original)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.count('RESEARCH_REPLAY_OK'),3)

    def test_forged_target_cannot_hide_behind_new_report_hash(self):
        report = self.mutate(lambda x: x['cases'][0]['target_values'].__setitem__(16,
                str(int(x['cases'][0]['target_values'][16])+1)))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('target disagreement',result.stderr)

    def test_fake_accumulated_work_is_refused(self):
        report = self.mutate(lambda x: x['cases'][0].__setitem__('searched_chainwork',
                str(int(x['cases'][0]['searched_chainwork'])+1)))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('chainwork mismatch',result.stderr)

    def test_forged_honest_baseline_is_refused(self):
        report = self.mutate(lambda x: x['cases'][1].__setitem__('honest_final_target',
                str(int(x['cases'][1]['honest_final_target'])+1)))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('invalid honest comparison',result.stderr)

    def test_time_beyond_fixed_future_window_is_refused(self):
        report = self.mutate(lambda x: x['cases'][2]['time_stamps'].__setitem__(48,48*10+121))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('illegal timestamp',result.stderr)

    def test_fabricated_native_w1_claim_is_refused(self):
        report = self.mutate(lambda x: x['cases'][2].__setitem__('full_w1_proofs',1))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('invalid research scope',result.stderr)

    def test_bogus_proof_status_and_unknown_fields_are_refused(self):
        report = self.mutate(lambda x: x['cases'][2].__setitem__('status','native-accepted'))
        self.assertEqual(self.replay(report).returncode,2)
        report = self.mutate(lambda x: x['cases'][0].__setitem__('production_eligible',True))
        r = self.replay(report)
        self.assertEqual(r.returncode,2)
        self.assertIn('unknown field',r.stderr)

    def test_duplicate_algorithm_cannot_pass_three_case_required_set(self):
        report = self.mutate(lambda x: x['cases'][2].__setitem__('algorithm','asert_raw'))
        result = self.replay(report)
        self.assertEqual(result.returncode,2)
        self.assertIn('duplicate algorithm',result.stderr)

    def test_all_four_half_lives_cross_language_replay(self):
        for half_life in (3600, 7200, 14400, 28800):
            report = {'schema': 'pon-daa-timewarp-screen-v1',
                      'cases': [find_high_target(Settings(algorithm=a, blocks=64,
                                        beam_width=32, half_life=half_life)) for a in ALGOS],
                      'actual_W1': False, 'production_acceptance': False}
            result = self.replay(report)
            self.assertEqual(result.returncode, 0, f'{half_life}: {result.stderr}')
            self.assertEqual(result.stdout.count('RESEARCH_REPLAY_OK'), 3)

    def test_mutated_report_hash_is_refused(self):
        report = copy.deepcopy(self.original)
        report['cases'][0]['case_sha256'] = '0'*64
        r = self.replay(report)
        self.assertEqual(r.returncode,2)
        self.assertIn('SHA mismatch',r.stderr)

if __name__=='__main__':unittest.main()
