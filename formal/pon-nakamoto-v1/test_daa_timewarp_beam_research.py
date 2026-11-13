"""Bounded deterministic legal-timestamp beam comparison; no real proof authority."""
import tempfile
import unittest
from pathlib import Path
from daa_timewarp_beam_research import (Settings, ALGOS, honest_path,
                                       find_high_target, valid_time, audit_path, target_at,
                                       chain_work)

class TimestampBeamTests(unittest.TestCase):
    def test_three_researched_rules_are_deterministic_and_replayable(self):
        for algorithm in ALGOS:
            cfg = Settings(algorithm=algorithm, blocks=32, beam_width=16)
            a, b = find_high_target(cfg), find_high_target(cfg)
            self.assertEqual(a["case_sha256"], b["case_sha256"])
            self.assertEqual(a["full_w1_proofs"], 0)
            self.assertEqual(len(a["time_stamps"]), 33)
            self.assertEqual(len(a["target_values"]), 33)
            self.assertGreaterEqual(int(a["evaluated_legal_candidates"]), 32)
    def test_no_time_or_legacy_difficulty_consensus_escape(self):
        for algorithm in ALGOS:
            cfg = Settings(algorithm=algorithm, blocks=48, beam_width=16)
            a = find_high_target(cfg)
            times = a["time_stamps"]
            targets = [int(x) for x in a["target_values"]]
            for h in range(1, len(times)):
                self.assertTrue(valid_time(times[h], tuple(reversed(times[max(0,h-11):h])), h*10, 120))
                self.assertEqual(targets[h], target_at(cfg, tuple(times[:h]), targets[h-1]))
                self.assertTrue(1 <= targets[h] <= cfg.pow_limit)
                if algorithm == 'legacy16' and h % 16 == 0:
                    self.assertLessEqual(targets[h], targets[h-1] * 4)
    def test_chainwork_not_target_is_accounted(self):
        cfg = Settings(algorithm='legacy16', blocks=32, beam_width=24)
        x = find_high_target(cfg)
        self.assertEqual(sum(chain_work(int(t)) for t in x['target_values'][1:]), int(x['searched_chainwork']))
        self.assertGreater(int(x['honest_chainwork']), 0)
    def test_parameter_inputs_reject_unsafe_expansion(self):
        for bad in [Settings('legacy16', blocks=1), Settings('legacy16', beam_width=10000),
                    Settings('asert_raw', half_life=0), Settings('legacy16', spacing=0),
                    Settings('legacy16', initial_target=0), Settings('legacy16', future_skew=-1),
                    Settings('asert_mtp11', beam_width=True), Settings('other')]:
            with self.assertRaises(ValueError): bad.validate()
    def test_honest_unchanged_with_zero_future_skew(self):
        for a in ALGOS:
            s=Settings(algorithm=a, blocks=48, future_skew=0)
            self.assertEqual(len(honest_path(s).times),49)

if __name__=='__main__':unittest.main()
