#!/usr/bin/env python3
"""Static CI controls only; this suite executes no research/native campaign."""
from pathlib import Path
import unittest
from check_ci_contract import check_independent_conformance
ROOT = Path(__file__).resolve().parents[2]
# Independent literals, never imported from the implementation's roster.
COMMANDS = ("python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_evidence_scope.py' -v",
 "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_native_bridge.py' -v",
 'python3 scripts/ci/test_w1_risc0_deep_event_audit.py',
 'python3 scripts/w1_risc0_deep_event_audit.py --repo-root .',
 'python3 scripts/ci/test_w1_p3_sampling_audit.py',
 'python3 scripts/w1_p3_sampling_audit.py',
 'python3 scripts/ci/test_pq_lifetime_composition.py',
 'python3 scripts/ci/pq_lifetime_composition.py',
 'python3 scripts/ci/test_pq_content_chain_review.py',
 'python3 scripts/ci/pq_content_chain_review.py',
 "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_success_query_frontier.py' "
 '-v',
 'python3 formal/pon-nakamoto-v1/fixed_success_query_frontier.py --check',
 "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_cost_tail_transfer.py' -v",
 'python3 formal/pon-nakamoto-v1/cost_tail_transfer.py --check',
 'python3 formal/pon-nakamoto-v1/test_quantum_bernoulli_source_audit.py -v',
 'python3 scripts/ci/test_retained_research_ci.py')
class RetainedResearchLaneTests(unittest.TestCase):
    def setUp(self):
        self.script = (ROOT / 'scripts/ci/ci_job.sh').read_text()
        self.required = {'repository-truth', 'protocol-contract', 'fuzz-smoke', 'rust-baseline', 'external-evidence-contract'}
    def test_normal_lane_keeps_one_exact_straight_line_group(self):
        check_independent_conformance(self.script,self.required)
        block = ''.join('    '+c+'\n' for c in COMMANDS)
        self.assertIn(block+'    python3 scripts/test_qualification_runtime.py\n',self.script)
        for c in COMMANDS:self.assertEqual(self.script.count('    '+c+'\n'),1)
    def test_every_control_rejects_omission_movement_duplication_and_swallowed_failure(self):
        check_independent_conformance(self.script,self.required)
        for c in COMMANDS:
            line='    '+c+'\n'
            variants=[self.script.replace(line,'',1),self.script.replace(line,line*2,1),
                      self.script.replace(line,'    # '+c+'\n',1),
                      self.script.replace(line,'    if false; then\n'+line+'    fi\n',1),
                      self.script.replace(line,line.rstrip()+' || true\n',1),
                      self.script.replace(line,'    if\n'+line+'    then :; fi\n',1),
                      self.script.replace(line,line.rstrip()+' &\n',1),
                      self.script.replace(line,'',1).replace('  fuzz-smoke)\n','  fuzz-smoke)\n'+line,1)]
            for changed in variants:
                with self.subTest(command=c),self.assertRaises(ValueError):
                    check_independent_conformance(changed,self.required)
    def test_group_order_cannot_be_replaced_by_a_set_of_commands(self):
        block=''.join('    '+c+'\n' for c in COMMANDS)
        changed=self.script.replace(block,''.join('    '+c+'\n' for c in reversed(COMMANDS)),1)
        with self.assertRaises(ValueError):check_independent_conformance(changed,self.required)
if __name__=='__main__':unittest.main()
