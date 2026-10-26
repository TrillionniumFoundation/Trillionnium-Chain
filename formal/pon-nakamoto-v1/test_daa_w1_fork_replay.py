"""Real 49,188-byte W1 work replay over a synthetic partition/lease scenario.

This is reference-work verification and fixed protocol target arithmetic, NOT
native consensus, a signed Q4 lease, independently administered WAN, or proof
of profitable timestamp manipulation. Keep these distinctions in reports.
"""
import base64
from copy import deepcopy
import hashlib
import unittest

from contract_wire import H, header_decode, header_encode
from work_oracle import field_bytes, precheck, verify
from daa_w1_fork_replay import (
    A, B, GENESIS, MATERIAL, ROOT_RECEIPT, ROOT_TX, SCHEMA, SPACING, START,
    WorkReplay, campaign, verify_campaign, _required_work,
)


class FullW1ForkResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A short actual-work cohort for ordinary unit tests; default CLI
        # campaign is the full 52-winning-certificate/partition case.
        cls.report = campaign(common=16, on_a=1, on_b=2)

    def test_real_w1_proofs_and_reorg_are_replayed_not_assumed(self):
        state = verify_campaign(self.report, audit_search=True)
        self.assertEqual(len(self.report['events']), 19)
        self.assertEqual(len(state.blocks), 20)
        self.assertEqual(self.report['summary']['real_w1_winning_proofs'], 19)
        self.assertEqual(self.report['summary']['reorg_removed_on_a'], 1)
        self.assertEqual(self.report['summary']['reorg_removed_on_b'], 0)
        self.assertGreater(self.report['summary']['real_w1_prover_attempts'], 19)
        self.assertEqual(self.report['summary']['native_w1_proofs'], 0)
        self.assertFalse(self.report['summary']['native_consensus_activation'])
        self.assertEqual(self.report['summary']['real_lease_signatures'], 0)
        self.assertEqual(state.blocks[state.tip_a].chainwork,
                         state.blocks[state.tip_b].chainwork)

    def test_all_optional_sources_unavailable_remains_explicit_maintenance(self):
        self.assertEqual(self.report['context']['genesis_maintenance_revision'], 12)
        for event in self.report['events']:
            header = header_decode(bytes.fromhex(event['header']))
            self.assertEqual(header['work_task'], MATERIAL)
            self.assertEqual(event['selection'], 'genesis-maintenance')
            self.assertEqual(event['optional_source_available'], event['phase'] == 'shared')
        mutated = deepcopy(self.report)
        mutated['events'][0]['selection'] = 'automatic-task-fallback'
        with self.assertRaisesRegex(ValueError, 'WORK_SELECTION'):
            verify_campaign(mutated)
        mutated = deepcopy(self.report)
        mutated['events'][0]['optional_source_available'] = False
        with self.assertRaisesRegex(ValueError, 'SOURCE_CLAIM'):
            verify_campaign(mutated)

    def test_forged_ticket_has_zero_valid_work_and_cannot_mutate(self):
        state = WorkReplay()
        event = self.report['events'][0]
        raw = bytes.fromhex(event['header'])
        header = header_decode(raw)
        challenge = H('challenge', raw)
        fixed_prefix = b'PNW1' + field_bytes(A) + field_bytes(B) + field_bytes([0] * 4096)
        for counter in range(256):
            digest = hashlib.sha256(b'fake-transcript' + counter.to_bytes(8, 'little')).digest()
            fake = fixed_prefix + digest
            try:
                precheck(challenge, MATERIAL, header['target'], fake)
                break
            except ValueError as ex:
                if str(ex) != 'TARGET':
                    raise
        else:
            self.fail('no cheap ticket match in 256 independent candidate hashes')
        before = (len(state.blocks), state.tip_a, state.tip_b)
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            verify(challenge, MATERIAL, header['target'], fake)
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            state.admit(raw, fake, event['now'])
        self.assertEqual((len(state.blocks), state.tip_a, state.tip_b), before)

    def test_corrupt_proof_target_timestamp_and_parent_fail_closed(self):
        report = self.report
        for change in ('proof', 'target', 'time', 'parent'):
            with self.subTest(change=change):
                modified = deepcopy(report)
                event = modified['events'][0]
                header = header_decode(bytes.fromhex(event['header']))
                if change == 'proof':
                    fake = bytearray(base64.b64decode(event['proof']))
                    fake[-1] ^= 1
                    event['proof'] = base64.b64encode(fake).decode()
                else:
                    if change == 'target':
                        header['target'] = (1).to_bytes(32, 'big')
                    elif change == 'time':
                        event['now'] = START - 500
                    else:
                        header['parent'] = bytes.fromhex('ee' * 32)
                    event['header'] = header_encode(header).hex()
                with self.assertRaises(ValueError):
                    verify_campaign(modified)
        # Search costs are deterministic and can be audited, not silently
        # counted from unverified self-reported attempts.
        tampered = deepcopy(report)
        tampered['events'][0]['attempts'] += 1
        with self.assertRaisesRegex(ValueError, 'ATTEMPT_NONCE'):
            verify_campaign(tampered)

    def test_report_summary_and_strict_context_cannot_grant_authority(self):
        mutated = deepcopy(self.report)
        mutated['summary']['native_w1_proofs'] = 19
        with self.assertRaisesRegex(ValueError, 'SUMMARY'):
            verify_campaign(mutated)
        mutated = deepcopy(self.report)
        mutated['context']['network'] = bytes(32).hex()
        with self.assertRaisesRegex(ValueError, 'CONTEXT'):
            verify_campaign(mutated)
        mutated = deepcopy(self.report)
        mutated['events'][17]['phase'] = 'shared'
        with self.assertRaisesRegex(ValueError, 'OUTAGE_ROLLBACK'):
            verify_campaign(mutated)

    def test_required_work_is_derived_from_validated_expected_target(self):
        state = verify_campaign(self.report)
        for block in state.blocks.values():
            if block.parent is None:
                self.assertEqual(block.chainwork, 0)
            else:
                parent = state.blocks[block.parent]
                self.assertEqual(block.chainwork, parent.chainwork + _required_work(block.target))
                self.assertEqual(block.useful_output_credit, 0)


if __name__ == '__main__':
    unittest.main()
