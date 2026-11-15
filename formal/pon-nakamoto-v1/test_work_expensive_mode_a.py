"""Chronology, replay, independent W1 and journal rollback adversarial controls."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from work_oracle import CELLS, field_bytes, prove, task_id
from work_expensive_mode_a import (
    MAX_EVENTS, MAX_IDEAL_ENVELOPE_EXACT_BITS, ModeAResearch, PROFILE, SCHEMA,
    family_id, ideal_selection_envelope,
)

PARENT = 'a1' * 32
SEED = '17' * 32
RECEIPT = '23' * 32
ZERO = [0] * CELLS


def fixture_contract(tag=0):
    def h(value):
        return hashlib.sha256(value.encode()).hexdigest()
    return dict(profile=PROFILE, task=task_id(ZERO, ZERO).hex(),
        model=h('model'), cell=h('cell'), generation=3, state_before=h('state'),
        transition=h('transition'), input_commitment=h('input'),
        request_commitment=h('request-' + str(tag)), route_commitment=h('routes'),
        shape=[3, 257, 64], numeric_contract=h('int257'), output_contract=h('output'))


def frozen(*, target='ff' * 32, max_candidates=8, max_per_actor=4,
           allowed_cycles=1, attempts_per_cycle=4096):
    machine = ModeAResearch(target_hex=target, max_candidates=max_candidates,
                            max_per_actor=max_per_actor, allowed_cycles=allowed_cycles,
                            attempts_per_cycle=attempts_per_cycle)
    machine.open_round(1, PARENT, 'public', 10, 100, 10000)
    reg = machine.register('miner', fixture_contract(), 20, 31, 37)
    receipt = machine.freeze(30)
    return machine, reg, receipt


def challenged(**kwargs):
    machine, reg, frozen_receipt = frozen(**kwargs)
    reveal = machine.reveal(SEED, RECEIPT, 100)
    return machine, reg, frozen_receipt, reveal


def complete_valid(machine, reg, *, now=110, cycle=0, nonce=0):
    challenge = bytes.fromhex(machine.challenge(reg, cycle, nonce))
    proof = prove(challenge, ZERO, ZERO)
    trial = machine.record_attempt(reg, cycle, nonce, proof[-32:].hex(), now, 101, 203)
    return proof, trial


class ChronologyTests(unittest.TestCase):
    def test_complete_configuration_is_bound_before_fresh_reveal(self):
        def run(**kwargs):
            m = ModeAResearch(**kwargs)
            m.open_round(1, PARENT, 'public', 10, 100, 10000)
            m.register('miner', fixture_contract(), 20, 31, 37)
            receipt = m.freeze(30)
            reveal = m.reveal(SEED, RECEIPT, 100)
            return m, receipt, reveal
        original, frozen_receipt, reveal = run()
        for changed in ({'allowed_cycles': 2}, {'attempts_per_cycle': 20},
                        {'target_hex': '07'+'ff'*31}, {'challenge_owner': 'owner-two'},
                        {'max_candidates': 9}, {'max_per_actor': 3}, {'max_events': 8192}):
            with self.subTest(changed=changed):
                _, other_frozen, other_reveal = run(**changed)
                self.assertEqual(other_frozen['candidate_root'], frozen_receipt['candidate_root'])
                self.assertNotEqual(other_frozen['configuration_commitment'],
                                    frozen_receipt['configuration_commitment'])
                self.assertNotEqual(other_reveal['seed'], reveal['seed'])
        self.assertEqual(frozen_receipt['configuration_commitment'], original.configuration_commitment())
        detached = original.config
        detached.update(target_hex='ff'*32, allowed_cycles=64, challenge_owner='attacker')
        self.assertEqual(original.config['allowed_cycles'], 1)
        self.assertEqual(original.config['target_hex'], '7f'+'ff'*31)
        self.assertEqual(original.config['challenge_owner'], 'external-owner')
        with self.assertRaises(AttributeError):
            original.config = detached

    def test_search_bounds_refuse_extra_cycles_and_boolean_counts(self):
        for kwargs in ({'allowed_cycles': 0}, {'allowed_cycles': 65}, {'allowed_cycles': True},
                       {'attempts_per_cycle': 0}, {'attempts_per_cycle': 4097},
                       {'attempts_per_cycle': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ModeAResearch(**kwargs)
        m, reg, _, _ = challenged()
        with self.assertRaisesRegex(ValueError, 'CYCLE'):
            m.record_attempt(reg, 1, 0, '12'*32, 110, 1, 1)
        with self.assertRaisesRegex(ValueError, 'NONCE'):
            m.record_attempt(reg, 0, 4096, '12'*32, 111, 1, 1)
        self.assertEqual(m.summary()['completed_attempts'], 0)

    def test_cycle_skipping_and_post_hit_grinding_are_refused_but_withheld_hits_count(self):
        m, reg, _, _ = challenged(allowed_cycles=2, attempts_per_cycle=3)
        with self.assertRaisesRegex(ValueError, 'PREVIOUS_CYCLE_INCOMPLETE'):
            m.record_attempt(reg, 1, 0, '12'*32, 110, 1, 1)
        # Reported hash hits are search endpoints; only submit can turn one into
        # independently scalar-verified work. Withholding does not refund cost.
        m.record_attempt(reg, 0, 0, '12'*32, 111, 13, 17)
        with self.assertRaisesRegex(ValueError, 'CYCLE_ALREADY_TERMINAL'):
            m.record_attempt(reg, 0, 1, '13'*32, 112, 1, 1)
        m.record_attempt(reg, 1, 0, '14'*32, 113, 19, 23)
        closed = m.close(114)
        self.assertTrue(closed['declared_searches_complete'])
        self.assertEqual(closed['terminal_searches'], 2)
        self.assertEqual(closed['unfinished_searches'], [])
        summary = m.summary()
        self.assertEqual(summary['hit_unsubmitted_attempts'], 2)
        self.assertEqual(summary['qualified_unique_work'], 0)
        self.assertEqual(summary['producer_cpu_ns'], 32)
        self.assertFalse(summary['undisclosed_work_excluded'])

    def test_exhaustion_advances_only_after_the_whole_attempt_cap(self):
        m, reg, _, _ = challenged(target='00'*31+'01', allowed_cycles=2, attempts_per_cycle=2)
        def miss(cycle, nonce, now):
            challenge = bytes.fromhex(m.challenge(reg, cycle, nonce))
            trace = bytes([cycle*2+nonce+1])*32
            self.assertGreater(H('ticket', challenge, trace), bytes.fromhex(m.config['target_hex']))
            m.record_attempt(reg, cycle, nonce, trace.hex(), now, 5, 7)
        miss(0, 0, 110)
        with self.assertRaisesRegex(ValueError, 'PREVIOUS_CYCLE_INCOMPLETE'):
            m.record_attempt(reg, 1, 0, '12'*32, 111, 1, 1)
        miss(0, 1, 112)
        miss(1, 0, 113)
        closed = m.close(114)
        self.assertFalse(closed['declared_searches_complete'])
        self.assertEqual(closed['terminal_searches'], 1)
        self.assertEqual([(r['cycle'], r['status'], r['attempts'])
                          for r in closed['unfinished_searches']], [(1, 'searching', 1)])
        self.assertEqual(m.summary()['producer_cpu_ns'], 15)
        self.assertEqual(m.summary()['losing_attempts'], 3)

    def test_close_enumerates_unstarted_cycles_instead_of_claiming_completion(self):
        m, reg, _, _ = challenged(allowed_cycles=3)
        m.record_attempt(reg, 0, 0, '12'*32, 110, 7, 11)
        closed = m.close(111)
        self.assertFalse(closed['declared_searches_complete'])
        self.assertEqual([(r['cycle'], r['status'], r['attempts'])
                          for r in closed['unfinished_searches']],
                         [(1, 'not-started', 0), (2, 'not-started', 0)])
        self.assertEqual(m.summary()['round_search_census']['1']['unfinished_searches'],
                         closed['unfinished_searches'])

    def test_every_named_contract_part_is_immutable_after_freeze(self):
        machine, reg, _ = frozen()
        original = fixture_contract()
        for field in original:
            modified = deepcopy(original)
            if field == 'profile':
                modified[field] = 'grouped-unimplemented'
            elif field == 'generation':
                modified[field] += 1
            elif field == 'shape':
                modified[field][2] += 1
            else:
                modified[field] = '99' * 32
            with self.subTest(field=field), self.assertRaises(ValueError):
                machine.check_frozen(reg, modified)
        detached = machine.contract(reg)
        detached['shape'][0] = 99
        self.assertEqual(machine.contract(reg), original)
        self.assertTrue(machine.check_frozen(reg, original))

    def test_native_seed_binds_candidate_set_parent_branch_round_and_cutoff(self):
        first, _, receipt, reveal = challenged()
        self.assertNotEqual(reveal['seed'], SEED)
        for field, changed in [('parent_hex', 'b2'*32), ('branch', 'private'),
                               ('round_id', 2), ('cutoff_ns', 101)]:
            args = dict(round_id=1, parent_hex=PARENT, branch='public',
                        now_ns=10, cutoff_ns=100, expiry_ns=10000)
            args[field] = changed
            m = ModeAResearch(target_hex='ff'*32)
            m.open_round(**args)
            m.register('miner', fixture_contract(), 20, 31, 37)
            m.freeze(30)
            other = m.reveal(SEED, RECEIPT, 101)
            self.assertNotEqual(other['seed'], reveal['seed'])
        self.assertEqual(first.summary()['waiting_wall_ns'], 70)
        self.assertEqual(receipt['candidate_count'], 1)

    def test_challenge_before_freeze_and_before_cutoff_refused(self):
        m = ModeAResearch()
        m.open_round(1, PARENT, 'public', 10, 100, 200)
        m.register('miner', fixture_contract(), 20)
        with self.assertRaisesRegex(ValueError, 'PHASE_FROZEN'):
            m.reveal(SEED, RECEIPT, 21)
        m.freeze(30)
        with self.assertRaisesRegex(ValueError, 'REVEAL_WINDOW'):
            m.reveal(SEED, RECEIPT, 99)
        m.reveal(SEED, RECEIPT, 100)
        self.assertEqual(m.summary()['refused_events'], 2)

    def test_postchallenge_commitment_grinding_is_refused_and_cost_is_retained(self):
        m, _, _, _ = challenged()
        with self.assertRaisesRegex(ValueError, 'PHASE_OPEN'):
            m.register('miner', fixture_contract(2), 110, 7, 13)
        summary = m.summary()
        self.assertEqual(summary['successful_registrations'], 1)
        self.assertEqual(summary['registration_calls'], 2)
        self.assertEqual(summary['preparation_cpu_ns'], 38)
        self.assertEqual(summary['preparation_wall_ns'], 50)

    def test_global_flood_cap_and_actor_cap_are_distinct_from_sybil_resistance(self):
        m = ModeAResearch(max_candidates=2, max_per_actor=1)
        m.open_round(1, PARENT, 'public', 1, 100, 1000)
        m.register('one', fixture_contract(0), 2, 10, 11)
        with self.assertRaisesRegex(ValueError, 'ACTOR_LIMIT'):
            m.register('one', fixture_contract(1), 3, 20, 21)
        m.register('sybil-two', fixture_contract(1), 4, 30, 31)
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_LIMIT'):
            m.register('sybil-three', fixture_contract(2), 5, 40, 41)
        m.freeze(6)
        m.reveal(SEED, RECEIPT, 100)
        closed = m.close(110)
        self.assertEqual(len(closed['unsubmitted_candidates']), 2)
        self.assertEqual(m.summary()['preparation_cpu_ns'], 100)
        self.assertFalse(m.summary()['sybil_resistance_verified'])

    def test_duplicate_family_cannot_multiply_candidates_by_new_actor(self):
        m = ModeAResearch(max_candidates=4)
        m.open_round(1, PARENT, 'public', 1, 100, 1000)
        m.register('one', fixture_contract(), 2)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_FAMILY'):
            m.register('two', fixture_contract(), 3)
        self.assertEqual(m.summary()['successful_registrations'], 1)

    def test_round_time_and_owner_observations_cannot_rewind(self):
        m, _, _, _ = challenged()
        m.close(120)
        with self.assertRaisesRegex(ValueError, 'ROUND_REWIND'):
            m.open_round(1, PARENT, 'public', 121, 200, 1000)
        with self.assertRaisesRegex(ValueError, 'CLOCK_REWIND'):
            m.open_round(2, PARENT, 'public', 119, 200, 1000)
        m.open_round(2, PARENT, 'public', 122, 200, 1000)
        m.register('miner', fixture_contract(), 123)
        m.freeze(124)
        with self.assertRaisesRegex(ValueError, 'OWNER_SEQUENCE_REWIND'):
            m.reveal('18'*32, '24'*32, 200, 1)
        with self.assertRaisesRegex(ValueError, 'OWNER_RECEIPT_REPLAY'):
            m.reveal('18'*32, RECEIPT, 201, 2)
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_SEED_REUSE'):
            m.reveal(SEED, '24'*32, 202, 2)
        with self.assertRaisesRegex(ValueError, 'OWNER_MISMATCH'):
            m.reveal('18'*32, '24'*32, 203, 2, 'self-selected')
        m.reveal('18'*32, '24'*32, 204, 2)

    def test_expiry_is_checked_before_relation_cost(self):
        m, reg, _, _ = challenged()
        with patch('work_expensive_mode_a.verify', side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(ValueError, 'SUBMISSION_EXPIRED'):
                m.submit(reg, 0, 0, '', PARENT, 'public', 10000)

    def test_lottery_envelope_labels_selection_and_independence_assumptions(self):
        one = ideal_selection_envelope('7f'+'ff'*31, 1, 1)
        many = ideal_selection_envelope('7f'+'ff'*31, 4, 2)
        self.assertEqual(Fraction(one['numerator'], one['denominator']), Fraction(1, 2))
        self.assertEqual(Fraction(many['numerator'], many['denominator']), Fraction(255, 256))
        self.assertIn('not a security bound', many['assumption'])

    def test_lottery_exact_bit_budget_is_checked_before_any_large_power(self):
        # T=1 gives miss=(2^255-1)/2^255, denominator.bit_length()=256.
        # Test both sides of the exact bound without computing either power.
        target = '00'*31+'01'
        self.assertEqual(MAX_IDEAL_ENVELOPE_EXACT_BITS, 4096*256)
        with patch.object(Fraction, '__pow__', return_value=Fraction(0)) as power:
            ideal_selection_envelope(target, 4096, 1)
            power.assert_called_once_with(4096)
        with patch.object(Fraction, '__pow__', side_effect=AssertionError('large power must not run')) as power:
            for seed_choices, candidates in ((17, 241), (4096, 4096)):
                with self.subTest(seed_choices=seed_choices, candidates=candidates):
                    self.assertGreater(seed_choices*candidates*256, MAX_IDEAL_ENVELOPE_EXACT_BITS)
                    with self.assertRaisesRegex(ValueError, '^IDEAL_ENVELOPE_EXACT_BUDGET$'):
                        ideal_selection_envelope(target, seed_choices, candidates)
            power.assert_not_called()

    def test_grouped_relation_is_not_faked_by_mode_a_chronology(self):
        m = ModeAResearch()
        m.open_round(1, PARENT, 'public', 1, 100, 1000)
        contract = fixture_contract(); contract['profile'] = 'pon-routed-int257-grouped-research-v0'
        with self.assertRaisesRegex(ValueError, 'RELATION_PROFILE_NOT_IMPLEMENTED'):
            m.register('miner', contract, 2)
        self.assertEqual(m.summary()['successful_registrations'], 0)


class NativeRelationAndIdentityTests(unittest.TestCase):
    def test_actual_w1_acceptance_duplicate_proof_representation_and_parent_replay(self):
        m, reg, _, _ = challenged()
        proof, trial = complete_valid(m, reg)
        self.assertTrue(trial['target_hit'])
        with patch('work_expensive_mode_a.verify', side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(ValueError, 'PARENT_BRANCH_REPLAY'):
                m.submit(reg, 0, 0, proof.hex(), 'b2'*32, 'public', 111)
            with self.assertRaisesRegex(ValueError, 'PARENT_BRANCH_REPLAY'):
                m.submit(reg, 0, 0, proof.hex(), PARENT, 'private', 112)
        accepted = m.submit(reg, 0, 0, proof.hex(), PARENT, 'public', 113)
        self.assertTrue(accepted['scalar_w1_verified'])
        self.assertFalse(accepted['native_node_accepted'])
        # Proof randomness/bytes cannot become another work identity.
        for candidate in (proof.hex(), proof.hex()[:-2]+'17'):
            with patch('work_expensive_mode_a.verify', side_effect=AssertionError('must not run')):
                with self.assertRaisesRegex(ValueError, 'DUPLICATE_WORK'):
                    m.submit(reg, 0, 0, candidate, PARENT, 'public', 114)
        self.assertEqual(m.summary()['qualified_unique_work'], 1)

    def test_shared_task_across_two_cells_cannot_duplicate_same_work(self):
        m = ModeAResearch(target_hex='ff'*32)
        m.open_round(1, PARENT, 'public', 10, 100, 1000)
        first_contract = fixture_contract()
        second_contract = fixture_contract(1)
        second_contract['cell'] = 'cd'*32
        first = m.register('miner-a', first_contract, 20)
        second = m.register('miner-b', second_contract, 21)
        m.freeze(30); m.reveal(SEED, RECEIPT, 100)
        self.assertNotEqual(family_id(first_contract), family_id(second_contract))
        self.assertEqual(m.challenge(first, 0, 0), m.challenge(second, 0, 0))
        proof, _ = complete_valid(m, first, now=110)
        m.record_attempt(second, 0, 0, proof[-32:].hex(), 111, 3, 5)
        m.submit(first, 0, 0, proof.hex(), PARENT, 'public', 112)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_WORK'):
            m.submit(second, 0, 0, proof.hex(), PARENT, 'public', 113)
        self.assertEqual(m.summary()['qualified_unique_work'], 1)
        self.assertEqual(m.summary()['completed_attempts'], 2)

    def test_hash_hit_forged_trace_is_not_verified_work(self):
        m, reg, _, _ = challenged()
        trace = '55'*32
        m.record_attempt(reg, 0, 0, trace, 110, 5, 7)
        proof = b'PNW1' + field_bytes(ZERO) * 3 + bytes.fromhex(trace)
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            m.submit(reg, 0, 0, proof.hex(), PARENT, 'public', 111)
        summary = m.summary()
        self.assertEqual(summary['qualified_unique_work'], 0)
        self.assertEqual(summary['completed_attempts'], 1)
        self.assertEqual(summary['hit_unsubmitted_attempts'], 1)

    def test_correct_trace_wrong_output_is_rejected(self):
        m, reg, _, _ = challenged()
        proof, _ = complete_valid(m, reg)
        changed = bytearray(proof)
        changed[4+8*CELLS:8+8*CELLS] = (1).to_bytes(4, 'little')
        with self.assertRaisesRegex(ValueError, 'PRODUCT'):
            m.submit(reg, 0, 0, changed.hex(), PARENT, 'public', 111)
        self.assertEqual(m.summary()['qualified_unique_work'], 0)

    def test_losing_attempts_cannot_be_omitted_or_counted_as_winners(self):
        m, reg, _, _ = challenged(target='01'+'ff'*31)
        proof, trial = complete_valid(m, reg)
        self.assertFalse(trial['target_hit'])
        with self.assertRaisesRegex(ValueError, 'MISSING_COMPLETED_ATTEMPTS'):
            m.record_attempt(reg, 0, 2, proof[-32:].hex(), 111, 13, 17)
        with self.assertRaisesRegex(ValueError, 'LOSING_TICKET'):
            m.submit(reg, 0, 0, proof.hex(), PARENT, 'public', 112)
        m.close(113)
        summary = m.summary()
        self.assertEqual(summary['losing_attempts'], 1)
        self.assertEqual(summary['producer_cpu_ns'], 101)
        self.assertEqual(summary['qualified_unique_work'], 0)
        self.assertEqual(len(summary['unsubmitted_candidates']['1']), 1)

    def test_two_challenges_one_application_and_reorg_never_sums_scopes(self):
        m, reg, _, _ = challenged()
        first, _ = complete_valid(m, reg)
        a = m.submit(reg, 0, 0, first.hex(), PARENT, 'public', 111)
        m.close(120)
        other_parent = 'b2'*32
        m.open_round(2, other_parent, 'private', 121, 200, 10000)
        other_reg = m.register('miner', fixture_contract(), 122, 10, 11)
        m.freeze(123); m.reveal('18'*32, '24'*32, 200, 2)
        second, _ = complete_valid(m, other_reg, now=210)
        b = m.submit(other_reg, 0, 0, second.hex(), other_parent, 'private', 211)
        self.assertNotEqual(a['work_id'], b['work_id'])
        self.assertEqual(a['application_outcome_id'], b['application_outcome_id'])
        self.assertTrue(a['application_first_observation'])
        self.assertFalse(b['application_first_observation'])
        m.close(220)
        public = m.select_scope(PARENT, 'public', 221)
        private = m.select_scope(other_parent, 'private', 222)
        self.assertEqual(public['qualified_target_weight'], 1)
        self.assertEqual(private['qualified_target_weight'], 1)
        summary = m.summary()
        self.assertEqual(summary['qualified_unique_work'], 2)
        self.assertEqual(summary['unique_application_outcomes'], 1)
        self.assertEqual(summary['selected_scope_weight'], 1)
        self.assertFalse(summary['parent_ancestry_verified'])
        self.assertFalse(summary['universal_cost_lower_bound'])


class PersistenceTests(unittest.TestCase):
    def test_five_full_search_plans_fit_a_configurable_bounded_journal(self):
        # open + five registrations + freeze + reveal + worst-case attempts +
        # at most five submits + close + scope selection. Refused extra API
        # calls consume their own capacity; this bound does not erase them.
        worst_planned_events = 1 + 5 + 1 + 1 + 5*4096 + 5 + 1 + 1
        m = ModeAResearch(max_candidates=5, max_per_actor=5, max_events=32768)
        self.assertLessEqual(worst_planned_events, m.summary()['journal_capacity_remaining'])
        self.assertEqual(m.config['max_events'], MAX_EVENTS)
        self.assertEqual(ModeAResearch().config['max_events'], 4096)
        self.assertIn('never a total budget B', m.summary()['cost_scope'])
        with self.assertRaisesRegex(ValueError, 'MAX_EVENTS'):
            ModeAResearch(max_events=32769)

    def test_restart_preserves_terminal_search_and_frozen_configuration(self):
        m, reg, _, _ = challenged(allowed_cycles=2, attempts_per_cycle=2)
        m.record_attempt(reg, 0, 0, '12'*32, 110, 7, 11)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'journal.json'
            checkpoint = m.save(path)
            restored = ModeAResearch.restore(path, checkpoint)
            self.assertEqual(restored.config, m.config)
            with self.assertRaisesRegex(ValueError, 'CYCLE_ALREADY_TERMINAL'):
                restored.record_attempt(reg, 0, 1, '13'*32, 111, 1, 1)
            restored.record_attempt(reg, 1, 0, '14'*32, 112, 13, 17)
            self.assertTrue(restored.close(113)['declared_searches_complete'])
            value = json.loads(path.read_bytes())
            value['config']['allowed_cycles'] = 3
            path.write_bytes(canonical(value)+b'\n')
            with self.assertRaisesRegex(ValueError, 'EVENT_ORDER'):
                ModeAResearch.restore(path, checkpoint)

    def test_roundtrip_and_native_verified_work_replay(self):
        m, reg, _, _ = challenged()
        proof, _ = complete_valid(m, reg)
        m.submit(reg, 0, 0, proof.hex(), PARENT, 'public', 111)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'journal.json'
            checkpoint = m.save(path)
            restored = ModeAResearch.restore(path, checkpoint)
            self.assertEqual(restored.summary(), m.summary())
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_WORK'):
                restored.submit(reg, 0, 0, proof.hex(), PARENT, 'public', 112)

    def test_truncation_old_snapshot_and_rewritten_receipt_rejected(self):
        m, _, _, _ = challenged()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'journal.json'
            old = m.save(path)
            original = path.read_bytes()
            m.close(110)
            current = m.checkpoint()
            with self.assertRaisesRegex(ValueError, 'CHECKPOINT_MISMATCH'):
                ModeAResearch.restore(path, current)
            path.write_bytes(original[:-20])
            with self.assertRaises(ValueError):
                ModeAResearch.restore(path, old)
            value = json.loads(original)
            value['events'] = value['events'][:-1]
            path.write_bytes(canonical(value)+b'\n')
            with self.assertRaisesRegex(ValueError, 'JOURNAL_TRUNCATED'):
                ModeAResearch.restore(path, old)
            value = json.loads(original)
            value['events'][1]['payload']['preparation_cpu_ns'] = 0
            path.write_bytes(canonical(value)+b'\n')
            with self.assertRaisesRegex(ValueError, 'EVENT_DIGEST'):
                ModeAResearch.restore(path, old)

    def test_restore_requires_external_anchor_and_retains_refusals(self):
        m, _, _, _ = challenged()
        with self.assertRaises(ValueError):
            m.register('miner', fixture_contract(2), 110, 7, 9)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'journal.json'
            checkpoint = m.save(path)
            with self.assertRaisesRegex(ValueError, 'EXTERNAL_CHECKPOINT_REQUIRED'):
                ModeAResearch.restore(path, None)
            restored = ModeAResearch.restore(path, checkpoint)
            self.assertEqual(restored.summary(), m.summary())

    def test_boolean_alias_and_unknown_contract_fields_refused(self):
        m = ModeAResearch()
        m.open_round(1, PARENT, 'public', 1, 100, 1000)
        value = fixture_contract(); value['generation'] = True
        with self.assertRaisesRegex(ValueError, 'GENERATION'):
            m.register('miner', value, 2)
        value = fixture_contract(); value['grinding_salt'] = 1
        with self.assertRaisesRegex(ValueError, 'CONTRACT_FIELDS'):
            m.register('miner', value, 3)

    def test_event_capacity_is_a_terminal_explicit_refusal(self):
        m = ModeAResearch(max_events=1)
        m.open_round(1, PARENT, 'public', 1, 100, 1000)
        with self.assertRaisesRegex(ValueError, 'JOURNAL_EVENT_LIMIT'):
            m.register('miner', fixture_contract(), 2)
        self.assertEqual(m.checkpoint()['event_count'], 1)


if __name__ == '__main__':
    unittest.main()
