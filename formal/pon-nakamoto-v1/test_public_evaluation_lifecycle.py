"""Signed lifecycle deadlines, conflicts and immutable appeals; not evaluator truth."""
from __future__ import annotations
import copy
import itertools
import unittest
from contract_wire import H, canonical
from ledger import key, public
from public_evaluation_lifecycle import *


def identity(value):
    return H('public-evaluation-test-v1', value.encode()).hex()


class PublicLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.keys = [key(200+i) for i in range(4)]
        self.roster = {public(k).hex(): identity('source'+str(i)) for i, k in enumerate(self.keys[:3])}
        self.authors = {public(self.keys[3]).hex(): identity('author-source')}
        self.raw, self.digest = freeze_round(round_number=1, parent_artifact=identity('parent'), family=identity('family'),
            task_root=identity('tasks'), model_contract=identity('adapter-contract'), roster=self.roster, authors=self.authors,
            expected_admission_root=admission_root(self.roster, self.authors), start=0, candidate_end=5, commit_end=10, reveal_end=15)
        self.round = PublicEvaluationRound(self.raw, self.digest)
        source = self.authors[public(self.keys[3]).hex()]
        self.candidate = candidate_identity(self.digest, identity('artifact'), source, identity('components'))
        self.candidate_record = signed_record(self.keys[3], phase='candidate', round_digest=self.digest,
            candidate=self.candidate, payload=dict(artifact=identity('artifact'), source=source, components=identity('components')))
        self.round.intake(self.candidate_record, height=1)

    def payload(self, score, salt='salt'):
        return dict(score=score, task_root=identity('tasks'), model_contract=identity('adapter-contract'),
                    evaluation_result=identity('actual-owner-result'+str(score)), salt=identity(salt))

    def commit(self, index, score, salt='salt'):
        return signed_record(self.keys[index], phase='commit', round_digest=self.digest, candidate=self.candidate,
                             payload=dict(commitment=reveal_commitment(self.payload(score, salt))))

    def reveal(self, index, score, salt='salt'):
        return signed_record(self.keys[index], phase='reveal', round_digest=self.digest, candidate=self.candidate,
                             payload=self.payload(score, salt))

    def complete(self, values=(10,100,100), order=(0,1,2)):
        for i in order: self.round.intake(self.commit(i, values[i]), height=6)
        for i in order: self.round.intake(self.reveal(i, values[i]), height=11)
        return self.round.close(height=16)

    def test_all_reveal_orders_have_same_complete_score_and_no_magic_reward(self):
        for order in itertools.permutations(range(3)):
            self.setUp(); result = self.complete(order=order)
            self.assertEqual(result['score'], 10)
            self.assertEqual(result['status'], 'complete-scored')
            self.assertTrue(result['eligible_for_external_owner_review'])
            self.assertFalse(result['adoption_authorized']); self.assertFalse(result['reward_authorized'])
            self.assertFalse(result['objective_result_replayed'])

    def test_missing_reveal_explicitly_aborts_no_synthetic_timeout_vote(self):
        for i in range(3): self.round.intake(self.commit(i, 100), height=6)
        for i in range(2): self.round.intake(self.reveal(i, 100), height=11)
        result = self.round.close(height=16)
        self.assertEqual(result['status'], 'aborted'); self.assertIsNone(result['score'])
        self.assertEqual(result['missing_reveals'], [public(self.keys[2]).hex()])
        self.assertFalse(result['eligible_for_external_owner_review'])

    def test_zero_reveal_remains_zero_and_not_adoption(self):
        result = self.complete((0,100,100))
        self.assertEqual(result['score'], 0); self.assertFalse(result['eligible_for_external_owner_review'])

    def test_deadline_phase_boundaries_and_height_rewind_reject(self):
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_PHASE'): self.round.intake(self.commit(0, 10), height=5)
        self.round.intake(self.commit(0, 10), height=10)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_PHASE'): self.round.intake(self.reveal(0, 10), height=10)
        self.round.intake(self.reveal(0, 10), height=15)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_HEIGHT'): self.round.intake(self.reveal(1, 10), height=14)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_CLOSE_PHASE'): self.round.close(height=15)
        self.assertEqual(self.round.close(height=16)['status'], 'aborted')

    def test_reveal_before_commit_or_changed_salt_score_does_not_match(self):
        self.round.intake(self.commit(0, 10), height=6)
        for record in [self.reveal(0, 100), self.reveal(0, 10, 'changed'), self.reveal(1, 10)]:
            with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_COMMITMENT_BINDING'): self.round.intake(record, height=11)
        self.assertEqual(self.round.observation()['reveals'], {})

    def test_author_and_unadmitted_keys_cannot_evaluate(self):
        for signer in (self.keys[3], key(999)):
            record = signed_record(signer, phase='commit', round_digest=self.digest, candidate=self.candidate,
                                   payload=dict(commitment=identity('fake')))
            with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_AUTHORITY'): self.round.intake(record, height=6)

    def test_signed_commit_equivocation_is_saved_and_current_roster_not_rewritten(self):
        first = self.commit(0, 10); second = self.commit(0, 100)
        self.round.intake(first, height=6)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_EQUIVOCATION'): self.round.intake(second, height=6)
        observed = self.round.observation()
        self.assertEqual(observed['frozen_roster'], self.roster)
        self.assertEqual(self.round.next_round_disqualified_keys(), [public(self.keys[0]).hex()])
        evidence = next(iter(observed['equivocations'].values()))
        self.assertEqual(evidence['records'], sorted([first,second], key=canonical))
        self.assertEqual(self.round.close(height=16)['status'], 'aborted')

    def test_late_signed_conflict_cannot_rewrite_closed_result(self):
        closed = self.complete()
        self.round.submit_equivocation(self.commit(0, 10), self.commit(0, 100))
        self.assertEqual(self.round.close(height=17), closed)
        self.assertEqual(self.round.next_round_disqualified_keys(), [public(self.keys[0]).hex()])

    def test_forged_identical_or_cross_signer_conflict_is_not_evidence(self):
        first, second = self.commit(0, 10), self.commit(0, 100)
        bad = copy.deepcopy(second); bad['signature'] = '00'*64
        for a,b,code in [(first,bad,'PUBLIC_EVAL_SIGNATURE'), (first,first,'PUBLIC_EVAL_NOT_EQUIVOCATION'),
                         (first,self.commit(1,100),'PUBLIC_EVAL_EQUIVOCATION_CONTEXT')]:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code): self.round.submit_equivocation(a,b)
        self.assertEqual(self.round.next_round_disqualified_keys(), [])

    def test_signed_reveal_conflict_is_verifiable_without_trusting_report_value(self):
        self.round.submit_equivocation(self.reveal(0, 10), self.reveal(0, 100))
        self.assertEqual(self.round.next_round_disqualified_keys(), [public(self.keys[0]).hex()])

    def test_appeal_records_evidence_and_never_silently_changes_result(self):
        closed = self.complete()
        result_id = H('public-evaluation-closed-result-v1', canonical(closed)).hex()
        record = signed_record(self.keys[3], phase='appeal', round_digest=self.digest, candidate=self.candidate,
            payload=dict(result=result_id, claim=identity('objection'), evidence=identity('supporting-artifact')))
        self.assertEqual(self.round.intake(record, height=17), 'appeal-recorded-current-result-unchanged')
        self.assertEqual(self.round.close(height=18), closed)
        self.assertEqual(len(self.round.observation()['appeals']), 1)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_APPEAL_REPLAY'): self.round.intake(record, height=19)

    def test_other_round_parent_task_and_numeric_aliases_reject(self):
        changed = self.reveal(0, 10); changed['record']['round'] = identity('other-round')
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_MESSAGE_CONTEXT'): self.round.intake(changed, height=11)
        for mutation, code in [(lambda p:p.update(task_root=identity('other-task')), 'PUBLIC_EVAL_REVEAL_CONTEXT'),
                                (lambda p:p.update(model_contract=identity('other-model')), 'PUBLIC_EVAL_REVEAL_CONTEXT'),
                                (lambda p:p.update(score=True), 'PUBLIC_EVAL_SCORE')]:
            payload = self.payload(10); mutation(payload)
            record = signed_record(self.keys[0], phase='reveal', round_digest=self.digest, candidate=self.candidate, payload=payload)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code): self.round.intake(record, height=11)

    def test_mutable_downloaded_roster_cannot_replace_expected_owner_root(self):
        raw = self.raw.replace(identity('source0').encode(), identity('attacker-source').encode())
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_ROUND_IDENTITY'): PublicEvaluationRound(raw, self.digest)
        exposed = self.round.plan; exposed['roster'].clear()
        self.assertEqual(self.round.plan['roster'], self.roster)

    def test_owner_admitted_same_lineage_alias_cannot_be_counted_as_two_evaluators(self):
        aliased = dict(self.roster); aliased[public(self.keys[1]).hex()] = aliased[public(self.keys[0]).hex()]
        with self.assertRaisesRegex(ValueError, 'PUBLIC_EVAL_LINEAGE_ALIAS'):
            freeze_round(round_number=2, parent_artifact=identity('parent'), family=identity('family'),
                task_root=identity('tasks'), model_contract=identity('model'), roster=aliased, authors=self.authors,
                expected_admission_root=admission_root(aliased,self.authors), start=20,candidate_end=25,commit_end=30,reveal_end=35)

    def test_missing_candidate_and_duplicate_closed_calls_are_explicit(self):
        empty = PublicEvaluationRound(self.raw,self.digest)
        result = empty.close(height=16)
        self.assertEqual(result['status'],'aborted'); self.assertIsNone(result['candidate'])
        self.assertEqual(empty.close(height=17), result)
        with self.assertRaisesRegex(ValueError,'PUBLIC_EVAL_CLOSED'): empty.intake(self.candidate_record,height=18)

    def test_next_round_freeze_enforces_signed_fault_and_known_lineage_alias_exclusion(self):
        closed = self.complete()
        self.round.submit_equivocation(self.commit(0, 10), self.commit(0, 100))
        kwargs = dict(round_number=2, parent_artifact=identity('parent'), family=identity('family'),
            task_root=identity('new-tasks'), model_contract=identity('adapter-contract'), roster=dict(self.roster),
            authors=self.authors, expected_admission_root=admission_root(self.roster,self.authors),
            start=20,candidate_end=25,commit_end=30,reveal_end=35)
        with self.assertRaisesRegex(ValueError,'PUBLIC_EVAL_NEXT_ROUND_DISQUALIFIED'):
            freeze_successor_round(self.round,**kwargs)
        offender = public(self.keys[0]).hex(); lineage = kwargs['roster'].pop(offender)
        kwargs['roster'][public(key(888)).hex()] = lineage
        with self.assertRaisesRegex(ValueError,'PUBLIC_EVAL_NEXT_ROUND_DISQUALIFIED'):
            freeze_successor_round(self.round,**kwargs)
        del kwargs['roster'][public(key(888)).hex()]
        kwargs['expected_admission_root'] = admission_root(kwargs['roster'],self.authors)
        raw, digest = freeze_successor_round(self.round,**kwargs)
        self.assertEqual(len(PublicEvaluationRound(raw,digest).plan['roster']),2)
        self.assertEqual(self.round.close(height=17),closed)

    def test_successor_cannot_replay_past_phases_after_actual_predecessor_close_and_observation(self):
        self.complete()  # Signed candidate, commits/reveals; closes at height16.
        kwargs = dict(round_number=2,parent_artifact=identity('parent'),family=identity('family'),
            task_root=identity('new-tasks'),model_contract=identity('adapter-contract'),
            roster=self.roster,authors=self.authors,
            expected_admission_root=admission_root(self.roster,self.authors),
            start=0,candidate_end=5,commit_end=10,reveal_end=15)
        for start in (0, 15, True):
            changed = dict(kwargs,start=start)
            with self.subTest(start=start), self.assertRaisesRegex(ValueError,'PUBLIC_EVAL_SUCCESSOR_HEIGHT'):
                freeze_successor_round(self.round,**changed)
        # A later actual confirmed observation matters too; checking only the
        # original close height or old reveal boundary would still permit rewind.
        self.round.close(height=20)
        kwargs.update(start=16,candidate_end=25,commit_end=30,reveal_end=35)
        with self.assertRaisesRegex(ValueError,'PUBLIC_EVAL_SUCCESSOR_HEIGHT'):
            freeze_successor_round(self.round,**kwargs)
        kwargs['start'] = 20
        raw,digest = freeze_successor_round(self.round,**kwargs)
        successor = PublicEvaluationRound(raw,digest)
        source = self.authors[public(self.keys[3]).hex()]
        payload = dict(artifact=identity('next-artifact'),source=source,components=identity('components'))
        record = signed_record(self.keys[3],phase='candidate',round_digest=digest,
            candidate=candidate_identity(digest,**payload),payload=payload)
        self.assertEqual(successor.intake(record,height=20),'candidate-admitted')
        self.assertEqual(successor.observation()['last_confirmed_height_observed'],20)


if __name__ == '__main__':
    unittest.main()
