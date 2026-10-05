"""Independent sparse-boundary and full-state relation controls; no native calls."""
import copy
import unittest

import account_archive_oracle as archive
import account_execution_oracle as application
import state_witness_oracle as oracle


class StateWitnessOracle(unittest.TestCase):
    def setUp(self):
        self.owners = [application.development_public(index) for index in range(12)]
        self.accounts = {owner: archive.Account(1000 + index, index)
                         for index, owner in enumerate(self.owners[:8])}
        self.checkpoint = bytes([79]) * 32
        self.parent = {'account:' + owner.hex(): value.as_json()
                       for owner, value in self.accounts.items()}

    def update(self, next_accounts, owners=None, mutate=None, **options):
        queried = sorted(self.accounts if owners is None else owners)
        root, paths = archive.full_sparse(self.accounts, queried)
        witnesses = [archive.witness_json(self.checkpoint, owner, self.accounts.get(owner), paths[owner])
                     for owner in queried]
        successor = {'account:' + owner.hex(): value.as_json()
                     for owner, value in next_accounts.items()}
        changes = oracle.account_changes(self.parent, successor)
        if mutate is not None:
            mutate(witnesses, changes)
        return oracle.account_delta_updates(options.get('checkpoint', self.checkpoint), root,
            options.get('count', len(self.accounts)),
            options.get('balance', sum(value.balance for value in self.accounts.values())),
            witnesses, changes)

    def test_combined_parent_paths_match_independent_full_sparse_reconstruction(self):
        next_accounts = dict(self.accounts)
        for index in (0, 2, 3, 5, 7):
            next_accounts[self.owners[index]] = archive.Account(index * 50, index + 10)
        for index in (8, 9, 11):
            next_accounts[self.owners[index]] = archive.Account(index, index)
        result = self.update(next_accounts, self.owners)
        self.assertEqual(result['root'], archive.full_sparse(next_accounts)[0])
        self.assertEqual(result['count'], len(next_accounts))
        self.assertEqual(result['balance'], sum(value.balance for value in next_accounts.values()))

    def test_complete_execution_frontier_over_32_keeps_all_proofs_and_nonce_values(self):
        self.owners = [application.development_public(index) for index in range(50)]
        self.accounts = {owner: archive.Account(1000 + index, index)
                         for index, owner in enumerate(self.owners[:40])}
        self.parent = {'account:' + owner.hex(): value.as_json()
                       for owner, value in self.accounts.items()}
        after = {owner: archive.Account(value.balance - 1, value.nonce + 1)
                 for owner, value in self.accounts.items()}
        after[self.owners[49]] = archive.Account(40, 0)
        result = self.update(after, self.owners)
        self.assertEqual(result['root'], archive.full_sparse(after)[0])
        self.assertEqual(result['count'], 41)
        self.assertEqual(result['balance'], sum(value.balance for value in self.accounts.values()))
        self.assertEqual(archive.MAX_VIEW_ACCOUNTS, 32)
        def later_invalid(witnesses, _changes):
            witnesses[39]['siblings'][255][0] ^= 1
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            self.update(after, self.owners, mutate=later_invalid)

    def test_unchanged_reads_preserve_root_and_aggregate_without_fabricated_changes(self):
        result = self.update(self.accounts)
        self.assertEqual(result['root'], archive.full_sparse(self.accounts)[0])
        self.assertEqual(result['count'], len(self.accounts))
        self.assertEqual(result['balance'], sum(value.balance for value in self.accounts.values()))

    def test_proved_absence_creation_and_present_zero_nonce_are_distinct(self):
        after = dict(self.accounts)
        after[self.owners[8]] = archive.Account(0, 1)
        result = self.update(after, [self.owners[8]])
        self.assertEqual(result['root'], archive.full_sparse(after)[0])
        self.assertNotEqual(result['root'], archive.full_sparse(self.accounts)[0])
        self.assertEqual(result['count'], len(self.accounts) + 1)
        self.assertEqual(result['balance'], sum(value.balance for value in self.accounts.values()))

    def test_changed_owner_needs_an_actual_original_parent_proof(self):
        after = dict(self.accounts)
        after[self.owners[8]] = archive.Account(1, 1)
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_MISSING_CHANGE_PROOF$'):
            self.update(after)

    def test_mutated_path_and_other_checkpoint_fail_before_root_update(self):
        after = dict(self.accounts)
        after[self.owners[0]] = archive.Account(3, 9)
        def corrupt(witnesses, _changes):
            witnesses[0]['siblings'][127][0] ^= 1
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            self.update(after, mutate=corrupt)
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT$'):
            self.update(after, checkpoint=bytes([80]) * 32)

    def test_duplicate_unsorted_or_unchanged_changes_are_not_alternate_encodings(self):
        after = dict(self.accounts)
        after[self.owners[0]] = archive.Account(3, 9)
        after[self.owners[1]] = archive.Account(4, 9)
        mutations = [lambda w, c: c.append(copy.deepcopy(c[-1])), lambda w, c: c.reverse()]
        for change in mutations:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'STATE_WITNESS_.*_ORDER'):
                self.update(after, mutate=change)
        def duplicated(witnesses, _changes):
            witnesses.append(copy.deepcopy(witnesses[-1]))
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_DUPLICATE_PROOF$'):
            self.update(after, mutate=duplicated)
        normal = self.update(after)
        permuted = self.update(after, mutate=lambda witnesses, changes: witnesses.reverse())
        self.assertEqual(permuted, normal)
        def unchanged(_witnesses, changes):
            changes[0]['after'] = copy.deepcopy(changes[0]['before'])
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_UNCHANGED_DELTA$'):
            self.update(after, mutate=unchanged)

    def test_deletion_nonce_rollback_and_wrong_before_value_are_rejected(self):
        after = dict(self.accounts)
        del after[self.owners[0]]
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_ACCOUNT_DELETION$'):
            self.update(after)
        after = dict(self.accounts)
        after[self.owners[7]] = archive.Account(1, 6)
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_NONCE_ROLLBACK$'):
            self.update(after)
        after[self.owners[7]] = archive.Account(1, 8)
        def wrong_before(_witnesses, changes):
            changes[0]['before']['balance'] += 1
        with self.assertRaisesRegex(ValueError, '^STATE_WITNESS_CHANGE_BEFORE$'):
            self.update(after, mutate=wrong_before)

    def test_aggregate_underflow_overflow_and_boolean_aliases_are_rejected(self):
        after = dict(self.accounts)
        after[self.owners[0]] = archive.Account(3000, 1)
        for options, expected in [({'count': 0}, 'COUNT_UNDERFLOW'),
                                  ({'balance': 0}, 'BALANCE_UNDERFLOW'),
                                  ({'count': True}, 'INTEGER'),
                                  ({'balance': True}, 'INTEGER'),
                                  ({'balance': archive.U64_MAX}, 'INTEGER')]:
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'STATE_WITNESS_' + expected):
                self.update(after, **options)

    def test_full_ordered_delta_retains_null_creation_deletion_and_changed_value(self):
        self.assertEqual(oracle.ordered_deltas({'b': None, 'c': 1}, {'a': None, 'c': 2}),
            [{'key': 'a', 'before': None, 'after': {'value': None}},
             {'key': 'b', 'before': {'value': None}, 'after': None},
             {'key': 'c', 'before': {'value': 1}, 'after': {'value': 2}}])
        self.assertEqual(oracle.ordered_deltas({'a': True, 'b': {'nested': False}},
                                              {'a': 1, 'b': {'nested': 0}}),
            [{'key': 'a', 'before': {'value': True}, 'after': {'value': 1}},
             {'key': 'b', 'before': {'value': {'nested': False}},
              'after': {'value': {'nested': 0}}}])


class CompleteStatePartition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = application.derive_context(1)

    def setUp(self):
        self.state = application.derive_genesis(self.context)
        self.checkpoint = bytes([73]) * 32
        self.commitment = oracle.derive_commitment(self.state, self.context)
        self.witness = oracle.derive_state_witness(self.state, self.context,
            self.checkpoint, self.context.genesis, 0)

    def verify(self, witness):
        return oracle.verify_complete_partition(witness, self.commitment,
            self.checkpoint, self.context.genesis, 0)

    def test_all_genesis_partitions_funds_and_full_root_are_independently_rebuilt(self):
        self.assertEqual(self.commitment['account_count'], 4)
        self.assertEqual(self.commitment['non_account_count'], 5)
        self.assertEqual(self.commitment['account_balance'], 40_000_000)
        self.assertEqual(self.commitment['issued'], 40_000_000)
        self.assertEqual(self.commitment['escrow_balance'], 0)
        self.assertEqual(self.commitment['reward_balance'], 0)
        self.assertEqual(bytes(self.commitment['state_root']), archive.source_state_root(self.state))
        self.assertEqual(self.verify(self.witness), oracle.non_accounts(self.state))

    def test_utf8_top_level_key_bytes_are_preserved_while_values_stay_ascii_canonical(self):
        state = copy.deepcopy(self.state)
        state['retained:\u4e2d\U0001f30f'] = None
        state['retained:\u00e9'] = {'value': True}
        commitment = oracle.derive_commitment(state, self.context)
        witness = oracle.derive_state_witness(state, self.context, self.checkpoint, self.context.genesis, 0)
        partition = oracle.verify_complete_partition(witness, commitment,
            self.checkpoint, self.context.genesis, 0)
        self.assertEqual(partition, oracle.non_accounts(state))
        encoded = oracle.non_account_row_bytes(witness['non_accounts'])
        self.assertIn('retained:\u4e2d\U0001f30f'.encode('utf-8'), encoded)
        self.assertNotIn(b'\\u4e2d', encoded)
        self.assertNotEqual(commitment['state_root'], self.commitment['state_root'])
        with self.assertRaisesRegex(ValueError, 'ARCHIVE_STATE_ASCII'):
            archive.source_state_root(state)
        invalid = dict(state)
        invalid['retained:\u4e2d\U0001f30f'] = '\u4e2d'
        with self.assertRaisesRegex(ValueError, 'ARCHIVE_STATE_ASCII'):
            oracle.state_root(invalid)
        invalid = dict(state)
        invalid['\u4e2d' * 54] = None
        with self.assertRaisesRegex(ValueError, 'STATE_WITNESS_STATE_LIMIT'):
            oracle.state_root(invalid)

    def test_every_non_account_row_is_required_even_when_no_money_or_due_action(self):
        for index, row in enumerate(self.witness['non_accounts']):
            changed = copy.deepcopy(self.witness)
            del changed['non_accounts'][index]
            with self.subTest(key=row['key']), self.assertRaisesRegex(ValueError, 'NON_ACCOUNT_COUNT'):
                self.verify(changed)
        changed = copy.deepcopy(self.witness)
        changed['non_accounts'][0]['value'] = None
        with self.assertRaisesRegex(ValueError, 'NON_ACCOUNT_ROOT'):
            self.verify(changed)

    def test_future_reward_and_positive_obligation_cannot_be_omitted(self):
        task = 'task:' + bytes([6]).hex() * 32
        reward = 'reward:' + bytes([7]).hex() * 32
        self.state['account:' + application.development_public(0).hex()]['balance'] -= 300
        self.state[task] = {'remaining': 100, 'deadline': 100,
                            'owner': application.development_public(1).hex()}
        self.state[reward] = {'amount': 200, 'maturity': 200,
                              'owner': application.development_public(99).hex()}
        self.commitment = oracle.derive_commitment(self.state, self.context)
        self.witness = oracle.derive_state_witness(self.state, self.context,
            self.checkpoint, self.context.genesis, 0)
        self.assertEqual(self.commitment['escrow_balance'], 100)
        self.assertEqual(self.commitment['reward_balance'], 200)
        for key in (task, reward):
            changed = copy.deepcopy(self.witness)
            changed['non_accounts'] = [row for row in changed['non_accounts'] if row['key'] != key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'NON_ACCOUNT_COUNT'):
                self.verify(changed)

    def test_self_consistent_forged_aggregate_digest_is_not_an_authenticated_parent(self):
        for field in oracle.COMMITMENT_NUMBERS:
            changed = copy.deepcopy(self.witness)
            changed['commitment'][field] += 1
            changed['commitment']['id'] = list(oracle.commitment_identity(changed['commitment']))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PARENT_COMMITMENT'):
                self.verify(changed)

    def test_partition_order_duplicate_account_injection_and_extra_fields_fail(self):
        mutations = [lambda value: value['non_accounts'].reverse(),
                     lambda value: value['non_accounts'].append(copy.deepcopy(value['non_accounts'][-1])),
                     lambda value: value['non_accounts'][0].update(key='account:' + '0' * 64),
                     lambda value: value['non_accounts'][0].update(extra=None)]
        for change in mutations:
            changed = copy.deepcopy(self.witness)
            change(changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(changed)

    def test_digest_parent_context_boolean_and_conservation_tampering_fail(self):
        for field in ('parent_checkpoint', 'parent_id'):
            changed = copy.deepcopy(self.witness)
            changed[field][0] ^= 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(changed)
        changed = copy.deepcopy(self.witness)
        changed['parent_height'] = False
        with self.assertRaisesRegex(ValueError, 'INTEGER'):
            self.verify(changed)
        for field in ('network', 'id'):
            changed = copy.deepcopy(self.witness)
            changed['commitment'][field][0] ^= 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'COMMITMENT_ID'):
                self.verify(changed)
        broken = copy.deepcopy(self.state)
        broken['meta:issued'] += 1
        with self.assertRaisesRegex(ValueError, 'CONSERVATION'):
            oracle.derive_commitment(broken, self.context)

    def test_original_parent_proofs_derive_both_matured_credit_and_later_spend(self):
        context = self.context
        owner = application.development_public(79999)
        miner = application.development_public(0)
        parent = application.transition(self.state, [], 1, owner, context.genesis, context)['state']
        for height in range(2, 21):
            parent = application.transition(parent, [], height, miner, context.genesis, context)['state']
        recipient = application.development_public(2)
        probe = application.signed_transaction(context, 79999, 1, 1, recipient + application.u64(1))
        fee = context.fees[1] + len(probe) * context.params['byte_fee_units']
        raw = application.signed_transaction(context, 79999, 1, 1, recipient + application.u64(1000 - fee))
        complete = application.transition(parent, [raw], 21, miner, context.genesis, context)
        mandatory, receipts = application.mandatory(parent, 21, context, application.AccountAccess(parent))
        queried = sorted({owner, recipient, miner})
        accounts = archive.accounts_from_state(parent)
        root, paths = archive.full_sparse(accounts, queried)
        witnesses = [archive.witness_json(self.checkpoint, who, accounts.get(who), paths[who]) for who in queried]
        self.assertIsNone(next(witness for witness in witnesses if bytes(witness['owner']) == owner)['account'])
        prologue = oracle.derive_transition(parent, mandatory, receipts, context, self.checkpoint, witnesses)
        final = oracle.derive_transition(parent, complete['state'],
            [bytes.fromhex(value) for value in complete['receipts_hex']], context, self.checkpoint, witnesses)
        prologue_owner = next(change for change in prologue['account_changes'] if bytes(change['owner']) == owner)
        final_owner = next(change for change in final['account_changes'] if bytes(change['owner']) == owner)
        self.assertIsNone(prologue_owner['before'])
        self.assertIsNone(final_owner['before'])
        self.assertEqual(prologue_owner['after'], {'balance': 1000, 'nonce': 0})
        self.assertEqual(final_owner['after'], {'balance': 0, 'nonce': 1})
        self.assertEqual(prologue['commitment']['account_count'], len(accounts) + 1)
        self.assertEqual(final['commitment']['account_count'], len(accounts) + 1)
        self.assertEqual(prologue['commitment']['issued'], parent['meta:issued'])
        self.assertEqual(final['commitment']['issued'], parent['meta:issued'] + 1000)
        self.assertNotEqual(bytes(prologue['commitment']['account_root']), root)
        self.assertNotEqual(prologue['commitment']['account_root'], final['commitment']['account_root'])

    def test_signed_fixture_bound_refusal_cannot_be_relabelled_as_cancellation(self):
        expected = self.witness
        case = {'state_witness': copy.deepcopy(expected), 'cancel_at': 'BeforeOutput'}
        self.assertEqual(oracle.negative_outcome(case, expected), {'kind': 'checked', 'code': 'Cancelled'})
        case['state_witness']['non_accounts'].pop()
        self.assertEqual(oracle.negative_outcome(case, expected), {'kind': 'state_witness', 'code': 'Partition'})
        case['state_witness'] = copy.deepcopy(expected)
        case['state_witness']['commitment']['account_count'] += 1
        case['state_witness']['commitment']['id'] = list(oracle.commitment_identity(case['state_witness']['commitment']))
        self.assertEqual(oracle.negative_outcome(case, expected), {'kind': 'state_witness', 'code': 'Commitment'})


if __name__ == '__main__':
    unittest.main()
