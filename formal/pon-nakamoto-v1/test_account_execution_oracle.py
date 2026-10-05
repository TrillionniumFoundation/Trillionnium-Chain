"""Independent relation negatives; no native process or supplied post-State answers."""
import copy
import unittest

import account_archive_oracle as archive
import account_execution_oracle as oracle


def transfer(context, sender, nonce, recipient, amount, **options):
    return oracle.signed_transaction(context, sender, nonce, 1,
        oracle.development_public(recipient) + oracle.u64(amount), **options)


def reserve(context, sender, nonce, provider, amount, due):
    identifier = oracle.h('task-instance-v3', context.network, context.parameters,
        oracle.development_public(sender), oracle.u64(nonce), oracle.development_public(provider),
        oracle.u64(amount), oracle.u64(due))
    raw = oracle.signed_transaction(context, sender, nonce, 2, identifier
        + oracle.development_public(provider) + oracle.u64(amount) + oracle.u64(due))
    return identifier, raw


def quota(context, sender, nonce, consumer, provider, units, due):
    identifier = oracle.h('quota-instance-v3', context.network, context.parameters,
        oracle.development_public(sender), oracle.u64(nonce), oracle.development_public(consumer),
        oracle.development_public(provider), oracle.u64(units), oracle.u64(due))
    raw = oracle.signed_transaction(context, sender, nonce, 10, identifier
        + oracle.development_public(consumer) + oracle.development_public(provider)
        + oracle.u64(units) + oracle.u64(due))
    return identifier, raw


def use(context, provider, nonce, consumer, identifier, units, result=bytes([9]) * 32):
    message = oracle.h('use', context.network, context.parameters, identifier,
        oracle.development_public(provider), oracle.u64(nonce), oracle.u64(units), result)
    signature = oracle.development_key(consumer).sign(message)
    return oracle.signed_transaction(context, provider, nonce, 11,
        identifier + oracle.u64(units) + result + signature)


class AccountExecutionOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = oracle.derive_context(1)

    def setUp(self):
        self.state = oracle.derive_genesis(self.context)
        self.miner = oracle.development_public(0)

    def run_block(self, transactions, height=1, state=None, parent=None, checked=None, miner=None):
        source = self.state if state is None else state
        before = oracle.canonical(source)
        try:
            return oracle.transition(source, transactions, height, miner or self.miner,
                parent or self.context.genesis, self.context, checked)
        finally:
            self.assertEqual(oracle.canonical(source), before)

    def account(self, state, number):
        return state.get('account:' + oracle.development_public(number).hex())

    def fee(self, raw):
        return self.context.fees[raw[92]] + len(raw) * self.context.params['byte_fee_units']

    def make_checked(self, state=None, parent=None, height=0, owners=(0, 10)):
        state = self.state if state is None else state
        parent = parent or self.context.genesis
        hashes = [oracle.development_public(owner) for owner in owners]
        checkpoint, details = archive.derive_checkpoint(self.context.as_json(), parent, None,
            height, archive.source_state_root(state), archive.accounts_from_state(state), hashes)
        accounts = archive.accounts_from_state(state)
        witnesses = [archive.witness_json(archive.hash_bytes(checkpoint['id']), owner,
            accounts.get(owner), details['proofs'][owner]) for owner in hashes]
        return checkpoint, [list(owner) for owner in hashes], witnesses

    def test_exact_independent_genesis_matches_frozen_context_and_all_nine_keys(self):
        self.assertEqual(self.context.network.hex(),
            'c2038f60bc15110ba112f1336b764a562c871553a1a36f313f5a14b4d9f53c47')
        self.assertEqual(self.context.parameters.hex(),
            '30263270f2bcaf5344a6533c102f33260f6bcd9eb14b32838534ce3f464460af')
        self.assertEqual(len(self.state), 9)
        self.assertEqual(self.state['meta:issued'], 40_000_000)
        self.assertEqual(self.context.maintenance['matrix_task'],
            'c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496')
        slot = self.state['qualified-demand-slot-v2:00']
        self.assertEqual(slot['statement_id'],
            '63aa41b93a17571bd9f977af13930afe2a086e637cdbc0bce935ae309961576f')
        raw = bytes.fromhex(slot['statement'])
        oracle.verify_signature(oracle.development_public(0), raw[-64:],
            oracle.h('qualified-task-source-sign-v2', raw[:-64]))
        self.assertEqual(self.context.genesis, oracle.h('genesis', self.context.network,
            self.context.parameters, archive.source_state_root(self.state), oracle.u64(1)))

    def test_changed_genesis_time_changes_complete_context_and_record_authorities(self):
        other = oracle.derive_context(2)
        self.assertNotEqual(other.network, self.context.network)
        self.assertNotEqual(other.parameters, self.context.parameters)
        self.assertNotEqual(other.genesis, self.context.genesis)
        self.assertNotEqual(other.genesis_state['qualified-demand-slot-v2:00']['statement'],
                            self.state['qualified-demand-slot-v2:00']['statement'])

    def test_self_transfer_charges_only_fee_and_preserves_nonce(self):
        raw = transfer(self.context, 1, 1, 1, 5)
        result = self.run_block([raw])
        self.assertEqual(self.account(result['state'], 1), dict(balance=10_000_000-self.fee(raw), nonce=1))
        self.assertEqual(result['fees'], self.fee(raw))
        self.assertEqual(result['subsidy'], 1000)
        self.assertEqual(result['state']['meta:issued'], 40_001_000)
        self.assertEqual(oracle.total_funds(result['state']), 40_001_000)

    def test_created_account_spends_in_same_block_and_present_zero_is_not_absence(self):
        spend = transfer(self.context, 10, 1, 2, 19)
        funding = transfer(self.context, 0, 1, 10, 19+self.fee(spend))
        result = self.run_block([funding, spend])
        self.assertEqual(self.account(result['state'], 10), dict(balance=0, nonce=1))
        self.assertEqual(self.account(result['state'], 2), dict(balance=10_000_019, nonce=0))
        missing = copy.deepcopy(result['state'])
        del missing['account:' + oracle.development_public(10).hex()]
        self.assertNotEqual(archive.source_state_root(missing), archive.source_state_root(result['state']))
        self.assertNotEqual(archive.full_sparse(archive.accounts_from_state(missing))[0],
                            archive.full_sparse(archive.accounts_from_state(result['state']))[0])

    def test_full_proofs_gate_transfer_and_parent_is_immutable(self):
        checkpoint, requested, witnesses = self.make_checked()
        checked = oracle.checked_witnesses(self.context, checkpoint, self.state,
            self.context.genesis, 0, requested, witnesses)
        raw = transfer(self.context, 0, 1, 10, 500)
        result = self.run_block([raw], checked=checked)
        self.assertEqual(self.account(result['state'], 10), dict(balance=500, nonce=0))
        self.assertIn(list(oracle.development_public(10)), result['used_owners'])

    def test_missing_witness_for_proved_absence_is_not_default_zero(self):
        checkpoint, requested, witnesses = self.make_checked(owners=(0,))
        checked = oracle.checked_witnesses(self.context, checkpoint, self.state,
            self.context.genesis, 0, requested, witnesses)
        with self.assertRaisesRegex(oracle.RelationError, '^MISSING_WITNESS:'):
            self.run_block([transfer(self.context, 0, 1, 10, 1)], checked=checked)

    def test_unused_valid_proof_is_not_silently_accepted(self):
        checkpoint, requested, witnesses = self.make_checked(owners=(0, 10, 99))
        checked = oracle.checked_witnesses(self.context, checkpoint, self.state,
            self.context.genesis, 0, requested, witnesses)
        with self.assertRaisesRegex(oracle.RelationError, '^UNUSED_WITNESS:'):
            self.run_block([transfer(self.context, 0, 1, 10, 1)], checked=checked)

    def test_checkpoint_full_source_account_and_branch_bindings(self):
        checkpoint, requested, witnesses = self.make_checked()
        for name, expected in [('branch', 'CHECKPOINT_PARENT'),
                               ('source_state_root', 'CHECKPOINT_SOURCE_ROOT'),
                               ('account_root', 'CHECKPOINT_ACCOUNT_ROOT')]:
            broken = copy.deepcopy(checkpoint)
            broken[name][0] ^= 1
            with self.subTest(field=name), self.assertRaisesRegex(oracle.RelationError, expected):
                oracle.checked_witnesses(self.context, broken, self.state, self.context.genesis,
                                         0, requested, witnesses)
        broken = copy.deepcopy(checkpoint)
        broken['context']['parameters'][0] ^= 1
        with self.assertRaisesRegex(oracle.RelationError, 'CHECKPOINT_CONTEXT'):
            oracle.checked_witnesses(self.context, broken, self.state, self.context.genesis,
                                     0, requested, witnesses)

    def test_witness_duplicates_wrong_owner_and_wrong_sibling_fail(self):
        checkpoint, requested, witnesses = self.make_checked()
        for bad in ([witnesses[0]]*len(witnesses), list(reversed(witnesses[:-1]))+[witnesses[0]]):
            with self.assertRaises((oracle.RelationError, ValueError)):
                oracle.checked_witnesses(self.context, checkpoint, self.state, self.context.genesis,
                                         0, requested, bad)
        bad = copy.deepcopy(witnesses)
        bad[0]['siblings'][77][0] ^= 1
        with self.assertRaises(ValueError):
            oracle.checked_witnesses(self.context, checkpoint, self.state, self.context.genesis,
                                     0, requested, bad)

    def test_task_cancel_receipt_settle_and_fees_are_ordered(self):
        first, reserve_first = reserve(self.context, 2, 1, 3, 5000, 12)
        second, reserve_second = reserve(self.context, 2, 2, 3, 3000, 12)
        one = self.run_block([reserve_first, reserve_second])
        receipt = oracle.signed_transaction(self.context, 3, 1, 4, first + bytes([7])*32)
        settle = oracle.signed_transaction(self.context, 2, 3, 5, first + bytes([7])*32)
        cancel = oracle.signed_transaction(self.context, 2, 4, 3, second)
        two = self.run_block([receipt, settle, cancel], 2, one['state'])
        self.assertEqual(self.account(two['state'], 3), dict(balance=10_005_000-self.fee(receipt), nonce=1))
        self.assertEqual(self.account(two['state'], 2), dict(balance=10_000_000-5000
            -sum(map(self.fee, [reserve_first, reserve_second, settle, cancel])), nonce=4))
        self.assertEqual(two['state']['task:'+first.hex()]['status'], 'settled')
        self.assertEqual(two['state']['task:'+second.hex()]['status'], 'cancelled')

    def test_quota_use_can_create_provider_and_pay_fee_from_reserved_budget(self):
        identifier, purchase = quota(self.context, 1, 1, 2, 12, 10, 6)
        one = self.run_block([purchase])
        self.assertIsNone(self.account(one['state'], 12))
        consume = use(self.context, 12, 1, 2, identifier, 5)
        two = self.run_block([consume], 2, one['state'])
        self.assertEqual(self.account(two['state'], 12), dict(balance=5120-self.fee(consume), nonce=1))
        record = two['state']['quota:'+identifier.hex()]
        self.assertEqual((record['units'], record['remaining'], record['status']), (5, 5120, 'reserved'))
        mutated = bytearray(consume)
        mutated[-65] ^= 1
        unsigned = bytes(mutated[:-64])
        wrong = unsigned + oracle.development_key(12).sign(oracle.h('tx-sign', unsigned))
        with self.assertRaisesRegex(oracle.RelationError, '^SIGNATURE$'):
            self.run_block([wrong], 2, one['state'])

    def test_expiry_before_transfer_preserves_nonce_and_strict_cleanup_height(self):
        identifier, reserve_raw = reserve(self.context, 10, 1, 3, 7000, 3)
        fund = transfer(self.context, 0, 1, 10, 7000+self.fee(reserve_raw))
        one = self.run_block([fund, reserve_raw])
        self.assertEqual(self.account(one['state'], 10), dict(balance=0, nonce=1))
        two = self.run_block([], 2, one['state'])
        drain = transfer(self.context, 10, 2, 2, 7000-self.fee(transfer(self.context, 10, 2, 2, 1)))
        three = self.run_block([drain], 3, two['state'])
        self.assertEqual(self.account(three['state'], 10), dict(balance=0, nonce=2))
        self.assertEqual(three['receipts_hex'][0], oracle.canonical({'expiry':'task:'+identifier.hex()}).hex())
        self.assertIn('task:'+identifier.hex(), three['state'])
        four = self.run_block([], 4, three['state'])
        self.assertNotIn('task:'+identifier.hex(), four['state'])

    def test_reward_maturity_precedes_spend_and_requires_parent_absence_witness(self):
        miner = oracle.development_public(79999)
        one = self.run_block([], miner=miner)
        state = one['state']
        for height in range(2, 21):
            state = self.run_block([], height, state)['state']
        self.assertIsNone(self.account(state, 79999))
        drain = transfer(self.context, 79999, 1, 2, 1000-self.fee(transfer(self.context, 79999, 1, 2, 1)))
        result = self.run_block([drain], 21, state)
        self.assertEqual(self.account(result['state'], 79999), dict(balance=0, nonce=1))
        missing = {owner: account for owner, account in archive.accounts_from_state(state).items()}
        with self.assertRaisesRegex(oracle.RelationError, '^MISSING_WITNESS:'):
            self.run_block([drain], 21, state, checked=missing)

    def test_nonce_is_branch_relative_and_zero_balance_reentry_does_not_reset_it(self):
        spend = transfer(self.context, 10, 1, 2, 19)
        main = self.run_block([transfer(self.context, 0, 1, 10,19+self.fee(spend)), spend])
        fork = self.run_block([])
        self.assertEqual(self.account(main['state'], 10)['nonce'], 1)
        self.assertIsNone(self.account(fork['state'], 10))
        self.run_block([transfer(self.context, 0, 1, 10,19+self.fee(spend)), spend], 2, fork['state'])
        with self.assertRaisesRegex(oracle.RelationError, '^NONCE$'):
            self.run_block([spend], 2, main['state'])

    def test_signature_and_canonical_transaction_error_order(self):
        bad_signature = bytearray(transfer(self.context, 0, 99, 2, 1))
        bad_signature[-1] ^= 1
        with self.assertRaisesRegex(oracle.RelationError, '^SIGNATURE$'):
            self.run_block([bytes(bad_signature)])
        with self.assertRaisesRegex(oracle.RelationError, '^NONCE$'):
            self.run_block([transfer(self.context, 0, 99, 2, 1), bytes(bad_signature)])
        expired = bytearray(transfer(self.context, 0, 1, 2, 1, expiry=0))
        expired[-1] ^= 1
        with self.assertRaisesRegex(oracle.RelationError, '^EXPIRED$'):
            self.run_block([bytes(expired)])

    def test_fee_precedes_transfer_amount_and_range_failures_do_not_mutate(self):
        with self.assertRaisesRegex(oracle.RelationError, '^FEE$'):
            self.run_block([transfer(self.context, 0, 1, 2, oracle.U64_MAX, fee_limit=0)])
        with self.assertRaisesRegex(oracle.RelationError, '^FUNDS$'):
            self.run_block([transfer(self.context, 0, 1, 2, 10_000_000)])
        with self.assertRaisesRegex(oracle.RelationError, '^FUNDS$'):
            self.run_block([transfer(self.context, 0, 1, 2, 0)])

    def test_capacity_zero_reward_still_reserves_missing_recipient_exactly_once(self):
        state = copy.deepcopy(self.state)
        owner = oracle.development_public(99).hex()
        for height in range(1, 3):
            state['reward:'+f'{height:064x}'] = dict(owner=owner, amount=0, maturity=20+height)
        value = oracle.capacity(state, 2, self.context)
        self.assertEqual(value, dict(actual_keys=11, credit_account_reserve=1,
            archive_reserve=0, reward_queue_reserve=18, required_keys=30))
        state['account:'+owner] = dict(balance=0, nonce=7)
        other = oracle.capacity(state, 2, self.context)
        self.assertEqual(other['credit_account_reserve'], 0)
        self.assertEqual(other['required_keys'], 30)

    def test_capacity_boundary_and_queue_gap_are_not_fake_headroom(self):
        # Component-only capacity test; no claim of 65,536 signed account admissions.
        state = copy.deepcopy(self.state)
        for index in range(65507):
            state['account:'+f'{index:064x}'] = dict(balance=0, nonce=1)
        self.assertEqual(oracle.capacity(state, 0, self.context)['required_keys'], 65536)
        state['account:'+f'{65507:064x}'] = dict(balance=0, nonce=1)
        with self.assertRaisesRegex(oracle.RelationError, '^STATE_CAPACITY$'):
            oracle.capacity(state, 0, self.context)
        small = self.run_block([])['state']
        del small[next(key for key in small if key.startswith('reward:'))]
        with self.assertRaisesRegex(oracle.RelationError, '^CONTINUITY_REWARD_QUEUE$'):
            oracle.capacity(small, 1, self.context)

    def test_unsupported_transaction_and_namespace_fail_closed(self):
        raw = bytearray(transfer(self.context, 0, 1, 2, 1))
        raw[92] = 6
        with self.assertRaisesRegex(oracle.RelationError, '^UNSUPPORTED_TRANSACTION_TAG$'):
            self.run_block([bytes(raw)])
        for key in ('contribution:'+('aa'*32), 'release:'+('bb'*32), 'unreviewed:extension'):
            state = copy.deepcopy(self.state)
            state[key] = {}
            with self.subTest(key=key), self.assertRaisesRegex(oracle.RelationError, '^UNSUPPORTED_STATE_NAMESPACE$'):
                self.run_block([], state=state)

    def test_exact_twenty_signed_transaction_plan_reaches_zero_accounts(self):
        state, count, tags = self.state, 0, set()
        for height in range(1, 22):
            transactions = oracle.fixture_transactions(self.context, height, state)
            count += len(transactions)
            tags.update(raw[92] for raw in transactions)
            miner = oracle.development_public(79999 if height == 1 else 0)
            state = self.run_block(transactions, height, state, miner=miner)['state']
        self.assertEqual(count, 20)
        self.assertEqual(tags, set(oracle.SUPPORTED_TAGS))
        for owner, nonce in ((10, 2), (11, 3), (79999, 1)):
            self.assertEqual(self.account(state, owner), dict(balance=0, nonce=nonce))
        self.assertEqual(self.account(state, 12)['nonce'], 1)
        self.assertEqual(oracle.total_funds(state), state['meta:issued'])

    def packet(self, transactions, output, transaction_domain='transactions', receipt_domain='receipts'):
        # Intentionally no W1 proof is constructed: this tests packet commitments
        # only and its unchanged scope explicitly refuses full work verification.
        header = b'PNH1\x01\x00' + self.context.network + self.context.parameters + self.context.genesis
        header += oracle.u64(1) + oracle.u64(11) + bytes.fromhex('7f'+'ff'*31) + self.miner
        header += oracle.sequence_root(transaction_domain, transactions) + oracle.hash_value(output['root'])
        header += oracle.sequence_root(receipt_domain, [bytes.fromhex(raw) for raw in output['receipts_hex']])
        header += bytes.fromhex(self.context.maintenance['matrix_task']) + oracle.u64(0)
        self.assertEqual(len(header), 318)
        return (header + len(transactions).to_bytes(2, 'little')
                + b''.join(len(raw).to_bytes(2, 'little') + raw for raw in transactions)
                + b'PNW1' + bytes(49184))

    def test_packet_domains_and_complete_roots_without_claiming_work_verification(self):
        transactions = [transfer(self.context, 0, 1, 10, 500)]
        output = self.run_block(transactions)
        packet = self.packet(transactions, output)
        identity = oracle.verify_packet(packet, transactions, output, self.context,
                                        self.context.genesis, 1, self.miner)
        self.assertEqual(identity, oracle.h('block', packet[:318], bytes(32)))
        self.assertIs(oracle.SCOPE['work_relation_reverified'], False)
        self.assertIs(oracle.SCOPE['fork_choice_reverified'], False)
        for transaction_domain, receipt_domain, error in (
                ('tx', 'receipts', 'PACKET_TRANSACTION_ROOT'),
                ('transactions', 'receipt', 'PACKET_RECEIPT_ROOT')):
            with self.subTest(error=error), self.assertRaisesRegex(oracle.RelationError, error):
                oracle.verify_packet(self.packet(transactions, output, transaction_domain, receipt_domain),
                    transactions, output, self.context, self.context.genesis, 1, self.miner)
        corrupt = bytearray(packet)
        corrupt[222] ^= 1
        with self.assertRaisesRegex(oracle.RelationError, 'PACKET_STATE_ROOT'):
            oracle.verify_packet(bytes(corrupt), transactions, output, self.context,
                                 self.context.genesis, 1, self.miner)
        with self.assertRaisesRegex(oracle.RelationError, 'PACKET_WORK_ENCODING'):
            oracle.decode_packet(packet + b'\0')

    def positive_prefix(self):
        checkpoint, requested, witnesses = self.make_checked(owners=(0, 1, 2, 10, 11, 79999))
        transactions = oracle.fixture_transactions(self.context, 1, self.state)
        checked = oracle.checked_witnesses(self.context, checkpoint, self.state,
            self.context.genesis, 0, requested, witnesses)
        output = self.run_block(transactions, checked=checked, miner=oracle.development_public(79999))
        labels = ([f'main-{height:02}' for height in range(1, 22)]
            + [f'fork-{height:02}' for height in range(3, 23)] + ['restored-22', 'restored-23'])
        owners = sorted(oracle.hash_value(owner) for owner in requested)
        tree = archive.full_sparse_details(archive.accounts_from_state(self.state), owners)
        witness_rows = [archive.witness_json(oracle.hash_value(checkpoint['id']), owner,
            archive.accounts_from_state(self.state).get(owner), tree['proofs'][owner]) for owner in owners]
        first = dict(label='main-01', height=1, parent=list(self.context.genesis),
            parent_state=copy.deepcopy(self.state), parent_checkpoint=checkpoint,
            miner=list(oracle.development_public(79999)), transactions_hex=[raw.hex() for raw in transactions],
            requested=[list(owner) for owner in owners], witnesses=witness_rows,
            witnesses_hex=[archive.encode_witness(row).hex() for row in witness_rows],
            witness_node_reads=[archive.point_reads(tree, owner) for owner in owners],
            native_output={field:copy.deepcopy(output[field]) for field in ('state', 'root', 'receipts_hex', 'used_owners')})
        return dict(schema=oracle.NATIVE_SCHEMA, genesis_timestamp=1, context=self.context.as_json(),
            params=copy.deepcopy(self.context.params), scope=dict(oracle.NATIVE_SCOPE),
            genesis_state=copy.deepcopy(self.state), genesis_checkpoint=checkpoint,
            blocks=[first] + [dict(label=label) for label in labels[1:]])

    def test_native_genesis_and_parent_state_are_compared_never_trusted(self):
        for target, expected in (('genesis_state', 'NATIVE_GENESIS_STATE'),
                                  ('parent_state', 'NATIVE_PARENT_STATE')):
            observed = self.positive_prefix()
            source = observed if target == 'genesis_state' else observed['blocks'][0]
            source[target]['meta:issued'] += 1
            before = oracle.canonical(observed)
            with self.subTest(target=target), self.assertRaisesRegex(oracle.RelationError, expected):
                oracle.check_positive_observation(observed)
            self.assertEqual(oracle.canonical(observed), before)

    def test_native_poststate_cannot_supply_its_own_answer(self):
        observed = self.positive_prefix()
        output = observed['blocks'][0]['native_output']
        output['state']['account:'+oracle.development_public(10).hex()]['nonce'] = 99
        output['root'] = list(archive.source_state_root(output['state']))
        before = oracle.canonical(observed)
        with self.assertRaisesRegex(oracle.RelationError, 'NATIVE_OUTPUT_STATE'):
            oracle.check_positive_observation(observed)
        self.assertEqual(oracle.canonical(observed), before)

    def test_native_scope_count_and_missing_full_block_list_cannot_be_promoted(self):
        observed = self.positive_prefix()
        observed['scope']['production_activation'] = True
        with self.assertRaisesRegex(oracle.RelationError, 'NATIVE_SCOPE'):
            oracle.check_positive_observation(observed)
        observed = self.positive_prefix()
        observed['blocks'] = observed['blocks'][:1]
        with self.assertRaisesRegex(oracle.RelationError, 'FIXTURE_BLOCK_SET'):
            oracle.check_positive_observation(observed)
        observed = self.positive_prefix()
        observed['blocks'][0]['height'] = True
        with self.assertRaisesRegex(oracle.RelationError, 'FIXTURE_PARENT'):
            oracle.check_positive_observation(observed)

    def test_unknown_account_fields_bool_and_float_are_not_silently_coerced(self):
        for value in ({'balance': True, 'nonce': 1}, {'balance': 0, 'nonce': 1.0},
                      {'balance': 0, 'nonce': 1, 'extension':0}):
            state = copy.deepcopy(self.state)
            state['account:'+oracle.development_public(0).hex()] = value
            with self.subTest(value=value), self.assertRaises((oracle.RelationError, ValueError)):
                self.run_block([], state=state)


if __name__ == '__main__':
    unittest.main()
