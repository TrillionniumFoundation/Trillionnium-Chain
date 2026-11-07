"""Synthetic owner statements exercise composition, never real demand claims."""
import copy
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from demand_evidence import (ACCOUNTS, ROLES, DemandEvidenceBook, canonical, commitment,
                             signed_record, validate_contract)


def ident(text):
    return hashlib.sha256(str(text).encode()).hexdigest()


class DemandTests(unittest.TestCase):
    def setUp(self):
        self.private = {name: Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
                        for i, name in enumerate((*ROLES, 'requester', 'provider'))}
        self.keys = {name: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
                     for name, key in self.private.items()}
        self.context, self.anchor, self.registry = map(ident, ('context', 'anchor', 'registry'))
        self.book = self.new_book()

    def new_book(self, **kwargs):
        return DemandEvidenceBook(context=self.context, owner_keys={r: self.keys[r] for r in ROLES},
                                  registry_root=self.registry, bonus_cap=kwargs.pop('bonus_cap', 10), **kwargs)

    def sign(self, kind, payload, contract, role):
        return signed_record(self.private[role], context=self.context, kind=kind,
                             contract=contract, payload=payload)

    def bundle(self, number=1, *, outcome='no-gain', origin='external-attested', bonus=False,
               inputs='same-inputs', candidate='complete-output'):
        terms = dict(context=self.context, request=ident(('request', number)),
            requester=self.keys['requester'], provider=self.keys['provider'], parent=ident('parent'),
            inputs=ident(inputs), output_spec=ident('output-spec'), qualified_work=ident(('work', number)),
            evaluation_protocol=ident('frozen-eval'), fee_schedule=ident('fixed-fees'),
            dispute_policy=ident('dispute-policy'), deadline=60, dispute_end=80, retention_until=90,
            fees=dict(service=20, evaluation=7, availability=3, improvement=5),
            fixed_net_fees=dict(service=20, evaluation=7, availability=3),
            beneficiaries=dict(service=self.keys['provider'], evaluation=self.keys['evaluation'],
                               availability=self.keys['availability'], improvement=self.keys['provider']))
        contract = validate_contract(terms)
        output = ident(candidate)
        def sign(kind, payload, role):
            return self.sign(kind, payload, contract, role)
        bundle = dict(contract=terms,
            request=sign('request', {'terms': contract}, 'requester'),
            funding=sign('funding', dict(anchor=self.anchor, observed_at=100, valid_until=110, locked_at=10,
                sources={a: dict(source=ident((number, a)), payer=self.keys['requester'],
                    beneficiary=terms['beneficiaries'][a], units=terms['fees'][a],
                    state='settled' if bonus or a != 'improvement' else 'locked')
                         for a in ACCOUNTS}), 'native'),
            provenance=sign('provenance', dict(registry=self.registry, valid_from=5, valid_until=110,
                classification=origin, control_groups={r: ident('controller-' + r) for r in
                    ('requester', 'provider', 'evaluator', 'auditor', 'adopter')},
                evidence=ident('external-audit-evidence'), status='complete'), 'audit'),
            delivery=sign('delivery', dict(output=output, completed_at=50, complete=True, correct=True,
                          verification=ident('full-correctness-replay')), 'delivery'),
            acceptance=sign('acceptance', dict(output=output, accepted_at=55), 'requester'),
            dispute=None,
            evaluation=sign('evaluation', dict(protocol=terms['evaluation_protocol'], output=output,
                completed_at=60, fulfilled=True, outcome=outcome, result=ident('frozen-result')), 'evaluation'),
            availability=sign('availability', dict(output=output, retained_from=50, retained_until=90,
                              complete=True, evidence=ident('retention-evidence')), 'availability'),
            adoption=None, payments=[])
        if bonus:
            bundle['adoption'] = sign('adoption', dict(parent=terms['parent'], candidate=output,
                evaluation=commitment('evaluation', bundle['evaluation']), receipt=ident(('adoption', number)),
                observed_at=95, status='adopted', evidence=ident('adoption-evidence')), 'adoption')
        for account in ACCOUNTS if bonus else ACCOUNTS[:-1]:
            bundle['payments'].append(sign('payment', dict(account=account,
                source=ident((number, account)), operation=ident(('payment', number, account)),
                beneficiary=terms['beneficiaries'][account], output=output, anchor=self.anchor,
                gross_units=terms['fees'][account], net_units=terms['fees'][account],
                settled_at={'service': 60, 'evaluation': 65, 'availability': 90, 'improvement': 96}[account]), 'native'))
        return bundle

    def resign(self, bundle, field, *, index=None, **updates):
        record = bundle[field] if index is None else bundle[field][index]
        body = record['body']
        payload = copy.deepcopy(body['payload']); payload.update(updates)
        role = next(role for role, key in self.keys.items() if key == body['signer'])
        replacement = self.sign(body['kind'], payload, body['contract'], role)
        if index is None:
            bundle[field] = replacement
        else:
            bundle[field][index] = replacement

    def observe(self, bundle, **kwargs):
        return self.book.observe(canonical(bundle), expected_contract=validate_contract(bundle['contract']),
                                 expected_anchor=kwargs.pop('anchor', self.anchor), height=kwargs.pop('height', 100), **kwargs)

    def refuse(self, bundle, code):
        before = self.book.snapshot()
        with self.assertRaisesRegex(ValueError, code):
            self.observe(bundle)
        self.assertEqual(before, self.book.snapshot())

    def test_no_gain_keeps_completed_service_evaluation_and_da_fees(self):
        result = self.observe(self.bundle())
        self.assertEqual(result['status'], 'NoUpdate')
        self.assertEqual(result['paid'], dict(service=20, evaluation=7, availability=3, improvement=0))
        self.assertFalse(result['conditional_fee_due']['improvement'])
        self.assertFalse(result['payment_authorized'])
        self.assertFalse(result['independent_demand_proven'])

    def test_positive_conditional_adoption_and_five_distinct_accounts(self):
        result = self.observe(self.bundle(outcome='positive-net', bonus=True))
        self.assertTrue(result['conditional_fee_due']['improvement'])
        record = self.sign('security-reward', dict(reward=ident('reward'), operation=ident('maturity'),
            beneficiary=self.keys['provider'], gross_units=100, net_units=100, anchor=self.anchor), self.context, 'native')
        self.book.record_security(record); self.book.record_security(record)
        snapshot = self.book.snapshot()
        self.assertEqual(snapshot['accounts'], dict(security=100, service=20, evaluation=7, availability=3, improvement=5))
        self.assertIsNone(snapshot['business_work_reuse_ratio'])
        self.assertFalse(snapshot['native_adapter_verified'])

    def test_fixed_evaluator_fee_is_equal_for_positive_and_negative_results(self):
        a = self.observe(self.bundle(number=1, outcome='no-gain'))
        b = self.observe(self.bundle(number=2, outcome='positive-net'))
        self.assertEqual(a['paid']['evaluation'], b['paid']['evaluation'])
        self.assertFalse(b['conditional_fee_due']['improvement'])

    def test_self_project_and_unknown_funding_do_not_become_external_revenue(self):
        for i, origin in enumerate(('self-or-related', 'project-budget', 'unknown'), 1):
            result = self.observe(self.bundle(i, origin=origin))
            self.assertEqual(result['origin'], origin)
        self.assertEqual(self.book.snapshot()['service_receipts_by_origin']['external-attested'], 0)

    def test_missing_provenance_and_unknown_or_revoked_control_stay_unknown(self):
        for status in (None, 'unknown', 'revoked', 'conflicted'):
            bundle = self.bundle()
            if status is None:
                bundle['provenance'] = None
            else:
                self.resign(bundle, 'provenance', status=status)
            self.book = self.new_book()
            result = self.observe(bundle)
            self.assertEqual(result['origin'], 'unknown')
            self.assertFalse(result['independence_attested'])

    def test_same_controller_two_keys_are_related(self):
        bundle = self.bundle()
        groups = bundle['provenance']['body']['payload']['control_groups'].copy()
        groups['provider'] = groups['requester']
        self.resign(bundle, 'provenance', control_groups=groups)
        result = self.observe(bundle)
        self.assertEqual(result['origin'], 'self-or-related')
        self.assertFalse(result['conditional_fee_due']['improvement'])

    def test_customer_may_itself_adopt_but_producer_or_evaluator_conflicts_block_bonus(self):
        bundle = self.bundle(outcome='positive-net', bonus=True)
        groups = bundle['provenance']['body']['payload']['control_groups'].copy()
        groups['adopter'] = groups['requester']
        self.resign(bundle, 'provenance', control_groups=groups)
        self.assertTrue(self.observe(bundle)['conditional_fee_due']['improvement'])
        for role in ('adopter', 'evaluator', 'auditor'):
            self.book = self.new_book()
            bad = self.bundle(outcome='positive-net', bonus=True)
            groups = bad['provenance']['body']['payload']['control_groups'].copy()
            groups[role] = groups['provider']
            self.resign(bad, 'provenance', control_groups=groups)
            self.refuse(bad, 'INELIGIBLE_PAYMENT')

    def test_negative_outcome_unknown_origin_missing_adoption_cannot_pay_bonus(self):
        for changes in ({'outcome': 'no-gain'}, {'outcome': 'inconclusive'}, {'origin': 'unknown'}):
            bundle = self.bundle(outcome='positive-net', bonus=True)
            if 'outcome' in changes:
                self.resign(bundle, 'evaluation', outcome=changes['outcome'])
                self.resign(bundle, 'adoption', evaluation=commitment('evaluation', bundle['evaluation']))
            else:
                self.resign(bundle, 'provenance', classification=changes['origin'])
            self.refuse(bundle, 'INELIGIBLE_PAYMENT')
        bundle = self.bundle(outcome='positive-net', bonus=True); bundle['adoption'] = None
        self.refuse(bundle, 'INELIGIBLE_PAYMENT')

    def test_signatures_context_anchor_registry_and_expected_contract_are_pinned(self):
        bundle = self.bundle(); bundle['funding']['body']['payload']['locked_at'] = 9
        self.refuse(bundle, 'SIGNATURE')
        bundle = self.bundle(); self.resign(bundle, 'provenance', registry=ident('other-registry'))
        self.refuse(bundle, 'REGISTRY')
        bundle = self.bundle()
        with self.assertRaisesRegex(ValueError, 'FUNDING_WINDOW'):
            self.observe(bundle, anchor=ident('old-anchor'))
        with self.assertRaisesRegex(ValueError, 'CONTRACT_BINDING'):
            self.book.observe(canonical(bundle), expected_contract=ident('wrong-contract'),
                              expected_anchor=self.anchor, height=100)

    def test_missing_underfunded_expired_and_cancelled_funding_refuse(self):
        for mutation in ('missing', 'units', 'state', 'expiry'):
            bundle = self.bundle()
            if mutation == 'missing':
                bundle['funding'] = None
            elif mutation == 'expiry':
                self.resign(bundle, 'funding', valid_until=99)
            else:
                sources = copy.deepcopy(bundle['funding']['body']['payload']['sources'])
                sources['service'][mutation] = 19 if mutation == 'units' else 'cancelled'
                self.resign(bundle, 'funding', sources=sources)
            self.refuse(bundle, 'DEMAND_')

    def test_partial_late_or_incorrect_delivery_cannot_collect_fees(self):
        for change in ({'complete': False}, {'correct': False}, {'completed_at': 61}):
            bundle = self.bundle(); self.resign(bundle, 'delivery', **change)
            self.refuse(bundle, 'ACCEPTANCE')

    def test_unaccepted_or_unresolved_delivery_never_silently_settles(self):
        bundle = self.bundle(); bundle['acceptance'] = None
        self.refuse(bundle, 'INELIGIBLE_PAYMENT')
        bundle['payments'] = bundle['payments'][1:]
        result = self.observe(bundle)
        self.assertFalse(result['conditional_fee_due']['service'])
        self.book = self.new_book(); bundle = self.bundle()
        bundle['dispute'] = self.sign('dispute', dict(policy=bundle['contract']['dispute_policy'],
            output=ident('complete-output'), verdict='unresolved', resolved_at=70, evidence=ident('case')),
            validate_contract(bundle['contract']), 'dispute')
        self.refuse(bundle, 'INELIGIBLE_PAYMENT')

    def test_explicit_objective_dispute_owner_resolution_can_support_fee_only(self):
        bundle = self.bundle(); bundle['acceptance'] = None
        bundle['dispute'] = self.sign('dispute', dict(policy=bundle['contract']['dispute_policy'],
            output=ident('complete-output'), verdict='pay-service', resolved_at=70, evidence=ident('case')),
            validate_contract(bundle['contract']), 'dispute')
        self.resign(bundle, 'payments', index=0, settled_at=75)
        result = self.observe(bundle)
        self.assertTrue(result['conditional_fee_due']['service'])
        self.assertEqual(result['paid']['improvement'], 0)

    def test_exact_replay_is_idempotent_and_changed_height_is_not_a_fresh_observation(self):
        bundle = self.bundle(); first = self.observe(bundle)
        self.assertEqual(first, self.observe(bundle))
        first['paid']['service'] = 900
        self.assertEqual(self.observe(bundle)['paid']['service'], 20)
        with self.assertRaisesRegex(ValueError, 'REPLAY_CONFLICT'):
            self.observe(bundle, height=101)
        self.assertEqual(self.book.snapshot()['contracts'], 1)

    def test_task_rewrapping_counts_real_service_fees_but_only_one_result(self):
        self.observe(self.bundle(1)); self.observe(self.bundle(2))
        snapshot = self.book.snapshot()
        self.assertEqual(snapshot['accounts']['service'], 40)
        self.assertEqual(snapshot['complete_unique_outputs'], 1)
        self.assertEqual(snapshot['repeated_complete_outputs'], 1)

    def test_duplicate_improvement_output_or_adoption_receipt_is_atomic(self):
        self.observe(self.bundle(1, outcome='positive-net', bonus=True))
        self.refuse(self.bundle(2, outcome='positive-net', bonus=True), 'DUPLICATE_IMPROVEMENT')
        bundle = self.bundle(2, outcome='positive-net', bonus=True, inputs='new-inputs', candidate='new-candidate')
        self.resign(bundle, 'adoption', receipt=ident(('adoption', 1)))
        self.refuse(bundle, 'DUPLICATE_IMPROVEMENT')

    def test_global_cap_cannot_be_split_across_sources_or_task_ids(self):
        for number in (1, 2):
            self.observe(self.bundle(number, outcome='positive-net', bonus=True, inputs=str(number), candidate=str(number)))
        self.refuse(self.bundle(3, outcome='positive-net', bonus=True, inputs='3', candidate='3'), 'GLOBAL_BONUS_CAP')
        self.assertEqual(self.book.snapshot()['improvement_gross_observed'], 10)

    def test_payment_replay_source_reuse_fixed_fee_and_time_travel_refuse(self):
        bundle = self.bundle()
        self.resign(bundle, 'payments', index=1, operation=ident(('payment', 1, 'service')))
        self.refuse(bundle, 'PAYMENT_REPLAY')
        bundle = self.bundle(); self.resign(bundle, 'payments', index=1, gross_units=6, net_units=6)
        self.refuse(bundle, 'FIXED_FEE')
        bundle = self.bundle(); self.resign(bundle, 'payments', index=1, settled_at=59)
        self.refuse(bundle, 'PAYMENT_AMOUNT')
        self.observe(self.bundle())
        bundle = self.bundle(2)
        sources = copy.deepcopy(bundle['funding']['body']['payload']['sources'])
        sources['service']['source'] = ident((1, 'service'))
        self.resign(bundle, 'funding', sources=sources)
        self.refuse(bundle, 'SOURCE_REUSE')

    def test_empty_queue_and_stale_snapshot_use_existing_zero_credit_maintenance(self):
        result = self.book.queue_observation(height=100, expected_anchor=self.anchor)
        self.assertEqual(result['mode'], 'existing-native-maintenance')
        self.assertEqual(result['useful_output_credit'], 0)
        bundle = self.bundle()
        for key in ('delivery', 'acceptance', 'evaluation', 'availability', 'adoption'):
            bundle[key] = None
        bundle['payments'] = []
        sources = copy.deepcopy(bundle['funding']['body']['payload']['sources'])
        for value in sources.values():
            value['state'] = 'locked'
        self.resign(bundle, 'funding', observed_at=20, valid_until=40, sources=sources)
        self.observe(bundle, height=20)
        self.assertEqual(self.book.queue_observation(height=30, expected_anchor=self.anchor)['mode'],
                         'funded-external-attested')
        for height, anchor in ((41, self.anchor), (30, ident('new-branch'))):
            self.assertEqual(self.book.queue_observation(height=height, expected_anchor=anchor)['mode'],
                             'existing-native-maintenance')

    def test_independent_review_dispute_and_bonus_time_travel_counterexamples(self):
        for resolved_at, settled_at in ((0, 1), (95, 96)):
            bundle = self.bundle(); bundle['acceptance'] = None
            bundle['dispute'] = self.sign('dispute', dict(policy=bundle['contract']['dispute_policy'],
                output=ident('complete-output'), verdict='pay-service', resolved_at=resolved_at, evidence=ident('case')),
                validate_contract(bundle['contract']), 'dispute')
            self.resign(bundle, 'payments', index=0, settled_at=settled_at)
            self.refuse(bundle, 'DISPUTE_WINDOW')
        bundle = self.bundle(outcome='positive-net', bonus=True)
        self.resign(bundle, 'adoption', observed_at=65)
        self.resign(bundle, 'payments', index=3, settled_at=66)
        self.refuse(bundle, 'PAYMENT_AMOUNT')

    def test_independent_review_fixed_net_evaluation_and_retroactive_scope(self):
        bundle = self.bundle(); self.resign(bundle, 'payments', index=1, net_units=0)
        self.refuse(bundle, 'FIXED_NET_FEE')
        bundle = self.bundle(outcome='positive-net', bonus=True)
        self.resign(bundle, 'provenance', valid_from=99)
        self.refuse(bundle, 'PROVENANCE_WINDOW')

    def test_independent_review_new_task_cannot_reaward_identical_candidate(self):
        self.observe(self.bundle(1, outcome='positive-net', bonus=True))
        self.refuse(self.bundle(2, outcome='positive-net', bonus=True, inputs='different-window'),
                    'DUPLICATE_IMPROVEMENT')

    def test_independent_review_settled_sources_do_not_become_queued_funding(self):
        bundle = self.bundle()
        for key in ('delivery', 'acceptance', 'evaluation', 'availability', 'adoption'):
            bundle[key] = None
        bundle['payments'] = []
        self.resign(bundle, 'funding', observed_at=20)
        self.observe(bundle, height=20)
        self.assertEqual(self.book.queue_observation(height=30, expected_anchor=self.anchor)['mode'],
                         'existing-native-maintenance')

    def test_refund_pending_dispute_and_prior_failed_delivery_are_not_new_queue_work(self):
        for verdict in ('refund', 'unresolved', 'pay-service'):
            self.book = self.new_book(); bundle = self.bundle()
            for key in ('delivery', 'acceptance', 'evaluation', 'availability', 'adoption'):
                bundle[key] = None
            bundle['payments'] = []
            sources = copy.deepcopy(bundle['funding']['body']['payload']['sources'])
            for value in sources.values():
                value['state'] = 'locked'
            self.resign(bundle, 'funding', observed_at=20, sources=sources)
            bundle['dispute'] = self.sign('dispute', dict(policy=bundle['contract']['dispute_policy'],
                output=None, verdict=verdict, resolved_at=25, evidence=ident('case')),
                validate_contract(bundle['contract']), 'dispute')
            if verdict == 'pay-service':
                with self.assertRaisesRegex(ValueError, 'DISPUTE_DELIVERY'):
                    self.observe(bundle, height=30)
            else:
                self.observe(bundle, height=30)
                self.assertEqual(self.book.queue_observation(height=30, expected_anchor=self.anchor)['mode'],
                                 'existing-native-maintenance')
        self.book = self.new_book(); bundle = self.bundle()
        for key in ('acceptance', 'evaluation', 'availability', 'adoption'):
            bundle[key] = None
        bundle['payments'] = []
        self.resign(bundle, 'delivery', complete=False)
        self.resign(bundle, 'funding', observed_at=55, sources=sources)
        self.observe(bundle, height=55)
        self.assertEqual(self.book.queue_observation(height=55, expected_anchor=self.anchor)['mode'],
                         'existing-native-maintenance')

    def test_strict_types_limits_canonical_shape_and_duplicate_json_keys(self):
        for value in (True, -1, 1 << 64, 0.5):
            bundle = self.bundle(); bundle['contract']['fees']['service'] = value
            with self.assertRaises(ValueError):
                validate_contract(bundle['contract'])
        bundle = self.bundle(); raw = canonical(bundle)
        for bad in (b' ' + raw, b'{"contract":0,' + raw[1:], b'[' + raw + b']'):
            with self.assertRaises(ValueError):
                self.book.observe(bad, expected_contract=validate_contract(bundle['contract']),
                                  expected_anchor=self.anchor, height=100)
        self.book = self.new_book(max_records=1); self.observe(bundle)
        self.refuse(self.bundle(2), 'DEMAND_LIMIT')


if __name__ == '__main__':
    unittest.main()
