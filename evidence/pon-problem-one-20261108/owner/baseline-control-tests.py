"""Service correctness, NoUpdate, distinct funding and no-work-credit controls."""
import copy
import json
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from service_work_settlement_v1 import (
    demo_case, execute_service, read_contract, reserve_contract, run_demo,
    settle_contract, supply_observation,
)


def key(label):
    return H('service-work-tests-v1', label.encode()).hex()


class ServiceWorkSettlementTests(unittest.TestCase):
    def setUp(self):
        self.book, self.raw, self.expected, self.material = demo_case()

    def reserve(self):
        self.book = reserve_contract(self.book, self.raw, self.expected, height=2)

    def complete(self, *, result=None, height=3, base_cost=None, bonus_cost=None):
        return settle_contract(self.book, self.raw, self.expected, height=height,
            outcome='complete', material=self.material,
            result=result if result is not None else execute_service(
                self.raw, self.expected, self.material),
            base_consumed=base_cost if base_cost is not None else
                {'evaluation_cpu_ns': 30, 'evaluated_examples': 200},
            bonus_consumed=bonus_cost if bonus_cost is not None else
                {'training_cpu_ns': 20, 'parameter_bytes': 100})

    def test_valid_no_update_pays_base_only_and_keeps_all_authority_closed(self):
        self.reserve()
        updated, report = self.complete()
        self.assertEqual(report['decision'], 'NoUpdate')
        self.assertEqual(report['conditional_base_fee_units'], 7)
        self.assertEqual(report['conditional_improvement_bonus_units'], 0)
        self.assertEqual(report['additional_consensus_credit'], 0)
        self.assertEqual(updated.summary()['additional_chainwork'], 0)
        for flag in ('work_profile_qualified', 'native_funding_verified',
                     'resource_cost_certified', 'independent_evaluation_certified',
                     'public_reward_eligible', 'external_payment_executed',
                     'model_adoption_authorized', 'production_activation'):
            self.assertIs(report[flag], False)
        self.assertEqual(report['evaluation_lane']['paid'], 7)
        self.assertEqual(report['contribution_lane']['paid'], 0)

    def test_measured_improvement_has_separate_beneficiary_and_funding(self):
        self.book, self.raw, self.expected, self.material = demo_case('improved')
        self.reserve()
        updated, report = self.complete()
        self.assertEqual(report['decision'], 'MeasuredImprovement')
        self.assertEqual(report['conditional_base_fee_units'], 7)
        self.assertEqual(report['conditional_improvement_bonus_units'], 11)
        claims = list(updated.branch.claims.values())
        self.assertEqual(len({c.beneficiary for c in claims}), 2)
        self.assertEqual(len({updated.branch.budgets[c.budget].source for c in claims}), 2)
        self.assertEqual(report['additional_consensus_credit'], 0)
        self.assertFalse(report['external_payment_executed'])

    def test_retention_loss_blocks_bonus_but_not_completed_evaluation_fee(self):
        self.book, self.raw, self.expected, self.material = demo_case('retention-regression')
        self.reserve()
        result = json.loads(execute_service(self.raw, self.expected, self.material))
        self.assertTrue(all(c['cluster_gate'] for c in result['comparisons'].values()))
        self.assertEqual(result['retention_regressions'], 20)
        _, report = self.complete(result=canonical(result))
        self.assertEqual(report['decision'], 'NoUpdate')
        self.assertEqual((report['conditional_base_fee_units'],
                          report['conditional_improvement_bonus_units']), (7, 0))

    def test_one_stronger_control_blocks_bonus(self):
        self.book, self.raw, self.expected, self.material = demo_case('improved')
        self.material['controls']['pooled'] = copy.deepcopy(self.material['candidate'])
        self._repin_material()
        self.reserve()
        _, report = self.complete()
        self.assertEqual(report['decision'], 'NoUpdate')
        self.assertEqual(report['conditional_improvement_bonus_units'], 0)

    def _repin_material(self):
        # Explicitly models a new owner-frozen test contract, never a producer override.
        from service_work_settlement_v1 import material_identity
        contract = json.loads(self.raw)
        contract['material'] = material_identity(self.material)
        self.raw = canonical(contract)
        self.expected = H('service-work-contract-v1', self.raw).hex()

    def test_incomplete_cluster_support_is_no_update_not_free_bonus(self):
        self.book, self.raw, self.expected, self.material = demo_case('improved')
        self.material['evaluation'] = self.material['evaluation'][:1]
        self._repin_material()
        self.reserve()
        _, report = self.complete()
        self.assertEqual(report['decision'], 'NoUpdate')
        self.assertEqual(report['conditional_base_fee_units'], 7)
        self.assertEqual(report['conditional_improvement_bonus_units'], 0)

    def test_full_output_replay_rejects_product_omission_and_forged_decision(self):
        self.reserve()
        original = json.loads(execute_service(self.raw, self.expected, self.material))
        before = copy.deepcopy(self.book.__dict__)
        mutations = []
        value = copy.deepcopy(original)
        del value['outputs']['evaluation']['candidate']['products']
        mutations.append(value)
        value = copy.deepcopy(original)
        value['outputs']['retention']['current']['products'][14][0] = 1
        mutations.append(value)
        value = copy.deepcopy(original)
        value['decision'] = 'MeasuredImprovement'
        mutations.append(value)
        value = copy.deepcopy(original)
        value['work_profile_qualified'] = True
        mutations.append(value)
        for value in mutations:
            with self.subTest(value=value.keys()), self.assertRaisesRegex(
                    ValueError, 'SERVICE_COMPLETE_REPLAY'):
                self.complete(result=canonical(value))
            self.assertEqual(self.book.__dict__, before)

    def test_unselected_expert_output_must_be_replayed(self):
        self.reserve()
        result = json.loads(execute_service(self.raw, self.expected, self.material))
        # All routes are zero; this is an unselected expert product, not a chosen logit.
        result['outputs']['evaluation']['candidate']['products'][14][0] += 1
        with self.assertRaisesRegex(ValueError, 'SERVICE_COMPLETE_REPLAY'):
            self.complete(result=canonical(result))

    def test_external_expected_context_refuses_self_consistent_replacement(self):
        contract = json.loads(self.raw)
        contract['consumer'] = key('replacement-consumer')
        replaced = canonical(contract)
        with self.assertRaisesRegex(ValueError, 'SERVICE_EXPECTED_CONTEXT'):
            reserve_contract(self.book, replaced, self.expected, height=2)
        changed = copy.deepcopy(self.material)
        changed['evaluation'][0]['label'] = 0
        with self.assertRaisesRegex(ValueError, 'SERVICE_MATERIAL_BINDING'):
            execute_service(self.raw, self.expected, changed)

    def test_material_binding_and_execution_use_the_same_private_snapshot(self):
        import service_work_settlement_v1 as settlement
        expected_result = execute_service(self.raw, self.expected, self.material)
        original_material = copy.deepcopy(self.material)
        bounded_copy = settlement._bounded_copy
        mutated = False

        def copy_then_mutate_external(value, code):
            nonlocal mutated
            snapshot = bounded_copy(value, code)
            if value is self.material and not mutated:
                # Deterministically change the caller's original only after its
                # first private snapshot has been completed. No timing/thread race.
                self.material['candidate']['base'][1][-1] = 1
                mutated = True
            return snapshot

        with patch.object(settlement, '_bounded_copy', side_effect=copy_then_mutate_external):
            result = execute_service(self.raw, self.expected, self.material)
        self.assertTrue(mutated)
        self.assertNotEqual(self.material, original_material)
        self.assertEqual(json.loads(result)['decision'], 'NoUpdate')
        self.assertEqual(result, expected_result)

    def test_contract_rejects_caller_work_qualification_and_identity_alias(self):
        contract = json.loads(self.raw)
        contract['work_profile_qualified'] = True
        raw = canonical(contract)
        with self.assertRaisesRegex(ValueError, 'SERVICE_CONTRACT_FIELDS'):
            read_contract(raw, H('service-work-contract-v1', raw).hex())
        contract = json.loads(self.raw)
        contract['service_provider'] = contract['improvement_beneficiary']
        raw = canonical(contract)
        with self.assertRaisesRegex(ValueError, 'EVALUATOR_AUTHOR_ALIAS'):
            read_contract(raw, H('service-work-contract-v1', raw).hex())

    def test_unknown_keeps_money_resources_and_exact_original_claims(self):
        self.reserve()
        before = copy.deepcopy(self.book.__dict__)
        updated, report = settle_contract(self.book, self.raw, self.expected,
                                         height=41, outcome='unknown')
        self.assertEqual(self.book.__dict__, before)
        self.assertEqual(updated.branch, self.book.branch)
        for claim, job in updated._resource_jobs.items():
            original = copy.deepcopy(self.book._resource_jobs[claim])
            original['service_work_last_height_v1'] = 41
            actual = copy.deepcopy(job)
            resolution = actual.pop('service_work_resolution_v1')
            self.assertEqual(resolution['schema'], 'pon-service-work-local-resolution-v1')
            self.assertEqual(resolution['contract'], self.expected)
            self.assertEqual(resolution['outcome'], 'unknown')
            self.assertIsNone(resolution['result_digest'])
            self.assertIsNone(resolution['base_consumed'])
            self.assertIsNone(resolution['bonus_consumed'])
            self.assertEqual(actual, original)
        self.assertEqual(report['status'], 'PENDING_UNKNOWN')
        self.assertTrue(report['original_reservations_retained'])
        self.assertEqual(report['evaluation_lane']['reserved'], 7)
        self.assertEqual(report['contribution_lane']['reserved'], 11)
        for budget in updated.summary()['resource_liabilities'].values():
            self.assertTrue(any(budget['reserved'].values()))
        with self.assertRaisesRegex(ValueError, 'SERVICE_UNKNOWN_NOT_TERMINAL'):
            settle_contract(self.book, self.raw, self.expected, height=3, outcome='unknown',
                            base_consumed={'evaluation_cpu_ns': 0, 'evaluated_examples': 0})

    def test_unknown_can_finish_once_without_new_reservation(self):
        self.reserve()
        self.book, _ = settle_contract(self.book, self.raw, self.expected,
                                      height=3, outcome='unknown')
        updated, report = self.complete(height=4)
        self.assertEqual(report['conditional_base_fee_units'], 7)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ALREADY_RESOLVED'):
            settle_contract(updated, self.raw, self.expected, height=5, outcome='unknown')

    def test_observed_expiry_cannot_be_backdated_after_unknown_or_branch_rewind(self):
        checkpoint = self.book.checkpoint()
        self.reserve()
        self.book, _ = settle_contract(self.book, self.raw, self.expected,
                                      height=41, outcome='unknown')
        with self.assertRaisesRegex(ValueError, 'SERVICE_HEIGHT_REWIND'):
            self.complete(height=3)
        with self.assertRaisesRegex(ValueError, 'SERVICE_HEIGHT_REWIND'):
            supply_observation(self.book, [(self.raw, self.expected)], height=3)
        self.book.reorg(checkpoint)
        with self.assertRaisesRegex(ValueError, 'SERVICE_HEIGHT_REWIND'):
            reserve_contract(self.book, self.raw, self.expected, height=2)

    def test_failure_and_cancellation_are_not_successful_no_update(self):
        self.reserve()
        for outcome in ('invalid', 'cancelled'):
            updated, report = settle_contract(self.book, self.raw, self.expected,
                height=3, outcome=outcome,
                base_consumed={'evaluation_cpu_ns': 30, 'evaluated_examples': 1},
                bonus_consumed={'training_cpu_ns': 20, 'parameter_bytes': 100})
            self.assertIsNone(report['decision'])
            self.assertEqual(report['conditional_base_fee_units'], 0)
            self.assertEqual(report['conditional_improvement_bonus_units'], 0)
            self.assertEqual(sum(v['used'].get('evaluation_cpu_ns', 0)
                for v in updated.summary()['resource_liabilities'].values()), 30)
        with self.assertRaisesRegex(ValueError, 'SERVICE_FAILED_RESULT'):
            settle_contract(self.book, self.raw, self.expected, height=3, outcome='invalid',
                result=b'{}', base_consumed={'evaluation_cpu_ns': 1, 'evaluated_examples': 1},
                bonus_consumed={'training_cpu_ns': 1, 'parameter_bytes': 1})

    def test_repeated_or_renamed_contract_cannot_collect_again(self):
        self.reserve()
        self.book, _ = self.complete()
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ALREADY_RESOLVED'):
            self.complete()
        contract = json.loads(self.raw)
        contract['consumer'] = key('different-consumer')
        renamed = canonical(contract)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_CONTRACT'):
            reserve_contract(self.book, renamed,
                H('service-work-contract-v1', renamed).hex(), height=4)
        self.assertEqual(self.book.__dict__, before)

    def test_base_reservation_does_not_publish_when_bonus_fails(self):
        contract = json.loads(self.raw)
        contract['bonus_fee'] = 101
        raw = canonical(contract)
        expected = H('service-work-contract-v1', raw).hex()
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'BUDGET_FUNDS'):
            reserve_contract(self.book, raw, expected, height=2)
        self.assertEqual(self.book.__dict__, before)
        self.assertEqual(len(self.book.branch.claims), 0)

    def test_each_budget_must_mature_before_the_entire_service_window(self):
        for prefix, lane in (('base', 'evaluation'), ('bonus', 'contribution')):
            for maturity in (2, 41):
                with self.subTest(lane=lane, maturity=maturity):
                    book, raw, _, _ = demo_case()
                    contract = json.loads(raw)
                    original = book.branch.budgets[contract[prefix + '_budget']]
                    source = key(lane + '-future-source')
                    budget = key(lane + '-future-budget')
                    # These are valid planner budgets: one matures inside the
                    # service window, the other only after the entire window.
                    book.register_funding(source=source, lane=lane, amount=100, height=1)
                    book.open_budget(budget=budget, source=source, lane=lane, cap=100,
                        maturity=maturity, deadline=50, resource_cap=original.resource_cap)
                    contract[prefix + '_budget'] = budget
                    raw = canonical(contract)
                    expected = H('service-work-contract-v1', raw).hex()
                    before = copy.deepcopy(book.__dict__)
                    with self.assertRaisesRegex(ValueError, 'SERVICE_BUDGET_IMMATURE_AT_ISSUE'):
                        reserve_contract(book, raw, expected, height=2)
                    self.assertEqual(book.__dict__, before)
                    self.assertEqual(len(book.branch.claims), 0)

    def test_base_payment_does_not_publish_when_bonus_resource_cost_overruns(self):
        self.reserve()
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'BUDGET_OVERRUN'):
            self.complete(bonus_cost={'training_cpu_ns': 51, 'parameter_bytes': 100})
        self.assertEqual(self.book.__dict__, before)
        self.assertEqual(self.book.summary()['lanes']['evaluation']['paid'], 0)

    def test_wrong_budget_lane_or_mining_money_cannot_fund_the_service(self):
        from reward_budget_oracle import mining_reward_limit
        contract = json.loads(self.raw)
        contract['base_budget'], contract['bonus_budget'] = (
            contract['bonus_budget'], contract['base_budget'])
        raw = canonical(contract)
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_FUNDING_LANES'):
            reserve_contract(self.book, raw, H('service-work-contract-v1', raw).hex(), height=2)
        self.assertEqual(self.book.__dict__, before)
        self.book.register_funding(source=key('mining-source'), lane='mining',
            amount=mining_reward_limit(1, 0), height=1, fees=0)
        self.book.open_budget(budget=key('mining-budget'), source=key('mining-source'),
            lane='mining', cap=100, maturity=21, deadline=50,
            resource_cap={'verified_work_units': 100, 'cpu_ns': 100})
        contract = json.loads(self.raw)
        contract['base_budget'] = key('mining-budget')
        raw = canonical(contract)
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_FUNDING_LANES'):
            reserve_contract(self.book, raw, H('service-work-contract-v1', raw).hex(), height=2)
        self.assertEqual(self.book.__dict__, before)

    def test_resources_or_beneficiary_cannot_change_after_reservation(self):
        self.reserve()
        contract = json.loads(self.raw)
        for field, replacement in (
                ('service_provider', key('other-payee')),
                ('base_reservation', {'evaluation_cpu_ns': 51, 'evaluated_examples': 200})):
            changed = copy.deepcopy(contract)
            changed[field] = replacement
            raw = canonical(changed)
            with self.assertRaisesRegex(ValueError, 'SERVICE_RESERVATION_BINDING'):
                settle_contract(self.book, raw, H('service-work-contract-v1', raw).hex(),
                                height=3, outcome='unknown')

    def test_task_policy_material_and_deadline_pins_survive_branch_rewind(self):
        checkpoint = self.book.checkpoint()
        self.reserve()
        for field, replacement in (('minimum_gain_ppm', 2), ('material', key('other-material')),
                                   ('deadline_height', 41), ('max_retention_regressions', 1)):
            contract = json.loads(self.raw)
            contract[field] = replacement
            raw = canonical(contract)
            expected = H('service-work-contract-v1', raw).hex()
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, 'SERVICE_ORIGINAL_CONTRACT'):
                settle_contract(self.book, raw, expected, height=3, outcome='unknown')
        self.book.reorg(checkpoint)
        contract = json.loads(self.raw)
        contract['minimum_gain_ppm'] = 2
        raw = canonical(contract)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_CONTRACT'):
            reserve_contract(self.book, raw, H('service-work-contract-v1', raw).hex(), height=2)
        replay = reserve_contract(self.book, self.raw, self.expected, height=2)
        self.assertEqual(replay.summary()['physical_resource_jobs'], 2)
        self.book = replay
        _, report = self.complete()
        self.assertEqual(report['conditional_base_fee_units'], 7)

    def test_deadline_expiry_and_unsupported_no_update_event_refuse(self):
        self.reserve()
        with self.assertRaisesRegex(ValueError, 'SERVICE_WINDOW'):
            self.complete(height=40)
        with self.assertRaisesRegex(ValueError, 'SERVICE_OUTCOME'):
            settle_contract(self.book, self.raw, self.expected, height=3, outcome='NoUpdate')

    def test_numeric_aliases_duplicate_tasks_and_overlap_refuse(self):
        for value in (True, -1, 1 << 64):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'BUDGET_UNITS'):
                reserve_contract(self.book, self.raw, self.expected, height=value)
        from service_work_settlement_v1 import material_identity
        changed = copy.deepcopy(self.material)
        changed['evaluation'].append(copy.deepcopy(changed['evaluation'][0]))
        with self.assertRaisesRegex(ValueError, 'SERVICE_TASK_REPLAY'):
            material_identity(changed)
        changed = copy.deepcopy(self.material)
        changed['retention'][0]['source_group'] = changed['evaluation'][0]['source_group']
        with self.assertRaisesRegex(ValueError, 'SERVICE_PARTITION_OVERLAP'):
            material_identity(changed)

    def test_empty_and_finite_supply_never_fabricate_liveness_or_filler(self):
        empty = supply_observation(self.book, [], height=2)
        self.assertTrue(empty['no_pending_contracts'])
        self.assertFalse(empty['synthetic_fill_authorized'])
        self.assertFalse(empty['liveness_qualified'])
        self.reserve()
        observed = supply_observation(self.book, [(self.raw, self.expected)], height=3)
        self.assertEqual(observed['pending_contracts'], 1)
        self.assertEqual(observed['conditional_base_reservations'], 7)
        self.assertFalse(observed['actual_demand_verified'])
        self.assertFalse(observed['liveness_qualified'])
        self.assertEqual(supply_observation(self.book, [(self.raw, self.expected)],
                                          height=40)['pending_contracts'], 0)
        with self.assertRaisesRegex(ValueError, 'SERVICE_SUPPLY_REPLAY'):
            supply_observation(self.book, [(self.raw, self.expected)] * 2, height=3)

    def test_demo_is_explicitly_synthetic_and_never_records_payment(self):
        report = run_demo()
        self.assertIn('synthetic', report['fixture'])
        self.assertTrue(all(r['external_payment_executed'] is False
                            for r in report['scenarios'].values()))
        self.assertEqual(report['qualification'], 'HOLD')


class ServiceWorkResolutionTests(unittest.TestCase):
    """Keep local outcome history separate from reversible monetary claims."""

    def setUp(self):
        self.book, self.raw, self.expected, self.material = demo_case()
        self.before_reservation = self.book.checkpoint()
        self.book = reserve_contract(self.book, self.raw, self.expected, height=2)
        self.after_reservation = self.book.checkpoint()

    def resolve(self, outcome='complete', *, height=3, result=None, base_cpu=30):
        kwargs = {}
        if outcome != 'unknown':
            kwargs.update(base_consumed={'evaluation_cpu_ns': base_cpu,
                                         'evaluated_examples': 200},
                          bonus_consumed={'training_cpu_ns': 20, 'parameter_bytes': 100})
        if outcome == 'complete':
            kwargs.update(material=self.material, result=result if result is not None
                          else execute_service(self.raw, self.expected, self.material))
        return settle_contract(self.book, self.raw, self.expected, height=height,
                               outcome=outcome, **kwargs)

    def supply(self, height=3):
        return supply_observation(self.book, [(self.raw, self.expected)], height=height)

    def test_completed_service_cannot_become_cancelled_after_reorg(self):
        self.book, _ = self.resolve()
        self.book.reorg(self.after_reservation)
        original = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_RESOLUTION'):
            self.resolve('cancelled', height=4)
        self.assertEqual(self.book.__dict__, original)

    def test_cancelled_service_cannot_become_complete_after_reorg(self):
        self.book, _ = self.resolve('cancelled')
        self.book.reorg(self.after_reservation)
        original = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_RESOLUTION'):
            self.resolve(height=4)
        self.assertEqual(self.book.__dict__, original)

    def test_completed_service_cannot_become_unknown_after_reorg(self):
        self.book, _ = self.resolve()
        self.book.reorg(self.after_reservation)
        original = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_RESOLUTION'):
            self.resolve('unknown', height=4)
        self.assertEqual(self.book.__dict__, original)

    def test_exact_terminal_reapplication_preserves_costs_and_external_intent(self):
        self.book, first = self.resolve()
        claim = next(key for key, value in self.book.branch.claims.items() if value.paid)
        operation, effect, receipt = key('one-payment'), key('payment-effect'), key('payment-receipt')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation,
                                                   effect=effect), 'new')
        self.book.finish_external(lane='evaluation', subject=json.loads(self.raw)['task'],
                                  operation=operation, receipt=receipt)
        original_jobs = copy.deepcopy(self.book._resource_jobs)
        original_effects = copy.deepcopy(self.book._effects)
        original_costs = self.book.summary()['resource_liabilities']
        self.book.reorg(self.after_reservation)
        observed = self.supply()
        self.assertEqual(observed['pending_contracts'], 1)  # Monetary reservation only.
        self.assertEqual(observed['recorded_terminal_contracts'], 1)
        self.assertEqual(observed['reserved_unobserved_contracts'], 0)
        self.assertEqual(observed['reconciliation_required_contracts'], 1)
        self.assertFalse(observed['execution_dispatch_authorized'])
        self.assertFalse(observed['fresh_work_supply_verified'])
        self.book, replay = self.resolve(height=4)
        self.assertEqual(replay['schema'], 'pon-service-work-settlement-reference-v2')
        self.assertTrue(replay['local_resolution_replayed'])
        self.assertFalse(first['local_resolution_replayed'])
        self.assertFalse(replay['execution_dispatch_authorized'])
        self.assertEqual(replay['additional_consensus_credit'], 0)
        self.assertEqual(self.book.summary()['resource_liabilities'], original_costs)
        self.assertEqual(self.book._effects, original_effects)
        for identity, job in original_jobs.items():
            self.assertEqual(self.book._resource_jobs[identity]['service_work_resolution_v1'],
                             job['service_work_resolution_v1'])
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation,
                                                   effect=effect), 'done')
        self.assertEqual(self.book.summary()['lanes']['evaluation']['paid'], 7)

    def test_terminal_result_bytes_and_cost_vector_remain_pinned(self):
        self.book, _ = self.resolve()
        self.book.reorg(self.after_reservation)
        original = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError,
                'BUDGET_RESOURCE_REPLAY_MISMATCH|SERVICE_ORIGINAL_RESOLUTION'):
            self.resolve(height=4, base_cpu=31)
        # Simulate a different verifier revision returning different complete
        # bytes for the same frozen service. A previous local result is immutable
        # even if a later accepting implementation would otherwise agree with it.
        changed = json.loads(execute_service(self.raw, self.expected, self.material))
        changed['later_diagnostic'] = 'different-result-bytes'
        changed = canonical(changed)
        with patch('service_work_settlement_v1.execute_service', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_RESOLUTION'):
                self.resolve(height=4, result=changed)
        self.assertEqual(self.book.__dict__, original)

    def test_unknown_is_retained_but_can_reconcile_to_one_terminal_outcome(self):
        self.book, _ = self.resolve('unknown')
        self.book, _ = self.resolve('unknown', height=4)
        self.book.reorg(self.after_reservation)
        observed = self.supply(height=4)
        self.assertEqual(observed['recorded_unknown_contracts'], 1)
        self.assertEqual(observed['reserved_unobserved_contracts'], 0)
        self.assertEqual(observed['resource_accounted_contracts'], 0)
        self.assertFalse(observed['execution_dispatch_authorized'])
        self.book, report = self.resolve(height=5)
        self.assertEqual(report['decision'], 'NoUpdate')
        self.assertFalse(report['local_resolution_replayed'])
        self.assertEqual(self.supply(height=5)['recorded_terminal_contracts'], 1)

    def test_expiry_and_orphaning_do_not_erase_unknown_or_terminal_history(self):
        for outcome in ('unknown', 'complete', 'invalid', 'cancelled'):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.book, _ = self.resolve(outcome)
                self.book.reorg(self.before_reservation)
                original = copy.deepcopy(self.book.__dict__)
                observed = self.supply(height=40)
                self.assertEqual(observed['pending_contracts'], 0)
                self.assertEqual(observed['expired_contracts'], 1)
                self.assertEqual(observed['orphaned_resource_contracts'], 1)
                self.assertEqual(observed['reconciliation_required_contracts'], 1)
                self.assertEqual(observed['observations'][0]['recorded_outcome'], outcome)
                self.assertFalse(observed['fresh_work_supply_verified'])
                self.assertFalse(observed['liveness_qualified'])
                self.assertEqual(self.book.__dict__, original)

    def test_reserve_after_branch_rewind_does_not_reset_terminal_outcome(self):
        self.book, _ = self.resolve('invalid')
        original_pins = [copy.deepcopy(j['service_work_resolution_v1'])
                         for j in self.book._resource_jobs.values()]
        self.book.reorg(self.before_reservation)
        self.book = reserve_contract(self.book, self.raw, self.expected, height=4)
        self.assertEqual([j['service_work_resolution_v1']
                          for j in self.book._resource_jobs.values()], original_pins)
        self.assertEqual(self.supply(height=4)['recorded_terminal_contracts'], 1)
        with self.assertRaisesRegex(ValueError, 'SERVICE_ORIGINAL_RESOLUTION'):
            self.resolve(height=4)

    def test_generic_close_accounts_resources_without_proving_execution(self):
        self.book, _ = self.resolve('unknown')
        contract = json.loads(self.raw)
        for budget in ('base_budget', 'bonus_budget'):
            self.book.close(budget=contract[budget], height=50)
        self.book.reorg(self.after_reservation)
        observed = self.supply(height=50)
        self.assertEqual(observed['recorded_unknown_contracts'], 1)
        self.assertEqual(observed['recorded_terminal_contracts'], 0)
        self.assertEqual(observed['resource_accounted_contracts'], 1)
        self.assertEqual(observed['reserved_unobserved_contracts'], 0)
        self.assertEqual(observed['observations'][0]['local_state'], 'unknown')
        self.assertFalse(observed['fresh_work_supply_verified'])

    def test_unbound_generic_resolution_is_not_a_service_completion(self):
        for claim, row in self.book.branch.claims.items():
            self.book.resolve(claim=claim, height=3, paid=0,
                              consumed=row.reserved, outcome='invalid')
        self.book.reorg(self.after_reservation)
        observed = self.supply()
        self.assertEqual(observed['resource_accounted_contracts'], 1)
        self.assertEqual(observed['recorded_terminal_contracts'], 0)
        self.assertEqual(observed['observations'][0]['local_state'],
                         'resource-accounted-outcome-unobserved')
        with self.assertRaisesRegex(ValueError, 'SERVICE_UNBOUND_PRIOR_RESOLUTION'):
            self.resolve('unknown', height=4)

    def test_two_resolution_pins_must_agree_and_bind_original_charge_vectors(self):
        self.book, _ = self.resolve()
        original = copy.deepcopy(self.book)
        jobs = list(self.book._resource_jobs.values())
        del jobs[0]['service_work_resolution_v1']
        with self.assertRaisesRegex(ValueError, 'SERVICE_RESOLUTION_PAIR'):
            self.supply()
        self.book = copy.deepcopy(original)
        for job in self.book._resource_jobs.values():
            job['service_work_resolution_v1']['base_consumed']['evaluation_cpu_ns'] = 31
        with self.assertRaisesRegex(ValueError, 'SERVICE_RESOLUTION_RESOURCE_BINDING'):
            self.supply()

    def test_unobserved_reservation_is_not_a_not_dispatched_certificate(self):
        original = copy.deepcopy(self.book.__dict__)
        observed = self.supply()
        self.assertEqual(observed['schema'], 'pon-service-work-supply-observation-v2')
        self.assertEqual(observed['pending_contracts'], 1)
        self.assertEqual(observed['reserved_unobserved_contracts'], 1)
        self.assertEqual(observed['observations'][0]['local_state'], 'unobserved')
        self.assertFalse(observed['execution_dispatch_authorized'])
        self.assertFalse(observed['fresh_work_supply_verified'])
        self.assertEqual(self.supply(height=40)['reserved_unobserved_contracts'], 0)
        self.assertEqual(self.book.__dict__, original)


if __name__ == '__main__':
    unittest.main()
