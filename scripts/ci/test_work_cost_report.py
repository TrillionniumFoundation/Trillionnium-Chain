#!/usr/bin/env python3
"""Same-target cost accounting counterexamples, not a work-hardness proof."""
import copy
import json
import sys
import tempfile
from unittest.mock import patch
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_work_cost_report as cost
from pon_work_cost_report import SOURCE_PATHS, encoded, source_inventory, summarize, target_value

TARGET = '7' + 'f' * 63


def fixture():
    return {'schema': 'pon-structured-cost-v3', 'target': TARGET,
            'fastest_adversary_implemented': False, 'hardness_accepted': False,
            'production_activation': False, 'samples': [
                {'class': name, 'sample': 0, 'honest_attempts': 2,
                 'honest_winning_ns': 8000, 'valid_verify_ns': 4000,
                 'forgery_hash_trials': 2, 'forgery_ns': 10, 'invalid_verify_ns': 4000}
                for name in ['dense', 'zero', 'rank-one', 'sparse']]}


class WorkCostAccountingTests(unittest.TestCase):
    def reject(self, mutate):
        raw = fixture()
        mutate(raw)
        with self.assertRaises((ValueError, KeyError)):
            summarize(raw, TARGET)

    def test_same_target_ratios_and_probability(self):
        result = summarize(fixture(), TARGET)
        self.assertEqual(result['assumed_uniform_ticket_probability'], {'numerator': '1', 'denominator': '2'})
        for row in result['classes'].values():
            self.assertEqual(row['invalid_rejection_to_forgery_ratio'], 400)
            self.assertEqual(row['honest_winner_to_valid_verification_ratio'], 2)
        self.assertFalse(result['work_hardness_accepted'])
        self.assertFalse(result['honest_public_service_measured'])

    def test_mixed_target_is_not_comparable(self):
        self.reject(lambda r: r.update(target='3' + 'f' * 63))

    def test_arbitrary_security_flag_rejects(self):
        self.reject(lambda r: r.update(hardness_accepted=True))

    def test_integer_zero_cannot_replace_false_scope(self):
        self.reject(lambda r: r.update(production_activation=0))

    def test_fastest_honest_code_is_not_fastest_attacker(self):
        self.reject(lambda r: r.update(fastest_adversary_implemented=True))

    def test_boolean_duration_rejects(self):
        self.reject(lambda r: r['samples'][0].update(valid_verify_ns=True))

    def test_boolean_attempt_count_rejects(self):
        self.reject(lambda r: r['samples'][0].update(honest_attempts=True))

    def test_boolean_sample_identity_rejects(self):
        self.reject(lambda r: r['samples'][0].update(sample=False))

    def test_zero_denominator_rejects(self):
        self.reject(lambda r: r['samples'][0].update(forgery_ns=0))

    def test_negative_duration_rejects(self):
        self.reject(lambda r: r['samples'][0].update(invalid_verify_ns=-1))

    def test_float_duration_rejects(self):
        self.reject(lambda r: r['samples'][0].update(valid_verify_ns=4.0))

    def test_counter_outside_native_budget_rejects(self):
        self.reject(lambda r: r['samples'][0].update(honest_attempts=4097))

    def test_duplicate_samples_cannot_inflate_evidence(self):
        self.reject(lambda r: r['samples'].append(copy.deepcopy(r['samples'][0])))

    def test_missing_structured_comparison_rejects(self):
        self.reject(lambda r: r['samples'].pop())

    def test_empty_sample_set_rejects(self):
        self.reject(lambda r: r.update(samples=[]))

    def test_unhashable_class_rejects_as_input_error(self):
        self.reject(lambda r: r['samples'][0].update({'class': []}))

    def test_extra_scope_claim_rejects(self):
        self.reject(lambda r: r.update(independent_accepted=True))

    def test_per_sample_target_cannot_hide_mixed_context(self):
        self.reject(lambda r: r['samples'][0].update(target='3' + 'f' * 63))

    def test_summary_does_not_mutate_raw_observations(self):
        raw = fixture()
        original = encoded(raw)
        summarize(raw, TARGET)
        self.assertEqual(encoded(raw), original)

    def test_target_is_canonical_positive_fixed_width(self):
        for value in ['0' * 64, 'F' * 64, 'f' * 63, 'f' * 65, '', True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                target_value(value)

    def test_actual_retained_samples_can_be_summarized_without_rerun(self):
        path = Path(__file__).resolve().parents[2] / 'evidence/pon-v3/work/structured.json'
        raw = json.loads(path.read_text())
        result = summarize(raw, TARGET)
        self.assertEqual(sum(v['samples'] for v in result['classes'].values()), len(raw['samples']))
        self.assertFalse(result['public_network_tested'])

    def test_source_inventory_cannot_omit_collector_or_configuration(self):
        with self.assertRaises(ValueError):
            source_inventory(SOURCE_PATHS - {'config/pon/work-profile-v1.json'})

    def test_inventory_includes_native_sources_but_not_doc_edits(self):
        paths = SOURCE_PATHS | {'trillionnium/Cargo.lock', 'trillionnium/crates/a/src/lib.rs', 'trillionnium/README.md'}
        result = source_inventory(paths)
        self.assertIn('trillionnium/Cargo.lock', result)
        self.assertIn('trillionnium/crates/a/src/lib.rs', result)
        self.assertNotIn('trillionnium/README.md', result)


class CostEvidenceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pon-cost-receipt-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = {p: b'measured source' for p in SOURCE_PATHS}
        self.original['config/pon/devnet-v1.json'] = encoded({'initial_target_hex': TARGET})
        self.hashes = {p: cost.digest(raw) for p, raw in self.original.items()}
        self.record = {
            'schema': 'pon-native-cost-execution-v1', 'source_commit': 'a' * 40,
            'source_tree': 'b' * 40, 'source_clean_before_and_after': True,
            'source_files_sha256': self.hashes, 'build_command': cost.BUILD_COMMAND,
            'build_returncode': 0, 'returncode': 0, 'command': ['/measured/pon_adversarial_cost'],
            'binary_sha256': 'c' * 64, 'process_wall_ns': 20000, 'target': TARGET,
            **{flag: False for flag in cost.FALSE_FLAGS}}
        for name, raw in [('build.log', b'build complete'), ('native-work.json', encoded(fixture())),
                          ('native-stderr.log', b''), ('summary.json', encoded(summarize(fixture(), TARGET)))]:
            (self.root / name).write_bytes(raw)
        self.save_record()
        self.refresh_manifest()

    def save_record(self):
        (self.root / 'execution.json').write_bytes(encoded(self.record))

    def refresh_manifest(self):
        names = ['build.log', 'native-work.json', 'native-stderr.log', 'summary.json', 'execution.json']
        self.manifest = {'schema': 'pon-native-cost-files-v1',
                         'files': {name: cost.digest((self.root / name).read_bytes()) for name in names},
                         **{flag: False for flag in cost.FALSE_FLAGS}}
        (self.root / 'manifest.json').write_bytes(encoded(self.manifest))

    def verify(self, current=None, historical=False):
        def git(*args):
            if args[0] == 'rev-parse': return 'b' * 40
            if args[0] == 'ls-tree': return '\n'.join(sorted(SOURCE_PATHS))
            self.fail('unexpected Git request')
        with patch.object(cost, 'git', git), patch.object(cost, 'source_bytes', return_value=self.original), \
             patch.object(cost, 'current_inputs', return_value=self.hashes if current is None else current):
            return cost.verify(self.root, require_current=not historical)

    def test_authentic_receipt_reports_no_new_execution(self):
        result = self.verify()
        self.assertTrue(result['current_measured_inputs_match'])
        self.assertFalse(result['experiment_reexecuted_by_verifier'])
        self.assertFalse(result['independent_accepted'])

    def test_modified_raw_cost_rejects_before_summary(self):
        (self.root / 'native-work.json').write_bytes(b'{}')
        with self.assertRaises(ValueError): self.verify()

    def test_rehashed_wrong_summary_is_not_measurement(self):
        value = summarize(fixture(), TARGET)
        value['classes']['dense']['invalid_rejection_to_forgery_ratio'] = 1
        (self.root / 'summary.json').write_bytes(encoded(value))
        self.refresh_manifest()
        with self.assertRaises(ValueError): self.verify()

    def test_rehashed_target_change_cannot_replace_measured_configuration(self):
        other = '3' + 'f' * 63
        raw = fixture(); raw['target'] = other
        (self.root / 'native-work.json').write_bytes(encoded(raw))
        (self.root / 'summary.json').write_bytes(encoded(summarize(raw, other)))
        self.record['target'] = other
        self.save_record(); self.refresh_manifest()
        with self.assertRaises(ValueError): self.verify()

    def test_rehashed_missing_source_cannot_claim_historical_verification(self):
        self.record['source_files_sha256'] = dict(self.hashes)
        self.record['source_files_sha256'].pop('rust-toolchain.toml')
        self.save_record(); self.refresh_manifest()
        with self.assertRaises(ValueError): self.verify(historical=True)

    def test_different_build_command_cannot_supply_recorded_native_cost(self):
        self.record['build_command'] = ['echo', 'success']
        self.save_record(); self.refresh_manifest()
        with self.assertRaises(ValueError): self.verify()

    def test_boolean_return_code_is_not_success(self):
        self.record['returncode'] = False
        self.save_record(); self.refresh_manifest()
        with self.assertRaises(ValueError): self.verify()

    def test_old_costs_remain_historical_after_source_change(self):
        current = dict(self.hashes); current['rust-toolchain.toml'] = '0' * 64
        with self.assertRaises(ValueError): self.verify(current=current)
        result = self.verify(current=current, historical=True)
        self.assertFalse(result['current_measured_inputs_match'])
        self.assertFalse(result['experiment_reexecuted_by_verifier'])



class WorkSecurityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.raw = fixture()
        self.raw['samples'] = [dict(row, sample=i) for row in self.raw['samples'] for i in range(8)]
        self.prepared = {'schema': 'pon-prepared-producer-cost-v1',
                         'fastest_adversary_qualified': False, 'public_service_measured': False,
                         'production_activation': False, 'samples': [
            {'class': c, 'target': t, 'sample': i, 'baseline_first': i % 2 == 0,
             'attempts': 2, 'baseline_ns': 8000, 'prepared_setup_ns': 4000,
             'prepared_search_ns': 2000, 'prepared_total_ns': 6000,
             'original_verifier_ns': 4000, 'proof_bytes': 49188, 'proof_commitment': 'a' * 64}
            for c in sorted(cost.CLASSES) for t in [TARGET, '07' + 'f' * 62] for i in range(8)]}
        self.policy = cost.load(cost.ACCEPTANCE_PROFILE)['service']
        self.service = {'schema': 'pon-work-service-events-v1', 'target': TARGET,
                        'window_ns': 60_000_000_000, 'scope': 'controlled-local',
                        'acceptance_profile_sha256': cost.digest(cost.ACCEPTANCE_PROFILE.read_bytes()),
                        'attacker_setup_cpu_ns': 100,
                        'independent_accepted': False, 'production_activation': False,
                        'honest': [{'id': i, 'offered_ns': i * 500_000_000, 'finished_ns': i * 500_000_000 + 10,
                                    'outcome': 'accepted'} for i in range(100)],
                        'attacker': [{'id': i, 'offered_ns': i * 500_000_000, 'finished_ns': i * 500_000_000 + 10,
                                      'outcome': 'rejected', 'construction_cpu_ns': 10,
                                      'encoded_bytes': 49188, 'rejection_cpu_ns': 1000}
                                     for i in range(100)]}

    def evaluate(self):
        return cost.acceptance(self.raw, self.prepared, TARGET)

    def service_result(self):
        return cost.service_acceptance(self.service, TARGET, self.policy)

    def test_cheapest_implemented_miner_and_setup_amortization(self):
        rows = self.evaluate()['costs']
        dense = [r for r in rows if r['class'] == 'dense']
        self.assertEqual([r['prepared_mean_winner_ns'] for r in dense], [6000, 2500, 2062.5])
        self.assertTrue(dense[0]['winning_cost_gate'])
        self.assertFalse(dense[1]['winning_cost_gate'])
        self.assertEqual(dense[0]['honest_attempts'], 16)
        self.assertFalse(dense[0]['invalid_cost_gate'])

    def test_missing_service_stays_unmeasured_and_no_activation(self):
        result = self.evaluate()
        self.assertEqual(result['service']['status'], 'unmeasured')
        self.assertEqual(result['local_observation_gate'], 'not-accepted')
        self.assertFalse(result['source_applicability_verified'])
        for flag in cost.FALSE_FLAGS:
            self.assertIs(result[flag], False)

    def test_all_rows_used_in_implementation_choice_not_sample_minima(self):
        for row in self.prepared['samples']:
            row['prepared_search_ns'] = 16000 if row['sample'] else 1
            row['prepared_total_ns'] = row['prepared_setup_ns'] + row['prepared_search_ns']
        self.assertTrue(all(r['cheapest_supplied_valid_producer'] == 'baseline' for r in self.evaluate()['costs']))

    def test_prepared_invalid_samples_fail_closed(self):
        for field, value in [('attempts', True), ('prepared_setup_ns', 0),
                             ('prepared_total_ns', 2000), ('baseline_first', 1),
                             ('proof_bytes', 1), ('proof_commitment', 'bad'),
                             ('prepared_search_ns', float('nan')), ('baseline_ns', float('inf'))]:
            raw = copy.deepcopy(self.prepared)
            raw['samples'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                cost.prepared_samples(raw)

    def test_missing_or_duplicated_prepared_rows_reject(self):
        for samples in [self.prepared['samples'][:-1], self.prepared['samples'] + self.prepared['samples'][:1]]:
            raw = dict(self.prepared, samples=samples)
            with self.assertRaises(ValueError): cost.prepared_samples(raw)

    def test_insufficient_invalid_samples_cannot_pass(self):
        with self.assertRaises(ValueError): cost.acceptance(fixture(), self.prepared, TARGET)

    def test_event_local_pass_is_not_external_acceptance(self):
        self.assertEqual(self.service_result()['status'], 'pass')
        report = cost.acceptance(self.raw, self.prepared, TARGET, self.service)
        self.assertFalse(report['honest_public_service_measured'])
        self.assertFalse(report['independent_accepted'])

    def test_timeout_and_drop_stay_in_offered_denominator(self):
        for outcome in ['timeout', 'dropped']:
            self.service['honest'][0].update(outcome=outcome, finished_ns=None)
            result = self.service_result()
            self.assertEqual(result['honest_offered'], 100)
            self.assertEqual(result['honest_completed'], 99)
            self.assertEqual(result['honest_failures'], 1)
            self.assertEqual(result['status'], 'fail')

    def test_slow_success_fails_tail_latency_gate(self):
        for row in self.service['honest'][:2]: row['finished_ns'] = row['offered_ns'] + 3_000_000_000
        self.assertFalse(self.service_result()['checks']['honest_p99_deadline'])

    def test_small_success_only_denominator_fails(self):
        self.service['honest'] = self.service['honest'][:1]
        self.assertEqual(self.service_result()['status'], 'fail')

    def test_nominal_window_cannot_hide_instantaneous_burst(self):
        for row in self.service['attacker']:
            row['offered_ns'] = 0
        self.assertFalse(self.service_result()['checks']['attacker_offer_span'])

    def test_empty_attack_is_not_attack_acceptance(self):
        self.service['attacker'] = []
        self.assertFalse(self.service_result()['checks']['attacker_offered_denominator'])

    def test_attacker_cpu_and_byte_budgets_are_enforced(self):
        self.service['attacker'][0]['construction_cpu_ns'] = 60_000_000_001
        self.service['attacker'][0]['encoded_bytes'] = 67_108_865
        checks = self.service_result()['checks']
        self.assertFalse(checks['attacker_cpu_budget'])
        self.assertFalse(checks['attacker_byte_budget'])

    def test_wrong_service_target_or_claim_rejects(self):
        for key, value in [('target', '3' + 'f' * 63), ('scope', 'public'), ('independent_accepted', True), ('acceptance_profile_sha256', '0' * 64)]:
            raw = dict(self.service, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                cost.service_acceptance(raw, TARGET, self.policy)

    def test_duplicate_events_cannot_inflate_denominator(self):
        self.service['honest'].append(self.service['honest'][0])
        with self.assertRaises(ValueError): self.service_result()

    def test_even_all_diagnostic_gates_pass_never_certifies_security(self):
        for row in self.raw['samples']:
            row['forgery_ns'] = row['invalid_verify_ns']
        for row in self.prepared['samples']:
            row['original_verifier_ns'] = 1000
        report = cost.acceptance(self.raw, self.prepared, TARGET, self.service)
        self.assertEqual(report['local_observation_gate'], 'pass')
        self.assertFalse(report['service']['hostile_service_qualified'])
        for flag in cost.FALSE_FLAGS:
            self.assertIs(report[flag], False)

    def test_rejected_terminal_response_is_completed_but_not_accepted(self):
        self.service['honest'][0]['outcome'] = 'rejected'
        result = self.service_result()
        self.assertEqual(result['honest_completed'], 100)
        self.assertEqual(result['honest_accepted'], 99)
        self.assertEqual(result['status'], 'fail')

    def test_forged_work_acceptance_rejects(self):
        self.service['attacker'][0]['outcome'] = 'accepted'
        with self.assertRaises(ValueError): self.service_result()

    def test_future_event_and_missing_success_completion_reject(self):
        for change in [{'offered_ns': 60_000_000_000}, {'finished_ns': None}, {'finished_ns': True}]:
            original = self.service['honest'][0]
            self.service['honest'][0] = dict(original, **change)
            with self.assertRaises(ValueError): self.service_result()
            self.service['honest'][0] = original


if __name__ == '__main__':
    unittest.main(verbosity=2)
