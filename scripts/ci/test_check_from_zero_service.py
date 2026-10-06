#!/usr/bin/env python3
"""Synthetic receipt mutations, never Rust execution or W1 proof evidence."""
import copy
import unittest
from check_from_zero_service import audit, NAMES, FALSE_FLAGS, unique


def fixture():
    def call(packet='honest'):
        return {'status': 'ok', 'returned_after_deadline': False,
                'elapsed_wall_ns': 1, 'deadline_ms': 2000,
                'request': {'packet': packet}, 'call_resources': {'thread_cpu_ns': 1}}
    phases, comparisons = [], []
    for i in range(2):
        attacks = []
        for j in range(8):
            request = call(str(j))
            request.update(status='refused', response={'value': {'error': 'WORK:Transcript'}})
            attacks.append({'construction': {'status': 'target_hit_unverified',
                'attempt_budget': 4096, 'setup_calls': 1, 'attacker_cpu_ns': 1,
                'winner_nonce': 0, 'packet': str(j),
                'attempts': [{'nonce': 0, 'target_hit': True}]}, 'call': request})
        phases.append({'phase': i, 'construction_count': 8, 'from_zero': attacks,
            'honest_reads': [call() for _ in range(8)], 'honest_submit': call(),
            'honest_read_successes': 8, 'finite_target_met': True,
            'full_native_state_equal': True, 'no_attack_accepted': True,
            'cpu_measurements_known': True, 'all_started_work_finished': True,
            'request_observations_complete': True, 'attacker_cpu_ns': 3,
            'all_preparation_resources': {'thread_cpu_ns': 1},
            'attack_actor_resources': {'thread_cpu_ns': 2}, 'late_transcript_rejections': 8,
            'request_observations': {'records_not_retained': 0, 'measurement_failures': 0,
                'counter_overflow': False, 'accepted_connections_seen': 17,
                'records': [{'complete': True} for _ in range(17)]},
            'service': {'error': None, 'metrics': {'mutation_cpu_clock_failures': 0,
                'work_started': 9, 'work_finished': 9, 'work_failed': 8,
                'mutation_cpu_charged_ns': 10, 'mutation_full_work_cpu_ns': 9}}})
        arms = [{'producer': name, 'reused': reused, 'equal_native_packet': True,
            'error': None, 'winner_packet': 'honest',
            'setup_calls': 0 if i == 1 and reused else 1,
            'resources': {'thread_cpu_ns': 1}, 'search_budget': 1,
            'trials': [{'nonce': 0, 'target_hit': True}]} for name in sorted(NAMES)
            for reused in (False, True)]
        comparisons.append({'phase': i, 'all_equal': True, 'rows': arms,
            'comparison_inside_concurrent_service_interval': False,
            'universal_cheapest_producer_claim': False})
    return {'schema': 'public-v3-local-from-zero-service-v2',
            **dict.fromkeys(FALSE_FLAGS, False), 'finite_target_met': True,
            'reopen_state_equal': True, 'cpu_domain_retained_across_owner_reopen': True,
            'phases': phases, 'producer_comparisons': comparisons}


class AccountingTests(unittest.TestCase):
    def reject(self, mutate):
        data = fixture()
        mutate(data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            audit(data)

    def test_complete_synthetic_fixture(self):
        self.assertEqual(audit(fixture())['result'], 'PASS')
    def test_missing_phase(self):
        self.reject(lambda d: d['phases'].pop())
    def test_single_success_cannot_replace_eight_reads(self):
        self.reject(lambda d: d['phases'][0].update(honest_reads=[d['phases'][0]['honest_reads'][0]], honest_read_successes=1))
    def test_late_read_cannot_use_false_timeliness_flag(self):
        self.reject(lambda d: d['phases'][0]['honest_reads'][0].update(elapsed_wall_ns=2_000_000_001))
    def test_failed_honest_submission(self):
        self.reject(lambda d: d['phases'][0]['honest_submit'].update(status='refused'))
    def test_missing_attack(self):
        self.reject(lambda d: d['phases'][0]['from_zero'].pop())
    def test_unknown_cpu_is_not_zero(self):
        self.reject(lambda d: d['phases'][0].update(attacker_cpu_ns=None))
    def test_boolean_cpu_is_not_integer(self):
        self.reject(lambda d: d['phases'][0]['attack_actor_resources'].update(thread_cpu_ns=True))
    def test_nested_cpu_double_count(self):
        self.reject(lambda d: d['phases'][0].update(attacker_cpu_ns=4))
    def test_wrong_attempt_nonce(self):
        self.reject(lambda d: d['phases'][0]['from_zero'][0]['construction']['attempts'][0].update(nonce=1))
    def test_boolean_nonce(self):
        self.reject(lambda d: d['phases'][0]['from_zero'][0]['construction']['attempts'][0].update(nonce=False))
    def test_exhaustion_cannot_have_submission(self):
        self.reject(lambda d: d['phases'][0]['from_zero'][0]['construction'].update(status='exhausted'))
    def test_accepted_attack_is_never_allowed(self):
        self.reject(lambda d: d['phases'][0]['from_zero'][0]['call'].update(status='ok'))
    def test_changed_submitted_packet(self):
        self.reject(lambda d: d['phases'][0]['from_zero'][0]['call']['request'].update(packet='other'))
    def test_missing_request_observation(self):
        self.reject(lambda d: d['phases'][0]['request_observations']['records'].pop())
    def test_incomplete_request(self):
        self.reject(lambda d: d['phases'][0]['request_observations']['records'][0].update(complete=False))
    def test_missing_started_work_completion(self):
        self.reject(lambda d: d['phases'][0]['service']['metrics'].update(work_finished=8))
    def test_omitted_producer(self):
        self.reject(lambda d: d['producer_comparisons'][0]['rows'].pop())
    def test_duplicate_producer_cannot_fill_roster(self):
        self.reject(lambda d: d['producer_comparisons'][0]['rows'].__setitem__(0, copy.deepcopy(d['producer_comparisons'][0]['rows'][1])))
    def test_wrong_winner_packet(self):
        self.reject(lambda d: d['producer_comparisons'][0]['rows'][0].update(winner_packet='changed'))
    def test_hidden_setup_on_reuse(self):
        self.reject(lambda d: d['producer_comparisons'][1]['rows'][1].update(setup_calls=1))
    def test_missing_producer_search_prefix(self):
        self.reject(lambda d: d['producer_comparisons'][0]['rows'][0].update(search_budget=2))
    def test_comparison_cannot_refill_interphase_budget(self):
        self.reject(lambda d: d['producer_comparisons'][0].update(comparison_inside_concurrent_service_interval=True))
    def test_scope_flags_cannot_promote_public_acceptance(self):
        self.reject(lambda d: d.update(public_network_ready=True))
    def test_duplicate_json_fields(self):
        with self.assertRaises(ValueError):
            unique([('value', 1), ('value', 2)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
