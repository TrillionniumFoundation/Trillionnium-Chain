#!/usr/bin/env python3
"""Check complete finite service denominators; not a W1 or state oracle."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

NAMES = {
    'prepared-generic', 'tiled-classical', 'tiled-strassen-one-level',
    'paired-product', 'maintenance-periodic-setup', 'maintenance-integer-paired',
    'maintenance-periodic-prefix', 'maintenance-split-limb',
}
FALSE_FLAGS = ('public_network_ready', 'independent_accepted', 'work_profile_qualified',
               'resource_fairness_qualified', 'physical_power_loss', 'production_activation')


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def integer(value, code: str) -> int:
    require(type(value) is int and 0 <= value <= (1 << 64) - 1, code)
    return value


def timely(call: dict) -> bool:
    return (type(call) is dict and call.get('status') == 'ok'
            and call.get('returned_after_deadline') is False
            and type(call.get('elapsed_wall_ns')) is int
            and type(call.get('deadline_ms')) is int
            and 0 <= call['elapsed_wall_ns'] <= call['deadline_ms'] * 1_000_000)


def audit(data: dict) -> dict:
    require(data.get('schema') == 'public-v3-local-from-zero-service-v2', 'SCHEMA')
    require(all(data.get(k) is False for k in FALSE_FLAGS), 'SCOPE')
    require(all(data.get(k) is True for k in (
        'finite_target_met', 'reopen_state_equal', 'cpu_domain_retained_across_owner_reopen')), 'REOPEN')
    phases = data['phases']
    comparisons = data['producer_comparisons']
    require(len(phases) == len(comparisons) == 2, 'PHASES')
    summaries = []
    for index, phase in enumerate(phases):
        require(type(phase['phase']) is int and phase['phase'] == index, 'PHASE_ID')
        require(phase['construction_count'] == 8, 'CONSTRUCTION_COUNT')
        attacks, reads = phase['from_zero'], phase['honest_reads']
        require(len(attacks) == len(reads) == 8, 'DENOMINATOR')
        require(all(timely(row) for row in reads) and timely(phase['honest_submit']), 'HONEST_DEADLINE')
        require(phase['honest_read_successes'] == 8, 'READ_COUNT')
        require(all(phase.get(k) is True for k in (
            'finite_target_met', 'full_native_state_equal', 'no_attack_accepted',
            'cpu_measurements_known', 'all_started_work_finished', 'request_observations_complete')), 'NATIVE_RESULT')
        preparation = integer(phase['all_preparation_resources']['thread_cpu_ns'], 'PREPARATION_CPU')
        worker = integer(phase['attack_actor_resources']['thread_cpu_ns'], 'WORKER_CPU')
        require(integer(phase['attacker_cpu_ns'], 'ATTACK_CPU') == preparation + worker, 'CPU_DOUBLE_COUNT')
        hits = exhausted = refused = attempts = 0
        for row in attacks:
            construction, call = row['construction'], row['call']
            trials = construction['attempts']
            budget = integer(construction['attempt_budget'], 'BUDGET')
            require(budget <= 4096 and len(trials) <= budget, 'BUDGET')
            require(construction['setup_calls'] == 1, 'SETUP')
            integer(construction['attacker_cpu_ns'], 'CONSTRUCTION_CPU')
            require(all(type(t['nonce']) is int and t['nonce'] == i
                        and type(t['target_hit']) is bool for i, t in enumerate(trials)), 'TRIAL_PREFIX')
            attempts += len(trials)
            if construction['status'] == 'exhausted':
                exhausted += 1
                require(len(trials) == budget and not any(t['target_hit'] for t in trials)
                        and construction['winner_nonce'] is None and construction['packet'] is None
                        and call is None, 'EXHAUSTION')
            else:
                hits += 1
                require(construction['status'] == 'target_hit_unverified' and len(trials) > 0, 'HIT')
                require(not any(t['target_hit'] for t in trials[:-1]) and trials[-1]['target_hit']
                        and type(construction['winner_nonce']) is int
                        and construction['winner_nonce'] == len(trials) - 1, 'FIRST_HIT')
                require(type(call) is dict and call['status'] in ('refused', 'error')
                        and call['request']['packet'] == construction['packet'], 'SUBMISSION')
                integer(call['call_resources']['thread_cpu_ns'], 'CLIENT_CPU')
                if call['status'] == 'refused' and call['response']['value']['error'] == 'WORK:Transcript':
                    refused += 1
        require(refused > 0 and phase['late_transcript_rejections'] == refused, 'LATE_REFUSAL')
        observations = phase['request_observations']
        require(observations['records_not_retained'] == 0
                and observations['measurement_failures'] == 0
                and observations['counter_overflow'] is False, 'OBSERVATION_LOSS')
        records = observations['records']
        require(len(records) == hits + len(reads) + 1
                and observations['accepted_connections_seen'] == len(records)
                and all(r['complete'] is True for r in records), 'REQUEST_DENOMINATOR')
        metrics = phase['service']['metrics']
        require(phase['service']['error'] is None and metrics['mutation_cpu_clock_failures'] == 0, 'SERVICE')
        started = integer(metrics['work_started'], 'WORK_STARTED')
        require(started == metrics['work_finished'] and started > refused
                and metrics['work_failed'] >= refused, 'WORK_COMPLETION')
        require(integer(metrics['mutation_cpu_charged_ns'], 'CHARGED_CPU')
                >= integer(metrics['mutation_full_work_cpu_ns'], 'FULL_WORK_CPU') > 0, 'RECEIVER_CPU')
        comparison = comparisons[index]
        require(comparison['phase'] == index and comparison['all_equal'] is True
                and comparison['comparison_inside_concurrent_service_interval'] is False
                and comparison['universal_cheapest_producer_claim'] is False, 'COMPARISON_SCOPE')
        arms = comparison['rows']
        require(len(arms) == 16 and all(type(r['reused']) is bool for r in arms), 'ARMS')
        require({(r['producer'], r['reused']) for r in arms}
                == {(n, reuse) for n in NAMES for reuse in (False, True)}, 'ROSTER')
        expected_packet = phase['honest_submit']['request']['packet']
        for arm in arms:
            require(arm['equal_native_packet'] is True and arm['error'] is None
                    and arm['winner_packet'] == expected_packet, 'PACKET_PARITY')
            require(arm['setup_calls'] == (0 if index == 1 and arm['reused'] else 1), 'SETUP_REUSE')
            integer(arm['resources']['thread_cpu_ns'], 'PRODUCER_CPU')
            trials = arm['trials']
            require(0 < len(trials) == arm['search_budget'] <= 4096
                    and all(type(t['nonce']) is int and t['nonce'] == i
                            and type(t['target_hit']) is bool
                            and t['target_hit'] == (i == len(trials) - 1)
                            for i, t in enumerate(trials)), 'PRODUCER_PREFIX')
        summaries.append({'phase': index, 'from_zero_hits': hits, 'exhausted': exhausted,
                          'trace_trials': attempts, 'transcript_refusals': refused,
                          'timely_reads': len(reads), 'producer_arms': len(arms),
                          'attacker_outer_cpu_ns': preparation + worker})
    return {'result': 'PASS', 'phases': summaries,
            'scope': 'finite retained accounting; not independent W1/state replay or saturation fairness'}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_FIELD')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    require(len(raw) <= 32 * 1024 * 1024, 'REPORT_SIZE')
    data = json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE')))
    result = audit(data)
    result['report_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
