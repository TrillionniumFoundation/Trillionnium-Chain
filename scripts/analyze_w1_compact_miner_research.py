#!/usr/bin/env python3
"""Registered compact/deferred comparisons; unmatched observations remain null."""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from read_w1_cost_research import hx, require
from read_w1_compact_miner_research import same_json
from run_w1_compact_miner_research import decode, registered_jobs


def ratio(numerator, denominator):
    if denominator == 0:
        return None
    value = Fraction(numerator, denominator)
    return dict(numerator=value.numerator, denominator=value.denominator, decimal=float(value))


def metrics(job):
    wins = job['full_winners_available_by_B']
    phases = job['phase_cpu_ns']
    waited = job['whole_waited_child_resources']
    whole = waited['user_cpu_ns'] + waited['system_cpu_ns']
    result = {key: job[key] for key in (
        'job', 'options', 'setup_complete', 'attempts', 'full_winners_available_by_B',
        'native_accepted_from_B', 'late_attempts', 'late_winners', 'censored_by_attempt_cap',
        'full_proof_records_replayed', 'raw_bytes', 'phase_cpu_ns', 'total_process_cpu_ns')}
    result.update(whole_waited_cpu_ns=whole,
        within_B_winners_per_allocated_miner_second=ratio(wins * 1_000_000_000, job['options']['miner_budget_ns']),
        within_B_winners_per_observed_miner_second=ratio(wins * 1_000_000_000, phases['miner']),
        within_B_winners_per_observed_setup_plus_miner_second=ratio(wins * 1_000_000_000, phases['setup'] + phases['miner']),
        whole_command_scope='includes receiver, posthoc audit and output; not online mining or network delivery',
        actual_network_bytes=None, energy_joules=None)
    if job['binary'] == 'pon_w1_compact_miner_research':
        result.update(original_miss_records=job['original_miss_records'],
            original_research_packet_count=job['original_research_packet_count'],
            deterministic_attempts_recomputed=job['deterministic_attempts_recomputed'],
            attempts_available_by_B=job['attempts_available_by_B'],
            post_stop_seal_cpu_ns=job['post_stop_seal_cpu_ns'],
            availability_to_accounting_observation_cpu_ns=job['miner_seal']['availability_to_accounting_observation_cpu_ns'])
    else:
        result.update(original_research_trace_count=job['attempts'],
            original_miner_full_proofs=job['original_miner_full_proofs'],
            posthoc_miss_proofs=job['posthoc_miss_proofs'],
            traces_available_by_B=job['traces_available_by_B'])
    return result


def compare(compact, late):
    overlap = min(compact['attempts'], late['attempts'])
    same_options = (late['options'].get('mode') == 'deferred' and
        same_json(compact['options'], {k: v for k, v in late['options'].items() if k != 'mode'}))
    same_setup = compact['setup_statement'] is not None and compact['setup_statement'] == late['setup_statement']
    same_prefix = (compact['opportunity_identities'][:overlap] == late['opportunity_identities'][:overlap]
                   and compact['hit_sequence'][:overlap] == late['hit_sequence'][:overlap])
    uncensored = all(j['setup_complete'] and not j['censored_by_attempt_cap'] for j in (compact, late))
    qualified = same_options and same_setup and same_prefix and uncensored and overlap > 0
    reasons = [reason for ok, reason in ((same_options, 'different-resource-envelope'),
        (same_setup, 'different-or-missing-paid-setup'), (same_prefix, 'different-opportunity-prefix'),
        (uncensored, 'incomplete-setup-or-cap-censoring'), (overlap > 0, 'no-shared-attempt')) if not ok]
    cw, lw = compact['full_winners_available_by_B'], late['full_winners_available_by_B']
    cp, lp = compact['phase_cpu_ns'], late['phase_cpu_ns']
    return dict(seed=compact['options']['seed'], miner_budget_ns=compact['options']['miner_budget_ns'],
        compact=compact['job'], late=late['job'], matched=qualified, null_reasons=reasons,
        same_resource_envelope=same_options, identical_paid_setup=same_setup,
        identical_shared_opportunity_prefix=same_prefix, shared_attempts=overlap,
        uncensored_complete_setup=uncensored,
        winners_by_B=dict(compact=cw, late=lw),
        winning_ticket_ratio=ratio(cw, lw) if qualified else None,
        setup_plus_miner_observed_win_rate_ratio=ratio(cw * (lp['setup'] + lp['miner']),
            lw * (cp['setup'] + cp['miner'])) if qualified else None,
        miner_observed_win_rate_ratio=ratio(cw * lp['miner'], lw * cp['miner']) if qualified else None,
        all_collected_raw_byte_ratio=ratio(compact['raw_bytes'], late['raw_bytes']) if qualified else None,
        byte_ratio_scope='all local research output, including posthoc audit; not measured network bandwidth',
        scope='one frozen local observation per arm; no statistical or universal advantage ceiling')


def analyze(value):
    require(value['schema'] == 'pon-w1-compact-miner-research-derived-v1' and
            value['external_identity_pins_checked'] is True and
            value['all_retained_full_proof_records_independently_replayed'] is True and
            value['compact_all_deterministic_attempts_independently_recomputed'] is True,
            'PINNED_COMPLETE_REPLAY_REQUIRED')
    jobs = value['jobs']
    registration = registered_jobs()
    require([j['job'] for j in jobs] == [j['name'] for j in registration], 'EXACT_REGISTERED_JOB_ORDER')
    require(all(j['binary'] == r['binary'] for j, r in zip(jobs, registration)), 'REGISTERED_BINARY_BINDING')
    for job, registered in zip(jobs, registration):
        if job['binary'] == 'pon_w1_compact_miner_research':
            from w1_compact_miner_reader import options_from_args
        else:
            from w1_late_assembly_reader import options_from_args
        require(same_json(job['options'], options_from_args(registered['args'])),
                'REGISTERED_OPTIONS_BINDING')
    by_name = {j['job']: j for j in jobs}
    comparisons = []
    for seed in (7101, 7102):
        for budget in (128000000, 512000000):
            prefix = f'main-s{seed}-b{budget}-'
            comparisons.append(compare(by_name[prefix + 'compact'], by_name[prefix + 'late']))
    totals = {key: sum(j[key] for j in jobs) for key in (
        'attempts', 'full_winners_available_by_B', 'native_accepted_from_B',
        'late_attempts', 'late_winners', 'full_proof_records_replayed', 'raw_bytes')}
    compact_jobs = [j for j in jobs if j['binary'] == 'pon_w1_compact_miner_research']
    late_jobs = [j for j in jobs if j['binary'] == 'pon_w1_late_assembly_research']
    record_classes = dict(
        compact_original_setup_packets=sum(j['original_setup_packet_count'] for j in compact_jobs),
        compact_original_research_packets=sum(j['original_research_packet_count'] for j in compact_jobs),
        compact_original_miss_records=sum(j['original_miss_records'] for j in compact_jobs),
        compact_all_deterministic_nonce_recomputations=sum(j['deterministic_attempts_recomputed'] for j in compact_jobs),
        compact_posthoc_miss_recomputations=sum(j['posthoc_miss_proofs_recomputed'] for j in compact_jobs),
        late_original_setup_proofs=sum(j['setup_statement'] is not None for j in late_jobs),
        late_original_research_proofs=sum(j['original_miner_full_proofs'] for j in late_jobs),
        late_posthoc_research_proof_records=sum(j['posthoc_miss_proofs'] for j in late_jobs),
        late_posthoc_setup_proof_records=sum(j['full_proof_records_replayed'] - int(j['setup_statement'] is not None)
            - j['original_miner_full_proofs'] - j['posthoc_miss_proofs'] for j in late_jobs))
    require(all(v >= 0 for v in record_classes.values()), 'PROOF_RECORD_CLASSIFICATION')
    return dict(schema='pon-w1-compact-miner-analysis-v1', source=value['source'],
        raw_manifest_sha256=value['raw_manifest_sha256'], plan_sha256=value['plan_sha256'],
        jobs=len(jobs), main_jobs=8, controls=5, totals=totals, proof_record_classes=record_classes,
        comparisons=comparisons,
        job_metrics=[metrics(j) for j in jobs],
        phase_cpu_ns={phase: sum(j['phase_cpu_ns'][phase] for j in jobs)
                      for phase in ('setup', 'miner', 'receiver', 'audit')},
        all_attempts_reconstructed_after_seal=True, compact_original_miss_records_retained=False,
        trace_commitment_is_removable_diagnostic_cost=True,
        ratio_to_older_source_campaign_permitted=False,
        canonical_research_chain_growth=0, mature_reward_claim=False, posthoc_credit=0,
        record_totals_are_not_unique_reward_identities=True,
        energy_joules=None, network_bandwidth_measured=False,
        independent_hardware_evidence=False, physical_minimum_cost_proved=False,
        universal_kappa_established=False, production_activation=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readback', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expected-readback-sha256', required=True,
                        help='External trusted-owner pin, never inferred from an untrusted input file')
    args = parser.parse_args()
    hx(args.expected_readback_sha256, 32, 'EXTERNAL_READBACK_PIN')
    raw = args.readback.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.expected_readback_sha256, 'READBACK_EXTERNAL_PIN_MISMATCH')
    result = analyze(decode(raw))
    result['readback_sha256'] = args.expected_readback_sha256
    result['external_readback_pin_checked'] = True
    result['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'jobs': result['jobs'], 'comparisons': len(result['comparisons']), 'totals': result['totals']}))


if __name__ == '__main__':
    main()
