#!/usr/bin/env python3
"""Fixed comparisons for the preregistered native late-assembly campaign.

Observed ratios are local algorithm/device observations, not production kappa.
The output retains regressions and refuses unmatched setup or challenge streams.
"""
from __future__ import annotations
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from read_w1_cost_research import require

def ratio(a, b):
    if b == 0:
        return None
    f = Fraction(a, b)
    return dict(numerator=f.numerator, denominator=f.denominator, decimal=float(f))

def analyze(value):
    require(value['schema'] == 'pon-w1-late-assembly-research-derived-v1' and
            value['external_identity_pins_checked'] is True and
            value['all_retained_full_proof_records_independently_replayed'] is True,
            'PINNED_REPLAY_REQUIRED')
    jobs = value['jobs']
    require(len(jobs) == 14 and len({j['job'] for j in jobs}) == 14, 'EXACT_PLAN_JOB_COUNT')
    main = [j for j in jobs if j['job'].startswith('main-')]
    controls = [j for j in jobs if j['job'].startswith('control-')]
    require(len(main) == 8 and len(controls) == 6, 'EXACT_MAIN_CONTROL_COUNTS')
    comparisons = []
    for seed in (4101, 4102):
        for budget in (128_000_000, 512_000_000):
            selected = [j for j in main if j['options']['seed'] == seed and j['options']['miner_budget_ns'] == budget]
            require(len(selected) == 2 and {j['options']['mode'] for j in selected} == {'eager', 'deferred'}, 'MATCHED_MODES')
            modes = {j['options']['mode']: j for j in selected}
            eager, deferred = modes['eager'], modes['deferred']
            require({k: v for k, v in eager['options'].items() if k != 'mode'} ==
                    {k: v for k, v in deferred['options'].items() if k != 'mode'}, 'SAME_RESOURCE_ENVELOPE')
            require(eager['setup_statement'] is not None and eager['setup_statement'] == deferred['setup_statement'], 'IDENTICAL_PAID_SETUP')
            overlap = min(eager['attempts'], deferred['attempts'])
            require(eager['opportunity_identities'][:overlap] == deferred['opportunity_identities'][:overlap] and
                    eager['hit_sequence'][:overlap] == deferred['hit_sequence'][:overlap], 'IDENTICAL_SHARED_OPPORTUNITIES')
            qualified = all(j['setup_complete'] and not j['censored_by_attempt_cap'] for j in selected)
            comparisons.append(dict(seed=seed, miner_budget_ns=budget, eager=eager['job'], deferred=deferred['job'],
                shared_original_opportunities=overlap, exact_setup_and_prefix_identity=True,
                uncensored_complete_setup=qualified,
                traces_by_B=dict(eager=eager['traces_available_by_B'], deferred=deferred['traces_available_by_B']),
                winners_by_B=dict(eager=eager['full_winners_available_by_B'], deferred=deferred['full_winners_available_by_B']),
                trace_ratio=ratio(deferred['traces_available_by_B'], eager['traces_available_by_B']) if qualified else None,
                winning_ticket_ratio=ratio(deferred['full_winners_available_by_B'], eager['full_winners_available_by_B']) if qualified else None,
                scope='single local observed run per frozen seed/envelope/mode; no universal or statistical advantage ceiling'))
    keys = ('attempts', 'traces_available_by_B', 'full_proofs_available_by_B', 'full_winners_available_by_B',
            'native_accepted', 'native_accepted_from_B', 'original_miner_full_proofs', 'posthoc_miss_proofs',
            'late_attempts', 'late_winners', 'full_proof_records_replayed')
    totals = {key: sum(j[key] for j in jobs) for key in keys}
    return dict(schema='pon-w1-late-assembly-analysis-v1', source=value['source'],
        raw_manifest_sha256=value['raw_manifest_sha256'], plan_sha256=value['plan_sha256'],
        jobs=len(jobs), main_jobs=len(main), controls=len(controls), totals=totals,
        phase_cpu_ns={key: sum(j['phase_cpu_ns'][key] for j in jobs) for key in ('setup', 'miner', 'receiver', 'audit')},
        comparisons=comparisons,
        control_results=[{k: j[k] for k in ('job', 'options', 'setup_complete', 'attempts', 'late_attempts', 'late_winners', 'censored_by_attempt_cap')} for j in controls],
        canonical_research_chain_growth=0, pure_matrix_relation_changed=False,
        posthoc_credit=0, original_miss_trace_retention=True,
        independent_hardware_evidence=False, network_bandwidth_measured=False, energy_measured=False,
        lower_bound_proved=False, production_kappa_established=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readback', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw = args.readback.read_bytes()
    result = analyze(json.loads(raw))
    result['readback_sha256'] = hashlib.sha256(raw).hexdigest()
    result['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.out.open('x') as out:
        json.dump(result, out, indent=2, sort_keys=True); out.write('\n')
    print(json.dumps({'jobs': result['jobs'], 'comparisons': len(result['comparisons']), 'totals': result['totals']}))

if __name__ == '__main__':
    main()
