"""Deterministic multi-seed *mathematical* PoN network risk study.

This module deliberately preserves every incomplete or divergent trial in the
fixed denominator. It cannot produce cryptographic, WAN, or safety evidence.
"""
from __future__ import annotations

import json
import math
import statistics
from daa_lease_network_sim_v1 import Campaign, Participant, Profile


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float,float]:
    if type(successes) is not int or type(total) is not int or total <= 0 or not 0 <= successes <= total:
        raise ValueError('bounded numerator/denominator')
    n = total
    p = successes/n
    mid = (p + z*z/(2*n)) / (1 + z*z/n)
    half = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n))/(1+z*z/n)
    return max(0.,mid-half),min(1.,mid+half)


def quantile(values: list[int], q: float) -> float | None:
    """Nearest-rank descriptive quantile; never substitute missing observations."""
    if type(values) is not list or not 0 <= q <= 1 or any(type(x) is not int or x<0 for x in values):
        raise ValueError('noncanonical observations')
    if not values:
        return None
    data=sorted(values)
    return float(data[max(0, math.ceil(len(data)*q)-1)])


def cohort(algorithm: str, scenario: str, *, trials: int = 100, duration: int = 600,
           seed_first: int = 20261026) -> dict:
    if type(trials) is not int or not 1 <= trials <= 1000 or not 1 <= duration <= 20000:
        raise ValueError('unbounded cohort')
    if scenario not in ('steady','partition','lease_loss','specialized_miner','timestamp_endpoint','withholding'):
        raise ValueError('unknown research scenario')
    records=[]
    for trial in range(trials):
        actors=(Participant('normal',.55),Participant('candidate',.45,
            mode='leased_only' if scenario=='lease_loss' else 'maintenance',
            speed=1.7 if scenario=='specialized_miner' else 1,
            timestamp_style='endpoint' if scenario=='timestamp_endpoint' else 'honest',
            withhold_until_lead=2 if scenario=='withholding' else 0))
        options={}
        if scenario=='partition':
            options.update(partition_from=150,partition_until=350)
        if scenario=='lease_loss':
            options.update(external_lease_lost_at=250)
        profile=Profile(algorithm,seconds=duration,seed=seed_first+trial,**options)
        raw=Campaign(profile,actors).run()
        records.append({
            'seed': profile.seed, 'all_views_agree': raw['all_views_agree'],
            'headers': raw['created_headers'],
            'candidate_headers': raw['by_miner']['candidate'],
            'confirmed_min': min(raw['confirmed_abstract'].values()),
            'reorgs': sum(raw['reorgs'].values()),
            'missing_ancestor_fetches_idealized':sum(raw['missing_ancestor_fetches_idealized'].values()),
            'deferred_timestamps': raw['deferred_time_observations'],
        })
    success=sum(int(row['all_views_agree']) for row in records)
    bound=wilson(success,trials)
    return {
        'schema':'pon-daa-multi-seed-synthetic-cohort-v1',
        'production_qualified':False,'actual_w1_proofs':0,
        'independent_operator_evidence':False,
        'perfect_history_available':True,
        'algorithm':algorithm,'scenario':scenario,
        'fixed_trial_count':trials,'fixed_duration_seconds':duration,
        'first_seed':seed_first,'last_seed':seed_first+trials-1,
        'agreement':{'numerator':success,'denominator':trials,
                     'wilson_95_interval':[round(bound[0],6),round(bound[1],6)]},
        'headers':{'median':quantile([r['headers'] for r in records],.5),
                   'p95':quantile([r['headers'] for r in records],.95) if trials>=20 else None},
        'minimum_abstract_confirmed_median':quantile([r['confirmed_min'] for r in records],.5),
        'all_trials':records,
        'interpretation':'complete-denominator descriptive mathematical Monte Carlo only; no true W1, WAN, Sybil, storage or economic qualification'
    }


def full_campaign(trials: int = 100) -> dict:
    matrix=[]
    for alg in ('legacy','asert_raw','asert_mtp'):
        for scenario in ('steady','partition','lease_loss','specialized_miner',
                         'timestamp_endpoint','withholding'):
            matrix.append(cohort(alg,scenario,trials=trials))
    return {'schema':'pon-daa-multi-seed-synthetic-matrix-v1','cohorts':matrix,
            'scenarios':18,'trials_per_cohort':trials,'total_trials':18*trials,
            'production_qualified':False,'actual_w1_proofs':0}


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--trials',type=int,default=100)
    args=parser.parse_args()
    print(json.dumps(full_campaign(args.trials),sort_keys=True,separators=(',',':')))
