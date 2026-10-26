#!/usr/bin/env python3
"""Research-only economic feasibility screen for original V3 Hashcash bits.

Numbers are operator-supplied observations, not trusted hardware attestation.
The output is NEVER a recommended production security policy or a work proof.
"""
import argparse
from decimal import Decimal, InvalidOperation
import json
import math
from pathlib import Path

SCHEMA = 'trnm-v3-cost-feasibility-research-v1'


def positive(value, name):
    if not isinstance(value, str):
        raise ValueError(name + '_DECIMAL_STRING_REQUIRED')
    try:
        d = Decimal(value)
    except InvalidOperation as e:
        raise ValueError(name + '_DECIMAL_INVALID') from e
    if not d.is_finite() or d <= 0:
        raise ValueError(name + '_MUST_BE_FINITE_POSITIVE')
    return d


def evaluate(data):
    keys = {'schema', 'honest_hashes_per_second', 'honest_fixed_ms',
            'cookie_lifetime_ms', 'honest_p95_budget_ms',
            'false_w1_receiver_cost_usd', 'attacker_arms', 'cost_margin',
            'measurement_identity'}
    if not isinstance(data, dict) or set(data) != keys or data['schema'] != SCHEMA:
        raise ValueError('SCHEMA')
    hr = positive(data['honest_hashes_per_second'], 'HONEST_HASHRATE')
    hf = positive(data['honest_fixed_ms'], 'HONEST_FIXED')
    ttl = positive(data['cookie_lifetime_ms'], 'COOKIE_LIFETIME')
    honest_budget = positive(data['honest_p95_budget_ms'], 'HONEST_P95')
    receiver = positive(data['false_w1_receiver_cost_usd'], 'RECEIVER_COST')
    margin = positive(data['cost_margin'], 'COST_MARGIN')
    if ttl > 2000 or honest_budget > ttl:
        raise ValueError('LIFETIME_PROFILE')
    arms = data['attacker_arms']
    if not isinstance(arms, list) or not 1 <= len(arms) <= 12:
        raise ValueError('ATTACKER_ARMS')
    unique, costs = set(), []
    for row in arms:
        if not isinstance(row, dict) or set(row) != {'name', 'hashes_per_second', 'cost_usd_per_second', 'provenance_sha256', 'hardware'}:
            raise ValueError('ARM_FIELDS')
        name = row['name']
        if not isinstance(name, str) or not 1 <= len(name) <= 80 or name in unique:
            raise ValueError('ARM_NAME')
        unique.add(name)
        provenance = row['provenance_sha256']
        if not isinstance(provenance, str) or len(provenance) != 64 or any(c not in '0123456789abcdef' for c in provenance):
            raise ValueError('ARM_PROVENANCE')
        if row['hardware'] not in ('cpu', 'gpu', 'asic'):
            raise ValueError('ARM_HARDWARE')
        rate = positive(row['hashes_per_second'], 'ATTACKER_HASHRATE')
        cost = positive(row['cost_usd_per_second'], 'ATTACKER_COST')
        costs.append((cost / rate, name, row['hardware']))
    identity = data['measurement_identity']
    if not isinstance(identity, dict) or set(identity) != {'source_commit', 'measured_on_real_hardware', 'independent_operator'}:
        raise ValueError('MEASUREMENT_IDENTITY')
    commit = identity['source_commit']
    if not isinstance(commit, str) or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('COMMIT_IDENTITY')
    if type(identity['measured_on_real_hardware']) is not bool or type(identity['independent_operator']) is not bool:
        raise ValueError('MEASURED_BOOLEAN')
    cheapest = min(costs)
    rows = []
    for bits in range(8, 21):  # Original V3 policy, not a proposed protocol change.
        p = 2.0 ** -bits
        q95 = math.ceil(math.log1p(-0.95) / math.log1p(-p))
        honest_p95_ms = hf + Decimal(q95) * Decimal(1000) / hr
        attack_expected_usd = Decimal(1 << bits) * cheapest[0]
        ratio = receiver / attack_expected_usd
        honest_fits = honest_p95_ms <= honest_budget
        attacked_cost_pass = attack_expected_usd >= receiver * margin
        rows.append({'bits': bits, 'honest_p95_trials': q95,
                     'honest_p95_total_ms': str(honest_p95_ms),
                     'attacker_cheapest_hardware': cheapest[2],
                     'attacker_cheapest_arm': cheapest[1],
                     'attacker_expected_ticket_cost_usd': str(attack_expected_usd),
                     'receiver_over_attacker_expected_cost': str(ratio),
                     'honest_latency_feasible': honest_fits,
                     'attacker_cost_feasible': attacked_cost_pass,
                     'both_model_constraints_pass': honest_fits and attacked_cost_pass})
    both = [r['bits'] for r in rows if r['both_model_constraints_pass']]
    # Even if all labels say measured, a local JSON evaluator cannot attest a
    # device, rental bill, independent actor, energy or actual signed V3 traffic.
    return {'schema': SCHEMA, 'original_policy_only': True,
            'original_bits_min': 8, 'original_bits_max': 20,
            'price_model': 'expected geometric hash ticket; NOT minimum per ticket or proof of economics',
            'hardware_rates_observed_by_this_model': False,
            'source_identity_verified_by_this_model': False,
            'independent_security_accepted': False,
            'production_activation': False,
            'model_feasible_bits': both,
            'model_has_solution': bool(both),
            'evidence_labels_claim_real_measurement': identity['measured_on_real_hardware'],
            'evidence_labels_claim_independence': identity['independent_operator'],
            'rows': rows}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('input')
    p.add_argument('--out')
    args = p.parse_args()
    data = json.loads(Path(args.input).read_text(encoding='utf-8'))
    result = evaluate(data)
    raw = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.out:
        with open(args.out, 'x', encoding='utf-8') as output:
            output.write(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
