"""PoN confirmation-risk *research* under a frozen constant-rate work-share model.

Zero authentic W1 proofs, no signer, packet, network, or consensus authority. The
negative-binomial model assumes independently arriving, equally costly *valid*
work tickets at fixed honest/attacker rates. It is not a public-network loss bound
under timestamp attacks, difficulty drift, network delay, selective withholding,
changing task eligibility or adaptive work profiles. This module MUST NOT be
used to authorize a release or determine a consensus-valid transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import argparse
import hashlib
import json
import random
from pathlib import Path

UINT256 = 1 << 256
MAX_DEPTH = 128


def ratio(value: int | str | Fraction, label: str) -> Fraction:
    if type(value) is bool or type(value) is float:
        raise ValueError(label + '_NONCANONICAL')
    if type(value) not in (int, str, Fraction):
        raise ValueError(label + '_TYPE')
    try:
        frac = Fraction(value)
    except (ZeroDivisionError, ValueError) as e:
        raise ValueError(label + '_INVALID') from e
    return frac


def effective_share(nominal_attacker: int | str | Fraction,
                    faster_valid_producer: int | str | Fraction) -> Fraction:
    q = ratio(nominal_attacker, 'ATTACKER_SHARE')
    s = ratio(faster_valid_producer, 'VALID_SPEEDUP')
    if not Fraction(0) <= q <= Fraction(1) or not Fraction(1) <= s <= Fraction(64):
        raise ValueError('SHARE_OR_SPEEDUP_RANGE')
    return q * s / (1 - q + q * s)


def eventual_catchup_probability(attacker_effective_share: Fraction,
                                 honest_confirmations: int) -> Fraction:
    """Exact probability that a hidden fork can *ever* catch up to z honest blocks.

    Let K be attacker blocks obtained before the z-th honest block. Then
    P(K=k)=C(z+k-1,k) * p**z * q**k. Conditional on K<z, a
    biased infinite random walk catches up with probability (q/p)**(z-k).
    For K>=z it has already caught up. Delays/fees/model utility are ignored.
    """
    q = ratio(attacker_effective_share, 'EFFECTIVE_SHARE')
    if type(honest_confirmations) is not int or not 1 <= honest_confirmations <= MAX_DEPTH:
        raise ValueError('DEPTH_RANGE')
    if not 0 <= q <= 1:
        raise ValueError('EFFECTIVE_SHARE_RANGE')
    if q == 0:
        return Fraction(0)
    if 2 * q >= 1:
        return Fraction(1)
    p = 1 - q
    # Compute NB probability P(K=0), and iterate k=0..z-1. The remainder
    # is the exact tail. No Poisson truncation or floating approximation.
    probability = p ** honest_confirmations
    lower_mass = Fraction(0)
    catchup_from_lower = Fraction(0)
    odds = q / p
    for k in range(honest_confirmations):
        lower_mass += probability
        catchup_from_lower += probability * odds ** (honest_confirmations - k)
        # NB recurrence: P(K=k+1)/P(K=k)=(z+k)/(k+1) * q
        probability *= Fraction(honest_confirmations + k, k + 1) * q
    result = (1 - lower_mass) + catchup_from_lower
    assert 0 <= result <= 1
    return result


def required_work(target: int) -> int:
    if type(target) is not int or not 1 <= target < UINT256:
        raise ValueError('TARGET_RANGE')
    return UINT256 // (target + 1)


def confirmation_policy(targets: tuple[int, ...], *, minimum_depth: int,
                        work_multiplier: int, included_target: int) -> dict:
    """Standalone arithmetic reflecting Chain's depth+expected-work predicate.

    Targets represent ONLY blocks *after* the inclusion block on an already
    valid active branch. The existing full native client must prove inclusion,
    verify those headers and check active generation/reorg. This helper cannot.
    """
    if type(minimum_depth) is not int or not 1 <= minimum_depth <= MAX_DEPTH:
        raise ValueError('POLICY_DEPTH')
    if type(work_multiplier) is not int or not 1 <= work_multiplier <= 65535:
        raise ValueError('POLICY_MULTIPLIER')
    threshold = required_work(included_target) * work_multiplier
    sum_work = 0
    for target in targets:
        sum_work += required_work(target)
    return {'post_inclusion_depth': len(targets),
            'work_delta': str(sum_work), 'required_work_delta': str(threshold),
            'depth_condition': len(targets) >= minimum_depth,
            'work_condition': sum_work >= threshold,
            'research_policy_condition': len(targets) >= minimum_depth and sum_work >= threshold,
            'native_membership_checked': False, 'native_proofs_checked': False}


def sample_catchup(*, effective_q: Fraction, depth: int, seed: int,
                   trials: int, max_extra: int = 4096) -> dict:
    """Monte Carlo cross-check with censored unfinished races, NOT new authority.

    Each trial samples attacker work before z honest wins; if behind, a biased
    random walk runs until catchup or the original per-trial bound. Unfinished
    cases stay censored, not reclassified as safe failures.
    """
    if (type(trials) is not int or not 1 <= trials <= 10_000 or
            type(depth) is not int or not 1 <= depth <= MAX_DEPTH or
            type(seed) is not int or not 0 <= seed < 2**64 or
            type(max_extra) is not int or not 1 <= max_extra <= 4096 or
            trials * max_extra > 2_000_000):
        raise ValueError('CAMPAIGN_BUDGET')
    q = ratio(effective_q, 'EFFECTIVE_SHARE')
    if not 0 <= q < Fraction(1, 2) or q.denominator > 1_000_000:
        raise ValueError('SAMPLER_EFFECTIVE_SHARE_RANGE')
    rng = random.Random(seed)
    success = 0
    censored = 0
    model_residual = Fraction(0)
    odds = q / (1-q)
    for _ in range(trials):
        attacker, honest = 0, 0
        while honest < depth:
            if rng.random() < float(q):
                attacker += 1
            else:
                honest += 1
        gap = depth - attacker
        if gap <= 0:
            success += 1
            continue
        for _ in range(max_extra):
            gap += -1 if rng.random() < float(q) else 1
            if gap == 0:
                success += 1
                break
        else:
            censored += 1
            # Conditional eventual hit under the STATED biased random-walk
            # model; not an observed hit and not a public-security upper bound.
            model_residual += odds ** gap
    return {'trials': trials, 'observed_catchups': success,
            'unfinished_censored': censored,
            'lower_fraction': str(Fraction(success, trials)),
            'upper_fraction': str(Fraction(success + censored, trials)),
            'model_adjusted_estimate': str((Fraction(success) + model_residual) / trials),
            'model_conditional_unobserved_mass': str(model_residual / trials),
            'simulates_native_W1': False, 'simulates_network': False}


@dataclass(frozen=True)
class Scenario:
    name: str
    nominal_share: str
    speedup: str
    depth: int

    def row(self) -> dict:
        effective = effective_share(self.nominal_share, self.speedup)
        probability = eventual_catchup_probability(effective, self.depth)
        return {'name': self.name, 'assumed_nominal_share': self.nominal_share,
                'assumed_valid_proof_speedup': self.speedup,
                'conditional_effective_share': str(effective),
                'post_inclusion_honest_depth': self.depth,
                'exact_catchup_probability': str(probability),
                'comparison_float_only': round(float(probability), 12),
                'attacker_majority_under_assumptions': effective >= Fraction(1, 2)}


def campaign() -> dict:
    cases = [Scenario(f'q{q}-s{s}-z{z}', q, s, z)
             for q in ('1/10', '1/4', '3/10', '2/5')
             for s in ('1', '3/2', '3', '8')
             for z in (1, 3, 6, 12)]
    rows = [case.row() for case in cases]
    raw = json.dumps(rows, separators=(',', ':'), sort_keys=True).encode('ascii')
    return {'schema': 'trnm-pon-confirmation-risk-research-v1',
            'scope': 'constant-rate independent Poisson valid-work arrivals; no public safety guarantee',
            'cases': len(rows), 'rows_sha256': hashlib.sha256(raw).hexdigest(),
            'zero_native_proofs': True, 'zero_independent_operators': True,
            'cases_data': rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = campaign()
    with args.output.open('x', encoding='utf8') as fp:
        json.dump(result, fp, sort_keys=True, indent=2)
        fp.write('\n')
    print(json.dumps({k: result[k] for k in ('schema', 'cases', 'rows_sha256')}, sort_keys=True))


if __name__ == '__main__':
    main()
