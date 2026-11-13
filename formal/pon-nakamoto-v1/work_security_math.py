"""PoN effective-work / idealized reorg-risk arithmetic; research only.

No W1 verifier or miner, hashpower measurements, network attack, permissionless
admission qualification, consensus version, security certificate or live node.

The eventual catch-up calculation is exact for a stylized independent two-party
block race, fixed q, no propagation delay and no clock/task interference. It
conditions on z honest blocks having arrived while the adversary mines
privately, and then uses gambler's-ruin eventual catch-up probabilities.
"""
from __future__ import annotations

from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import islice
from typing import Iterable

MAX_DEPTH = 96
MAX_FRACTION_PART = 10_000_000
MAX_SPEEDUP = 64
MAX_PRESSURE = 100_000


class SecurityModelError(ValueError):
    """Refusal is a model/input error, never a consensus-invalid verdict."""


def _fraction(value: Fraction, name: str, *, maximum: Fraction) -> Fraction:
    if type(value) is not Fraction or value.numerator < 0 or value > maximum:
        raise SecurityModelError(name)
    if abs(value.numerator) > MAX_FRACTION_PART or value.denominator > MAX_FRACTION_PART:
        raise SecurityModelError(name + '_BOUNDED')
    return value


def _positive(value: Fraction, name: str, *, maximum: int = MAX_SPEEDUP) -> Fraction:
    value = _fraction(value, name, maximum=Fraction(maximum))
    if value <= 0:
        raise SecurityModelError(name)
    return value


def effective_work_fraction(nominal_fraction: Fraction, legal_speedup: Fraction) -> Fraction:
    """Idealized share after fastest LEGAL W1 implementation speed difference.

    A mathematically valid proof is still mandatory. This does not infer a
    speedup from hardware/attack evidence and excludes invalid forged tickets.
    """
    q = _fraction(nominal_fraction, 'NOMINAL_SHARE', maximum=Fraction(1))
    s = _positive(legal_speedup, 'LEGAL_SPEEDUP')
    denom = Fraction(1) - q + q * s
    return q * s / denom


def ideal_private_catchup_risk(effective_fraction: Fraction, honest_confirmations: int) -> Fraction:
    """Exact eventual catch-up probability in one constant-rate model.

    For K adversarial blocks found before honest miners add z blocks,
    P(K=k) = binom(z+k-1,k) * p**z * q**k. For k<z,
    catchup probability is (q/p)**(z-k). For K>=z catchup has
    already happened. This is *not* an upper bound for real PoN.
    """
    q = _fraction(effective_fraction, 'EFFECTIVE_SHARE', maximum=Fraction(1))
    if type(honest_confirmations) is not int or not 1 <= honest_confirmations <= MAX_DEPTH:
        raise SecurityModelError('CONFIRMATION_DEPTH')
    if q == 0:
        return Fraction(0)
    if q >= Fraction(1, 2):
        return Fraction(1)
    p = 1 - q
    z = honest_confirmations
    probability_k = p ** z  # k=0, exact negative-binomial mass
    probability_less_than_z = Fraction(0)
    catches_after_z = Fraction(0)
    for k in range(z):
        probability_less_than_z += probability_k
        catches_after_z += probability_k * (q / p) ** (z - k)
        # NB(z,k+1) = NB(z,k)*(z+k)/(k+1)*q
        probability_k *= Fraction(z + k, k + 1) * q
    tail_already_caught = 1 - probability_less_than_z
    result = tail_already_caught + catches_after_z
    if not 0 <= result <= 1:
        raise AssertionError('MODEL_ARITHMETIC')
    return result


def verifier_pressure(attacker_cpu_fraction: Fraction,
                      false_proof_rejection_ratio: Fraction,
                      reserved_honest_cpu_fraction: Fraction) -> dict:
    """One-core necessary-capacity screen for FIXED matched-hardware budgets.

    Ratio is the observed victim CPU cost divided by attacker complete CPU
    cost per false candidate. There is no token/HW/economics qualification.
    Cancellation and queues can cap damage but do not produce work-hardness.
    """
    a = _fraction(attacker_cpu_fraction, 'ATTACKER_CPU_FRACTION', maximum=Fraction(1))
    r = _positive(false_proof_rejection_ratio, 'FALSE_PROOF_REJECTION_RATIO',
                  maximum=MAX_PRESSURE)
    h = _fraction(reserved_honest_cpu_fraction, 'HONEST_CPU_FRACTION', maximum=Fraction(1))
    total = h + a * r
    return {
        'projection': f'{total.numerator}/{total.denominator}',
        'over_one_receiver_cpu': total > 1,
        'public_network_safe': False,
        'scope': 'single-equal-hardware-cpu-arithmetic-only',
    }


def _decimal_string(value: Fraction) -> str:
    with localcontext() as ctx:
        ctx.prec = 75
        out = Decimal(value.numerator) / Decimal(value.denominator)
        return format(out, '.16f')


def risk_matrix(*, nominal_shares: Iterable[Fraction],
                legal_speedups: Iterable[Fraction],
                confirmation_depths: Iterable[int],
                max_idealized_risk: Fraction = Fraction(1, 1_000_000)) -> dict:
    """Freeze exact caller-provided scenario order. No risk=PASS promotion."""
    # Consume no more than one item beyond the bound, even for a generator.
    shares = tuple(islice(nominal_shares, 17))
    speeds = tuple(islice(legal_speedups, 17))
    depths = tuple(islice(confirmation_depths, 17))
    if not (1 <= len(shares) <= 16 and 1 <= len(speeds) <= 16
            and 1 <= len(depths) <= 16):
        raise SecurityModelError('SCENARIO_BUDGET')
    for q in shares:
        _fraction(q, 'NOMINAL_SHARE', maximum=Fraction(1))
    for s in speeds:
        _positive(s, 'LEGAL_SPEEDUP')
    for z in depths:
        if type(z) is not int or not 1 <= z <= MAX_DEPTH:
            raise SecurityModelError('CONFIRMATION_DEPTH')
    if len(set(shares)) != len(shares) or len(set(speeds)) != len(speeds) \
            or len(set(depths)) != len(depths):
        raise SecurityModelError('DUPLICATE_SCENARIO')
    maximum = _positive(max_idealized_risk, 'IDEAL_RISK_LIMIT', maximum=1)
    scenarios = []
    for nominal in shares:
        for speedup in speeds:
            q = effective_work_fraction(nominal, speedup)
            for depth in depths:
                risk = ideal_private_catchup_risk(q, depth)
                scenarios.append({
                    'nominal_share': str(nominal),
                    'legal_speedup': str(speedup),
                    'effective_share': str(q),
                    'depth': depth,
                    'catchup_risk_fraction': str(risk),
                    'catchup_risk_decimal': _decimal_string(risk),
                    'ideal_model_below_proposed_limit': risk <= maximum,
                    'no_finite_confirmation_guarantee': q >= Fraction(1, 2),
                    'production_security_qualified': False,
                })
    return {
        'schema': 'trnm-pon-ideal-work-security-screen-v1',
        'max_idealized_risk': str(maximum),
        'actual_w1_proofs': 0,
        'measured_hardware': False,
        'hostile_wan_tested': False,
        'actual_operator_independence': False,
        'consensus_activated': False,
        'accepted_security_gate': False,
        'assumptions': [
            'independent two-party Poisson/Bernoulli block race',
            'fixed q and equal chance of a valid lottery per unit effective work',
            'instant propagation; no selfish-mining strategy advantage',
            'zero timewarp, no DAA response and no source outage feedback',
            'all valid PoN proofs have the stated relative marginal cost',
        ],
        'scenarios': scenarios,
    }


def frozen_campaign() -> dict:
    return risk_matrix(
        nominal_shares=(Fraction(1, 10), Fraction(1, 4), Fraction(3, 10)),
        legal_speedups=(Fraction(1), Fraction(3, 2), Fraction(3), Fraction(8)),
        confirmation_depths=(6, 12, 24, 48),
    )
