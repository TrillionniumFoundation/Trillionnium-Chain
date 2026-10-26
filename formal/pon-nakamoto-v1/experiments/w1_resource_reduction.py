"""Conditional W1 resource reductions and exact finite countermodels.

These are resource-accounting implications, not established SHA-256 extraction,
W1 prefix hardness, a physical cost floor, native benchmarks or a new protocol.
All costs in the finite schedules are explicitly declared abstract integer units.
The actual-header helper computes identities only; it does not verify work,
parent eligibility, admission, rewards or chain security.
"""

from __future__ import annotations

from fractions import Fraction
from functools import lru_cache
from math import comb
import hashlib
import json
import struct
from typing import Iterable

from w1_adaptive_cost_models import binomial_pmf, mean, tail

MAX_EXACT_UNITS = 128
HEADER_BYTES = 318


def _nat(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(f"{name} must be a {'positive' if positive else 'nonnegative'} integer")
    return value


def _small(value: int, name: str, *, positive: bool = False) -> int:
    _nat(value, name, positive=positive)
    if value > MAX_EXACT_UNITS:
        raise ValueError(f"{name} exceeds the finite exact-model cap")
    return value


def _exact(value: int | Fraction, name: str, *, positive: bool = False) -> Fraction:
    if type(value) not in (int, Fraction):
        raise ValueError(f"{name} must be an exact int or Fraction")
    value = Fraction(value)
    if value < 0 or (positive and value == 0):
        raise ValueError(f"{name} must be {'positive' if positive else 'nonnegative'}")
    return value


def _probability(value: int | Fraction, name: str = 'probability') -> Fraction:
    value = _exact(value, name)
    if value > 1:
        raise ValueError(f"{name} must lie in [0, 1]")
    return value


def _hash32(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return value


def pon_hash(tag: bytes, *parts: bytes) -> bytes:
    """Existing public PON1 framing; no new protocol domain is installed."""
    if not isinstance(tag, bytes) or len(tag) > 65535:
        raise ValueError('tag must be bytes of at most 65535 bytes')
    h = hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag)
    for part in parts:
        if not isinstance(part, bytes) or len(part) >= 1 << 32:
            raise ValueError('part must be bytes with a u32 length')
        h.update(struct.pack('<I', len(part)))
        h.update(part)
    return h.digest()


def actual_w1_identities(header: bytes, trace: bytes) -> dict[str, bytes]:
    """Literal existing Header.challenge/block_id/ticket/research identity.

    This verifies only the fixed header envelope. A fabricated trace also has
    these identities, so calling this function never establishes valid work.
    """
    if not isinstance(header, bytes) or len(header) != HEADER_BYTES:
        raise ValueError('header must have the native 318-byte length')
    if header[:6] != b'PNH1\x01\x00':
        raise ValueError('header version must be PNH1 version 1')
    _hash32(trace, 'trace')
    challenge = pon_hash(b'challenge', header)
    ticket = pon_hash(b'ticket', challenge, trace)
    task = header[278:310]
    return {
        'challenge': challenge,
        'ticket': ticket,
        'block_id': pon_hash(b'block', header, trace),
        'research_semantic_id': pon_hash(b'w1-cost-game-semantic-ticket-v1', task, challenge, ticket),
    }


def target_probability(target: bytes) -> Fraction:
    """Ideal uniform 256-bit ticket only. Native target zero is invalid."""
    _hash32(target, 'target')
    threshold = int.from_bytes(target, 'big')
    return Fraction(threshold + 1, 1 << 256) if threshold else Fraction()


def temporal_oracle_failure_bound(*, preprocessing_trace_queries: int,
                                  online_trace_queries: int,
                                  preprocessing_lottery_queries: int,
                                  online_lottery_queries: int,
                                  header_queries: int, task_queries: int,
                                  submissions: int,
                                  digest_bits: int = 256) -> dict[str, int | Fraction | str]:
    """Conservative ideal-domain bound from BEFORE captured preprocessing.

    Requires the temporal/binding model of W1_RESOURCE_REDUCTION_V1.md section 3.
    Header/task caps include public setup, helpers and terminal verification.
    Submissions include ALL complete candidates, not only retained winners.
    Trace verification queries are bounded by submissions; their work is not
    producer work. All oracle-dependent advice must have captured origins.
    This is NOT a bound conditioned on an arbitrary favorable initial table.
    """
    counts = (preprocessing_trace_queries, online_trace_queries,
              preprocessing_lottery_queries, online_lottery_queries,
              header_queries, task_queries, submissions)
    for value in counts:
        _nat(value, 'query/submission cap')
    _nat(digest_bits, 'digest_bits', positive=True)
    if digest_bits > 4096:
        raise ValueError('digest_bits exceeds the arithmetic model cap')
    space = 1 << digest_bits
    traces = preprocessing_trace_queries + online_trace_queries + submissions
    references = preprocessing_lottery_queries + online_lottery_queries + submissions
    terms = {
        'trace_response_collision': Fraction(comb(traces, 2), space),
        'header_response_collision': Fraction(comb(header_queries, 2), space),
        'task_response_collision': Fraction(comb(task_queries, 2), space),
        'late_header_opening': Fraction(header_queries * references, space),
        'late_task_opening': Fraction(task_queries * header_queries, space),
        'early_trace_guess': Fraction(references, space),
    }
    return {'model': 'independent-ideal-whole-message-domains-before-preprocessing',
            'trace_query_cap_including_terminal_audit': traces,
            'lottery_reference_cap_including_submissions': references,
            **terms, 'union_bound': min(Fraction(1), sum(terms.values(), Fraction()))}


def extraction_resource_cap(*, budget: int | Fraction,
                            prefix_cost: int | Fraction,
                            simulation_scale: int | Fraction = 1,
                            fixed_overhead: int | Fraction = 0,
                            preprocessing_credit: int | Fraction = 0,
                            per_correct_overhead: int | Fraction = 0,
                            per_candidate_overhead: int | Fraction = 0,
                            candidate_cap: int = 0) -> int | None:
    """Solve ell*m-d <= a*B+b+h_correct*m+h_candidate*E, with E<=candidate_cap.

    A finite result is CONDITIONAL on both inequalities, in the same declared
    resource units and adversary class. No primitive lower bound is supplied by
    this function. None means the extraction inequality gives no finite cap;
    it never silently replaces a zero/nonpositive denominator with unit work.
    Invalid candidates may incur extraction overhead even without a valid ticket.
    """
    budget = _exact(budget, 'budget')
    ell = _exact(prefix_cost, 'prefix_cost', positive=True)
    scale = _exact(simulation_scale, 'simulation_scale')
    fixed = _exact(fixed_overhead, 'fixed_overhead')
    credit = _exact(preprocessing_credit, 'preprocessing_credit')
    correct = _exact(per_correct_overhead, 'per_correct_overhead')
    candidate = _exact(per_candidate_overhead, 'per_candidate_overhead')
    _nat(candidate_cap, 'candidate_cap')
    gap = ell - correct
    if gap <= 0:
        return None
    return (scale * budget + fixed + credit + candidate * candidate_cap) // gap


def fresh_opportunity_cap(*, new_prefix_cap: int | None, prepared_unqueried_cap: int,
                          online_lottery_queries: int, submissions: int) -> int | None:
    """New valid opportunities, NOT all raw (possibly fabricated) ticket queries.

    None propagates an unavailable computation cap, even though a separately
    declared raw-query cap may still provide an oracle-only counting bound.
    """
    for value in (prepared_unqueried_cap, online_lottery_queries, submissions):
        _nat(value, 'capacity')
    if new_prefix_cap is None:
        return None
    _nat(new_prefix_cap, 'new_prefix_cap')
    return min(prepared_unqueried_cap + new_prefix_cap, online_lottery_queries + submissions)


def conditional_ticket_bounds(*, fresh_opportunities: int, probability: Fraction,
                              known_winning_credit: int, fanout: int,
                              failure_probability: Fraction, output_cap: int,
                              at_least: int) -> dict[str, Fraction | int]:
    """Tail/mean consequences of a PREDICTABLE valid-opportunity cap.

    These premises must be established separately. Stop/pad the process before
    conditioning on future failures; do not treat the distribution conditional
    on a good event as an unchanged binomial distribution.
    """
    _small(fresh_opportunities, 'fresh_opportunities')
    p = _probability(probability)
    _nat(known_winning_credit, 'known_winning_credit')
    _nat(fanout, 'fanout', positive=True)
    eps = _probability(failure_probability, 'failure_probability')
    _nat(output_cap, 'output_cap')
    _nat(at_least, 'at_least')
    required = max(0, (at_least - known_winning_credit + fanout - 1) // fanout)
    pmf = binomial_pmf(fresh_opportunities, p)
    probability_bound = min(Fraction(1), tail(pmf, required) + eps)
    if at_least > output_cap:
        probability_bound = Fraction()
    expectation_bound = min(Fraction(output_cap),
                            known_winning_credit + fanout * fresh_opportunities * p + eps * output_cap)
    return {'required_fresh_hits': required, 'tail_bound': probability_bound,
            'expectation_bound': expectation_bound}


def early_screening_countermodel(*, trace_values: int, distinct_guesses: int,
                                 probability: Fraction) -> dict[str, Fraction]:
    """Guess r distinct digests, inspect lotteries, then compute the true digest.

    Submit at most one correctly matched winning pair. The true digest is
    uniform and independent of the r independent lottery bits. This is a tiny
    ideal game exposing why G_final/2^lambda is not a temporal extraction bound.
    """
    _nat(trace_values, 'trace_values', positive=True)
    _nat(distinct_guesses, 'distinct_guesses')
    if distinct_guesses > trace_values:
        raise ValueError('distinct guesses exceed trace space')
    p = _probability(probability)
    return {'matched_early_guess': Fraction(distinct_guesses, trace_values),
            'accepted_winning_pair': Fraction(distinct_guesses, trace_values) * p,
            'incorrect_final_one_output_guess_bound': Fraction(1, trace_values)}


def winner_only_proof_pmf(budget: int, useful_cost: int, proof_cost: int,
                          probability: Fraction) -> tuple[Fraction, ...]:
    """Result first; generate a proof only for a hit; count only affordable proofs.

    A hit with insufficient remaining proof budget yields no accepted ticket
    and stops that branch. The schedule does not borrow budget, obtain refunds,
    carry an unpaid hit into another cohort, or assert an optimal mining policy.
    """
    _small(budget, 'budget')
    _small(useful_cost, 'useful_cost', positive=True)
    _small(proof_cost, 'proof_cost')
    p = _probability(probability)

    @lru_cache(maxsize=None)
    def solve(left: int) -> tuple[Fraction, ...]:
        if left < useful_cost:
            return (Fraction(1),)
        remaining = left - useful_cost
        miss = solve(remaining)
        if remaining < proof_cost:
            hit = (Fraction(1),)
        else:
            hit = (Fraction(),) + solve(remaining - proof_cost)
        result = [Fraction()] * max(len(miss), len(hit))
        for count, mass in enumerate(miss):
            result[count] += (1 - p) * mass
        for count, mass in enumerate(hit):
            result[count] += p * mass
        while len(result) > 1 and result[-1] == 0:
            result.pop()
        return tuple(result)

    return solve(budget)


def eager_proof_pmf(budget: int, useful_cost: int, proof_cost: int,
                    probability: Fraction) -> tuple[Fraction, ...]:
    """Separate comparison schedule: pay useful+proof before each lottery."""
    _small(budget, 'budget')
    _small(useful_cost, 'useful_cost', positive=True)
    _small(proof_cost, 'proof_cost')
    return binomial_pmf(budget // (useful_cost + proof_cost), _probability(probability))


def proof_gating_expectations(useful_cost: int, proof_cost: int,
                              probability: Fraction) -> dict[str, Fraction | None]:
    """Untruncated attempted-useful-work and first-accepted-win expectations."""
    _nat(useful_cost, 'useful_cost', positive=True)
    _nat(proof_cost, 'proof_cost')
    p = _probability(probability)
    return {
        'winner_only_per_started_useful_attempt': useful_cost + p * proof_cost,
        'eager_per_started_useful_attempt': Fraction(useful_cost + proof_cost),
        'winner_only_first_accepted_win': Fraction(useful_cost, 1) / p + proof_cost if p else None,
        'eager_first_accepted_win': Fraction(useful_cost + proof_cost, 1) / p if p else None,
    }


def proof_variant_structure(variants: int, *, lottery_binds_proof: bool,
                            credit_binds_proof: bool) -> tuple[tuple[tuple[int, int], tuple[int, int]], ...]:
    """Abstract encodings of ONE fixed statement with valid proof randomizations.

    Tokens are injective finite identities, not claims about a deployed ZK scheme.
    The statement is token 0. A proof index influences only the named policies.
    """
    _small(variants, 'variants', positive=True)
    if type(lottery_binds_proof) is not bool or type(credit_binds_proof) is not bool:
        raise ValueError('identity policies must be bool')
    return tuple(((0, i if lottery_binds_proof else 0),
                  (0, i if credit_binds_proof else 0)) for i in range(variants))


def proof_variant_credit_pmf(variants: int, probability: Fraction, *,
                             lottery_binds_proof: bool,
                             credit_binds_proof: bool) -> tuple[Fraction, ...]:
    """Distribution of distinct credited identities after trying all variants."""
    proof_variant_structure(variants, lottery_binds_proof=lottery_binds_proof,
                            credit_binds_proof=credit_binds_proof)
    p = _probability(probability)
    if not credit_binds_proof:
        hit = 1 - (1 - p) ** (variants if lottery_binds_proof else 1)
        return (1 - hit, hit)
    if lottery_binds_proof:
        return binomial_pmf(variants, p)
    return (1 - p,) + (Fraction(),) * (variants - 1) + (p,)


def monotone_consumption_count(events: Iterable[tuple[str, str]], *,
                               include_scope_in_key: bool) -> int:
    """Atomic monotone set within this abstract execution, without rollback.

    Events are (scope, useful_statement). A key including a parent/epoch scope
    permits one use in EACH scope. This function supplies no cross-fork authority.
    """
    if type(include_scope_in_key) is not bool:
        raise ValueError('include_scope_in_key must be bool')
    used: set[tuple[str, ...]] = set()
    for event in events:
        if not isinstance(event, tuple) or len(event) != 2 or any(type(x) is not str for x in event):
            raise ValueError('events must contain (scope, statement) string pairs')
        scope, statement = event
        used.add((scope, statement) if include_scope_in_key else (statement,))
    return len(used)


def shared_component_cost(first: Iterable[int], second: Iterable[int]) -> dict[str, int]:
    """Unit-operation sets: separate component bounds need not add."""
    a, b = set(first), set(second)
    for operation in a | b:
        _nat(operation, 'operation label')
    return {'first': len(a), 'second': len(b), 'overlap': len(a & b),
            'joint': len(a | b), 'unjustified_sum': len(a) + len(b)}


def report() -> dict:
    p = Fraction(1, 2)
    eager = eager_proof_pmf(36, 9, 9, p)
    gated = winner_only_proof_pmf(36, 9, 9, p)
    variants = {}
    for lottery in (False, True):
        for credit in (False, True):
            name = f'lottery_proof_{int(lottery)}_credit_proof_{int(credit)}'
            rows = proof_variant_structure(4, lottery_binds_proof=lottery, credit_binds_proof=credit)
            pmf = proof_variant_credit_pmf(4, p, lottery_binds_proof=lottery, credit_binds_proof=credit)
            variants[name] = {'unique_lottery_inputs': len({x for x, _ in rows}),
                              'unique_credit_keys': len({y for _, y in rows}),
                              'credit_pmf': pmf, 'expected_credits': mean(pmf), 'any_credit': tail(pmf, 1)}
    return {
        'schema': 'pon-w1-resource-reduction-v1',
        'status': 'exact-conditional-implications-and-countermodels-only',
        'sha256_extraction_established': False,
        'adaptive_prefix_hardness_established': False,
        'physical_resource_floor_established': False,
        'o01_closed': False, 'o05_production_composition_closed': False,
        'o07_production_zk_closed': False, 'production_activation': False,
        'temporal_guess_control': early_screening_countermodel(trace_values=8, distinct_guesses=4, probability=p),
        'ideal_oracle_illustration': temporal_oracle_failure_bound(
            preprocessing_trace_queries=2, online_trace_queries=4,
            preprocessing_lottery_queries=2, online_lottery_queries=8,
            header_queries=8, task_queries=3, submissions=2),
        'abstract_resource_transfer': {
            'declared_parameters': {'budget': 100, 'prefix_cost': 12, 'fixed_overhead': 3,
                                    'preprocessing_credit': 5, 'per_correct_overhead': 2,
                                    'per_candidate_overhead': 1, 'candidate_cap': 40},
            'new_prefix_cap': extraction_resource_cap(budget=100, prefix_cost=12, fixed_overhead=3,
                preprocessing_credit=5, per_correct_overhead=2, per_candidate_overhead=1, candidate_cap=40),
            'output_only_bound_cancels': extraction_resource_cap(budget=100, prefix_cost=12, per_correct_overhead=12),
        },
        'proof_gating': {'budget': 36, 'useful_cost': 9, 'proof_cost': 9, 'probability': p,
                         'eager_pmf': eager, 'winner_only_pmf': gated,
                         'eager_expected_credits': mean(eager), 'winner_only_expected_credits': mean(gated),
                         **proof_gating_expectations(9, 9, p)},
        'proof_randomness_policies': variants,
        'consumption_scope': {
            'events': [('parent-a', 'same-useful-result'), ('parent-a', 'same-useful-result'),
                       ('parent-b', 'same-useful-result')],
            'global_monotone_key_credits': monotone_consumption_count(
                [('a', 's'), ('a', 's'), ('b', 's')], include_scope_in_key=False),
            'parent_scoped_key_credits': monotone_consumption_count(
                [('a', 's'), ('a', 's'), ('b', 's')], include_scope_in_key=True)},
        'overlapping_work': shared_component_cost(range(10), range(10)),
    }


def _json_default(value):
    if isinstance(value, Fraction):
        return str(value)
    raise TypeError(type(value).__name__)


if __name__ == '__main__':
    print(json.dumps(report(), default=_json_default, sort_keys=True, indent=2))
