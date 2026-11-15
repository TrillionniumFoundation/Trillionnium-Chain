"""Resource-transfer counterexamples for the grouped fresh-seal research.

This module separates three claims that cannot be substituted for each other:

* total classical chain-oracle queries, including honest verification;
* the attack coalition's own queries;
* physical or fresh useful-computation costs.

It adds no consensus rule, attestation, permit or activation switch. A numeric
budget supplied to a function below is a premise, not authenticated evidence.
The native closed-authority experiment must establish its own limited topology
and actual replay ceiling; other authorities, clones, rollbacks and other
oracle-dependent advice remain outside that ceiling.

CONSERVATIVE TRANSFER THAT DOES NOT NEED HIDDEN VERIFICATION.
Under the classical aggregate theorem in fresh_work_query_floor_v0, suppose
Q_A <= q_A are all coalition step-oracle queries and Q_V <= B_V are all other
step-oracle queries that can provide information used by the coalition. Include
verification, preprocessing and public helpers; do not omit an external service
merely because the attacker does not pay its bill. If mu_A = E[Q_A], then

  E[C] <= min(L*(mu_A+B_V),
              mu_A+B_V+L*(q_A+B_V)*(q_A+B_V+1)/(2*M)).

Proof: Q_total=Q_A+Q_V, its cap is q_A+B_V, and its expectation is at most
mu_A+B_V. Both branches of the aggregate bound are increasing in this
expectation. The verifier can reveal its complete oracle transcript, result,
timing and cache behavior: an ordinary classical algorithm with access to that
entire charged transcript is already included in the aggregate theorem. This
does NOT permit oracle-dependent advice whose originating queries are outside
the accounting horizon, or change the fixed statement/target/unique-credit
premises. It does not charge B_V to the attacker's wallet. With B_V nonzero,
zero coalition queries can still earn positive expected credit.

If one durably serialized authority starts at most K callbacks, and each callback
performs at most R complete L-step replays, then Q_V_callbacks <= K*R*L. One may
choose B_V = K*R*L only when these callbacks cover all assisting step queries;
otherwise add the ceilings for the remaining sources.
Reserved/started callbacks lost to a crash must retain their full possible
charge. Cached reply retransmissions can have zero further step queries, but
are not free parsing, network, signing or storage. Seed hashes are separate:
the underlying theorem grants the public independent seed for free. Multiple
independent authorities require summing their capacities. A quota per local
journal, receiver, nonce or epoch is not a global cap by itself.

TWO EXACT CLASSICAL COUNTEREXAMPLES.
1. Uniform hidden endpoint: different winning guesses submitted through cloned
   local budgets can exploit the sum of those budgets, even for one candidate.
   Their mean nominal credit is min(total_guesses,T+1)*W/M. This is a model
   counterexample to using one journal's K, not an observed native exploit.
2. A verifier that additionally reveals one requested endpoint bit per reply
   permits a zero-chain-query coalition to reconstruct the endpoint in at most
   lambda checks and make one final exact claim. All successful equalities
   close the candidate. Its mean is (T+1)*W/M, near L, even though each reply
   only has one extra bit. Arbitrary one-bit/timing feedback is NOT the hidden
   endpoint-equality oracle assumed by the stronger coalition corollary.

WHY NO POSITIVE FRESH NEURAL-MAC FLOOR FOLLOWS FOR THIS PROFILE.
Its business product F(task,input,model) is challenge-independent and lawfully
cacheable. Once F has been computed, every subsequent challenge can use that
same product and compute only the security seal. Thus the existing constructive
producer has zero fresh business contractions after preparation. Since counts
are nonnegative, this REFUTES a positive per-challenge producer contraction
floor for the current admitted cache scope; it is stronger than "not proved".
The independent verifier may still recompute F and pay that separate cost.
Preparation cost and finite cache scope still matter; neither a linear hash
chain nor a larger sample count can imply a positive fresh producer F cost here.
For a newly chosen finite-domain useful relation, unrestricted preparation can
also tabulate all supported input/output pairs: online multiplication count,
offline work, table bytes/access and the amortization window must be separated.

QUANTUM SCOPE AND THE EXACT FINITE SEARCH CONTROL.
The ideal search below is a strategy in a quantum black-box model, NOT a
compiled SHA-256 circuit or physical lower bound. N candidate endpoints are
independent and uniform in M values; the target is fixed before the search.
For each possible number k of winners, Grover's two amplitudes are evolved
exactly with rational arithmetic. We average over k~Binomial(N,(T+1)/M), rather
than condition on an unusually favorable marked set. One fixed search schedule
is used for every k, including k=0. A clean phase evaluation is assumed to do
L forward step-oracle calls and L inverse calls; one measured candidate is then
computed with L classical calls to learn its endpoint, and submitted for a
second independent L-call verifier replay even on a target miss. All
(2*r+2)*L calls are counted, including the verifier. The phase oracle had
uncomputed its endpoint, so it must not be given to the claimant for free.
Public seed preparation is free in this abstract model, as in the classical
lemma. Data loading, the hash/seed/challenge circuits, diffusion gates, memory,
error correction, proof and propagation are not supplied. The independent
verifier's abstract L-query replay is included, not its complete machine cost.

The exact strategy can exceed the CLASSICAL aggregate-credit envelope at the
same abstract query count. This is a counterexample to applying that envelope
to coherent queries, not a contradiction of its explicitly classical theorem.
PoSW quantum sequentiality of a particular protocol is a different claim from
the lottery's total-query fairness; a bound for finding a full chain cannot be
silently applied to an endpoint-only verifier and a weighted lottery.

Primary sources (background results, not attribution of our special bounds):
* Zalka, optimal black-box quantum search:
  https://arxiv.org/abs/quant-ph/9711070
* Blocki, Lee, Zhou, post-quantum PoSW and parallel query rounds:
  https://arxiv.org/abs/2006.10972
* Chung, Fehr, Huang, Liao, compressed-oracle technique and full PoSW analysis:
  https://eprint.iacr.org/2020/1305
"""
from __future__ import annotations

from fractions import Fraction
from math import comb

import fresh_work_query_floor_v0 as floor


SCHEMA = 'pon-fresh-work-resource-transfer-model-v0'
MAX_ENUMERATION_BITS = 12
MAX_SEARCH_CANDIDATES = 256
MAX_GROVER_ITERATIONS = 64


def rational(value):
    """Lossless JSON representation; no floating confidence or cost claim."""
    number = Fraction(value)
    return dict(numerator=number.numerator, denominator=number.denominator)


def replay_step_query_cap(submission_cap, *, length=floor.RESEARCH_STEPS,
                          replays_per_submission=1):
    """Conditional callback cap, excluding seed and other non-step work.

    A caller must establish that all potentially informative replays fit these
    parameters. This arithmetic does not validate a native log or authenticate
    the existence/identity of the authority that enforces the cap.
    """
    floor.integer(submission_cap, 'SUBMISSION_CAP')
    floor.integer(length, 'LENGTH', 1)
    floor.integer(replays_per_submission, 'REPLAYS_PER_SUBMISSION', 1)
    return submission_cap * replays_per_submission * length


def total_work_bound_with_verifier_budget(query_cap, verifier_query_cap, *,
        bits=256, length=floor.RESEARCH_STEPS, expected_queries=None):
    """Classical total-work corollary allowing complete verifier disclosure.

    No bound on the attacker's own physical or neural cost is returned. B_V is
    a deterministic ceiling, not a mean and not the observed successful count.
    """
    floor.integer(query_cap, 'COALITION_QUERY_CAP')
    floor.integer(verifier_query_cap, 'VERIFIER_QUERY_CAP')
    floor.integer(length, 'LENGTH', 1)
    mean = Fraction(query_cap) if expected_queries is None else expected_queries
    if type(mean) is not Fraction or not 0 <= mean <= query_cap:
        raise ValueError('EXPECTED_COALITION_QUERIES')
    return floor.expected_credit_bound(query_cap + verifier_query_cap,
        bits=bits, length=length, expected_queries=mean + verifier_query_cap)


def winning_guesses_expectation(guesses, *, target, bits=256,
                                length=floor.RESEARCH_STEPS):
    """Uniform endpoint, no own queries, distinct winning guesses, one award.

    Success closes the candidate, so more guesses than winning values cannot
    inflate the expectation beyond the chance that this candidate is a winner.
    """
    floor.integer(guesses, 'GUESSES')
    size = floor.modulus(bits)
    award = floor.nominal_award(target, bits=bits, length=length)
    distinct = min(guesses, target + 1)
    return Fraction(distinct * award, size)


def copied_budget_counterexample(*, local_cap=16, copies=8, bits=12,
                                target=2047, length=floor.RESEARCH_STEPS):
    """A local quota cannot certify the endpoint-only lemma's global K."""
    floor.integer(local_cap, 'LOCAL_CAP', 1)
    floor.integer(copies, 'COPIES', 1)
    award = floor.nominal_award(target, bits=bits, length=length)
    actual_cap = local_cap * copies
    exact_credit = winning_guesses_expectation(actual_cap, target=target,
                                              bits=bits, length=length)
    return dict(
        case='copied_local_quotas_one_candidate', bits=bits, target=target,
        length=length, local_cap=local_cap, independent_budget_copies=copies,
        actual_submission_cap=actual_cap, canonical_candidates=1,
        own_chain_queries=0, maximum_award=award,
        exact_expected_credit=rational(exact_credit),
        incorrectly_assumed_local_bound=rational(floor.coalition_credit_bound(
            0, local_cap, award, bits=bits, length=length)),
        correctly_aggregated_bound=rational(floor.coalition_credit_bound(
            0, actual_cap, award, bits=bits, length=length)),
        observed_native_exploit=False, actual_chainwork=0)


def endpoint_bit_leak_counterexample(*, bits=8, target=127,
                                    length=floor.RESEARCH_STEPS):
    """Enumerate every endpoint for a synthetic one-extra-bit verifier.

    It compares a guessed endpoint and additionally reveals bit j. A successful
    equality closes the candidate even for a target miss. The adversary first
    guesses zero, requesting successive bits. If zero is correct it closes
    immediately; otherwise all bits reconstruct the endpoint for a final claim.
    The verifier may cache its one complete chain replay across bit requests.
    No such side channel is asserted to exist in the current native program.
    """
    floor.integer(bits, 'ENUMERATION_BITS', 2, MAX_ENUMERATION_BITS)
    size = floor.modulus(bits)
    award = floor.nominal_award(target, bits=bits, length=length)
    credit = calls = successes = 0
    maximum_calls = 0
    for endpoint in range(size):
        reconstructed = 0
        used = 0
        closed = False
        for bit in range(bits):
            used += 1
            if endpoint == 0:
                closed = True
                credit += award
                successes += 1
                break
            reconstructed |= ((endpoint >> bit) & 1) << bit
        if not closed:
            used += 1
            if reconstructed != endpoint:
                raise AssertionError('BIT_RECONSTRUCTION')
            closed = True
            if reconstructed <= target:
                credit += award
                successes += 1
        if not closed:
            raise AssertionError('SUCCESSFUL_EQUALITY_MUST_CLOSE')
        calls += used
        maximum_calls = max(maximum_calls, used)
    exact_credit = Fraction(credit, size)
    if exact_credit != Fraction((target + 1) * award, size):
        raise AssertionError('EXHAUSTIVE_EXPECTATION')
    return dict(case='synthetic_endpoint_bit_feedback', bits=bits,
        target=target, length=length, oracle_worlds=size,
        own_chain_queries=0, successful_winning_worlds=successes,
        maximum_verifier_calls=maximum_calls, mean_verifier_calls=rational(
            Fraction(calls, size)), maximum_award=award,
        exact_expected_credit=rational(exact_credit),
        invalid_equality_only_bound=rational(floor.coalition_credit_bound(
            0, maximum_calls, award, bits=bits, length=length)),
        actual_verifier_step_queries_each_world=length,
        valid_total_work_bound_with_cached_verifier=rational(
            total_work_bound_with_verifier_budget(0, length,
                bits=bits, length=length)),
        observed_native_side_channel=False, actual_chainwork=0)


def grover_probability(candidate_count, marked_count, iterations):
    """Exact success of a specified ideal Grover strategy, including zero marks.

    Per-basis-state amplitudes are a/sqrt(N) and b/sqrt(N). Their rational
    coefficients stay exact; this is not an upper bound on arbitrary circuits.
    """
    floor.integer(candidate_count, 'SEARCH_CANDIDATES', 1, MAX_SEARCH_CANDIDATES)
    floor.integer(marked_count, 'MARKED_COUNT', 0, candidate_count)
    floor.integer(iterations, 'GROVER_ITERATIONS', 0, MAX_GROVER_ITERATIONS)
    if candidate_count & (candidate_count - 1):
        raise ValueError('SEARCH_DOMAIN_POWER_OF_TWO')
    marked, unmarked = Fraction(1), Fraction(1)
    for _ in range(iterations):
        mean_after_phase = (-marked_count * marked +
            (candidate_count - marked_count) * unmarked) / candidate_count
        marked, unmarked = (2 * mean_after_phase + marked,
                            2 * mean_after_phase - unmarked)
    norm = marked_count * marked ** 2 + (candidate_count - marked_count) * unmarked ** 2
    if norm != candidate_count:
        raise AssertionError('GROVER_NORM')
    return marked_count * marked ** 2 / candidate_count


def quantum_random_candidates_counterexample(*, candidate_count=64, iterations=5,
        bits=64, target=(1 << 58) - 1, length=floor.RESEARCH_STEPS):
    """Average a fixed strategy over every independently marked candidate set.

    Neither target nor iteration count adapts to the measured marked count.
    Binomial multiplicities account for all 2**N subsets without listing them.
    """
    size = floor.modulus(bits)
    award = floor.nominal_award(target, bits=bits, length=length)
    # This call also checks candidate_count, iteration range and power-of-two.
    grover_probability(candidate_count, 0, iterations)
    win_probability = Fraction(target + 1, size)
    probability = probability_mass = Fraction(0)
    for marked in range(candidate_count + 1):
        mass = (comb(candidate_count, marked) * win_probability ** marked *
                (1 - win_probability) ** (candidate_count - marked))
        probability_mass += mass
        probability += mass * grover_probability(candidate_count, marked, iterations)
    if probability_mass != 1:
        raise AssertionError('BINOMIAL_MASS')
    step_queries = (2 * iterations + 2) * length
    expected_credit = award * probability
    classical_envelope = floor.expected_credit_bound(step_queries, bits=bits,
                                                     length=length)
    return dict(case='ideal_quantum_search_random_candidates', bits=bits,
        target=target, length=length, candidate_count=candidate_count,
        iterations_precommitted=iterations,
        marked_set_count=1 << candidate_count,
        marked_count_classes=candidate_count + 1,
        one_candidate_probability=rational(win_probability),
        zero_marked_probability=rational((1 - win_probability) ** candidate_count),
        exact_success_probability=rational(probability),
        nominal_award=award, exact_expected_credit=rational(expected_credit),
        forward_step_queries=iterations * length,
        uncomputation_step_queries=iterations * length,
        measured_candidate_check_step_queries=length,
        independent_verifier_step_queries=length,
        own_abstract_step_queries=(2 * iterations + 1) * length,
        total_abstract_step_queries=step_queries,
        inapplicable_classical_credit_envelope=rational(classical_envelope),
        exceeds_classical_envelope=expected_credit > classical_envelope,
        physical_resources_complete=False, coherent_native_circuit_implemented=False,
        independent_verifier_and_propagation_costs_complete=False,
        quantum_lower_bound_proved=False, actual_chainwork=0)


def finite_report():
    """Deterministic exact controls, no production qualification claim."""
    return dict(schema=SCHEMA,
        copied_budget=copied_budget_counterexample(),
        bit_leak=endpoint_bit_leak_counterexample(),
        quantum=quantum_random_candidates_counterexample(),
        callback_cap_example=dict(submission_cap=256, complete_replays_per_submission=1,
            length=floor.RESEARCH_STEPS, conditional_step_query_cap=replay_step_query_cap(256),
            authenticated_native_cap=False),
        conclusion=dict(aggregate_classical_transfer='conditional_with_explicit_verifier_queries',
            endpoint_only_coalition_transfer_established=False,
            producer_fresh_business_contractions_after_legal_preparation=0,
            positive_producer_fresh_contraction_floor_refuted_for_current_cache_scope=True,
            physical_resource_lower_bound_proved=False, quantum_security_proved=False,
            production_qualification='HOLD', actual_chainwork=0))
