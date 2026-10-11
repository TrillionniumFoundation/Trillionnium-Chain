"""Conditional W1 query accounting, not a work-hardness or service certificate.

Model and binding. Put M=2**bits. Count first evaluations of distinct ticket
inputs, including preprocessing, delegation, and verifier evaluations requested
without local hashing. Before the i-th first query its legal target T_i is
predictable; conditional on the past the ideal ticket Y_i is uniform. Challenge
collisions, target rebinding and double credit must be excluded separately.
Let w_i=floor(M/(T_i+1)), I_i=1{Y_i<=T_i}, and L_n=sum(w_i*I_i).
Eventual newly credited valid work attributable to the first n queries is
pathwise at most L_n. This observation does not assume that eventual validity
is measurable at the time of the query.

First moment. E[w_i*I_i | past] <= 1. Consequently E[L_tau] <= E[tau]
for bounded stopping times tau. Splitting a fixed total query budget between
identities changes neither bound. Excluding delegated work invalidates it.

Tail and anytime bound. Suppose a deterministic W >= 1 bounds every w_i and
r>1. Convexity on [0,W] gives r**w-1 <= (w/W)*(r**W-1). Therefore
    E[r**(w_i*I_i) | past] <= 1 + (r**W-1)/W =: m.
Thus Z_n=r**L_n/m**n is a nonnegative supermartingale, Z_0=1. Markov gives
    P(credited work from first q queries >= s) <= min(1,m**q/r**s).
For K>1, stop at the first Z_n>=K and at an arbitrary finite horizon N.
E[Z_stop]<=1 implies P(max_(n<=N) Z_n>=K)<=1/K. Increasing N preserves
this bound. Hence, with probability at least 1-delta, simultaneously for all n,
    credited_work(n)*log(r) < n*log(m) + log(1/delta).
The inclusion remains valid for eventual credit because credited_work(n)<=L_n.
This is not a finality confidence level: it counts all relevant queries, not
attacker-only CPU, matrix multiplications, energy, network permits or service.
Repeated invalid proofs can consume verifier resources with no new ticket
query. No physical-cost, Sybil-service, efficacy or production flag is set.

The Fraction helpers below accompany the algebra with finite exact checks.
They do not evaluate the random-oracle assumption or run an admission policy.
"""
from fractions import Fraction


def parameters(target: int, bits: int = 256) -> tuple[int, int]:
    if type(bits) is not int or not 2 <= bits <= 256:
        raise ValueError("BITS")
    modulus = 1 << bits
    if type(target) is not int or not 1 <= target < modulus:
        raise ValueError("TARGET")
    return modulus, modulus // (target + 1)


def expected_first_query_credit(target: int, bits: int = 256) -> Fraction:
    modulus, work = parameters(target, bits)
    return Fraction((target + 1) * work, modulus)


def union_bound(target: int, own_queries: int, delegated_queries: int = 0,
                bits: int = 256) -> Fraction:
    modulus, _ = parameters(target, bits)
    if any(type(n) is not int or n < 0 for n in (own_queries, delegated_queries)):
        raise ValueError("QUERY_COUNT")
    return min(Fraction(1), Fraction((own_queries + delegated_queries) *
                                    (target + 1), modulus))


def step_envelope(r: Fraction, work_cap: int) -> Fraction:
    if not isinstance(r, Fraction) or r <= 1:
        raise ValueError("EXPONENTIAL_BASE")
    # Only the exact-arithmetic helper is bounded; the theorem is not.
    if type(work_cap) is not int or not 1 <= work_cap <= 4096:
        raise ValueError("FINITE_CHECK_CAP")
    return 1 + (r ** work_cap - 1) / work_cap


def fixed_query_tail(q: int, credit: int, r: Fraction,
                     work_cap: int) -> Fraction:
    if any(type(n) is not int or not 0 <= n <= 4096 for n in (q, credit)):
        raise ValueError("FINITE_CHECK_RANGE")
    m = step_envelope(r, work_cap)
    return min(Fraction(1), m ** q / r ** credit)
