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

Rounding and cost conversion. This upper bound is not equality at every target.
Write d=T+1 and eta(T)=d*floor(M/d)/M. If T<=P and k=floor(M/(P+1)),
then k/(k+1)<eta(T)<=1: for w=floor(M/d), d>M/(w+1), so
eta(T)>w/(w+1)>=k/(k+1). For the current P=M/2-1 this gives 2/3<eta<=1.
At T=M/3 rounded down, w=2 and eta=2*(floor(M/3)+1)/M, approaching
2/3 as bits increases. At T=M/2-1, eta=1. Distinct-target per-query
credit therefore need not match even if the full legal attempt costs match.

In a conditional constant-rate comparison, q denotes the attacker's share of
one additive resource and s its complete legal attempt rate per resource unit
relative to the honest rate. The ratio of expected credited-work rates is
    q_eff = q*s*eta_A / (q*s*eta_A + (1-q)*eta_H).
The equal-mean-work resource share is eta_H/(s*eta_A+eta_H). If s already
means credited-work rate per resource, eta is absorbed and must NOT be applied
twice. For any targets bounded by P, q<k/(k+(k+1)*s) is a sufficient
condition for honest expected work to exceed attacker expected work in this
model. It is neither necessary nor a common-prefix/finality theorem. Current
DAA targets are branch-derived; this arithmetic does not show that an attacker
can select or sustain either target, account for transitions/withholding, or
measure s. The lower bound applies to fully legal attempts whose wins can be
credited, not fabricated traces, delegated validation or unavailable blocks.

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


def strict_credit_lower_bound(pow_limit: int, bits: int = 256) -> Fraction:
    """Strict lower bound for eta over 1<=T<=pow_limit, not attained generally."""
    _, minimum_weight = parameters(pow_limit, bits)
    return Fraction(minimum_weight, minimum_weight + 1)


def _rate(value: Fraction, name: str, *, share: bool = False) -> Fraction:
    if not isinstance(value, Fraction) or (not 0 <= value <= 1 if share else value <= 0):
        raise ValueError(name)
    return value


def conditional_mean_work_share(resource_share: Fraction, attempt_rate_advantage: Fraction,
                                attacker_target: int, honest_target: int,
                                bits: int = 256) -> Fraction:
    """Ratio of mean credited-work rates; no chain-race success probability."""
    q = _rate(resource_share, "RESOURCE_SHARE", share=True)
    s = _rate(attempt_rate_advantage, "ATTEMPT_RATE_ADVANTAGE")
    attack = q * s * expected_first_query_credit(attacker_target, bits)
    honest = (1 - q) * expected_first_query_credit(honest_target, bits)
    return attack / (attack + honest)


def equal_mean_work_share(attempt_rate_advantage: Fraction, attacker_target: int,
                          honest_target: int, bits: int = 256) -> Fraction:
    """Resource share at equal expected work rates under the stated cost model."""
    s = _rate(attempt_rate_advantage, "ATTEMPT_RATE_ADVANTAGE")
    attack = s * expected_first_query_credit(attacker_target, bits)
    honest = expected_first_query_credit(honest_target, bits)
    return honest / (attack + honest)


def sufficient_mean_work_share(attempt_rate_advantage: Fraction, pow_limit: int,
                               bits: int = 256) -> Fraction:
    """Any smaller q gives honest mean-work dominance; not protocol security."""
    s = _rate(attempt_rate_advantage, "ATTEMPT_RATE_ADVANTAGE")
    honest_lower = strict_credit_lower_bound(pow_limit, bits)
    return honest_lower / (s + honest_lower)


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
