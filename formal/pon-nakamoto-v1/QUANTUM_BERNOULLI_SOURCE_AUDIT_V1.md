# Quantum Bernoulli source audit: reject the printed finite-sum certificate

Status: **REJECT_PRINTED_SOURCE_BOUND; production HOLD.** This note audits a
specific expression printed in arXiv:2012.15254v4 and the published Quantum
7:944 PDF. It does not demonstrate an attack against the Chain-of-PoWs game,
MU1, W1, or a deployed node. The repository's independent conservative
recording proof remains a separate mathematical object.

Implementation: [quantum_bernoulli_source_audit.py](quantum_bernoulli_source_audit.py).
Regression checks: [test_quantum_bernoulli_source_audit.py](test_quantum_bernoulli_source_audit.py).

## 1. Preserve the distinction between algebra and an applicable theorem

The printed Bernoulli expression is

\[
 F(n,k)=4(1-p)p^k
 \left[\sum_{i=0}^k {n\choose i}(1-p)^{i/2}\right]^2.
 \tag{1}
\]

Substituting the paper's stated chain argument n=N+k, then k=N, and extending
the nonnegative sum from i<=N to i<=2N gives the algebraic inequality

\[
 F(2N,N)
 \le \frac{15}{4}
 \left[\frac{1921+496\sqrt{15}}{4096}\right]^N,\qquad p=1/16.
 \tag{2}
\]

The base is approximately 0.9379882177048045. That algebra is correct.
Its correctness does not establish that (1) bounds the relevant search
probability. Section 2 gives a finite counterexample to (1) as printed.
Accordingly the right side of (2) is retained only as a
**printed_expression_only** calculation. Neither expression is accepted as
a security certificate by this audit.

The simplified epsilon parameterization is also inapplicable at p=1/16:
the lower limit e sqrt(p)/(1-e sqrt(p)) is approximately 2.1208108684,
which cannot coexist with 0<epsilon<1. Directly rearranging the decay
condition shows that some epsilon in that interval exists only when
p<1/(4e^2). This parameter incompatibility is distinct from the finite
counterexample below. Reducing p to satisfy the epsilon condition would not
repair a failed source inequality.

The expression evaluator retains the N+k substitution explicitly and checks
1<=k<=N, N<=4096, k<=64. Those are finite evaluator limits, not production
consensus parameters. All probability qualification flags remain false.

## 2. Exact three-partition Grover counterexample

Take a Boolean function on the 64-address domain {0,...,63}, with each bit
independently marked with probability p=1/16. This is a finite power-of-two
domain in the stated Bernoulli search model. Use the disjoint partitions

- {0,...,15};
- {16,...,31};
- {32,...,47}.

The remaining 16 addresses are unused. In each partition prepare its uniform
superposition, apply one Boolean phase-oracle query, reflect about that
uniform superposition, and measure an address. Do this separately in all
three partitions. Total oracle queries are n=3; the algorithm outputs k=3
distinct addresses. The final external search-success test asks whether all
three outputs are marked. The algorithm does not request free online
verification feedback.

For a partition of size m containing j marked addresses, put a=j/m. The
phase query and reflection give success probability

\[
 g(j,m)=a(3-4a)^2.
 \tag{3}
\]

This formula also follows directly from the state vector: before the query
each amplitude is 1/sqrt(m); the query changes the signs of the marked
amplitudes; reflection replaces each amplitude v by 2 mean(v)-v.
Every marked amplitude afterward is (3-4j/m)/sqrt(m).

Averaging over J~Binomial(16,1/16) gives

\[
 q=\sum_{j=0}^{16}
 {16\choose j}\left(\frac1{16}\right)^j
 \left(\frac{15}{16}\right)^{16-j}
 \frac{j}{16}\left(3-\frac{j}{4}\right)^2
 =\frac{13073}{32768}.
 \tag{4}
\]

Because the partitions use disjoint independent oracle coordinates, their
success events are independent. Therefore the legal three-query strategy has
success probability exactly

\[
 q^3=\frac{2234219220017}{35184372088832}
 \approx 0.06350032947514705.
 \tag{5}
\]

In contrast, the printed expression evaluated at n=k=3 is

\[
 F(3,3)=\frac{1786065+461160\sqrt{15}}{67108864}
 \approx 0.05322888493444044.
 \tag{6}
\]

Equation (5) is strictly larger than (6). This comparison uses integers, not
floating-point tolerances. For success r/t and printed expression
(a+b sqrt(15))/d, define C=rd-ta and D=tb. Here C>0 and

\[
 C^2-15D^2=
 3636360139341798489242762333020607217664>0.
\]

Thus the displayed finite sum fails as a universal bound in that Boolean
Bernoulli query game. This is a qualification failure of the cited
expression. It is not a Chain-of-PoWs attack: that different game requires
chained full oracle values, and the construction here outputs three
independent marked Boolean addresses.

The regression test independently computes all 17 permutation classes of
16-dimensional phase-query/reflection state vectors using rational
amplitudes. It verifies unit norm and averages their exact marked
probabilities. A separate control enumerates all 65,536 Boolean truth tables
on a 16-address partition, verifies normalization for every table, and obtains
the same weighted success without binomial grouping. No quantum device, real
hash experiment, or native node run is claimed.

## 3. A local progress-lemma check identifies a missing factor

The same issue is visible earlier in the printed proof. A Boolean phase
query changes a dual-record zero coordinate to a one coordinate with
amplitude magnitude

\[
 c=2\sqrt{p(1-p)}.
\]

Starting from an independent oracle record, query two different fixed
addresses. The amplitude of the record with both coordinates excited is
c^2=4p(1-p). At p=1/16 this is 15/64. The printed Lemma 3.12 expression for
n=k=2 gives 2 sqrt(1-p) p = sqrt(15)/32. Their squares are respectively
225/4096 and 60/4096, so that printed upper bound is too small.

Selected-coordinate projection also requires its actual operator norm.
On k selected coordinates and excitation layer i, that norm includes
sqrt(binomial(k,i)). Mapping multiple orthogonal excitation patterns onto
the same success vector cannot discard this factor.

These checks explain why the repository's existing proof retains both
2 sqrt(p(1-p)) and sqrt(binomial(k,i)). They are not a claim that inserting
one missing constant repairs every statement of the external paper.

## 4. The existing conservative proof is the available replacement interface

Use [MANDATORY_UNITS_RELATION_V1.md](MANDATORY_UNITS_RELATION_V1.md)
Sections 6-7 and [mandatory_units_query.py](mandatory_units_query.py).
Their recording recurrence and selected-output projection are derived
separately; their formulas do not import (1).

Some exact finite checks of that existing interface at p=1/16 are:

| Query interpretation | Bit queries n | Required distinct outputs k | Existing conservative bound |
| --- | ---: | ---: | ---: |
| Boolean search, same counts as the counterexample | 3 | 3 | approximately 0.4132436551 |
| Boolean search | 64 | 64 | approximately 0.00002965220956 |
| Full-value diagonal, even granting output extraction free | 2k | k, every k=1,...,64 | exactly 1 |

The first row covers the actual success probability in (5). The second row
is a nontrivial conditional ideal-query result. Neither supplies physical
cost or native confirmation risk.

The last row matters for replacing the old chain claim. The repository's
safe full-value-oracle simulation uses at most two Boolean queries per full
query. Even before charging possible extra queries to recover chain values,
the existing conservative arithmetic returns one throughout this tested
diagonal range. More allowed queries cannot improve that upper bound.
Therefore this audit supplies **no replacement nontrivial diagonal
Chain-of-PoWs exponential bound**. That question remains HOLD.

The exact integer calculations and the existing bound are independent:
a successful arithmetic test for (2) is not allowed to select the rejected
source in place of the conservative interface.

## 5. Stopping is qualified separately from the source expression

For any independently established terminal-query theorem, a stopping rule
can be incorporated into the same query algorithm if it starts from the
same oracle-independent joint initial state, uses at most N total queries
on every path, and chooses its stopping time using information actually
available to it. It may retain its stopped candidate and pad the remaining
query slots with identity calls. The resulting terminal algorithm has the
same output law. This observation does not establish the missing theorem
for (1).

It also does not justify a probability bound for "some unverified guess at
some time was valid" when the algorithm cannot identify that time without
additional oracle information. Such an event requires paid membership
feedback, or retention of the complete bounded output list followed by the
fixed-index union used in
[lifecycle_query_charging_v1.md](lifecycle_query_charging_v1.md), Section 3.

All preprocessing, public helpers and retained coherent states belong to the
same global query history. A later epoch, process restart, work profile,
private branch or task deadline does not make that state independent of the
oracle again. Conditional continuation needs the actual complete prefix or
a proved joint residual-state certificate. The existing lifecycle theorem
already states these conditions; this audit does not create a second,
weaker interpretation.

## 6. Reproduction and fail-closed behavior

Run:

    python3 formal/pon-nakamoto-v1/test_quantum_bernoulli_source_audit.py
    python3 formal/pon-nakamoto-v1/quantum_bernoulli_source_audit.py

The machine-readable report has status REJECT_PRINTED_SOURCE_BOUND and
source_bound_usable=false even when the printed expression is below one.
The explicitly rejected certificate entry point raises
PRINTED_SOURCE_BOUND_REJECTED. Decimals are display-only; all comparisons
that establish the counterexample use rational or integer arithmetic.

The finite tests do not certify the completeness of a real query budget,
the absence of oracle-correlated initial advice, actual SHA-256 behavior,
minimum W1 cost, native fork choice, production admission, or confirmation
security. Existing HOLD gates retain their meaning.

## 7. Primary source locations and scope

- Cojocaru, Garay, Kiayias, Song and Wallden,
  [arXiv:2012.15254v4](https://arxiv.org/html/2012.15254v4),
  Theorem 3.1, Lemmas 3.12-3.13, Theorem 3.14, and Lemma 4.4.
  The [published PDF](https://quantum-journal.org/papers/q-2023-03-09-944/pdf/)
  contains the same audited expressions. This note concerns that explicit
  version and those expressions; any corrected version must be reviewed
  independently before qualification.
- Bailey and Sattath,
  [arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2).
  Their difficulty-amplification mechanism remains relevant to linear
  chain credit and square-root quantum search scaling; it does not validate
  the rejected Bernoulli constants.
- Jeffery and Zur,
  [ICALP 2026, Article 118](https://drops.dagstuhl.de/storage/00lipics/lipics-vol374-icalp2026/html/LIPIcs.ICALP.2026.118/LIPIcs.ICALP.2026.118.html).
  The MLADV proof framework requires an explicit admissible progress
  operator. Its independent-input direct-product statement and sequential
  query scope do not automatically instantiate the W1 lifetime contract.
