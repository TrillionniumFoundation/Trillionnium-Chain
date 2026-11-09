# Fixed-success query costs: exact conditional frontiers

Date: 2026-11-09. Status: **research arithmetic; HOLD_NO_GO**.

This continuation separates unconditional expected cost, a hard query cap,
and uncharged final output checking. It proves an exact frontier for **every
classical adaptive policy in one specified independent-Bernoulli oracle game**.
The first-moment argument already appears in [work_query_bound.py](work_query_bound.py).
The additions are its fixed-success optimum, finite-domain/output boundary,
and explicit resource-transfer requirements. These elementary results are
not a new general search algorithm or an actual W1 cost theorem.

Implementation: [fixed_success_query_frontier.py](fixed_success_query_frontier.py).
Controls: [test_fixed_success_query_frontier.py](test_fixed_success_query_frontier.py).
All sixteen actual classical/quantum cost points in the
[fixed-probability contract](fixed_probability_contract_v1.json) remain
`lower=null`, `upper=null`, `status=unproved`. No admission or credit rule changes.

## 1. Fix the experiment before minimizing cost

An actual cost envelope must fix the work relation and eligible data, success
event, initial joint state or allowed initial-state family, deadline, resource
units, and the party whose resource is charged. Its target is, for example,

\[
K_\chi(\alpha,\Delta)=\inf_{A\in\mathcal A_\chi}
 \{\mathbb E[C_A]:\Pr[E_A\text{ by }\Delta]\ge\alpha\}.
\]

The expectation includes failure, cancellation, abandoned and unpublished
work. Initial preparation is either in this account or in a justified initial
allowance, never erased at a restart. If the participant may choose its
initial state, the lower bound must be uniform over those permitted choices.
Publicly available preparation cannot simply be billed again to each miner.
Proof creation, transmission, verification and recovery need their own
declared ownership and prices. A query count alone specifies none of them.

The executable experiment here deliberately fixes a narrower resource:

- There are `d` available addresses. Each address has an independently sampled
  Bernoulli mark with known probability `p`. Initial state, program and private
  randomness are independent of the entire mark table.
- Any classical history-dependent address choice, repetition, randomization
  and stopping policy is allowed. Every producer membership query costs one,
  including repeats; at most `n` producer queries are permitted on every path.
- Success is a marked queried output, or a marked address among at most `m`
  distinct, previously unqueried outputs returned at termination. The latter
  receive no online membership feedback. The mathematical final check is not
  billed to the producer. A checked winner can be output also when `m=0`.
- Non-query computation and arbitrary exact private probability coins are
  free **in this query metric**. This does not certify finite-seed, gate-cost
  or wall-clock attainment. A hard query cap is not a physical deadline.

Probability and expectation average over both the random table and private
coins. They are not success guarantees for each fixed table: the all-unmarked
table has positive probability when `p<1`. A fixed SHA instance does not
automatically have this averaged experiment's law.

`m` caps unchecked final guesses; it is not permission to exceed a separately
specified total-output contract. For a positive total cap `M`, the attaining
policy below outputs one checked winner, or at most `m<=M` unchecked guesses.
No quantum policy, oracle-correlated advice, later public oracle help or actual
SHA-256 assumption is covered by this experiment.

## 2. Exact frontier, including finite data availability

For `0<p<1`, put

\[
g=\min(m,d),\quad k=\min(n,d-g),\quad
f=1-(1-p)^g,\quad s_{\max}=1-(1-p)^{k+g}.
\tag{1}
\]

**Theorem.** A target `0<=alpha<=1` is feasible precisely when
`alpha<=s_max`. On that feasible range the minimum unconditional expected
producer query cost is

\[
\boxed{K(\alpha)=
\begin{cases}
0,&\alpha\le f,\\
\dfrac{\alpha-f}{p(1-f)},&f<\alpha\le s_{\max}.
\end{cases}}
\tag{2}
\]

**Lower bound for all policies.** Let `N` count fresh producer queries and
`Q` all paid producer queries. Just before each fresh answer, its conditional
mark probability is `p`, regardless of past answers and address selection.
The decision to make that query precedes its answer. Summing conditional
expectations up to the hard cap gives

\[
\mathbb E[\text{marked fresh queries}]=p\mathbb E[N]
 \le p\mathbb E[Q].
\]

Consequently the event `W` that any queried address is marked satisfies
`Pr(W)<=p E[Q]`. Conditional on a complete query transcript with no queried
winner, the unqueried coordinates remain independent Bernoulli marks. At most
`g` final guesses succeed with probability at most `f`. Therefore

\[
\Pr[\text{success}]\le f+(1-f)\Pr[W]
 \le f+p(1-f)\mathbb E[Q],
\tag{3}
\]

which proves (2)'s lower bound. Random stops, failed runs and zero-query runs
are included in these expectations; there is no conditioning on eventual success.

**Feasibility.** Append only for analysis the membership checks of the final
outputs. At most `min(d,n+m)=k+g` different addresses are inspected. Repeated
addresses add no new success. Padding to that many fresh observations gives
success probability `1-(1-p)^(k+g)`, so no adaptive policy exceeds `s_max`.
These appended checks prove this probability statement; they do not become
producer-paid resource.

**Attainment.** Reserve `g` addresses for final unchecked output. Query up to
`k` other fresh addresses, stopping at the first mark. If no queried mark is
found, output the reserved addresses. This paid mode has success `s_max` and
expected query count

\[
\sum_{j=0}^{k-1}(1-p)^j=\frac{1-(1-p)^k}{p}.
\]

The free-only mode outputs the `g` addresses and succeeds with probability
`f`; the abort mode has zero success and cost. If `alpha<=f`, mix free-only
with abort using probability `alpha/f` (take pure abort if `alpha=0`). If
`alpha>f`, choose paid mode with probability
`t=(alpha-f)/(s_max-f)` and free-only otherwise. Its success is exactly
`alpha` and its expected paid cost is exactly (2). When `f=0`, the second
mode can be abort. Every listed coin is oracle-independent.

The finite-domain reservation loses nothing: once at most `g` unqueried
addresses remain, outputting all of them without further paid queries cannot
reduce success and cannot increase cost. This explains why `k` can be smaller
than `n`. The construction establishes a minimum under the declared ideal
randomization rule; it is not an implementation of those coins under a deadline.

For `p=0`, only target zero is feasible. For `p=1`, any available free output
makes all targets feasible at zero cost; with no such output and at least one
available paid query, the minimum is `alpha`. If no address can be inspected
or output, only target zero is feasible. The implementation treats these
endpoints and `d=0` separately from the division in (2).

The **independent** mark law is essential. A finite table with exactly a fixed
number of marks is a different experiment: observing failures changes the
remaining density. Merely supplying a numerical density does not establish
the hypothesis used at each conditional-expectation step.

## 3. What one-half success at p=1/16 actually says

With no free unchecked output and enough data, (2) gives `E[Q]>=8`, attained
under a sufficient hard cap. The smallest feasible hard cap is eleven:

| Hard cap | Maximum success | Fixed target one half |
| --- | --- | --- |
| 10 | `522861237151/1099511627776`, about 0.475540 | Infeasible |
| 11 | `8942430185041/17592186044416`, about 0.508318 | Minimum expected paid cost 8 |

Running the eleven-query first-hit mode every time has mean about 8.133093.
Mixing it with abort gives exact mean 8 at success one half. Thus **eleven is
a cap threshold, not an expected-cost lower bound**. Ten available addresses
make the target infeasible even if the declared query cap is much larger.

Output-accounting changes the answer:

| Free unchecked outputs | Sufficient paid cap / available addresses | Minimum expected paid queries |
| --- | --- | --- |
| 0 | 11 / at least 11 | `8` |
| 1 | 10 / at least 11 | `112/15`, about 7.466667 |
| 11 | 0 / at least 11 | `0` |

The last row is an exact result in a deliberately generous oracle model,
not zero-cost W1 production. Constructing or moving complete real candidates
has not been priced by this model.

In particular [MU1's existing query reduction](MANDATORY_UNITS_RELATION_V1.md)
grants valid unit construction for free and uses final **virtual** membership
queries to extract successful outputs. If that relaxed experiment allows
eleven distinct complete terminal inputs without producer terminal feedback,
its producer-only terminal-query lower bound for this event is zero. The
zero-query success formula also already appears in the
[finite joint-state certificate](FINITE_JOINT_STATE_CERTIFICATE_V1.md).
Equations (1)--(3) identify the complete paid-query frontier around this case.
No positive arithmetic-work cost proportional to `u` follows from a relaxation
that makes all unit work free. This conclusion rejects that inference; it does
not exhibit an actual W1 algorithm with zero physical cost.

## 4. The necessary coverage and resource-transfer direction

Let every legal real strategy `A` admit a strategy `B_A` in a proved surrogate
game, with the same eligibility/deadline semantics or a justified relaxation,
such that uniformly over all permitted initial states and histories,

\[
\Pr[E_{B_A}]\ge\Pr[E_A]-\varepsilon,
\qquad \mathbb E[Q_{B_A}]\le a\mathbb E[C_A]+b,
\quad a>0,\ b\ge0,\ \varepsilon\ge0.
\tag{4}
\]

If the surrogate's fixed-success lower envelope is `L`, then

\[
\mathbb E[C_A]\ge
 \max\left\{0,\frac{L((\alpha-\varepsilon)_+)-b}{a}\right\}.
\tag{5}
\]

**Proof.** Its success guarantee forces `E[Q_B]>=L`; combine with (4).
If the surrogate success target is infeasible, no real strategy with that
target can satisfy all these simulation premises. Costs and probability
losses must use the same experiment, not a favorable conditioned subset.

This is why extraction overhead matters. When a proof appends `M` checks
not paid by the producer, their cost belongs in `b`, or they must remain free
outputs in `L`. The tested-output frontier `L(1/2)=8` with `b=11` yields only
zero in (5). Removing this overhead without a resource argument is invalid.

Conversely, optimizing a subset of strategies raises the infimum:
`inf_all cost <= inf_subset cost`. A finite menu of implementations is not
the required stronger surrogate. Even its upper-bound interpretation for
real work requires realizable policies, their full cost laws and the same
success event. A list of known shortcuts cannot prove coverage of all
algorithms. Correct execution proofs do not prove (4).

## 5. Hidden state and quantum costs remain separate obligations

The existing [FJS1 operator-domination theorem](FINITE_JOINT_STATE_CERTIFICATE_V1.md)
transfers a reference **hard-cap success** bound to a fully specified joint
initial state with loss `lambda B+epsilon`. This note does not rederive or
promote that result. Actual initial hidden state, nonuniform program advice,
retained quantum state, public help and earlier branch stock still require
complete coverage. A local memory limit or a new context label is insufficient.
FJS1's probability allowance does not directly bound an unbounded expected
resource discrepancy.

One elementary expectation conversion is available under an additional
stopping premise. Suppose `Q` is an observed, nonnegative integer query count,
and a legal truncation before query `q+1` preserves the probability law of
every complete history with `Q<=q`, including its success event. Let `B(q)` bound that truncated
strategy with the **same initial-state and output-accounting rules**. Then

\[
\Pr[E]\le B(q)+\Pr[Q\ge q+1]
 \le B(q)+\frac{\mathbb E[Q]}{q+1},
\qquad
\mathbb E[Q]\ge\sup_{q\in\mathbb Z_{\ge0}}(q+1)(\alpha-B(q))_+.
\tag{6}
\]

The first inequality splits off truncated histories; the second is Markov's
inequality. This conditional lemma permits retained quantum registers only
when the stated history-preserving truncation exists. It does not establish
that coherent variable-time or branch-weighted physical resource models have
that property. Substituting `E[Q]` into a quadratic hard-query success bound
is not a valid alternative. No quantum W1 cost row is filled by (6).

## 6. Verification and remaining work

Run from the repository root:

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_success_query_frontier.py' -v
python3 formal/pon-nakamoto-v1/fixed_success_query_frontier.py --check
```

The independent certificate verifier reconstructs the first-hit distribution
and the attaining mixture without calling the frontier constructor. Tiny
truth-table decision trees and exact lower convex hulls provide independent
finite controls. These check the implementation; the universal-policy lower
bound is the mathematical proof in Section 2, not a machine proof obtained
by extrapolating that finite enumeration. Reports keep `HOLD_NO_GO` and
`actual_w1_lower_bound=false` even when arithmetic verification succeeds.

The actual next gate is (4) for W1/MU1, including every allowed cached,
shared, low-rank, batched and preprocessed implementation, public assistance,
failed/unpublished work, old inventory, proof handling and recovery. It also
needs the actual initial-state law, eligible data and physical deadline.
The relation-source pins and observed native execution costs do not supply
these universal premises. All sixteen actual cost points therefore stay open.

Relevant primary research retains its own hypotheses:

- [Cojocaru et al., Quantum 7:944 (2023)](https://arxiv.org/abs/2012.15254v4)
  studies Bernoulli multi-solution quantum queries, not unavoidable W1 arithmetic.
- [Liu, EUROCRYPT 2023](https://arxiv.org/abs/2210.06693) and
  [Dong, Liu and Wu, CRYPTO 2024](https://arxiv.org/abs/2405.20281) treat
  preprocessing/advice and explicitly salted games. Parent/context digests
  alone do not establish their fresh-salt and advice hypotheses.
- [Komargodski and Weinstein, ESA 2026](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
  describes useful matrix work under an explicit hardness conjecture;
  it is not an unconditional lower bound for this W1 relation.
