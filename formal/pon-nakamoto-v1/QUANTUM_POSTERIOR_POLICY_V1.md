# Exact finite posterior policies for a persistent marked domain

Status: conditional research calculation; whole-chain quantum qualification
remains **HOLD / NO-GO**. The
[single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
owns integration and promotion. This addition changes no native target,
timestamp, DAA, required-work score or activation rule.

The [policy calculator](quantum_posterior_policy.py) fills a specific gap beside
the existing [bounded renewal model](quantum_adversarial_search.py): it updates
the hidden marked-count distribution after failed measurements on a persistent
domain, and optimizes whether to retry or pay for a fresh domain under one
declared finite budget. The earlier renewal model correctly requires fresh
independent domains for its finite-domain throughput objective. Its existing
results and scope are unchanged.

## Conditional model and observable information

A domain has `N` items. The caller declares a normalized rational prior
`pi[m]` on its marked count `M`. A helper constructs a binomial prior under an
explicit independent uniform-ticket assumption. Neither that helper nor an
input probability proves the actual W1 marked-set distribution.

Every measured batch independently re-prepares a uniform state and applies a
selected number `q` of ideal Grover iterations. The fixed `P` processors share
the **same** domain and marked count; their measurement outcomes are independent
conditional on `M`. Only the Boolean batch success/failure is retained.
Candidate identities, information about individual failed positions, partial
measurements and residual coherent state are discarded. On success, one
declared proof-production cost is paid and the objective terminates. The model
assumes that this ideal success produces an acceptable proof at that cost;
it executes no real proof validator or delivery protocol. A paid
refresh produces a new independent domain with the original prior. The model
does not establish a W1-realizable mechanism for that refresh.

The controller knows the prior, costs and previous Boolean failures. It is
never handed the sampled `M`. In particular, a failure can make an empty domain
more likely; it does not justify silently resampling the original prior.

## Exact probabilities and budget recurrence

For a declared count `m`, let `x=m/N`. The implementation computes ideal Grover
probabilities by the rational recurrence starting at `a=b=1`:

\[
a'=(1-2x)a+2(1-x)b,\qquad b'=-2xa+(1-2x)b.
\]

After `q` iterations, the single-processor probability is `x*a*a` and the
batch probability is `s_q(m)=1-(1-x*a*a)^P`. This is the exact probability of
the specified circuit, including overshoot. It is not an upper bound for all
quantum algorithms. No trigonometric rounding enters the calculation.

For current belief `pi`, the successful-batch probability and failed-batch
posterior are

\[
s_q(\pi)=\sum_m\pi_m s_q(m),\qquad
\pi'_m=\frac{\pi_m(1-s_q(m))}{1-s_q(\pi)}.
\]

When the denominator is zero, failure is impossible and no posterior is
invented. Averaging over `M` happens **after** combining the processors; replacing
the shared count with independent unconditional probabilities is incorrect.

All costs use one caller-declared additive resource unit. A batch costs

\[
C_q=P(c_{\mathrm{prepare}}+q c_{\mathrm{iteration}}+
      c_{\mathrm{readout}}+c_{\mathrm{check}}).
\]

Zero-iteration batches still pay preparation, readout and candidate checks.
Failures pay the same batch cost. Domain setup `S` is paid initially and on
each refresh. Proof cost `H` is paid once on success, never on a failed batch.
These are resource charges for all processors, not parallel wall-clock time.

For remaining budget `b`, the Bellman value is the maximum of stopping at zero,
every affordable measurement action,

\[
s_q(\pi)+(1-s_q(\pi))V(b-C_q,\pi'),\quad C_q+H\le b,
\]

and, when refresh is enabled and affordable, `V(b-S,pi_initial)`. An action
that cannot leave enough budget for a successful proof cannot deliver later by
spending more, so stopping dominates it. Failed batches retain the unspent proof
allowance. Refreshing an unchanged belief with a positive setup cost is weakly
dominated and omitted.

Each continuation strictly decreases the integer budget. Induction therefore
gives the exact maximum over this finite action/information model; randomized
mixing among the enumerated actions cannot improve their maximum. Probability
ties minimize expected resource spent, then prefer the earlier sorted iteration
choice to refresh. If delivery has zero probability, stopping avoids even the
initial setup cost. Explicit domain, iteration, processor, budget, state-count
and rational-bit limits fail closed without a partial optimum report.

This optimality statement excludes general coherent algorithms, variable-time
search, identity-aware rejection, arbitrary iteration choices, quantum side
information, network interruption and adaptive DAA/clock strategies. Constructed
oracle resource upper bounds never become attacker cost lower bounds here.

## Exact finite observations

For `N=4`, independent ticket prior `p=1/4`, one processor and `q=1`, the
first-batch success probability is `17/32`. After a failure the posterior over
`M=0,1,2,3,4` is

\[
(27/40,\ 0,\ 9/40,\ 1/10,\ 0).
\]

Repeating `q=1` then succeeds with probability `9/80`. A new zero-iteration
measurement succeeds with probability `3/16` and uses one fewer oracle
iteration. Two `q=1` batches on the same domain have total success `299/512`;
refreshing to an independent domain between the batches gives `799/1024`,
before accounting for its additional setup cost. The distinction follows from
conditioning on one persistent `M`, not from a measured W1 advantage.

The CLI example declares setup `2`, preparation `1`, each iteration `1`, readout
`1`, candidate checking `1`, winner proof `2`, one processor, iteration choices
`0,1,2`, and total budget `20`:

| Permitted policy class | Optimal all-failures path | Delivery probability | Expected resource spent |
| --- | --- | --- | --- |
| Persistent domain, refresh disabled | `q1`, then four `q0` batches | `11089/16384` | `97735/8192` |
| Paid refresh enabled | `q1`, refresh, `q1`, refresh, `q1` | `29393/32768` | `195377/16384` |

Every successful branch includes proof cost and fits the same budget. The report
retains the complete chosen failure path, conditional probabilities, posterior
at each step, charged costs, reach probabilities and terminal stop. The
single-domain existence ceiling `1-pi[0]` is explicitly scoped to paths without
refresh; it is not presented as a bound on the refreshed search or real W1.

## Reproduction and independent controls

From the repository root:

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_posterior_policy.py -v
python3 formal/pon-nakamoto-v1/quantum_posterior_policy.py --example > /tmp/quantum-posterior-report.json
python3 formal/pon-nakamoto-v1/quantum_posterior_policy.py --example --verify /tmp/quantum-posterior-report.json
python3 formal/pon-nakamoto-v1/quantum_posterior_policy.py --example --require-qualified
```

The last command returns `3` with `REFUSED_UNPROVED_NATIVE_QUANTUM_SECURITY`
after successfully calculating the research report. It does not report a
malformed calculation as a qualification refusal. Invalid requests, state/size
limits and altered reports return `2`.

The [independent controls](test_quantum_posterior_policy.py) explicitly enumerate
all small marked predicates and their full amplitude vectors. A separate
exhaustive solver retains probabilities on entire bitsets and enumerates every
affordable failure schedule, including the dominated refresh choices omitted by
the production solver. Other controls reconstruct chosen-path costs, compare
persistent and refreshed domains, cover zero queries and zero solutions, verify
proof-budget boundaries, and reject probability/policy/source/scope and JSON
type substitutions. Exact source-bound execution results belong in the
successor's evidence record; this note does not transfer historical tests to it.

The report hashes this research module only. That hash is a read source
identity, not execution authentication, native build closure or a full
repository snapshot. Full input/report replay, duplicate-key rejection and
canonical JSON comparison preserve bool/integer distinctions.
Input uses a nonblocking descriptor followed by a regular-file check, so a FIFO
cannot block before type rejection. Symlinks are refused on the supported
no-follow platforms. Reader and generated-report byte limits are explicit.

## Primary sources and transfer limits

- [Zalka, *Grover's quantum searching algorithm is optimal*, published version,
  arXiv:quant-ph/9711070v2](https://arxiv.org/abs/quant-ph/9711070v2): unstructured
  query-model optimality and parallelism do not establish the minimum physical
  cost of the structured W1 predicate.
- [Ambainis, Kokainis and Vihrovs, *Improved Algorithm and Lower Bound for Variable
  Time Quantum Search*, TQC 2023](https://doi.org/10.4230/LIPIcs.TQC.2023.7):
  variable item-check costs define a distinct algorithmic problem. This finite
  fixed-cost batch policy does not cover those algorithms.
- [Cojocaru et al., *Quantum Multi-Solution Bernoulli Search with Applications to
  Bitcoin's Post-Quantum Security*, Quantum 7:944, 2023](https://quantum-journal.org/papers/q-2023-03-09-944/):
  the fixed-density chain-search/backbone model needs further reductions before
  it can support W1 resource or native variable-difficulty claims.
- [Bailey and Sattath, *51% Attack via Difficulty Increase with a Small Quantum
  Miner*, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2): difficulty,
  timestamps and cumulative work matter jointly. Its ideal Grover assumptions
  and this finite search calculation do not establish a native W1 attack,
  defense, hardware calibration or lifetime security bound.

All hardware, actual W1 probability, full-oracle cost, all-algorithm optimum,
work lower-bound, joint-consensus security and whole-chain qualification flags
remain false. The existing reversible W1 construction is not denied or
reclassified by these per-calculation scope flags.
