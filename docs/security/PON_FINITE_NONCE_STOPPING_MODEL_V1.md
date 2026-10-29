# Conditional finite-nonce stopping and interruption model v1

This research increment adds an executable finite-domain search race to the
existing [conditional DAA experiment](PQ_NATIVE_TRANSFER_AND_QUANTUM_DAA_V1.md).
It does not change the PoN work relation, target/chainwork arithmetic, production
DAA, fork choice or activation. It produces neither valid W1 tickets nor a
measured quantum mining rate. The old `r=0.25` assumption remains uncalibrated.

The implementation is [quantum_stopping.py](../../formal/pon-nakamoto-v1/quantum_stopping.py),
with [independent controls](../../formal/pon-nakamoto-v1/test_quantum_stopping.py)
and [local execution evidence](../../evidence/pon-finite-nonce-stopping-20261027/README.md).
The existing logical oracle and native DAA files remain byte-identical to base
`5d16aafee014fe7a06a0ed76b9aaa06b6058c5d0`.

## 1. Source-backed assumptions

[Boyer, Brassard, Hoyer and Tapp, sections 3–4](https://arxiv.org/html/quant-ph/9605034v1)
give the finite-marked-set success probability and explain why measuring before
the near-certain-success iteration count can reduce expected restart cost. This
model conditions on the actual marked count; it does not implement their
unknown-count search policy or quantum counting.

[Bailey and Sattath](https://arxiv.org/html/2403.08023v2) study the mismatch between
linear chainwork weight and square-root quantum search cost during difficulty
increases. Their introductory model explicitly ignores search constants and
success randomness, and treats one quantum miner. Our earlier synthetic DAA
experiment remains a conditional reproduction of that structure. This separate
race calculation does not establish its whole-chain attack probability.

[Gallager, Poisson processes, sections 2.2–2.3](https://www.rle.mit.edu/rgallager/documents/Poisson.pdf)
supplies the independent exponential waiting-time and independent-process
aggregation rules. They apply here only because the model expressly assumes
independent constant-rate external arrivals. Other quantum miners need their own
stopping distributions; a Poisson approximation is not silently imposed on them.

[Gallager, renewal processes, theorem 4.4.1](https://ocw.mit.edu/courses/6-262-discrete-stochastic-processes-spring-2011/931ffa0940899c27f34b71ad64fd2bb0_MIT6_262S11_chap04.pdf)
supports the expected-reward/expected-cycle-time interpretation only for
independent identically reset contexts with finite mean duration. The bounded
budget output is labelled a campaign ratio, rather than a steady-state share.

[Lee, Ray and Santha](https://arxiv.org/abs/1809.03671v2) explain the strategic
role of measurement times and simultaneous successes in quantum races. Our small
enumerator evaluates declared fixed policies with an explicit research tie rule;
it neither implements their equilibrium algorithm nor claims an equilibrium.

## 2. The complete cost interface

Let a fixed context have a nonce domain of size `N=2**n`, `1 <= n <= 64`, and an
explicit actual marked count `0 <= M <= N`. The ideal probability after `j`
Grover iterations is

\[
  p_j=\sin^2((2j+1)\theta),\qquad \sin^2\theta=M/N.
\]

`M/N` is not replaced with the target's ideal hash probability. Knowing `M` is
an assumption; obtaining it has not been costed. For example, only under
independent Bernoulli marking does a target probability `2**-64` on a 64-bit
domain give empty-domain probability approximately `exp(-1)=0.36787944`.
The model makes no such independence claim about actual W1 tickets.

Each policy uses four positive/nonnegative timing inputs:

| Input | What it charges |
| --- | --- |
| `oracle_and_diffusion_seconds > 0` | One complete clean W1 phase oracle, including its adjoint, plus diffusion |
| `measure_check_restart_seconds > 0` | Every measurement, classical outcome check, and repeated preparation |
| `context_setup_seconds >= 0` | The initial setup on every new context, even if interrupted |
| `winning_witness_publication_seconds >= 0` | Successful witness/proof/admission/propagation tail before winning |

The model requires positive per-attempt checking even at `j=0`; a classical
sample is not a free valid ticket. The published examples assume respectively
`0.01, 0.01, 0.02, 0.03` seconds. These are illustrative inputs, not hardware
observations or values derived from gate counts. Zero setup/tail inputs in
endpoint tests are idealized analytical controls only.

Failed measurements are fully reset and may repeat the same nonce. They do not
learn an excluded subset or shorten the nonce domain. Therefore the number of
attempts can exceed `N`; `M=0` is permanently empty. Adaptive scheduling,
amplitude retention, failed-nonce exclusion, last-minute measurement on a tip,
hardware parallelism, and network propagation races remain outside the model.
Abandoning a context immediately on an external tip is a policy assumption, not
an optimality theorem.

## 3. Derived single-worker calculation

For fixed `j`, set `p=p_j`, setup `c`, per-attempt time `s>0`, and winning tail
`v>=0`. Conditional on the fixed predicate and independent repeated measurement,

\[
 K\sim\mathrm{Geom}(p),\quad D=c+Ks+v,\quad T\sim\mathrm{Exp}(\lambda),
\]

where `T` is independent of `K`. `D` means completed delivery, so an external
tip during a successful measurement's remaining witness/publication tail still
prevents winning. For finite hard budget `B`, write

\[
 k_B=\max(0,\lfloor(B-c-v)/s\rfloor),\quad
 d_1=c+s+v,\quad a=(1-p)e^{-\lambda s}.
\]

Summing the geometric completion distribution gives

\[
 P_{\rm win}=p e^{-\lambda d_1}\sum_{k=0}^{k_B-1} a^k.
\]

For no budget the sum is infinite. Expected elapsed context time is derived
separately from the survival function:

\[
 E=\int_0^B e^{-\lambda t}P(D>t)\,dt.
\]

Define `J(t)=(1-exp(-lambda*t))/lambda`, with `J(t)=t` at `lambda=0`. Up to the
first possible completed delivery, the contribution is `J(min(B,d1))`. If
`B>d1`, let `B-d1=L*s+r`, `0<=r<s`; the remaining contribution is

\[
 e^{-\lambda d_1}(1-p)\left[J(s)\sum_{k=0}^{L-1}a^k+a^LJ(r)\right].
\]

The independent external-tip hazard yields `P_external=lambda*E`, while
`P_budget=exp(-lambda*B)*(1-p)**k_B`. Completion exactly at `B` counts as
completion. An unbounded empty domain with no external tips has no termination;
the JSON returns an explicit nontermination probability and `null` expected
time. With no external tips and `p>0`, `E=c+s/p+v`.

The implementation uses logarithms and `expm1` for geometric tails. Budget
ordering uses `Fraction` representations of the exact supplied binary64 times,
with no permissive epsilon. Thus input float `0.3` is earlier than three exact
input float `0.1` periods. Probabilities and integrals are binary64 numerical
evaluations, not certified interval or symbolic results.

The numerical API accepts only minority-angle phases
`(2*j+1)*asin(sqrt(min(M,N-M)/N)) <= 64` radians, apart from exact empty/full
endpoints. All larger phases are explicitly rejected, for every marked fraction.
This conservative range retains the declared first-peak search and bounded
small-domain controls. Complementing alone does not repair accumulated angle
error: `N=2,M=1,j=2**52-1` naively gives `0.0741385878` although the exact
probability is `0.5`; even `j=2**40` gives `0.5001790422`. These actual review
counterexamples remain regression controls, alongside nonsymmetric large phases.

## 4. Multiple fixed-stop workers

For up to four workers, each `D_i=c_i+Geom(p_i)*s_i+v_i` is sampled independently
conditional on the specified fixed marked sets and non-entangled initial states.
Sharing a deterministic oracle does not itself correlate independent measurements.
Mixing over a common unknown random `M` generally would correlate them; this
implementation does not perform that mixture.

The enumerator merges all exact completion times through `B`, enumerates every
simultaneous success subset, and integrates elapsed time between events.
Simultaneous successful workers share the winning probability uniformly. This
research tie rule is not the native network's settlement or fork-choice rule.
All due completions at `B` are processed before budget expiry. The default
10,000 completion-opportunity ceiling is enforced by explicit rejection, with
no silently truncated trajectory.

The example with policies `(6,12)`, the stated illustrative timings, budget
`2` seconds and external rate `0.1/s` yields win probabilities about
`(0.52134313, 0.46393635)`. Both workers stopping at `12` instead yields
simultaneous success probability about `0.98205701`. These observations expose
policy/tie sensitivity; they do not identify an optimal quantum mining strategy.

## 5. Difficulty versus variable-work scenarios

The report exhaustively enumerates integer stopping counts from zero through
the declared first peak, on finite `N=2**24`, baseline `M=65536`. It chooses the
best reward/time ratio among those counts. This is a bounded policy comparison,
not the cheapest legal oracle or a global stopping optimum.

Three counterfactual candidates use relative weight `m`:

| Candidate | Actual `M` assumption | Complete phase-oracle time | Setup, check and winning tail |
| --- | --- | --- | --- |
| Decrease marked fraction | `65536/m` | Unchanged | Unchanged |
| Fixed fraction, linear oracle | `65536` | Multiplied by `m` | Each multiplied by `m` |
| Fixed fraction, square-root oracle | `65536` | Multiplied by `sqrt(m)` | Each multiplied by `m` |

All are research cost laws, not changes to the original PoN difficulty rules.
The report emits 45 rows covering `m=1,4,16,64,256` and external tip rates
`0,0.1,1/s`. Representative relative-weight rates per assumed second are:

| External tip rate | Multiplier | Decrease marked fraction | Fixed fraction, linear | Fixed fraction, square-root |
| --- | --- | --- | --- | --- |
| `0` | `1` | `6.017291` | `6.017291` | `6.017291` |
| `0` | `16` | `32.160752` | `6.017291` | `11.438229` |
| `0` | `256` | `140.475952` | `6.017291` | `14.886686` |
| `0.1/s` | `256` | `129.993533` | `0.728882` | `5.596267` |
| `1/s` | `256` | `68.758723` | `0.000000231` | `0.000011697` |

These model outputs distinguish the assumptions. If every mandatory cost scales
linearly and there are no interruptions, multiplying weight by the same factor
does not increase the weighted rate. Sublinear complete-oracle cost can restore
an advantage, although linearly growing setup/check/tail costs limit it. Long
fixed-work completion times are heavily discounted by interruptions; that can
reduce an attacker's weighted rate while also reducing honest service. Neither
observation is a chain-quality proof or a recommendation to activate a DAA.

A retained negative control scales only the oracle and leaves classical checking
fixed. At `m=256`, it chooses `j=0`, receiving growing weight while paying the
same classical sample cost. This is an invalid shortcut in a purported
mandatory-work scaling argument. The main comparison therefore charges all
non-oracle stages explicitly. The negative control remains in the report.

At the baseline domain, increasing assumed interruption rate from `0` to
`10/s` changes the selected first-peak policy from `9` to `7` iterations.
The corresponding conditional rates change from `6.017291` to `2.662672/s`.
No such timing was measured on a quantum computer.

## 6. Validation and limitations

Eighteen new controls include 1,139 small-domain dense state-vector comparisons,
5,000 independent geometric-distribution enumerations, 120 independent
2–4-worker tuple enumerations, exact budget neighbors, empty domains, zero
external rate, classical competition, and nonzero winning-tail interruption.
They also retain these numerical counterexamples:

* For `N=2**64, M=N-1, j=2**31`, the naive angle loses the unmarked item and
  reports approximately `1`; complementary-angle evaluation gives
  `0.2919265815`, independently checked with 80-digit Decimal series.
* For `p=2**-64` and `2**64` attempts, naive `(1-p)**K` becomes `1` instead of
  approximately `0.36787944`. The logarithmic calculation retains the tail.

The original eleven reversible-template/adjoint controls and seven native DAA
controls were rerun. The latter compiled the actual pinned Rust consensus
source and compared 1,079 requests; it was not skipped. Both original JSON
reports reproduced the prior #510 CI artifact byte for byte.

The full-W1 source audit retains 4,096 noise-compactor calls, 512 ordered prefix
tiles, 327,680 MACs, 49,152 field reductions and 3,076 SHA compressions. The
[logical blueprint](PON_W1_LOGICAL_CIRCUIT_BLUEPRINT_V1.md) still reports
2,748,849,006 Toffoli gates for the retain-all clean phase oracle, or
5,497,698,012 for the specified compute/copy/uncompute alternative, with its
separate diffusion cost. These are construction upper bounds; no complete
billion-gate expansion, global wiring proof, physical error correction cost,
lowest-cost oracle, hardware rate or quantum security conclusion follows.

This local source checkout inherits sparse historical evidence. Full repository
and tracked-worktree identity guards must retain any actual refusal; selected
file hashes and passing model tests are not a full repository qualification.
The research CI is extended to run the existing native parity, new controls and
new report on a future exact source. No remote run or deployment is claimed.

## Independent numerical-boundary correction

The classical Poisson baseline previously accepted finite positive rates whose
unbounded expected time exceeded binary64. For example, own rate `1e-310/s`
with no competitor returned infinite expected time, an infinite own-win value
and a NaN competing-win value. Such values are not valid probabilities. It now
refuses an unrepresentable positive expected time with the same
`EXPECTED_TIME_NUMERIC_RANGE` error as the quantum campaign. An overflowing sum
of finite competing rates is explicitly refused as `TOTAL_RATE`.

This does not ban tiny rates: a finite budget can make the expected time
representable. The new bounded-rate control compares the integral and both win
probabilities with a 90-digit Decimal calculation. The original failure and
final 39 passing controls, including the actual pinned Rust DAA arithmetic,
are retained in the [boundary evidence](../../evidence/pon-finite-rate-boundary-20261028/README.md).
The fixed scenario report is unchanged apart from its source hash. Original
schema names, all declared timing assumptions, complete W1/DAA semantics and
the unqualified physical-resource/security status remain unchanged.

## Separate outcome tails and peak correction (v2 numerical report)

The continuation on the exact research source
`0682274361e529cd6a8e13285324c3c9ee0744b8` fixes two further finite-domain
counterexamples. For `N=2**64, M=N-1, j=0`, the success probability rounds to
one in binary64, while the failed tail is exactly `2**-64`. Previously the
known-M single-worker budget and multiple-worker race reconstructed failure as
`1-success` and incorrectly erased both budget expiry and a later worker's
chance to win. The separate unknown-M implementation already retained both
tails; its source and policy are unchanged.

Computing both sine and cosine from the same rounded angle would not close the
second defect. With `M=3*N/4 +/- 1` and one Grover iteration, the old success
projection returned approximately `2.5860584564e-32`. The independent identity
`p1=p*(3-4*p)**2`, with exact `p=M/N`, gives approximately
`3.5264830525e-38`. Near the complementary quarter-domain peak, the equally
small failed tail must also survive. Exact quarter-domain zero tails must
remain zero.

The corrected evaluator uses `x=1-2*M/N` and binary doubling of the Chebyshev
polynomial `T_(2*j+1)(x)`. It computes success `(1-T)/2` and failure `(1+T)/2`
at 80 decimal digits, then rounds each tail separately. This requires only
`O(log(j+1))` arithmetic steps and retains the existing 64-radian minority-angle
domain guard. It is a numerical evaluation, without a certified interval bound
or a quantum hardware claim. `grover_success` remains the compatible scalar
projection; `search_stop` carries both tails into elapsed-time, budget and
worker-race calculations. Direct `FixedStop(p, ...)` callers retain their
existing interface, with an optional separately supplied failure tail whose
rounded sum must agree with one.

The stored finite-stopping report uses the new namespace
`pon-finite-nonce-stopping-conditional-model-v2`. Five added methods check the
actual dense-domain loss, a later worker's nonzero chance, the independent exact
one-iteration cubic, agreement with the retained sequential unknown-M
recurrence, and invalid explicit tails. The original 21 stopping methods are
retained, including state-vector comparisons, geometric-path enumeration,
budget boundaries, full-cost work scaling and large-phase refusal. The W1
relation, complete logical oracle cost, native integer DAA, policy budgets and
production flags are unchanged.
