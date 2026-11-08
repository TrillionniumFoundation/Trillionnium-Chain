# Finite lifecycle cost game and unpaid-credit potential, v1

Status: **implemented finite-model certificates and counterexamples; actual
W1 cheapest-legal-work qualification remains HOLD_NO_GO**.

[The implementation](lifecycle_cost_v1.py) uses exact rational arithmetic to
check every action of a declared finite classical Markov decision process
(MDP). It has a Bellman search, a separate certificate checker, initial-budget
refutations, positive-cycle and stationary-flow witnesses, and an exact
finite-horizon exponential tail bound. [The tests](test_lifecycle_cost_v1.py)
include deferred paid nonces, shared-result caching, withheld winners,
duplicate credit, restart, initial-state information and strategy expansion.

This is a new research namespace. It changes no native admission rule,
chainweight, payment, difficulty, signature domain or production qualification.
A proof of the Cell execution relation and a proof of this finite model do not
establish a lower bound against every legal implementation of that relation.

## 1. Scope and relation to the earlier nonce bank

The frozen [selected nonce-bank research at 09fbc0f4](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/09fbc0f45151a68a1bf205641171840fbf309882/formal/pon-nakamoto-v1/selected_nonce_bank_research/README.md)
already demonstrates a missing strategy: purchase selectors, retain the unused
nonce records, then reorder continuations to reuse one useful-result slot. Its
[theorem and counterexample](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/09fbc0f45151a68a1bf205641171840fbf309882/formal/pon-nakamoto-v1/selected_nonce_bank_research/THEOREMS.md)
separate an old online-class lower bound of `109.625` from a legal bank strategy
with expected cost `104.5`, at the same auxiliary success requirement `3/4`.

That relation is the complete original **selected local product8** relation.
It is not cumulative W1, a STARK relation or production Node admission. Its
finite independent-ticket theorem is not a theorem about the deterministic
concrete SHA outcomes measured in its separate native campaign.

This v1 package provides a general accounting checker and a smaller explicitly
priced lifecycle example. It does not import the earlier bank theorem as a
physical-cost premise. In particular, it does not assume that a cache contains
only completed results: the paid, not-yet-continued nonce selectors are separate
state with their own remaining credit value.

## 2. The state and cost contract

Let `S_t` be the complete state of the **declared model** before transition
`t`, and let `a_t` be any action selected from its permitted actions. Policies
may depend on the entire observed history and private randomness. The model
must make the next-outcome law conditional on that full history equal to its
declared `P(outcome | S_t, a_t)`. This is a substantive sufficiency assumption;
omitting hidden advice, a reusable algorithm or correlations can invalidate it.

Each outcome carries a nonnegative credit increment `r`, a nonnegative cost
increment `c`, and a next state. Every action carries a nonnegative predictable
deficit `eta`, fixed before that outcome. Define, from the start of this game,

\[
R_n=\sum_{t<n}r_t,\qquad C_n=\sum_{t<n}c_t,\qquad
A_n=\sum_{t<n}\eta_t.
\]

`R` counts credit only once under the independently specified work-identity
rule. Publication count, signature count and number of alternative encodings
are not credit. Already credited work cannot also remain as unused potential.
`C` is consumed resource, not a cash transfer: monetary refunds do not undo
work, and negative cost increments are rejected by this schema.

These credit-identity requirements are **semantic premises**, not facts
discovered by the general numeric checker. That checker verifies the supplied
inequalities and cannot recognize that two submitted reward labels mean the
same underlying work. The concrete bank encodes deduplication by `h -> r`
and gives duplicate publication reward zero. Its negative mutation test
rejects that particular incorrect potential; it is not a general proof that
every accepted numeric potential excludes all semantically redeemed credit.

The implementation accepts one declared scalar resource price. A real resource
vector may be mapped to it only through fixed, explicit weights and a justified
conversion. The game itself does not turn scalar multiplication counts,
compression counts, CPU time, GPU time, memory traffic, energy or financial
cost into interchangeable units.

The following premises must survive any model extension:

| State or cost component | Required treatment |
| --- | --- |
| Public model and inputs | Available initially; no fictitious per-attempt training charge |
| Private precomputation, compiled representations and caches | Included in state; paid creation or a bounded initial allowance |
| Deferred nonce and selector records | Retained independently of completed-result cache capacity |
| Shared work, batching and helper advice | Every allowed sharing strategy and its cost included; an atomic oracle is a restriction |
| Losing, aborted and unpublished attempts | Their consumed cost remains in `C`; stopping does not refund it |
| Parent, epoch, profile, version and restart | An actual transition with its old and new potential; no fresh initial allowance on every relabel |
| Public-help and off-device channels | An explicit provenance and resource premise, not an unverified assertion of absence |
| Quantum state | Requires a separate quantum experiment and reduction; not classical bank entries |

The analysis state need not be publicly observable. A potential table does not
attest a real attacker's private state or certify that an operator has declared
all of its machines, advice or retained data.

## 3. Exact potential certificate

Fix `kappa >= 0`, a nonnegative function `Phi : S -> Q`, an independently
specified initial law `mu_0`, and an initial expectation cap `B_0`. For every
state and every legal action the checker requires

\[
\sum_o P(o\mid s,a)
  \bigl[r(o)+\Phi(s'(o))-\kappa c(o)\bigr]
\leq \Phi(s)+\eta(s,a),
\tag{1}
\]

and separately checks

\[
\sum_s\mu_0(s)\Phi(s)\le B_0.
\tag{2}
\]

The caller supplies `expected_kappa` and `initial_budget_cap`; neither can be
silently increased by the submitted certificate. The game digest binds the
states, initial distribution, actions, transition probabilities, costs,
rewards, deficits and the description of the resource premise. All fractions
are canonical and checked exactly. There is no floating-point tolerance.

### Finite-horizon theorem

For every history-dependent randomized policy in this game and every stopping
time `tau <= N`,

\[
\mathbb E[R_\tau]+\mathbb E[\Phi(S_\tau)]
\leq \kappa\mathbb E[C_\tau]+\mathbb E[A_\tau]
     +\mathbb E[\Phi(S_0)],
\]

and therefore

\[
\mathbb E[R_\tau]
\leq \kappa\mathbb E[C_\tau]+\mathbb E[A_\tau]+B_0.
\tag{3}
\]

**Proof.** Condition on the full pre-outcome history, including the selected
action. Equation (1) says that
`R_t + Phi(S_t) - kappa*C_t - A_t` is a supermartingale. Randomized action
selection preserves the inequality by averaging. The state/action/outcome
spaces and horizon are finite, so all relevant random variables are
integrable. Multiply each conditional increment inequality by
`1{t < tau}`, then sum for `0 <= t < N`. This yields the first inequality;
nonnegative terminal potential and (2) yield (3).

This theorem does not silently extend to arbitrary unbounded stopping. Such
an extension must provide the appropriate integrability, domination,
uniform-integrability or nonnegative monotone-limit argument for its actual
cost/reward process. No unbounded-stop or infinite-lifetime release claim is
made by the executable checker.

### Why the initial cap and nonnegativity matter

Potential inequalities alone are invariant under adding a constant to every
state. Without (2), a large initial bank could be hidden by exactly that shift.
Without `Phi >= 0`, terminal negative potential could manufacture credit.
Both are rejected. A prehistory cost can instead be charged in one complete
lifetime `C`; it cannot be charged again and also sold as a fresh initial
allowance after a restart.

An expectation cap is not a pathwise cap. If an initial state contains eight
credits with probability `1/8` and no credit otherwise, `E[Phi_0]=1`, but the
initial potential can be eight. Selecting only that rare start changes the
initial law and is a different experiment. The tail check below retains the
full initial exponential moment.

If a miner may select or repeatedly redraw its initial state, that choice
and every redraw must be actions in the game with their actual cost, or the
initial condition must hold uniformly over the allowed initial-state set.
An average under one fixed `mu_0` cannot be reused for adversarially selected
starts.

`eta` is an accumulated credit deficit, not a disposable tolerance. Setting
`eta=1` permits one unit of otherwise unpaid credit per step. A real security
claim must bound the sum of all deficits; the checker reports the maximum
per-step deficit and the tail event explicitly subtracts the accumulated sum.

## 4. Bellman search and independently checked refusals

Write `g(o,a) = r(o) - kappa*c(o) - eta(a)`. With stopping allowed, start
`V_0=0` and compute exactly

\[
V_{n+1}(s)=\max\left\{0,\max_a
 \sum_o P(o\mid s,a)[g(o,a)+V_n(s'(o))]\right\}.
\tag{4}
\]

Backward induction makes `V_n` the greatest expected excess credit achievable
within at most `n` steps in the stated model. Any nonnegative certificate
satisfying (1) dominates every `V_n`. Three outcomes are distinguished:

| Search outcome | What the independent checker establishes |
| --- | --- |
| Exact stationary fixed point | Every action satisfies (1), and the initial cap satisfies (2) |
| Finite-horizon value exceeds `B_0` | A supplied nonstationary policy, replayed forward without Bellman maximization, has expected excess greater than `B_0` |
| Iteration limit reached | `INCONCLUSIVE`; no stationary certificate is emitted |

The second outcome refutes the requested bound in this model. It does not
merely show that one proposed potential was poor. The forward checker adds
the probability-weighted cost and reward on every branch, including failures
and branches that stop without a result.

There are feasible finite games where exact value iteration approaches a
fixed point forever without reaching it in finitely many steps. A geometric
test has `V_n=1-2^(-n)` and exact solution `Phi=1`; the search correctly remains
inconclusive at its cap while the independent checker accepts the separately
provided exact potential.

For arbitrary finite games, (1), (2) and `Phi >= 0` are rational linear
constraints. An external LP solver may propose a solution, but its floating
output is not accepted until a rational certificate passes these same checks.
This package is not a complete rational LP feasibility solver.

### Positive-cycle and stochastic-flow witnesses

For deterministic actions, a directed cycle with strictly positive
`sum(r-kappa*c-eta)` makes (1) impossible: summing its inequalities cancels
every potential. A bounded Bellman-Ford search produces such a witness, and a
separate checker verifies the edges, reachability and exact positive sum.
Finding no deterministic cycle says nothing about stochastic actions.

A supplied stochastic occupation measure `x(s,a) >= 0` is checked by

\[
\sum_{s,a}x(s,a)=1,\qquad
\sum_a x(s,a)=\sum_{u,a}x(u,a)P(s\mid u,a).
\]

If its weighted expected `g` is positive, multiplying (1) by these weights
and summing again gives a contradiction. The supported states must be
reachable with positive probability under the declared initial law. This
is a feasibility countercertificate. Its stationary net rate is **not** a
profit rate from the initial distribution: reaching that class may require
cost, time or a rare event, and no real implementation or market price is
certified here.

## 5. Concrete lifecycle example and strict strategy expansion

The example fixes two nonce identities, two selector coordinates, and one
reusable useful-result cache slot. Its state stores each nonce separately:

| Code | Meaning |
| --- | --- |
| `u` | Selector not yet purchased |
| `p0`, `p1` | Paid selector, awaiting continuation at the named coordinate |
| `h` | Complete winning result withheld from publication |
| `m` | Losing continuation or explicitly discarded unspent record |
| `r` | Credit already redeemed; no remaining reward |

Selector purchase costs one. Acquiring or replacing the useful result costs
two. A continuation costs one, independently hits with probability `1/4`,
and consumes that nonce's pending status on either outcome. A hit earns one
credit only when first published. The public model/input is initially free;
no training fee appears in these costs. All these are fixed **auxiliary oracle
prices and independent lottery laws**, not measured SHA or hardware facts.

The action set allows prepaying both selectors, delaying and reordering their
continuations, computing results before selector purchase, retaining/replacing
the single result cache, stopping, withholding/discarding results, restarting,
and changing a context label. Two labels denote the **same work namespace**;
the `r` records persist across both. A context-retirement action can destroy
unused potential and a cache but cannot revive credit already spent.

This example has 216 reachable states and 1,848 actions. At `kappa=1/8` and an
empty bank, exact Bellman iteration reaches a fixed point after five steps
with initial potential zero. A simpler independently checked upper potential
is

\[
\Phi_{\mathrm{simple}}(s)=
\#\{h\}+\tfrac18\#\{p0,p1\}.
\]

The Bellman certificate can be smaller when a missing useful-result cache
would itself require a new charge. A fully redeemed record contributes zero.

With two already-paid selectors for coordinate zero and a resident result,
the exact initial excess is `1/4`. Supplying a zero initial allowance produces
a checked counterpolicy. Supplying the explicit `1/4` allowance produces a
valid certificate. These outcomes account for prehistory; neither proves
where a real operator obtained that initial bank.

### A newly allowed cheap batch breaks the old bound

Extend that same warm-bank game with one legal action that continues both
nonces for a single cost unit, retaining the same independent ticket law.
Publishing both hits is allowed, each under its own unique nonce identity.

| Same fixed initial state and `kappa=1/8` | Best expected excess credit |
| --- | ---: |
| Two separately charged continuations | `1/4` |
| Shared two-nonce continuation charged once | `3/8` |
| Strict increase | `1/8` |

The report includes a full-action upper potential at `3/8` and a three-step
policy whose separately checked forward expectation is exactly `3/8`. Against
the old initial cap `1/4`, that policy has a strict gap of `1/8`. This is a
synthetic strategy-expansion counterexample, not a claim that such a native
batch algorithm has been implemented or measured.

An initial test incorrectly expected this one state-specific shortcut also
to violate a zero-cap **cold-start** bound after averaging over random
selectors. The solver returned a valid certificate for that different
experiment. The corrected regression fixes the already-selected warm state
and its old `1/4` cap, as required for the stated comparison. No action,
probability, price or verifier threshold was weakened to obtain a pass.

The restart mutation adds `r -> h` for free. Combined with first publication
it creates a deterministic cycle with one unpaid credit per traversal. The
checker returns the two exact edges and the strictly positive cycle sum;
no finite stationary potential can certify this mutated game.

These controls establish accounting behavior for their stated work
namespace. Distinct real parents, independently chosen models, profile
migrations and future work identities require an actual composition
relation; toggling a label is not a proof of that relation.

## 6. Exact finite-horizon tail bound

Expected excess alone is insufficient for a chain-security claim. This
package therefore checks one stronger finite-model property without calling
a first-moment bound an exponentially small tail.

Let `G_t=R_t-kappa*C_t-A_t` and choose a rational `q>1`, a positive integer
scale `d`, and a rational `rho>=1`. For every outcome define

\[
\Delta M=g(o,a)+\Phi(s')-\Phi(s).
\]

The checker requires integral exponents and verifies, for **every** action,

\[
\sum_o P(o\mid s,a)q^{d\Delta M}\le\rho.
\tag{5}
\]

It also checks the initial exponent domain, rather than validating only the
increments. The nonnegative process

\[
Z_t=\frac{q^{d(G_t+\Phi(S_t))}}{\rho^t}
\]

is then a supermartingale. For a declared finite horizon `N`, nonnegative
threshold `b` with integral `db`, and any adaptive policy,

\[
\Pr\{\exists t\le N:G_t\ge b\}
\le\min\left\{1,
\frac{\rho^N\,\mathbb E[q^{d\Phi(S_0)}]}{q^{db}}\right\}.
\tag{6}
\]

**Proof.** Equation (5) establishes the conditional supermartingale
inequality. At any crossing time `t<=N`, `Phi>=0` and `rho>=1` imply
`Z_t >= q^(db)/rho^N`. Apply the nonnegative-supermartingale maximal
inequality, or stop at the first crossing and use bounded optional stopping.
Its initial expectation is exactly the full initial exponential moment.

The implementation uses rational powers with integer exponents, not
floating-point exponentials or rounded probabilities. It refuses unsupported
scales/exponents and horizons. Current computational limits are 512 states,
64 actions per state, 64 outcomes per action, 512 Bellman iterations,
scale at most 1,000,000, exponent magnitude at most 4,096, and tail horizon
at most 1,024. These are tool bounds, not protocol security parameters.
The tail synthesizer checks the same initial-exponent limit as the verifier;
a constant shift with zero increments cannot produce an unusable certificate.

### Independent tail controls

For fair paid coin trials, take `r` equal to the win bit, unit cost,
`kappa=1/2`, `Phi=0`, `q=2`, `d=2`. The exact per-step moment is `rho=5/4`.
At horizon ten and excess threshold four, (6) gives

\[
\frac{9{,}765{,}625}{268{,}435{,}456}\approx 0.03638.
\]

Enumeration of all 1,024 outcome strings gives exact **any-time crossing**
probability `3/256`, below this bound. The event is crossing by time ten,
not merely the terminal number of wins. This is an independent finite test
of the formula; it is not a PoN attack probability.

The rare initial-bank control has `Phi_0=8` with probability `1/8`, zero
otherwise, and allows free redemption of that already owned bank. Its mean
is one, but (6) uses initial moment `263/8`, yielding `263/2048` for threshold
eight. Replacing that moment with `2^(E[Phi_0])` would incorrectly produce
`1/128`, below the real `1/8` event probability. That substitution is forbidden.

The finite tail game contains no honest chain, network delay, timestamp,
difficulty adjustment, receiver budget or private-fork adoption model. A
common-prefix or chain-quality theorem still needs their joint law and a
real-resource simulation argument. `native_chain_security_probability`
therefore remains `null` in every tail result.

## 7. Quantum and actual-work obligations remain separate

No quantum state is coerced into the finite classical nonce records. A
quantum extension must specify the joint initial classical/quantum state,
allowed coherent queries, advice and help channels, state preparation,
reversible depth, uncomputation, retained cross-round states, measurements,
and the extraction or simulation loss relating the actual work relation to
that quantum experiment. Classical atomic acquisition prices do not imply
quantum lower bounds.

For actual W1 or a future useful Cell relation, the unresolved obligations
include full allowed-strategy coverage, input/model/profile choice,
cross-instance sharing, truthful lifetime initial state and help accounting,
physical resource conversion, proof/execution composition, honest-progress
and fork-race tails, and sustainable real task supply. A public task's
economic utility and a model update's quality are independent of (1).
`NoUpdate` remains a possible service result and does not create consensus
credit in this model.

## 8. Reproduction

Read the repository's `AGENTS.md` and run the original preflight before edits
or builds. This module requires only the Python standard library.

```bash
bash scripts/project-preflight.sh
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_lifecycle_cost_v1.py -v
python3 -B formal/pon-nakamoto-v1/lifecycle_cost_v1.py --output /tmp/new-lifecycle-cost-v1.json
```

The output path must not already exist. The report includes complete
declared games and checkable witnesses for cold start, a prepaid warm bank,
strategy expansion, the restart-positive cycle and the finite tail control.
Results retain `HOLD_NO_GO`, a null actual W1 all-algorithm lower bound and
a null quantum lifecycle certificate. It does not rewrite earlier evidence.

## 9. Primary sources reviewed

- Di Wang, Jan Hoffmann and Thomas Reps,
  [Expected-Cost Analysis for Probabilistic Programs and Semantics-Level Adaption of Optional Stopping Theorems, arXiv:2103.16105v1](https://arxiv.org/abs/2103.16105v1),
  30 March 2021. This is background for expected-cost supermartingale and
  stopping conditions, not a theorem about the present work relation.
- Krishnendu Chatterjee, Amir Kafshdar Goharshady, Tobias Meggendorfer and
  Dorde Zikelic,
  [Quantitative Bounds on Resource Usage of Probabilistic Programs](https://doi.org/10.1145/3649824),
  OOPSLA 2024. Expected-cost analysis and tail-cost analysis have distinct
  obligations; a bibliographic mirror's later deposit date is not the paper's
  publication date.
- Steven R. Howard, Aaditya Ramdas, Jon McAuliffe and Jasjeet Sekhon,
  [Time-uniform Chernoff bounds via nonnegative supermartingales, arXiv:1808.03204v8](https://arxiv.org/abs/1808.03204v8),
  revised 17 December 2025. Equation (6) above is a directly proved finite
  rational instance of the nonnegative-supermartingale method, not an
  unverified use of stronger concentration parameters from that paper.
- Ilan Komargodski and Omri Weinstein,
  [Proofs of Useful Work from Arbitrary Matrix Multiplication, ESA 2026](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2),
  published 25 August 2026. Its optimal-security claim is a conjecture about
  correlated low-rank random linear systems, not an unconditional lower
  bound available for this project. The separate
  [ePrint 2025/685 record](https://eprint.iacr.org/2025/685)
  lists a latest revision of 8 December 2025 as reviewed on 8 November 2026;
  versions and model assumptions must not be silently interchanged.
- Juan A. Garay, Aggelos Kiayias and Nikos Leonardos,
  [The Bitcoin Backbone Protocol with Chains of Variable Difficulty](https://eprint.iacr.org/2016/1048),
  CRYPTO 2017, revised ePrint record 25 August 2019. Its computational and
  network assumptions illustrate why a cost account alone does not replace
  difficulty, honest-progress and ledger-security analysis.
