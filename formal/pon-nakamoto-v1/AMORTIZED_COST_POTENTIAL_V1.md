# AC1: synthesized additive lifecycle cost potentials

Status: exact finite-model research; **HOLD for actual W1 minimum cost, quantum
resource cost, native consensus qualification, and confirmation risk**.

This component addresses a different question from the existing
[exponential state-potential certificate](STATEFUL_RESOURCE_TAIL_V1.md): given
one frozen credit schedule, one resource price, and a finite menu of lifecycle
transitions, **does any common additive potential exist at all?** It synthesizes
one or returns an exact algebraic contradiction. It does not repeat the 6,156
checks of the previous hand-written exponential inventory potential.

Implementation: [amortized_cost_potential.py](amortized_cost_potential.py).
Controls: [test_amortized_cost_potential.py](test_amortized_cost_potential.py).
Independent finite-model oracles and adversarial input regressions:
[test_amortized_cost_potential_independent.py](test_amortized_cost_potential_independent.py).

## 1. Frozen contract and accounting convention

The input fixes positive credit weights `w[u]`, a nonnegative rational resource
price `kappa`, and the complete action menu **of the declared finite model**.
Synthesis cannot quietly reduce the weights, increase the resource price, or
introduce unbounded error allowances to make a failing contract pass. Choosing
an allowed maximum price and an honest-progress requirement remains part of the
larger [work-scale security contract](WORK_SCALE_SECURITY_CONTRACT_V1.md).

Each outcome contains an exact probability, successor state, nonnegative
resource cost, counts of newly credited objects at each work scale, and an
optional finite error-allowance debit. Its reward is

\[
 r_o=\sum_u n_{o,u}w(u).
\]

`R` counts one declared extraction event for each distinct eligible identity.
Storage, repeated delivery, measurement-window changes, and stopping do not
credit that identity again. A stored, uncredited candidate may have positive
potential; that potential is **not itself an extra reward**. Immediate stopping
has payoff zero in the independent dynamic program. There is no terminal
inventory payment added to `R`.

A finite abstract graph does not independently prove real identity uniqueness.
For an actual relation, the state refinement must establish deduplication or
map every abstract reward to a new identity. The
[MU1 identity implication](MANDATORY_UNITS_RELATION_V1.md) is relevant to such a
mapping, but MU1's in-memory counter is not a native consensus spent set. A
profitable duplicate-credit loop can be rejected by this cost checker; the
absence of such a detected loop is not a cryptographic anti-replay proof.

A state must retain every feature that changes the laws of future actions:
cache contents, remaining candidates, legal work scales, parent/profile
constraints, prior advice, and remaining allowance. A state name or owner log
does not authenticate that this representation covers an adversary's private
state. The existing [observability boundary](CERTIFICATE_OBSERVABILITY_V1.md)
continues to apply. All declared states must be graph-reachable from a declared
initial state; unreachable failures are refused as malformed model input.

## 2. Additive Bellman certificate

For each state `s`, action `a`, and outcome `o`, require

\[
 \sum_o P(o\mid s,a)
 \bigl[r_o+\Phi(s_o)-\Phi(s)-\kappa c_o-\eta_o\bigr]\le0,
 \qquad \Phi(s)\ge0.                                      \tag{1}
\]

Each allowed initial state additionally has an explicit bound

\[
 \Phi(s_0)\le B_0(s_0).                                   \tag{2}
\]

Thus a cold state may be required to have zero potential. A start carrying
previously paid preparation needs an adequate nonzero initial budget, or the
original preparation transitions must be included before that start. Public
models and public intermediate results are free side information unless a
separate reduction actually justifies charging them to the adversary.

### 2.1 The finite eta ledger

Every state has a rational nonnegative balance `ell(s)`. Every outcome must obey

\[
 \ell(s_o)+\eta_o=\ell(s),\qquad \eta_o\ge0.                \tag{3}
\]

Consequently the cumulative allowance `A_n = sum eta_o` is at most the initial
balance on every path. The executable checker rejects a restart that refills
the balance, a missing debit, and a negative debit. A protocol version label
cannot issue a new allowance for the same retained lifecycle. A predictable
allowance in the user's original inequality is the special case in which its
value is already fixed before the outcome; outcome-dependent debits here are
charged inside the conditional expectation.

An allowance is an explicit addition to the final credit bound. It is not
proof of paid work. The demonstration with one zero-resource credit of weight
4 requires initial allowance 4 and consumes it permanently.

### 2.2 Composition and stopping

Suppose the finite-state abstraction correctly represents every permitted
history-adaptive action in the asserted model. For the natural measured
filtration, (1) makes

\[
 X_n=R_n+\Phi(S_n)-\kappa C_n-A_n
\]

a supermartingale whenever the finite-time expectations exist. Randomizing
between certified actions preserves (1) by linearity. For every bounded
stopping time `tau`, summation and conditional expectation give

\[
 \mathbb E[R_\tau+\Phi(S_\tau)]
 \le B_0+\kappa\mathbb E[C_\tau]+\mathbb E[A_\tau].          \tag{4}
\]

For an unbounded stopping time, apply (4) first to `tau min N`. If cumulative
resource and credit are nonnegative, `E[C_tau]` is finite, and the initial
budgets are finite, monotone convergence for the cumulative accounts and
Fatou's lemma yield

\[
 \mathbb E[R_\tau]\le B_0+\kappa\mathbb E[C_\tau]+\ell(s_0).
                                                               \tag{5}
\]

Here `R_tau` at an infinite stopping time means the monotone limit. This
one-sided bound does not need a claim that an arbitrary signed stopped process
is uniformly integrable. If expected cost is infinite, (5) provides no finite
security guarantee. Retaining the final potential in an unbounded-stop formula
requires its appropriate limiting or integrability condition.

This is an expectation theorem. It supplies neither an exponential attack
tail nor a native common-prefix theorem. The existing stateful exponential
certificate and native fork-event mapping remain separate obligations.

### 2.3 A reset has to be an action

A zero-cost, zero-reward transition `s -> t` requires `Phi(t) <= Phi(s)`.
If two labels describe the same retained information and both relabelings are
free, their potentials must agree. Losing real information can lower potential.
Renaming a retained cache as a cold state while silently omitting its future
redemption action is an invalid abstraction, not a successful reset proof.

## 3. Exact synthesis and exact rejection

For `n` states, (1), nonnegativity, and (2) form a rational linear feasibility
problem

\[
 A\phi\ge b.                                               \tag{6}
\]

The action row has coefficient `+1` at its source, subtracts each successor
probability, and has right side `E[r-kappa*c-eta]`.

### 3.1 Strict input shape and unambiguous row identity

Python type annotations are not runtime validation. A one-shot iterator used
as an action, outcome, or credit container could previously be consumed by a
validation pass, making the later constraint builder omit its contents. In
particular, a positive-credit zero-cost loop could be misreported as feasible.
The checker now rejects malformed shape **before traversing such a container**:

- Model maps and certificate maps must be exact built-in `dict` values.
- Per-state actions, action outcomes, outcome credits, and each two-item credit
  record must be exact `tuple` values. Generators and list substitutes are
  rejected without consumption.
- Model, action, and outcome elements must be the exact declared record types;
  names must be exact nonempty `str`, scale/count fields exact integers, and
  rational values exact `Fraction`. Booleans and custom subclasses cannot
  silently supply another meaning for these fields.

The rejection applies again to an already exhausted iterator; it cannot become
a valid empty declaration on the next verification call. The regressions invoke
both synthesis and verification on the same malformed positive-credit loop and
check that the refused iterator remains unconsumed.

Constraint identities use the kind followed by a canonical JSON array of their
name components. Thus `action:["a","b:c"]` and `action:["a:b","c"]` are distinct.
The earlier concatenation `action:{state}:{name}` aliased these two rows and
could invalidate a synthesized dual witness. `constraint_label` checks kind,
arity, and exact string components; old ambiguous labels are not accepted as
aliases. Separate row identities are retained in every dual receipt.

The implementation enumerates bases of `n` active constraints and solves them
using exact rational Gaussian elimination. Every candidate is independently
checked against **all** original inequalities. On exhaustive enumeration it
minimizes `sum Phi`; the positive objective and nonnegative orthant ensure an
attained vertex optimum whenever the feasible set is nonempty.

For completeness of the interpretation, let

\[
 V_0(s)=0,\quad
 V_{h+1}(s)=\max\!\left(0,\max_a
       \mathbb E[r-\kappa c-\eta+V_h(S')]\right).             \tag{7}
\]

The first term is immediate stopping. `V_h` is the best expected excess credit
under arbitrary adaptive policies stopping within `h` actions. Every feasible
potential dominates every `V_h`, by induction. Therefore the increasing limit
is finite whenever a feasible potential exists. Finiteness of the action menu
allows the limit through the finite maxima and sums, making that limit a
feasible Bellman potential. It is pointwise least. Minimizing `sum Phi` selects
this least potential, including any compatible initial caps.

This interpretation does not turn finite-horizon nonconvergence into
infeasibility. One included model has
`V_h(cache) = 1 - (3/4)^h`: no finite iteration equals its exact potential 1,
yet exact synthesis succeeds.

### 3.2 Farkas certificate

An infeasibility result is returned only with rational multipliers satisfying

\[
 \lambda\ge0,\qquad \lambda^T A=0,\qquad \lambda^T b>0.       \tag{8}
\]

The separate `verify_dual` function checks all three conditions exactly.
Multiplying (6) by `lambda` would give `0 >= lambda^T b > 0`, a contradiction.
The search normalizes the final scalar to 1; a minimal-support witness uses at
most `n+1` independent columns. This permits a finite basis search of the dual
as well.

If only action rows have positive multipliers, their coefficients describe a
stationary state-action occupation flow. The potential terms cancel and the
flow earns strictly more expected credit than its priced cost and allowance.
Such a witness exposes a lifecycle defect. If initial-cap or nonnegativity rows
participate, the witness is instead labeled `budget_or_state_constraint`;
it must not be presented as a repeatable profitable physical cycle.

The `max_basis_checks` cap bounds work of the synthesis algorithm. An exhausted
budget without a certificate returns `unknown`. A verified feasible potential
found before exhaustive enumeration may be returned, but it is not labeled
least. Floating-point tolerances and solver status strings are not trusted.
This enumerator is intended for small finite state spaces; no polynomial-time
scalability claim is made.

## 4. New finite countermodels

These are explicit counterfactual action models, **not implemented MU1 attacks**.
The numerical demonstration uses `p=1/4`, weights `w(1)=4`, `w(4)=16`, and a
single priced resource. MU1 has different frozen lottery constants. The state
choices and cache conversions below require an actual legality/reachability
argument before being transferred to a required-u native protocol.

### 4.1 Separately sound scales can fail together

Preparing an untested `u=1` candidate costs `3/4`; checking it costs `1/4` and
credits 4 with probability `1/4`. Preparing a `u=4` candidate costs `15/4`;
checking it costs `1/4` and credits 16 with the same probability. A check consumes
the candidate on either outcome and returns to the empty state.

Each scale in isolation has expected credit equal to cost at `kappa=1`.
The common potentials are

| State | Potential |
| --- | ---: |
| Empty | 0 |
| Untested u=1 candidate | 3/4 |
| Untested u=4 candidate | 15/4 |

Now allow an additional paid conversion from the small untested candidate to
the large one. A conversion cost of 3 is consistent with these potentials.
A conversion cost of 1 is not: it would require `15/4 - 3/4 <= 1`.

The executable strict witness is a cycle of three **positive-cost** actions:
prepare the small candidate, convert it, check the large candidate. Its total
resource is `3/4 + 1 + 1/4 = 2`; expected credit is 4. The net excess is 2 per
cycle. Every potential cancels on return to the empty state. This is not a
zero-cost duplicate and does not select a winner before completing the work.
All probability assumptions remain fixed at `1/4`.

At `kappa=2`, the same frozen weights become compatible with this declared
menu. The synthesized small and large cache potentials become `3/2` and `7/2`.
That is a changed resource-to-credit contract, not proof that the original
`kappa=1` claim held. With even `kappa=1999/1000`, the checker still produces an
exact infeasibility certificate.

### 4.2 Batch preparation must be priced on the shared lifecycle

The model also prepares a pair containing one small and one large untested
candidate. Two checks cost `1/2` in total. Their independent outcomes have
probabilities `9/16, 3/16, 3/16, 1/16`, with rewards `0, 4, 16, 20`.
Expected total credit is 5. The action menu includes checking both together or
checking either first and retaining the other candidate; adaptive order is
covered by the same potential.

A pair setup cost of `9/2` permits pair potential `9/2` at `kappa=1`. A setup
cost of `5/2` creates a paid cycle with total cost 3 and expected credit 5.
The exact compatible price boundary for that isolated batch discount is
`kappa=5/3`. These examples count two distinct eligible outputs across the
whole research menu. They do not claim that two siblings both contribute to
one adopted chain. A one-winner-per-parent model must explicitly invalidate or
retain the other candidate according to its actual semantics.

### 4.3 Failed attempts can retain useful preparation

A separate, genuinely stochastic-state model pays setup cost 1. Each subsequent
attempt succeeds with probability `1/4`, credits 4, and consumes the cache on
success; a failure retains the cache. With marginal attempt cost `3/4`, the
expected cost per completed cycle is `1 + 4*(3/4) = 4`, and the exact cache
potential is 1.

With marginal attempt cost `1/2`, the expected cycle cost falls to 3. A strict
occupation witness uses multiplier 1 for the setup row and multiplier 4 for
the attempt row. State flows cancel exactly and the net expected excess is 1.
This general stochastic witness cannot be recovered by treating each possible
outcome as an independently selectable deterministic edge.

## 5. Relation to quantum and subset strategies

Fixed Bernoulli density does not force an implementation to prepare uniformly
over the full advertised search domain. Brassard, Hoyer, Mosca and Tapp's
[amplitude-amplification construction](https://arxiv.org/abs/quant-ph/0005055)
amplifies a general measurement-free preparation algorithm, including useful
heuristics, and uses that preparation and its inverse. A subset-search cost
row must therefore count the actual preparation, inverse, predicate,
uncomputation, failed measured attempts, and accepted-output construction for
that subset. The source establishes a search algorithm; it does not establish
a lower bound on Cell work.

Ambainis's [variable-time search result](https://doi.org/10.4230/LIPIcs.STACS.2008.1333)
gives the optimal known-evaluation-time dependence
`O(sqrt(sum_i t_i^2))` in its query model. It does not justify charging
`max_i(t_i)` for every item. The [2023 follow-up](https://arxiv.org/abs/2302.06749)
separately studies the setting where individual times are unknown. Neither
result converts nominal dense FLOPs into actual reversible gate cost.

A completed quantum strategy with a rigorously established resource/outcome
law can falsify a proposed contract by supplying one of the allowed actions.
Covering selected quantum strategies still does not cover every quantum
strategy. Arbitrary residual quantum states require a sound abstraction or an
operator certificate; their full contents cannot simply be placed in a
classical sigma-algebra.

For clarity, a sufficient additive operator analogue uses positive operators
`L_h >= 0` and instrument branches `E_o`:

\[
 \sum_o E_o^*\!\left(L_{h_o}+
       (r_o-\kappa c_o-\eta_o)I\right)\preceq L_h.            \tag{9}
\]

Taking the trace against the conditional joint state proves the conditional
mean inequality. This note does not construct those operators for MU1 or W1.
The prior exponential operator contract remains the stronger tail obligation.
The new scalar synthesizer is a necessary audit layer for a proposed finite
classical abstraction, not a substitute for either quantum refinement or
all-algorithm completeness.

## 6. Reproduction and qualification boundary

From the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 formal/pon-nakamoto-v1/amortized_cost_potential.py --compact
```

The tests check synthesized potentials against independently derived values,
finite adaptive-policy DP, positive-cost regenerative cycles, a stochastic
occupation witness, initial budgets, finite eta consumption, exact rational
boundaries, reward accounting at stopping, tampered certificates, and explicit
unknown outcomes under a search budget. An initial local test invocation found
two test-fixture parenthesis errors, corrected before the first 22-test run.
Independent adversarial review then exposed the iterator omission, delimiter
collision, and permissive model-name type. These input-soundness defects were
corrected with the strict shape checks and row encoding above; the failed
observations are retained here rather than treated as passing evidence.

The current local suite contains 34 methods. Together with six independent
methods, **40 tests pass**. Two independent methods compare 1,600 deterministic
models to a complete integer-potential grid and 2,025 stochastic models to an
exact two-state difference interval, checking both feasibility and the least
potential. The other four independently reproduce the entry-point defects and
check a typed positive-credit-loop contradiction. These 3,625 cross-model
comparisons do not use the synthesizer's basis enumeration as their oracle and
do not establish that the finite state spaces include actual W1 algorithms.

Every machine-readable result retains these false fields:

- `all_algorithm_cost_qualified`
- `quantum_cost_qualified`
- `native_consensus_qualified`
- `tail_qualified`

A passing certificate establishes an additive cost bound for the declared
finite action graph. It does not establish that actual SHA-256 is a random
oracle, that real preprocessing and public help were completely observed,
that the graph includes every legal batch/cache/subset strategy, that u can
be selected freely on a native fork, or that a given confirmation depth is
secure. Those are explicit remaining premises of the original cost contract.
