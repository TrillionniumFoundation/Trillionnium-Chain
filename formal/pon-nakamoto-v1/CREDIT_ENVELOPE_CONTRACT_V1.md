# Public credit under classical and quantum cost envelopes

Date: 2026-11-08, UTC.

Status: **conditional mathematical component; actual W1 and consensus
qualification remain HOLD**. The development starting point was
`b66e66d2465258d808c0f56ff851123306d4bdb4`. That identifier is not the final
integration or publication pin. Retained validation must identify its actual
tested source after integration; results from different candidate revisions
must not be combined into an untested release claim.

Implementation: [exact envelope solver](credit_envelope_contract.py),
[independent certificate and adversarial tests](test_credit_envelope_contract.py),
[normalized search and complete-cost arithmetic](normalized_search_cost.py),
and [search-cost tests](test_normalized_search_cost.py).

This contract extends the existing
[work-scale security contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b66e66d2465258d808c0f56ff851123306d4bdb4/formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md) and
[residual-state resource-to-weight contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b66e66d2465258d808c0f56ff851123306d4bdb4/formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md).
It supplies a finite feasibility decision and mathematical certificates. It
does not implement a new native lottery, target, chainweight, confirmation
rule, checkpoint, miner-class attestation, activation, or deployment. The
repository's [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the sole plan.

The two preceding contracts are referenced at their immutable published research
commit; they are not present in integration base `8d5389748873dad6e296d17f2ff20483b5afa5bc`.
This component does not import that separate pending branch or certify its execution.

## 1. Objects, success standard, and the direction of the evidence

Let `chi` be classical or quantum, let `u` be a legal work scale, and let
`Theta` fix the resource and device model. A scalar cost requires an explicit
unit or an explicit conversion of a resource vector. Oracle queries, logical
gates, depth, qubits, memory-time, joules, money and elapsed seconds cannot be
silently substituted for one another. More hardware can reduce elapsed time
without reducing total operations.

First fix a success contract `S`: for example, producing a distinct fully
valid claim with probability at least a fixed `eta`, with a specified initial
state, deadline and acceptance event. Define

\[
c_\chi(u;\Theta,S)
=\inf_{A\in\mathcal A_\chi:\,A\text{ meets }S}
  \mathbb E[C_A].
\tag{1}
\]

The expectation is unconditional: costs of failed, abandoned, cancelled,
unpublished and restarted attempts remain charged. A strategy that simply
abandons the task does not meet `S`. Alternatively one may define an
eventual-success renewal contract, but its stationary restart premises and
success event must be stated. These two conventions are not interchangeable
without a reduction. Every cost compared in one feasibility instance uses
the same success contract and resource convention.

Throughout the pointwise theorems assume

\[
0<L_{\chi,i}\le c_\chi(u_i;\Theta,S)\le U_{\chi,i}<\infty.
\tag{2}
\]

An implemented algorithm can establish an upper bound `U` for its declared
model. Measurements of several algorithms do not establish `L` against every
allowed algorithm. A supplied lower-bound number is a mathematical premise,
not an experimental observation that this component can authenticate. The
same applies to the declared initial state and the completeness of the legal
strategy class.

The competitive scope includes every history and parameter choice that can
still compete under the claimed protocol. A per-epoch clamp, a new anchor,
a restart, or a version change does not prove that old private histories or
retained state have ceased to matter. A finite list is a complete competitive
scope only if another argument establishes that fact. The implementation
checks matching scope labels; it does not authenticate that argument or
interpolate between supplied scales.

Pointwise efficiency below means `s(u)/c_chi(u)` under this common success
standard. It is not a block-arrival rate, adversarial resource share or
confirmation-risk bound.

## 2. Exact neutrality: the necessary and sufficient condition

Write `c_C(u)` and `c_Q(u)` for fixed, positive exact cost functions on the
entire competitive set `U`. A public credit `s(u)>0` is scale-neutral for
each class if there are constants `k_C,k_Q>0` such that

\[
\frac{s(u)}{c_C(u)}=k_C,
\qquad
\frac{s(u)}{c_Q(u)}=k_Q
\quad\text{for every }u\in\mathcal U.
\tag{3}
\]

**Theorem 1.** Such a public credit exists if and only if
`c_Q(u)/c_C(u)` is constant on the entire competitive set.

**Proof.** Dividing the two equalities in (3) gives
`c_Q(u)/c_C(u)=k_C/k_Q`, proving necessity. If that ratio is a constant `r`,
choose `s(u)=c_C(u)`. Then the two efficiencies are `1` and `1/r`, proving
sufficiency. The argument also works for unattained infima in (1), provided
the resulting cost numbers are positive and finite. QED.

This theorem does not require equal efficiencies between the two classes.
Different constants remain. At any common scale and for every positive
public credit,

\[
\frac{s(u)/c_Q(u)}{s(u)/c_C(u)}=\frac{c_C(u)}{c_Q(u)}.
\tag{4}
\]

Changing the common credit cannot change this same-scale relative efficiency.
Giving different credit to a self-declared miner class is not this model;
such a proposal would need a separate enforceable classification and trust
contract.

## 3. Exact-cost minimax compromise

For a positive credit define its cross-scale spread within each class by

\[
R_\chi(s)=
\frac{\sup_{u\in\mathcal U}s(u)/c_\chi(u)}
     {\inf_{u\in\mathcal U}s(u)/c_\chi(u)}.
\tag{5}
\]

Let `r(u)=c_Q(u)/c_C(u)` and assume
`0<inf r <= sup r < infinity`. Put `B=(sup r)/(inf r)`.

**Theorem 2.** Among all positive real public credits,

\[
\inf_s\max\{R_C(s),R_Q(s)\}=\sqrt B.
\tag{6}
\]

The geometric-mean credit `s(u)=sqrt(c_C(u)c_Q(u))` attains this value.

**Proof.** Let `x=log s`, `a=log c_C`, `b=log c_Q`, and write
`osc(f)=sup f-inf f`. The oscillation triangle inequality gives

\[
\log B=\operatorname{osc}(b-a)
\le\operatorname{osc}(x-a)+\operatorname{osc}(x-b)
\le2\max_\chi\log R_\chi(s).
\]

This proves the lower bound. With `x=(a+b)/2`, the two oscillations are both
`(log B)/2`, proving attainability. QED.

More generally, spreads bounded by separately specified
`rho_C,rho_Q >= 1` are simultaneously attainable exactly when

\[
\rho_C\rho_Q\ge B.
\tag{7}
\]

Necessity follows from the same triangle inequality. For sufficiency choose
`s=c_C^(1-t)c_Q^t` with `0<=t<=1`,
`t log B <= log rho_C` and `(1-t) log B <= log rho_Q`. Such a `t` exists
precisely under (7); `B=1` is immediate.

### 3.1 Difficulty and work-scale examples

In the deliberately idealized exact-cost model
`c_C(D)=a_C D`, `c_Q(D)=a_Q sqrt(D)`, with one common competitive range
`D in [D_min,D_max]` and `K=D_max/D_min`, the ratio range is `B=sqrt(K)`.
The smallest worst within-class spread is therefore `K^(1/4)`, attained by
`s(D)` proportional to `D^(3/4)`.

This is a compromise for metric (5), **not a proposal or proof of a secure
fork-choice repair**. The same-scale relative efficiency in (4) still varies
as `sqrt(D)`. Attack feasibility also depends on reaching a difficulty,
timestamps, privately retained work, network effects and resource limits.

Similarly, for exact costs `c_C(u)=a_C u`, `c_Q(u)=a_Q u^alpha`,
`alpha<=1`, and a whole competitive range ratio `K_u`, the minimum worst
spread is `K_u^((1-alpha)/2)` and a minimizing credit is proportional to
`u^((1+alpha)/2)`. A constant ticket probability has not established
`alpha=1` or the completeness of either cost law.

Applying one strictly increasing function, such as a square root, to a
whole exact cumulative score preserves the ordering of chains. Applying it
to every block before summing generally changes the ordering. Integer
rounding can create ties, so even the first observation needs separate
analysis when the actual transformation is not strictly increasing.

## 4. Weak robust calibration over rectangular cost uncertainty

For finitely many scales `i=1,...,n`, regard each exact cost vector as unknown
within the declared rectangle

\[
\mathcal K_\chi=\prod_{i=1}^n[L_{\chi,i},U_{\chi,i}].
\]

For a fixed `rho>=1`, the implemented robust requirement is

\[
\exists s_i>0\quad
\forall\chi,\ \forall c_\chi\in\mathcal K_\chi:\quad
\frac{\max_i s_i/c_{\chi,i}}
     {\min_i s_i/c_{\chi,i}}\le\rho.
\tag{8}
\]

Call this *weak robust calibration* to distinguish it from Section 6. It is
robust against every cost vector in the rectangle; "weak" refers only to
allowing the normalization of a class's efficiency to depend on its realized
cost vector. The credit itself is fixed before the unknown costs are chosen.

**Theorem 3.** Requirement (8) is equivalent to all of the inequalities

\[
\boxed{\frac{s_i}{s_j}\le
\rho\frac{L_{\chi,i}}{U_{\chi,j}}}
\quad\text{for every }\chi\text{ and }i\ne j.
\tag{9}
\]

**Proof.** Necessity follows by choosing the allowed vector with
`c_chi,i=L_chi,i` and `c_chi,j=U_chi,j`. These two coordinates can be chosen
independently because `i!=j` and the uncertainty set is rectangular.
For sufficiency, any allowed vector satisfies

\[
\frac{s_i/c_{\chi,i}}{s_j/c_{\chi,j}}
\le\frac{s_i}{s_j}\frac{U_{\chi,j}}{L_{\chi,i}}
\le\rho.
\]

Every pairwise efficiency ratio is bounded, so their maximum is bounded.
QED.

### 4.1 The same-scale exception is essential

At `i=j` the actual cost cancels and the efficiency ratio is exactly one.
It is incorrect to replace that same cost by `L_i` in one occurrence and
`U_i` in the other. No self-edge is introduced.

Consequently a one-scale instance passes (8) with `rho=1` even if its cost
interval is wide. This result certifies only a vacuous cross-scale
comparison; it does not certify a precise cost or a useful resource bound.

### 4.2 Joint uncertainty can be narrower than a rectangle

For a separately justified joint set `K`, define

\[
\beta_{\chi,ij}=\sup_{c\in\mathcal K}
                    \frac{c_{\chi,j}}{c_{\chi,i}}.
\]

The exact robust replacement of (9) is `s_i/s_j <= rho/beta_chi,ij`.
The rectangular interface uses `beta_chi,ij=U_chi,j/L_chi,i` for distinct
scales and can therefore be conservative when shared uncertainty is known.

For example, if
`c_C=k_C(1,16)` and `c_Q=k_Q(1,4)`, with each common multiplier in `[1,2]`,
the minimum worst spread is two: the multipliers cancel within each class.
Forgetting that coupling gives the larger rectangle
`L_C=(1,16), U_C=(2,32), L_Q=(1,4), U_Q=(2,8)`, whose minimum robust spread
is four.

An infeasible rectangular certificate means that no fixed credit works for
every cost vector in that declared rectangle. It does not prove that the
single unknown physical cost vector has no suitable credit. Different edges
of an infeasibility certificate may attain their worst cases at different
cost vectors: this is legitimate because the same fixed credit must satisfy
all the universally quantified constraints in (8).

## 5. Exact graph certificate and minimax threshold

For every class and ordered pair `i!=j`, make an edge from `j` to `i` with
positive rational weight

\[
w(j,i,\chi)=\rho L_{\chi,i}/U_{\chi,j}.
\tag{10}
\]

The edge means `s_i <= w(j,i,chi) s_j`.

**Theorem 4.** Positive credits satisfying every edge exist if and only if
every directed cycle has edge-weight product at least one. For rational
inputs and rational `rho`, a feasible instance has a positive rational
credit witness.

**Proof.** Multiplying the credit inequalities around any cycle cancels every
credit and gives `1 <= product(w)`. This proves necessity and the validity
of a product-below-one refusal certificate.

For sufficiency, introduce a virtual source with unit-weight edges to all
vertices. If no cycle has product below one, deleting cycles from any walk
never increases its product. A minimum-product path can therefore be chosen
simple. There are finitely many such paths, and all have positive products.
Let `d_i` be their minimum product to vertex `i`. Extending a path by an edge
gives `d_i <= w(j,i,chi)d_j`. Thus `s_i=d_i` satisfies every constraint.
Finite products and minima of positive rational numbers remain positive
rational numbers. Dividing all credits by the first credit normalizes it
to one without changing any inequality. QED.

The implementation performs synchronous multiplicative Bellman--Ford
relaxations using `Fraction`. After round `k`, each stored path has at most
`k` edges. A strict improvement at round `n` must contain a closed subwalk
with product below one: otherwise deleting its cycles gives a path of at
most `n-1` edges with no larger product, contradicting the previous round's
minimum. Keeping the actual path avoids combining predecessor pointers from
different relaxation times. The independent witness verifier reconstructs
the original inequalities or cycle edges from the declared intervals.

For a candidate credit, the exact worst spread is

\[
\max\left\{1,
\max_{i\ne j}\frac{s_iU_{\chi,j}}{s_jL_{\chi,i}}\right\}.
\tag{11}
\]

The explicit `1` covers the same-scale ratio, including a one-scale instance.

### 5.1 Characterization of the optimal robust tolerance

For the rectangular problem, the smallest real tolerance is

\[
\rho_*=
\max\left\{1,
\max_{\gamma}
\left[
\prod_{(j\to i,\chi)\in\gamma}
\frac{U_{\chi,j}}{L_{\chi,i}}
\right]^{1/|\gamma|}\right\}.
\tag{12}
\]

It suffices to take simple cycles; a closed walk decomposes into cycles and
cannot have a larger log mean than all its component cycles. Equation (12)
follows immediately from requiring `rho^|gamma|` times the cycle's
unscaled edge product to be at least one. With no cycles, `rho_*=1`.

The shipped interface decides a supplied rational `rho`; it does not return
an unverified floating-point optimum. A later search can bracket (12) with
rational tolerances, retaining an infeasibility cycle at the lower endpoint
and a feasible credit at the upper endpoint. An algebraic irrational optimum
must not be reported as an exact rational answer.

### 5.2 Two-scale boundary fixture

For the exact costs at scale identifiers `(1,16)`

\[
c_C=(1,16),\qquad c_Q=(1,4),
\]

Theorem 2 gives `rho_*=2`, with normalized credit `(1,8)`. At `rho=3/2`,
the classical edge `16 -> 1` has weight `3/32`, and the quantum edge
`1 -> 16` has weight `6`. Their product is `9/16<1`, an exact refusal.
At `rho=2` the same cycle has product one and both class spreads are two.
The numerical scale identifiers in a fixture do not establish a physical
cost law between untested scales.

### 5.3 Three-scale refusal that all two-scale cycle checks miss

Use `rho=2` and the following cost rectangle:

| Scale identifier | Classical lower | Classical upper | Quantum lower | Quantum upper |
| --- | ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 3 | 3 |
| 2 | 1 | 3 | 4 | 4 |
| 3 | 4 | 4 | 4 | 8 |

After taking the tightest class edge in each direction, the three two-edge
cycle products are `4/3`, `4/3`, and `1`. All pass. But the cycle

\[
1\xrightarrow[Q]{8/3}3
 \xrightarrow[C]{1/2}2
 \xrightarrow[C]{2/3}1
\]

has product `8/9<1`. The full instance is infeasible. In this example all
edge weights are proportional to `rho`; the other oriented three-cycle is
weaker, and (12) gives `rho_*=cuberoot(9)>2`. Checking only pairs of scales
would miss the obstruction.

## 6. Strong robust calibration is a different quantifier order

One can demand class normalization constants fixed across all possible cost
vectors:

\[
\exists s_i>0,\ k_C,k_Q>0\quad
\forall c,\chi,i:\qquad
k_\chi\le s_i/c_{\chi,i}\le\rho k_\chi.
\tag{13}
\]

Call (13) *strong robust calibration*. It is equivalent to

\[
k_\chi U_{\chi,i}\le s_i\le
\rho k_\chi L_{\chi,i}.
\tag{14}
\]

In (8), the equivalent normalization constant may depend on the realized
cost vector; in (13), it may not. This distinction is substantive even for
one scale. Strong calibration requires `rho>=U_chi,i/L_chi,i`, whereas
the implemented weak condition correctly has no such self-comparison.

For two classes define

\[
W=\max_{\chi,i}\frac{U_{\chi,i}}{L_{\chi,i}},\qquad
A=\max_i\frac{U_{C,i}}{L_{Q,i}},\qquad
B=\min_i\frac{L_{C,i}}{U_{Q,i}}.
\]

The minimum strong tolerance is

\[
\rho_{\rm strong}=\max\{W,\sqrt{A/B}\}.
\tag{15}
\]

**Proof.** Normalize `k_C=1` and write `t=k_Q/k_C`. At every scale the
two intervals in (14) overlap exactly when the within-class widths are at
most `rho` and `U_C,i/(rho L_Q,i) <= t <= rho L_C,i/U_Q,i`.
A common `t` exists exactly when `A/rho <= rho B`; these conditions give
(15). Choosing each credit from its nonempty intersection proves
sufficiency. QED.

Equation (15) is explanatory mathematics, not the semantics of the shipped
weak-robust solver. The two meanings must not share an unlabeled verdict.

## 7. Rational certificates and native integer credits

For the finite rational constraints at a supplied rational `rho`, Theorem 4
provides rational credits. Multiplying all credits by the least common
multiple of their denominators gives positive integer credits with exactly
the same ratios. This mathematical fact does not ensure that the resulting
integers or accumulated chainweights fit the native representation.

A bounded integer implementation needs a separately specified maximum
credit, accumulation range, overflow behavior and canonical encoding. These
cannot be inferred from the rational research witness. Native target
rounding, including the existing inclusive-target convention, also remains
part of the actual cost and credit relation in the work-scale contract.

If credits are rounded with multiplicative error `e_i=s'_i/s_i` and
`0<e_min<=e_i<=e_max`, then

\[
R_\chi(s')\le(e_{\max}/e_{\min})R_\chi(s).
\tag{16}
\]

This follows by multiplying each pairwise efficiency ratio by `e_i/e_j`.
In particular, relative errors bounded by `epsilon<1` can enlarge the
spread by `(1+epsilon)/(1-epsilon)`. A credit rounded to zero is invalid.
The exact verifier should check the intended integer schedule rather than
assuming that this upper bound leaves sufficient slack.

Even rational exact costs can have an irrational optimal tolerance and
require irrational credit ratios at that optimum. With `c_C=(1,2)` and
`c_Q=(1,1)`, the optimum is `sqrt(2)` and its unique normalized second credit
is `sqrt(2)`. No finite integer ratio attains it exactly. Rational schedules
can approach it with slack, but fixed bit limits impose their own feasibility
question.

The research implementation bounds input counts and integer sizes and
refuses unsupported inputs. Its finite limits are resource controls for an
auditor, not a proof that all native competitive scales have been supplied.

## 8. Pointwise calibration does not compose across winners or states

The previous work-scale contract already gives a multi-winner reusable-setup
countermodel. The following version also makes the cross-scale issue clear.
Suppose a common preprocessing step costs `M>0`, and each subsequent fresh
task of scale `u` costs `u`. A task evaluated alone from a cold start has
exact cost `M+u` in both classes. Credit `s(u)=M+u` is perfectly neutral
under Theorem 1 and passes a degenerate-envelope pointwise test.

After preprocessing once, `m` distinct scale-one successes cost `M+m` but
receive total credit `m(M+1)`. Their efficiency is

\[
\frac{m(M+1)}{M+m}\longrightarrow M+1.
\tag{17}
\]

Thus a correct cold-start bound is not an additive bound for a campaign.
Fresh challenge salts do not themselves erase model preprocessing, generic
indices or reusable coherent information. This is an abstract countermodel,
not a demonstrated W1 attack.

### 8.1 A first-moment composition interface

Let `H_t` be the measured classical history and `sigma_t` the complete
conditional retained state, including relevant private quantum registers
and correlated side information. A possible sufficient interface is a
nonnegative potential `Phi_chi(sigma)` such that every allowed action obeys

\[
\mathbb E[\Delta S_t+
 \Phi_\chi(\sigma_{t+1})-\Phi_\chi(\sigma_t)\mid H_t]
\le r_\chi\,\mathbb E[\Delta C_t\mid H_t].
\tag{18}
\]

For integrable finite horizons, summing (18) gives

\[
\mathbb E[S_T]\le
r_\chi\mathbb E[C_T]+\mathbb E[\Phi_\chi(\sigma_0)],
\tag{19}
\]

where initial incremental credit and cost are zero and the nonnegative
terminal potential was dropped. A random stopping time requires its own
boundedness or optional-stopping justification. Preprocessing is either
charged when performed or carried in a justified initial potential; it must
not be omitted or charged twice. Restarting an observation window does not
set the actual potential to zero.

Equation (18) is a proof obligation against the complete allowed action
class. Defining a potential by an optimal-control supremum does not show it
is finite, compute it, or prove it applies to W1. A repeated cheap action
that restores its accounting state while earning excessive credit can
preclude any finite valid potential.

### 8.2 The existing tail interface is stronger and remains necessary

A first-moment envelope does not supply a common-prefix failure probability.
The linked residual-state contract already uses a conditional joint density
operator, a measured classical filtration and positive progress operators
`K_h>=I`. For every permitted quantum instrument `{E_o}`, its sufficient
condition is

\[
\sum_o e^{\theta w_o-\kappa\cdot r_o}
 E_o^*(K_{h_o})\preceq K_h.
\tag{20}
\]

That contract derives the resource-to-new-credit anytime tail from a
nonnegative supermartingale and retains the actual initial potential. The
pointwise graph solver neither proves (20) nor replaces its complete action
coverage, resource-price model, ideal/real coupling or public-help accounting.
Quantum registers must not be treated as fully observed classical random
variables in `H_t`.

The same convention must determine when a credit is first counted. Counting
new extraction and later release of the same claim twice is invalid. If
credit is counted at release, hidden completed inventory and coherent
progress must remain in the potential. Unique eligible claim identities,
unpublished successes, all failed attempts and all surviving private
branches belong to the lifecycle model.

## 9. Search phases, normalized probability and accepted total credit

The separate [normalized search component](normalized_search_cost.py)
provides finite distribution, complete search-unit and stationary renewal
arithmetic. Its assumed costs and stationarity premises are not measured
quantum circuits or all-strategy lower bounds.

If the baseline distribution is `mu`, its successful set is `G`, and
`p0=mu(G)`, a retained subset `S` has domain mass `r=mu(S)` and retained
successful fraction `w=mu(G intersect S)/p0`. Direct conditional preparation
on `S` gives `p'=w p0/r`, so the success ratio is `f=w/r`. Keeping the
original sampling distribution and rejecting candidates outside `S` instead
gives `f=w`. A statement that one quarter of candidates or winners was
retained does not, by itself, determine the normalized success probability.

In the applicable ideal search model the shortcut factors are `a_C/f` and
`a_Q/sqrt(f)`. Thus a shortcut can be classically unprofitable but quantumly
profitable when `a_C>=f` and `a_Q^2<f`. The arithmetic example
`f=1/4, a_C=a_Q=2/5` gives factors `8/5` and `4/5`. It is a conditional
example, not an implemented W1 quantum attack.

An illustrative complete winning-cost decomposition is

\[
C_C(u)\asymp P_C(u)+T_C(u)/p_0+Z_C(u),
\qquad
C_Q(u)\asymp P_Q(u)+kT_Q(u)/\sqrt{p_0}+Z_Q(u).
\tag{21}
\]

It applies only under its explicit stationary search and fixed-success
assumptions. `P` is setup charged once under the declared sharing convention;
`T` includes a complete classical attempt or coherent search iteration;
`Z` is work performed only after finding a successful candidate. A classical
proof generated only after winning belongs in `Z`, not in every coherent
oracle call. Conversely a necessary predicate component really evaluated
coherently belongs in `T`, together with preparation/reflection, reversible
computation, membership checks and uncomputation as applicable.

The standard amplitude-amplification theorem uses a preparation procedure
and its inverse, not merely free access to a sample state [R1]. Variable-time
amplification/search can exploit unequal checking times [R2, R3]; multiplying
the maximum full-path cost by a fixed Grover iteration count does not exclude
those legal strategies. These query-model results do not establish a minimum
physical implementation cost for W1.

At a fixed `p0`, the ideal query count is constant with respect to `u`.
Consequently the claimed growth in `u` needs an actual computational lower
bound or a valid resource reduction, not just an unstructured-search query
bound. Fixed query costs, bounded-error predicates and optimal exact
measurement schedules are additional assumptions, not consequences of
writing (21).

### 9.1 Conditioned success is not campaign accounting

The distribution of cost conditional on a successful run omits the paid
unsuccessful runs. Likewise, observing one output after a convenient
measurement is not a bound on accepted total credit produced by arbitrary
restarts and adaptive policies. A pointwise cost with a fixed `eta` may be
a useful diagnostic, but it does not automatically bound the multi-winner
tail in Section 8.

Distinguish finding a marked nonce, constructing a fully valid claim,
delivering it before the declared deadline, and receiving native fork-choice
credit. Proof latency, propagation, validation, cancellation and recovery
can separate these events. Any renewal formula must name which event it
counts. Honest-block interruptions, state-dependent task selection and
deadlines require a larger model; they cannot be silently fitted into a
memoryless success parameter.

## 10. Executable scope and refusal semantics

The Python interface uses `Scope(success_contract, resource_model,
competitive_scope)`, `CostEnvelope(lower, upper, scope)`,
`CostPoint(scale, classical, quantum)` and
`CreditProblem(rho, scope, points)`. All cost and tolerance inputs are exact
`Fraction` values; JSON uses canonical rational strings. Scope identities
must match across every envelope. Labels identify declarations and do not
authenticate the truth of the declarations.

`solve_credit(problem)` returns one of:

- `FEASIBLE_FOR_DECLARED_RECTANGULAR_ENVELOPES`, with a positive rational
  schedule normalized at the first sorted scale and the recomputed worst
  efficiency spread for both classes;
- `INFEASIBLE_FOR_DECLARED_RECTANGULAR_ENVELOPES`, with a closed walk whose
  original-interval edge product is strictly below one.

`verify_witness(problem, witness)` does not call the solver. It checks every
original ordered-pair inequality for a feasible witness, or reconstructs
every refusal edge, its continuity, closure and exact product. Forging a
spread, status, edge or product does not supply a valid certificate.

The current limits are 16 distinct positive scale identifiers, unsigned
64-bit scale values, and 128-bit input rational numerators and denominators.
Certificate bounds allow the exact intermediate products required by those
limits. Missing, zero, negative or reversed cost intervals; mismatched
success/resource/scope declarations; duplicate scales; unsupported numeric
types; and tolerances below one are refused. These engineering bounds do
not assert a native domain bound or an adversarial resource bound.

The report command emits a fixed demonstration roster. It is not a native
miner benchmark or an arbitrary-instance CLI. `problem_document` and
`problem_from_document` expose the strict finite-input representation for
programmatic callers. Reports bind the local solver and test source hashes;
those hashes are not remote attestation, an external lower-bound certificate
or proof that the checkout is the production source.

From the repository root, with a fresh output path:

```bash
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_envelope_contract.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_normalized_search_cost.py' -v
python3 formal/pon-nakamoto-v1/credit_envelope_contract.py --output /tmp/pon-credit-envelope-new.json
python3 formal/pon-nakamoto-v1/credit_envelope_contract.py --verify /tmp/pon-credit-envelope-new.json
```

Report verification rejects altered qualification flags and preserves false
as a Boolean rather than accepting a numeric zero in its place. The source
and input checks certify this finite arithmetic and its declared scope only.
All flags for actual W1 lower bounds, complete legal-strategy coverage,
stateful composition, mixed-mining consensus qualification and production
activation remain false.

The resulting decision has three separate layers: validity of the input and
certificate; mathematical feasibility within the declared rectangle; and
external qualification of the cost, state and native-consensus premises.
Passing either of the first two does not close the third. Common prefix,
chain growth and chain quality still need the native fork witness and
resource-tail premises already specified in the work-scale contract.

## 11. Primary references and their limits

The elementary feasibility and minimax results above are proved in this
document. They are not attributed to a new consensus theorem in the sources.
The following primary sources were inspected on 2026-11-08; they motivate
specific model boundaries rather than filling the missing W1 premises.

| Reference | Relevant content | Boundary retained here |
| --- | --- | --- |
| R1. Brassard, Hoyer, Mosca and Tapp, *Quantum Amplitude Amplification and Estimation*, 2000 preprint / 2002 publication | Success probability in the prepared normalized state; use of the preparation and its inverse | Does not make state preparation, inverse operations, or a structured W1 predicate free |
| R2. Ambainis, *Variable time amplitude amplification and a faster quantum algorithm for solving systems of linear equations*, v2, 2010 | Amplification with different stopping times; RMS stopping-time dependence | An algorithmic theorem in its declared access model, not a W1 physical-cost lower bound |
| R3. Ambainis, Kokainis and Vihrovs, *Improved Algorithm and Lower Bound for Variable Time Quantum Search*, TQC 2023 | Known/unknown checking-time models and their query-complexity bounds | The model explicitly excludes non-query transformations from its measured query cost |
| R4. Bailey and Sattath, *51% Attack via Difficulty Increase with a Small Quantum Miner*, v2, 2024 | Interaction of variable difficulty, linear accumulated work and quantum search | Does not certify this work relation, a bounded competitive window, or a proposed replacement credit |

- R1: <https://arxiv.org/abs/quant-ph/0005055>
- R2: <https://arxiv.org/html/1010.4458v2>
- R3: <https://doi.org/10.4230/LIPIcs.TQC.2023.7>
- R3 full paper: <https://drops.dagstuhl.de/storage/00lipics/lipics-vol266-tqc2023/LIPIcs.TQC.2023.7/LIPIcs.TQC.2023.7.pdf>
- R4: <https://arxiv.org/html/2403.08023v2>

The existing stateful and work-scale contracts contain the quantum
multi-solution/backbone, public-help, direct-product and native-fork
interfaces. Their hypotheses remain required; neither a cost-rectangle
certificate nor a fixed confirmation count supplies them.
