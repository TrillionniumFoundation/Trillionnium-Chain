# Fixed probability: executable cost-contract continuation

Date: 2026-11-08. Status: **research implementation; HOLD_NO_GO**.

This continuation makes three parts of the proposed cost contract executable:
joint credit feasibility, finite lifecycle potential synthesis, and a bounded
native branch-schedule candidate. It extends the existing MU1 relation and
stateful resource research. It does not establish a minimum cost for every
legal W1 algorithm, activate a new native work profile, or qualify a public
network. The authoritative development plan remains the repository's single
[development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## 1. An audit contract bound to the actual MU1 relation

The [machine-readable contract](../../../../formal/pon-nakamoto-v1/fixed_probability_contract_v1.json)
and [reader](../../../../formal/pon-nakamoto-v1/fixed_probability_contract.py)
bind to the existing
[MU1 relation](../../../../formal/pon-nakamoto-v1/MANDATORY_UNITS_RELATION_V1.md):

- inclusive aggregate target `2^252 - 1`, with ideal terminal-oracle density
  `1/16`;
- one through eight complete ordered PNW1 units;
- all of MU1's actual context fields and parameter digest;
- the existing **research** credit `16u`, without a native weight bridge;
- four exact relation-source hashes, whose scope is explicitly narrower than
  a full executable/dependency identity;
- one success standard: at least one distinct valid result with probability
  at least one half, with all unsuccessful work counted.

The source pins identify `mandatory_units_relation.py`, `work_oracle.py`,
`contract_wire.py`, and the Rust `pon_work.rs`. This is a relation-source check.
It does not authenticate the complete build graph, dependencies, process,
loaded executable, owner, or every legal implementation. Native execution
receipts and their source/build identities are separate evidence.

All sixteen actual cost points (eight scales, two algorithm classes) retain
`lower=null`, `upper=null`, and `status=unproved`. V1 refuses an attempt to
replace them with zero, an observed time, or a self-declared certificate.
The reader reports `binding_validation=PASS` alongside
`qualification=HOLD_NO_GO`. Its version cannot be made to authorize activation
by setting a JSON flag. A future cost theorem requires a separately reviewed
evidence verifier and contract revision.

The contract records batching, low-rank/shared work, preprocessing, public help,
failed and unpublished work, all competing branches, restart/profile state,
false-root and proof grinding, quantum subsets, state preparation,
uncomputation, variable-time search, parallelism, and retained quantum state.
A list of strategies is a required coverage scope, not proof of completeness.
Public model training is not repeatedly charged to every miner. Setup is paid
once, previous credit is excluded from residual potential, and neither an
epoch nor a profile change resets the cost account.

### Concrete MU1 whole-proof reuse control

The [complete reuse probe](../../../../formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py)
replays a pinned full MU1 fixture and a separately pinned expected context.
It retains the first unit proof from nonce 24 and recomputes only the last
unit for nonce 26. The resulting hybrid really passes the outer aggregate
target; its new last unit passes complete W1 verification and legally reuses
the prepared `A,B,AB` prefix. The retained first unit instead fails at
`TRANSCRIPT`, and both complete MU1 verification and its research counter
reject at `W1_TRANSCRIPT`, without adding credit. Regenerating under the
unchanged context produces identical bytes, ticket and identity, with zero
duplicate credit. All 21 predicates must hold for the probe to report success.

This is a concrete control for the shared context's binding to every unit,
under the stated hash-binding assumption. It does not prove that each fresh
unit pays the reference implementation's cost. Context-specific nonce banks,
legal prepared matrices, shared traces, batching and quantum shortcuts still
belong in the full lifecycle analysis. The probe uses the complete scalar
verifier; it does not claim a new native execution or map the synthetic MDP
into actual W1 resource costs.

## 2. Decide whether a common credit function even exists

[Credit feasibility](../../../../formal/pon-nakamoto-v1/CREDIT_FEASIBILITY_V1.md)
implements the proposed robust constraints, for all declared ordered pairs:

```text
s(u) U_chi(v) <= Gamma_chi s(v) L_chi(u).
```

Each constraint is a directed edge `v -> u` with positive rational multiplier
`Gamma_chi L_chi(u)/U_chi(v)`. A common positive schedule exists if and only if
no directed cycle has product below one. The implementation uses synchronous
multiplicative Bellman-Ford and exact rational arithmetic. It returns either
a schedule or a strict contradiction cycle. The independent verifier checks
the original inequalities or reconstructs the cycle's multipliers directly;
it does not rerun the solver.

As a **synthetic cost-law example**, take scales `{1,16}`, classical optima
`{1,16}`, and quantum optima `{1,4}`. Exact fairness in both classes is
impossible: the mixed cycle has product `1/4`. Feasibility requires
`Gamma_C Gamma_Q >= 4`; common tolerance `Gamma=2` permits weights `{1,8}`.
Scale 16 is outside MU1 V1's allowed range: this example is a general
mathematical diagnostic, not a new allowed native or MU1 scale.

An infeasible result rejects the supplied **envelope criterion**. Loose lower
and upper bounds can make that criterion impossible even when the unknown
actual costs permit a schedule. Conversely, a feasible schedule does not prove
that the declared bounds are true. Lower-bound references remain unverified
declarations; measurements can only be tagged as upper-bound evidence, and
even then a finite measurement does not prove the declared expectation.

The reader binds every row to its relation, profile, lifecycle scope, success
standard, and declared resource model. It refuses missing/duplicate scales,
unknown or zero lower bounds, inverted intervals, floats, duplicate JSON keys,
and evidence from a different experiment. Integer credits are produced by
exact common-denominator scaling; independently flooring weights can violate
the constraints.

## 3. Find a finite lifecycle potential, or a certified contradiction

[Additive potential synthesis](../../../../formal/pon-nakamoto-v1/AMORTIZED_COST_POTENTIAL_V1.md)
complements the earlier hand-specified exponential-potential checks. Its
finite model contains every declared action and outcome, frozen work credits,
a resource price, explicit initial potential caps, and a non-refillable eta
ledger. It seeks a nonnegative potential satisfying every Bellman inequality:

```text
E[credit + Phi(next) - Phi(state) - kappa cost - eta_debit] <= 0.
```

The solver returns an exactly verified potential or nonnegative Farkas
multipliers whose state coefficients cancel and whose right-hand sides have
a strictly positive sum. A bounded incomplete search returns `UNKNOWN`; it
does not turn failure to find a solution into an impossibility claim.
The independent finite-horizon policy optimizer checks adaptive action choices
against the potential certificate.

The controls include shared setup, cross-scale reuse, stochastic failures,
batched outcomes, releases, initial prefilled state, duplicate credit,
stopping, and eta depletion. A cycle with excess credit after *positive* cost
is sufficient to refute a frozen price contract; the attack need not be a
zero-cost duplicate. A certificate applies only to the supplied finite model.
Its all-algorithm simulation obligation remains open, and an expectation
certificate is not a chain-security tail bound. The existing
[stateful tail interface](../../../../formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md)
retains that separate obligation, including joint quantum state.

## 4. Normalize cheap subsets before comparing cost

Let `q` be the retained fraction of baseline winners and `g` the retained
fraction of the domain. Uniform search on that domain has density `p0*q/g`.
The diagnostic first verifies both inside and outside winner masses are
possible, then uses exact arithmetic under the **assumed** inverse-probability
and inverse-square-root cost laws:

```text
f = q/g
classical relative cost = a_C/f
quantum relative cost squared = a_Q^2/f.
```

Comparing the squared quantum ratio avoids numerical square-root tolerance.
For `p0=1/16`, `q=1/8`, `g=1/2`, and `a_C=a_Q=2/5`, the model gives classical
ratio `8/5` and quantum ratio `4/5`. In contrast, retaining one quarter of both
the domain and its winners leaves density unchanged.

These are exact algebraic consequences of the declared scaling laws, not
exact finite-Grover running times at the contract's one-half success threshold.
They do not include shared setup or post-win tails, or supply an actual W1
quantum implementation. An eight-element-domain exhaustive control checks
the mass conditions against explicitly enumerated subsets.

## 5. Branch-bound native C0/C1 research component

The [branch schedule component](BRANCH_WORK_SCHEDULE_RESEARCH_V1.md) moves
ASERT beyond the earlier Python arithmetic model into the native Rust package.
It reconstructs a complete bounded genesis-to-parent path, derives the anchor
from that path, and binds the profile/anchor identity. It supports C0 fixed
target for the entire research window and C1 integer ASERT, with the activation
block checked under the preceding target rules.

`required_target` has no candidate timestamp or current clock argument.
Post-activation time must be nondecreasing and greater than MTP11. Clock
eligibility is a separate `DeferredUntil` decision and cannot rewrite stored
historical target or work. Required-target work uses the existing exact
512-bit checked accumulator. The native component retains full 256-bit
targets, without BCH compact-target rounding or its testnet exception.

The bridge reads an already-open Node's PNH1 or PGH2 parent path and replays
complete W1 proofs in the correct native challenge domain. Its research
checks are not application-state execution or native admission. Current
Node owners retain their old policy. A future activated profile needs explicit
parameter/wire/schema migration, both admission owners, cold recovery, and
joint security qualification. A proof with an old target failing under the
new target is not evidence that a timestamp rule was fixed.

## 6. Reproduction and interpretation

Run the focused mathematical and contract controls:

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_probability_contract.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_feasibility.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential_independent.py' -v
python3 formal/pon-nakamoto-v1/fixed_probability_contract.py
python3 formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py --check
python3 formal/pon-nakamoto-v1/amortized_cost_potential.py
```

Run the native candidate and retained consensus regression on the frozen source:

```bash
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test research_work_schedule -- --test-threads=1
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib consensus::tests -- --test-threads=1
```

The new mathematical checks are mandatory in the existing repository-truth
lane; existing CI controls reject omission, duplication, or movement to a
different lane. The new native test target is included by the existing
workspace `--all-targets` lane. Execution evidence must name the tested commit
and retain failures, rather than inherit a parent branch's successful result.

The scientific next gate is still the joint lower envelope for the actual
legal W1/MU1 strategy class and initial state. The engineering next gate is an
explicit new native admission/recovery profile on one tested source. Neither
gate is replaced by a successful arithmetic certificate.

## 7. Fixed-success query frontier and the output-checking loss

The [fixed-success continuation](../../../../formal/pon-nakamoto-v1/FIXED_SUCCESS_QUERY_FRONTIER_V1.md)
proves an exact optimum over every classical adaptive policy in a separately
declared independent Bernoulli membership-query game. Its
[calculator and independent verifier](../../../../formal/pon-nakamoto-v1/fixed_success_query_frontier.py)
distinguish an unconditional expected producer-query cost, a hard query cap,
the available finite domain, and terminal output checks performed outside the
producer's account. Arbitrary exact private coins are free in this query metric;
finite-seed or wall-clock attainment is not implied.

For `p=1/16`, success at least `1/2`, enough fresh addresses and no unqueried
terminal outputs, the minimum expected producer-query count is exactly `8`;
the minimum feasible hard query cap is `11`. With one unqueried final output,
the expected producer-query optimum is `112/15`. With eleven such outputs and
enough available addresses, this relaxed model admits success at least one
half with zero producer membership queries. Other computation and receiver
verification remain outside that deliberately relaxed resource metric.

MU1's existing ideal reduction grants valid unit construction for free and
uses virtual terminal membership checks for extraction. Those checks cannot
be silently billed to the producer. The new theorem quantifies that loss and
states the required direction of an all-algorithm simulation and its additive
overhead. It supplies no physical-cost simulation for W1, no bound increasing
with the number of units, and no quantum optimum. All sixteen actual cost
points retain their original `null/null/unproved` values.

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_success_query_frontier.py' -v
python3 formal/pon-nakamoto-v1/fixed_success_query_frontier.py --check
```


## 8. Integrate resource tails without changing the actual cost rows

The [resource-tail continuation](../../../../formal/pon-nakamoto-v1/COST_TAIL_TRANSFER_V1.md)
proves `E[C] >= sum_t (alpha-H(t))_+` for nonnegative observable integer
resource cost, under a legal success-preserving budget truncation and a valid
cap-success bound at every budget. Every finite prefix is usable without
extrapolating the uncomputed tail. This strengthens the retained single-cut
Markov conversion. It places additive simulator/virtual-check queries inside
the cap function, without charging them as actual producer work.

The exact arithmetic verifier does not verify reference search theorems,
initial-state coverage or the universal real-resource simulation. Its finite
advice counterexample shows why state probability domination alone cannot
transport the independent-state expected-cost optimum. The original sixteen
actual `lower`, `upper` and `status` fields remain `null`, `null`, `unproved`.

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_cost_tail_transfer.py' -v
python3 formal/pon-nakamoto-v1/cost_tail_transfer.py --check
```

## Primary references

- [BCHN integer ASERT specification](https://bitcoin-cash-node.gitlab.io/bchn-sw/bitcoincash-upgrade-specifications/2020-11-15-asert/): integer division, polynomial, anchor semantics, and reference vectors; deployment parameters are not copied into PoN.
- [Cojocaru et al., Quantum 7:944](https://arxiv.org/abs/2012.15254v4): multi-solution Bernoulli quantum-query analysis under its stated adversary and honest-miner model; no automatic W1 physical-cost reduction.
- [Komargodski and Weinstein, ESA 2026](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2): useful matrix work under explicit hardness conjectures, rather than an unconditional lower bound for arbitrary optimized Cell arithmetic.
