# Exact finite common-credit feasibility

Date: 2026-11-08. Status: **conditional research; native qualification HOLD**.

This executable decides whether a single positive credit schedule can satisfy
all of the *declared finite envelope inequalities*. It does not establish the
lower envelopes for W1, MU1, Hepta, a GPU implementation, or a quantum algorithm.
It does not change a lottery, work profile, DAA, chainwork, fork choice, or local
model adoption.

Implementation: [credit_feasibility.py](credit_feasibility.py).
Tests: [test_credit_feasibility.py](test_credit_feasibility.py).
Context: [WORK_SCALE_SECURITY_CONTRACT_V1.md](WORK_SCALE_SECURITY_CONTRACT_V1.md)
and [STATEFUL_RESOURCE_TAIL_V1.md](STATEFUL_RESOURCE_TAIL_V1.md).

## 1. The question the checker answers

For each declared cost model chi and finite mandatory-work scale u, suppose
positive rational numbers satisfy the intended, separately justified contract:

```text
L_chi(u) <= inf over admitted algorithms A of E[C_A^win(u)] <= U_chi(u).
```

The experiment must use one success standard, relation, profile, and lifecycle
scope. Each cost model has its own explicitly named resource model. Comparing
units within a model requires that resource model to stay the same. Classical
and quantum models may deliberately use different resource units: a change of
units by a constant cancels from the within-model ratios checked here. This
permission does not convert queries into wall time, gates into energy, or a
resource vector into a scalar cost without an explicit cost model.

For rational Gamma_chi >= 1, decide whether a single s(u) > 0 exists such that
**every ordered pair, including u = v**, satisfies:

```text
s(u) U_chi(v) <= Gamma_chi s(v) L_chi(u).
```

Including the self pairs matters: an interval U(u)/L(u) wider than Gamma already
makes the proposed robust certificate impossible, even with only one scale.

The result is about this conservative envelope criterion. An infeasible result
does not prove the actual unknown optimum has no fair schedule; narrower
bounds or joint information about the optima might change that conclusion.
A feasible result also does not prove that the declarations bound the optimum.

## 2. Exact constraint graph and certificates

Each ordered pair supplies an edge from v to u with positive multiplier

```text
a(v -> u, chi) = Gamma_chi L_chi(u) / U_chi(v),
s(u) <= a(v -> u, chi) s(v).
```

The finite problem is feasible exactly when every directed cycle has product
at least one. Necessity follows by multiplying the inequalities around a cycle
and cancelling the positive credits. For sufficiency, initialize every vertex
with value one, as if an auxiliary source had an edge of multiplier one to
every vertex. Shortest multiplicative path values give a feasible schedule
when no decreasing cycle exists.

The implementation is synchronous multiplicative Bellman-Ford:

1. At round k retain the least exact rational product of any walk with at most
   k edges ending at each vertex.
2. If a round has no strict improvement, the retained values satisfy every
   edge. Divide all of them by the first scale's value to make its credit one.
3. A strict improvement on round n, where n is the number of scales, has a walk
   of n edges and hence a repeated vertex. Removing a cycle with product >= 1
   would give a no-costlier walk of at most n-1 edges, contradicting the strict
   improvement. The first repeated-vertex cycle is therefore a product-<1
   contradiction.

All multiplication, division, and comparison use Python `Fraction` with
arbitrary-precision integers. There is no floating logarithm, epsilon,
quantum square-root approximation, or numerical optimization tolerance.
Synchronous rounds cap the stored witness walk at n edges even when a
contradictory cycle exists; an in-place relaxation can unnecessarily grow
fractions by traversing a bad cycle many times in one pass.

A feasible certificate contains every positive rational credit. Its verifier
checks the original pair inequalities directly. An infeasible certificate
contains a simple directed cycle, the cost-model identity on each edge, the
edge multipliers, and their strict product. Its verifier reconstructs every
multiplier from the input and checks closure, uniqueness, and product < 1.
Neither verification path reruns Bellman-Ford or trusts the solver's claim.

The graph contains O(m n^2) edges and uses at most n synchronous passes. The
arithmetic operation count is O(m n^3); integer bit complexity still matters.
The research parser caps n at 64, models at 8, and each input rational's reduced
numerator and denominator at 4096 bits. This is not a production consensus
parser or a certificate-processing denial-of-service specification.

## 3. Python API and exact JSON schema

Primary API:

```python
problem = problem_from_document(document)
certificate = solve(problem)
assert verify_result(problem, certificate)
```

Other public interfaces are `CreditProblem`, `Scope`, `SuccessStandard`,
`Scale`, `Bound`, `CostPoint`, `CostModel`, `constraints`,
`verify_credit_schedule`, `verify_cycle`, `integer_credit_schedule`,
`problem_to_document`, `problem_sha256`, and `load_document`.

Direct constructors require `Fraction` values, tuples of the declared record
types, positive integer work units, and distinct scale and model identifiers.
JSON numeric fields accept exact integers or strings such as `"3/2"`.
Boolean values, floats, exponential notation, NaN, Infinity, unknown fields,
and duplicate JSON object keys are refused. Exact rational strings have no
whitespace, sign, decimal point, or leading zero; equivalent fractions are
reduced before the problem digest is calculated.

Here is a complete **synthetic assumption**, containing one scale and two
models. Adding a scale requires adding exactly one matching point to every
model. Every point repeats its scope and resource identity so importing a row
from a different experiment fails instead of silently joining comparisons.

```json
{
  "schema": "pon-credit-feasibility-v1",
  "scope": {
    "relation_id": "synthetic-assumption-v1",
    "profile_id": "fixed-p-synthetic-v1",
    "epoch_scope": "one-lifetime-with-carried-inventory-v1",
    "success_standard": {
      "kind": "fixed_success_probability",
      "probability": "1/2",
      "cost_accounting": "unconditional_including_failures"
    }
  },
  "scales": [{"id": "u1", "units": 1}],
  "models": [
    {
      "id": "classical",
      "family": "classical",
      "gamma": "1",
      "resource_model": "declared-classical-lifecycle-cost-v1",
      "points": [{
        "scale_id": "u1",
        "scope": {
          "relation_id": "synthetic-assumption-v1",
          "profile_id": "fixed-p-synthetic-v1",
          "epoch_scope": "one-lifetime-with-carried-inventory-v1",
          "success_standard": {
            "kind": "fixed_success_probability",
            "probability": "1/2",
            "cost_accounting": "unconditional_including_failures"
          }
        },
        "resource_model": "declared-classical-lifecycle-cost-v1",
        "lower": {"value": "1", "basis": "assumption", "reference": "synthetic example"},
        "upper": {"value": "1", "basis": "assumption", "reference": "synthetic example"}
      }]
    },
    {
      "id": "quantum",
      "family": "quantum",
      "gamma": "1",
      "resource_model": "declared-quantum-lifecycle-cost-v1",
      "points": [{
        "scale_id": "u1",
        "scope": {
          "relation_id": "synthetic-assumption-v1",
          "profile_id": "fixed-p-synthetic-v1",
          "epoch_scope": "one-lifetime-with-carried-inventory-v1",
          "success_standard": {
            "kind": "fixed_success_probability",
            "probability": "1/2",
            "cost_accounting": "unconditional_including_failures"
          }
        },
        "resource_model": "declared-quantum-lifecycle-cost-v1",
        "lower": {"value": "1", "basis": "assumption", "reference": "synthetic example"},
        "upper": {"value": "1", "basis": "assumption", "reference": "synthetic example"}
      }]
    }
  ]
}
```

`success_standard.kind` is exactly `fixed_success_probability` with a positive
probability <= 1, or `almost_sure_first_success` with the probability field
absent. Both require `unconditional_including_failures` cost accounting.
These identifiers record the intended experiment; the checker does not prove
that an implementation succeeds almost surely or attains a stated probability.

A lower bound's `basis` must be `assumption` or `proof_reference`. An upper
bound may additionally use `measurement` or `implementation`. A reference is
required but is untrusted descriptive evidence: the checker does not prove,
authenticate, retrieve, or execute it. A finite timing measurement alone does
not establish a worst-case bound or an expected-cost bound. Selecting
`proof_reference` also does not make a bound verified.

An unknown lower bound, including `null`, `"unknown"`, or zero, is rejected.
It must stay an open obligation in the outer cost contract. A surrounding
report must not substitute a measured upper bound for the missing lower one
or run a synthetic envelope as a fallback that qualifies the real profile.

Result schema is `pon-credit-feasibility-result-v1`, with:

- `problem_sha256`: SHA-256 of the canonical normalized input document,
  including scope, bound evidence declarations, and record ordering.
- `status`: `feasible` with `credits` rows (`scale_id`, `value`), or
  `infeasible` with `cycle` rows (`model_id`, `source`, `target`, `multiplier`)
  and `cycle_product`.
- `qualification`: exactly the four declarations shown below. The verifier
  rejects attempts to upgrade them.

```json
{
  "domain": "finite_declared_envelopes",
  "lower_bound_claims": "unverified_declarations",
  "lifecycle_composition": "not_proved",
  "native_consensus": "not_qualified"
}
```

The normalized first-scale credit is one. To obtain integer credits, multiply
by the common denominator and then divide by the common gcd. This preserves
all ratios. Independently flooring rational credits does not preserve the
contract and may produce zero or infeasible credits. The integer conversion
helper verifies the original and converted schedules and imposes no native
chainwork width or rounding policy.

## 4. Exact examples and independent controls

Let the grid be u in {1,16}. Under the synthetic exact declarations
`K_C(u)=u` and `K_Q(u)=sqrt(u)`, classical costs are {1,16} and quantum costs
are {1,4}. For r=s(16)/s(1), the respective constraints require

```text
16/Gamma_C <= r <= 16 Gamma_C,
4/Gamma_Q <= r <= 4 Gamma_Q.
```

These intervals intersect exactly when `Gamma_C Gamma_Q >= 4`.
Thus Gamma_C=Gamma_Q=1 is infeasible; Gamma_C=Gamma_Q=2 is feasible with
r=8. The two-edge contradictory cycle has product
`Gamma_C Gamma_Q / 4` when that product is below one. Taking
`Gamma_C=Gamma_Q=(2*10^80-1)/10^80` remains strictly infeasible, although a
binary floating representation can round that input to 2. No tolerance is
permitted at this boundary.

The test suite compares decisions against an independently derived two-scale
interval intersection, independently enumerates simple cycles and model
assignments on small three-scale instances, checks cycle and credit tampering,
checks exact threshold and integer conversion behavior, and checks scope and
bound-evidence rejection paths. These are finite arithmetic tests, not
algorithms establishing actual Cell cost lower bounds.

## 5. What remains outside this certificate

A finite grid does not interpolate to other u values. A fixed-success
experiment is not interchangeable with an almost-sure stopping experiment.
If the admitted quantum or classical algorithm family expands, or batching,
cache reuse, preprocessing, subset search, helper work, withheld winners, or
cross-epoch state makes the proposed lower bound false, the checker has no
mechanism to repair that bound. Every admitted strategy must already be in the
cost-envelope statement before the input is meaningful.

Pointwise single-winner expected bounds do not establish an adaptive,
stateful, multiwinner cost contract or a chain-security tail. The separate
potential/resource-tail obligations remain, including initial preprocessing,
carried inventory, deduplication, optional stopping, and publication choices.
The report's `native_consensus: not_qualified` flag remains even when a
synthetic credit schedule is feasible or the `proof_reference` label is used.

Reproduce from the repository root:

```bash
python -m unittest discover -s formal/pon-nakamoto-v1 -p test_credit_feasibility.py -v
python formal/pon-nakamoto-v1/credit_feasibility.py solve INPUT.json --output CERTIFICATE.json
python formal/pon-nakamoto-v1/credit_feasibility.py verify INPUT.json CERTIFICATE.json
```

The subset-success normalization `f=q/g`, work-scale arithmetic, and native
relation provenance belong to their existing or outer contract modules and
are deliberately not reimplemented here.

## 6. Required outer scope for actual Hepta work

The finite solver's matching scope labels are declarations. They do not
authenticate task provenance, the admissible input set, an execution owner or
the meaning of success. Connecting this certificate to the existing Hepta
owners requires those facts outside the solver; a second string-only verifier
would not establish them.

### Input selection belongs inside the strategy

Let K fix the complete admitted work family, input access and selection rules,
initial-state distribution, legal preprocessing/advice/cache state, sharing and
invalidation rules, and the lifecycle horizon. Let S fix the success event and
threshold eta. For a fixed-success experiment the intended object is

```text
c_chi(u; K, S) = inf { E[C_pi] :
    pi is an admitted policy in resource model chi under K,
    Pr_pi[S] >= eta }.
```

Cost is still unconditional. Policies include acquiring tasks, rejecting sampled
tasks, selecting inputs/batches/permutations, abandoning attempts and publishing
results. Task selection is not an external honest preprocessing step unless K
actually enforces that restriction. The original task and budget owners retain
their authority; this notation creates no new admission or dispatch path.

A lower bound for one fixed input x does not automatically lower-bound this
experiment. With free choice among two equal-size tasks of deterministic costs
1 and 99, an equal-mixture average is 50 while an admitted selector can always
pay 1. This arithmetic counterexample concerns declared costs, not measured W1
or Hepta costs. A scale-only lower bound needs a uniform bound over every
selectable input and permitted initial state, or a distributional reduction
that includes the actual selection policy and all costs of rejected samples.
Expanding the input domain or advice/cache allowance requires reconsidering
the bound even when the matrix shape and solver labels stay unchanged.

### The same probability is not the same success event

Finding a marked terminal hash, proving the complete work relation, delivering
before the original deadline, obtaining original-owner acceptance, acquiring
unique native credit, and actual authorized consumer use are different events.
An eta attached to one event cannot be relabelled as eta for another. The outer
contract must pin the relevant verifier/program, complete inputs and state,
original operation identity, expiry convention, replay/currentness rule and
the event whose probability is being lower-bounded. A retained expected-context
digest binds bytes; it does not authenticate the owner's live state or prove
that an external effect occurred.

The existing [useful-Cell relation](../../docs/development/specs/pon/USEFUL_CELL_RELATION_V1.md)
and [owner map](../../docs/development/specs/pon/NEXT_HEPTA_OWNER_BINDINGS_V1.md)
separate these responsibilities. Their public-source feature extractor is not
the ordinary trained Hepta encoder. A correct local relation remains distinct
from native owner admission, final use, payment and consensus qualification.

### Cached application outputs and fresh seals

When an admitted application output is independent of the challenge and legal
cache reuse remains valid, preparing that output once can leave zero fresh
application contractions for a later seal. A new nonce or parent context may
require fresh security work without requiring another useful inference or
learning improvement. The constructive scope and retained costs are recorded in
the [grouped metering contract](../../docs/development/specs/pon/GROUPED_SECURITY_WORK_METERING_V1.md).
This refutes a positive *per-ticket fresh-application-contraction* floor in
that scope. It does not set preparation, sealing, proof, transport, verification
or lifecycle resource cost to zero, and does not assume an unlimited cache
lifetime where the admitted profile imposes a limit.

An application comparison must use the ordinary optimized Hepta implementation
for the same distinct authorized uses, including its low-rank, routing, shared
base and cache behavior. A joint comparison additionally needs the same security
success event and success standard. If C_H, C_S and C_J are complete matched
costs for application alone, security alone and joint execution in the same
resource convention, the joint saving is `1 - C_J / (C_H + C_S)` for a positive
denominator. Missing costs leave the saving unestablished. Attribution of joint
costs to the application requires a separately stated allocation rule; counting
all seals as useful invocations cannot supply that rule. An offline accounting
readback is not a newly executed matched-baseline experiment.

### Quantum model boundaries and primary sources

[Variable-time search](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.TQC.2023.7)
and [computation-tree search](https://arxiv.org/abs/2505.22405v2) analyze query
models with nonuniform checking costs. Their results do not justify replacing
every admitted strategy by equal-cost independent trials followed by Grover.
[Hybrid query bounds](https://arxiv.org/abs/2610.06803v1) specifically require
all qubits to be measured and discarded between bounded-query subroutines.
That theorem cannot lower-bound an admitted miner that retains coherent state
across those boundaries merely because it declares a bounded hardware class.

[Arbitrary-matrix PoUW](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
uses an explicit conjecture for its security conclusion and compares overhead
to naive matrix multiplication. Applying it to Hepta requires a reduction that
covers Hepta's actual legal input selection, low-rank/cache optimizations and
chosen resource model. It does not supply the sixteen missing actual MU1 cost
bounds in [the frozen contract](fixed_probability_contract_v1.json).

The cancellation `(s/c_Q)/(s/c_C) = c_C/c_Q` holds algebraically. A physical
hardware-efficiency interpretation additionally requires common calibrated
resource units or an explicit conversion model. The within-model feasibility
check above permits different classical and quantum resource units; it makes
no query-to-energy conversion and cannot equalize a real same-scale advantage.
