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

## 6. Outer scope required before using real cost bounds

The matching labels in this finite checker are declarations. Using a result
for an actual work owner requires separate evidence for the input family,
admitted strategies, success event, resource convention and lifecycle. The
checker does not authenticate those facts.

A cost bound must include the permitted selection of tasks, rejected samples,
preprocessing, advice, cache reuse, sharing and invalidation. A bound for one
fixed input is not automatically a bound for a selectable family. For example,
if two permitted tasks have declared deterministic costs 1 and 99, their
equal-mixture average is 50, while a free selector can choose the task costing
1. This arithmetic example assumes those costs; it measures no implementation.

The success event must remain exact. Finding a terminal hash, verifying the
whole relation, delivering before expiry, obtaining original-owner acceptance,
receiving unique credit and reaching authorized final use are distinct events.
A probability attached to one event cannot establish the same probability for
another. An authenticated byte digest also needs the original owner's current
state and operation identity when the claim depends on a live external effect.

Where a profile permits reuse of an application output that is independent of
the new challenge, a fresh security seal does not by itself establish another
application execution or learning improvement. Any cost comparison must state
which preparation, proof, transport, verification, cache and lifecycle costs it
includes, and use the same distinct authorized uses and success standard.

For declared matched costs C_H (application), C_S (security) and C_J (joint),
the expression 1 - C_J / (C_H + C_S) describes a saving only when the denominator
is positive and all three costs use the same stated resource convention.
Unknown costs leave that comparison unknown. Allocating joint costs to one
purpose requires a separate allocation rule.

Query, gate, time and energy quantities require an explicit conversion model
before a physical comparison can be claimed. A theorem may be applied only
after its input, access, state-retention and success assumptions have been
matched to the admitted strategy family. No theorem-specific claim or actual
cost lower bound is supplied by this section.

These are outer evidence obligations. They add no admission authority, runtime
dispatch, native credit schedule or qualification. Native qualification remains
HOLD, and missing evidence must not be replaced with a synthetic example.
