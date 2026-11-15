# Sharp conditional marginal product bound — research evidence only

This is an application of classical rearrangement, not a new probability
inequality or an actual W1 security theorem. It leaves the installed checker,
CI contract, native sources and all qualification fields unchanged.

## Conditional interface

At one common history let U=(f_next/f) z^(Delta(A+E)) and H=z^(-Delta J),
with the same residual potential and accounting as the existing joint-tail note.
For supplied finite positive conditional marginal laws define their increasing
quantiles Q_U and Q_H. Over every coupling of these marginals,

    lower = integral_0^1 Q_U(t) Q_H(1-t) dt
    upper = integral_0^1 Q_U(t) Q_H(t) dt.

Both extrema are attainable. In particular E[UH | history] <= upper, without
independence. If upper <= 1 at every reachable history and permitted action,
then f_n z^(A_n+E_n-J_n) is a nonnegative supermartingale. If upper is positive
but can exceed one, its predictable cumulative product is the compensator;
the original bounded-compensator conditions and initial multiplier still apply.

**Finite proof.** A coupling is a nonnegative transportation matrix with the
specified row and column masses. For u_i<=u_k and h_j<=h_l, moving mass delta
from cells (i,l),(k,j) into (i,j),(k,l) changes the objective by
`delta (u_k-u_i)(h_l-h_j)>=0`. Saturating the smallest remaining row/column in
this manner proves the ascending mass-matching construction optimal by
induction; ties cause no problem. Reversing the second order minimizes it.
The constructions preserve both marginals and attain the two quantile
integrals. They use at most m+n-1 positive matching segments.

The robust upper is no larger than sqrt(E[U^2] E[H^2]), by Cauchy-Schwarz on
the quantile functions. Thus it can certify a conditional marginal premise
when the previous sufficient second-moment check cannot. For U=1/2 or 3/2
with equal mass and H=9/10 constant, the exact worst-coupling product is 9/10
while the squared Cauchy-Schwarz bound is 81/80>1. This is a benign finite
control, not an observed native law. These factors can arise with z=10/9,
Delta(A+E)=0, Delta J=1 and potential f=2 changing to 1 or 3.

Conversely, U=1 or 2 with masses 3/5,2/5 and H=1/2 or 1 with the same masses
have product of means 49/50, but sharp worst product 11/10. The method does
not rehabilitate multiplication of marginal means.

## Scope and verification

The marginals must be valid under the **same full conditioning history**, with
all residual state, allowed actions and entry debt covered. Pooled empirical
marginals are insufficient. Full conditional distributions contain more
information than two moments; this is not a free strengthening of moment-only
premises. Couplings inconsistent with native dynamics may be included, making
the bound conservative. A known joint law can give a still tighter direct
bound. No actual law, marginal domination, clock/service bound or native
reduction is authenticated by the finite artifact.

`check.py` uses exact Fraction arithmetic, returns attaining transport plans,
and refuses nonpositive/nonrational values, incorrect mass and size/bit limits.
It is a research helper, not a node API; it caps each marginal at 64 atoms,
inputs at 256 bits and accumulated arithmetic at 65,536 bits. It is not wired
into the installed qualification checker or its acceptance criteria.

Seven controls include an independent exhaustive assignment oracle for 15
uniform-marginal cases through five atoms, and independent affine endpoint
optimization for nine nonuniform 2-by-2 transportation cases. Neither oracle
uses the helper's mass-matching algorithm. The attaining plans are checked
against both marginal mass constraints. Native failure bounds stay null and
production activation stays false.

Run from this directory:

```bash
python3 test_check.py -v
python3 check.py
```

Primary mathematical source: Puccetti and Wang, *Extremal dependence concepts*,
Statistical Science 30(4), 485–517 (2015), sections on comonotonicity and
countermonotonicity. The author-hosted version records corrections through
May 2026: https://www.math.uwaterloo.ca/~wang/papers/2015Puccetti-Wang-STS.pdf .
The new deliverable is the conditional-accounting specialization and exact
reproducible artifact; no novelty is claimed for rearrangement itself.
