# W1: formal composition and joint-oracle obligations

Date: 2026-11-07. Scope: the candidate at
`7150d96a2112875b4afcf3023361a5cef4a0e4b1`, its pinned RISC Zero profile, and
the explicitly identified manuscript versions below.
Status: **CONDITIONAL ARITHMETIC CHECKED; COMPLETE W1 SECURITY HOLD**.

This continuation adds two executable results. The first evaluates the precise
sequential-composition expression in the indexed January CDHZ manuscript. The
second is a finite countermodel to replacing shared hash purposes by independent
ideal functions merely because each individual output is uniform. Neither
result instantiates a security theorem for the accepted W1 relation.

The code is independent of the earlier component calculator:

* [Composition evaluator](../../scripts/w1_qrom_composition_budget.py), with
  [16 tests](../../scripts/ci/test_w1_qrom_composition_budget.py).
* [Joint-oracle diagnostic](../../scripts/w1_qrom_joint_oracle_diagnostic.py),
  with [10 tests](../../scripts/ci/test_w1_qrom_joint_oracle_diagnostic.py).
* [Retained evidence](../../evidence/pon-w1-qrom-formal-bridge-20261107/README.md).

Every output keeps unconditional project security bits `null`, proof
qualification `false`, and the three independent authorization, proof, and
quantum-work conclusions separate.

## 1. Version and access boundary

The [CDHZ ePrint landing page](https://eprint.iacr.org/2025/2166) identifies the
March 2, 2026 revision. The [EUROCRYPT chapter](https://doi.org/10.1007/978-3-032-25336-1_14)
was published May 9, 2026. The formal statements reviewed here come from the
search provider's readable index of a manuscript whose title page is **January
1, 2026**, hosted at [CORE](https://files01.core.ac.uk/download/690750245.pdf).
This is a selected-statement and interface review, not a complete proof audit.

Ordinary HTTPS retrieval of the latest ePrint PDF returned 403; retrieval of the
CORE PDF returned 522 in the authorized host trial. No local PDF was obtained,
so there is no PDF-byte digest or verified January-to-March equivalence. The
index, landing page, and publisher preview must not be described as a verified
copy of the latest full manuscript. In particular, an interface discrepancy in
the January index is not evidence of an unresolved error in the current paper.

## 2. Theorem 10.6: the expression actually evaluated

The source is CDHZ January, Definition 10.3, Remark 10.4, Construction 10.5,
and Theorem 10.6, pp. 71–73. Write `ext_i`, `com_i`, and `sim_i` for the two
components' error functions, at one common parameter slice `(lambda, n)`.
Define:

\[
\begin{aligned}
A&=t+q_{V_1}+q_{V_2}+q_{E_2},\\
B&=t+q_{V_1},\\
C&=t+2q_{V_1}+q_{V_2}+q_{E_2}+q_{\widehat R_2}+q_{\widehat R_3},\\
K&=2q_{E_2}^{2}\bigl(q_{V_1}^{2}+(q_{\widehat R_2}+q_{\widehat R_3})^2\bigr).
\end{aligned}
\]

Then a sufficient expression for the composed extraction error is

\[
 2\,\mathrm{ext}_1(A)+2\,\mathrm{ext}_2(B)
 +K\min\{\mathrm{com}_1(C),\mathrm{com}_2(C)\}.
\]

The simulation and commutativity expressions are the corresponding minima at
the same requested query bound. These expressions require both reductions to
use the **same** emulated oracle `(Init, U1, U2)` and to share exactly the middle
strict and relaxed relations. The commutativity error is a squared-norm bound;
it must not be silently replaced by an amplitude error or a probability with a
different convention. Ordinary queries commute perfectly in this definition.
Classical repetition must preserve both the answer and the residual oracle
state. The `U1/U2` commutator envelope is nondecreasing in the query bound.

The composed extractor recomputes the first verifier's intermediate instance,
then invokes the second extractor followed by the first. Under the declared
component costs this gives `q_V3 = q_V1 + q_V2` and
`q_E3 = q_V1 + q_E2 + q_E1`. The calculator does not prove these declared costs,
the component extractors' existence, or the common instance-size coverage.

### Input and claim discipline

Each error envelope is explicitly an **assumed** polynomial with nonnegative
exact rational coefficients, on a declared finite query domain and fixed
`(lambda, n)`. This restricted representation makes its monotonicity checkable.
It does not prove that it bounds any real algorithm. The script evaluates it
at `A`, `B`, or `C`, and refuses evaluation beyond its declared domain. A bound
known only at the original adversarial budget `t` is insufficient.

SHA-256 values in this input identify hypothetical complete relation and
oracle specifications. Matching values are only a description-consistency
check. Missing descriptions block the conditional expression; known
incompatibilities are rejected. Missing coefficients, parameter scopes, or
query domains propagate `null`, including a product of a known zero with an
unknown factor. A numerical upper expression greater than one is retained as
such; it is neither clipped nor interpreted as an attack.

The retained hypothetical example has `(A,B,C)=(14,7,23)` and `K=1696`. With
`ext_1(q)=q^2/2^64`, `ext_2(q)=(q+1)/2^64`, and common commutativity upper
envelope `(q+1)/2^96`, the resulting expression is exactly

\[
\frac{408}{2^{64}}+\frac{40704}{2^{96}}.
\]

Those are invented demonstration envelopes. Passing the example's target
comparison leaves every real security qualification false.

## 3. Component statements and why 11.3 is not numerically instantiated

The earlier calculator's named January 6.10 component is consistent with the
displayed statement on p. 46:

\[
\kappa^{sr}_{IOR}(s,t,w,Z,\delta)
\le 80(t+k+1)(w+k)\kappa_{RRBR}(\delta)
 +(t+k+1)k\,2^{-r_{\min}},
\qquad
\kappa_{RRBR}(\delta)=\max_{i\in[k],(x,y)\in Z}\kappa_i(x,y,\delta).
\]

Here the missing input is a full relaxed round-by-round **knowledge** argument,
with an extractor, uniformly over the specified statement set. A classical
interactive estimate for one FRI component cannot supply that premise. The
finite-randomness term remains even if a hypothetical RRBR error is set to zero.

The four named January 8.3 component expressions on p. 53 are:

| Component | Displayed upper expression |
|---|---|
| Commutativity | `240 (t+1) / 2^sigma` |
| Extraction correctness | `8 n_VC l_max / 2^sigma` |
| Offline extractability | `(160 w_VC t^2 + 16 q_s log2(l_max)) / 2^sigma` |
| Online indistinguishability | `240 w_VC t^2 / 2^sigma` |

`n_VC` here distinguishes the commitment-count argument from the instance-size
parameter `n` used elsewhere. Definition 8.2 uses a specified Merkle scheme,
including salted leaf encoding, ordered binary nodes, and an ideal bit-string
random oracle. The actual Poseidon2 leaf/cap/transcript encodings need their own
compatible commitment and emulation argument. Eight stored field words do not
establish `sigma=256` or an independently uniform bit-string oracle.

### The 11.3 dependency interface

For reference, let `t=t_NRDX`, `q_R=q_CRhat`, `q_Rp=q_CRhat_prime`,
`w_M=w_MultiExtract`, and
`T=t+1+q_V+k+q_R+q_Rp`. The indexed January 11.3 extraction expression on
pp. 78–79 reads:

\[
\begin{aligned}
\max_{w_{FS}+w_{VC}+w_M\le t}\big[&
4\kappa^{sr}_{IOR}(s,t,w_{FS},n,\delta)\\
&+4\kappa_{extract}(\lambda,2t+1,w_{VC},w_M+2w_{FS}+1,
\sigma,l_{\max},n_y+k,n_y)\\
&+8\kappa_{offline}(\lambda,2t+1,w_{VC},w_M+2w_{FS}+1,
\sigma,l_{\max},q_y+q_\Pi+l_{\max}n'_y)\\
&+4\kappa_{online}(\lambda,T,w_M+1,w_{VC}+q_R+q_{Rp},w_{FS}+k,\sigma)
\big]\\
&+2q_V^2\kappa_{com}(\lambda,t+1+k+q_V,l_{\max},k+n_y).
\end{aligned}
\]

This records the dependency and argument order without substituting 8.3.
Definition 7.3 writes the online signature in the order
`(lambda,t,w_M,w_VC,w_Record,sigma)`, while 8.3 displays
`(lambda,t,w_VC,w_M,w_Record,sigma)`. The 11.3 call follows the former order.
An authoritative version check or an independently verified correction is
required before a positional numerical substitution. The source index's
typesetting may also need comparison with actual PDF pages. This review does
not choose which interface was intended and does not assert the March revision
contains the same discrepancy.

Even after resolving that source question, the following implementation
obligations remain:

| Obligation | Required artifact for this fixed instance |
|---|---|
| Complete relations | Definitions of `R`, `R'`, both committed relations, both relaxed committed relations, and their actual accepted encodings |
| Monotone target | A proof of Definition 11.1's property under partial implicit-instance restriction, at each required proximity parameter |
| Uniform PQSR | An extractor and bound over `Z = {(x,y): |x| <= n}`, not a saved journal alone |
| Commitments | Compatible quantum multi-extractability for all `k+n_y` commitments, with the admissible coherent extractor and all four error functions |
| Joint oracle | A compatible model for the FS and VC oracle registers and every exposed implementation use |
| Query accounting | `q_V`, both relaxed committed-relation decider costs, `q_y`, `q_Pi`, vector lengths/counts, and the enlarged budgets |
| Adaptive mass | Bounds on superpositional query masses `w_FS,w_VC,w_M`; they are not successful-receipt counts or honest native permutation counts |
| Recursion | The actual reduction construction, compatible middle relations/oracle state, and bounds valid for every admitted recursive program and reachable size |

Theorem 11.3 gives an extractor for every proximity parameter in `[0,1]`, under
its hypotheses and the Definition 10.3 quantifiers. Its target relation is
monotone. The VC extractor must be polynomial-time and admissible, including
the repeated-index and prefix-consistency behavior of Definition 7.1. Merely
extracting a classical opened Merkle path does not establish that interface.
The maximized query masses need not be integers: a coherent query can place
amplitude on several oracle purposes. A future optimizer must handle that
domain or prove a conservative relaxation.

## 4. Fixed FRI applicability: concrete unresolved steps

The [existing implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md)
fixes BabyBear `p=2013265921`, its degree-four extension, inverse rate 4,
folding factor 16, 50 queries sampled with replacement, and a terminal
polynomial of at most 256 extension coefficients. These are implementation
facts. They do not identify a complete `k`-round IOR or a per-round knowledge
extractor.

[Fiat–Shamir Security of FRI and Related SNARKs](https://eprint.iacr.org/2023/1071)
is a positive security-analysis paper. The indexed full-text title page is
February 15, 2024; its metadata records a March 5, 2024 update. Its Algorithm 1
uses binary folding and a constant terminal value. Theorems 4.1 and 5.11 give
specified RBR and RBR-knowledge results. Applying them requires a proof of the
actual radix-16/terminal-polynomial transformation, power batching, sampler,
extension-field/domain choices, and their interaction with the surrounding
AIR, lookup, permutation, and DEEP steps. Lemma 5.10 explicitly distinguishes
power batching from independent random coefficients.

There is also a simple parameter obstruction to a casual numerical import.
The Johnson-regime Theorem 4.1 requires
`delta < 1-sqrt(rho)-eta`, with `eta>0`, and its sufficient expression contains
`(1-delta)^ell`. Even granting the missing protocol mapping, with `rho=1/4`
and `ell=50` that term is strictly greater than `2^-50`. **That particular
sufficient expression cannot supply a 97-bit RRBR bound.** This is an
observation about the expression, not a lower bound on real failure probability,
not a 50-bit security assertion, and not evidence of a W1 forgery. A stronger
theorem or additional assumptions must be identified and mapped separately.

The 2024 indexed paper's p. 18 explicitly leaves a full RISC Zero RBR-knowledge
proof as a future task at its time of writing. That historical sentence does
not establish the absence of subsequent results. This review did not locate a
formal instantiation covering the exact locked `3.0.6 / 3.0.5 / 3.0.2 / 4.0.5`
profile and complete accepted recursion relation. These two statements have
different evidentiary scopes.

The [new semantics audit](W1_QROM_SEMANTICS_AUDIT_20261107.md) narrows one
implementation premise by interpreting the generated constraint DAG. Its
degree bound is conditional on the trace-polynomial interpretation. Actual
trace divisibility, DEEP denominator events, and a full RBR extractor remain
separate obligations; a degree bound alone is not that extractor.

For conjecture accounting, use the exact hypothesis and quantifiers. The
[2025 Crites–Stewart paper](https://eprint.iacr.org/2025/2046) addresses specified
up-to-capacity and related conjectures. The
[2026 multiplicative-subgroup counterexample](https://arxiv.org/abs/2604.09724)
is an existential parameter-family result. Neither title licenses a statement
that all FRI fails, nor identifies an attack at this particular BabyBear
extension, domain, and proximity parameter. The audit needs an explicit
dependency for every conjectural estimate used in the fixed profile.

## 5. Shared hash purposes require a joint model

The finite diagnostic assumes an ideal function with a hypothetical output
set of size `M`. Each purpose returns a uniform marginal. If their encoded
inputs coincide, the shared world has `Pr[Y_left=Y_right]=1`; two independent
purpose functions give probability `1/M`. Two ordinary classical queries have
acceptance-probability gap and joint total variation distance `1-1/M`.
For `M=16` the retained example is exactly `15/16`. Distinct encoded inputs in
the same ideal function give the independent product law for this experiment,
and the retained positive control has distance zero.

This is a mathematical countermodel to an inference from marginal laws. It is
not an attack on the real permutation, not a proof of its distribution, and
not a replacement for a quantum reduction. A classical distinguisher suffices
to demonstrate the model mismatch because it is also permitted within the
larger quantum-adversary class.

The separate [semantics audit](W1_QROM_SEMANTICS_AUDIT_20261107.md) records a
concrete memory/control permutation-input alias after reversing word order
and converting the control digest boundary from Montgomery representation.
That observation motivates the joint-model obligation. It does not establish
that the alias is reachable in an accepted W1 proof, or that a relevant
committed relation can be forged. A valid proof could instead analyze all
purposes through a compatible shared oracle. What is invalid is silently
replacing exposed intersecting interfaces by independent random functions.

## 6. What changed and what remains to discharge

The new tests exercise the enlarged-query domain, strict/relaxed relation and
oracle compatibility, exact rational comparisons, null propagation, parser
rejection, and exhaustive small finite joint distributions. They establish
the stated evaluator and toy-model behavior. They do not establish a component
envelope or cryptographic security. Existing contracts, production code,
historical reports, and the earlier CI workflow are unchanged by this work.

The next proof artifact must bind the accepted implementation relation to a
specific formal IOR/VC/recursive construction, including all hash interfaces
and all allowed program/size branches. It must then provide error functions
valid over the lifetime query envelope. Until those premises and the
authoritative-version bridge are supplied, the complete-proof bound remains
`null`. Authorization and quantum work each still need their independent
arguments.
