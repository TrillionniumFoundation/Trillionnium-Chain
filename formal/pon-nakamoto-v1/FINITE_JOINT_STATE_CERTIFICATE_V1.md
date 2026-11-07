# FJS1: exact finite joint initial-state domination

## 1. Result and qualification

FJS1 verifies a complete, explicitly supplied finite classical-oracle/quantum-
advice state. It checks an operator-order witness against one oracle-independent
reference state and transfers an independent-state search bound with a proved
multiplicative loss and an optional explicit positive excess. The checker uses
exact rational arithmetic, including singular positive semidefinite matrices.

This is an advance over merely accepting a claimed residual-tail vector: all
oracle tables, their prior probabilities, and their conditional density
matrices are present and checked. It is a certificate of the supplied
mathematical model. Its input is not an authenticated description of a real
worker, helper, clock, storage device, or environment. No experiment in this
component measures or prepares a quantum state.

The implementation is
[finite_joint_state_certificate.py](finite_joint_state_certificate.py); its
independent exact controls are
[finite_joint_state_tests.py](finite_joint_state_tests.py). The earlier
[joint recording-tail arithmetic](mandatory_units_query.py) and
[finite retained-advice obstruction](CERTIFICATE_OBSERVABILITY_V1.md) retain
their meanings. FJS1 neither replaces the native work relation with a finite
search game nor supplies an actual resource simulation theorem.

The new namespaces are `pon-finite-cq-initial-state-certificate-v1` and
`pon-finite-cq-initial-state-report-v1`. They do not change any signed domain,
stored native schema, work credit, or confirmation rule. Actual state coverage,
future help coverage, counterfactual budget enforcement, SHA/Poseidon
idealization, physical resource loss, native weight correspondence, native
six-successor risk, and production qualification remain false in every report.

## 2. Complete input model

Let the terminal mark oracle have addresses `0,...,D-1`, with independently
sampled marks of probability `p`, where `0 < p < 1`. Its complete table is

\[
f\in\{0,1\}^{D},\qquad
\pi_f=p^{|f|}(1-p)^{D-|f|}.
\tag{1}
\]

The mathematical register `F` holds this classical table. A coherent query
leaves `F` unchanged and applies the controlled mark-bit XOR oracle
`|x,b> -> |x,b XOR f(x)>`. The register `A` includes all initially retained
systems that may later influence the declared strategy, including helpers and
their entangled shares. For each complete table the input supplies a density
matrix `rho_f` on the same joint space `A`:

\[
\rho_{FA}=\sum_f\pi_f |f\rangle\langle f|\otimes\rho_f,
\qquad \rho_f\succeq0,\quad \operatorname{Tr}\rho_f=1.
\tag{2}
\]

Classical `F` does not restrict the receiver to classical queries or classical
advice. The matrices `rho_f` may contain off-diagonal coherence and entanglement
between declared advice registers. A classical sampled oracle with conditional
quantum advice is exactly a cq state of this form. A model with an additional
purification accessible to the strategy must include that accessible system
in `A`; discarding it is a different input model.

The input also supplies one density matrix `sigma_A`, one exact rational
`lambda >= 1`, and, for every table, a positive semidefinite matrix `Delta_f`.
The reference state is the same for every `f`:

\[
\omega_{FA}=\rho_F\otimes\sigma_A,
\qquad
\rho_F=\sum_f\pi_f|f\rangle\langle f|.
\tag{3}
\]

The verifier checks, block by block,

\[
\Delta_f\succeq0,\qquad
\lambda\sigma_A+\Delta_f-\rho_f\succeq0,
\qquad
\epsilon_*:=\sum_f\pi_f\operatorname{Tr}\Delta_f\le\epsilon.
\tag{4}
\]

The declared excess allowance satisfies `0 <= epsilon <= 1`. It is only a cap:
the reported probability uses the recomputed `epsilon_*`. Matrices `Delta_f`
need not be density matrices or have trace at most one individually. Their
positivity and weighted trace, not an unverified smoothing label, pay the
additive loss. FJS1 does not identify this particular witness convention with
a standard smooth-entropy distance parameter.

Every table has positive prior mass. Therefore every table must occur exactly
once, in index order, with its exact probability from (1). Table index bit `i`
is the mark at address `i`; index zero is the all-unmarked table. Checking only
normalization, an observed support, or the tables reached by one run is
insufficient and is refused. A row-specific `sigma_f` has no accepted encoding.

The checker accepts real rational symmetric density matrices. These are
ordinary complex-Hilbert-space density matrices with real entries. The
transfer theorem below applies to arbitrary subsequent complex quantum
operations. Complex-valued initial matrix entries require a different
encoding/checker; they are not rounded or silently discarded here.

## 3. Transfer theorem, including positive excess

**Theorem.** Assume (1)--(4). Fix one subsequent strategy whose initial
oracle-correlated information is entirely contained in the declared `FA`
state. All additional oracle-correlated information must arise from the
counted queries. Suppose this same strategy satisfies its hard query and
complete-output caps on every input path, including when initialized with the
reference state `omega`. Let `E` be its success event under the same complete
oracle/output relation. If its reference-state success probability is at most
`B`, then

\[
\boxed{\Pr_{\rho}[E]\le\min\{1,\lambda B+\epsilon_*\}.}
\tag{5}
\]

**Proof.** Form the positive block matrix

\[
\Delta_{FA}=\sum_f\pi_f |f\rangle\langle f|\otimes\Delta_f.
\]

Equations (3)--(4) give

\[
\rho_{FA}\preceq\lambda\omega_{FA}+\Delta_{FA},
\qquad \operatorname{Tr}\Delta_{FA}=\epsilon_*.
\tag{6}
\]

Keep classical outcomes, retained memories, output history, and aborts in the
computation. For the fixed strategy, the subsequent evolution is one CPTP map
`T` on this joint input. An oracle query is a controlled unitary on `F` and
the query registers; the fact that its action depends on `f` does not give
different maps for the actual and reference experiments. Adaptive measurements,
classical control, local computation, and communication inside the declared
joint system also give the same linear map in both experiments.

Complete positivity preserves (6). The final success test is an effect
`0 <= M_E <= I`, allowed to examine `F` and the final output history in the
mathematical experiment. Hence

\[
\begin{aligned}
\Pr_{\rho}[E]
 &=\operatorname{Tr}\bigl(M_E T(\rho_{FA})\bigr)\\
 &\le\lambda\operatorname{Tr}\bigl(M_E T(\omega_{FA})\bigr)
      +\operatorname{Tr}\bigl(M_E T(\Delta_{FA})\bigr)\\
 &\le\lambda B+\operatorname{Tr}T(\Delta_{FA})
  =\lambda B+\epsilon_*.
\end{aligned}
\]

The last inequality uses positivity, `M_E <= I`, and trace preservation. A
trace-nonincreasing successful branch can instead be completed with an abort
outcome. It still bounds the **unconditioned mass** of success; normalizing a
postselected branch is not a linear CPTP operation and is not justified by
this argument. Clipping at one proves (5).

When `epsilon_* = 0`, positivity and strictly positive prior masses force
every `Delta_f = 0`. In that case (6) is pure domination and
`D_max(rho_FA || omega_FA) <= log_2(lambda)`. This is the operator-order
definition and data processing property of max-relative entropy, not a new
entropy theorem; see Datta's Definition 1 and Lemma 7 in [1]. The direct proof
also makes explicit why the positive-excess convention is sufficient without
relying on a smoothed-entropy normalization convention.

For `lambda=1` and zero excess, each positive matrix `sigma-rho_f` has trace
zero, so every `rho_f=sigma`. Thus an exact loss-one certificate really proves
independence **inside the supplied complete cq model**. A measured local
marginal does not establish that this is the complete model.

This is a theorem for every subsequent strategy satisfying the stated model
and uniform caps. It is not a theorem that an actual unobserved adversary
satisfies those caps or that the input matrices came from actual execution.

## 4. The reference search event and its recomputed bound

The admitted event is: at least `k` distinct marked addresses appear among at
most `M` complete outputs, after at most `q` coherent mark-bit queries.
Complete outputs include the entire intermediate publication history and
blind guesses. Actual acceptance or membership feedback used later is a
query; the external mathematical success test is not free online feedback.
Let `m=min(M,D)`.

With oracle-independent initial advice and `q=0`, the whole output list is
independent of `F`. Its maximum success probability is exactly

\[
B_0=\sum_{j=k}^{m}{m\choose j}p^j(1-p)^{m-j}.
\tag{7}
\]

Duplicate addresses are removed without an oracle query. A shorter list
cannot have greater success probability; padding it to `m` distinct addresses
establishes the upper bound and a fixed full list achieves it.

For `q>0`, the
[existing recording theorem](MANDATORY_UNITS_RELATION_V1.md), implemented in
`mandatory_units_query.bernoulli_bounds`, bounds the event that a strategy
outputs `k` specified distinct marked addresses. One retained exact rational
upper bound is

\[
R_1(q,k,p)=
\min\left\{1,
p^k\left(\sum_{i=0}^{\min(k,q)}
{k\choose i}{q\choose i}[2(1-p)]^i\right)^2\right\}.
\tag{8}
\]

The second implemented rational branch keeps the saturation of the recording
tail and applies Cauchy--Schwarz:

\[
R_2(q,k,p)=\min\left\{1,(k+1)
\sum_{i=0}^{\min(k,q)}{k\choose i}p^{k-i}(1-p)^i
\min\{1,{q\choose i}^{2}[4p(1-p)]^i\}\right\}.
\tag{9}
\]

Set `R=min(R_1,R_2)`. For every fixed `k`-subset of output indices, copying
those addresses to the final output does not query the oracle; missing or
invalid slots abort that subset. The union of these fixed-index success
events covers a list containing at least `k` distinct marked addresses. Thus

\[
B_q\le\min\{1,{m\choose k}R(q,k,p)\}.
\tag{10}
\]

No virtual oracle calls are charged merely to identify the successful subset
in the analysis. The code recomputes these branches; it does not accept an
arbitrary caller-supplied `B` or a report label as a proof.

Independently of any advice or strategy, success requires the full oracle to
have at least `k` marks. Its exact probability is

\[
U=\sum_{j=k}^{D}{D\choose j}p^j(1-p)^{D-j}.
\tag{11}
\]

FJS1 first caps the reference bound by (11), then reports
`min(1,U,lambda*B+epsilon_*)`. If `k>m`, the event is impossible even with
positive excess, so the reported value is zero. If `k=0`, its value is one.

The query unit is exactly a Bernoulli mark-bit query. There is no conversion
from time, gates, energy, CPU usage, SHA-256 compression calls, Poseidon2
permutations, or native block weight in this interface. The finite event is
not automatically the full W1 or MU1 work event. Any such application still
requires the separate relation, extraction, oracle simulation and resource
proofs, with all their losses.

## 5. Exact verification and encoding rules

The JSON object has exactly the following top-level fields:

| Field | Checked meaning |
| --- | --- |
| `schema` | Exact FJS1 certificate namespace |
| `oracle` | Exact complete Bernoulli law namespace, `D`, and rational `p` |
| `advice_registers` | Ordered unique register names and dimensions; their product is the joint matrix dimension |
| `reference_state` | One common symmetric PSD trace-one matrix `sigma` |
| `multiplier` | Exact rational `lambda >= 1` |
| `excess_allowance` | Exact rational `epsilon` in `[0,1]` |
| `tables` | All `2^D` indexed prior/rho/Delta blocks |
| `search_contract` | Exact global probability scope, mark-bit query interface, and `q,M,k` |

Every rational is a reduced object with integer `numerator` and positive
integer `denominator`. Booleans, floats, numeric strings, unreduced fractions,
unknown fields, and nonfinite JSON constants are rejected. Duplicate JSON
keys are rejected by the file reader. The table row has exactly `index`,
`probability`, `advice_state`, and `positive_excess`.

The finite check limits are `1<=D<=8`, joint advice dimension at most 16, at
most eight named tensor factors, `q<=4096`, and `M,k<=64`. Input integer
numerators and denominators have at most 256 bits, including each explicitly
encoded table probability. Exact intermediate fractions are bounded at 8192
bits. Exceeding these limits produces an explicit refusal, never rounding,
table omission, or a fallback probability. JSON file inputs are capped at
16 MiB. This explicit representation is exponential in `D` and is not an
enumeration of the actual terminal hash domain.

For a real symmetric matrix, the PSD test visits exact rational pivots. A
negative pivot rejects. A zero diagonal in a PSD matrix must have a zero row,
because every corresponding two-by-two principal minor is `-a_ij^2`.
Otherwise a positive pivot permits the exact Schur complement. Recursing
proves equivalence to PSD and counts rank, including singular matrices. No
float, eigenvalue tolerance, or positive-definite-only Cholesky rule is used.
Independent tests compare it with **all principal minors** on every one of
729 symmetric three-by-three matrices with entries in `{-1,0,1}`. Additional
controls include rational Gram matrices and nonzero off-diagonal entries of
size `10^-40` next to a zero diagonal.

Reports bind the full canonical certificate with SHA-256 and include the
recomputed prior, each matrix/slack rank, weighted excess, complete reference
search bound, transfer result, scope, and unchanged qualification flags.
`recheck_report` recomputes the entire report and compares its complete
canonical encoding. This detects changed results or claims relative to the
provided input. It does not authenticate an input's publisher or provenance.

## 6. Explicit examples and adversarial controls

The evidence command writes all input matrices and all reports for five
complete finite models. Their zero-query successes can be independently
computed by exact Born probabilities. The examples are mathematical
computations, not quantum hardware executions.

| Model | Verified witness | Exact explicit-strategy success | Reported upper bound |
| --- | --- | --- | --- |
| Independent singular `\|+>` state, `D=4,p=1/16` | `lambda=1,epsilon_*=0` | A fixed address has probability `1/16` | `1/16` |
| Noisy first-winner advice, `D=4,p=1/16` | `lambda=11/8,epsilon_*=0` | `43583/524288` | `11/128` |
| Coherent first-bit advice, `D=2,p=1/16` | `lambda=2,epsilon_*=0` | `31/256` | `31/256` |
| Full truth-table advice, `D=4,p=1/16` | `lambda=16,epsilon_*=0` | `14911/65536` | `14911/65536` |
| Rare state outside a singular reference support, `D=2,p=1/16` | `lambda=1,epsilon_*=15/256` | `31/256` | `31/256` |

For noisy first-winner advice, let `j(f)` be the first marked address, or zero
if none is marked. The state is

\[
\rho_f=\tfrac78 I_4/4+\tfrac18|j(f)\rangle\langle j(f)|,
\qquad\sigma=I_4/4.
\]

Its largest eigenvalue is `11/32`, so `lambda=11/8` is valid. Measuring the
address basis yields success
`(7/8)p+(1/8)(1-(1-p)^4)=43583/524288`, below `11/128` and strictly above the
fresh one-output value `1/16`. The improvement over a generic dimension-four
loss uses the complete stipulated noisy channel. Observing a noisy-looking
sample would not establish that channel.

For coherent first-bit advice, use `|+>` when `f(0)=1` and `|->` otherwise.
Both density matrices have the same computational diagonal. They do not have
the same full state; a diagonal-only checker would wrongly accept loss one.
The common reference `I_2/2` needs loss two. Measuring in the `+/-` basis and
outputting address zero on `+`, address one on `-`, achieves `1-(1-p)^2`.

The two-register control uses Bell states `|Phi+>` and `|Phi->` to encode the
first oracle bit at `p=1/2`. Each receiver-only marginal is `I_2/2`, while a
joint Bell measurement distinguishes the bit. A reduced input can correctly
certify independence of that reduced model and still omit the helper that
raises the two-address search success from `1/2` to `3/4`. The full joint
model refuses loss one and accepts loss two. Accordingly no register list
or successful PSD check turns the actual-coverage flag true.

For positive excess, set `sigma=|0><0|`, and provide `rho_f=|1><1|` only on
the table `f(0)=0,f(1)=1`; otherwise set `rho_f=sigma`. A positive excess
`Delta_f=|1><1|` on that table, zero elsewhere, pays exactly `(1-p)p=15/256`.
With no excess, no finite multiplier can make this singular reference cover
the orthogonal state. An allowance smaller by even `2^-100` is rejected.
Negative excess eigenvalues cannot cancel the trace charge.

Additional controls reject incomplete tables, changed but still normalized
priors, duplicated or reordered indices, table-dependent reference states,
bad traces, non-PSD matrices, malformed exact fractions, unrecognized
schemas/interfaces, and any attempt to insert physical qualification fields.
Report mutation tests alter the bound, source hash, query count, verified
status, and false qualifications; all must fail complete recomputation.

Finally, conditioning the coherent example on the observed `+` outcome
proves `f(0)=1`, giving conditional success one. The global `31/256` is not
a bound at that selected start. FJS1 rejects a conditional scope string and
does not infer a fresh prior from a new process, empty cache, or new log.

## 7. Reproduction, retained sources, and failures

Run from the repository root:

```sh
python3 formal/pon-nakamoto-v1/finite_joint_state_tests.py -v
python3 formal/pon-nakamoto-v1/finite_joint_state_certificate.py \
  --evidence-dir /absolute/path/to/new-fjs1-attempt
```

The evidence directory must be new. It contains complete certificates,
recomputed reports, original rejected certificate inputs and their actual
refusal codes, exact zero-query measurement results, relevant source hashes,
and a file-by-file manifest. The four relevant source files are hashed before
example construction and again after all checks. Both endpoint lists are
retained; unequal lists reject with `SOURCE_BINDINGS_CHANGED_DURING_EVIDENCE`
and cannot produce a PASS summary or manifest. A negative test changes real
bytes in a private source copy between these reads and checks the retained
failure. Endpoint equality does not attest which module bytes were loaded,
exclude an undetected change-and-restore between reads, or authenticate
execution. `loaded_module_execution_attested` therefore remains false.

If an attempted check fails, its written inputs
and a `failed-attempt.json` remain; it does not receive a PASS summary. It
never falls back to a native fixture, a synthetic execution receipt, a new
oracle prior, or a weaker hidden qualification.

Recheck a retained input/report pair:

```sh
python3 formal/pon-nakamoto-v1/finite_joint_state_certificate.py \
  --certificate /absolute/path/to/noisy-first-winner.certificate.json \
  --report /absolute/path/to/noisy-first-winner.report.json
```

`--output` writes a new complete report and refuses overwriting an existing
file. The retained repository run is under
[joint-state evidence](../../evidence/pon-joint-state-risk-ledger-20261107/joint-state/).
Source hashes identify the exact checked implementation; they authenticate
neither the real-world source state nor an observer's honesty.

## 8. Remaining bridge obligations

The finite checker closes the mathematical task of verifying an explicit
complete cq-state domination witness and transferring its loss to the
declared marked-list game. It does not close the user's actual initial-state
obligation. That requires evidence that the supplied model covers every
relevant retained register and environment, and that future helping channels
are included or separately charged. A signed state description, a benchmark,
a classical process snapshot, and a local density marginal do not prove it.

Nor does this prove that actual SHA-256 or Poseidon2 output tables have the
independent distribution (1), that a physical algorithm is resource-simulated
with the declared `q`, or that all hidden complete work has been extracted
within `M`. A valid work packet can be copied; a correct signature does not
prove its computation cost. Physical costs for all legal algorithms and
complete lifecycle budgets remain distinct obligations.

Native failure probabilities additionally require the actual relation/weight
bridge and the same-law clock, availability, hidden-inventory, honest-progress,
and repeated-start conditions. The FJS1 global scope supplies none of those
from local observations. It is not passed to the native risk promotion gate
as if it were an authenticated complete deployment state.

## 9. Primary sources and provenance of the argument

1. Nilanjana Datta,
   [Min- and Max-Relative Entropies and a New Entanglement Monotone](https://arxiv.org/abs/0803.2770),
   IEEE Transactions on Information Theory 55(6), 2009;
   [author manuscript](https://arxiv.org/pdf/0803.2770), Definition 1, equation (6),
   and Lemma 7, equations (19)--(20). These give the operator-order definition
   of max-relative entropy and its CPTP data processing property. FJS1 uses
   this existing principle and gives its complete application above; it does
   not claim a new information-theoretic primitive.
2. John Watrous,
   [The Theory of Quantum Information](https://jhwatrous.github.io/TQI.pdf),
   2018 author draft, Sections 2.2 and 2.3. The channel and measurement
   framework explains the common CPTP map and positive success effect used
   in the proof. No text or manuscript file is redistributed here.

These sources were checked on 2026-11-07. They support the general
information-theoretic transfer, not an actual hash, deployment state,
measurement provenance, physical-work lower bound, or whole-chain security
certificate. The code, strict finite representation, application bound,
counterexamples, and qualification boundaries above are this component's
explicit deliverable.
