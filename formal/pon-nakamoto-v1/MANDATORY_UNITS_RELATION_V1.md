# MU1: mandatory full W1 units and a conditional query certificate

Status: frozen research relation, version 1, **unactivated**. This file specifies
an explicit relation for the fixed-target / variable-unit candidate. It adds no
native header, admission, chain selection, persisted identity set, or activation
rule. Its research credit `16u` is **not** the current native
`required_work(target)`. No native identity/weight bridge has been established.

The new results are a complete executable relation using actual full PNW1
units, differential execution against the existing native examples, and a
self-contained conditional quantum **query** bound for distinct aggregate
winners. They do not prove the minimum gate, energy, memory, or time cost of
producing those units. They do not qualify any native confirmation depth,
including the existing six-successor semantics.

## 1. Frozen parameters and exact namespace

| Item | MU1 version 1 |
| --- | --- |
| Hash domain | ASCII `TRNM-PON-MU1` followed by one zero byte |
| Profile | ASCII `pon-mandatory-w1-64-research-v1` |
| Context magic / packet magic | `PMH1` / `PMU1` |
| Version | unsigned little-endian 16-bit integer `1` |
| Full unit relation | PNW1, `N=64`, `R=8`, field modulus `4294967291` |
| Unit proof size | 49,188 octets |
| Allowed units | integer `1 <= u <= 8` |
| Unit verifier target | 32 octets of `ff`; no additional unit lottery |
| Aggregate target | big-endian 256-bit `T0 = 2^252 - 1`, inclusive |
| Research credit | `16u`; maximum identity credit 128 |

For tag `t` and ordered byte strings `v_1,...,v_r`, define

```text
MU(t; v_1,...,v_r) = SHA256(
    "TRNM-PON-MU1\0" || LE16(len(t)) || t ||
    LE32(len(v_1)) || v_1 || ... || LE32(len(v_r)) || v_r
)
```

Tags are ASCII bytes and fixed at each use. All lengths must fit their stated
unsigned fields. There is no alternative serialization or optional proof
randomness. `RELATION_PARAMETERS` is `MU("parameters"; PARAMETER_BYTES)`, where
the exact parameter bytes are:

```text
PROFILE || 00 || LE16(1) || LE32(64) || LE32(8) ||
LE32(4294967291) || LE32(49188) || LE16(1) || LE16(8) ||
LE32(16) || BE256(2^252 - 1) ||
"PNW1\0ordered-indexed-full-transcript\0single-final-ticket\0"
```

The code fixing these bytes is
[mandatory_units_relation.py](mandatory_units_relation.py). Changing the
relation, transcript order, domain, encoding, target, allowed unit range, or
credit law requires a new version/namespace and new evidence.

If the terminal hash is modeled as an independent uniform 256-bit random
function, an unqueried fixed terminal input is marked with probability

\[
p=(T_0+1)/2^{256}=1/16.
\]

This cardinality calculation does not prove that actual SHA-256 is a random
oracle or that adaptively chosen tickets are independent Bernoulli trials.
The executable implementation uses actual SHA-256. The conditional theorem
below explicitly replaces its terminal domain by an ideal oracle.

## 2. Canonical context and packet

Every verifier receives an **externally supplied expected context**. Extracting
an expected context from an untrusted packet and then calling the verifier is
not authentication of that context. MU1 checks syntactic window membership;
it does not authenticate an anchor, select eligible task material, check a
native parent state, or establish admissible network timestamps.

The context has the following fields in this exact order. Hash-like fields are
exactly 32 raw octets; they have no alternative string form on the wire.

| Field | Encoding |
| --- | --- |
| magic, version | `PMH1`, `LE16(1)` |
| relation parameters | 32 octets, equal to the fixed digest above |
| network, chain parameters, window anchor | 32 octets each |
| window start height, window end height | `LE64` each |
| parent | 32 octets |
| height, timestamp | `LE64` each |
| miner/reward owner | 32 octets |
| transaction root, state root, receipts root | 32 octets each |
| aggregate target | 32 octets, exactly `BE256(T0)` |
| nonce | `LE64` |
| unit count `u` | `LE16`, in `[1,8]` |
| ordered task commitments | exactly `u` consecutive 32-octet values |

The height must satisfy `start <= height <= end`. The context is exactly
`368 + 32u` octets. Every integer is an unsigned integer of its stated width.
No trailing octets or overlong encodings are allowed. Python convenience
objects also reject booleans as integers, mutable task lists, and non-byte
hash fields; these checks are local API hygiene, not extra wire choices.

Let `C` be this canonical context, `d = MU("context"; C)`, and `task_j` its
task at zero-based index `j`. The challenge for unit `j` is

\[
c_j=\operatorname{MU}(\texttt{unit};d,\operatorname{LE16}(j),task_j).
\]

Thus nonce, unit count, task order, target, parent, miner, roots, window,
timestamp, network, and parameters all enter every unit challenge. The
binding implication against adversarial collisions is conditional on the
corresponding hash-binding assumption; tests show actual concrete fixtures,
not a proof that all unequal contexts have unequal digests.

The packet is exactly

```text
PMU1 || LE16(1) || C ||
for j = 0,...,u-1:
    LE16(j) || task_j || canonical_PNW1_j
```

Unit indexes must be contiguous and in this order. The task in each record
must equal the context task. A unit record is `2 + 32 + 49188 = 49222`
octets. The complete packet size is

\[
L(u)=6+(368+32u)+49222u=374+49254u.
\]

The maximal packet has 394,406 octets. A smaller packet, omitted unit,
duplicated index, swapped record, extra octet, wrong version, changed fixed
target, or different expected context is refused. A valid prefix of a packet
at one `u` is not the same attempt at another `u` because `u` and the entire
ordered task list are in every unit challenge.

## 3. What every full W1 unit must verify

Each 49,188-octet PNW1 proof is

```text
PNW1 || A[4096] || B[4096] || product[4096] || trace_digest[32]
```

All matrix values use canonical little-endian 32-bit field elements strictly
below `4294967291`. The existing task commitment is recomputed from `A,B`.
The full existing W1 algorithm derives the challenge-dependent low-rank
noise, executes the specified 512 cumulative tile updates in their fixed
order, hashes the complete ordered tile stream, and recomputes the denoised
product. Both the resulting trace digest and every product field element
must equal the submitted values. Only the final trace **digest**, not the
whole tile stream, is serialized; full verification recomputes the stream.

Normative implementation references are the existing full relation in
[pon_work.rs](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
and the independent scalar specification [work_oracle.py](work_oracle.py).
The evidence records their exact source hashes. A noise-expansion budget
failure is a refusal; no alternate successful transcript is substituted.

MU1 calls the full unit verifier with `ff...ff` as the **unit** target. This
retains the complete PNW1 relation without requiring each unit to win its own
`T0` lottery. Passing a cheap syntax/task/hash filter is not valid work. The
reference verifier finishes every unit check before testing the aggregate
target, so the negative controls can distinguish an invalid unit from a
valid-unit aggregate loser. This order is not a performance requirement for
a future implementation that preserves the same complete predicate.

For fixed `A,B,c_j`, field values, trace, denoised product, and bytes are
deterministic. The producer has no legal blinding field or optional encoding
that supplies extra aggregate tickets for the same full unit output. For a
fixed task commitment, extending uniqueness to `A,B` additionally needs task
commitment binding. Colliding task material is not ruled out by the fact that
the encoding is canonical.

Repeated task commitments and repeated matrices are deliberately **allowed**.
Prepared multiplication results can be reused honestly across units, nonces,
and contexts. `PreparedMatrices` caches `AB` and the PNW1 matrix prefix once;
each new unit challenge supplies its new complete trace. Four implementations
are compared byte-for-byte: fresh scalar, prepared scalar, fresh native,
and native `PreparedTask`. Rejecting literal copied traces does not establish
that every legal algorithm must redo all reference operations or cannot
amortize them. That all-algorithm cost question remains open.

## 4. One aggregate predicate and unique research credit

For the ordered full unit proofs `P_j`, define

\[
\begin{aligned}
\ell_j&=\operatorname{MU}(\texttt{unit-output};\operatorname{LE16}(j),task_j,P_j),\\
r&=\operatorname{MU}(\texttt{ordered-units};d,\ell_0\Vert\cdots\Vert\ell_{u-1}),\\
t&=\operatorname{MU}(\texttt{ticket};d,r),\\
id&=\operatorname{MU}(\texttt{identity};d,r).
\end{aligned}
\]

A packet passes MU1 exactly when its expected context/framing and **all** full
units pass, and `t <= T0`. Its research credit is then `16u`. None of the
unit tickets supplies additional credit or additional lottery gates.

`inspect_packet` only parses/binds/hashes. Its return value is explicitly not
a valid-work result. `verify_packet` returns `VerifiedUnits`, a local
mathematical result with no native admission authority. `UniqueWorkCounter`
reverifies every input and increments credit only for an identity not already
in its one in-memory set across all supplied branches. Repeated delivery and
shared prefixes do not generate new research credit. This set is not a
consensus spent set, durable anti-replay mechanism, or reorganization policy.

**Deterministic terminal-input implication.** If two credited identities
differ, their pairs `(d,r)` differ, because an identical pair under the fixed
`identity` tag deterministically yields the same identity. Consequently
distinct credited identities imply distinct terminal lottery inputs under
the fixed `ticket` tag. This direction requires no injectivity assumption.
Hash collisions can collapse identities; they do not invalidate this
implication. No mutable delivery label or proof-external owner identifier may
be added to identity while being omitted from the terminal input.

**A limited byte result.** If a resource model charges every raw octet of each
canonical serialized packet, then for distinct accepted packets

\[
W=16\sum_b u_b\le\frac{16}{49254}\sum_bL(u_b).
\]

The executable helper implements this format bound with rational arithmetic.
It does not lower-bound compressed communication, gates, FLOPs, energy,
elapsed time, or data already held by another participant. Reference execution
contains `512u` tile updates, but that instruction count is an upper-cost
description of one algorithm, not a lower bound on every algorithm.

## 5. Explicit ideal query game

The following theorem concerns an ideal terminal random oracle and research
credit. It grants all valid unit construction and all nonterminal work for
free. This is a stronger attacker than any MU1 producer in this model, and
therefore makes a valid but deliberately conservative reduction. In
particular it does not recover a lower cost proportional to `u`.

The game requires all of the following conditions.

1. The terminal table is an independent uniform 256-bit random function on
   the finite terminal-input domain. Distinct domain-separated nonterminal
   tables are independent of it and may be given for free. A query combining
   terminal and other domains must still be charged conservatively as a
   terminal query or explicitly simulated; domain separation does not hide
   the terminal component of a coherent query.
2. At the start of the **entire charged computation**, the joint algorithm,
   advice, helpers, and auxiliary state are independent of that terminal
   table. Arbitrary oracle-independent computation is free. Mixed states,
   classical randomness, intermediate measurements, adaptive scheduling,
   and retained classical/quantum states are included by purification and
   retaining the transcript. Unitaries other than oracle queries cannot
   operate directly on the inaccessible oracle-reference register.
3. `Q` counts all relevant full-value terminal queries over that lifecycle:
   preprocessing, batching, selection, retained-state preparation, public
   helpers, and any verifier/acceptance feedback that informs future
   production. All participants providing such information can be treated
   as one joint algorithm if their relevant queries are charged. The bound
   is not based on adversary-only online queries. A concurrent query batch
   can be serialized for a total-query budget; this supplies no depth or
   wall-clock guarantee.
4. At most `M` complete output candidates are emitted. This is a real bound
   on the whole output transcript, including failed candidates, not the
   number of accepted packets retained after filtering. At the end, at most
   `M` **virtual** membership checks are allowed to extract successful
   outputs. These are proof accounting, not a claim that the adversary paid
   them. They do not permit unlimited uncharged online acceptance feedback.
5. Credit is counted once per identity using this same research relation and
   `16u <= 128`. Changing eligibility, identity, or weight requires a new
   mapping. A fixed terminal input cannot be credited repeatedly merely by
   delivery to different branches or observers.

`QueryBudget` checks the shape of the numerical declaration. Its boolean
flags do not establish that a physical execution actually satisfied these
conditions. It expressly refuses uncharged preprocessing, uncharged public
help, an unspecified output cap, or a fresh-game restart with qualified or
unqualified oracle-correlated advice. The finite helper limits `Q <= 4096`
and `M <= 64` bound evaluation cost, not the scope of the mathematical proof.

## 6. Self-contained conservative quantum tail

### 6.1 From full values to Bernoulli bits

Let `S1` be the 256-bit values at or below `T0`, and `S0` its complement.
Sample independent `f(x) ~ Bernoulli(p)`, where `p=1/16`, and independent
stable tables `g1(x)` uniform on `S1` and `g0(x)` uniform on `S0`. Then

\[
H(x)=g_{f(x)}(x)
\]

is exactly a uniform random function and its threshold predicate is exactly
`f`. Give `g0,g1` to the attacker for free. One reversible full-value `H`
query is simulated by computing `f(x)` in a clean bit, XORing `g_f(x)` into
the answer, and uncomputing that bit: at most **two** bit queries. Hence a
`Q`-query full-value algorithm is included in a `2Q`-query Boolean algorithm.
The implication is in the direction needed for an upper bound on success.

### 6.2 Global recording-weight recurrence

Purify the independent Bernoulli table. At each coordinate use the real
self-inverse matrix

\[
U=\begin{pmatrix}\sqrt{1-p}&\sqrt p\\\sqrt p&-\sqrt{1-p}\end{pmatrix}.
\]

In the dual/recording basis, its initial state is all zero. Putting the
query-answer qubit in the Fourier basis makes a Boolean query either the
identity or, on the addressed table coordinate,

\[
UZU=\begin{pmatrix}1-2p&c\\c&2p-1\end{pmatrix},
\qquad c=2\sqrt{p(1-p)}.
\]

Let `P_{>=i}` project onto global dual-table Hamming weight at least `i`, and
`a[n,i] = ||P_{>=i} psi_n||`. Oracle-free joint operations commute with this
projector. One oracle query changes at most one table bit. The crossing block
from exact global weight `i-1` into weight at least `i` has norm at most `c`.
For a superposition of query addresses this is a direct sum over the address
register, so no sum over domain size is introduced. The lower-weight block
cannot reach `i` in one query. The triangle inequality gives

\[
a[n+1,i]\le a[n,i]+c\,a[n,i-1].
\]

Initially `a[0,0]=1` and `a[0,i]=0` for `i>=1`. Pascal induction and the unit
norm of the joint state yield

\[
a[N,i]\le\min\{1,\binom Ni c^i\},\qquad
\binom Ni=0\text{ for }i>N.
\tag{1}
\]

This is a joint-state norm statement, not an independent-trials assertion
about selected oracle outputs or a statement about a private reduced state.

### 6.3 Adaptive distinct outputs and the selected-coordinate projector

For an output register containing `k` distinct addresses, let `Xi_i` be the
output-controlled projector onto exactly `i` recording-basis ones among
**those k addresses**. It is not exact global weight `i`: unselected
coordinates may have other excitations. Nevertheless `Xi_i <= P_{>=i}`.

The success projector, after changing these coordinates back to the standard
table basis, requires all `k` selected bits to be one. At selected weight
`i`, the row has `binom(k,i)` entries of absolute value
`p^((k-i)/2)(1-p)^(i/2)`. Thus its restricted operator norm is

\[
d_i=\sqrt{\binom ki}p^{(k-i)/2}(1-p)^{i/2}.
\]

The construction is a direct sum over distinct output tuples; unselected
coordinates undergo a unitary. Its norm therefore remains `d_i` for adaptive
addresses and for the whole coherent workspace. An invalid/failure output
flag is annihilated by the success projector. Using the decomposition by
`Xi_i` and (1),

\[
\Pr[\text{k distinct selected marked inputs}]
\le \min\left\{1,\left(\sum_{i=0}^{\min(k,N)}d_i a[N,i]\right)^2\right\}.
\tag{2}
\]

One exact rational upper envelope replaces `sqrt(binom(k,i))` by
`binom(k,i)` in the unsaturated consequence of (1):

\[
B_1(N,k,p)=\min\left\{1,
p^k\left[\sum_{i=0}^{\min(k,N)}
\binom Ni\binom ki[2(1-p)]^i\right]^2\right\}.
\tag{3}
\]

A second applies Cauchy--Schwarz to at most `k+1` nonnegative terms while
retaining the norm saturation in (1):

\[
B_2(N,k,p)=\min\left\{1,(k+1)
\sum_{i=0}^{\min(k,N)}\binom ki p^{k-i}(1-p)^i
\min\left\{1,\binom Ni^2[4p(1-p)]^i\right\}\right\}.
\tag{4}
\]

Both are valid upper bounds, so `B = min(B1,B2)` is also valid. For `k=0`
the bound is one. They can be loose or completely vacuous; no nontriviality
is inferred merely from finite input space or a finite calculation.

### 6.4 At most M complete candidates and weighted credit

After the output transcript is fixed, append at most `M` Boolean membership
queries. Select a fixed canonical list of `k` distinct successful terminal
inputs if it exists, otherwise emit a failure flag. This is a legal algorithm
with

\[
N=2Q+M.
\]

It succeeds whenever at least `k` distinct credited MU1 identities exist;
granting it even invalid-unit candidates can only enlarge that event. There
is no post-hoc free choice of a successful subset or omitted union factor:
the virtual queries pay for extraction. Distinct identity implies distinct
terminal input by Section 4. Since each identity has credit at most 128,

\[
\boxed{\Pr[W\ge x]\le
\begin{cases}
0,&k>M,\\
B(2Q+M,k,1/16),&0\le k\le M,
\end{cases}\qquad k=\lceil x/128\rceil.}
\tag{5}
\]

This is a full-lifecycle ideal-query tail for unique research credit. It
allows arbitrary unit selection, batching, legal preparation reuse, and
stateful quantum strategies over that lifecycle because all unit work is
free and all oracle information must be charged. It does not imply that
larger `u` is paid for by proportionally larger physical resource use.

Under hard total `Q,M` caps, stopping at the first credit crossing gives the
same bound for a finite-horizon crossing event; increasing horizons gives
the corresponding anytime event by monotone convergence. The cap and the
initial independent state are not reset at each horizon or confirmation.
An unconditional global tail is not a bound on conditional confirmation
failure after an arbitrarily selected history.

For example, the purely mathematical choice `Q=1`, `M=32`, `x=4096` has
`N=34`, `k=32`; (3) is one and (4) is approximately
`0.06575603822076288`. This is an exact-rational model calculation with a
displayed decimal approximation. It is not a native rollback probability,
an observed attacker success rate, or a risk estimate for six successors.

For a classical-only query algorithm, each first visit to a new terminal
input is a fresh Bernoulli trial in this ideal model. Repeated inputs add no
unique successes, so the sharper classical envelope is the binomial tail
with at most `Q+M` trials, and zero if `k>M`. It is invalid to apply this
classical formula to coherent quantum queries.

## 7. Correlated residual state: explicit conditional interface

Starting at a later time does not erase oracle information. A private
reduced density matrix does not describe all joint correlations with the
oracle reference, helpers, public information, or retained registers.
Fresh-game `QueryBudget` therefore continues to reject a correlated start.

The same recurrence does provide an additional, conditional interface. If
an external proof supplies joint recording-tail norm bounds
`a[0,i] >= ||P_{>=i} psi_initial||`, then induction gives

\[
a[N,i]\le\min\left\{1,
\sum_{j=0}^{\min(N,i)}\binom Nj c^j a[0,i-j]\right\}.
\tag{6}
\]

For the induction at `i=0`, the upper expression remains `a[0,0]=1`; for
`i>=1` Pascal's identity combines the old layer and its one-step crossing.
Insert (6) into the **untruncated** selected-coordinate inequality

\[
\Pr[\text{k distinct selected marked inputs}]
\le\min\left\{1,\left(\sum_{i=0}^{k}d_i a[N,i]\right)^2\right\}.
\]

The upper limit `min(k,N)` in (2) was justified by the fresh initial state's
zero support above record weight `N`; it must not be retained for an
oracle-correlated initial state. In particular a known winner can have
positive initial record weight with zero new queries. This requires only a
profile through layer `k` for a `k`-success event; it does not require
inventing a certificate for all possible classical descriptions of residual
state.

The executable `residual_bernoulli_bound` takes rational squared-norm upper
bounds `b_i >= ||P_{>=i} psi_initial||^2`, not a private-state statistic.
It validates the finite tuple's shape: `b_0=1`, `0<=b_i<=1`, nonincreasing.
That validation does **not** prove the input certificate is true. For

\[
J_i=\{0\le j\le\min(N,i):b_{i-j}>0\},
\]

another Cauchy inequality supplies an exact rational upper bound

\[
\widehat b_{N,i}=\min\left\{1,
|J_i|\sum_{j\in J_i}\binom Nj^2[4p(1-p)]^j b_{i-j}\right\},
\]

where an empty sum is zero. The implemented probability upper bound is

\[
\min\left\{1,(k+1)\sum_{i=0}^k
\binom ki p^{k-i}(1-p)^i\widehat b_{N,i}\right\}.
\tag{7}
\]

With `b=(1,0,...)`, each nonzero convolution has one term, so this exactly
recovers the fresh saturated branch (4). With unrestricted `b_i=1`, it
returns one. Knowing a winning address at the later start can allow certain
success with zero new queries: the recording profile of a known standard
table bit equal to one is `(1,1-p)`, not `(1,0)`. The tests retain this
negative control explicitly.

There is no actual W1 residual-state certificate here. Nor does the finite
terminal input space supply a useful initial potential merely because some
astronomical finite upper bound exists. An application must prove its
profile or operator certificate at the exact event cut, show the resulting
tail is useful for its declared budgets, and account for future public
information. For random starts, such a statement must be justified under
the appropriate conditional law; selecting a favorable history does not
establish it.

## 8. Native evidence, controls, and reproducibility

The bridge is the existing
[pon_work_io example](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs)
for fresh production and complete verification, and the existing
[pon_zero_io example](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs)
`generic` mode for `PreparedTask`. Native verification emits the existing
receipt bound to the exact challenge, task, target, and proof bytes. The
Python wrapper checks that binding and a zero native exit. Missing binaries,
invalid modes, failed subprocesses, malformed receipts, and partial output
refuse. There is no successful stub or silent fallback.

The fixtures use full-size deterministic dense matrices and a zero task.
They do not claim random workload sampling, full rank, numerical model
utility, or a cost lower bound. They mine five complete MU1 contexts:
repeated dense tasks at `u=1,2,4,8`, plus an ordered dense/zero pair. Every
attempted nonce, aggregate ticket, unit proof hash, and losing result is
retained. The first-winner stopping rule and fixture selection mean their
observed winning fraction is **not** an estimator of independent SHA success
probability. Native calls used to generate losing attempts remain in the
same call log.

The complete-relation negative controls include nonce/parent/miner/anchor/
state-root rebinding, noncanonical field values, correct trace with wrong
product, correct product with wrong trace, copied unit proof, renumbered
proof reorder, repeated wire index, omitted unit, smaller-`u` prefix reuse,
mixed-task reorder, outer-winning fabricated trace, and complete valid
units whose aggregate ticket loses. The fabricated-trace control prevents
confusing the aggregate hash filter with verified mandatory work. The cache
control positively demonstrates lawful product preparation reuse rather
than pretending all reuse is prohibited.

From the repository root, after building the existing release examples,
run the required-native tests as follows:

```bash
MU1_NATIVE_WORK="$CARGO_TARGET_DIR/release/examples/pon_work_io" \
MU1_NATIVE_PREPARED="$CARGO_TARGET_DIR/release/examples/pon_zero_io" \
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p mandatory_units_tests.py -v
```

Both environment variables must point to existing executables. Omitting
one is a test failure, never a successful skip. To create durable detailed
evidence in a fresh output directory:

```bash
python3 formal/pon-nakamoto-v1/mandatory_units_evidence.py \
  --native-work "$CARGO_TARGET_DIR/release/examples/pon_work_io" \
  --native-prepared "$CARGO_TARGET_DIR/release/examples/pon_zero_io" \
  --out evidence/pon-work-native-certificates-20261107/mandatory_units
```

The evidence runner creates files exclusively and refuses to overwrite a
previous run's observations. It records actual native child exchanges,
including expected nonzero rejections; the count covers that evidence run,
not separate unittest or other agents' executions. Exact source/binary
hashes, full positive packets/contexts, negative-control outcomes, all nonce
attempts, query arithmetic, and residual interface examples accompany its
summary. Timing observations are not minimum-cost certificates.

## 9. Qualification boundary and remaining scientific obligation

| Claim | This deliverable |
| --- | --- |
| A concrete context/nonce/unit-order-bound relation exists | Specified and executable |
| Each accepted unit passes the actual complete PNW1 predicate | Native/scalar differential evidence |
| Four tested producer paths give one canonical packet | Byte-for-byte evidence on full-size fixtures |
| Duplicate research identity cannot add unique research credit | Explicit in-memory accounting rule |
| Distinct credit identities map to distinct terminal inputs | Deterministic implication |
| Ideal full-lifecycle query tail with bounded output count | Equations (1)--(5), exact arithmetic |
| Conditional joint residual-tail propagation | Equations (6)--(7); actual initial certificate absent |
| Raw canonical packet-byte credit bound | Limited serialization model only |
| Actual SHA-256 satisfies the ideal random-oracle model | Unproved |
| Every actual algorithm pays a minimum cost for `u` units | Unproved |
| Quantum/classical memory, energy, time, or gate resource tail | Unproved |
| Actual production/preparation/public-help budget certificate | Unproved |
| Current native identity and weight equal MU1 identity and `16u` | No bridge; unactivated new research relation |
| Native availability, timestamps, delay, stock, and fork mapping are instantiated | Not established by this query theorem |
| Existing six-successor confirmation has a certified risk | False |
| Production/security qualification | False |

Closing the first physical-work obligation still requires a minimum-resource
reduction for **all** allowed algorithms and their preparation/reuse/batching
strategies, or another sufficiently strong actual relation. Merely executing
all reference operations, rejecting copied transcripts, or proving a black
box query theorem does not supply that reduction. Closing the native safety
obligation additionally requires the same accepted relation, identity,
completion clock, and weight on both sides of the event inclusion, plus
the native parameter/network/inventory certificates. Fresh global oracle
arithmetic cannot retroactively qualify the current six-successor rule.

## 10. Research provenance

The recording-basis method and Bernoulli multi-solution problem have primary
research precedent in Cojocaru, Garay, Kiayias, Song, and Wallden,
[Quantum Multi-Solution Bernoulli Search with Applications to Bitcoin's
Post-Quantum Security, Quantum 7, 944 (2023)](https://quantum-journal.org/papers/q-2023-03-09-944/).
The formulas used here are derived in Sections 6--7 and were independently
reviewed against the declared game. No unverified displayed constant from
that paper is imported, and no publication-error claim is made. Its Bitcoin
model is not assumed to be this repository's native chain rule.

The [existing work-scale security contract](WORK_SCALE_SECURITY_CONTRACT_V1.md)
continues to supply the broader qualification boundary. This new relation
and query calculation resolve a concrete interface and a restricted oracle
model result; the unresolved physical and native obligations remain explicit.
