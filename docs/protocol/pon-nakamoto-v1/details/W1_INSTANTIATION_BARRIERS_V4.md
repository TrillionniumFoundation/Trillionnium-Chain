# W1 actual-instantiation obligations and three unusable inference routes

Date: 2026-10-26. Source baseline: `5301a319d4011f24f808f8644583cb4322cdbc97`.
Status: **explicit route obstructions, a conditional transfer interface and exact
finite controls**. This does not instantiate SHA-256, establish a physical work
floor, or close the original O01/O02 obligations.

The previous [ticket-composition result](W1_TICKET_COMPOSITION_V3.md) is useful
inside its empty-table, captured-preprocessing ideal-cipher experiment. The next
step cannot be to attach an unexplained small `epsilon_SHA` and announce a
production work bound. This note proves why three tempting shortcuts do not
provide that step. It also specifies the narrower W1 event that an actual
instantiation argument would have to preserve.

No work function, hash, target, header, reward, challenge source or activation
rule changes. The accompanying [model](../../../../formal/pon-nakamoto-v1/experiments/w1_instantiation_barriers_v4.py)
and [tests](../../../../formal/pon-nakamoto-v1/experiments/test_w1_instantiation_barriers_v4.py)
are research controls. They are not a production eligibility mechanism.

## 1. A public SHA algorithm is not indistinguishable from an ideal oracle

Fix any message block b and chaining state h independently of the sampled ideal
family. Let `E_b(h)` be the public, deterministic SHA-256 round transformation
before feed-forward. Consider a test that computes `v=E_b(h)` locally, makes one
forward oracle query at `(b,h)`, and accepts exactly when the answer equals v.

In the actual-public-algorithm world it accepts with probability 1. For a fresh
independent 256-bit permutation family, it accepts with probability `2^-256`.
Its distinguishing advantage is therefore exactly

\[
1-2^{-256}.
\]

The test pays for one ordinary local evaluation and one oracle query. It does
not invert a standard-IV hash, find a collision, make a canonical W1 proof or
earn a ticket. The same argument applies to any fixed public deterministic
function with a cheaply computable output; it is not a new SHA weakness.

**Consequence.** An unrestricted transcript-indistinguishability assertion
between the public SHA program and independent random keyed permutations is the
wrong missing assumption. If that assertion permits the above test, its error
cannot be small. Ordinary ideal-model reasoning instead provides heuristic
evidence about selected application properties. Section 4 states a one-sided
W1 event comparison explicitly; it does not assume general indistinguishability.

The finite control enumerates every permutation on domains of size 2 through 6
and checks the exact acceptance law. A separate actual-SHA control uses the
retained [literal SHA implementation](../../../../formal/pon-nakamoto-v1/experiments/w1_sha256_model_boundary.py)
to perform the public comparison. The 256-bit probability is the mathematical
calculation above, not an experimentally measured frequency.

### 1.1 Counting a library interface is not counting all implementations

The control also hashes literal W1 noise and ticket messages, respectively 66
and 90 unpadded bytes. It first obtains comparison digests through `hashlib`, then
disables that interface and computes exactly the same digests with the retained
scalar SHA rounds. Each scalar computation performs two compression executions
and makes zero `hashlib.sha256` API calls.

This is a concrete instrumentation boundary. Zero calls through one observed
API does not imply zero logical or physical hash work. The scalar computation is
not claimed to be faster; it is deliberately ordinary. A proposed `Q_A` conversion
must include inline implementations, fused kernels, shared message schedules,
precomputation and nonuniform circuits permitted by its attacker class. Native
reference counters describe that implementation, not every possible producer.

## 2. Generic hash hardness does not supply the threshold lottery law

Let R be a random function from messages to `n-b` bits, with `1<=b<n`, and define
the hypothetical n-bit hash

\[
H_{n,b}(x)=0^b\,\|\,R(x).
\]

Use exactly the threshold `T=2^(n-b)-1`. Every output of this hash satisfies
`H(x)<=T`, whereas a uniform n-bit value satisfies that test with probability
`2^-b`. This discrepancy persists for tagged, length-delimited messages: domain
framing does not change the fixed output prefix.

The cryptographic properties of this counterfamily must be stated accurately.
For a target uniform in its declared image of size `N=2^(n-b)`, q distinct fresh
random-function queries hit the target with probability

\[
1-(1-1/N)^q\le q/N.
\]

Their exact collision probability is `1-(N)_q/N^q`, with the usual upper bound
`q(q-1)/(2N)` and probability 1 when q exceeds N. Adaptive fresh query choices
do not change these laws in this independent random-function experiment.
Taking, for example, `b=floor(n/4)` retains negligible preimage/collision success
for polynomially many queries as n grows, while threshold success is 1 rather
than exponentially small.

This counterfamily **does not preserve full n-bit concrete preimage or
collision strength**. For n=256,b=64 the random image has 192 bits: generic
preimage scale is 192 bits and birthday scale is 96 bits. Calling its security
“256-bit SHA security” would be false. The logical result is that unspecified
asymptotic one-wayness/collision resistance alone does not imply the required
uniform threshold distribution or a resource-to-winning-ticket law. A precise
stronger assumption might rule it out; it must be named and proved applicable.

Hypothetically replacing W1's hash family by this counterfamily would make
every otherwise valid proof meet that threshold. This supplies no shortcut for
the actual fixed SHA-256 W1 verifier, no valid actual-native winning packet and
no lower-cost canonical transcript algorithm. The test enumerates small random
function tables to check both the retained hash properties and the lottery
failure, instead of conflating the two.

## 3. Why the direct auxiliary-input presampling lift is presently vacuous

This section rejects one concrete attempted composition. It does not reject
auxiliary-input cryptography or prove that W1 cannot have a stronger advice bound.

The [rooted-path theorem](W1_ROOTED_CIPHER_PATHS_V1.md) gives, for P arbitrary
consistent initially fixed permutation pairs, the coarse capacity inequality

\[
m\le H+\lfloor Q/2049\rfloor
 \le P+\lfloor Q/2049\rfloor
\]

outside its newly created Join event. Here m counts distinct canonical challenge
openings and Q covers all captured calls after the fixed table is supplied. H
reserves all challenges associated with relevant seeded first edges. Seeded
cycles and aliases are why replacing H by `P/2049` is not licensed. The seeded
capacity statement already precedes the additional ticket-composition problem.

The relevant external theorem is Coretti–Dodis–Guo Theorem 1 [1]. In the
auxiliary-input ideal-cipher setting, S advice bits are supplied after unbounded
preprocessing. Its transfer uses **combined attacker and challenger queries**
`C_comb`, not attacker calls alone. With `gamma=2^-h`, its additive loss is

\[
12(S+h)C_{\rm comb}/P+2\gamma,
\]

and its multiplicative branch requires

\[
P\ge6(S+2h)C_{\rm comb},\qquad
\epsilon_{\rm AI}\le2\epsilon_{\rm BF}+2\gamma.
\]

The cited theorem requires state-space size at least 16 and `gamma>0`; the
native `2^256` space and the choices below satisfy those conditions.

Use the current complete-opening checker: its declared primitive-call cap is
`C_comb=Q+3594G`, where G covers all openings, including failed attempts, and the
source-derived 3,594 bound comes from v3's full header/material/noise/trace/ticket
check. Its query cost cannot be removed merely because the miner does not pay
it. Let `G>=1`, `S>=0`, and `h>=2`.

**Proposition: neither branch, directly applied to this coarse capacity
inequality and checker cap, yields a nontrivial capacity restriction.**

*Multiplicative branch.* Its minimum P is at least `24 C_comb`, hence exceeds G.
But `m<=G` by the definition of the opening cap. Consequently the would-be
capacity violation `m>P+floor(Q/2049)` cannot occur. The transferred capacity
upper bound admits every possible opening count; it says nothing about work
needed for those G openings.

*Additive branch.* If `P+floor(Q/2049)>=G`, the same problem occurs. If the
capacity violation is nonempty, then `P<G`. In that case

\[
\frac{12(S+h)C_{\rm comb}}P
\ge \frac{12h\cdot3594G}P>1.
\]

The transfer loss alone is already trivial before any bit-fixing failure term
is added. These alternatives cover every positive P. QED.

This is a statement about the specific coarse seeded allowance and combined
query cap. In fact, the same dichotomy survives the weaker inequality
`C_comb>=G`; only dropping the checker entirely would incorrectly evade it.
It is not an impossibility theorem for refined seeded graph arguments, direct
auxiliary-input analysis, different challengers or new protocols. The exact
integer/rational controls cover both alternatives, including P so large that the
additive loss is small but the capacity restriction has disappeared.

The 2026-05-01 full version of *How to Simulate Random Oracles with Auxiliary
Input* [2] develops efficient simulation of AI random functions using PRFs. It
is the full version of FOCS 2024 work, not a newly invented SHA instantiation.
Its oracle and computational simulation result do not supply the missing
bidirectional shared-permutation W1 event mapping or a positive physical cost
per query. The newer compressed-permutation work [3] likewise remains in an
ideal permutation/cipher setting. Neither paper is silently used as a numerical
W1 loss estimate.

### 3.1 What a useful next advice result would need to improve

The immediate research target is a substantially sharper bound on *useful*
seeded canonical opportunities, or a direct advice result for the native W1
predicate. It must account for seeded material aliases, shared trace paths,
multiple ticket interpretations, old winner credit and terminal checking. Merely
replacing the symbol P with S, or assuming every 2,049 fixed pairs buy exactly
one opportunity, contradicts the existing seeded-graph scope.

An unpredictable external salt can change an auxiliary-input game, but current
miner-selected headers/parents are not automatically such a salt. A salt-based
proposal would need an entropy/timing premise after advice is fixed, treatment
of all parallel parents and discarded choices, a literal new framing if the
protocol changes, and a proof that seeded material aliases do not survive the
salt into useful opportunity fanout. No such protocol change is adopted here.

## 4. The narrower actual-W1 transfer obligation

Let A range over an explicitly named class of actual classical implementations,
including its allowed inline SHA, arbitrary legal task structures, adaptive
inputs, all parallel parents, batches and retained state. Specify a finite
lifetime or reuse horizon. Its complete physical resource bounds form a vector,
not one unqualified scalar:

\[
\mathbf B=(\text{logical operations},\text{aggregate CPU time},
\text{memory byte-time},\text{system peak memory},
\text{transferred bytes},\text{energy}).
\]

The unit, measuring boundary and aggregation rule of each component must be
declared. CPU time sums over workers; wall time and peak memory do not sum in the
same manner. Public/outsourced initial information is an exposure allowance even
when its producer's cost was not paid by this miner. An omitted measurement is
unknown, rather than zero. A physical claim may restrict hardware to an explicit
class, but must say so; a measured x86 implementation does not bound all devices.

For fixed d,k and a fixed target T, define the actual outcome event

\[
E_{d,k}=\{W\ge K_0+k\;\land\;D_0\ge d\}.
\]

W counts distinct native block candidate identities; K0 is already exposed
winning capacity from the captured old canonical bank; D0 retires canonical
old paths whose lottery answers, including misses, have already been exposed.
Prepared paths with unseen lottery answers stay in preprocessing. This is not a
statement about subsidy consumption, finality or adopted Hepta model updates.

A usable reduction would have to provide all of the following, uniformly over
the declared actual class:

| Obligation | Required output and boundary |
| --- | --- |
| Resource conversion | Finite `Q_P( B_pre,F0 )` and `Q_A( B_online,F0 )` caps, or explicit conversion failures; include failed searches, inline/fused algorithms, shared work and every worker/parent/task |
| Exposure and checker | Predeclared G, V and explicit-reference caps covering old/new sealed openings, all discarded candidates and bounded no-feedback checking; V affects failure but is not miner-paid work |
| Chronological representation | A capped ideal-world adversary/event representation with full c/d/t references at v3's pre-answer times and a simultaneous immutable seal; support the actual initial-state/advice distribution |
| Event comparison | A one-sided bound for this native W1 outcome event, not an unrestricted public-SHA indistinguishability assertion |
| Identity transfer | Native identities and old/new bank accounting map to the comparison event; v3's fanout one does not prove money consumption or arbitrary proof-system fanout |

For clarity, a sufficient *unproved hypothesis* is that cap and identity failures
have probabilities at most `epsilon_cap` and `epsilon_id`, and for the resulting
capped comparison strategy B,

\[
\Pr_{\rm actual}[E_{d,k}\land\mathrm{GoodCaps}\land\mathrm{GoodIdentity}]
\le\Pr_{\rm IC}[E^*_{d,k}]+\epsilon_{\rm W1}.
\]

The comparison must use v3's legitimate distribution and attacker information;
it may not condition lazy sampling on selected favorable advice. The quantities
`epsilon_W1`, `epsilon_cap` and `epsilon_id` are **not supplied by this note**.
Writing this hypothesis only identifies the precise obligation. Assuming the
desired outcome law directly would not independently justify that obligation.

With `C=Q_P+Q_A+V`, `R=3C+2G+R_explicit`, and the original range conditions, the
already-proved ideal result then yields the conditional formula

\[
\begin{aligned}
n_d&=\left\lfloor\frac{Q_P-2049d+Q_A}{2049}\right\rfloor,\\
\bar p_T&=\min\left(1,\frac{T+1}{2^{256}-C+1}\right),\\
\delta&=\min\left(1,\frac{2C(C+R)}{2^{256}-C+1}\right),\\
\Pr_{\rm actual}[E_{d,k}]
&\le\min\{1,\operatorname{BinTail}(n_d,\bar p_T,k)
 +\delta+\epsilon_{\rm W1}+\epsilon_{\rm cap}+\epsilon_{\rm id}\}.
\end{aligned}
\]

Use the trivial bound 1 outside the nontrivial Join range. d and k are fixed
before the experiment; D0/K0 may be random. The formula never sets K0 to zero
because a run was called “cold,” never charges V as miner work, and never chooses
the most favorable realized budget after success. Additional independent
protocol assumptions require their own losses and accounting.

The executable calculation preserves unknown losses as `null`. Even explicitly
provided hypothetical numbers produce a **conditional formula only**, never an
`actual_protocol_bound_established` result. It rejects payment/encoding/model-
adoption counts and fanout other than the native one already proved in v3.
Toy digest/path sizes are labeled separately from the actual W1 geometry. The
helper enforces the development target limit, and declines large nontrivial
exact binomial expansions instead of fabricating a numerical answer; its
computation limit is not a theorem restriction on all finite query budgets.

## 5. Results and remaining closure requirements

The concrete progress is three rejected inference routes and an exact finite
interface which cannot quietly replace unknown losses with zero. The new tests
exercise public-function distinguishing, literal SHA outside one API counter,
threshold and cryptographic-property separation, both advice-lift branches,
old-bank retirement, auditor-versus-miner accounting, alternative count units,
invalid probabilities and exhausted nontrivial ranges. Exhaustive small-state
enumeration checks examples; the arguments above establish their stated general
scope. These controls are not performance measurements.

| Original obligation | Effect of this work |
| --- | --- |
| O01 actual W1 resources to opportunities | Still open. Whole-public-primitive indistinguishability and unspecified collision/preimage claims are ruled out as substitutes for a W1-specific resource/event argument. |
| O02 arbitrary adaptive/advice strategies | Still open. The particular coarse seeded-capacity plus CDG transfer route is proven uninformative with the complete checker; a useful refined advice result remains absent. |
| O03 production kappa and settlement | No production parameter follows from this note; the unknown actual-event and resource-conversion losses remain explicit. |
| O04 physical hardware | No new hardware, energy or bandwidth evidence is created. |
| O05/O07 optional mixed work or ZK | Not adopted; their own binding, unique consumption and amortized cost proofs remain required if adopted. |
| O06 Hepta product loop | No effect; valid work still does not establish useful model progress or adoption authority. |

## 6. Primary sources and exact use

[1] Coretti, Dodis and Guo, *Non-Uniform Bounds in the Random-Permutation,
Ideal-Cipher, and Generic-Group Models*, CRYPTO 2018, author full version dated
2023-02-02, definitions in section 2 and Theorem 1 in section 3:
https://cs.nyu.edu/~dodis/ps/ai-perms.pdf . Only its stated auxiliary-input/bit-
fixing transfer interface and constants are used. The vacuity proposition is
the source-specific algebra above; no actual-SHA theorem is imported.

[2] Dodis, Jain, Lin, Luo and Wichs, *How to Simulate Random Oracles with Auxiliary
Input*, full version dated 2026-05-01 of FOCS 2024, introduction and sections 2–3:
https://cs.nyu.edu/~dodis/ps/ro-sim.pdf . The ePrint metadata identifies this as a
major revision of that work: https://eprint.iacr.org/2026/854 . Used to check the
model and simulation scope, not as a W1 query/physical-cost theorem. The ePrint
PDF endpoint returned 403; the author-hosted full version was opened instead.

[3] Carolan and Majenz, *Compressed Permutation Oracles Revisited*, 2026-09-23:
https://arxiv.org/html/2609.28469v1 . Its ideal-permutation/cipher results do not
instantiate the public SHA program or this physical-resource game.

[4] NIST, *FIPS 180-4*, SHA-256 padding and round specification:
https://doi.org/10.6028/NIST.FIPS.180-4 . The actual scalar controls reuse the
previously checked implementation of these definitions; this specification
contains no claimed W1 cost lower bound.
