# W1 resource reduction: temporal extraction and composition controls

Status: **conditional mathematical implications and exact finite controls**.
Inspected native baseline: `4081bf6f397b74cf4f928e845259a18d68211181`.
This refines O01, O05 and O07 of the existing research obligations; it is not a
new development plan. The [sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [cost-security game](W1_COST_SECURITY_GAME.md) retain their authority.
No wire bytes, targets, chainwork, rewards, native task rules, signed domains,
production implementation or qualification flags are changed here.

The new result is a **conditional path from a temporally available canonical
prefix to valid lottery opportunities**, with the extractor's own costs included.
The previous cost-game section 9.3 concerned a fixed final batch. A batch lemma
alone cannot justify charging every lottery the cost of an eventual proof: the
miner may inspect the lottery and complete only its winners.

## 1. Actual W1 binding, with a narrow uniqueness consequence

The current [header codec](../../../../trillionnium/crates/trnm-protocol/src/pon_wire.rs),
[work relation](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
and [packet identity](../../../../trillionnium/crates/trnm-pon-node/src/lib.rs)
use these deterministic dependencies. `H_tag` is the existing length-framed
PON1 SHA-256 hash, not a newly deployed random oracle.

| Value | Actual input |
| --- | --- |
| Header bytes `h` | Fixed 318-byte PNH1 v1 encoding, including network, parameters, parent, height, timestamp, target, miner, transaction/state/receipt roots, task and nonce |
| Challenge `c` | `H_challenge(h)` |
| Task commitment `d` | `H_task(canonical_A, canonical_B)`, required to equal the header task |
| Canonical trace message `M(h,A,B)` | Existing 16-byte trace domain, `c`, then 32,768 canonical prefix words; 131,120 bytes total |
| Trace digest `t` | SHA-256 of that whole message; the intermediate words are not in the submitted PNW1 proof |
| Lottery value | `H_ticket(c,t)` |
| Native block identity | `H_block(h,t)` |

For a nonzero target integer `T`, the independent-uniform-ticket idealization
has inclusive success probability `p=(T+1)/2^256`. Native target zero is rejected.
This probability statement is conditional on the idealization and on fixing the
header/target before the relevant fresh lottery answer.

**Proposition 1 — one lottery input, at most one native block identity.**
Assume no collision among the relevant header-challenge hashes. Fix one input
`(c,t)` to the ticket hash. Any accepted header opening of `c` is the same `h`,
so its block identity is the same deterministic `H_block(h,t)`. Thus this input
has `L=1` for the count of distinct native block identities. The proposition
needs no assumption that different ticket outputs never collide: a collision
of ticket outputs is not another lottery input.

This agrees with the actual [store admission path](../../../../trillionnium/crates/trnm-pon-node/src/store.rs):
`check_admission_header_context` looks up an existing block id, requires the
same packet bytes (`DUPLICATE_CONTENT` otherwise), and returns the existing id.
It does not insert another block for a repeated packet. These facts do not prove
cross-fork reward consumption, canonical confirmation, external customer payment
or Hepta improvement. The research semantic-ticket hash is a separate observer
identity; it is not a new native reward rule.

Task-commitment binding additionally makes `A,B` fixed for a header, and the
canonical relation fixes the product, trace and PNW1 bytes. Proof uniqueness is
stronger than necessary for Proposition 1. A future randomized ZK encoding may
have many valid proofs for the same statement without creating another block,
but only if its lottery and credit rules preserve the two controls in section 6.

## 2. Resource contract, including initial state and nonuniform advice

A resource claim must name a classical adversary class, a resource unit and
finite caps before observing success. The table is an interface for a theorem,
not a declaration that W1 already satisfies its assumptions.

| Symbol | Required meaning |
| --- | --- |
| `P,S,F0` | Allowed preparation resource, retained state/code/advice size and complete public/private initial state; also state source, lifetime and dependence on oracles |
| `B` | Aggregate online producer resource, across workers, tasks, parent branches, failures and abandoned strategies |
| `Q_A` | Declared online oracle-query caps by domain; raw ticket queries include fabricated traces, early guesses and losing attempts |
| `G` | Cap on all complete submitted candidates, including unqueried lottery submissions and rejected outputs; never only eventual winners |
| `K0` | Upper bound on remaining credit capacity of initial already-revealed winning lottery inputs, even if their witnesses are unfinished |
| `U0` | Upper bound on initial prepared canonical trace opportunities whose lottery answer is still unseen; separate from `K0` |
| `L` | Maximum credited semantic identities per successful distinct lottery input; Proposition 1 supplies one only for its stated native identity count |
| `Nmax` | A finite cap on total credited identities, including the bad-event case, when an expectation bound is claimed |
| `epsilon` | Sum/union bound for explicitly named failure events, including extraction, binding, resource and instantiation failures |

All oracle-dependent advice, helper computations, public setup and supplied
parent/task material used by the reduction must have a captured origin. An
opaque source of prepared hash answers is not free oracle-independent advice.
In the ideal model one may allow bounded nonuniform code independent of the
sampled oracles, while charging/recording oracle-dependent preprocessing. For
actual SHA-256, which is fixed and public, that syntactic distinction does not
establish independence or eliminate specialized nonuniform circuits.

`K0` cannot be inferred as `S/256`. Compressed advice may describe many outputs,
and its relevant capacity depends on the game. Nor does a bounded advice string
prove that the work used to construct it was paid. A conservative recorded
ideal-game bound is to count every previously queried winning input's remaining
capacity, even when some have no known valid witness. `U0` can conservatively
include all trace-table candidates that might later acquire a valid opening;
it must also include any supplied prepared prefixes outside that table.

The allowed task and parent choices are those of the original game. A header
nonce, source, lease renewal, parent fork, batching decision or restart may not
reset the aggregate budget. Any input-supply restriction used by a theorem must
be stated; current miner-chosen transactions/headers cannot be relabeled an
unpredictable external round seed. An unbounded free verifier, helper, state
supply or query channel prevents a resource-only cap unless its effects are
separately bounded. Receiver admission CPU and post-run verification remain
receiver/auditor costs, not a physical lower bound charged to a producer.

## 3. Temporal extraction in an explicitly ideal model

**This section is about independent whole-message random-oracle domains.**
It is neither an ideal SHA-256 compression-function theorem nor a theorem about
arbitrary implementations of actual SHA-256. A query presents the complete
message bytes or a charged explicit byte stream. A compressed-description oracle
is a different interface. The real protocol's use of one SHA-256 algorithm with
different framing does not itself establish the independent-domain assumption.

Use independent ideal functions for task, challenge, noise, trace and ticket
hashing. The canonical prefix relation is unchanged, with noise supplied by its
own domain. Capture the full preparation and online history. Count all prior
oracle-dependent public setup and helpers in that history. Count terminal
private verification queries separately; they reveal no information to the
producer before its final batch is fixed. Live verification feedback requires
its own accounted interaction, not this batch endpoint.

Let `Q_C,Q_D` be complete caps on distinct challenge and task oracle queries,
including initial public setup and at most `G` terminal openings in each domain.
Let `Q_P^tr,Q_A^tr` count trace queries by preparation and the producer, and
`Q_P^lot,Q_A^lot` count their ticket queries. Set

`Qtr = Q_P^tr + Q_A^tr + G`,
`R = Q_P^lot + Q_A^lot + G`.

`G` conservatively allows one canonical trace and one lottery completion per
candidate during terminal checking. It is not charged as producer work.

**Lemma 2 — early availability of accepted lottery inputs.** From before the
captured preprocessing, exclude the following events:

| Bad event | Conservative probability numerator, over `2^lambda` |
| --- | --- |
| A collision among captured/terminal trace responses | `choose(Qtr,2)` |
| A collision among challenge or task responses | `choose(Q_C,2)+choose(Q_D,2)` |
| A newly opened header challenge matches a previously used ticket challenge with no earlier header opening | `Q_C*R` |
| A newly opened task digest matches a task reference in an earlier queried header with no earlier task opening | `Q_D*Q_C` |
| A correctly matched trace digest was guessed in a lottery reference before its canonical trace query | `R` |

The sum, clipped at one, is a sufficient `epsilon_ROM` in this **captured,
independent-domain game**. It is conservative, not an optimal cryptographic
bound. It is not a bound conditioned on an arbitrary favorable precomputed
state. Hidden oracle-correlated advice invalidates the premise.

Here is the extraction argument. At each first fresh ticket query `(c,t)`, use
already opened task/header bindings and the prior trace table. If a matching
trace-table digest exists, emit that message with its claimed opened instance
*before returning the ticket answer*. The emitted message may be incorrect;
no free verifier is supplied. The primitive enumeration problem below counts
only its correct distinct outputs. A correct eventual ticket whose header/task
opening was unavailable at this point would require a late match or a binding
collision. If its canonical trace was unavailable, the guessed `t` is an attempt
to predict an as-yet unseen independent canonical trace value. All `R` early
references, including discarded guesses, must be counted. If its canonical
trace was already queried, absence of trace collisions makes the matching
record the correct message. Direct final submissions are handled by their
terminal fresh lottery completion, using only producer/preparation trace records
already present before the submission deadline. The auditor's newly computed
canonical messages are never credited as producer-generated prefixes.

Each fresh oracle response is uniform conditional on its prior history, which
bounds the collision/late-reference events by their possible pairs. For the
trace-guess term, binding fixes the canonical input before the lottery answer;
unrevealed noise values can be fixed independently of the trace/ticket domains.
Repeated guesses for one still hidden trace are all counted: at most `r` chosen
values can cover `r/2^lambda` of that trace's possible values. Shared inputs and
adaptive stopping do not turn the cap into the number of selected winners.
These arguments apply to the stated recorded oracle experiment, not a physical
SHA implementation or an unaudited real initial state.

The distinction is executable. In a trace space of eight values, first query
lotteries for four distinct trace guesses; let each lottery succeed with
probability one half. Then compute the true trace and submit only if its guess
was a hit. There is at most one final submission, yet acceptance probability is
`(4/8)*(1/2)=1/4`, greater than the incorrect temporal guess bound `G/8=1/8`.
This does not refute the old **batch** lemma: that lemma never promised availability
before earlier lottery answers.

## 4. A resource transfer that pays for the extractor

Define a separate **canonical-prefix enumeration problem**. A solver may choose
all tasks/headers/parents, retain advice, batch instances and use preprocessing
allowed by the declared W1 game. It outputs candidate tuples containing the
opened instance and the complete canonical prefix message. Count `m` correct,
distinct new tuples beyond the prepared `F0` supply; invalid candidates may be
output, but their processing/output costs are paid. This is a target-independent
computation problem. It does not define one reference multiplication as a
mandatory unit of work.

A useful lower-bound hypothesis must cover this adaptive, multi-instance
problem, with the actual enlarged preprocessing/memory limits `P',S'` of the
extractor. Suppose it gives, except with failure `epsilon_pref`,

`W_enum >= ell*m - d(P',S',F0)`, with `ell>0`.

Neither that hypothesis nor a usable positive value of `ell` is established for
W1. A single-instance distributional bound, different activations, or observed
reference operation counts do not supply this multi-instance hypothesis.

Separately suppose a resource-preserving simulation/extractor satisfies

`W_enum <= a*B + b + h_correct*m + h_candidate*E`, where `E <= Emax`.

`b` includes explicitly bounded recording, lookup, binding and validation costs
not otherwise charged; it is not assumed small or independent of raw query caps.
`E` counts **all candidate extractions**, including incorrect prefixes selected
by cheap invalid ticket queries. One may use `Emax <= Q_A^lot+G` for fresh online
emissions in the stated construction. Copying candidates is not free. Keeping
pointers instead requires persistent accessible message storage and a matching
primitive output/resource model. Logging discarded streams and preparation
queries also changes `P',S'` and must be accounted for.

**Proposition 3 — conditional transfer.** If `ell>h_correct`, then

`m <= M = floor((a*B+b+d+h_candidate*Emax)/(ell-h_correct))`.

This follows by subtracting the charged `h_correct*m` term from the two
inequalities. If `ell<=h_correct`, they provide **no finite resource bound**.
The executable returns `None`, not zero or an invented unit floor. A specialized
extractor with `E<=m+e` may move its per-candidate term into the denominator and
charge `h_candidate*e` in the numerator, but must prove that inequality. The
basic extractor above does not supply it: most candidates can be wrong.

This exposes an otherwise circular argument. If the sole alleged lower bound
is writing `ell` words per correct transcript, and the extractor itself writes
those words, then `h_correct=ell` cancels the claimed bound. In the general
candidate form, a copying charge at least `ell*E` with `E>=m` is similarly unable
to tighten the independent candidate cap merely by counting output bytes.
The original compact-digest producer did not retroactively pay the extractor's
materialization or the receiver's verification cost.

Let `M` be established with its stated failure probability, and put

`n = min(U0+M, Q_A^lot+G)`.

Outside the listed failures, every newly counted valid lottery is among at most
`n` fresh opportunities whose canonical status is fixed before its ticket
answer. `K0` covers prior revealed winning inputs; initial losing inputs do not
become fresh trials by replay. Correct but previously unseen lotteries can be
prepared in `U0`, so omitting that term is also unsound.

For fixed target probability `p` and integer `k>=1`, the conditional consequence is

`Pr[N >= K0+L*k] <= Pr[Binomial(n,p) >= k] + epsilon`, clipped at one.

For a finite `Nmax`, also

`E[N] <= min(Nmax, K0+L*n*p + epsilon*Nmax)`.

Use predictable marking, stop at the declared opportunity cap, and pad with
independent dummy trials for this domination argument. **Do not condition on a
future good event and then assert that the remaining distribution is still
binomial.** The cap-violation/extraction failures are added outside the stopped
comparison. The same unweighted domination works when each predictable success
probability is at most `p`; adaptive difficulty and actual chainwork require the
separate weighted/chain argument. These formulas do not establish canonical
chain security or replace an honest resource-to-opportunity guarantee.

### 4.1 What actual SHA-256 would still need

An actual-protocol claim needs an explicit **resource-preserving, temporal SHA
extraction/instantiation assumption** for the chosen adversary class: a real
producer must be mapped to the stated ideal-domain experiment with bounded
`P',S',a,b,h_correct,h_candidate,Emax` and failure `epsilon_SHA`. It must preserve
preprocessing, adaptive selections, hidden shared computations, first lottery
answer times and outputs. Merely replacing a named hash function in notation is
not such a map. Ordinary collision/preimage resistance does not imply recovery
of all hashed prefix bytes before a lottery query at a usable resource cost.

Total failure must include `epsilon_SHA + epsilon_ROM + epsilon_pref`, plus any
extra eligibility/credit/interaction assumptions. The published SHA-256
algorithm specification [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)
specifies the hash; it does not prove this extractability or a physical cost floor.
No value for `epsilon_SHA`, `ell`, or a cross-hardware W1 advantage bound is
estimated here. A finite native benchmark provides constructive producer costs,
not these missing lower bounds. In particular, native observers, database
admission and duplicate checks in the budget harness cannot be charged as a
minimum cost an arbitrary miner must pay.

## 5. Proof after winning: an exact O05/O07 composition obstruction

Suppose a future useful-work/ZK design has these dependencies: useful computation
costs `u>0`; its result exposes a lottery with success probability `p`; publication
of a hit additionally requires a proof costing `z>=0`. Assume, favorably, exact
constant costs, no sharing and independent lotteries. If misses need no proof,
then an untruncated useful attempt has expected cost

`u+p*z`,

and the first fully proven winner has expected cost `u/p+z`, for `p>0`.
Charging `u+z` per lottery would instead predict `(u+z)/p` for that winner. Requiring
a proof before **publication** does not move its cost before lottery inspection.
A cap on the number of completed pairs may remain correct while the inference
that those completed pairs form an unbiased capped lottery sequence is false.

The exact finite-budget control retains this difference without borrowing work
from a future cohort. For `B=36,u=z=9,p=1/2`:

| Schedule | PMF for 0, 1, 2 credited outcomes | Expected credited count |
| --- | --- | --- |
| Pay useful+proof before every lottery | `[1/4,1/2,1/4]` | `1` |
| Inspect useful-result lottery; prove only hits | `[1/8,5/8,1/4]` | `9/8` |

An unaffordable proof creates zero credited outcomes. The dynamic program is
checked against independent complete coin-space executions. It specifies this
schedule, not an optimal adversary or a deployed W1/ZK implementation. Its
finite-budget ratio need not equal the ratio of first-win expected costs.

Likewise two component cost lower bounds imply only their **maximum** absent
an additional non-overlap/direct-sum property. In the unit-operation-set control,
two ten-operation predicates using the same ten operations cost ten jointly;
separate labels do not make the cost twenty. Consuming a useful result once on
a winning floor nonce still does not force useful recomputation after each
failed nonce; the existing cost-game section 8.3 proves that separate point.

A proposed mixed mechanism must therefore fix the dependency order, failed-work
reuse, overlapping computation, preprocessing and complete finite-budget counting
before selecting a floor fraction. A proof-cost component can be charged before
each lottery only under a real dependency and cost argument establishing it.
Putting random proof bytes in the lottery to obtain such a dependency introduces
the separate grinding surface below.

## 6. Statement consumption and proof randomness require two controls

Consider a fixed semantic statement with `r` independently valid proof encodings.
The following exact ideal-lottery cases distinguish two protocol choices. All
variants attest the same statement; the finite model does not assert that a
particular deployed proof system permits cost-free randomization.

| Lottery input includes proof bytes? | Credit key includes proof bytes? | Distinct trials | Result for one statement |
| --- | --- | --- | --- |
| No | No | `1` | At most one credit, success probability `p` |
| Yes | No | `r` | At most one credit, but success probability `1-(1-p)^r` |
| No | Yes | `1` | One successful answer can fan out to `r` credited keys |
| Yes | Yes | `r` | Distinct proof trials and credit keys; expected credits `r*p` in this finite model |

For `r=4,p=1/2`, retaining one statement credit but hashing proof randomness into
the lottery raises its success probability from `1/2` to `15/16`. Final-credit
deduplication alone does not stop lottery grinding. Excluding proof randomness
from the lottery alone does not stop a credit key that still counts proof files.
Changing a miner identity, signature, wrapper or randomized commitment inside the
challenge can create the same issue unless its work dependency is charged.

**Proposition 4 — scope-limited consumption.** In one ledger execution with an
atomic check-and-insert into a monotone spent set, an injective canonical key for
a fixed useful statement permits at most one successful insertion. This is a
set invariant, independent of how many valid proof encodings are offered. It
requires both a stable key and atomicity. If the key includes the parent/epoch,
the same statement can be consumed once **per parent/epoch**. If the set is reset
or rolled back, monotonicity no longer holds across that boundary. A local cache,
a collection of independently spent sets or a reorganization test does not by
itself establish cross-fork or permanent economic consumption.

**Proposition 5 — fixed-statement randomized-proof independence.** Assume proof
soundness, binding canonical statement identity, a lottery input determined by
that statement alone, and an at-most-one-credit monotone rule at the intended
scope. Changing only valid proof randomness creates neither a new lottery input
nor a new semantic credit. This is an algebraic/interface consequence, not a
proof of witness-generation cost or of a concrete future proof system's security.
Aggregation can still cover several distinct statements, and distinct genuinely
statement-bound challenges remain distinct opportunities whose joint costs need
the resource theorem. O05/O07 production implementation and composition remain
open until those actual rules and security arguments are supplied.

## 7. Latest primary literature: usable interfaces and limits

[Wong, Ciampi and Sarkar, PoML, arXiv v1, 2026-10-19](https://arxiv.org/html/2610.26713v1)
uses circuit depth in Definitions 1 and 11, explicitly assumes prover independence
in Appendix F.2, and introduces a joint completed-pair cost condition in F.3.
The latter is an additional premise, not a direct consequence of individual
depth bounds. F.3 also allows a lottery to depend on the inference result before
publication of its proof. Section 5 above shows why that ordering needs a
predictable opportunity analysis. The framework is useful for specifying the
interface to a chain theorem; it does not establish W1's resource assumptions.
Its different-activation argument is not by itself a lower bound on shared
computation. These are scope/gap observations about a new preprint, not a claimed
implementation exploit or a refutation of all conditional PoML results.

A depth lower bound alone cannot be substituted for an operation-count lower
bound. In a circuit model, `w` copies of the same depth-`d` chain can produce `w`
identical outputs with `w*d` gates in a redundant reference. A shared chain with
fanout has the same depth and uses `d` gates; explicitly charged output-copy
costs can be added to both. Preserving the depth does not preserve the reference
work. Similarly, appending distinct public labels makes outputs different without
making their shared expensive core independent. These are logical countermodels,
not claims that a particular neural model has exactly this structure.

[Komargodski and Weinstein, ESA 2026](https://doi.org/10.4230/LIPIcs.ESA.2026.2)
provides a construction-specific correlated-prefix assumption; the existing
cost game records its applicability limits for W1's compact transcript and
adaptive batches. [Ball, Rosen, Sabin and Vasudevan, CRYPTO 2018](https://eprint.iacr.org/2018/559)
proves properties of its particular low-degree-polynomial construction, not a
universal matrix or SHA work lower bound. The official abstract of
[It Takes Two: Proofs of Work for Fiat-Shamir, 2026/2326](https://eprint.iacr.org/2026/2326)
separates stronger PoW properties from non-amortization in the relevant verifier
setting; its full PDF was inaccessible during this increment, so no new
full-paper theorem from it is imported here. Fresh Fiat-Shamir challenges and
correct proof verification do not by themselves prove every prover operation
has to be repeated before every lottery.

## 8. Executable acceptance and the still-open completion standard

Run the existing project preflight, then:

```sh
python3 -B formal/pon-nakamoto-v1/experiments/test_w1_resource_reduction.py -v
python3 -B formal/pon-nakamoto-v1/experiments/w1_resource_reduction.py
```

The [new model](../../../../formal/pon-nakamoto-v1/experiments/w1_resource_reduction.py)
uses exact `Fraction` arithmetic and imports the existing finite binomial
utilities. Its [controls](../../../../formal/pon-nakamoto-v1/experiments/test_w1_resource_reduction.py)
check native header/hash framing against the independent wire oracle, early
trace screening, extraction overhead cancellation, prepared banks, finite proof
gating, proof-randomness grinding/fanout and consumption scope. Independent
small enumerations check the probability distributions. These are unit controls,
not timing runs; no performance data are collected.

| Obligation | Result of this increment | Remaining closure requirement |
| --- | --- | --- |
| Temporal digest-to-prefix implication | Proved for the captured independent whole-message model with explicit query/guess/binding terms | A usable actual-SHA temporal extraction/instantiation argument for the declared adversary class |
| Prefix-to-opportunity resource transfer | Algebraic conditional bound, with all-candidate extraction cost and an unavailable result when its denominator is nonpositive | An independently supported adaptive multi-instance prefix lower bound with preprocessing/advice and a useful extractor cost gap |
| One lottery input to distinct native block identities | `L=1` conditional on header-challenge binding, with actual store duplicate behavior inspected | Separate actual economic consumption, chain and eligibility rules at their intended scope |
| Inference/proof/floor composition | Exact counterexample to charging proof cost on every result-first miss; conditional disjointness/consumption rules | A concrete production composition and non-amortization/dependency argument, including failures and branches |
| Randomized proof encoding | Exact separation of lottery grinding from final-credit fanout; conditional invariant when both use stable statement identity | Concrete sound proof system, statement/lottery/credit integration and adversarial tests on that implementation |

The global O01/O05/O07 blockers remain open. Their closure requires premises
that hold for the actual protocol and adversary class, quantitative parameters
that produce a useful budget-to-ticket result, and the separate native/chain
integration evidence. Finite test success cannot establish the nonexistence of
a faster algorithm, remove an unknown SHA instantiation failure, or turn a
reference/harness cost into an adversarial physical lower bound.
