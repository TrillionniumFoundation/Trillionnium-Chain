# Grouped fresh-work floor research v0

Status: **research HOLD, actual chainwork zero**. This is a successor experiment
to the [legal-work audit](GROUPED_WORK_FAIRNESS_AUDIT_V0.md), on the same
[grouped Cell operator](GROUPED_CELL_OPERATOR_V0.md). It neither replaces W1 nor
registers a production work profile. It adds an explicit security computation;
it does not prove that useful neural arithmetic itself has an adequate minimum
cost. No benchmark result changes that distinction.

The [resource-transfer continuation](GROUPED_RESOURCE_TRANSFER_V0.md) adds an
explicit shared verification owner, independent-receiver fanout accounting and
classical/quantum finite counterexamples. It also strengthens one limitation:
the lawful cached producer constructively refutes a positive fresh business
contraction floor for the current cache scope. It retains this exact seal
relation and does not grant production qualification.

## 1. What the relation changes

The earlier audit bound candidate fields but allowed one cached correct Cell
product to obtain additional hash-only lottery queries. Merely hashing more
metadata would preserve that property. This research profile fixes
`pon-grouped-int257-sealed-research-v0`, exactly 16 ordered requests, the existing
three-expert/three-output int257 operator, and exactly **64** security steps.

The business relation still includes real router scores, lowest-index argmax,
stable gathers, selected expert results, scatter and predictions. Coefficients
are the pinned signed integer matrices, inputs retain their bias8 convention,
and exact i64 semantics remain fixed. Merging, exact factor execution, sparsity
and properly scoped activation reuse remain lawful. The experiment deliberately
reuses a sparse-merged business product across all admitted nonces; its fresh
neural contraction count is zero after the preparation has been charged.

For a canonical candidate challenge `c` and the unique correct grouped statement
commitment `s`, the extra relation is:

```text
z0 = H_fresh("seed", profile_hash, c, s)
zi = H_fresh("step", profile_hash, c, u16_be(i), z(i-1)), i = 1..64
ticket = z64
```

The ticket is the endpoint itself. There is no new lottery hash over randomized
proof bytes, signature bytes, JSON whitespace or a receipt. Native preparation
legally clones the SHA256 state after hashing the common prefix. Thus one
random-oracle query is not asserted to have one uniform implementation cost,
compression count, CPU duration or energy price.

The proof has exactly 134 bytes:
`PGSF\0\0 || profile_hash32 || challenge32 || statement32 || endpoint32`.
The full verifier recomputes all 64 steps. A cheap claimed-endpoint/target
filter is explicitly insufficient: a forged zero endpoint passes that filter
and is rejected by full replay. This is not a succinct proof or the
Cohen--Pietrzak PoSW construction. The fixed length 64 is a bounded research
parameter, not a claim of adequate production security or difficulty.

## 2. Candidate chronology and independently expected authority

The controlled native fixture performs these operations in order:

1. Pin the actual model commitment, all ordered request bytes and their common
   authorization scope, task/source/withdrawal identities, model generation,
   batch, payment recipient, expiry and a finite nonce interval.
2. Capture network, parameters, genesis, active parent, prior state, height,
   generation and `Node::expected_target(parent)` from an actual local Node.
   Recheck that branch during admission and verification.
3. Sign the complete body under two distinct, externally pinned public keys
   and distinct requester/source signing roles. Persist the expected body,
   exact capsule digest and current registry sequence/digest separately.
4. Append an authorized nonce to the body, derive the challenge and work ID,
   and only then calculate the statement and security seal.
5. Fully verify and persist the result. Proof/output/receipt bytes never feed
   backward into the candidate challenge.

The new capsule is a native strict Ed25519 research codec. Both signing keys in
the example are intentionally public controlled test keys; no customer keys or
real authority are claimed. There is no ML-DSA/PQ signature claim and no
conversion into `W1QualifiedTask` or production block admission.

The canonical body is **728 bytes**. It contains `PGAB\0\0`, profile hash,
u16BE step count, six branch hashes, two branch u64BE values, thirteen intent
hashes and eight intent u64BE values. The capsule is **862 bytes**:
`PGAC\0\0 || body || requester_signature64 || source_signature64`.
The candidate is **742 bytes**:
`PGCE\0\0 || body || nonce_u64_be`. Signature carriers are excluded from it.

The complete field ordering is executable in the
[independent wire parser](../../../../formal/pon-nakamoto-v1/grouped_fresh_admission_wire_v0.py)
and the
[native admission implementation](../../../../trillionnium/crates/trnm-pon-node/src/grouped_fresh_admission_v0.rs).
Do not confuse their hash framing:

| Context | Domain and lengths |
|---|---|
| Candidate challenge, work ID, role signatures | Existing `TRNM-PON1\0`, u16LE tag length, u32LE part lengths |
| Fresh seal and profile identity | Fresh `TRNM-GROUPED-FRESH-SEAL0\0`, u16BE tag length, u32BE part lengths |
| Existing model/input/statement commitments | Existing grouped native domain framing with u64BE lengths |

The Python parser independently rebuilds full model and request commitments,
checks every request scope and clock, all body fields, nonce coverage and
candidate hashes, and checks separately supplied local file pins. It does not
authenticate Ed25519 or live Node state. The native signature verifier does not
recompute the Cell. The complete receiver requires **both** checks and the
independent original-coefficient Cell replay before accepting the seal. Supplying
one's own expected hashes is not independent authority.

The controlled Node's development target is approximately one half of the hash
range. That is an observed local fixture target, not a current public network
target. Historical consumer inputs and reconstructed source provenance are
real retained artifacts; fixture demand IDs, public test signatures and replay
clocks do not demonstrate new demand, independent customers or funded payment.

## 3. Conditional aggregate query bound

The [executable finite model and proof](../../../../formal/pon-nakamoto-v1/fresh_work_query_floor_v0.py)
state a classical black-box random-oracle theorem. Let `M=2^lambda`, with fixed
length `L`. Every full candidate uniquely fixes its public seed, profile and
target `T_c` before **any** final-index query for that candidate, including a
speculative wrong-predecessor probe before admission. Seed material is
independent of unrevealed chain-oracle outputs; candidate/profile/index domains
are injective and disjoint. The endpoint itself is the ticket. At most one
nominal award `L*floor(M/(T_c+1))` is counted per candidate.

Let `Q <= q` count all relevant queries, including preprocessing, delegation,
discarded candidates, cancellation and verifier replay. In particular, if a
producer guesses an endpoint without querying it, any verifying computation
that supplies the missing queries remains inside this accounting horizon.
For bounded adaptive stopping and nominal accepted credit `C`:

\[
\mathbb E[C]\leq
\min\left\{L\mathbb E[Q],\;
\mathbb E[Q]+\frac{Lq(q+1)}{2M}\right\}.
\]

The proof partitions first final-index queries before seeing their answers.
If the complete canonical prefix is revealed, the fresh answer has the fixed
target probability; the expected award is at most `L`, charged to disjoint
sets of `L` queries. If the prefix is not revealed, a guessed predecessor
matches it with probability at most `(s+1)/M`, where `s` is the number of
previous prefix queries for that candidate. Deferred decisions and index
separation give this bound by union bounding hits into known suffix labels
plus one final guess. The final-index answer is independent of those prefix
values; inverse-probability weighting cancels the target probability.
Summing over the deterministic cap gives the additive term. The proof does
not condition the whole execution on an absence of collisions.

This is an expected aggregate accounting result. It does not say every
successful individual attempt deterministically performs 64 queries: lucky
guesses are possible. It does not prove SHA256 physical hardness, the cheapest
neural implementation, memory hardness, quantum security or the producer's own
expenditure. A finite transcript auditor can check a supplied transcript's
consistency; it cannot authenticate that no preprocessing or other owner was
omitted. Instantiating injective candidate domains with SHA256 digests requires
separate binding assumptions and bounded failure transfer. A failure probability
must be multiplied by explicit maximum admissions and maximum award; it cannot
bound unbounded credit by itself.

## 4. Verification is a resource, not free evidence

A nonce cap is insufficient to cap verification work: an attacker can submit
many false endpoints for the same nonce. The research journal therefore has a
separate immutable **256-submission** budget for one exact frozen policy.
Before expensive Cell replay, the receiver durably reserves a verification
permit bound to mode, nonce, statement, proof digest and capsule digest. Native
claim consumes that one-use permit before signature/chain replay. Failed,
abandoned, mismatched and duplicate requests do not refund it. Reopening the
same SQLite journal retains the count; changing the frozen policy cannot reset
the existing file. An unknown permit cannot authorize a replay.

The producer similarly reserves a nonce before its computation. A cancellation
after 17 actual steps leaves the reservation and its completed-prefix fact;
it returns no proof or final-query claim. An intent reserved without running
has unknown external-work status and cannot become a free fresh reservation.

These are local journal guarantees, including held locks and readback. They are
not a global quota across cloned validators, identity changes, copied files or
an attacker-controlled host. Parsing, signatures, transport and storage still
cost resources outside the 64 chain queries. A pure mathematical verifier
exists for correctness checks and is explicitly unmetered; the NDJSON session
cannot call its expensive path without a charged permit.

The separate coalition-only corollary in the finite model is conditional on a
real cap `K`, bounded maximum award, fixed canonical seed/statement before all
probes, hidden verifier states and restricted equality feedback. The current
timed local fixture does **not** establish that side-channel model or a global
cap. An endpoint guess has probability on the scale of `1/M`, but its weighted
credit is on the scale of `L/(T+1)`; it is not uniformly negligible when `T`
may be arbitrarily small. Receiver computation must not silently be charged to
the attacker's own budget. The complete corollary, assumptions and finite
controls are kept with the executable model, not advertised as an unconditional
property of the native system.

Specifically, with coalition queries `Q_A <= q`, maximum award `W_max` and
`D=M-K(q+1)>0`, the conservative general equality-feedback bound is

\[
\mathbb E[C]\leq\min\left\{K W_{\max},\;
\frac{M}{D}\mathbb E[Q_A]
+\frac{Lq(q+1)}{2D}+\frac{K W_{\max}}{D}\right\}.
\]

The factor `M/D` allows information gained from rejected guesses; treating later
answers as uniformly distributed after that feedback would be incorrect. The
last term charges a correct endpoint guess whose final input the coalition
never queried. A single such guess at `T=1`, `L=64` has expected nominal award
32 for any hash length, despite its tiny success probability. Exact small-oracle
tests expose this behavior. They are not a mechanized proof for every adaptive
adversary, and this corollary has no claimed native implementation transfer.

## 5. Challenge-transform counterexamples

The [shortcut implementations](../../../../formal/pon-nakamoto-v1/grouped_challenge_shortcuts_v0.py)
and [fixed campaign](../../../../formal/pon-nakamoto-v1/experiments/grouped_challenge_shortcuts_v0.py)
retain original business output checks and separately verify auxiliary challenge
relations. These are new proposed-relation controls, not discovered W1 exploits.

| Proposed dependency | Implemented lawful shortcut | What remains charged |
|---|---|---|
| Rank-one blinding | Cache the fixed original projections and compute low-dimensional challenge corrections | Preparation, challenge expansion, correction arithmetic, independent verification |
| Full-rank batch mixing `X S_c` | Precompute `R X` and every `M_e X`; mix the small outputs, even when routing changes | All-expert preparation and per-challenge small products |
| Finite dropout masks | Use scoped block lookup tables on the fixed input/model | Table construction, table bytes, mask expansion, lookups and additions |
| Self-selected zero operator | Skip challenge expansion for an identically zero auxiliary relation | Separate named chosen-model control; never substitute for the pinned trained model |

Original inputs remain signed `[-8,8]` with bias8. Explicit auxiliary bounds
(16 for rank-one, 264 for batch mixing) belong to separate probes and do not
silently change the business numerical profile. The real sparse-corpus LUT and
the dense synthetic LUT have separate preparation/storage observations. Ordinary
factor, merged, direct selected-expert, sparse and scoped-cache baselines from
the previous audit remain applicable. No finite set of strategies proves a
globally cheapest implementation.

## 6. Evidence and cost boundary

The [end-to-end runner](../../../../formal/pon-nakamoto-v1/experiments/grouped_fresh_work_v0.py)
replays the source of the retained trained model and frozen consumer corpus,
precommits its complete nonce schedule, records every hit/miss/failure and uses
a bounded persistent native child. It records actual native process exit and
retains exact request, response and stderr bytes. Before/after source identity
checks bind the clean source and all listed inputs; final runs require the
source SHA and source replay.

The measured path includes model/input reads, source replay, legal preparation,
native Node startup, both fixture signatures, external-pin checks, statement
binding, proof production, independent Python hash crosschecks, actual localhost
TCP, independent full Cell replay, full native seal replay, reservations and
exact received packet and receipt persistence/readback. This is local byte
retention, not a replicated availability service. Phase timings are nested; parent process CPU
already includes the receiver thread and child CPU already includes native
phase CPU. They must not be added again. Unknown partial stages remain null.

Sixty-four JSON encodings of a fixed proof must retain one work identity;
replays do not add native first records. Negative controls include wrong
outputs/context/capsule, a forged low endpoint, malformed trailing data, a
17-step cancellation, reserved unknown work, reopen and budget exhaustion.
A valid proof produced outside the native producer journal exercises the
independent verifier and prevents that journal from becoming the correctness
oracle. Every admission still awards actual chainwork zero.

These measurements omit real WAN/TLS propagation, global storage availability,
production proof systems and external authority/service operation. Python parent
startup/import/exit and final report writing have stated scopes. Native child
startup and exit are included in its measured lifetime and child CPU. No new GPU
allocation is required to answer this structural question: GPU timing cannot
replace the missing minimum-cost or real-demand arguments.

## 7. Literature and remaining gates

[Ball, Rosen, Sabin and Vasudevan (CRYPTO 2018)](https://eprint.iacr.org/2018/559)
make non-amortizability a multi-instance hardness obligation. Their revised
worst-case PoW result should not be cited as automatically proving usefulness
for arbitrary business tasks.
[Cohen and Pietrzak](https://eprint.iacr.org/2018/183) analyze sequential work in
the random-oracle model with a different proof construction; our full replay
does not inherit their succinct verification.
[Alwen et al.](https://eprint.iacr.org/2016/989) prove a memory measure for scrypt
under their explicit model, illustrating why a named cost measure matters.

[Komargodski and Weinstein (ESA 2026)](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
explicitly rely on a new correlated-intermediate-computation conjecture for
their matrix-work construction. Output-only cached/factored shortcuts are not
eliminated merely by adding low-rank noise. Their large-matrix naive baseline
and finite-field assumptions do not transfer automatically to this int257
profile or to factorized Hepta inference. An extra security chain is the
conservative separated-work approach discussed in that literature; it is not
a demonstration of negligible overhead or intrinsic useful-work hardness.

Production qualification still requires: a defensible adversary-owned resource
model and cost relation; independently governed task/target/profile authority;
authenticated real demand and useful outputs; complete proof, validation,
availability and propagation economics; global replay/verification limits;
quantum and concrete implementation analysis; and original service/consensus
integration gates. Changing profile semantics requires a fresh identity and
independent validation. Increasing GPU samples closes none of these by itself.
