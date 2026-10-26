# Exact task-product facts across fresh W1 challenges

Status: opt-in local verification component and fixed service experiment. No
consensus, default verifier, Node admission, task eligibility, proof wire, target,
DAA, production activation or original O01–O07 closure standard changes.

## Why the existing challenge caches do not remove this work

The current [W1 implementation](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs)
replays the complete challenge-bound transcript, checks its claimed digest, then
recovers the useful product using four correction matrix products. The existing
[work-fact cache](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/facts.rs)
and [arithmetic-fact cache](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/arithmetic_facts.rs)
key on challenge. They retain their existing contracts. A fresh nonce yields a
fresh challenge and cannot reuse those transcript facts.

For fixed canonical A and B, the final useful product C = AB is independent of
challenge. Let E = EL ER, F = FL FR, A' = A + E and B' = B + F over the original
field. The full transcript computes every required partial product of A' B'.
After its final value C' is reached, the original correction is

\[
C' - (A FL) FR - EL(ER B') = (A+E)(B+F)-AF-E(B+F)=AB.
\]

A positive AB fact learned from a complete successful original verification is
therefore reusable for exactly the same A/B bytes on a different challenge.
The current challenge's entire transcript must still be recomputed. Neither a
product fact nor a cached digest can attest that transcript.

## Opt-in owner and exact acceptance relation

The new [TaskProductFactCache](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts.rs)
returns the existing `VerifiedWork` type. It does not provide a new acceptance or
installation authority. Its fixed compiled W1 profile, dimensions, field and
canonical encoding are implicit in the type; callers cannot load a serialized
fact, change its profile or inject a product. The public construction parameters
contain only a bounded slot count.

Each invocation performs these steps:

1. Run the original `checked_proof_inputs` with the original validation/error
   order. All current A/B/C words must be canonical. Check the current task hash,
   current challenge-bound claimed ticket and current target before cache access.
2. Invoke the original `BeforeReplay` cancellation point. Look up **all 32,768
   canonical A/B bytes**, not a task hash alone. Copy a matching product while
   holding a short bounded lock, then release the lock.
3. Run the unchanged transposed transcript kernel with the current challenge.
   Recompute all four noise factors, both noise products and all 512 transcript
   tiles. Compare the complete computed digest with the current claimed trace.
4. On a hit, pass `BeforeProduct` and compare the cached 16,384-byte mathematical
   product against every current C byte. On a miss, run the unchanged four
   correction products and compare the result with every current C byte.
5. Pass the original `BeforeVerifiedWork` callback. Only a complete successful
   miss may now publish the positive A/B/product fact. Return the original
   challenge, task, ticket and product in `VerifiedWork`.

The cold miss uses the product already computed by ordinary verification; it does
not compute a second direct AB product. A trace mismatch, product mismatch,
malformed proof, wrong task/target or cancelled call publishes no new fact. An
already valid fact is not revoked by a later malformed or cancelled request.
Task leases, parent state, transaction execution, rewards and operator policy are
checked by their original owners when this math component is integrated. No such
integration is activated here.

The callback sequence retains every transcript/noise checkpoint. A warm hit has
`BeforeProduct` and `BeforeVerifiedWork`, but no correction `MatrixRow` events.
This is explicitly observed; it does not pretend that four matrix products ran.
The default verification path keeps its original callbacks and arithmetic.

## Storage, contention and cancellation

The owner has 1–64 fixed-size slots. Each slot owns exact A/B bytes and one computed
product, with its presence tag. `software_bytes()` uses actual Vec capacity and
`size_of` for all retained slots, mutex and owner metadata, and rejects a value
over 4 MiB. This includes keys and products, not merely a product payload.
Allocator bookkeeping, the ordinary verifier workspace, a copied lookup product,
return values and caller threads are outside this retained-object measure. It is
not an RSS or host-wide cap. Lookup copies at most one 16-KiB product.

Each lookup/publication probes at most the configured capacity. Locks are taken
with `try_lock`; contention falls back to the complete original arithmetic path
and may skip publication. It never waits for another computation, spawns work or
adds an unmetered helper. Poison observed while accessing a lock or conflicting
positive products for the same full key produces local unavailability. Neither
error can construct valid work.

No callback runs while the mutex is held. Cancellation before the final callback
success cannot publish a new fact. Bounded final comparison/publication and return
still follow the last cooperative checkpoint; this is not hard preemption or a
zero-overrun assertion. Concurrent callers can each pay full arithmetic on a cold
key. The implementation does not assume single-flight deduplication or subtract
that duplicated work from a resource budget.

## Exact arithmetic savings and their limits

For this current transposed scalar-product implementation, N = 64 and R = 8:

| Component | Original or empty owner | Existing exact A/B product fact |
| --- | ---: | ---: |
| Two challenge-noise matrix products | 2 N² R = 65,536 | 65,536 |
| Complete transcript partial products | N³ = 262,144 | 262,144 |
| Four product-correction products | 4 N² R = 131,072 | 0 |
| Total scalar multiplications in these products | 458,752 | 327,680 |

The removed count is 2/7 of this implementation's multiplication count. The table
is not a CPU-time, joule, bandwidth, throughput or attacker-cost lower bound. All
noise hashing, the full transcript hashing, task/ticket hashing, field checks,
current-claim comparisons and copying remain. A full owner with unrelated tasks
can spend more time on byte comparisons and miss bookkeeping. The complete
receiver also spends time on parent state, eligibility, execution and durable
storage; a relation-kernel gain does not give a Node or chain TPS gain.

A shorter verifier path establishes no new miner opportunity, unique rewarded
identity, production kappa or SHA-256 instantiation theorem. Each W1 winner still
requires its original 49,188-byte proof and current native admission.

## Fixed native service observation

The [native example](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_task_product_facts.rs)
accepts exactly `--seed 8101` or `--seed 8102`. Each invocation constructs six
canonical material families: zero, identity, rank-one A, sparse, near-field-boundary
and deterministic dense. Four fresh challenges per family use a capacity-two
owner created before that family's first case. A separate capacity-one sequence
zero, identity, zero, zero requires miss, miss, miss, hit on four fresh challenges.
There are 28 complete proof cases and 56 raw/fact verification calls per process.

Every case retains its full original PNW1 proof, task, challenge, target, SHA-256,
scalar proof-generation observation and independent original scalar-reference
verification observation. Both compared methods receive exactly those same
bytes. Seed 8101 runs raw then facts; seed 8102 runs facts then raw. The inputs,
order and repeat counts are fixed before formal collection, without pilot timing
or parameter tuning.

The target is all-255 bytes. This is a full-relation service benchmark, not a
mining target or registered task/parent lifecycle campaign. These canonical
matrices have W1 relation validity; the example does not assert Node task
eligibility. The default Node path is unchanged.

Per-operation observations use `Instant` elapsed wall time. They include actual
progress-counter updates but exclude later JSON/hex serialization and output.
Material preparation, scalar generation, scalar-reference checking, owner
construction and owner drop have separate wall observations. The external whole
process observer includes both arms plus generation, reference checking,
serialization, output and cleanup. Its CPU measurement cannot be apportioned to
one arm using wall-time fractions.

An empty owner is not a cold physical CPU cache. The reference verifier has
already touched the case's material before both compared operations. Later owner
hits reuse a positive product across distinct challenges and do not reuse a
challenge transcript. Nonexclusive scheduling and a finite fixed input family
limit all timing conclusions. No unobserved speedup, operator independence,
ARM/GPU execution, energy result or peer transfer is supplied by this experiment.

## Meaningful controls

The [native tests](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts/tests.rs)
compare fresh-challenge outputs with both scalar-reference and original raw
verification over structured and dense material. They require all 512 transcript
tiles on both paths and count 200 original correction rows versus zero warm rows.
Current trace, product, encoding, field, challenge, task and strict target
mutations fail on both empty and populated owners. Equal products with different
A/B bytes do not alias; eviction requires new arithmetic. Cancellation includes
noise, first/last transcript tiles, correction work and the final callback.
Contention, concurrent fresh challenges, poison and full retained-storage bounds
have separate controls. These tests do not certify independent hardware,
worst-case physical cost or production service capacity.
