# Explicit native W1 mathematical-fact reuse

Status: local development implementation and finite native regressions. No public
listener, CLI profile, consensus parameter, readiness flag, Hepta pin or deployed
owner is changed. This continues the original W1 relation and M05/M06 owner path.

## Exact authority boundary

`pon_work::facts::WorkFactCache` is a fixed-profile volatile cache. Its key binds
W1, the complete header-derived challenge, the canonical actual task, and the
claimed transcript. A cached product is published only after the unchanged full
native verifier succeeds, including exact C and the final cancellation checkpoint.
Every request repeats the original length/version/field/task/current-target checks.
A hit compares C byte for byte before constructing a fresh private `VerifiedWork`.
Target, source leases, revocations, branch state, membership, confirmations and
local execution authority are never cached. SHA-256 collision resistance remains
an explicit assumption of content-addressed task and challenge identity.

There is no negative cache. A false C with the same block/transcript identity
cannot blacklist a later valid packet. A false transcript does not publish a fact.
At cold start, a false C arriving before its valid counterpart still costs one full
failed verification. Repeated distinct false transcripts still require admission
protection; the cache is not a solution to public work economics or Sybil flooding.

The original Node already checks exact packet content for an existing block ID
before W1 replay. Do not report this cache as newly fixing that durable duplicate
path. Its incremental benefit is pre-persistence and concurrent mathematical
verification, including work-valid statements that do not become admitted blocks.

## Bounded concurrency and cancellation

The caller selects 1..256 direct-mapped slots. Each completed slot owns 4096 u32
product words (16 KiB), plus bounded metadata. This is not a whole-process memory
bound; request buffers, verification scratch and caller threads are separate.
At most one computation owns each slot. Identical requests share that work; a
colliding key waits, and a completed different key can be evicted. This policy
bounds internal state but does not prove adversarial cache-hit rates or fairness.

Slot locks never cover W1 arithmetic or caller callbacks. A waiting call polls its
original cancellation callback after a Condvar timeout of at most five milliseconds;
this is not a wall-time/preemption guarantee. Callers bound threads and provide
an absolute deadline. Leader cancellation, native rejection or unwind releases its
computing slot and wakes waiters. Each waiter rechecks its own cancellation and
acquires its own verification attempt if necessary. A poisoned local lock returns
Unavailable, not consensus-invalid work and not an uncached silent fallback.

`full_replays` counts started full-verifier calls, including rejected/cancelled
ones; `hits` includes fast rejected C variants. Counters saturate and never grant
acceptance. A fresh cache has no retained verdicts. Returned products are independent
owned copies, not mutable aliases of cached facts.

## Existing native M05 integration

`ingress::dispatch_shared_with_work_facts` is an explicit local embedding API. It
calls the existing shared dispatcher and the existing `WorkCheckedPacket` boundary.
Current context and owner permits are checked before verification, the expensive
verification runs outside the only durable writer mutex, and the original owner,
state/root/nonce/current-clock and commit checks still run afterward. Original
cancellation is forwarded into W1 waits/replay, M06 and durable admission. Existing
V2/V3 public listeners and CLI continue using the original full-replay verifier;
no resource-policy digest is silently reinterpreted. Public integration requires
its own explicit resource-profile selection and complete hostile-service tests.

No additional Node, database, operation journal, trainer or authority owner exists.
The original scalar/transposed/limb verifiers and original callback ordering remain
available unchanged. The new API has its own cache-hit/wait callback schedule.

## Finite observations and reproduction

The original Rust source plus a negative regression reproduced four complete
replays for one valid proof and three canonical false C variants; zero invalid
proofs were accepted. The one-replay assertion failed (exit101), as expected.
The failure log and exact additive test are retained outside the working tree.

The native primitive controls cover the 4-to-1 replay case, invalid-first ordering,
current target/task/field checks, 64 scalar differential cases over four structures
and two challenges, restart/eviction/capacity, independent returned bytes, eight
concurrent callers, waiter cancellation, leader cancellation, unwind, final-hit
cancellation and explicit poisoned-lock failure.

Native M05 fixtures contain real signed development transfers. They exercise
false-product rejection with no mutation, exact original state equality and cold
reopen; eight concurrent requests with one full replay and one durable block;
unchanged context failures; lock release and cancelled-hit/no-commit retry; and
one cache slot with a full 256-transfer block whose duplicate does not consume
another nonce. Development fixture signatures are not independent real operators.

Run the normal project preflight, then the existing package tests:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --lib
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::work_fact_tests -- --nocapture
```

These tests establish finite implementation behavior, not elapsed-time speedup,
independent public qualification, compact-proof soundness, physical durability,
future learning quality or production activation. Hosted results must refer to the
actual new source, not the predecessor's Chain/Hepta paired green.
