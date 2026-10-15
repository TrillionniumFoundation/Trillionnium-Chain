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

The current exported entry is `ingress::dispatch_shared_with_metered_work_facts`.
The first unmetered embedding wrapper is now crate-private and cfg(test) only;
it retains the original seven owner controls, not an alternate production path.
The current Submit-only entry requires the existing ServiceMutationCpuDomain.
It never constructs a new budget, reserves before W1/M06 work, and checks an
installed continuous owner's domain before dispatch. The caller's deadline and
cancellation are checked alongside that same live CPU operation at native and
W1 checkpoints. Actual M06 scoped workers register with the same operation and
are joined before settlement. A callback alone is insufficient: the original
unmetered wrapper plus an external CPU checkpoint was reproduced rejecting a
valid parallel M06 execution with unknown/unregistered worker accounting.

The complete native success/rejection/cancellation result is retained separately
from the CPU settlement. Known CPU, including failed request tails, remains paid.
Unknown accounting fences subsequent shared-domain starts, but cannot rewrite
an already committed native success as an unexecuted operation. Panic uses the
existing operation Drop rule: unknown accounting, no fabricated refund. Pool
and read requests are not routed through this mutation-only entry. The trusted
caller must not nest it inside an already reserved V3 request (which would buy a
second reservation); V3's existing dispatcher continues owning its own permit.

Current context and owner permits are checked before verification, the expensive
verification runs outside the only durable writer mutex, and the original owner,
state/root/nonce/current-clock and commit checks still run afterward. Public
V2/V3 listeners and CLI still use their original verifier and pinned resource
policies. No automatic public-cache profile selection is added.

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

## Shared CPU continuation observations

Nine additional Linux tests exercise actual metered signed native admission,
owner-plus-scoped CPU accounting, exact paid-tail conservation with refill frozen
only in test controls, cold/warm refusal before replay under exhaustion, positive
facts after failed C, cancellation/retry, two real occupied reservations, eight
server reconstructions sharing one retained debt, and unwind fencing.
A separate test within those nine opens two actual framed V3 TCP listeners sharing
the same CPU domain. While one deliberately held invalid cached request remains
in flight outside the writer lock, a valid public submission and six additional
native blocks complete. An independent local Node obtains seven real History
pages over the other listener, fully verifies them, confirms all eight signed
transfers under the installed depth/work policy, and cold-reopens equal state.
The held invalid request is then rejected and charged; no resource remains live.

This is one bounded controlled overlap, not a saturation/flooding campaign or a
WAN throughput estimate. Holding a request is test scheduling, not measured
attacker CPU. Eight reconstructed PublicServer objects do not simulate an OS
process or host reboot. Same-domain pointers do not enforce a host-global cap
across independent processes, unrelated Nodes or deliberately created standalone
budgets. Cross-process kernel enforcement, unclean-restart debt qualification,
pre-cookie connection costs and public-cache profile integration remain open.
Mining generation and independent client work in the test are outside the
receiver mutation accounting. Signed wire and consensus bytes are unchanged.
