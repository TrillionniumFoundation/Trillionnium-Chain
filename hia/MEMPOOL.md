## Single-call M05 original QoS snapshot candidate — 2026-11-16 UTC

LQV1 opcode **24** produces the original five-field `qos_snapshot` decision
tuple `(total_headroom, normal_headroom, critical_headroom,
fresh_normal_admissible, fresh_critical_admissible)` as 40 little-endian
bytes from one immutable 56-byte caller request. The HIA machine code
reuses the same underlying exact-capacity and saturated headroom predicates
as scalar operations 13–17, and rejects a 39-byte output without partial
publication. This is a pure mathematical snapshot, not a read of actual
authoritative queues or a transaction. The mandatory test now obtains all
five fields from a **single actual original Rust LaneAdmissionGate::qos_snapshot**
after 792 real admission/dequeue scenarios and compares them to one
emitted-machine invocation; it also retains the earlier five independent
scalar comparisons and full u64-boundary testing.

The preceding exact-head `03c84d28` [native HIA run 43802991240](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43802991240)
completed all six tasks successfully, including original-Rust M05 comparisons.
This is evidence for the **previous opcode-23 source only**, not PASS for
new opcode 24. The new source's exact-head native/Rust execution and original
PQ negative qualification remain NOT_RUN until its own CI completes.
All 26 Rust packages and all nine retirement gates remain OPEN; PQ remains
HOLD_NO_GO.

## One-call native M05 post-pop projection — 2026-11-16 UTC

LQV1 opcode **23** returns a 40-byte little-endian `(selected_lane, normal_after, critical_after, fairness_after, popped)` projection using **one immutable 56-byte request and one emitted HIA machine-code invocation**. The caller must provide a `mutbuf` of at least 40 bytes; smaller output buffers return status 2 without writing anything. The remaining bytes of a larger buffer and the distinct scratch buffer are unchanged. This avoids mixing separately sampled caller inputs when inspecting lane/fairness proposals, but is **not an atomic dequeue, thread-safety guarantee, a queue owner, a local-pool handoff, a persistent Node transaction or a package-retirement witness**. The complete original Rust `pop_ready` tests compare its observed lane/count/popped fields; the original fairness module differential checks the fairness field separately. New exact-head machine-code and Rust CI results must be observed before PASS; all 26 original packages, nine gates and PQ HOLD_NO_GO remain.

## Native post-dequeue queue projections — 2026-11-16 UTC

The HIA LQV1 policy now includes opcodes 20 (normal count after one original-selected
dequeue), 21 (critical count after one original-selected dequeue), and 22
(whether a dequeue would occur). These compose the *same* opcode-18 choice rather
than recomputing a distinct priority order; zero-length lanes remain unchanged and
no unsigned count wraps on the selected path. The full original Rust
`LaneAdmissionGate::pop_ready` fixture now reports its actual post-pop counts
and popped flag, with the independent Rust shell and all 64-bit model edges also
covered by mandatory native tests. This is a pure proposed projection, **not** a
queue mutation, durable reservation, Node ownership or a package retirement witness.
New exact-source CI is NOT_RUN until its execution; all nine gates remain OPEN,
all 26 Rust packages remain, and PQ remains HOLD_NO_GO.

The exact prior `5524ce8b` [run 43791117254](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43791117254)
completed six SUCCESS: 222 native-components tests, 70,998 shared native calls,
zero skipped, and the actual original-Rust adapter; standalone executor ran
5,274 original/native comparisons with its explicit original safety defect.
Typed Delta ran 8,551 native controls with actual original Rust PASS, and the
response, transport, settings and source/archive jobs also succeeded. This is
qualification of **only that prior source**, not the new opcodes or whole Node.

## Original idle-poll oracle correction (exact-head requalification required)

The previous `ac0d7b78` six-job HIA run
([run 43786960479](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43786960479))
finished **five SUCCESS, one FAILURE**. The `native-components` test
`test_actual_original_lane_modules` failed at record 4,126, when opcode 19
received empty normal/critical queues and a nonzero injected fairness streak.
The **test adapter** had not modeled the original `LaneAdmissionGate::pop_ready`
idle-poll call to `reset_idle_state(true)`; consequently it returned a stale
streak even though the original full node resets that counter to zero. The
emitted HIA opcode 19 correctly returned zero for the empty state. The adapter
now preserves the zero-capacity metadata exception while explicitly resetting
the fairness counter, adds five nonzero-streak idle regressions, and reports
the exact failing row on future divergences. Neither the original Rust crate
nor the HIA native kernel was changed in this correction. New exact-head Rust
execution and emitted-machine differential remain **NOT_RUN** until CI reports
results. All nine migration gates and PQ HOLD_NO_GO remain unchanged.

# HIA M05 lane quota and fairness predicate candidate

This independent finite native HIA component targets the original **pure quota, fairness and QoS snapshot decisions**
from the original `trnm-mempool` lane admission and fairness implementation.
It is not a complete mempool, a persistent queue, an admission guard, a nonce
owner, or a whole-node rewrite. The original packages remain present and all
nine migration gates remain OPEN. No original service budget or consensus
authority is changed.

## Exact caller ABI

The source is [`src/mempool/lane_quota.hepta`](src/mempool/lane_quota.hepta).
The only public entry is `f0(readbuf, mutbuf, mutbuf) -> u32`, executed as
emitted native machine code under the pinned HIA compiler and disjoint borrowed
buffers. The input is **exactly 56 bytes**; it consists of `LQV1` (offset
0..4), one operation byte (4), three reserved zero bytes (5..8), then six
little-endian unsigned 64-bit words:

| Offset | Original Rust semantic input |
| --- | --- |
| 8 | `total_capacity` |
| 16 | caller's `critical_reserve` (clamped to total, matching `LaneAdmissionGate::new`) |
| 24 | current normal queue length |
| 32 | current critical queue length |
| 40 | `critical_served_streak` |
| 48 | `critical_burst_limit` |

| Operation | Native `u64` result on success |
| --- | --- |
| 0 | global capacity: normal count + critical count is strictly below total capacity, without wrapping the sum |
| 1 | critical free slots: `saturating_sub(min(total,reserve), critical_count)` |
| 2 | normal queue length is below its dedicated capacity |
| 3 | normal borrowing permitted: nonzero free slot and (reserve-only mode, surplus free slots, or final slot while critical queue idle) |
| 4 | dedicated normal lane exists, critical-served streak has reached the threshold, and normal queue is nonempty |
| 5 | post-pop critical streak becomes `min(streak+1, burst)` in a dedicated-normal configuration; otherwise zero |
| 6 | post-pop normal streak becomes `burst-1` only while both queues remain nonempty and dedicated-normal capacity exists; otherwise zero |
| 7–12 | accepted, duplicate or backpressured outcomes crossed with pre-admission normal emptiness; accepted dual-backlog warmup sets streak to burst |
| 13 | total headroom `total.saturating_sub(normal.saturating_add(critical))` |
| 14 | normal dedicated headroom, saturating at zero |
| 15 | critical reserved headroom, saturating at zero |
| 16 | fresh normal admission eligibility, including critical spillover borrowing and global limit |
| 17 | fresh critical admission eligibility, including normal-lane spillover and global limit |
| 18 | original `pop_ready` queue selection: 0 idle, 1 normal, 2 critical, using the post-admission critical streak and the live queue counts |
| 19 | full-drain-aware post-pop critical streak from the selected lane and the pre-pop counts, matching the original fairness update plus idle reset |

The caller must supply queue lengths, fairness counts and a complete authenticated
context from its own authority. This primitive **does not** derive or authorize
those values, or enforce their consistency with real queues. It accepts even
unreachable counts as total deterministic arithmetic inputs so its behavior
can be checked across all 64-bit boundaries.

The output buffer must contain at least eight bytes. A successful call writes
exactly the `u64LE` answer at offset 0..8, preserving the remainder. Errors
preserve the entire output, input and scratch. Return codes: 0 success;
1 wrong input extent; 2 insufficient output; 3 magic/reserved-field error;
4 unsupported operation. Check order is extent, output, header, operation.
No dynamic allocation or metadata side effects occur in the HIA function.

## Exact-original differential and limitations

[`tests/rust_mempool_quota_reference.rs`](tests/rust_mempool_quota_reference.rs)
uses explicit `#[path]` imports of the unchanged
`trillionnium/crates/trnm-mempool/src/lane_quota.rs` and
`lane_fairness.rs`, compiling and invoking the real Rust methods with an
independent narrow queue shell. The test suite
[`tests/test_mempool_quota.py`](tests/test_mempool_quota.py) requires
`rustc`, pinned HIA native artifact build, real child process returns,
unchanged borrowed bytes and direct comparisons, including malformed frames and
u64 overflow boundaries. Missing compiler/native execution is a hard test
failure, never a skip. The main qualification's source manifest includes
these two original Rust implementation files so their mutation invalidates
the comparison.

The exact preceding `54a3f02b` [HIA CI](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43782301850)
executed the original Rust QoS snapshot comparison against emitted native
machine code: 221 native tests / 69,767 shared machine-code calls and zero
skips. This prior source has opcodes 0–17 only; **opcode 18 is newly added and
its exact-head native/original Rust comparison is NOT_RUN until CI finishes**.

The dedicated QoS test compiles the actual unchanged original
`trnm-mempool/src/lib.rs`, including the typed admission module, executes real
normal/critical ingress and dequeues, reads `LaneAdmissionGate::qos_snapshot`,
and compares each of its five derived fields to emitted HIA machine-code
decisions. Original source identity, process exits and borrowed-buffer integrity
are bound by the mandatory main qualification. New exact-head qualification
is **NOT_RUN** until its own CI has completed.

The remaining M05 owner includes authoritative queue state, deduplication
repair after restored-state skew, critical-vs-normal scheduling, mutations,
nonce reservations, persistent handoff, cancellation and cold recovery.
Those are neither delegated to this primitive nor qualified as finished.

## Original dequeue lane choice — opcode 18

The source now emits the pure next-dequeue lane decision from the actual
`LaneAdmissionGate::pop_ready` priority order: when the normal lane exists,
contains work and has reached the critical burst threshold, prefer normal;
otherwise prefer critical if nonempty, then normal if nonempty, else idle.
This is only a proposed lane-selection decision. It neither removes items,
repairs restored duplicate caches, mutates the fairness streak, nor owns a
persistent transaction or outbox.

The [original dequeue adapter](tests/rust_mempool_pop_reference.rs) compiles the
unchanged complete M05 crate, performs real admissions and one real
`pop_ready` for each of 693 small-queue scenarios, and infers the actual
popped lane from **before/after original `qos_snapshot`** counts, including
cross-lane spillover. Its finite scenarios have no intermediate dequeues, so
the expected pre-pop fairness streak follows from accepted admission outcomes
and the original initial burst rule. The
[mandatory native test](tests/test_mempool_quota.py) compares the observable
original dequeue side with both the finite independent rule and the native HIA
result, and separately exercises full unsigned-64-bit boundary values. No
claim is made for actual Node queue ownership, concurrency, crash recovery or
an original service-budget pass.

## Fused next-pop fairness transition — opcode 19

The native opcode 19 composes the next-lane selection and the original fairness
update from the **pre-pop** snapshot. It decrements the selected queue before
checking whether both queues remain backlogged, and zeroes the streak at full
drain, including the final critical item. The independent Rust adapter invokes
the unchanged original `lane_fairness.rs` method on bounded physical queues.
Shared native qualification includes full 64-bit streak/burst edge cases and
unchanged borrowed buffers.

This remains a pure proposed transition; it does **not** mutate the real queue,
repair stale duplicate caches, reserve nonces, transfer local-pool ownership,
or commit Node state. Exact-head native/original qualification is **NOT_RUN**
until the new published commit has CI observations.
