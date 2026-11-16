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

The exact prior `ddcd5791` [HIA CI](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43772265993)
executed all 6,695 original Rust quota/fairness comparisons against emitted native
machine code. Its main native qualification passed 220 tests and 65,762
machine-code calls, with zero skips. These results bind only the previous
source and **do not** qualify the newly added QoS snapshot operations.

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
