# M05 native lane decisions

The `lane_quota.hepta` byte entry uses exactly 56 input bytes:
`LQV1 | opcode:u8 | reserved[3]=0 | total:u64LE |
requested_reserve:u64LE | normal_queued:u64LE |
critical_queued:u64LE | streak:u64LE | burst_limit:u64LE`.
The first eight mutable output bytes receive a little-endian `u64`
only on success; the remaining output bytes and scratch remain untouched.
Input and output extents and reserved bytes are validated before mutation.

Ops 0–4 reproduce the original global-capacity, critical-free,
critical-spillover, normal-borrowing and normal-preference predicates.
Ops **5** and **6** reproduce the original `record_pop_fairness` transition,
respectively after serving a critical item or a normal item. Their input
queue counts **must be post-pop** lengths, as the original Rust method
observes the queues after dequeue. The returned number is the updated
critical-served streak. The saturating increment is evaluated as
`streak < burst ? streak + 1 : burst`, which avoids overflow at
`u64::MAX`. Reserve requests are clamped to total capacity. Ops **7–12** cover the original maybe_warm_normal_fairness transition
after an admission attempt, with **post-admission** queue counts. In order,
the opcode pairs encode (normal_was_empty=false, true) for each outcome:
7–8 Accepted, 9–10 Duplicate, 11–12 Backpressured. Only opcode 8 may warm
the streak to burst_limit, and only when dedicated normal capacity and
both nonempty queues exist. All other combinations preserve the incoming
streak, including the full u64 range. This makes the original method's
acceptance and before/after-queue ordering explicit without inferring it
from queue counts. Ops above **12** are rejected without writing output.

These are *pure decisions/transitions* on supplied queue counts.
There is no HIA-owned queue, duplicate cache, nonce reservation,
atomic dequeue, persistent transaction, or integration into the live
Node. Malformed frames, full-width counters and the actual original
Rust methods are exercised in `hia/tests/test_mempool_quota.py`.
A candidate and its oracle require exact committed native CI before
any qualification claim; this does not close a migration gate.
