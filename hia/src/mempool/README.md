# M05 native lane decisions

The `lane_quota.hepta` entry accepts exactly 56 input bytes:
`LQV1 | opcode:u8 | reserved[3]=0 | total:u64LE |
requested_reserve:u64LE | normal_queued:u64LE |
critical_queued:u64LE | streak:u64LE | burst_limit:u64LE`.
The reserve is clamped to the total. All queue lengths and counters are caller
supplied; the module does not inspect or acquire a real queue.

Opcodes **0–4** implement global admission, reserved capacity, dedicated
normal capacity, borrowing and fairness preference. Opcodes **5–6** compute
post-pop fairness, **7–12** model the original admission outcome warmup,
**13–17** compute the five original `qos_snapshot` fields, **18** selects
the next queue, **19** computes full-drain-aware post-pop fairness, and
**20–22** compute post-pop lengths and whether a dequeue would occur.
Opcode **23** returns five `u64LE` post-pop fields in one native call:
`(lane, normal_after, critical_after, fairness_after, popped)`.
Opcode **24** returns five `u64LE` original QoS fields in one call:
`(total_headroom, normal_headroom, critical_headroom,
fresh_normal_admissible, fresh_critical_admissible)`.

The scalar opcodes need at least 8 bytes of mutable output; 23 and 24 need at
least **40 bytes**. On success only the first 8 or 40 bytes are written.
Any refusal preserves the whole output and scratch; successful calls preserve
their unused output tails and scratch. The error precedence is input length,
minimum 8-byte output, header and reserved bytes, opcode, then 40-byte
composite output. Unknown opcodes **25–255** return 4 without writing output.

The native HIA machine code is checked against independently computed
unsigned-64-bit boundaries and the unchanged original Rust
`LaneAdmissionGate` implementation, including actual `pop_ready` and real
`qos_snapshot` after admissions and dequeues. See
[`test_mempool_quota.py`](../../tests/test_mempool_quota.py) and the
[complete M05 contract](../../MEMPOOL.md).

These are *pure proposals*, not authoritative admission, atomic dequeue,
deduplication repair, a nonce reservation, local-pool handoff or durable Node
state. Exact-head CI is mandatory before qualification, and no original Rust
package or migration gate is retired by this kernel.
