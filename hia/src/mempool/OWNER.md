# Native lane admission owner

`lane_owner.hepta` owns the two physical FIFO queues and the fairness state of
the original `trnm_mempool::LaneAdmissionGate`. Its public operation histories
start at `LaneAdmissionGate::new` and cover `admit`, `pop_ready`,
`queued_counts`, and `qos_snapshot`. Queue contents persist in the same private
context between native calls. Admission, membership scans, ring writes,
dequeue, lane selection, and fairness updates execute emitted HIA machine code.

This component does not complete M05. Typed signed admission, pending nonce
authority and reservations, local pool integration, Node call-site integration,
restart persistence, concurrency, and service-budget qualification remain
outside this owner. It does not accept restored Rust private fields or emulate
the original private cache corruption/recovery tests. Its behavioral comparison
covers states reached through the public constructor and operations.

## Entry and lifetime

The exported byte entry is `f0(input: readbuf, output: mutbuf, ctx: mutbuf)`.
Its three borrowed regions follow the pinned compiler's private-buffer entry
profile. The caller retains the allocation, provides exclusive access for each
call, and keeps the same context alive across an operation sequence. A valid
context is private owner memory, not an authenticated external storage format
or an invitation to edit queue bytes between calls.

Input is exactly 40 bytes. All integer fields are unsigned little-endian u64.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `NLOV0001` |
| 8 | 8 | Operation |
| 16 | 8 | Argument 0 |
| 24 | 8 | Argument 1 |
| 32 | 8 | Reserved, must be zero |

| Operation | Arguments | Effect |
| --- | --- | --- |
| 0, NEW | Total capacity, requested critical reserve | Construct a live owner; clamp reserve to total |
| 1, ADMIT_NORMAL | ID, zero | Admit to normal capacity or permitted critical headroom |
| 2, ADMIT_CRITICAL | ID, zero | Admit to critical capacity or free normal capacity |
| 3, POP | Zero, zero | Dequeue an actual ID according to lane fairness |
| 4, COUNTS | Zero, zero | Read the live queue counts and accompanying QoS fields |
| 5, QOS | Zero, zero | Read the live queue counts and QoS fields |
| 6, CLEAR | Zero, zero | Erase all queued IDs and reconstruct with the same configuration |
| 7, CLOSE | Zero, zero | Erase the complete owned extent and end the lifetime |

CLEAR and CLOSE are explicit ABI lifetime extensions. Their reference adapter
uses the original public constructor after dropping the existing Rust gate, or
drops the Rust gate without replacement, respectively. They are not advertised
as new methods on the original type.

NEW requires a zero 128-byte header. The backing queue region may contain old
bytes; successful construction erases the complete new owned extent before
publishing its header. NEW refuses a live owner. CLOSE permits reusing the same
allocation for a later NEW. Querying or closing an already closed owner refuses
without rewriting bytes. The owner does not automatically destroy a live
context whose descriptor is invalid.

The physical region must hold at least `128 + 8 * total_capacity` bytes. Capacity
is checked by dividing the supplied available extent before multiplying any
untrusted capacity. A requested critical reserve of `u64::MAX` is valid when the
total fits; it clamps to that total. A total of zero is a live hard-stop owner:
fresh admission is backpressured, pop returns none, and all headroom is zero.

## Reply and refusal

Successful calls publish exactly 96 bytes and leave any output suffix unchanged.
The reply uses `NLOR0001` at bytes 0–7 followed by eleven little-endian u64 fields.

| Offset | Meaning |
| --- | --- |
| 8 | Operation |
| 16 | Operation outcome |
| 24 | Supplied or popped ID |
| 32 | Normal queued count |
| 40 | Critical queued count |
| 48 | Total queued count |
| 56 | Normal headroom |
| 64 | Critical headroom |
| 72 | Total headroom |
| 80 | Fresh normal admission permitted, zero or one |
| 88 | Fresh critical admission permitted, zero or one |

Admission outcomes are 0 Accepted, 1 Duplicate, and 2 Backpressured. The supplied
ID is returned for each of those outcomes. POP outcomes are 0 None and 1 Some;
the separate outcome field makes popped ID zero unambiguous. Other successful
operations use outcome and ID zero. CLOSE returns a zeroed closed snapshot after
the magic and operation; it does not retain a live configuration in the reply.

The byte entry's u32 result is:

| Status | Meaning |
| --- | --- |
| 0 | Success; inspect the reply's operation outcome |
| 1 | Invalid frame length, magic, operation, or reserved arguments |
| 2 | Output has fewer than 96 bytes |
| 3 | Context has fewer than 128 bytes, or NEW capacity exceeds supplied memory |
| 4 | NEW header is nonzero, owner is not live, or private scalar shape is invalid |
| 5 | Allocation of the temporary canonical-policy frame failed |

Checks run in the table's general order: complete frame, output extent, minimum
context extent, then new/live state. NEW checks capacity before its zero header.
Returned refusals 1–5 leave the complete supplied output and context unchanged.
Duplicate and Backpressured are successful admission observations and also
leave all context bytes unchanged. COUNTS and QOS are byte-idempotent reads.

All non-close successful operations allocate one 56-byte internal frame before
any context or output mutation. A failed `buffer.try_new` is handled by status 5;
the empty owner is dropped. Successful calls end the frame loan and drop the
temporary buffer. CLOSE performs no allocation. This ordering keeps resource
refusal atomic even for a NEW or CLEAR that would otherwise erase memory.

Internal impossible queue overflow/underflow traps are not converted into
successful outcomes. An unexpected refusal from the checked canonical policy
also traps. A signal, trap, or incomplete native worker observation fails the
qualification; none is counted as a refusal or a completed operation.

## Private memory layout

The owner header is 128 bytes, followed by `total_capacity` u64 slots. No ID value
is a sentinel: zero and `u64::MAX` are ordinary queue entries. Head and count
fields identify the live slots. Unoccupied slots are zeroed on construction,
clear, and individual dequeue, but membership never treats that zero as an ID.

| Offset | Private field |
| --- | --- |
| 0 | `NLOC0001` |
| 8 | Live flag, one |
| 16 | Exact owned extent, `128 + 8 * total` |
| 24 | Total capacity |
| 32 | Clamped critical reserve |
| 40 | Normal capacity, total minus reserve |
| 48 | Normal ring head |
| 56 | Normal count |
| 64 | Critical ring head |
| 72 | Critical count |
| 80 | Critical served streak |
| 88 | Critical burst limit, `max(1, saturating(2 * reserve))` |
| 96–127 | Four reserved zero words |
| 128 | Start of normal ring, normal-capacity slots |
| `128 + 8 * normal_capacity` | Start of critical ring, reserve slots |

Successful POP zeros its old physical slot, advances that ring modulo its
capacity, and resets the head to zero when the ring becomes empty. Empty or
zero-capacity rings are never indexed. CLOSE zeros all bytes up to the stored
owned extent, including header and every queue slot. Bytes after that extent
belong to the caller and remain unchanged.

Every live call validates magic, live flag, exact extent, total fitting the
actual borrowed extent, clamped configuration, burst and streak bounds, both
ring heads/counts, empty heads, and reserved words before queue access. These
checks defend the described ABI shape. They are not a corruption detector for
arbitrary changes to valid-looking private IDs or ring contents, and do not
claim recovery of a forged or restored context.

## Canonical policy composition

The component manifest includes exactly three existing functions from
`lane_quota.hepta`: `lane_policy`, `f1`, and `f2`. The prior first entry `f0` stays
first as a thin call wrapper. Its previous complete body is renamed
`lane_policy`; the original `f1`/`f2` bodies are unchanged. Existing scalar
callers keep their original entry and wire contract.

The owner constructs the canonical `LQV1` frame from its own actual capacities,
counts, and fairness streak. It calls the existing checked policy for fresh
class admissibility (16/17), lane choice (18), post-pop streak (19), accepted
admission warmup (7/8), and the five-field QoS result (24). The caller never
supplies projected queue counts or an admission authorization bit.

ID deduplication scans only the live slots of both physical rings before any
headroom decision, preserving cross-class duplicate precedence even when full.
The original HashSets are derived caches of public-state queue membership. This
owner stores authoritative queue contents and performs exact scans; it needs no
cache self-heal path for public histories. An admission stores its ID in the
selected physical queue, then updates fairness from the new authoritative
counts. A POP computes lane and post-pop streak from the pre-pop state, removes
that queue's actual front ID, then stores the new streak.

## Qualification

The retained [development observations](../../qualification/mempool-owner-development.json)
contain 41,365 local native owner calls and 2,042 existing scalar-policy calls.
A separate real Rust 1.95 build of the complete unchanged original crate
executed 41,248 public operations across 1,862 histories; all reply and input
digests matched. The final-source hosted test below must still complete its
direct original/native comparison. The isolated development include manifest
and the published composition are separately identified in the report.

`test_mempool_owner.py` compiles this source with the pinned native self-hosted
compiler. The worker seals and loads the exact emitted ELF. It creates each
private context once, retains its physical address throughout the history, and
interleaves independent owners. It never copies an observed context back in or
runs the model on the native path. Every reply and private ring observation is
checked against a separate deque model.

The corpus includes zero capacity, reserve zero, reserve-only configurations,
reserve greater than total, requested `u64::MAX` reserve, both extreme ID values,
duplicate probes in both classes, saturation, spillover, warm and cold fairness,
drain and reuse, explicit queries, clear, close, and subsequent new lifetimes.
Long histories require observing both physical rings wrap while they remain
nonempty. Short histories exhaust all three-command combinations of normal/
critical admission with ID zero/MAX and pop for fourteen configurations.

Malformed frames, short output, insufficient context, active reinitialization,
closed calls, and malformed private scalar descriptors verify exact refusal and
unchanged bytes. Close and clear verify physical erasure and suffix canaries.
The allocation test builds a temporary Linux/glibc test injector that denies
`calloc` only while the unchanged native entry executes. It observes status 5
and unchanged bytes for NEW, both admissions, POP, both queries, and CLEAR, then
checks that CLOSE still succeeds, erases the owner, and makes no allocation.
The injector performs no admission, queue, or successful runtime computation.

The mandatory original-Rust test compiles the complete unchanged
`trillionnium/crates/trnm-mempool/src/lib.rs` and its real module dependencies as
an rlib. `rust_mempool_owner_reference.rs` only translates the same public
commands to actual public Rust calls and serializes their returned IDs,
outcomes, counts, and QoS. Every operation result is compared with emitted HIA
and the independent model. Missing Rust, a failed build, or a mismatch fails the
test; it is never silently skipped. The existing scalar-policy suite must also
run after the wrapper refactor.

Correctness of these histories is separate from throughput qualification. Live
ID lookup is linear in queued IDs; enqueue/dequeue and snapshots otherwise use
bounded scalar work. Each non-close call allocates and frees a temporary frame.
No production latency, adversarial flood budget, multi-thread scheduling,
restart durability, cross-target result, or whole-chain migration claim follows
from this component's correctness tests.
