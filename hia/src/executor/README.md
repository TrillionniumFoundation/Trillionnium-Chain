# Native executor scheduling kernel

`schedule.hepta` implements the active `trnm-executor/src/lib.rs` scheduling
kernel with explicit effective configuration. This is the M06 reusable executor
package in the complete repository inventory. The ordinary Node dependency
closure does not currently contain this crate; `trnm-bench` is its ordinary
workspace consumer.

The module implements all seven strategies, the complete 17-field raw grouping
profile, the complete 10-field adaptive decision, and object-domain conflict
detection. It retains ordering, duplicate-reference handling, opaque transaction
identity, version-skew refusal, hot-bucket rotation, adaptive sampling and
aggressive deep-scan flags/counters. It compiles through the unchanged pinned
HIA selfhost compiler and explicitly includes the named binary64 helpers from
`../math/binary64.hepta`. No Python algorithm executes in the native artifact.

## Intentional safety correction

The original public function promises groups without pairwise read/write or
write/write conflicts. Its reader map overwrites a previously higher group with
the group of a later reader. This violates that promise. With object versions 1:

| Input index | Reads | Writes |
|---|---|---|
| 0 | — | B |
| 1 | A, B | — |
| 2 | A | — |
| 3 | — | A |

Source-derived original groups are `[[0,2],[1,3]]`; indices 1 and 3 conflict on A.
The HIA result is `[[0,2],[1],[3]]`. Each object's reader entry now retains the
maximum reader group. The unchanged original Rust library remains the reference
for recording this defect, not an acceptance target for its unsafe result.

This correction can also change deep-scan placement/counters when an original
result happened to be conflict-free. Tests record every old/new difference and
require the new result to agree with the independently represented high-water
correction. A separate pairwise graph verifies no conflicting group and every
input index exactly once. No old result is exempted solely because it was unsafe.

The correction has a direct invariant: writer groups for one key increase
strictly, while the reader entry is the maximum of every previous reader group.
The lower placement bound is therefore greater than every earlier conflicting
access. Both ordinary placement and every deep-scan candidate meet this bound;
appending a new group also meets it. This preserves the promised within-group
safety independently of which deterministic reorder strategy supplies the input
order. Native pairwise graph tests check the invariant's observable consequence.

The source-derived legacy model is not evidence that Rust was executed. The
original-library qualifier reports `NOT_RUN` and exits 2 when Cargo/rustc are
unavailable. It reports PASS only after building the unchanged pinned library,
running the real original public functions, comparing them with the legacy
model, and comparing native results with the repaired model. Its result is
explicitly `PASS_WITH_EXPLICIT_ORIGINAL_SAFETY_DEFECT`, preserving original
failures rather than claiming original safety or whole-project acceptance.

## Entry and ownership

The only export is `f0(readbuf input, mutbuf output, mutbuf scratch) -> u32`.
All integers use little-endian unsigned 64-bit words unless specified otherwise.
Caller allocations must satisfy the existing exclusive borrowed-buffer ABI;
the source, output and scratch live extents must not overlap. Input is read only.
The function has no filesystem, process environment, clock or external authority
access. Scratch is initialized for every successful parse, permitting sequential
reuse across different batch sizes and configurations.

There is no new transaction/reference/payload count ceiling. Checked lengths,
addressable memory and the caller's extents bound the frame. The test runner's
1 MiB convenience bound is not a product limit: raw sealed-artifact tests run
8,192 transactions with a 1,970,176-byte scratch arena, unaligned pointers,
canaries and sequential reuse. This demonstrates that extent; it does not
establish throughput, a service deadline or an unbounded resource guarantee.

### Input header: 128 bytes

| Offset | Field | Accepted values |
|---|---|---|
| 0 | Magic | 8 bytes `EXSCH001` |
| 8 | Operation | 0 schedule; 1 detect conflict; 2 adaptive decision |
| 16 | Strategy | 0 Original; 1 FootprintDesc; 2 WriteFirst; 3 WriteLast; 4 HotBucketInterleave; 5 AutoAdaptive; 6 AggressiveGreedy |
| 24 | Transaction count N | Frame must contain exactly N records; conflict operation requires 2 |
| 32 | Flags | bit 0 deep scan; bit 1 skip empty stage checks; bit 2 round robin; no other bits |
| 40 | Hot bucket count | 4..64 |
| 48 | Adaptive minimum batch | 64..4096 |
| 56 | Adaptive sample | 64..2048 |
| 64 | Aggressive scan window | 0..4096; zero means unlimited |
| 72 | Round-robin seed | Complete u64 range |
| 80 | Streak threshold | binary64 bits; finite [0,1], including -0 |
| 88 | Minimum margin | Same binary64 domain |
| 96 | Minimum hot share | Same binary64 domain |
| 104 | Minimum expected gain | Same binary64 domain |
| 112,120 | Reserved | Both zero |

The default effective values, when explicitly supplied by a caller, are flags
6, buckets 8, minimum batch 512, sample 2048, window/seed 0, and binary64 values
0.22, 0.04, 0.0075, 0.01. All fields are validated even if the selected operation
does not consume them. The frame is a pure-kernel interface, not the original
environment text format or an activated node protocol.

Each transaction contains four words `id, read_count, write_count, payload_len`,
then `read_count` pairs `(object_id, version)`, then `write_count` pairs, then
exactly `payload_len` opaque bytes. Trailing bytes are refused. Object ID zero,
high-bit IDs, version zero, version u64::MAX and duplicate transaction IDs are
valid. Within one transaction, a repeated object ID must carry the same version
across both lists; otherwise code 5 is returned. Across transactions, conflict
identity is the object ID, independently of version.

### Capacity and refusal

Let M be the number of raw reference pairs, including duplicates. Scratch needs
`4096 + 168*N + 72*M` bytes. Schedule output requires the conservative capacity
`264 + 16*N`; conflict/decision output requires 256. All arithmetic is checked
before writes. The schedule's actual written prefix is `264 + 8*(N+G)`, where G
is its group count. No bytes after the written/used prefixes change.

| Code | Meaning | Mutations |
|---|---|---|
| 0 | Successful result | Only declared output/scratch prefixes |
| 1 | Truncated/inconsistent frame or trailing bytes | No output or scratch writes |
| 2 | Bad magic | No output or scratch writes |
| 3 | Invalid operation, strategy, effective config, reserved field or conflict arity | No output or scratch writes |
| 5 | Within-transaction object version skew | Output unchanged; scratch may contain parsing work |
| 100 | Insufficient capacity or capacity arithmetic overflow | No output or scratch writes |

The order is minimum header length, magic, configuration/arity, complete frame
shape, capacities, version consistency, operation. The Rust API accepts typed
transactions and panics for version skew; code 5 is the native wire boundary's
explicit refusal, not a claim that Rust returned the same numeric code.

### Output header: 256 bytes

Words 0..4 contain magic `EXSCOUT1`, operation, N, G and selected strategy. For
conflict detection word 3 contains the conflict Boolean. AutoAdaptive resolves
to Original or HotBucketInterleave for nonempty schedule input; empty scheduling
returns before resolution, matching the original early return.

Words 5..21 contain the full raw profile in original declaration order:
`tx_count, group_count, grouped_count, max_group_size, min_group_size,
avg_group_size_bits, hot_object_share_bits, conflict_checks, conflict_hits,
candidate_groups_scanned, retry_fallback_new_groups, stage_ww_checks,
stage_ww_hits, stage_wr_checks, stage_wr_hits, stage_rw_checks, stage_rw_hits`.

Words 22..31 contain the adaptive decision:
`use_hot_bucket, reason, sample_len, streak_ratio_bits, streak_threshold_bits,
min_margin_bits, hot_key_share_bits, min_hot_key_share_bits,
expected_gain_score_bits, min_expected_gain_score_bits`. Reason codes are 0 not
requested, 1 small batch, 2 insufficient sample, 3 hotspot detected, 4 low hot
share, 5 low expected gain, 6 below streak budget. Non-requested fields are zero.

Schedule results append G+1 cumulative u64 group offsets, then N original input
indices. These indices identify unchanged input transaction records, including
opaque payload and duplicate-ID identity, without allocating host-side Tx
clones. Other operations do not append arrays and leave raw profile words zero.

## Evidence and remaining scope

`hia/tests/test_executor_schedule.py` uses independent Python sets/queues and
hardware binary64 for expectations; tests execute the actual HIA artifact.
It includes all 8^4 four-transaction access combinations distributed over seven
strategies, all-strategy randomized batches, all bucket counts, adaptive reason
and ULP boundaries, the 2048-element sampler, wide group spans, malformed frames,
within-domain version skew, output atomicity, unaligned physical buffers and
arena reuse. The source-derived model and native execution have separate roles.

`hia/tools/qualify_executor_original.py` compiles the actual pinned original
Cargo `trnm-executor` library using `--locked`, obtains the emitted library paths
from Cargo's JSON output, and links only a transport adapter. The adapter invokes
the public grouping, profiling, conflict and adaptive-decision functions. Its
test frames have unique opaque payloads, and it verifies every returned clone
against the complete original transaction before returning input indices. It
does not replace the original Tx type or copy the algorithm into a fake oracle.

The environment string parser, derived profile convenience methods (including
the `ln` entropy metric), bench integration, execution of transactions, state
application and a Node owner are outside this component. Raw profile output does
not imply those methods were ported. The deep-scan implementation represents
group-set intersections by scanning actual group members; it can have higher
cost than the original HashSet implementation. Adaptive histograms are bounded
by the original 2048 sample count but currently use a quadratic comparison loop.
No service performance or whole-crate retirement is claimed.

The original executor and source-inventory readers must remain until their
remaining contracts and all real original qualification are closed. Uncompiled
sibling Rust files still have inventory consumers; this work does not authorize
their deletion.
