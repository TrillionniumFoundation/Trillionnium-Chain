# Native history and state resource boundaries

This development change preserves PNH1/PNW1, transaction bytes, all profile rules
and the existing native SQLite schema. It changes bounded SQL reads, statement
preparation and cancellation. No stored validity or clock verdict is introduced.

## Joined header projection

Full-history clock and batch-confirmation scans use a prepared recursive SELECT
for at most64 ancestors at a time. Each projected row joins the recorded parent
and reads the bounded header,
the final32-byte trace, stored height/root/work and parent height/work. It checks
the header-derived block identifier, stored parent/height/root and exact
parent-height increment. Evaluation observations retain the single-link form of
the same checked projection and their per-edge cumulative-required-work checks.

The first optimization replaced four statements per ancestor with one joined
statement. The current confirmation loop executes ceil(H/64) statements for
H ancestors. The recursive CTE has an explicit64-row LIMIT even for corrupt
cycles, follows only the exact recorded parent, and excludes genesis from packet
projection. The outer SELECT orders rows by their distance from the starting
block. Rust checks consecutive distance, exact expected identity and every
per-link rule before the clock or membership visitor can advance. A short batch
must reach the installed genesis; a missing start or premature end is an error.
The final child still validates the genesis record's parent/root/work shapes.

This reduces SQL executions. Recursive traversal and parent joins still perform
indexed lookups, and the scan remains linear in ancestry length. The query may
read/sort a complete64-row batch before returning its first row; the bound is
not a64-fold latency claim or a deadline. No full packet body is read for ancestors that do not
need transaction membership checks. Every distinct queried inclusion body is
still decoded and its transaction root and membership are checked.

Node-local monotonic counters expose actual header-link query executions and
header/trace bytes returned to Rust. They exclude SQLite page traffic, state
queries, statement preparation, body reads, CPU, RSS and lock queueing. They
count failed projection attempts and never authorize a successful response.
Reopen resets these local counters. The wire response is unchanged.

Every call uses its own observed clock and validates the entire requested
ancestry. Confirmation cancellation runs between queries at most64 checked
headers apart, after the prior statement has ended and before another starts.
It returns no partial confirmation batch. The final active
tip/generation check, changed-header/trace rejection, full inclusion-body checks,
future-ancestor rejection and heavier-branch reorganization tests remain required.

## Ordinary native history pages

The ordinary `history`/`history_with_progress` API and the native ingress History
request still check every actual ancestor from their explicit `tip` down to
`after`. They now use the separate
[`history_page.rs`](../../../../trillionnium/crates/trnm-pon-node/src/store/history_page.rs)
implementation. Each prepared recursive SELECT returns at most 64 complete
child/parent record projections. This path reads the original record metadata;
it does not add the header/trace checks of a confirmation clock scan, use the
binary-lifting index, or reuse a prior ancestry verdict.

The cursor's complete record is checked before the tip's complete record, as
before. For each requested edge, the child's parent/hash/work/root shapes are
checked first, then the parent's complete record and exact height increment.
Parent failures keep their local stored-data identity. An absent caller locator
remains `UNKNOWN_PARENT`; a known but unrelated cursor still becomes `CURSOR`.
Recursion excludes `after`, although the last required child still reads that
cursor's complete parent-record projection. Records below the cursor cannot
introduce a new error. The explicit 64-row LIMIT also bounds a corrupt cycle's
single query; actual per-edge height validation still rejects that cycle.

Only the most recent `limit` IDs in the downward traversal are retained, in an
operation-local deque. At most 16 Hashes, or 512 logical payload bytes, survive
an iteration. At the cursor they are read in reverse order to produce the same
earliest page. The whole H-ID temporary file and its 32H explicit bytes of path
writes are removed. All H edges must finish successfully before any returned
packet is decoded. Packet decoding, complete packet encoding for byte accounting,
the 800,000-byte page cutoff and the first-packet exception retain their order.
The current packet codec's 256 transactions of at most 2,048 bytes already bound
one encoded packet below 800,000 bytes; the retained exception is not claimed to
have a larger valid current-packet witness.

Cancellation preserves the initial callback, the callback before traversal, each
256-edge boundary, and the final callback with the total count. Each callback runs
after the prior SQL statement has ended. A required parent at an edge is checked
before the next callback, even if that parent is also the next batch's child.
The explicit historical tip remains valid across a change of active generation;
this read does not introduce a new active-tip fence or use the active State.
Existing active-KV/root checks and tip/generation/physical-slot fences elsewhere
are unchanged. No history result, State, derived snapshot or lock ownership is
published by this operation.

`history_page_read_counters` reports actual ancestry SELECT attempts, complete
checked edges and the Node-lifetime high-water count of retained page IDs. The
high water is not a per-call difference. Counters include work done before a
failure or cancellation and reset when the Node opens. They are local Rust
observations, absent from the wire schema. They exclude readiness and cursor
queries, complete packet reads, SQLite page traffic and statement preparation.
The 64-row projection and 16-ID deque do not establish an allocator/RSS bound:
SQLite may materialize/sort a batch, and invalid stored metadata can require
allocation before its existing shape rejection.

For a successful H-edge request, ancestry SELECT executions change from 2H to
ceil(H/64), and explicit temporary-path writes change from 32H bytes to zero.
The read still visits all H edges and remains O(H). There is no constant-time
history, bounded total history retention, new lock-splitting result, or implied
64-fold latency improvement.

## State reads and durable writes

Actual KV state is still read, canonically decoded and checked against the
committed root. The new cancellable reader checks cancellation before work,
at most256 rows apart, before and after root construction, and before publishing
the derived snapshot. It rechecks tip/generation and physical state slot before
publication. A cancelled or stale operation cannot publish its prepared snapshot.
Root construction itself remains one bounded nonpreemptive stage; the callback
does not create a hard CPU or wall-clock deadline for that stage.

Delta insertion and attach/detach now reuse prepared INSERT/SELECT/DELETE
statements. They retain exact before-byte checks, canonical before/after bytes,
the same progress fences, single owner and original SQLite transaction boundary.
This adds no persistent cache, schema migration, undo shortcut or reordered write.

A warm M06 `CheckedExecutionParent` now compares every current State entry's canonical
bytes with its opaque predecessor before sharing that predecessor's immutable map.
This avoids a second complete parent-map allocation for that operation, while keeping
all per-value canonical checks, protocol bounds and expected-root checks. The Node's
actual KV read, committed-root validation, progress order and final tip/generation/slot
checks are unchanged. Cold binding, complete successor encoding and history scans are
also unchanged. The [derived commitment contract](DERIVED_STATE_COMMITMENT.md#sharing-complete-bytes-within-a-warm-parent-binding)
defines error precedence, immutable lifetime, complete parity controls and the separate
finite binding A/B observer; its logical retained-map counts do not measure RSS.

Let N be state keys, H the traversed ancestry length, D changed keys and Q the
number of distinct queried inclusion blocks. The current costs remain:

| Operation | Work retained | Boundary |
| --- | --- | --- |
| Actual state read/root | O(N) decoding plus the checked root implementation | Protocol maximum65,536 keys; callback every256 rows; no incremental authority cache. |
| Full confirmation batch | Actual state check, ceil(H/64) header SELECTs, H checked headers and Q full inclusion bodies | At most256 confirmation queries per batch; complete clock scan remains O(H). |
| Ordinary native History page | ceil(H/64) actual parent-record SELECTs, all H edge checks, then complete returned bodies | At most16 retained page IDs and no H-ID temporary file; time remains O(H), with the original256-edge callback positions. |
| Public one-packet History | Bounded local binary-lifting lookups and one full packet | Existing1,024-statement budget; see [ancestry index](NATIVE_ANCESTRY_INDEX.md). |
| Ordinary append | D changed KV writes, actual state/root validation | No full KV copy on the ordinary append path; it still scans actual state. |
| Reorganization/recovery | Verified deltas, snapshots and exact roots | No fixed global branch/history/disk-size bound or constant-time recovery claim. |
| Pool prefix checks | One actual parent and mandatory prologue per operation; M06 applies each newly accepted transaction once | [Pool lifecycle](LOCAL_MEMPOOL_LIFECYCLE.md#same-block-incremental-m06-prefix) preserves complete M05 checks, full roots/output state and independent batch validation; no end-to-end linear-time claim. |

Production public V3 History retains the complete held-owner algorithm. The
operation-local reader described below is private cfg(test) research: its
complete-operation regression prevents enabling it as a production optimization.
State, Head, pool and History still need separately justified read-side
integration. A cache that skips actual checks would change the trust boundary;
no cross-request successful verdict is retained.

## Operation-local readonly public History

Production public V3 retains its original complete held-owner History path.
The two-phase reader below is explicit cfg(test) research only: its module,
operation-local ReadSet and per-owner network-test selector are absent from
production. There is no public opt-in flag, API or failed-read fallback.
For an explicitly selected research V3 `tip != after`, the actual Node owner
prepares a private path/source pin under its mutex. The pin retains the existing writer-lock file descriptor,
directory/database/WAL/SHM identities, immutable source-derived DDL identity,
network/parameters/genesis, actual active tip/generation, physical state slot,
active record and that same writer connection's SQLite `data_version`. It does
not clone a mutable Node or create a second durable writer.

Outside the Node mutex, one fresh SQLite READ_ONLY/NOFOLLOW connection with
`query_only` opens a read transaction. It checks source metadata/schema and the
pinned epoch, runs the original checked binary-lifting lookup in its original
query/validation order, loads the capped complete body, verifies the same packet
identifier/parent/height and constructs the complete original Page. Every used
raw shape/header/jump query fact is recorded once in first-read order; repeated
reads must match. Those facts are private to this operation and never authorize
a future request. The full body and Page remain private.

The actual owner then reenters under the mutex and checks namespace/source,
the current epoch/slot/record, every used raw query fact and complete body again
in one current transaction. The final checks compare `data_version` on the same
original writer connection, including after the ending epoch check. Foreign SQL
write-and-restore is refused even if active generation is unchanged. This does
not claim protection against an owner that can rewrite arbitrary state and its
source; the existing derived-index trust limit still applies. A legitimate same-
owner admission that leaves the pinned active epoch and all used facts unchanged
can complete while the reader's real SQLite snapshot is open.

One cumulative1024 application-statement allowance covers owner preparation,
readonly PRAGMA/BEGIN and context/epoch reads, all repeated ancestry queries,
body reads, final current fact/body/source/epoch/version checks and both mandatory
transaction rollbacks. Cleanup slots are reserved before work starts, including
RAII rollback after error/cancellation. SQLite's internal page work, connection
setup and filesystem checks are not SQL-slot counts or hard deadlines. There is
no renewed second1024 allowance and no held-owner fallback on a failed snapshot.
Final revalidation can make a request exceed the allowance earlier than the
prior held-owner lookup; this conservative availability limit is retained.

Genuine request-budget exhaustion keeps `ANCESTRY_INDEX_BUDGET` and Capacity,
using a private request-budget origin that keeps a healthy owner running. The
production held-owner lookup selects this origin only at its original charged
statement boundary; its single index/body allowance is unchanged. The research
snapshot shares its allowance with the extra fences. Invalid trusted maximums
and callback errors do not acquire this origin. Invalid
trusted limit configuration and original unrecorded ancestry-owner budgets keep
their prior stop policy. Corrupt metadata/schema/read facts are never downgraded;
`local_integrity` overrides even the request origin. A parsed peer error cannot
select that origin. In the research snapshot, an intervening activation of an actual append or
heavier reorganization returns existing `STALE_VIEW` before Page publication; a fresh operation may still
read the explicit old historical tip. Callback cancellation retains its error,
releases the readonly transaction/lease and returns no partial Page.
An unchanged generation with a changed active tip, physical slot or active record
is instead a local-integrity failure with the same `STALE_VIEW` diagnostic; it
cannot downgrade corrupt stored invariants to a routine concurrent-generation
change. Cancellation during those record/slot queries remains outside that
integrity conversion.

For `tip == after`, both default and research V3 keep the original fresh
zero-payload held-owner lookup.
It avoids connection/pin/fence overhead on this case, including the empty-page
tail regression observed in the earlier allocation comparison. No cached empty
answer or new response field is introduced. V2 and ordinary APIs are unchanged.
Readonly SQL still uses SQLite WAL/SHM bookkeeping; no SQL mutation is not a claim
of zero filesystem writes. Selected packet/root/source checks remain
nonpreemptive between callbacks and no process RSS or global disk cap follows.

`store::public_reader::tests::readonly_history_*` controls actual signed packet
admission during a held read snapshot, unchanged single-writer authority, full
Page equality, actual append/heavier reorg refusal, same-generation foreign
write-and-restore and used-fact/body damage, namespace replacement, cancellation,
cold reopen and exact N/N−1 cumulative limits without SQL writes. A real signed
loopback control deliberately lowers only a cfg(test) operation limit, observes
three refusals in each of the default held-owner and explicit research snapshot
paths, then proves both normal History paths and actual Submit still succeed.
The production endpoint always uses1024; this test is not an extreme-height
production exhaustion or public-service availability qualification.

The ignored `readonly_history_whole_operation_and_retained_growth_cost` builds512
real admitted/activated blocks, including256 signed transactions, and records
growth at powers of two, logical database/WAL/SHM bytes and complete cold-reopen
state. It compares64 alternating whole-operation pairs for first-body, short-tail
and empty-page cases against the prior held-owner algorithm in the same binary.
Complete Page JSON encoding/release is included; equality/hashing/export are
outside both clocks. It separately reports time actually holding the owner
mutex, used read facts and the completed cumulative statement count. Full source
and executable hashes and competing-load context are emitted. All regressions
remain evidence; no sustained TPS, WAN gain, permanent retention cap or conflict-
scheduling benefit follows from this read-only comparison.
Diagnostic JSON allocation/hex encoding, equality checks and report export are
outside both sample clocks. The actual512-block deep request also compares the
old full Page, exact complete SQL allowance and one-less refusal, preserving no
Page/SQL-write on that refusal. That deliberately reduced-limit control does not
claim default1024 exhaustion on a realistically retained production height.

    TRNM_PUBLIC_READER_EVIDENCE_DIRECTORY=NEW_DIRECTORY TRNM_READER_CONCURRENT_CONTEXT=RECORDED_CONTEXT cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::public_reader::tests::readonly_history_whole_operation_and_retained_growth_cost -- --exact --ignored --nocapture

### Retained negative complete-operation observation

The finite source-qualified experiment retained four separate M06 Node cost
processes and one512-block reader process, with all competing team builds,
runtimes and scans held during its19.25-second same-host window. A bounded parent
PIPE retained each entire reaped process stream, then atomically saved and fsynced
it, checked all sample identities/source and executable hashes, and compared its
JSONL bytes exactly with the original incremental child file. It accepted256
Node samples and384 reader samples. An earlier window's last baseline had only63
retained sample rows and no terminal result despite an earlier driver completion
claim. That observation remains incomplete and unmodified; the loss cause is
unknown and its missing sample is not reconstructed or combined with this run.

Both reader arms in the complete experiment used the same three `prepare_cached`
SQL helpers. All raw query facts, foreign-write/restore detection, full body,
current owner fencing and the single1024 budget remained. It still found:

|512-block case;64 pairs|Held-owner median / p95|Snapshot median / p95|Whole-call result|
|---|---|---|---|
|First complete packet|1.514 /1.942ms|2.723 /4.338ms|Median +79.88%;64/64 snapshot calls slower|
|Late empty packet|0.630 /0.708ms|1.388 /1.464ms|Median +120.32%;63/64 snapshot calls slower|
|Empty Page;same original path|38.012 /57.946µs|37.957 /42.624µs|Labels execute the same algorithm; no attributable gain|

For the first packet, owner-held median fell from1.391 to0.588ms; that reduction
is not a whole-call throughput gain. The late-packet owner-held median fell from
0.548 to0.353ms. Their complete cumulative SQL counts were232 and58. The exact232
cap succeeded and231 returned no Page/SQL write with a healthy owner. The actual
512-block directory retained31,379,488 logical bytes before and after reads;
complete cold reopen and exact State equality took6.523ms. These are finite
logical-file/recovery observations, not storage-media, RSS, permanent retention
or sustained goodput bounds.

The snapshot also changes availability: a formerly held-lock request could finish
while delaying the writer; a concurrent public Submit/activate can now advance
the pinned generation and refuse the research History call. Actual inactive
admission concurrency and append/reorg refusal are tested, but high-write mixed
successful-History goodput, refusal cost and write latency are not measured.
No claim about that workload follows from the shorter held-lock interval.

The experiment therefore does **not** enable the snapshot as a production
performance path. Production keeps the prior held-owner algorithm. The cached
SQL helper itself has only cross-window supporting timings, without a matched
whole-operation attribution; it is also withdrawn and production uses original
`query_row`. Exact experimental source archives and executables retain the cached
cut so its negative comparison can be reproduced. The only production change
from this reader work is the narrow request-budget origin repair; the cfg(test)
research reader keeps all correctness controls for future measured work.

### Retained disk and recovery model

Let B count all admitted blocks on every retained branch, H a requested ancestry,
D the total retained delta rows/bytes and K the complete active State size. Current
logical storage contains every block packet, every branch delta, at most63 jump
rows per non-genesis block, actual live KV slots and at most64 non-genesis complete
canonical snapshots plus genesis. Legacy snapshots occur at128-height cadence;
the explicitly authenticated backend snapshots each admitted block but keeps
that same64-row policy. Authenticated retained tree/record bytes are an additional
backend-specific term. Neither snapshot pruning nor the fixed scalar accounting
files prune admitted packets, all branch deltas or retained authenticated records.

Ignoring SQLite/index/file overhead, the model is packet bytes plus D plus the
sum of `floor(log2(height))+1` jump-row payloads plus bounded snapshot-count times
actual snapshot payload and live State. The protocol's65,536 keys and160/4096-byte
key/value limits bound a single valid State, not B or permanent admitted-account
growth. The8MiB derived-cache limit chooses a cache/fallback and is not a ledger
disk cap. SQLite pages, freelists, WAL/SHM and filesystem allocation make actual
physical bytes differ from these logical terms. The finite observer reports all
directory files, page counts, block/delta/snapshot/jump/KV rows and actual State
keys rather than treating a small SQLite main file as total disk consumption.

Cold open still selects the heaviest retained candidate, resumes any recorded
intent, checks actual active State/root and active-tip index, and preserves the
selected backend's retained-history verification. The current heaviest selection
orders retained blocks without a dedicated chainwork-order index. A historical
State without a retained snapshot can walk back to genesis and apply/check every
needed delta/root; an old side branch has no promised snapshot distance. Reorg
and authenticated verification can still traverse the actual required ancestry.
There is no constant-time recovery or global H/B bound derived from this reader.

At current limits, State/protocol failures reject complete execution and leave
the admitted transaction/nonce/root unchanged. New History quota exhaustion is
the narrow nonfatal whole-request refusal above; it does not repair a store or
mint another allowance. SQL/storage integrity and durability failures keep their
existing failure policy. No implicit disk-full retry, branch eviction or pruning
is added. Retention/archive policy and a proven old-History/recovery contract
require a separate design and fresh namespace if stored layout changes.512
small-State blocks and one cold reopen establish only their measured scope.

## Reproducible actual growth observation

The history_state_cost example mines, verifies, persists and activates a real
native chain with distinct miner recipients. Its first block contains64 actual
signed transfers; later blocks are empty. It emits every block timing and
1/16/64-query batches at powers of two, with actual state key counts, projected
SQL counters and reopen timing. Read-observation schema v2 records the64-header
limit and actually checked link count, and refuses a sample whose SQL executions
are not ceil(H/64) or whose processed header/trace bytes are not350H. These counts
exclude metadata bytes and physical SQLite page reads. Each reopen compares the exact state and active
identity. Header spacing is logical; this is not a live-paced TPS or WAN test.

The example emits compiled source/config hashes, binary SHA-256 and optional
builder Git claims. Run from a clean committed checkout, capture stdout/stderr
and exit status, and record compiler, hardware, filesystem and concurrent load:

    cargo run --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example history_state_cost -- NEW_DIRECTORY 512

Accepted block limits are16..8192. A failure emits a terminal failure row and
keeps preceding samples and the owned directory. No script turns missing or
failed observations into successful measurements. Timing comparisons require
the same workload, hardware, compiler, filesystem and competing-load conditions.
The bounded example does not replace native exact-capacity tests, independently
operated public service campaigns, long retention or physical power-loss tests.

A separate `pon-history-state-commitment-cost-v1` row at each sampled height records
the actual state-read duration, the checked derived-cache method and retained software
charge before and after that read and each confirmation batch. It also times a fresh
authoritative `pon_executor::root` over the exact observed State and requires equality
with the actual packet root and every reported cache root. This full-root control runs
after all1/16/64-query batches, outside their clocks, and cannot populate or warm the
Node cache. Original v2 read rows retain their schema and interpretation.

The cache observations distinguish rebuilt trees, checked delta application and each
explicit full-root fallback reason; they do not infer an incremental method from a
short duration. Workspace and retained charge are bounded software accounting, not
process RSS, allocator traffic or physical peak memory. The example still uses one
owner without concurrent readers or writers, so these rows measure neither lock
queueing nor the gain from a proposed reader/writer split. No old/new speedup follows
from a single-source full-root control.

The native129-height boundary regression crosses three SQL batches, cancels
before the second query, restores and rechecks a corrupt boundary ancestor's
height and trace, detects an intervening generation change, then reopens and
compares the complete confirmation result. Existing future-ancestor, corrupt
genesis, inclusion-body, actual heavier-reorg and no-partial-response tests remain.

SQL semantics reference: [SQLite recursive CTE algorithm and explicit LIMIT](https://www.sqlite.org/lang_with.html).

## Paired ordinary-page observation

### Bounded packet allocation within the existing owner

The private native `Packet::checked_wire_length` validates count, proof length and
each exact envelope in the original order and returns the complete wire length.
Ordinary History uses this check for its byte cutoff without constructing a full
wire copy merely to obtain its length. The native `Packet::encode` uses the same
check before reserving the remaining wire capacity once. It still
copies every transaction and proof into owned output, checks the same wire limit,
and grants no decoding, work or state authority. Invalid early envelopes cannot
trigger a reservation derived from later unvalidated lengths. A second bounded
transaction traversal fills the output; the change does not remove packet checks.

`packet_encoding_tests::bounded_packet_reservation_preserves_bytes_and_first_error`
compares the complete original grow-and-append codec with the new allocator for
empty, single and full-count packets, short/oversize inputs, malformed envelope/count
and multiple-damage precedence. The normal
`store::history_page::tests::packet_reservation_history_keeps_cancel_errors_and_reopen`
checks complete real history responses, cancellation, no read-side writes and cold
reopen using the same traversal and both codecs.

The separately ignored
`store::history_page::tests::packet_reservation_history_complete_call_cost`
compares 128 alternating pairs for each of three actual-chain read/response cases.
The 32-block fixture has eight actual full 256-signed-transfer blocks followed by
24 empty blocks; every packet is mined, admitted and activated by the existing Node.
Both clocks include the same complete history read, every returned Packet's encoding
to owned response bytes and release of Packet values. Complete byte comparisons,
response hashing/export and release of encoded bytes are outside both clocks.
The original full-copy length calculation and codec are test-only controls in the
same current binary; this is not
a comparison against a separately built historical release. All sample durations,
including regressions, remain in the JSONL report. The final row checks unchanged
database file size, no read-side SQL writes, complete state/root and cold reopen.
The report separates checked packet bytes (including the first cutoff packet),
constructed length-check wire bytes and returned response Vec capacities. Those
are logical owned payload facts, not allocation/RSS or physical-copy counters.
It does not measure WAL/page traffic, process RSS, concurrent lock waiting,
sustained TPS or global history/disk retention. Run from the exact committed source:

    TRNM_PACKET_COST_DIRECTORY=NEW_DIRECTORY cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::history_page::tests::packet_reservation_history_complete_call_cost -- --exact --ignored --nocapture

This allocation change alone did not complete reader/writer separation. Production
public Head, History and pool reads still hold the same Node mutex. The fenced
reader above remains private research after its complete-operation regression.
Existing point proofs
and batched nonce reads use a read transaction on that Node's own connection and
retain full-State checks; they are not independent service reader handles. A further
read-side integration must preserve owner-controlled path/namespace fencing, one
consistent SQLite snapshot through complete checks, fixed historical-tip semantics,
required active-generation re-entry and exactly one durable writer. No mutable
`Node` or authority cache may simply be cloned to remove the mutex. Complete State
cost remains O(N), ordinary history O(H), and pre-COMMIT state readbacks remain.

The regular `history_page_native_pages_keep_complete_bytes_cursor_cancellation_and_reopen`
control constructs 257 actual mined, admitted and activated development blocks.
Its first 17 blocks contain 16 signed transfers each. It compares every returned
packet byte with the earlier complete `ready`/record-query/tempfile/packet
algorithm, including wide-body cutoff, empty pages, 64/256-edge boundaries and
short tails. It also checks required-parent corruption before a boundary callback,
callback cancellation and retry, corruption below an excluded cursor, an actual
fork and heavier-branch switch, unchanged State/slot during reads and reopen.
The smaller `history_page_record_errors_keep_origin_and_validation_order` control
checks full parent shapes, missing parents, cycles and caller-record error order.
The old algorithm is compiled only into the test binary, never exposed as a
production fallback or a second history API.

The ignored `history_page_complete_call_cost` control uses the same independent
whole-operation reference for five fixed cursor/height cases and eight alternating
sample pairs per case. It builds 256..512 actual blocks in a new output directory.
Its timer includes the complete history call, encoding each returned Packet into
owned bytes, and releasing the Packet values. Framing, full-byte comparison,
hashing, file output and release of the retained encoded bytes happen outside
the timer. This scope is broader than a bare API-call timer and is identical for
both arms. The control is the earlier algorithm in the current test binary with
logical counters, not a separately compiled old binary. Source, binary and
builder-claim bindings are emitted before the experiment. No process page cache
is cleared, and no RSS, concurrent lock queue, network or public service claim is
derived from it.

Run explicitly from the exact clean source, keeping the entire output directory,
stdout, stderr and process exit status:

    TRNM_HISTORY_PAGE_COST_DIRECTORY=NEW_DIRECTORY TRNM_HISTORY_PAGE_COST_BLOCKS=512 cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::history_page::tests::history_page_complete_call_cost -- --exact --ignored --nocapture

Every sample checks all output bytes, actual SQL/edge counters and source-defined
path-spool absence against the reference. The first pair of each case exports
complete frames for both arms. A frame contains ASCII `TRNMPAGE1`, a u32 little
endian packet count, then a u32 little endian byte length and full original bytes
for each packet. Later pairs retain complete equality checks and frame SHA-256;
they are repeated observations of those fixed pages, not independent chains.
The original SQLite namespace, complete actual State, full reference root and
reopen check are retained. The observer writes a terminal success only after all
samples and checks finish; a test panic, nonzero process exit or missing terminal
result is failure and must remain visible.


## Streaming authenticated delta comparison continuation

The explicitly selected authenticated backend no longer constructs a second
complete `Vec<Delta>` only to compare it with the actual retained delta rows.
`matches_difference` visits both existing ordered State maps, canonically encodes
every value in the original before/after order, and compares each actual change
with the next retained row. It detects missing, extra, reordered and altered rows.
No Value-equality shortcut replaces byte comparison; absent data, null and signed
zero retain their original distinctions.

The operation checks its existing progress callback before traversal, after every
256 visited union keys (including unchanged keys), and after the final key. A
mismatch does not bypass remaining canonical checks or the final cancellation
fence. Cancellation is propagated before the caller labels an actual completed
mismatch as local integrity failure; no partial result authorizes publication.
Only the current key's temporary encoded values are retained by this comparison.
The stored delta vector, actual full State, root construction, account checks,
final transaction fences and full retained-history verification remain unchanged.
This reduces one duplicate allocation and adds cancellation opportunities; it does
not establish a whole-operation RSS/time bound, incremental-history complexity,
permanent-account growth, or a new authenticated consensus root.

The original independent union reference and all its native differential controls
remain. `store::native_authenticated::difference_stream_tests` additionally exercise
omissions/substitution/order, all-equal and mismatching full traversals, 65,536-key
mechanics, cancellation at every cut and successful retry without input mutation.
Those finite mechanics are not signed ledger-growth or public availability evidence.

### Controlled Submit uses the existing readers

The ordinary public shared Submit path now threads its original cancellation
and execution/CPU observations through the actual parent-state acquisition before
work verification. Controlled native admission also uses those readers on re-entry
and during its complete pre-COMMIT delta/state/active-state fences. Both legacy
and authenticated delta materialization check progress every256 rows before
returning a complete list. Authenticated retained-record hashing can stream those
same checked rows without retaining a full list merely to verify its root.

No full-state check, retained ancestor or final transaction fence is skipped.
All required State and ancestry costs in the table above remain, as do the
nonpreemptive root/SQL primitives and the original post-COMMIT result semantics.
A caller cancelled during a read receives its original error rather than a
partially published snapshot or a local-integrity classification. New callbacks
are not a claim that independent hostile WAN service or permanent account growth
has been accepted.

## Complete-state root encoding without a second payload map

The existing M06 `pon_executor::root` now feeds canonical encodings directly to
`pon_wire::state_root_from_entries`. It no longer builds a second complete
`BTreeMap<Vec<u8>, Vec<u8>>` containing cloned keys and every encoded value before
hashing. Every value's original canonical grammar is still checked in full,
in sorted State order, before the total wire count or per-row byte bounds can
reject. This keeps a late noncanonical value ahead of an earlier oversized key
or the 65536-key limit, as in the original complete-map algorithm.

After that complete grammar pass, one value is encoded, hashed with its borrowed
key, and dropped before the next value is requested. The wire root still retains
all fixed-size key-path and leaf hashes, sorts them by key-path, rejects collisions
and constructs the entire original 256-level sparse tree. The original empty,
key, leaf and node hash domains and all root bytes are unchanged. Empty values
remain distinct from missing leaves. Iterator errors return no partial root.

For N keys the hash-vector payload is still 64N bytes, before Vec capacity and
allocator overhead, plus one temporary encoding. The separately owned input
State is still complete. This removes the extra whole encoded-payload map; it is
not O(log N) total memory, a new sparse-state admission rule, account growth past
the old cap or a measured endpoint throughput result. Root construction and
sorting remain nonpreemptive between the existing surrounding callbacks. Full
account, retained-history, canonical-value and final transactional checks remain.

Native regressions compare against the retained independent pre-refactor sparse
algorithm, both entry orders, branch edits, missing and present empty records,
exact and excessive byte/count bounds, duplicate keys and injected iterator
failure. An owned-value Drop probe verifies that the previous encoding is no
longer retained when the next item is produced. M06 tests retain original error
precedence and actual original canonical encodings. These are mechanism checks,
not public storage or model-service qualification.


## Bounded cache encoding on the actual State path

`pon_commitment::derive_snapshot`, native `checked_snapshot`, and the existing
M06 staged-execution/prefix closures no longer unconditionally retain another
complete canonical successor map before choosing a full-root fallback. The
encoder retains entries only while the selected key/payload/workspace budget
can still fit. Once even the current-state lower bound exceeds that budget, it
drops the accumulated map and continues checking every canonical value and the
original wire dimensions. Later malformed values retain the old error precedence;
an invalid cache option is still reported only after valid State encoding.

The fallback reuses the complete streaming M06 root. When actual parent bytes
are present, two sorted passes compare that retained parent directly against
one successor encoding at a time: first exact delta count/bytes, then the required
public changes after the full root finishes. The old charge formula, fallback
priority, complete change order/bytes, snapshot-absence result and final root
comparison are unchanged. The original full-map algorithm remains a differential
reference, and the selected limits remain 65,536 keys, 8 MiB canonical payload
and 512 MiB logical workspace. These limits select a cache, not ledger validity.

This closes a gap left by optimizing only `pon_executor::root`: an ordinary Node
snapshot check could previously build the whole canonical map *before* finding
that the cache would be refused. It does not remove the complete input State,
the already retained parent bytes of `CheckedExecutionParent`, public deltas,
the fixed-size root hash vector, retained-history checks, or nonpreemptive
canonical/root primitives. A cache that fits still retains its canonical map.
Software charges describe the original conservative selection model, not measured
live allocation after a map was discarded.

Four native differential tests cover exact budget edges, full-map charge parity,
branch changes and removals, explicit parent/prior combinations, and late errors.
An explicitly selected release comparison runs the retained old and new fallback
in separate fresh processes. Its process RSS includes fixture and test harness;
it is not a whole-Node or endpoint throughput measurement.

## Bounded copies from live KV

Both native storage modes use the same active-slot reader. Its SQL projection
preserves invalid SQLite types for refusal, bounds correctly typed key/value
prefixes to161/4097 bytes, and exposes the original byte lengths. Before constructing
an owned Rust key/value, the cursor rejects more than 65,536 rows, keys over
160 UTF-8 bytes and values over4096 bytes. The value must still be a BLOB and the
key TEXT; a CAST does not legitimize another stored type. JSON decoding,
canonical-byte equality, full state/root/account verification and final active
generation checks remain. The extra byte in each projection is only a refusal
sentinel, not a new accepted wire limit.

Initial, each256-row and final cancellation retain the caller's exact typed
error. Stored dimensional/type/canonical failures are local-integrity errors,
not remote-consensus-invalidity or cancellation. No partial State or derived
snapshot is returned. SQLite may still perform internal page reads and sorting;
these copy bounds do not make its internals preemptive or bound process RSS.

Native tests deliberately corrupt and repair real SQLite rows, exercise both
storage modes and reopen, preserve exact byte/type edges, and check the65,536
row decoder boundary. They do not admit extra accounts or simulate a network
attack. In particular, a successful internal row decoder is not a committed
state: a well-formed but uncommitted extra row still fails the actual root check.
