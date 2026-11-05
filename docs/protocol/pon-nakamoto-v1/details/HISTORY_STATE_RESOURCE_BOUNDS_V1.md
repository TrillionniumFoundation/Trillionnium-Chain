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

Snapshot ownership and lock splitting need a separate design that preserves the
single durable writer, operation-local parent validity, cancellation and
post-verification re-entry checks. A cache that skips those checks would change
the trust boundary. These changes do not close that remaining engineering work.

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
