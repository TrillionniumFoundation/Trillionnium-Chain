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

Let N be state keys, H the traversed ancestry length, D changed keys and Q the
number of distinct queried inclusion blocks. The current costs remain:

| Operation | Work retained | Boundary |
| --- | --- | --- |
| Actual state read/root | O(N) decoding plus the checked root implementation | Protocol maximum65,536 keys; callback every256 rows; no incremental authority cache. |
| Full confirmation batch | Actual state check, ceil(H/64) header SELECTs, H checked headers and Q full inclusion bodies | At most256 confirmation queries per batch; complete clock scan remains O(H). |
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

The native129-height boundary regression crosses three SQL batches, cancels
before the second query, restores and rechecks a corrupt boundary ancestor's
height and trace, detects an intervening generation change, then reopens and
compares the complete confirmation result. Existing future-ancestor, corrupt
genesis, inclusion-body, actual heavier-reorg and no-partial-response tests remain.

SQL semantics reference: [SQLite recursive CTE algorithm and explicit LIMIT](https://www.sqlite.org/lang_with.html).
