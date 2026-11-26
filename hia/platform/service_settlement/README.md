# Native SettlementEngine

This directory builds and qualifies the finite Service SettlementEngine public owner. The implementation is HIA. The hosted Python files orchestrate compilation and test execution; they do not execute Settlement business decisions for the public library.

The owned interface is declared in `engine_owned.h` and has 21 exact exports. Constructors and successful operations mint independent immutable owners. Borrowed views remain valid while their owner is alive. Callers must pass live handles created by this library and honor the C pointer, length, and ownership contract.

## Rebuild and qualify

Use the repository's pinned Hepta revision and native compiler. Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER`, and `HIA_NATIVE_COMPILER_SHA256` according to `hia/toolchain.lock.json` and the compiler binding. Rust qualification uses the unchanged locked original source with Rust 1.95.0, offline Cargo dependency resolution, and an empty target in the new output.

```sh
bash scripts/project-preflight.sh
python3 -B -m hia.platform.service_settlement.build --output /new/out/build
python3 -B -m hia.platform.service_settlement.qualify run --output /new/out/qualification --rust-bin /path/to/1.95.0-x86_64-unknown-linux-gnu/bin
python3 -B -m hia.platform.service_settlement.readback --input /new/out/qualification --output /new/out/independent-readback
```

Attached development checkouts run the normal project preflight before qualification. Detached read-only CI uses the existing audit mode and still binds the exact source, HEAD, tree, project boundary, and remote identity. The audit mode does not alter staged or push rules.

Every output must be new and outside the repository. The independent reader writes only its separate output. A complete gate requires both the fresh qualifier and independent reader to succeed.

The gate retains all eight native compiler inputs and outputs, the actual HIA ownership emitter buffers, exact public link, current source and tool identities, original Cargo events and feature graph, all process stdout and stderr, and complete observed response bytes. It preserves the original 30-second compiler limit and 128-function, 8192-operation budgets. The full qualification has a 1200-second deadline. Native observations and allocation controls retain their 240-second deadlines; the original generator retains 120 seconds. Owned commands use one independent three-second cleanup deadline.

The finite required roster is 137 original registered tests: 136 outer tests and the original child fixture explicitly exercised by its parent in both crash phases. The two original compile-fail documentation tests, formatting and strict Clippy are mandatory. Native comparison covers all 320 fixtures and 2636 operations, including 16066 native calls and 1754 independently recorded FFI height values. Allocation coverage requires 162 controls with 136 actual calloc refusals and eight concurrent readers producing 256 independent owners. The fixed 68 integrity controls are named in `qualification/integrity_roster.py`; a partial or failed result cannot become a successful report.

## Scope

This is the Engine owner qualification. It does not qualify a native SQLite Store, Node integration, the original service resource budget, other targets, production activation, a complete host dependency closure, package retirement, or whole-chain native completion. Original Rust remains the mandatory comparison implementation. The public runtime does not fall back to Rust or a Python interpreter. The allocator observer is test-only C and is linked only into the separate test image; the production library is not changed by those controls.

All failures and partial captures remain in their original output. Repeating qualification creates a new output and new execution identity.

For a native-stage timeout, inspect `native/fixture-progress.jsonl` in the original evidence. Its last complete line records the most recent phase reached; the fixture and operation ordinals are one-based positions in the frozen corpus. An `operation_start` row identifies an operation entered, not one completed. Rows include elapsed monotonic wall time, calling-thread CPU time, completed counts, and the next `calls.jsonl` ordinal. `public_dispatch_wall_ns` accumulates wall time inside the common public ABI dispatcher, excluding direct drops and private fee calls. It is a subset of stage wall time; neither it nor wall time minus CPU identifies scheduler wait by itself. The journal is best effort, bounded to 4096 rows (512 bytes each), retains complete lines without a final flush, contains no request or response bytes, and does not determine qualification status or change any deadline.

The hosted Settlement matrix additionally uploads `hia-settlement-compact-<head>-<run>-<attempt>` before packaging the complete archive. Its one bounded `summary.json` contains hashes of observed original source binds and phase receipts; it projects only fixed statuses, flags and counts. The last complete fixture-progress row, complete-row count and trailing-fragment byte count come from the existing journal. Missing, refused, changed and over-limit inputs are named without substituting successful values. The original receipt files, cursor history and full archive remain unchanged; raw requests, responses, command lines, exception text and environment records are not part of this companion. It neither qualifies a run nor changes a job outcome. A runner terminated before collection may have no companion.

The same compact summary reports the original integrity report's availability and hash separately from its 240-second process receipt. The report exposes only the fixed roster's recorded `PASS`/`REJECTED` values in order, plus the last recorded and first unrecorded control. An unrecorded control is not an observed failure or acceptance, and a producer `PASS` is not independent reader success. No exception strings, source inputs, arbitrary control labels or nested diagnostics are exported.

### Read-only Store schema gate (finite qualification)

`schema_read.hepta` is a separate qualification-only SQLite continuation. The
native URI encoder supplies the pathname URI; a disposable fixture transport
supplies the first 20 raw file bytes and relays the continuation's requests to
the exact checked native SQLite provider. HIA refuses a WAL header before any
SQLite open, selects the original read-only URI/NOFOLLOW/NOMUTEX flags, sets the
original two-second busy timeout, and executes `BEGIN DEFERRED`. HIA then checks
the exact three ordered names and SQLite definitions and the original zero
trigger count; nothing is published before the real statement and connection
close. An owned rollback-journal reader keeps an original writer from committing
between steps. The test uses the extracted exact original Rust Store open and
schema functions with its locked bundled SQLite, and checks extra/missing/
changed tables, forbidden triggers, and the original WAL refusal.

The fixture checks its private directory's currently resolved pathname and
refuses a final symlink before reading the header. SQLite also uses NOFOLLOW.
That is not a stable ancestor/descriptor identity, the original sidecar gate,
or the original post-open file check. None of those owner checks, metadata/state
decoding, journal replay, application state verification, or whole-Store or Node
integration is qualified here.

```sh
python3 -B -m unittest hia.tests.test_settlement_schema_read -v
```

### Bounded, checksum-checked metadata observation

`metadata_read.hepta` reuses the successful schema check without closing the
read transaction first. A private invocation supplies the independently
encoded, expected fixture configuration (1 to 65,536 bytes). HIA reads the
original singleton SELECT, checks SQLite value types, schema version,
nonnegative sequence/height, fence, config equality, and the fixed-width
BLOBs. It hashes the original store-checksum domain and all nine original
little-endian-length-prefixed fields, including the raw serialized state,
without publishing configuration or state. An oversized column response
(over 1 MiB including the 24-byte provider framing) is refused. These are
private fixture bounds, not proposed production database limits.

Only after statement finalization and real close does the handler expose a
147-byte diagnostic: schema u16 LE, sequence and height u64 LE, block ID,
state root field, journal root field, fence byte and stored checksum. This
is an observation of checked raw bytes, not verification of state or history.
A checksum does not convey authority. The Rust Store still owns strict Borsh
state decode and round-trip, recomputation of the canonical state root,
committed-block and journal replay, fence policy at public open/readback,
and the filesystem identity and sidecar checks above.

### Bounded, checksum-checked operation lookup

`operation_read.hepta` binds an exact 32-byte operation ID as a SQLite BLOB
in the original `operations WHERE operation_id=?1` select. A native schema
check and the query share one rollback-journal read transaction. For a row,
HIA checks the signed SQLite sequence, exact returned ID, encoded BLOB types
and widths, and original checksum over sequence, ID and the raw execution,
command and receipt bytes. Responses larger than the private 1 MiB frame cap
are refused. After finalize and real close it publishes an 8-byte absent
marker or an 80-byte found diagnostic (marker, sequence, ID and checksum).
Raw operation payloads are never published.

The oracle runs the exact retained Rust `load_operation` on stores where
the original owner genuinely committed two commands from the pinned
Settlement fixture. It compares present and absent observations, held
rollback reads and failure controls. Native lookup does not supersede
Rust's strict typed Borsh decodes and derived operation/receipt identity,
nor production Store metadata checks, replay, confirmation or trust.

### Bounded committed-block marker checksum and linkage

`marker_read.hepta` reads the original typed fields in marker-sequence order
inside the same read-only SQLite transaction as the original schema check.
The disposable test fixture binds the independently original genesis height,
block ID, state root, empty operation-journal root, and canonical configuration.
HIA checks the original checksum domain and length-framed marker fields,
the original configuration-bound predecessor checksum, the anchor and every
direct parent link. It checks marker-sequence continuity, height advancement,
parent identity, predecessor checksum, and source sequence/state/operation
roots against the prior row's targets. It refuses empty journals and states
a private maximum of 64 marker rows, not a new production limit.

Only after finalize and close does the handler publish a 40-byte observation
(row count and tail checksum). The original owner still checks operation
ranges and canonical operation roots by replay, target state and metadata
head, and all production Store and authority rules. The original differential
uses its public Store API to create the anchor, commit commands and advance
empty blocks, and its exact retained Rust marker loader and public readback
for comparison, including a checksum-valid but invalid direct-parent fixture.

### Joined read-only terminal comparison

`terminal_join.hepta` checks the original schema, checksum-checked metadata,
and the ordered checksum-checked marker chain in a single provider read
transaction. Both checks must use exactly the same fixture configuration.
Without reopening the database, HIA compares the terminal marker's target
sequence, height, block ID, state-root field and journal-root field with
the metadata and reads the actual operation count. It refuses fenced
metadata as the original public readback does. Only after finalization and
close does it return the marker and metadata diagnostics together (187 bytes).

This covers a bounded terminal consistency check, not canonical state-root
or operation-journal root recomputation, per-operation replay, or authority.
The original differential includes a held read with actual operations and
empty committed blocks. Checksum-valid components can each be read alone,
yet the joined check will reject disagreement with the marker or with the
actual operation count. The previous standalone readers continue to close
after their own observations.

### Ordered receipt journal root in the held terminal snapshot

`journal_read.hepta` continues the checked terminal snapshot without
reopening SQLite. It binds the original signed SQLite upper sequence bound
and streams the exact original `length(receipt), receipt` query in sequence
order. Native SHA-256 consumes the original little-endian u32 domain framing,
Borsh vector count, and each receipt's little-endian u32 length and raw bytes.
It checks actual typed lengths, exact row count and original aggregate byte
bound. The fixture envelope additionally caps receipts at 256 rows and each
response at 1 MiB including provider framing, without changing production
limits. Oversized receipt length refuses before asking the provider for
the BLOB.

The recomputed journal root must equal both the checked metadata root field
and marker tail target operation root. The diagnostic appends the result
to the earlier terminal observation only after final statement and physical
connection close. Raw receipts are not published. This is not semantic
receipt verification, state-root recomputation, operation execution replay,
or authority. On a disposable genuine original Store, substituting a raw
receipt while preserving row count and its exact original row checksum
still changes the actual ordered original root; the previous terminal join
alone passes, while this read refuses before publication.

The standalone M12 `transition_receipt_decode.hepta` accepts the entire
canonical Borsh transition receipt, not just its identity range. Its private
input is an independently supplied 42-byte sequence/operation-ID/kind binding
followed by the receipt. The fixed-width fields have no noncanonical encodings.
The settlement-ID option requires tag 0 with exactly 149 receipt bytes or tag 1
with exactly 181 bytes. Only after validating that complete shape and all three
identity fields does it output the complete canonical receipt. The original
Store comparison uses retained receipt, rollup, and settlement commands, and
consumes their actual persisted receipts with the original strict decoder. This
standalone fixture does not yet run inside the native held journal stream,
derive the operation ID from the command, or authorize replay or publication.

The opt-in M12 `identity_journal_read.hepta` adds strict receipt shape and
typed SQLite sequence and operation-ID checks to the existing held journal
stream. It requires the actual row sequence to be the next contiguous sequence
and compares both actual row fields to the canonical receipt before streaming
that receipt into the same original journal root. It neither treats the receipt's
kind as independently validated nor derives a command ID. Both private read
routes retain the existing 219-byte diagnostic, compare original root bytes, and
publish it only after closing the held snapshot; the earlier raw route keeps
its original scope. The original-Store differential includes actual Some
settlement receipts and uses original checksum/root routines on disposable
negative fixtures to distinguish Borsh/identity refusal from hash mismatch.

The standalone M12 `settle_command_id.hepta` fully traverses the original
`Settle` Borsh command. The enum tag, fixed fields, exact-length UTF-8
`ProtocolContextV1.chain_id`, and complete suffix are checked before digest
publication. It reconstructs the canonical Borsh frame in work memory,
derives the original SHA-256 operation ID over the length-prefixed domain and
that frame, and emits little-endian kind 26, the ID, and the full canonical
frame. The private reader bounds the chain ID to 4096 bytes and refuses every
other command tag; neither the private cap nor encoding validation is a
protocol acceptance rule. It does not validate trust, apply a settlement,
own the Receipt or Rollup commands, or yet run inside the held journal.

The standalone M12 `receipt_command_id.hepta` similarly owns the complete
original kind-24 `AdmitReceipt` Borsh frame. It traverses both nested usage
vectors (each entry has two byte vectors), the prior-receipt option, both
signature entries, the UTF-8 protocol context, and every remaining fixed-width
field. It reconstructs canonical length encodings before calculating the
exact original operation-ID digest and publishes the whole canonical command.
Private limits are 65536 command bytes, 4096 bytes per dynamic byte vector or
context string, and 64 entries per usage vector. The underlying signature
bytes are parsed as Borsh data, not verified; policy, authorization, the held
command stream and replay are outside this slice.

The standalone M12 `rollup_command_id.hepta` strictly traverses the complete
original kind-25 `AdmitRollup` Borsh command, including the rollup body,
receipt-ID vector, usage vector, UTF-8 context, and both signature entries.
Each nested receipt is parsed with the same HIA walker as kind 24, including
each receipt's own independent UTF-8, usage vectors, option and signatures.
It re-encodes canonical lengths and emits kind, original operation ID, and the
complete canonical command. The finite caps are 65536 command bytes, 64
rollup receipt IDs, 32 nested receipts and the existing dynamic-field caps.
No comparison of receipt IDs to nested receipts, signature validation,
settlement policy, held command execution, replay or authority is implied.

The opt-in M12 `command_journal_read.hepta` adds actual typed SQLite command
length and blob reads to the held canonical receipt stream. All three original
Borsh command forms are walked in native code, with the same receipt/rollup
walkers and context validation as the standalone checks. It derives the
original domain-separated SHA-256 command ID and kind, compares the ID to the
actual operation row, and compares the kind to the strictly parsed receipt.
It preserves and resumes the in-progress journal-root digest, uses the same
private 219-byte output only after close, and leaves raw and receipt-only
entry points available. The existing fixture provider-call limit still applies;
the result does not validate the row checksum, signatures, policy, replay,
or production authority.

The separate M12 `checksum_journal_read.hepta` additionally reads the
actual typed SQLite execution length, raw execution BLOB and 32-byte stored
checksum. It computes the original checksum over the exact domain followed
by the five length-prefixed fields: sequence (little endian), row operation
ID, raw execution, raw command and raw receipt. The running journal-root hash
is saved and restored around the independent row hash. This route refuses
checksum and extent mismatches before any projection and keeps the unchanged
219-byte diagnostic after a real close. Its 65536-byte private execution
limit and the existing provider-call cap are not coverage claims for larger
valid stores. Execution remains opaque Borsh bytes for this checksum owner:
no execution decoding, authority, signatures, policy or replay is implied.

The standalone M12 `execution_context.hepta` validates the original complete
Borsh committed-execution form and an independently supplied canonical
ProtocolContext. It checks the original schema version and full context
bytes, then compares unsigned previous and current order heights; equal
height requires equal block IDs, while higher height does not. It publishes
only the canonical execution bytes after validation. Both contexts share
the private 4,096-byte string ceiling. Differential fixtures include actual
retained Rust Store commits and separate structural boundary controls.
This is a local invariant check, not externally granted Order authority,
state replay, or original production Store ownership.

The opt-in M12 `execution_journal_read.hepta` checks the same actual execution
bytes already bound by the raw row checksum. It reads the trusted context
from the exact configuration bytes previously matched to the held metadata,
uses the same strict context and local order rules, and compares the actual
execution's current height and block ID with the strict receipt. The prior
checksum-only and other held readers keep their previous behavior. Successful
publication still follows the verified close and uses the same 219-byte
diagnostic. This does not establish Order proof authority, replay commands,
or independently derive Settlement state.

The separate M12 `state_root_read.hepta` reads the same actual metadata row
and independently hashes its raw state BLOB using the original state-root
u32 domain length and domain. It preserves the running metadata checksum,
compares the computed result with the actual stored root, and publishes
only the fixed diagnostic after the original close. The original fixture
uses canonical Borsh state; a disposable typed-state change with a freshly
valid metadata checksum but an unchanged stored root is refused. This
verifies the bytes' root, not strict state decoding, execution replay, or
order/production authority. The earlier metadata-only mode is unchanged.

The independent M12 `kernel_state_shape.hepta` mode decodes the complete
Borsh state layout in a finite private profile. It traverses receipt states,
the optional rollup and settlement (including intent and applied receipt),
escrow and result state, and account balances. It reuses the signed rollup
body parser without the command-only trailing receipt vector. Options and
the escrow Boolean accept only tags 0 and 1; status and maturity octets stay
opaque. The mode accepts at most 65,536 input bytes, caps vectors of state
records at 64, and inherits the individual receipt/rollup string, byte-vector
and usage-vector bounds. These are private diagnostic limits, not new
protocol constraints or eligibility rules.

Call `f0(raw, output, scratch)` with disjoint buffers; output needs 32 bytes
plus the input length and scratch needs 4,096 bytes plus the input length.
Success (0) writes the original state root followed by the strict canonical
bytes and does not touch later output bytes. Malformed, incomplete, trailing,
or out-of-profile input returns 100; short output or scratch returns 102;
an internal digest failure returns 103. No output is published on refusal.
The original Rust store and typed codec are independent differential
oracles at genesis, after actual receipt commits, after rollup, and after
settlement. This standalone mode neither opens a database nor proves an
authorized transition, semantic validity, or a replayed state.

The separate `held_state_shape.hepta` mode runs that same strict parser on
the exact state frame at phase 27 of the held metadata read. It clears its
private copy and passes the original frame unchanged to the existing hash
and checksum logic. It never issues a second query for state. The original
root check, ordered field reads, finalize, and close still gate publication
of the same 147-byte diagnostic. Actual Rust-written stores cover four
stages, including a held reader with an original competing writer. On
separate disposable stores, malformed tags and trailing data are refused
before publication even when both the raw root and metadata checksum match
those bytes exactly. This does not execute or replay Settlement commands.

`first_replay_receipt_join.hepta` is an independent finite diagnostic for
the first original AdmitReceipt only. Its 285-byte request holds the actual
149-byte original receipt followed by store ID, operation ID, little-endian
order height, order block ID and the native successor root. It reconstructs
the exact receipt (schema 1, sequence 1, kind 24, absent settlement ID) and
compares every byte before copying it to output. Both output and scratch
must hold at least 149 bytes. Refusal (100) and insufficient capacity (102)
leave output untouched. This join is not an accepted receipt or an authority
to dispatch an operation.

The companion witness creates real original SQLite genesis and committed
stores, checks the original full durable audit and read-only preview from
genesis, and takes the typed execution, command, receipt and state from
those stores. A freshly built and sealed native Engine starts from the
identical trust, validates the exact execution, calls `engine_apply`
(not the idempotent `engine_replay` lookup), and checks immutable parent
history and complete successor bytes and root. The native join checks that
root against the original full receipt. This is a standalone comparison
against real data, not execution inside the native SQLite read lock, later
operation replay, or production authorization.

The opt-in `held_first_replay.hepta` test path extends the checksum- and
execution-checked journal with one sealed Engine call in the same SQLite
snapshot. It admits only one original AdmitReceipt in the fixed witness
profile (914-byte configuration, 163-byte execution, 868-byte command,
149-byte receipt and 1,196-byte state). The HIA reader checks state shape
and root in the original metadata stream, verifies the actual journal row
before requesting replay, and checks native successor history, operation
ID, root and complete state bytes before it resumes the pending SQLite
step. The original journal completion, finalize and physical close still
gate the unchanged 219-byte readback. The sealed Engine and adapter are
test-only; the host cannot pass an arbitrary command pointer or publish a
production receipt.

An original competing writer cannot commit while the replay request is
outstanding. The actual original empty and two-operation stores are
outside this lane and never dispatch the Engine. With the same actual
original one-operation store, result disturbances in any of the four
native observations give no projection and release the held provider.
This does not yet replay subsequent operations, historical interval roots,
or supply production Store or order authority.

The opt-in `held_pair_replay.hepta` lane applies two original consecutive
AdmitReceipt commands with one sealed Engine and immutable successors
inside the same read transaction. Both lanes share one HIA continuation.
It binds the first row's parent coordinates to trusted genesis and each
subsequent row to the previous checked receipt. The two-row lane checks
the first successor root against the actual first receipt before fetching
the second row, then compares the second successor root and complete state
against checked durable metadata and both history counts and operation
IDs against their rows. It also requires the final receipt's order
coordinates to equal terminal metadata. The fixture host reuses one Engine
owner chain and releases all private handles on success and refusal.

An original competing writer is blocked at both replay calls. An actual
one-row store, an actual later rollup, and a two-row store with a trailing
empty block are outside this finite lane. Intermediate root, terminal
state and history-result controls refuse without publishing. No general
handling of empty committed blocks, signatures beyond the original/Engine
checks, later operation kinds, or production admission is claimed.

A separate `held_rollup_replay.hepta` lane continues the two original
receipt admissions with the genuine 2,689-byte AdmitRollup command. It
accepts only the exact three-step consecutive profile and checks the
same sealed successor owner and row commitments each time. The last
complete state includes both receipts assigned to the persisted rollup
and must match the original 3,185-byte typed state exactly. The rollup
receipt's absent settlement ID is checked separately from the state.
The fixture proves the original SQLite read lock across all three
callbacks; it does not support later settlement or empty-block intervals.

`settlement_state_id.hepta` fully checks the finite Borsh state before
locating the typed settlement option. It skips the receipts vector and
the independently checked rollup option. A 33-byte diagnostic contains
tag 0 followed by zeros or tag 1 followed by the nested SettlementState
ID; it is not read from the caller's receipt. Scratch must fit the state,
and refusal leaves the output untouched.

The standalone Rust differential observes genesis, post-rollup and
post-settlement states and compares the exact ID with the genuine
181-byte committed receipt. The sealed native Engine also applies all
four actual journal commands at original heights 10, 11, 12 and 15 and
reproduces the full 4,870-byte final state, root and identity. The Engine
runs after the original record export. This does not prove that the
intervening empty committed markers are preserved inside one native
SQLite snapshot and does not confer production authority.

`journal_prefix_hashes.hepta` computes every original receipt-journal
prefix commitment for a private 0–4 row Borsh vector of raw 149- or
181-byte receipts. It hashes the original domain and the actual count
of each prefix, rather than using the terminal digest's running state.
The output contains consecutive 32-byte values starting at the empty
prefix and leaves later bytes untouched. Both native backends match
the unchanged original `operation_journal_root_through` and the actual
source and target roots for all seven original markers, including the
two consecutive empty committed blocks. This standalone raw hashing
diagnostic does not decode receipt semantics or execute within the
held reader.

The finite `held_settle_replay.hepta` lane uses one original SQLite
snapshot for the actual four commands and seven actual committed block
markers (including two consecutive empty blocks before Settle). It
retains markers only after the same typed native column, row checksum
and predecessor checks as the earlier reader. It chronologically binds
each original command to its checked marker and uses the checked second
empty marker as the Settle execution parent.

The sealed Engine runs only for the four operation rows. HIA compares
each original receipt, operation ID and predecessor/successor state root
to that history, and compares the complete final state and typed
settlement ID. Before original SQLite finalization and close, HIA
independently hashes all five receipt prefixes and compares both ends of
each marker's operation and state intervals. Empty markers must not
advance either root or the operation sequence. The readback diagnostic
bytes remain unchanged; no new authority or write surface is exposed.
This fixed witness does not qualify arbitrary marker intervals or the
production Store/VFS.

`held_same_block_replay.hepta` covers a separate original Store history:
the first AdmitReceipt and a native-replayed AdmitRollup share exactly the
same Order coordinates. Only the original block marker's operation target
advances, from the previous sequence zero to two. HIA checks the first
intermediate state against its own receipt without treating it as the block
marker target, then checks the final transition and both original marker
intervals against the full native state and receipt prefix commitments.
The independent original harness generates the test keys and two commands
from unchanged Rust methods. The actual original writer remains blocked
at both replay calls. This finite mode is not generalized batching or
production confirmation.
