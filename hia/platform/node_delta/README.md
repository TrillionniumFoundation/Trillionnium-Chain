# Native typed Delta command owner

The live ordinary Node owns its `rusqlite::Connection` directly. This work targets
its shared per-Delta mutation path, not the unrelated executor benchmarks or the
checkpoint value type. It does not yet replace the outer Node transaction.

## Original entry points and exact semantics

The retained sources are `trillionnium/crates/trnm-pon-node/src/store.rs`:
`Delta` at 217 is `(String, Option<Vec<u8>>, Option<Vec<u8>>)`,
`delta_rows_with_progress` at 3938 reads all sorted typed Delta rows,
`apply_delta_with_progress` at 6199 applies those rows. Both direct-child activation
and each multi-step reorganization call this same write path.

The original order for an already constructible Delta vector is:

1. Initial apply progress callback.
2. Initial full Delta read progress callback.
3. Every Delta is materialized in key order. A progress callback occurs after
   each 256 rows, including after the last row if its count is a multiple of 256.
4. Final Delta read progress callback, including an empty vector.
5. For each row: progress; read the actual optional bytes; choose
   expected/new `(after,before)` for detach or `(before,after)` for attach;
   compare full Option identity and every byte (`UNDO_ROOT`, local integrity);
   replace for Some or delete for None; require exactly one affected row
   (`STORAGE_WRITE`, local integrity).
6. Return to the original atomic tail. There is no extra progress callback inside
   `apply_delta_with_progress` after the final row write.

`None` and `Some([])` differ. A `None -> None` delta against an absent row passes
comparison and then fails because DELETE affects zero rows. An unchanged Some
value is still replaced and counts as one row. Neither keys nor value byte
vectors are narrowed to M06 ASCII/integers in this layer. Valid non-ASCII UTF-8
String keys are accepted; value bytes may be empty or arbitrary binary. The
later `slot_state_with_progress`, continuity and complete root checks retain their
own order and cannot be preempted by a new JSON validator here.

## Current HIA implementation

`delta_owner.hepta` is a reusable command state machine. Its private context owns
a captured complete typed Delta tape plus the exact block id and target slot; the incoming start buffer is never retained
as replaceable host state. Commands are Progress, Read, Put and Delete. Every
reply has an exact monotonically increasing ticket. Synchronous malformed/stale
replies leave the context unchanged. Read/write/progress failures retain the
caller's original opaque error token and class; logical mismatch/row-count failures
have distinct local-integrity identities. Terminal replies cannot resume an
operation. A terminal context can begin a fresh operation.

`delta_fixture.hepta` is a native test-only transaction adapter. It evaluates all
current-KV reads and changed-row effects itself, runs the command loop, and emits
the complete sorted resulting KV relation. A failed operation returns the entire
original KV relation in the fixture. Unique Delta keys mean each key is read only
once, so the fixture's immutable base lookup plus final private merge is equivalent
to the row-by-row relational mutation. No Python dictionary supplies a read reply,
write decision or rollback result to that running program. The independent Python
dictionary predicts results only for assertions.

This fixture rollback is not a claim about real filesystem rollback or the outer
Node commit. Native StoreOwner integration and final State/readback/root validation
remain open. The command actor alone cannot publish an active tip, mint a peer
ACK, or claim that a block or complete State is authorized.

### Constructor and ABI

The legacy native entry is `f0(readbuf event, mutbuf command, mutbuf context)->u32`.
Results: 0 command issued; 256 Delta staging complete; 512 terminal operation
failure; 1024 synchronous event/constructor refusal; 1025 local buffer capacity.
Capacity/constructor errors are local ABI admission and never become an original
M06, SQLite or consensus verdict.

Event header is six u64le words: magic `NDLEVT01`, operation, ticket, error class,
value, payload bytes. Start op=1 has ticket/error zero and value=detach 0/1. Its
payload is `NDLT0001`, count:u64le, block_id:32 bytes, target_slot:u64le, then repeated
`key_bytes:u64le,before_bytes:u64le,after_bytes:u64le,key,before,after`.
UINT64_MAX means absent optional bytes; zero means present empty bytes. Keys are
valid UTF-8 in strictly increasing decoded-byte order. This represents the original
String/ordered unique SQL row type; constructor refusal is separate from SQL
row conversion errors. No node-count/key/value-size constant is silently imposed;
actual caller-provided extents bound storage and every arithmetic advance is checked
against its enclosing supplied range. The context needs 256+tape bytes. Command
capacity covers a 104-byte command plus its largest key/value. Generic result errors
use an opaque error token owned by the enclosing native operation, not a copied
error message or manufactured source chain.

Reply op=2 uses the pending ticket. Error classes 1..4 are opaque operation error,
cancelled, original public CPU budget and original continuous-owner CPU budget;
the value is the original error token. Successful Progress has no payload and value
zero; successful Read has value 0/1 for absent/present and exact payload bytes;
successful Put/Delete reports affected-row count. A mismatching Read length or
presence returns UNDO_ROOT before a command-buffer capacity issue can hide it.

Commands contain `NDLCMD01`, kind (1 Progress,2 Read,3 Put,4 Delete), ticket,
key bytes, value bytes, Delta index, progress index and private phase, then target_slot:u64le and block_id:32 bytes, followed by
key/value bytes. The block/slot binding is captured at Start and cannot be changed
by a reply. Slot is the original full u64 argument; the valid ordinary Node path
bounds generations to i64::MAX before activation. This constructor does not add
an earlier SQLite integer-conversion error to an empty Delta operation. Context phases 1..7 are pending progress/read/write; 8 is staged
complete; 9 is terminal failure. Context fields include captured tape size/count,
collection/application cursors, exact before/after offsets, error identity and
observed command counts. The private tape starts at 256. No pointer/FD/durable
transaction authority is exposed by this ABI.

Only the exact canonical `value_utf8` function is included from the shared JSON
primitives source. ASCII JSON/M06 Value validation and integer/JSON serialization
are not duplicated or selected here.

## Remaining typed branch / reorg dependency graph

The outer original flow is:

* `activation_selection` (6244) reads active then target/old Work, selects only
  strictly greater 512-bit work, and checks generation+1 <= i64::MAX.
* Direct-child activation mutates the existing slot inside one original atomic
  transaction, validates complete State/continuity/root, updates active and event,
  checks exact readback, commits, then publishes the volatile commitment.
* General reorg copies old State into a new generation slot; computes detach/attach
  steps by actual parent heights (equal heights detach left first); persists intent
  plus reserved lifecycle; checks staging readback; commits the intent.
* `resume_intent_with_progress` checks every retained row/step and generation,
  applies each Delta into staging and advances its cursor within one transaction,
  verifies resulting State and readback, then commits that step.
* Final publication checks complete staging State/continuity/root, gathers expected
  steps, updates active/generation/slot, inserts all events, marks done=1 and lifecycle
  outcome=1, deletes old slots, and rechecks active/rows/events/State under the original
  writer identity before its commit. Only then is the published cut factual.

`atomic_with_readback` (6099) retains original writer/snapshot identity across every
callback and the final write boundary; the last progress check precedes unchanged-
snapshot verification and COMMIT. No cancellation is checked after COMMIT.

`store/reorg_cancellation.rs` retains a separate same-owner reservation: old/target,
generation, old slot/root, owner context, data/schema/temp-schema epochs, lifecycle
operation, and the pre-reserved CPU cleanup account. On Cancelled or the two exact
budget errors, `cancel_unpublished_reorg` rechecks namespace/storage/owner/epochs.
If already published it verifies completed lifecycle and rolls back its read-only
cleanup transaction. Otherwise active/old slot/root must match, and only two
metadata rows may change: lifecycle outcome=2/cursor/reason, then reorg done=2.
Those two writes must commit even though the original operation is cancelled.
The cleanup authorizer forbids changes to State/active/blocks/replay/CPU journals.
It then returns the original cancellation, with no terminal peer ACK or new deadline.

Those reservation, paid CPU, snapshot/transaction, publication, recovery and
metadata-only mandatory-commit semantics are not replaced by this Delta owner.
The next composition must route its complete staging result through those exact
checks and the native StoreOwner's unknown-commit/reopen rules; it cannot treat
result 256 as permission to publish a tip.

## Original reference

`rust_delta_reference.rs` is a cfg(test)-only appended child of an isolated original
store.rs. It calls the real private original method and real SQLite transaction,
using a non-active slot so arbitrary byte-vector controls do not impersonate an
admitted State. Its write-count refusal uses real SQLite RAISE(IGNORE) triggers;
all original production function bytes remain intact. Original compilation and
execution are NOT_RUN locally because no Rust toolchain is installed. Test commands
and hook path are in the fixture header. Native event errors without corresponding
SQLite injection are separate conformance tests, not fabricated original failures.

## Qualification entry points

`qualify.py` runs the complete independent relational corpus, per-message ABI
controls, and caller-extent controls through the exact registered HIA sources
and the locked native compiler. `native_support.py` is hosted test tooling. Its
8 MiB private-buffer limit and 32 MiB batch-input limit are a bounded qualification
profile; the HIA actor itself uses the supplied extents. The 131,072-row union
control covers two 65,536-row KV relations, with valid JSON integer bytes in that
control. It does not run complete State/continuity/root admission or qualify the
maximum combined key/value byte extent of an original State.

Run from any working directory, with `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER`
and `HIA_NATIVE_COMPILER_SHA256` set to the repository's explicit qualified pins:

```sh
python3 -B /path/to/repository/hia/platform/node_delta/qualify.py \
  --output /fresh/external/delta-qualification --require-rust
```

The main result is `<output>/report.json`. Full native reports, build identities,
process receipts, and the original comparison remain below that output directory.
A missing local Rust toolchain is `NOT_RUN`, never a passed original comparison.
Without `--require-rust`, native-only development reports use the overall status
`NATIVE_PASS_ORIGINAL_NOT_RUN`; CI must pass `--require-rust`. This complete
qualification runs once as an independent CLI step; startup unit tests do not
repeat the corpus.

The independent original driver compiles the complete preserved source roots
with `cargo test --locked --manifest-path <isolated>/trillionnium/Cargo.toml -p
trnm-pon-node --lib --no-run --message-format=json --target-dir <fresh-target>`.
It obtains the actual unique Node test executable from Cargo's compiler-artifact
event and invokes `store::hia_delta_reference::evaluate` with `--exact`,
`--nocapture`, and `--test-threads=1`. It does not guess Rust library directories
or link a copied algorithm. Both directions of every 32nd exhaustive KV relation pair
plus all later boundary/random/cancellation/write-count cases are selected;
synthetic read errors remain native-only because no equivalent SQLite fault is
injected. Full native coverage and the precise selected original count are
reported separately. The original error kind, progress count, and complete KV
bytes are compared against the actual native result.

Command consumers use only the declared 104-byte header and key/value payload.
Bytes outside that extent may retain an older command. The private context and
its captured tape belong to the enclosing native operation; callers may not
modify them between replies. This is an internal actor ABI, not an untrusted
peer protocol, a durable commit receipt, or a thread-safe shared context.

## Constructor cost and cancellation boundary

Start first validates the complete already-supplied typed tape and copies it into
private context. Only after that admission does it emit the first Progress
command. That constructor scan/copy is not interrupted by this actor. The
retained original method emits its first callback before statement preparation,
and performs real SQL row conversion/materialization between the subsequent
collection callbacks. This typed-vector actor has not replaced that I/O owner,
its conversion-error precedence, its physical materialization cost, or its CPU
and cancellation response. The original reference compares admitted typed inputs
and the method's logical outcomes/callback sequence; it is not a paired CPU
budget or input-acquisition deadline test.

The future Node owner must materialize complete Delta rows under one retained
transaction snapshot: initial apply progress, initial collection progress, actual
row decoding with a checkpoint every 256 rows, final collection progress, and
only then the first mutation. Pre-recording a tape before those checks, or
mutating while rows are still being collected, does not preserve this order.
`delta_rows_with_progress` is therefore not retired by the present component.
