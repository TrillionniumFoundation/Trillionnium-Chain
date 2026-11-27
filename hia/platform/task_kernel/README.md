# Task kernel: main Store and owned values

This directory implements the original `TaskKernelStoreV1` method family in
native HIA, together with canonical Task values, the AgentTransaction wire and
the private policy, SQL, audit and transaction continuations needed by the Store.
It is a finite migration stage. The separate archive planner, archive verifier,
`TaskArchiveStoreV1` and StateImport business methods are still open. The original
Rust crate remains necessary; none of the reports authorize its retirement or
claim that the complete chain is native HIA.

## Runtime ownership

`build_store_public.py` composes 27 HIA continuation images and three HIA
emitters. Every image is compiled by the pinned native HIA compiler. The emitted
physical driver, dispatcher and opaque owner object are linked with those exact
objects and the independently qualified provider. The final export map exposes
exactly 51 symbols from [task_store.h](task_store.h); private continuation and raw
byte-to-result entry points remain hidden.

The driver and opaque owner provide allocation, bounds, copies, field access and
dispatch. Store policy, canonical parsing, authorization, checksums, roots, SQL,
transaction ordering and result construction execute in the HIA continuations.
Python is build or qualification orchestration. The C allocator observer exists
only in qualification builds and does not implement Task behavior.

Each public call creates its own continuation/provider owner. The Store owns an
immutable copy of its path, store ID and trust bundle. `Clone` copies that config
without I/O or renewed trust validation. Readback, preview, execution outcome,
confirmed receipt, state and error results have independent allocations; they
remain valid after the Store is dropped. Returned byte views borrow their owning
result. The caller must keep live, correctly sized FFI pointers and must not drop
an object during a borrow. Concurrent read-only calls on the same Store are
supported with separate call owners.

Readback equality compares the complete original value, including context and
all roots. A readback returned by another Store instance is accepted when its
complete value is equal. The ABI exposes no arbitrary byte-to-readback, preview,
outcome or confirmed receipt constructor. Non-Clone original private result
types do not acquire a new public Clone operation.

The provider is one shared mechanical implementation with exactly 29 operations.
It binds the original bundled SQLite 3.54.1 implementation and its C ABI. It does
not contain Task schema or business policy. This stage does not claim an HIA
SQLite engine or remove the underlying SQLite dependency. The provider identity,
compile options and original dependency bytes are independently checked by
`build_provider.py`; consumer builds reject changed source or artifacts.

## Method mapping

| Original surface | Native entry or continuation |
| --- | --- |
| Store `open`, `open_existing`, `Clone` | Public owned constructors and clone; verified/open/bootstrap continuations |
| `fresh_readback` | Complete schema, metadata, object, operation and committed-block audit |
| `execute_committed_execution` and all six command variants | Policy → authorization → scope → command → authorization consumption → receipt/marker/metadata commit |
| `advance_empty_committed_execution_v1` | Checked successor, idempotent target, immediate transaction, metadata/marker CAS and fresh readback |
| `preview_before_vote_v1` | Actual owned parent, complete candidate transaction, rollback, fresh readback and file inventory check |
| `confirm_receipt` | Store-bound fresh audit and exact persisted receipt comparison |
| Capability/session/nonce/task/bid/lease/escrow/account/bond getters | Canonical object loader and nine independently owned typed states |
| FreshReadback, Preview, Outcome, ConfirmedReceipt getters | Borrowed views and scalar access to the original complete result layouts |
| AgentMarketError getters, Display and Clone | Owned complete original code/message/display |

The preview ABI uses a u64 count followed by canonical command values. It does
not add a u32 count cap to the original Rust slice API. Arithmetic, nonce,
generation, canonical-value, database and protocol limits remain the original
ones. Compiler budgets remain 8,192 operations, 128 functions, 16 block
parameters and 2,047 SSA values per function.

## Qualification

The portable entry below creates fresh original Cargo artifacts, original
private observation adapters, signed fixture values and databases. It then
builds and executes both current HIA images and the original Rust methods. It
does not depend on historical development directories or import their PASS.

```sh
python3 hia/platform/task_kernel/build_provider.py \
  --dependency /absolute/cargo/registry/src/registry/libsqlite3-sys-0.39.1 \
  --output /absolute/fresh-provider

python3 hia/platform/task_kernel/qualify_task_store.py \
  --provider /absolute/fresh-provider \
  --rust-bin /absolute/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin \
  --output /absolute/fresh-task-store-evidence
```

Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` to the repository's pinned toolchain and compiler.
The current compiler identity is
`87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
The original Cargo build is locked and offline and uses Rust 1.95.0. Original
source bytes are checked against the actual checkout's Git objects. No original
tests are filtered or ignored. Clippy runs all targets/features with warnings
denied, and the original package must pass formatting unchanged.

The entry requires all 1,390 private native/original comparisons, 445 ordered
public comparisons, 1,877 actual getter calls and 413 actual method/drop/equality
calls. Public operations include the full signed eight-step lifecycle, preview
and rollback, commit, replay, confirmation, empty advancement, all state getters,
cross-Store equal and stale parents, Clone/drop order, errors after owner drop and
actual eight-thread calls on the same Store. Complete database bytes and result
values are compared after each relevant operation.

The allocator gate links the identical compiled HIA objects with a
qualification-only libc allocation observer. Its 112 controls include 96 actual
allocation failure positions across clone, fresh readback, open-existing,
complete eight-step preview and error clone. Each failure must return no owned
result, preserve existing values and files, permit exact retry, and end with zero
live allocations, zero live bytes and zero bad frees. The provider is unchanged.

### Recorded development evidence

These identities retain their original exact graphs. They are not rewritten
when later integration adds source files or changes qualification orchestration.

| Run | Actual result and scope | Report SHA256 |
| --- | --- | --- |
| records-v22 / source-v35 | 1,390 private native/original comparisons; six transitions, audits, transaction faults and preview | `596247d5b885c6f9ec4389cab86e1a82b4259a2b5b3d6e9d4f7fa3a1a02eea6e` |
| public-v3 / source-v39 | 445 public comparisons; 2,290 actual public ABI calls; 51 exports | `9536d3d0dcef94d798d08652fefb74cbacd0384d3ebc1849f9f482a29e8096da` |
| allocator-v3 / source-v39 | 112 controls; 96 forced allocations; final live=0, bytes=0, bad-frees=0 | `9afd86387b212bb3a9321b14791ae57cb56cd9b4df6c91b49ffb0179aa049f46` |
| original-final-v2 | Unchanged original 35 unit + 2 wire + 2 archive + 2 doc tests, strict Clippy and fmt | `a8169990c4e5d2651dc9171e12c642882a64b76a94a9918085d32012057c04cb` |

The earlier public-v2 report's `native_abi_calls=701` was a protocol bookkeeping
count, not the count of actual ABI invocations. Source-v39 counts the 413 actual
method/drop/equality calls plus 1,877 actual getters, for 2,290. The old report is
preserved with this correction rather than silently edited.

Historical failures are retained with their original source and raw output. In
particular, nonzero capability/session generation counterexamples exposed an
incorrect generation field; a truncated preview command exposed misuse of the
canonical parser's cursor as a success flag; and the first public owner emitter
exceeded the unchanged per-function SSA budget. Those defects were repaired and
tested on new source graphs. Splitting the emitter into bounded HIA helpers kept
its exact emitted object bytes unchanged. Fixture, dependency-availability and
composition failures are recorded separately from semantic mismatches.

The first portable-entry attempt also retained an orchestration failure after
all 41 original tests passed: Cargo produced both SHA-2 0.10.9 (the Task direct
dependency) and SHA-2 0.11.1 (a transitive dependency), and the initial selector
refused the ambiguous crate name. The entry now derives exact direct package
identities from the unchanged Cargo lockfile and retains every actual Cargo
artifact before selecting them. It does not choose a library by an old path or
substitute a different SHA-2 version.

Passing the original archive tests only preserves the original implementation;
it does not establish native archive behavior. Whole-crate and whole-chain
completion remain false until those distinct runtime obligations are completed.

### Terminal archive typed hashes

`src/task_kernel/archive_hash.hepta` is separate from the archive planner and
durable store. Selector 0 hashes a canonical Borsh `TaskArchivePolicyV1`,
including the original schema, positive bounds and maximum 4,096 batch record
checks. Selector 1 hashes a canonical inert `TerminalTaskArchiveRecordV1`;
only its schema is checked by the original hash method. It does not validate
retention, terminality, outside evidence or a pruning decision.

The private request is one selector byte and the exact Borsh body; the UTF-8
chain ID is bounded to 512 bytes by this ABI, not by the Rust method. It
publishes only a 32-byte digest and uses 1,264 scratch bytes. Both digests bind
the original little-endian u32 domain length, exact candidate domain string
and unchanged Borsh body. Statuses 1 and 22 reflect this route's original
InvalidBounds and SchemaMismatch codes; 100 is malformed private input, 102
is insufficient caller capacity, and 103 is internal hash refusal. It writes
no digest on refusal.

```sh
python3 -B -m unittest -v hia.tests.test_task_archive_hash
```

The test uses the original locked Rust crate and its two public hash methods,
plus stock Direct and Selfhost execution. It does not exercise archive
selection, inclusion, filesystem mutation, consensus, or node routing.

### Ordered archive inclusion fold

`src/task_kernel/archive_inclusion_fold.hepta` is the pure final Merkle join
of the public verifier, not the complete proof-verifier entry. Its private
borrowed input is exact packed little-endian count (u32), leaf index (u32),
sibling count (u64), 32-byte admitted seal root, 32-byte leaf hash, and one
32-byte word per sibling. The seal count and Merkle root are explicit inputs
from separate seal validation. Seal and proof schemas, seal hash, context and
prepaid-retention admission remain untouched in Rust. The native route does
not authenticate the seal or create deletion authority.

The fold checks the index, the original 4,096-count bound and the exact
ceil-halving depth, then hashes each ordered pair in the original framed
archive-node domain based on the active index parity. In the odd-tail case the
actual prover supplies the duplicate sibling; the original verifier does not
add another proof-shape predicate for duplicate tails. The input is immutable,
output is untouched, and scratch requires 1,344 bytes. A mismatched root is
status 23, index or calculated-depth mismatch 13, and out-of-range count 1
after an otherwise valid index. Zero count is invalid in this private fold;
the outer original seal hash rejects it before a fold is called.

The test drives both native compilers with actual public planner/proof output
and actual public verifier status. The already-native archive record hash
supplies the leaf, not a precomputed comparator result. It covers ordinary
odd/even ends, capacity and tampering. This route does not plan deletion,
mutate a store, change CI policy or route production traffic.

### Typed archive inclusion header and prepaid retention

The private native header takes little-endian u64 seal and record byte lengths,
then the complete Borsh-encoded seal, record, and inclusion-proof values.
It checks exact object extents and UTF-8 chain IDs (at most 512 bytes), then
replicates the public `verify_task_archive_inclusion_v1` order: checked
inclusive retention, proof/seal schema, nonzero seal count, recomputed seal
hash, exact protocol context, leaf index, protocol count/depth, and record
schema. This phase reads only the proof vector's length, not its elements.
It publishes no output and does not import a caller-supplied seal hash
as trusted. Private transport errors and capacity refusals are distinct.

The qualification test connects accepted headers to the already-native
record hash and ordered inclusion fold using fields of the *same* validated
immutable typed packet. It also checks layered failures against the locked
original public API and exercises both stock backends. This test composition
is not a public or installed dispatcher and does not replace an authority
that selects the seal or verifies its policy, receipt, terminality, or
deletion; actual batch validation is separate.

### One-call typed archive inclusion verification

`src/task_kernel/archive_inclusion_verify.hepta` takes the same immutable
complete typed packet as the header and executes the header, record digest
and ordered proof fold within one native call. A single scratch extent of
1,344 bytes is checked before any work; the output buffer is never changed.
The three independent native entries remain available with their original
contracts. The combined entry calls their shared verifier/hash/fold bodies:
the record and siblings are read directly from the already-admitted immutable
packet, and the computed leaf and intermediate roots remain in private
scratch. No caller-supplied intermediate hashes or mutable-to-read buffer
coercions are used.

This mirrors the public `verify_task_archive_inclusion_v1` result on the
bounded typed input. It does not validate a batch, decide which seal to trust,
or supply policy, receipt, terminality, deletion or production authority.

### Complete singleton archive batch verification

`src/task_kernel/archive_singleton_batch.hepta` mirrors the public
`verify_task_archive_batch_v1` result for exactly one archived record. Its
private immutable packet has two little-endian u64 lengths (policy/seal),
canonical Borsh policy bytes and the complete Borsh batch (seal, u32 record
count and exactly one record). Chain ID bytes are UTF-8, each bounded to 512
by this ABI. It publishes no auxiliary outputs and uses 1,360 scratch bytes.

The validator binds the canonical policy digest to the seal, checks context,
record schema and eligibility, and uses the existing exact checked unsigned
128-bit product for the charge. Mandatory retention, charged-block count,
required charge and inclusive expiry overflow retain original precedence.
It then checks total encoded bytes, full charge, canonical range, and the
actual native record hash as the singleton Merkle root, with no injected
trusted digest. For a singleton, order/uniqueness are vacuous and the tree
has no parent node; multi-record admission and tree reduction are separate
work. No planner selection, pruning, deletion, database mutation or
production routing is enabled.

The original Rust planner creates an actual singleton fixture. The unchanged
public batch verifier judges both that fixture and typed boundary variants,
including full high-limb charge and failure ordering, before comparison with
the pinned Direct and Selfhost entries.

### Variable archive batch verification

`src/task_kernel/archive_variable_batch.hepta` uses the same private
canonical packet as the singleton for exactly one to eight actual Borsh Vec
records. The original singleton entry and ABI remain unchanged. The variable
entry first validates all typed extents and UTF-8 contexts (each chain ID at
most 512 bytes), then uses the same exact policy/seal and per-record prepaid
checks. In original order it refuses any repeated Task ID, checks strict
(terminal height, bytewise Task ID) order, adds checked u64 and u128 totals,
and hashes each original record from the admitted immutable packet.

The node hash helper reduces the ordered leaves in private scratch, duplicating
odd tails as the original planner does. Both actual sums, the computed root,
and exact first/last ranges must match the bound seal. The scratch prefix is
1,720 bytes; output is always unchanged. Vec count outside the private
profile returns 100 and is not reclassified as an original public decision.
The native result does not authorize archive selection, deletion, ownership,
database mutation or routing.

The locked original public planner and verifier drive actual valid 1/2/3/5/8
records and layered bad values, including global nonadjacent duplicate,
same-height lexicographic order, overflow, limb carry and odd-tail root.

### Archive planner selection projection

`src/task_kernel/archive_selection.hepta` is the original deterministic
selection and retained-order stage for at most eight **already typed-admitted**
terminal facts and eight supplied hold IDs. It does not itself prove facts,
create a hold, verify original billing/context, generate seal bytes, or
authorize deletion. The locked original public planner supplies statuses and
ordered outputs for the genuine generated cases. No production code calls
this diagnostic entry.

The exact private input is eight little-endian u64s (fact count, hold count,
current height, sequence, live count cap, live byte cap, batch count cap,
batch byte cap), then 72 bytes per fact (TaskId32, terminal height, inclusive
paid-through height, encoded byte count, u128 prepaid charge), then 32 bytes
per hold. The initial authoritative policy and row checks remain separate.
Native logic sorts the supplied original indexes by terminal height and
bytewise Task ID, rejects duplicates/checked live total overflow, checks
hold membership, then handles live pressure, holds, maturity and batch
caps in original order. It computes checked selected charge only after
resolving pressure.

Scratch is 216 bytes. On success the 168-byte projection contains
selected count, selected bytes, selected charge (two words), retained count,
then eight selected and eight retained canonical original indexes (unused
slots are u64 max). Errors publish no output or partial selection. The result
does not provide a seal root or authority to install/prune/delete records.

### Typed archive planner selection

`src/task_kernel/archive_typed_selection.hepta` unifies original policy
validation, canonical terminal record parsing and billing, and the native
bounded selector in one borrowed call. Its private packet begins with five
little-endian u64s (policy byte length, record count, hold count, current
height, batch sequence), then exact Borsh policy and variable records,
then packed 32-byte hold IDs. At most eight records and hold IDs and
512 UTF-8 chain-ID bytes per typed object are admitted. The input is read
directly as immutable bytes; no encoded host projections are trusted.

The sorter processes original (height, Task ID) order before record
validation, duplicate/total checks, hold-subset admission and selection.
Batch verification can reuse the original paid charge checks but still
requires expired rows; selection checks expiry only when needed after
testing holds. Both previous diagnostic ABIs retain their original contracts.

Scratch needs 1,496 bytes and the caller reserves 6,276 output bytes before
any publication. Success writes the existing 168-byte selection projection,
a u64 byte length, and the exact Borsh Vec of chosen original records
(canonical u32 count and directly copied original bodies). Unused output
remains unchanged. This is not a complete seal/root or storage pipeline and
does not confer node, pruning or deletion authority.

### Original sealed archive planner projection

`src/task_kernel/archive_sealed_plan.hepta` privately admits the same bounded
canonical typed Borsh policy, unordered records and legal holds as the typed
selector. Its separate input profile appends the exact 32-byte previous seal
hash to that packet; the archive height and sequence stay in the original
header. It builds the original candidate `TaskArchiveBatchV1` in one call,
using selected record bytes from native-owned selection state and the original
policy and record hash transcripts, checked charge total and odd-tail Merkle
fold. The original planner returns no batch when there is no surplus.

The output is a little-endian u64 length followed by the exact Borsh
`TaskArchiveBatchV1` (zero length for no batch). The caller supplies a
disjoint 6,914-byte output region and 1,824-byte scratch region. Admission,
selection, the checked total, and hashing complete before any output is
published. Existing selected/retained projections keep their separate ABI.
The unchanged public Rust planner supplies exact byte and status fixtures on
both native backends. The resulting batch is only a candidate: production
authorization, applying pruning, retention/durability, storage and runtime
routing remain with the original owner.

### Bounded original archive seal-chain readback

`src/task_kernel/archive_store_seal_chain.hepta` checks one held readback packet
from the original archive store: a little-endian u64 count followed by
metadata `{generation: i64, sequence: i64, seal_hash[32], live_root[32]}`, then
at most eight ordered entries. Each entry is
`{Borsh_seal_length: u64, sequence: i64, generation: i64, seal_hash[32],
live_root_before[32], live_root_after[32], original_Borsh_seal_bytes}`. The seal
bytes are the exact prefix of the persisted complete batch, not re-encoded
fields. The native stage verifies the typed seal shape, computes the original
seal digest, binds each sequence and generation, verifies its predecessor
seal and live-root chain, then publishes the 80-byte metadata tuple only
after agreement with the final link. The output and scratch regions are
disjoint, with minima of 80 and 1,264 bytes respectively; a refused call
never changes the output.

The positive fixtures are genuine disposable databases produced and cold-read
by the immutable original store. A separate mechanical read-only SQLite
transaction captures the exact same held rows, including generated benign
mismatch controls. The HIA stage does not open SQLite, validate schema or
record blobs, reconstruct the inventory roots, replace the full store audit,
repair durability, perform deletion, or authorize production use.
