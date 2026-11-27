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
