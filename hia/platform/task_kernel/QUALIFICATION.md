# Main TaskKernelStore qualification and independent readback

This gate covers the main `TaskKernelStore`, its six command transitions, private
database audits, preview and commit behavior, and the public opaque Store and
value owners. It does not complete the separate task archive business, its
durable archive Store, or StateImport. The original crate remains required until
those surfaces and their integrations are separately closed.

## Run the complete gate

Use the pinned Hepta source and native compiler identified by the repository
toolchain manifest, Rust 1.95.0, the original locked Cargo dependency cache, and a
separately built and qualified shared Task provider. The provider retains its
29-operation mechanical ABI. The gate refuses an existing output directory and
does not modify the original Rust sources.

The production provider is emitted by `provider_native.hepta`; it implements
all six public lifecycle entries and 29 operations. `witness_emitter.hepta`
creates the runtime witness from a fresh build-time C ABI probe. The production
link includes those two native objects, the pinned external SQLite object and
system libraries. `provider.c` remains only an explicit `--original-oracle`
comparison with a separate fence. External SQLite is still C; Archive,
StateImport and full Node integration remain separate obligations.

The formal CI entry point first builds the native provider, executes its full
original/native qualification, independently reads it back and runs all 46
provider-reader negative controls. Both consumers require all four stages
before their own tests. Use this entry point for complete source-bound evidence:

```sh
python3 hia/tools/qualify_task_ci.py \
  --component task-store \
  --rust-bin /absolute/rust-1.95.0/bin \
  --output /absolute/fresh-task-ci-evidence

python3 hia/tools/qualify_task_ci.py \
  --component task-boundary \
  --rust-bin /absolute/rust-1.95.0/bin \
  --output /absolute/fresh-boundary-ci-evidence
```

The provider gate retains 1,182 original/native comparisons, 143 actual paired
allocation failures, 256 concurrent calls, 123 witness controls, 12 emitter
controls and eight build refusals. Its independent reader validates complete
source and artifact graphs, actual compiler argv/cwd, emitted instructions and
PLT targets, original C translation-unit provenance, ABI probe observations,
real failure ordinals and final resource counts. The same qualified provider
can also be supplied to the lower-level Store commands below; those commands
do not replace the formal consumer's mandatory provider stages.

```sh
python3 hia/platform/task_kernel/qualify_task_store.py \
  --provider /absolute/qualified-provider \
  --rust-bin /absolute/rust-1.95.0/bin \
  --output /absolute/fresh-task-store-evidence

python3 hia/platform/task_kernel/readback_task_store.py \
  --evidence /absolute/fresh-task-store-evidence \
  --repo /absolute/Trillionnium-Chain \
  --output /absolute/fresh-task-store-readback

python3 hia/platform/task_kernel/qualification/readback_negative_controls.py \
  --reader /absolute/Trillionnium-Chain/hia/platform/task_kernel/readback_task_store.py \
  --evidence /absolute/fresh-task-store-evidence \
  --repo /absolute/Trillionnium-Chain \
  --roster /absolute/Trillionnium-Chain/hia/platform/task_kernel/qualification/task_store_roster.json \
  --output /absolute/fresh-task-store-negative-controls
```

Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` before running the gate. An explicit `CARGO_HOME`
may identify the existing locked dependency cache. Each gate creates a private
Cargo target. Original tests, adapter compilation, HIA compilation, native
execution, allocation failures, Clippy and formatting must actually execute;
there is no missing-oracle skip path.

The qualification snapshots every file under the Task platform and native
source directories, including this document, the independent reader, and its
fixed case roster. Changes to these inputs require a new source-bound run.
Existing reports are never relabelled with a newer source graph.
The reader independently enumerates those current directories and the recorded
original Git source entries. It requires the exact source set, its own canonical
checkout path and identity, and the canonical case roster path and identity.
An external copy with identical bytes cannot replace either input.

## What must pass

The main gate retains the complete original package roster: 35 unit tests,
two transaction-wire tests, two archive integration tests and two compile-fail
documentation tests. It also runs all-target, all-feature Clippy with warnings
denied and the original formatting check. These retained archive tests are
original Rust tests; their presence does not qualify a native archive owner.

Four adapters are freshly compiled against the exact original Cargo dependency
graph. Private observation adapters include the unchanged original `store.rs`
followed by a separately recorded observation hook. The public adapter calls
the original public methods without appending private code to the Store module.

The native comparison contains 1,390 private transaction and audit cases and
445 ordered public cases. The latter independently account for 413 actual
method, drop and equality calls and 1,877 actual getter calls, including the
eight-thread cohorts. Returned values and complete database and filesystem
observations are compared with the original execution. Protocol wrapper
messages do not count as extra native calls.

Allocation qualification relinks the exact compiled HIA objects with a
qualification-only allocation observer. Its 112 controls exercise all 96
observed failure positions, rollback and retry, input ownership, cloning,
concurrent access and final release. A passing run must end with zero live
allocations, zero live bytes and zero invalid frees. The observer is not a
production allocator or a Task business implementation.

## Independent readback

`readback_task_store.py` uses the Python standard library and does not import
the builders or observers. It reads evidence; it does not execute the native
runtime or manufacture new comparison results. Both the main gate and reader
must have finalized `PASS` reports to accept this finite qualification.

The reader checks the fixed ordered case roster in
`qualification/task_store_roster.json`, every case input and output, all
referenced database bytes, the full original process streams, and the actual
allocation failure ordinals. It recalculates public call counts from the
individual observations. A matching summary count alone is insufficient.

For native code it checks exact canonical function bodies, complete call
closures, the pinned compiler, actual compiler stdin and ELF stdout, the
actual HIA-emitted linker objects, symbol renaming and the complete final link
graph. It parses the public ELF symbol table independently and requires the
51 declared public exports. The native observers must reference those exact
builds and original executables. The provider source, compiled library and
29-operation ABI are part of the same relationship. Store readback also invokes
the independent provider verifier; a C-oracle library, foreign reader, missing
emission stage or merely matching summary cannot satisfy the native source graph.
Each image's function owners are independently derived from its canonical HIA
source and include declaration. Every owner must be in that build's source
fence; copying identical function bytes to a foreign file does not establish
the required source relationship.

For Rust it checks every retained original test name and unfiltered test
summary, original Git blob identities, actual Cargo messages, the complete
retained Cargo artifact set, exact locked direct dependency versions, actual
adapter sources and compiler arguments, and the retained executables. The
same content identities must still hold at the end of the readback.

The portable negative-control entry point retains the 27 command and environment
controls and adds ten source-binding controls. It tests omitted reader, roster
and document inputs, external identical reader and roster copies, an added
foreign source, unfenced function and include owners, and foreign function
owners both with and without an added build fence. Read overlays leave the
original source and recorded evidence unchanged. Rejection must occur at the
expected source guard, rather than an unrelated missing-file error.

The reader operates on a preserved live evidence tree and its exact source
paths. A content-addressed archive needs a separate archive-member readback
before reconstruction; archive hash verification does not replace these
case and compilation relationship checks. Historical missing artifacts stay
explicitly missing and must not be substituted with later compilations.
