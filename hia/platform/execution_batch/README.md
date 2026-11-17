# Ordinary M06 batch and retained TransactionPrefix owners

This component implements the actual ordinary default-Config M06 execution path
in HIA. The pinned compiler emits the machine code directly. Its adapter performs
real Linux system calls and calls the compiled HIA images in one process.
Python builds, supplies qualification inputs, records actual bytes and compares
observations. It does not calculate an execution result for the native owner.

## Three distinct private profiles

| Profile | Original relationship | Lifetime |
| --- | --- | --- |
| batch | execute_with_control | Prepare the complete raw transaction set, join all real workers, apply/reexecute in canonical order, complete mandatory work, fees/rewards and root |
| prefix | TransactionPrefix::new and execute_with_commitment_and_control | Keep accepted raw prefix, unfinalized State, fees and receipt vector across actual method calls; failed execution restores them |
| scoped | Native embedding extension over the same genuine State heap | Keep an independent base State; clone for each Prefix, retire only that Prefix's objects/journals, and retain the base across failures/drop |

The public pipe protocols are qualification entry points. Their initial State
input is explicitly a test fixture. They do not construct Node
AdmissionPersistence. An actual Node embedding must create the State from its
internally validated source and initialize the private scoped base handle itself.
A caller-supplied serial, State/root, successful callback or NGREAD record cannot
authorize persistent publication.

The supported Config is constructed by the native Settings implementation:
legacy-first-two-v3, legacy-task-v1 and linear-expert-dev-v1. The original default
commands 1 through 12 are implemented by the shared application owner; profile
checks reject the other tags in their original preparation order. The installed
worker set is exactly 1, 2, 4 or 8. Actual slots and transaction storage use the
runtime count and the installed max_transactions. Eight pending worker slots
reflect the accepted worker domain, rather than a new State or transaction limit.

Custom Config, PQ and growth-selected commitment/execution, paid Host access,
full Node admission, ancestor/catalog validation and durable successor commit
remain outside this component. AccountPointAccess is the original None path.
No 4-second service or resource-slice qualification is implied by a successful
component run. There is no new 1 MiB State ceiling or substitute small-state
algorithm.

## Execution and lifetime

The batch owner creates real scoped Linux threads for the selected worker
stride. Each worker has private continuation/work buffers. Shared State/View/
Value operations use a real aligned atomic mutex and futex handoff. A worker
never holds that heap mutex while waiting on an external progress callback.
There is at most one outstanding callback per worker and the owner polls all
lanes. Successful thread birth and kernel clear_tid retirement are observed;
all created workers are joined before panic/cancellation/error priority is
resolved. A partial spawn failure joins only workers that actually exist.

Preparation uses the genuine PNX1 decoder, actual SHA256 and strict Ed25519
verification. The signature counter follows the original network/expiry checks
and includes a failed verification. Account conflict hints determine whether a
transaction receives speculative application. Canonical consumption handles
Prepared errors before apply, uses Patch.current for complete point/range reads,
and reexecutes stale or failed predictions exactly once. Reexecution consumes
the already privately prepared transaction and does not verify its signature
again. No external Patch/Prepared or success flag enters this sequence.

Mandatory work and finalization have their own real continuations over the same
State heap. They preserve the original cleanup, expiry, settlement, fee, reward,
issued-supply and root ordering. Prefix execution journals every temporary
mutation, preserves accepted raw bytes, and restores private State/fees/receipts
on semantic error, callback cancellation or a real application panic.

The scoped profile keeps the owner base at private offset 54000. A base must
come from a real State producer in the same heap. new borrows that base and
creates an independent State clone. Prefix drop retires its own objects and
journal and never invokes whole-heap close. The qualification-only final
root-close method runs only after scopes are retired and verifies zero live
objects/allocations. abi.json describes the private offsets and pipe observations;
these are representations, not caller authority.

## Exact source and image closure

images.json is an ordered list of original HIA function bodies. Shared State,
Value, preparation, Settings, crypto, root and seven application kernels are
included from their canonical source paths. support.hepta contains identical
helpers used by the three entries. Batch and Prefix have distinct worker and
mandatory entry functions; their differences are explicit, not selected from
an unbound runtime file.

Every build captures all owned source plus the complete recursive application
and pinned compiler inputs, and the original Rust/local Cargo/include fixture
graph. A successful build records all 21 actual stages: 19 image compilations,
one native emitter compilation, then the native emitter's 19-length input and
prefix output. The public reader reconstructs the exact full ELF from every
ordered flat image and the emitted prefix. It verifies every complete compiler
stdin/stdout/stderr, source snapshot, integer counter and before/after source
fence. A self-consistent empty original manifest or partial image hash cannot
replace the real source graph.

Actual pipe readers require complete, contiguous stdin/stdout/progress/reply
ranges, strict JSON types, every command record and complete raw streams.
False and 0.0 cannot stand in for integer 0. Missing/skipped fixture methods are
reported separately from methods actually executed. Physical fixtures are
regular files or metadata observations; an evidence reader never opens a FIFO,
socket or symlink as data.

## Reproducible qualification

All output paths below must be fresh and outside the source repository.
Use PYTHONDONTWRITEBYTECODE=1. The compiler and toolchain environment must point
to the exact pins in hia/toolchain.lock.json and compiler-binding.json.

- python3 -B -m hia.platform.execution_batch.test_integrity --report OUTPUT/integrity.json
- python3 -B -m hia.platform.execution_batch.qualification --profile batch --part 0 --output OUTPUT/batch
- python3 -B -m hia.platform.execution_batch.qualification --profile prefix --part N --output OUTPUT/prefix-N
- python3 -B -m hia.platform.execution_batch.physical --output OUTPUT/physical
- python3 -B -m hia.platform.execution_batch.lifecycle --output OUTPUT/scoped

Prefix N is 0, 1, 2 and 3. The four source-defined strided partitions cover all
186 histories exactly once. Batch retains all 102 original histories. Each
actual native process retains its 240-second limit and 3-second cleanup limit.
No partition reduces the accepted semantic corpus or the runtime State extent.

A successful semantic run makes OUTPUT/bundle containing the entire build,
source snapshot, full corpus, selected complete process artifacts and report.
Use the public single-part reader:
python3 -B -m hia.platform.execution_batch.bundle --profile PROFILE --bundle BUNDLE

The actual Rust runner requires one batch bundle or all four Prefix bundles:
python3 -B -m hia.platform.execution_batch.rust_oracle --profile PROFILE
--bundle BUNDLE [--bundle BUNDLE ...] --output OUTPUT --target-dir CARGO_TARGET

Its validate-only mode performs full bundle admission before any Cargo work.
The real run copies the complete original source graph, appends one private
cfg(test) hook without modifying original functions, uses explicit bound
compiler/Cargo executables, checks the locked serde archive and actual
default/std library artifact, runs the complete original corpus plus nine batch
or six Prefix retained tests, then rechecks source, binary and tool identities.
It retains original error/panic/cancellation outcomes and every raw stage.

After a valid bundle exists, test_integrity --bundle BUNDLE --profile PROFILE
performs actual public-CLI mutation controls on a private exact copy. These
include the previously observed empty original-source map, boolean stream range
and complete machine-code link substitutions. It never rewrites the source or
original qualification artifacts.

## Evidence and limits

Development observations belong to their executed source sets. Recomposition
and byte-identical runtime images alone do not upgrade older observations to a
new complete source set. New canonical qualification and actual Rust reports
must be generated after all owned files are frozen. Initial adapter, transport,
observer, source-admission and runtime failures remain separately available in
development evidence; their status is never rewritten as PASS.

Physical controls include malformed/aliased descriptors, complete framing
refusals, EOF, actual injected mmap/mremap ENOMEM and a real wrong-worker ACK.
Scoped controls separately cover repeated new/drop, full base rereads, actual
IndexMut panic, constructor failures, journal rollback and whole-heap retirement.
They do not establish durable Node publication or resistance to an unrestricted
malicious process of the same UID.

CI should use separate jobs for batch, the four Prefix parts, physical and
scoped lifetimes; actual original jobs consume only same-head/same-run complete
native artifacts. Each job retains its existing 20-minute outer deadline.
Checkout needs only the exact current head, not unused Git history. Whole-source
Git validation belongs before and after every job in the integration workflow.
