# Native streaming typed-state staging

This component performs real Linux file reads and writes inside a HIA-generated
static executable. It combines the existing typed Delta relation with a complete
scan of the resulting stored State and an optional classical sparse State root.
It has **no namespace publication or Node commit authority**.

The executable invokes the pinned native compiler's emitted HIA machine code.
The Python files construct test inputs, compile captured HIA source, run physical
processes, and verify observations. They do not execute a production state
algorithm or supply successful syscall results. The Linux adapter is HIA source
which emits its own fixed machine instructions; those literal instructions
remain a separate trusted boundary.

## Source and execution boundaries

stage_policy.hepta owns capability admission, immutable-capture framing,
streaming merge, callback order, whole-byte before-value comparison, file writes,
the complete stored State scan, canonical JSON checks, leaf derivation, cleanup,
fsync, file identity recheck, close, and staging receipt emission.

root_finalize.hepta sorts actual derived paths, rejects duplicate paths, and
runs the existing native sparse-tree arithmetic. It is linked into the same
ELF. The private adapter command 4096 calls this HIA image; it is not a host
algorithm request.

includes.json lists exact canonical HIA functions. The builder independently
Core-verifies every contributing component and selects only explicitly named
functions owned by that file. It does not copy a dependency's imported helpers
implicitly. linux_stage_emitter.hepta emits the complete static Linux x86-64
adapter around the two machine images. Splitting the images preserves the
unchanged compiler operation limit.

No function in this component accepts an opaque COMMIT, caller-supplied leaf,
expected-root admission bit, existing HEAD discovery, or persistent namespace
capability. The block and slot in the receipt are typed tape metadata; they are
not authenticated chain selection.

## Real file capability admission

The bootstrap is 96 bytes: TSTAGE01 followed by eleven little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0, 1, 2 | Inherited base, Delta and empty output file descriptors |
| 3 | Detach, exactly 0 or 1 |
| 4, 5 | Progress writer and callback reply reader, or both u64::MAX |
| 6 | Stored-row profile: 0 classical, 1 growth dimensions |
| 7 | Calculate classical root, exactly 0 or 1 |
| 8–10 | Zero |

All provided descriptors must be at least 3, below 2^31, and numerically
distinct. Admission uses actual fstat, fcntl, geteuid and flock syscalls:

- Base and Delta are regular files with exact finite i64 extents and all four
  immutable-capture seals. A caller flag cannot replace F_GET_SEALS.
- Output is initially empty, regular, mode 0600, owned by the effective UID,
  has one link, is open read/write without append, and accepts a nonblocking
  exclusive lock. The native process records its device and inode.
- Progress and reply descriptors are actual FIFOs/pipes. The progress endpoint
  is write-only; the reply endpoint is read-only. O_PATH descriptors are
  rejected. Their actual device/inode pairs must differ, preventing a pipe
  from reading back its own progress record.

Every capability check precedes the first progress write. Checking FIFO type
also rejects a different descriptor number which aliases the regular output or
either regular input. These checks address a concrete earlier candidate defect:
a progress/output alias could write a 32-byte progress record before the
staging-write cleanup flag was set. Fresh qualification must physically verify
the fixed source; results from the lost earlier executor do not certify it.

The output descriptor is retained by the qualifying caller to inspect the
actual file. The executable itself closes its three file descriptors before
emitting a receipt. It cannot open a path, rename a file, publish HEAD, or commit
a namespace. The caller must keep exclusive control of these handed-off
capabilities. This is not a guarantee against an actor with the same UID
continuously changing inherited open-file descriptions or the output file.

## Stream formats and memory

Base and output use TKVSTR01, then a u64 row count. Each row contains u64 key
length, u64 value length, key bytes and value bytes.

Delta uses the existing NDLT0001 layout: u64 row count, 32-byte block identity,
u64 slot, followed by rows containing u64 key length, u64 before length, u64
after length, key and present before/after values. u64::MAX means absent;
zero means a present empty value.

Both captures must have exact framing, valid UTF-8 keys, and strictly increasing
unique keys. This constructor check finishes before the original operation's
first progress callback. It is a local typed-capture contract. The original
SQLite schema's primary keys provide uniqueness; this component makes no claim
about a corrupted schema with those constraints removed. SQL type conversion,
query/materialization failures and their callback order are separate obligations.

The kernel compares and copies arbitrary pre-State keys and values in 32,768
byte chunks. UTF-8 decoder state survives a chunk boundary. It does not impose
a 1 MiB or 196,608 byte total-State limit. Before values may exceed 2 MiB and
still must match every byte before a replacement or deletion proceeds.

The executable maps 4,587,520 bytes: 65,536 bytes each for event and command
buffers and 4,456,448 bytes of private state. Only the public event/command
payload ranges can be passed to a read or write syscall. The classical root
retains 64 bytes per derived path/leaf plus the existing bounded tree workspace.
The immutable file captures themselves still occupy operating-system storage;
stream acquisition and its resource budget are not qualified here.

## Original relation and progress order

The retained source calls are Node::apply_delta_with_progress,
Node::delta_rows_with_progress, Node::slot_state_with_progress, and
trnm_mvcc_fee::pon_executor::root. After the separate typed constructor:

1. Invoke the initial apply callback.
2. Invoke the initial Delta-read callback, then one after each 256 collected
   rows, then the final read callback. An exact multiple of 256 has both
   callbacks, including the final one. Empty Delta still has its final callback.
3. Before each Delta row, invoke its callback. Compare actual optional bytes
   with before when attaching and with after when detaching. Only an exact
   match permits the put/delete. Absent-to-absent deletion fails
   STORAGE_WRITE; present-empty remains distinct from absent.
4. After all Delta rows, scan every actual output row. Invoke the initial
   State callback and each 256-row callback, including row zero. Check count,
   key bytes at most 160, and value bytes at most 4096 before decoding that row.
   Preserve the original legacy SQL projection: substr of an empty BLOB becomes
   NULL, so the key's CAST/substr/CAST projection rejects an empty TEXT key,
   and the value's substr projection rejects an empty BLOB value. Dimensions
   precede these conversions, key conversion precedes value conversion, and
   the row callback can cancel before either conversion. These are stored-row
   materialization rules; Delta still compares and can delete or repair such
   values, and the separate M06 library root still permits an empty map key.
   Parse the entire stored JSON using the existing jv_parse with stored-value
   mode zero. Its canonical flag must confirm the exact original serde
   roundtrip. Then invoke the final State callback.
5. If requested, reread every actual row, parse again, validate M06 integer and
   ASCII value grammar, derive actual paths and leaves, and compute the root.

The row count limit is 65,536 in the classical profile and 1,065,536 in the
growth dimension profile. A growth-profile classical-root request is rejected
with status 69. No GSC2 root or growth owner success is substituted.

A progress record is TSPROG01 and u64 sequence, kind and row. Kinds 1 through
7 denote apply-start, Delta-read-start, Delta-collected, apply-row,
State-start, State-row and State-finish. A reply is sequence, class and token,
all u64. A successful reply has class zero and token zero. Classes 1 through 4
are opaque callback errors; the exact class and token are retained. The
sequence is checked before continuing. Without gate descriptors, the kernel
still records the same logical callback count.

Complete M06 State/root calculation is an observation in this component.
The original outer Node's continuity checks precede checked commitment and
must be preserved when the eventual typed owner is assembled. This staging
component cannot replace that ordering.

## Receipts and refusal

A successful 128-byte TSRESULT contains five u64 words (kind, row count,
file byte extent, Delta count, progress count), 32-byte block identity, u64
slot, 32-byte root and a zero reserved word. Kind 1 is validated stored rows;
kind 2 additionally contains the calculated classical root. Kind 1 has a zero
root field. Both kinds describe a staging file.

Before emitting a receipt the kernel fsyncs the file and rechecks actual
device, inode, link count, mode, effective UID and complete extent. It then
closes base, Delta and output. A lost receipt can leave a complete staging
file, but it cannot become a successful Node acknowledgement.

| Status | Meaning |
| --- | --- |
| 64 | Bootstrap or callback contract |
| 65 | Actual file capability refusal |
| 66 | Capture framing, key UTF-8 or ordering |
| 67 | Output already locked |
| 68 | Signed file-offset bound |
| 69 | Growth root not implemented |
| 70 | Actual I/O failure |
| 78, 79 | Adapter command or arena failure |
| 80 | Opaque callback failure |
| 81, 82 | Original UNDO_ROOT, STORAGE_WRITE |
| 83 | Stored key/value projection or serde decode family |
| 84 | Original stored STATE_BYTES family |
| 85, 86 | M06 RANGE, NONCANONICAL |
| 87, 88 | Internal root failure, duplicate derived path |

A refusal may emit seven diagnostic u64 words: code, phase, last syscall
result bits, progress count, callback class, token and cleanup error. Once a
staging write was attempted, an ordinary failure attempts ftruncate(0).
The original failure is retained if cleanup itself fails, with that secondary
failure in the diagnostic. SIGKILL may leave incomplete untrusted staging
bytes. No process-kill test is evidence of physical power-loss behavior.

Status 83 deliberately does not claim byte-identical SQL/serde error display
text, column positions or the full Rust error-source chain. The original Rust
oracle retains those actual values for review.

## Reproducible qualification

Set the three explicit compiler/toolchain environment variables required by
hia.platform.build, then run from the repository:

~~~sh
python3 -B -m hia.platform.typed_store.qualify --output /tmp/typed-stage-fresh
~~~

The qualification compiles captured HIA source, executes the resulting ELF
with actual sealed inputs and ordinary files, compares complete output bytes
and independent roots, checks callback identities, exercises file capability
refusals and every short framing prefix, and tests SIGKILL, fresh restart,
whole-file cold reads, real partial-write EFBIG, and loss of the staging
receipt. It also scans and roots a complete State above 1 MiB in a fresh process.
The complete 279,969,808 byte classical extent uses three dependent capacity
stages so each can retain the existing 20-minute CI job deadline:

~~~sh
python3 -B -m hia.platform.typed_store.capacity --stage produce \
  --run-id EXPLICIT_RUN --attempt 1 --output /tmp/capacity-produce
python3 -B -m hia.platform.typed_store.capacity --stage cold \
  --run-id EXPLICIT_RUN --attempt 1 --prior /tmp/capacity-produce \
  --output /tmp/capacity-cold
python3 -B -m hia.platform.typed_store.capacity --stage bounds \
  --run-id EXPLICIT_RUN --attempt 1 --prior /tmp/capacity-cold \
  --output /tmp/capacity-bounds
~~~

Every stage independently builds the HIA executable and checks the exact head,
run, attempt, complete source identities and executable hash against its
predecessor. In CI, the captured native source inputs must also match the
committed head selected by the required 40-hex TRNM_EXPECTED_SOURCE_SHA;
GITHUB_SHA is retained as event provenance and may be a pull-request merge
identity. Development snapshots are labeled explicitly. The producer
computes the complete native root and an independent full reference root,
then preserves the fully synchronized and closed native output in a lossless
archive. The cold stage restores and synchronizes every byte, verifies its
whole-file SHA, and invokes a fresh native process to reread and root the
entire State. The bounds stage actually changes the final physical byte,
checks its late refusal, checks the classical count-plus-one refusal, and
checks the growth dimension count edge. Archives transport exact bytes; they
never supply a runtime State verdict or root. Wall times and observed memory
high-water values remain in each report. No power-loss claim follows from
restoring a file on another CI worker.

Archive restoration writes at most the exact 279,969,808 byte corpus extent,
rejects short/extra decoded bytes and trailing archive data, and bounds the
test decoder's memory before comparing the actual restored file SHA. Each
long-running native child records its actual process identity. Creating STOP
in that stage's own output directory requests a real SIGKILL through its
controller, which reaps the child and records the terminal result. This
development cancellation cannot produce a passing stage or owner receipt.

native-comparison.json and corpus.jsonl.xz form the source-bound original
oracle bundle. On a machine with the locked Cargo graph available:

~~~sh
python3 -B -m hia.platform.typed_store.rust_oracle \
  --repository /absolute/repository \
  --bundle /absolute/native-bundle \
  --output /tmp/typed-stage-original-fresh \
  --target-dir /absolute/isolated-cargo-target
~~~

The driver copies the complete original source without changing production
function bytes, appends one cfg(test) declaration, and links rust_reference.rs
as its test child. It runs three retained original State tests and calls the
actual private apply/slot-State methods and original M06 root for every corpus
case. SQL rollback is checked byte for byte on every failure. Native and
original error class, progress count, result bytes and root must agree.
Missing Cargo is NOT_RUN, never a successful differential.

## Remaining complete owner work

The native owner still must create trusted typed captures from its owned
namespace, bind block/slot/context and generation to its durable journal,
perform original continuity and profile-specific checks, and execute the
atomic publication and reopen/readback path while preserving failure and
cancellation order. Durable replay, outbox, multi-block reorganization,
revocation history, GSC2 arithmetic, and the rest of the Node runtime remain
separate requirements. This component is an executable streaming staging
unit with a strict publication boundary, not a completed Node or authorization
to delete the retained implementation.
