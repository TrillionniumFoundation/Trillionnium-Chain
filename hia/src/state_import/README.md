# StateImport forbidden-namespace predicate

`reserved_namespace.hepta` is a finite native port of the original
`trnm_state_import::forbidden_authority_namespace` helper. On the pinned Linux
x86-64 direct and self-hosted backends its checked byte ABI accepts one
borrowed namespace span and two untouched mutable ABI spans. It returns `1` if any of the seven original
case-sensitive prefixes match, or `0` otherwise. It neither reads past a
short span nor treats a delimiter, a NUL byte, UTF-8, or case as special.
The original helper has no namespace-length filter; the checked callable is
limited to the stock 1 MiB span and does not impose the original caller's
distinct 128-byte row limit.

`hia.tests.test_state_import_namespace` compiles the unchanged standalone Rust
function body from the current original crate with a transport-only observer.
It compares both native images, including exact prefixes, one-byte extensions,
truncations, byte mutations and the real 1 MiB callable boundary. It does not
link or qualify the full Rust crate, admit imports, decide row-digest/finality
validity, implement SQLite durability, replace an existing owner, or authorize
any signing state or production activation.

## Finalized export header commitment

`finalized_export_header_digest.hepta` ports the exact original
`FinalizedExportHeaderV0::canonical_digest()` value computation. It constructs
the 321-byte domain-plus-fields transcript in private HIA scratch and invokes
the retained native streaming SHA-256 code. No caller-supplied transcript or
stored `header_digest` participates in hashing.

The private borrowed callable takes one exact 240-byte input, at least 32
bytes of output, and at least 1,529 bytes of scratch. The input is a local
fixture ABI, not an original serialization: source-chain (32),
source-protocol (32), source-height (8, big endian), source-state-root (32),
source-schema (32), source-finality-proof (32), row-count (8, big endian),
export-root (32), stored-header-digest (32). Success returns 0 and writes only
the first 32 output bytes; malformed extent (100) precedes capacity refusal
(102), both before output or scratch writes. Internal hash refusal is 103 and
does not publish output. The bytes are a commitment, not validation of export
rows, finality proofs, or admissibility of the header.

The differential compiles the unchanged original two types and implementations
with the existing General C original SHA2 0.10.9 dependency, checks ordinary
and boundary values, compares both real native images, and shows that changing
each stored digest byte has no effect. No production verifier is replaced.

## Export row admission

`export_row_validate.hepta` ports the bounded call to the exact Rust
`ExportRowV0::validate()`. It checks namespace/key/value lengths, computes
the original SHA-256 domain-and-three-parts transcript, compares all 32 stored
digest bytes, then applies the same seven native reserved-prefix checks to
the namespace extent only. A stale digest therefore precedes the forbidden
namespace error, as in Rust. No validation bytes or authority capability are
published.

For this private borrowed callable, concatenate namespace, key, and value
bytes, then append three little-endian 32-bit field lengths and the stored
32-byte row digest. This fixture ABI is not an original wire format. The
direct x86-64 wrapper still admits at most 1 MiB per borrowed span. The pinned
Selfhost legacy `f0(readbuf,mutbuf,mutbuf)->u32` profile also runs the original
full row extent in an opt-in isolated fixture with live, disjoint allocations:
128 namespace bytes, 65,536 key bytes and a 16 MiB value plus the 44-byte
trailer (16,842,924 bytes). Logical field limits are unchanged. Native SHA-256
uses the existing offset-based stream with a row-specific transcript bound
of 16,842,940 bytes (maximum fields plus the 28-byte domain and four 8-byte
length prefixes). The second ABI span is never used or written, and
the scratch span must have at least 1,248 bytes when hashing is needed.
Return codes: success 0; malformed private framing 100; Rust
`InvalidExportRow` 101; short scratch 102; internal hash refusal 103; Rust
`ForbiddenAuthorityState` 104. Framing and logical length refusals precede
scratch validation and hashing. This is row-level validation only, without
export ordering, finality, SQLite import, caller integration, or activation.
The larger private fixture does not widen the Direct ABI or any mutable span,
and does not establish a production full-size batch or durable handoff.

## Ordered export Merkle commitment

`export_merkle_root.hepta` ports the exact original
`trnm_state_import::merkle_root_v0(&[Digest32V0])`. The input is the ordered
concatenation of 32-byte digest leaves. Empty input hashes the original
empty-root domain; a singleton returns that digest unchanged. Every reduction
layer hashes ordered, length-prefixed digest pairs in the original node domain.
An odd final node at any layer is paired with itself, not skipped.

The local borrowed fixture takes one exact multiple-of-32 input, at least
32 bytes of output, and at least 1,336 bytes plus the input extent of scratch.
The implementation reduces layers in private scratch and publishes the final
32 bytes only after completion. Returns: success 0; malformed input extent 100;
short output or scratch 102; internal hash refusal 103. The stock 1 MiB
borrowed scratch ceiling admits at most 32,726 leaves in one call; this is a
local ABI bound, not a change to the original export row-count policy. This
method does not validate, sort or deduplicate leaves, verify a finalized
source, issue an authorization, or qualify persistent import.

## Export header admission before independent finality

`export_header_admission.hepta` implements the complete pure header predicate
before the original `verify_export_v0` calls `SourceFinalityVerifierV0`. It
requires nonzero source identities, source height, export root and stored
header digest; an exact nonzero row count at most 100,000,000; and equality of
the stored and natively recomputed header digests. It never examines rows
before finality: the original may report a finality refusal in the presence
of invalid or unsorted rows.

The local input appends one big-endian `u64` observed rows length to the
240-byte header fixture. The returned status is not a verified export:
0 means only that an independent finality verifier may be called; 107 maps to
original `InvalidExportHeader`. Malformed fixture extent (100), short private
scratch (102), and internal hash refusal (103) are local transport errors.
The second ABI span is untouched, and private hash computation requires
1,529 scratch bytes. This entry never calls a finality verifier, issues a
capability or admits a batch, nor does it validate the provided count against
actual rows from an independent host.

The exact Rust differential calls the original `verify_export_v0` with
intentionally invalid row objects and a separate refusing sentinel. It verifies
that valid header cases reach the sentinel exactly once and that rejected
headers reach it zero times; it never allows the original post-finality loop.
The separate high-count ABI control supplies an observed length, not a
fabricated Rust vector of 100 million rows.

## Post-finality ordered root and digest join

`export_ordered_root_join.hepta` ports the final pure join from
`verify_export_v0` for **already validated rows in their established order**.
The caller supplies only a sequence of at least one 32-byte row digest and
then the expected 32-byte export root, all in that order. Internally it
computes the original raw-domain SHA-256 ordered digest and uses the original
pair reduction to recompute the Merkle root. It publishes the ordered digest
only if the Merkle root equals the supplied value. A root mismatch returns
108 (`ExportRootMismatch`) and does not publish output; scratch is private
and may have changed. It does not verify the trust of the supplied root.

This local callable requires disjoint borrowed spans, a multiple-of-32 input
of at least 64 bytes, at least 32 output bytes and private scratch of at least
1,400 bytes plus the leaf bytes. Stock 1 MiB scratch permits 32,724 leaves.
Transport extent (100), capacity (102) and internal hash (103) refusals are
not original protocol errors. The Direct stock borrowed wrapper rejects overlap before entering the kernel;
self-hosted callers must supply disjoint owned spans as a precondition. On
success only the first 32 output bytes change.

The test executes the original Rust function in an isolated fixed synthetic
fixture context, with actual row validation and ordering before the root join.
The context is not a production finality verifier or transferable recipient
capability. The native callable itself cannot establish those prerequisites,
does not validate rows or their order and cannot accept an export, issue a
`VerifiedExportV0`, or authorize persistent import.

## Post-finality row-order step

`export_order_step.hepta` is the original within-loop sequence on one
current export row and an optional established prior (namespace, key)
tuple: validate the current row first, then require strictly increasing
unsigned byte order by namespace and then key. Shared native helpers
recompute the original canonical digest and enforce the seven reserved
prefixes. The resulting order error (109, `RowsNotStrictlyOrdered`) cannot
supersede `InvalidExportRow` (101) or `ForbiddenAuthorityState` (104).

The private fixture appends the prior namespace and key after the current
namespace, key and value. Then append five little-endian `u32` lengths in
that order and the current stored 32-byte digest (52 trailer bytes).
Two empty prior fields mark the first row. Otherwise each prior field must
be nonempty and meet the original width bounds; this distinguishes
malformed transport (100) from an original current-row refusal. The prior
tuple is an input from the caller, not a verified or persisted state.
Private scratch requires 1,248 bytes (or returns 102); hash refusal is 103.
The second ABI span is untouched, and all calls require disjoint spans
under the stock 1 MiB cap. No output record is published.

The actual Rust differential runs exact `verify_export_v0` on one or two
synthetic rows in an isolated local context that recognizes only its exact
test fixture; eligible prior rows are independently validated in Rust.
This helper does not perform independent finality, accumulate an entire
batch, install a retained prior tuple or authorize any future row.

## Post-finality batch fold

`export_post_finality_fold.hepta` joins the original pure downstream
operations of `verify_export_v0` in one native call: validate each current
row, reject non-increasing tuples against the prior row already observed by
this same call, collect the original row digests, recompute and compare the
Merkle root, and publish the original ordered digest only on success. The
first original row, reserved-namespace, or ordering error precedes any
later row or root check. A failed root comparison does not publish output.

The private fixture begins with the already admitted header's expected root
(32 bytes), then a little-endian `u32` nonzero row count. Each row encodes
three little-endian `u32` widths (namespace, key, value), the 32-byte stored
row digest, then the three byte fields. Bounds are checked before reads.
Malformed transport or trailing data returns 100; 101, 104, 108 and 109
correspond to original row, reserved namespace, root and ordering refusals.
Transport capacity (102) and internal hash (103) are not protocol errors.
Native borrowed spans must be disjoint and satisfy the stock 1 MiB extent.
The first 32 output bytes receive the ordered digest on success; scratch
requires at least 1,400 + 32 times row count bytes. Scratch may contain partial
work on refusal; it is not an output or a transferable state.

This pure entry is not a public import command, an independent finality
verifier, a `VerifiedExportV0` constructor, or a durable owner. Its caller
must establish the actual source and finality outside the kernel. The
stock input extent bounds the call, not the original export row-count or
value limits. The Rust differential is the actual unchanged
`verify_export_v0` operating on synthesized rows in a local exact-fixture
context; it issues no production authorization.

## Durable SQLite snapshot shadow

The qualification runs the complete unchanged original `trnm-state-import`
crate with its locked bundled SQLite. Its disposable owner initializes a real
database, exits, and a fresh process calls
`SqliteIncrementalStateStoreV0::open_existing` and `export_snapshot_v0`.
A second cold read must observe the identical generation bytes and must not
change the database bytes. A separate original process commits a real delta
with changed rows, root, and target context. Both cold generations replay in
HIA; a private frame mixing intact predecessor rows with successor metadata
is rejected without output. The fixture-only deterministic root callback is
not the production State root builder or any finality verifier.

Both native backends independently check the returned snapshot: row framing,
row shape and digest, reserved prefixes and strict order, exact row count,
the canonical target-rows transcript, and the canonical nine-field snapshot
commitment. The private shadow frame starts with six raw 32-byte metadata
digests, two big-endian u64 fields, the last-delta digest and the expected
snapshot digest, followed by the same private 44-byte row header plus data
used by the folded export fixture. All private buffers are disjoint. Within
the normal 1 MiB fixture spans, the scratch minimum is 1,400 + 32 × rows
bytes. Output is the 32-byte recomputed commitment only on success. Shadow
codes 110/111 distinguish rows and snapshot commitment mismatch; ordinary
row and private framing/capacity codes are reused, not original SQLite
or install errors.

The native call observes the original owner's atomic snapshot export. It
does not own the SQL transaction, recompute the application state root,
decide snapshot admissibility, verify finality, install or authorize cutover.
No production routing is changed. Run with the pinned compiler environment
and a populated locked Cargo cache:

```sh
python3 -B -m unittest hia.tests.test_state_import_snapshot_shadow -v
```

## Bounded incremental-delta commitment

`incremental_delta_commitment.hepta` computes the original ordered
`incremental_delta_root_v0` and `IncrementalStateDeltaV0::canonical_digest`
together. Its first 272 input bytes are eight 32-byte digests (plan, target
schema, source context identity, target context identity, base rows, base
state root, target rows, target state root), then two big-endian u64 counts
(base, target). The remainder contains zero to eight 280-byte operation slots
in caller-supplied order:

- A little-endian u64 descriptor: low byte `0` for absent value (delete) or
  `1` for present value (insert or update); the upper bits are the value
  byte count, which must be zero for delete.
- Little-endian u64 namespace and key lengths, each 1–64.
- Fixed slots of 64 bytes for the namespace, 64 for the key and 128 for the
  value. Only each declared span is hashed; slot padding is ignored.

The call requires 2,016 bytes of independent private scratch and 64 bytes
of output, in which it publishes the delta root followed by the delta digest
only on success. A malformed frame returns 100, insufficient capacity 102,
and an internal hashing failure 103. Input is untouched; scratch is private
and unspecified after use.

This computes an ordered commitment, not `IncrementalStateDeltaV0`
admission. It does not sort, validate namespace policy, verify context
authority, recompute an application state root or open SQLite. Its original
Rust oracle links the unchanged locked crate, computes context identities
from actual `SourceCheckpointContextV0` values, and consumes its actual
operation, Merkle and final canonical digest methods. Both stock native ELF
backends independently match those observations.

### Migration plan commitment and deterministic admission

`migration_plan.hepta` computes the original `MigrationPlanV0` SHA-256
commitment over its domain and eleven length-framed fields. The private
266-byte canonical form supplies the exact fixed fields and two boolean
octets. Its separate 434-byte admission form also supplies the submitted
digest and 136 bytes of already verified export binding. Native admission
checks both flags, the required nonzero identities, equality to the supplied
source binding, the different target chain and the recomputed digest.
Only successful requests publish the 32-byte digest. Differential tests use
the locked original Rust crate on both pinned x86-64 native backends.
This is a pure predicate. It does not verify source finality, establish the
authority of the supplied binding, or install a migration.

### Source checkpoint context commitment and structural check

`checkpoint_context.hepta` hashes the original nine length-framed
`SourceCheckpointContextV0` fields. The 240-byte canonical lane hashes the
full fixed layout; the 241-byte structural lane appends mode byte 1 and also
requires the same seven nonzero identities, nonzero height, and nonzero
result as the original. Epoch zero and equal digest fields are valid.
The scratch capacity is 1,572 bytes, and successful output is exactly a
32-byte raw context digest. The locked Rust comparison uses an owner
callback that always refuses and counts its invocations, so no test path
mints a verified context. This kernel verifies only byte structure, not
finality, proof content, checkpoint ownership, or migration permission.

### Finalized-source binding and migration projection commitments

`handoff_commitments.hepta` computes the original source-binding and
projection domains over the exact original length-framed fields. The two
standalone shapes are 272 and 200 bytes. The 576-byte private binding form
also checks the supplied source digest and exact equality to a separate
272-byte projection from the already verified export. It returns only the
32-byte digest after success. Tests obtain actual original Rust projections
and source bindings with the retained disposable fixture owner and compare
all pairwise binding outcomes. The native code does not create a verified
export, derive an application state root, perform a cutover, or install data.

### Per-operation target delta row

`target_delta_row_validate.hepta` qualifies the original
`TargetDeltaRowV0::validate` on one immutable operation in a shared stock
1 MiB Direct/Selfhost envelope. The private borrowed frame is the namespace,
key and optional value byte spans, followed by four little-endian `u32`
words (namespace, key and value lengths, then the option tag) and the
stored 32-byte operation digest. Tag 0 requires zero value length;
tag 1 permits a present empty value. The two forms hash differently.
The namespace/key nonempty and original width checks and the same
reserved-prefix checks precede a real framed SHA-256 computation and
comparison against the stored digest. The envelope is narrower than
the original Rust 16 MiB per-value limit; the shared native maximum is
1 MiB minus the 48-byte trailer and the namespace/key spans.

The entry never writes the second ABI span. The scratch span must be
disjoint and supply 1,256 bytes; only those bytes can change. Status 101
represents the original `InvalidDeltaRow` result without distinguishing its
causes. Private framing, scratch or internal hashing refusals (100, 102,
103) are not protocol errors. The locked Rust witness invokes the genuine
typed `TargetDeltaRowV0` implementation and tests the same typed inputs
against both stock native machines, including the full shared envelope
and one Rust-only value just outside it.

This is not whole-delta validation: ordered replay, context checks,
resulting rows and application root computation, durable CAS and cutover
remain with the current owner. No production caller or SQLite route uses
this qualification entry.

### Ordered target delta rows and Merkle equality

`target_delta_rows_root.hepta` is the next pure substage of
`IncrementalStateDeltaV0::validate` after the original header and context
checks. Within one immutable, disjoint stock 1 MiB input it parses zero to
eight operation rows, validates each actual stored operation SHA-256
against its own bytes, requires strict unsigned namespace/key order, then
computes the actual empty or odd-layer delta Merkle root. An invalid row
wins over a tuple-order failure on the same row, and the first row/order
failure wins over root mismatch. It stores computed leaves only in
2,016 bytes of private scratch and never changes the second ABI span.

The private frame is little-endian `u32` row count, a 32-byte expected
delta root, and concatenated row frames. Each row begins with four
little-endian `u32` words (namespace, key, value widths, and optional-value
tag), its stored 32-byte operation digest, and the declared fields. Status
101 is the original invalid row, 109 order failure, and 112 delta root
mismatch. Private extent/framing status 100, capacity 102, and hash 103
are not original protocol errors. The cap of eight rows and the shared
envelope are narrower than the original Rust format.

The original locked Rust witness canonicalizes the enclosing pure synthetic
delta and calls the real `apply_incremental_delta_v0`. Accepted HIA status
corresponds to that call reaching its fixture root-owner boundary exactly
once, where the test owner always refuses. Earlier errors never reach the
owner. The native root comparison does not authenticate its supplied root,
verify header/context, compute an application root, authorize replay, or
change SQLite/production routing.

### Incremental delta header and paired checkpoint context

`incremental_delta_header_validate.hepta` covers the pure header prefix of
`IncrementalStateDeltaV0::validate`. It checks the two original typed
checkpoint contexts in source/target order and computes both of their
original framed SHA-256 identities. It then checks the header's nonzero
fields and original row-count bounds, compares the genuine canonical delta
digest with the stored value, and enforces the original chain, protocol,
height, epoch and state-root relationships. The epoch comparison retains the
allowed equal or next epoch, including saturation at `u64::MAX`.

The private borrowed 760-byte frame contains two 240-byte checkpoint
context values, six 32-byte digests in order (plan, target schema, base
rows, base state root, target rows, target state root), two big-endian
`u64` base/target row counts, the 32-byte delta root and stored 32-byte delta
digest, then one big-endian `u64` observed operation count. This stock
profile is restricted to zero through eight operations and uses 1,808 bytes
of disjoint private scratch; the second ABI span is never changed.
Original invalid context and invalid header are represented by 113 and 114;
private 100, 102, and 103 denote exact-frame, capacity, and internal-hash
refusals. A successful header is not an operation/root validation.

The independent locked Rust witness exercises the original
`apply_incremental_delta_v0` with owned synthetic values. It records
whether the original call rejected a context, rejected the header, or
proceeded to the separate rows/root/base stage. Its fixture root owner
always refuses and never returns application state. The HIA call issues no
verified source context, trusts no external signer, and never changes any
database, application state, or production route.

### One-call incremental delta validation

`incremental_delta_validate.hepta` runs the whole **pure**
`IncrementalStateDeltaV0::validate` sequence in one stock native call
over the bounded synthetic profile already used by the separate header
and ordered batch qualification entries. The single immutable input
starts with the exact 760-byte header frame. The row frames from the
batch profile follow it, without the batch's separate count and root
prefix. The header's count is the only count used both for digest and
row consumption. Its stored root is the only root used both for digest
and post-row equality. A missing or extra row cannot be accepted.
The fixed offset adaptations are tested against the older component
sources, and the earlier two emitted components remain unchanged.

A header/context error precedes an operation or root error on a complete
typed fixture. Inside the operation stage the current row is validated
before its tuple order; the first operation error wins over a root error.
One call compares the real recomputed digests and never receives an
external validation result. Private malformed frames or trailing bytes
return 100, and a stock 1 MiB, eight-operation or 2,016-byte scratch
capacity constraint is not a limit of the original Rust data model.
The second ABI span is not used or changed.

The locked original witness calls the actual
`apply_incremental_delta_v0`. A native success on a valid synthetic
fixture corresponds to the original reaching its owner boundary, where
the witness refuses. The native code never calls that owner, recomputes
an application root, returns applied rows, verifies checkpoint authority,
opens a database, or changes production routing.

### Outer base-row witness before the application root owner

`incremental_delta_base_witness.hepta` covers the read-only stage after
pure delta validation but before the first root-owner callback in
`apply_incremental_delta_v0`. It checks full equality between the two
embedded and two separately supplied raw typed contexts. It then checks
every base row's shape and reserved prefix, and compares strict unsigned
namespace/key order. Only after that pass does it compare the original
base row count and compute and compare the genuine ordered
`trnm.migration.target-rows.v0` digest over the canonical row hashes.
It has no root-builder callback or writable result buffer.

The private 1,008-byte prefix is four 240-byte raw contexts (embedded
source, embedded target, supplied source, supplied target), the
big-endian `u64` declared base row count, its 32-byte digest, and the
big-endian `u64` count of actual row frames. Each row frame has four
little-endian `u32` values (namespace, key and value byte lengths,
then zero), then the declared payloads. The profile permits zero through
eight rows and a 1 MiB total loan, with 1,656 disjoint private scratch
bytes. Status 117 means original context mismatch, 118 invalid base
row, 109 row order failure, and 115 base count or digest mismatch.
Private frame, capacity and hashing statuses 100, 102, 103 are not
original errors. The native call never changes the second ABI span.

The locked Rust witness uses real `derive_incremental_delta_v0` values to
bind the expected count and digest, then calls the unchanged
`apply_incremental_delta_v0`. When the matching synthetic base reaches
the first root callback, the witness checks the actual ordered rows and
always refuses. This does not verify opaque contexts, recheck pure delta
validation, compute application state, apply a delta, or write to SQLite
or any production owner.
