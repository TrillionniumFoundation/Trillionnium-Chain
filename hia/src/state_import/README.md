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
