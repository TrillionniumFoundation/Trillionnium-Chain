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
32-byte row digest. This fixture ABI is not an original wire format. Its
stock x86-64 borrowed input limit is 1 MiB including the 44-byte trailer;
the original Rust row type can carry a value up to 16 MiB. Logical field
limits are unchanged. The second ABI span is never used or written, and
the scratch span must have at least 1,248 bytes when hashing is needed.
Return codes: success 0; malformed private framing 100; Rust
`InvalidExportRow` 101; short scratch 102; internal hash refusal 103; Rust
`ForbiddenAuthorityState` 104. Framing and logical length refusals precede
scratch validation and hashing. This is row-level validation only, without
export ordering, finality, SQLite import, caller integration, or activation.

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
