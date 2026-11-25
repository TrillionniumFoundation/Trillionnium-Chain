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
