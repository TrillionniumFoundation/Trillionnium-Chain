# Read-only TCM1 cell manifest

These private HIA entries implement a pure subset of
[`CellManifestV1`](../../../trillionnium/crates/trnm-data-availability/src/cell/manifest.rs).
The original cache validates and hashes a TCM1 before use
([store](../../../trillionnium/crates/trnm-data-availability/src/cell/store.rs)).
The entries have no storage, provider or payload access and no live wiring.

- `cell_manifest.hepta` takes the original TCM1 bytes untouched. It writes the
  computed SHA-256 of `trnm.cell-manifest.v1\0 || TCM1`, then the complete
  canonical TCM1 bytes.
- `cell_manifest_chunk.hepta` takes a private u32 little-endian index followed
  by the same TCM1. Only after validating the complete manifest does it return
  the computed digest, u32 little-endian index, u32 little-endian source length,
  and the selected declaration's 32-byte source digest (72 bytes total).

These are deterministic content and metadata observations. The projection
does not fetch bytes or compare an expected manifest ID/context. Neither
entry checks provider
identity, construct an authoritative Rust binding, or run the RS46 recovery
component. The owner must still supply authenticated state and dependency pins
before using the declaration. No retention, production admission, model
adoption, or package retirement follows from these entries.

The wire uses original big-endian integers. A `TCM1` tag, u8 family extent
and family bytes precede five 32-byte opaque context digests, u64 cell length,
32-byte payload digest, u32 chunk size and u32 count. Each chunk row has a u32
length then a 32-byte digest. Full original semantic bounds are retained:
family 1–64 bytes, original chunk sizes 16 KiB–4 MiB and power of two,
cell sizes 1 byte–64 GiB, 1–16,384 rows with exact final coverage. The original
1 MiB input reject precedes tag parsing; the largest valid TCM1 is 590,101 bytes.
No new condition is imposed on digest bytes, including zero digests.

The original first diagnostic order is preserved: length limit, truncated
reads, version, family length and UTF-8, on-wire count, wire coverage, family
alphabet, chunk size, total size, expected count, then per-chunk lengths.
The length-limit, truncation, version, family-length and encoding classes
are statuses 1–5; 6–12 cover the remaining seven ordered checks. The
optional indexed entry uses 13 for no such row and 100 for a missing private
index prefix. Each requires 1,232 scratch bytes and sufficient output
capacity (102); 103 is reserved for internal hash errors. Input is immutable;
output stays wholly untouched on refusal and on success only the required
prefix is written. Callers supply disjoint borrowed buffers.

## Optional equality check in the same call

`cell_manifest_binding.hepta` reads a separate private `TCB1` frame:
ASCII magic, u32 little-endian index, 32-byte expected manifest ID, then
u8 expected family length, those exact UTF-8 bytes, and the five expected
opaque context digests in their TCM1 order. The remainder is the original
TCM1 wire. The expected family may be empty or contain non-ASCII UTF-8: it
is a caller observation and is only compared to the valid manifest family.
Invalid expected UTF-8 or a truncated private prefix is status 100.

A single call fully decodes the TCM1, compares all six context fields,
computes and compares the actual TCM1 content ID, and finally checks the
selected index. The ordering matches the unchanged
`CellRs46ManifestBindingV1::new(...).chunk(index)` after original
`CellManifestV1::decode`. After successful input validation a duplicate
Rust geometry pass would be equivalent, since the input is immutable.
The scratch and 72-byte observation layout are the same as the unbound
projection. Declared context mismatch is 14, content-ID mismatch is 15,
and missing chunk is 13. Scratch capacity is checked before hashing and
output capacity before publication. Input and the output suffix stay
unchanged; late refusal may modify only bounded scratch.

These equalities do not confer any authority: the caller is responsible
for where its expected context, expected content ID and TCM1 came from.
This adds no production caller, RS46 payload path, storage or access.
The [binding differential](../../tests/test_cell_manifest_binding.py)
isolates the original Rust binding structs and methods from
[erasure.rs](../../../trillionnium/crates/trnm-data-availability/src/cell/erasure.rs),
not the recovery implementation.

## Verification

The [native tests](../../tests/test_cell_manifest.py) run both pinned
emitters against ordinary synthetic manifests. The separately reported
exact original comparison uses the unchanged Rust source with
`HIA_M09_SHA2_RLIB` set to a trusted `sha2 0.10.9` artifact from a target
with the original Cargo graph and pinned Rust. The adapter validates
regular files, Cargo compiler and dependency fingerprints, package versions
and lock checksums. It records a bounded linked-library graph, not a new
Cargo build or deployed authority. Without that artifact, the original
methods are explicitly skipped, never replaced with another implementation.
