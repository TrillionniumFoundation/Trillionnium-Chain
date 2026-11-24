# Read-only TCR1 declared release metadata

The standalone HIA component decodes the original TCR1 bytes of
[`CellReleaseManifestV1`](../../../trillionnium/crates/trnm-data-availability/src/cell/manifest.rs)
and computes its exact content ID. Original
[`read_pinned_release`](../../../trillionnium/crates/trnm-data-availability/src/cell/release.rs)
uses that shape and digest before comparing a supplied pin.
[Closure decode](../../../trillionnium/crates/trnm-data-availability/src/cell/closure.rs)
also consumes TCR1. The HIA component does not replace either callers' file,
pin, cache, admission or execution decisions.

Input is the unmodified TCR1 wire: `TCR1`, u8 family length and UTF-8 bytes,
five 32-byte context digests, u32 big-endian declared cell count, then that
many exact 32-byte cell IDs. Original limits remain 1 MiB, family size 1–64,
and 1–32,760 rows. The maximum canonical input is 1,048,553 bytes. Context
digests must be nonzero. Cell IDs must be strictly increasing in byte order
and nonzero. The decoder neither sorts nor deduplicates them.

There is one private borrowed invocation. Output is 36 bytes: SHA-256 of
`trnm.cell-release-manifest.v1\0 || TCR1`, then the declared u32 little-endian
count. The canonical bytes remain available in the immutable input, so the
routine doesn't copy up to one MiB into the result. It requires 1,240 bytes
of scratch. The output and suffix are unchanged on refusal, and success
writes only its first 36 bytes.

Original statuses 1–11 report length limit, version, truncated field read,
family length, family UTF-8, family alphabet, context digest, cell count,
wire coverage, order or duplicate, and zero cell digest, respectively.
All context fields must be read before semantic context validation, which is
checked before reading the count. The overall cell ordering is checked
before cell nonzero validation even if both would fail. Private output or
scratch capacity is 102; an internal digest failure is 103. These private
failures are not original file or I/O diagnoses.

The [differential](../../tests/test_cell_release_manifest.py) calls the
unchanged Rust decoder, verifies its re-encoded bytes exactly equal the
input, and compares its actual ID, count and refusal order against both
locked emitters. The genuine Rust run requires the trusted original
`sha2` target specified by `HIA_M09_SHA2_RLIB`; without it only native
vectors and private capacity controls run. Maximum canonical size is
exercised on both emitters; the existing borrowed harness limits individual
buffers to 1 MiB, so the over-cap original refusal fixture is Rust-only.
No payload availability, custody, release authority, adoption or
production qualification is claimed.
