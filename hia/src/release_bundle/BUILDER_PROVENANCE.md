# ReleaseBundle V0 builder provenance

[This HIA kernel](builder_provenance.hepta) computes the original
[`BuildInputV0` and `BuilderProvenanceV0` canonical digests](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs).
It optionally checks the declarations and duplicate rules of
`BuilderProvenanceV0::validate`. It does not identify an actual builder,
inspect files or attest a build.

The private `f0(input, digest, scratch)` uses disjoint buffer regions.
The supplied frame has this fixed header and exact extent:

| Offset | Field |
| ---: | --- |
| 0 | Mode: `00` digest only, `01` candidate validation and digest |
| 1 | Build-input count, little-endian unsigned 16-bit (0–64) |
| 3 | Builder identity digest (32 bytes) |
| 35 | Workflow digest (32 bytes) |
| 67 | Run identity digest (32 bytes) |
| 99 | Isolated-environment digest (32 bytes) |
| 131 | Exact-source digest (32 bytes) |
| 163 | Artifact-set digest (32 bytes) |
| 195 | SBOM digest (32 bytes) |
| 227 | Declared provenance digest (32 bytes; ignored in digest-only mode) |
| 259 | Exactly one 578-byte slot per build input |

Each slot is little-endian u16 logical-name length (0–512), source and
content digests (32 bytes each), then a 512-byte logical-name slot. Unused
text suffix bytes are ignored. The private bounded selection scans at
most 64 rows per pass, at most 64 passes. The original 100,000-input
bound is not changed; this kernel is not a large-roster API.

Each build input hashes the parts `trnm.release.build-input.v0`, logical
name, source digest and content digest. Every part has its own big-endian
u64 byte count. The aggregate starts with 34 raw domain bytes,
`trnm.release.builder-provenance.v0`, then the five fixed digest fields
through exact source, a big-endian u64 row count, the ordered 32-byte
build-input digests, then the artifact-set and SBOM digests. Nothing else
is length-framed at the aggregate level. The original derived order sorts
by logical name, source digest, then content digest, each by unsigned byte
lexicographic order. The digest-only operation includes all entries,
including repeats and the empty set.

Candidate mode follows original validation precedence: the seven fixed
digests must be nonzero and the roster nonempty, then the computed digest
must match the declaration. Only then are individual inputs checked in
original input order: name must be nonempty printable ASCII, and source
and content digests must be nonzero. Each valid input is checked for a
duplicate **(logical name, source digest)**, regardless of content. Thus
staleness precedes an invalid member or duplicate, and an invalid row
precedes checking its own duplicate key.

Output needs at least 32 bytes, and scratch at least 5,114 bytes. `0`
writes the first 32 output bytes. `100` is malformed framing; `102` is
insufficient capacity. `105`, `106` and `107` map to original
`InvalidProvenance`, `InvalidBuildInput` and `DuplicateBuildInput`.
Failure never publishes a digest. Frame, fixed-identity predicates and
capacity are checked before scratch changes; declaration mismatch or
invalid/duplicate rows can leave private scratch changed after hashing.
`103` is reserved for internal computation refusal. Input is immutable, and the output and
scratch suffixes stay unchanged.

Tests compile the unchanged Rust V0 methods and derived ordering, using
GNU coreutils only at the external `sha2` seam. Each sorted member and the
complete aggregate transcript is compared with Rust and independent hashlib.
Both emitters are tested with native [source](EXACT_SOURCE.md),
[artifact set](ARTIFACT_SET_DIGEST.md) and [SBOM](SBOM_DIGEST.md) results
feeding this kernel, then the result feeding [bundle binding](BUNDLE_BINDING.md).
This in-memory qualification is not a production caller, an SBOM coverage
check, signing, custody, filesystem observation or build attestation.

```sh
python3 -B -m unittest -v hia.tests.test_release_builder_provenance
```
