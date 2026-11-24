# ReleaseBundle V0 artifact set digest

[This HIA kernel](artifact_set_digest.hepta) implements the original
[`ArtifactEntryV0::canonical_digest`, `ReleaseBundleV0::artifact_set_digest`
and per-entry membership check](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs)
over supplied artifact metadata. It does not authenticate file contents,
expected artifact coverage, provenance or signatures.

The private borrowed entry `f0(input, digest, scratch)` requires three
disjoint regions. The exact input begins with a mode byte (`00` digest,
`01` candidate check then digest), then a two-byte little-endian row count.
The roster has exactly that many 877-byte slots:

| Offset in slot | Extent | Field |
| ---: | ---: | --- |
| 0 | 2 | Logical-name length, little endian (0–512) |
| 2 | 2 | Media-type length, little endian (0–256) |
| 4 | 8 | Artifact size, unsigned little endian |
| 12 | 1 | Executable Boolean, 0 or 1 |
| 13 | 32 | Content digest |
| 45 | 32 | Platform digest |
| 77 | 32 | Source-path digest |
| 109 | 512 | Logical-name slot |
| 621 | 256 | Media-type slot |

Suffix padding in text slots is ignored. The private roster bound is 64
rows; the original admission limit remains 4,096. The exact Rust order is
name, media type, unsigned **numerical** size, content digest, executable
Boolean, platform digest, and source-path digest. Raw text and digests
sort lexicographically by unsigned byte; a proper prefix sorts before a
longer value. The work is bounded by 64 selections with at most 64 row
visits each (plus bounded entry checks). This is not a large-roster API.

The canonical member transcript contains the 24 raw bytes
`trnm.release.artifact.v0` and the seven fields in Rust declaration order,
using an individual big-endian u64 byte count for the domain and each
field. The size field itself is big-endian u64 in the canonical hash.
The aggregate hashes the 28 raw bytes `trnm.release.artifact-set.v0`
followed by the sorted 32-byte member digests, with no count or delimiter.
Mode `00` does not validate entries, deduplicate or reject an empty set.

Mode `01` matches the original artifact-only part of bundle verification:
nonempty, then in original input order check each entry's printable/nonempty
name and media type, size in 1–137,438,953,472 and three nonzero digests,
then reject that member's duplicate logical name even if other fields
differ. A second invalid row with an already seen name fails on validity
before duplicate checking; a prior duplicate fails before a later invalid
row. There is no required-artifact-list rule in the original verifier.
The required-production-package rule applies to its separate SBOM checks.

The output requires 32 bytes and scratch requires 4,876 bytes. On `0`
the first 32 output bytes contain the digest. `100` is malformed input;
`105`, `106`, `107` correspond to the original empty-artifact
`InvalidBundle` case, `InvalidArtifact`, and `DuplicateArtifact` in
candidate mode. These precede capacity refusal (`102`) and do not change
either output or scratch. Internal failure (`103`) may change scratch
but never publishes a digest. Input, output suffix and scratch suffix
remain unchanged.

Tests compile the unchanged original V0 types, digest methods and
verifier. The SHA-256 adapter uses GNU coreutils at the original `sha2`
seam, and the signature boundary deliberately returns an error rather
than reporting a signature pass. Native tests compare sorted member
digests and complete framing against Rust and independent hashlib,
exercise membership/refusal precedence, and pass both artifact and
[SBOM](SBOM_DIGEST.md) outputs into the
[native bundle binding](BUNDLE_BINDING.md), which calculates the source
digest itself. Changed artifact or SBOM rosters fail against the unmodified
original binding. This test composition is not a production caller or
evidence of filesystem, signing or release readiness.

```sh
python3 -B -m unittest -v hia.tests.test_release_artifact_set_digest
```
