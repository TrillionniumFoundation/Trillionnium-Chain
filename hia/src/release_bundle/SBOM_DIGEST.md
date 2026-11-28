# ReleaseBundle V0 SBOM digest

[The HIA component](sbom_digest.hepta) computes the per-package canonical
digest and sorted aggregate of the original
[`SbomPackageV0::canonical_digest` and `ReleaseBundleV0::sbom_digest`](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs).
It reads raw typed inputs, not precomputed package digests or a claimed
ordering. It does not verify completeness or an SBOM's relationship to
the actual lockfile or build.

The private borrowed `f0(input, digest, scratch)` uses three disjoint
buffer regions. Input starts with a little-endian u16 row count, followed
by exactly that many 1,351-byte slots:

| Slot offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 2 | Name length (little endian, maximum 512) |
| 2 | 2 | Version length (little endian, maximum 256) |
| 4 | 2 | License-expression length (little endian, maximum 512) |
| 6 | 1 | Direct production dependency Boolean (0 or 1) |
| 7 | 32 | Source digest |
| 39 | 32 | Package checksum |
| 71 | 512 | Name bytes |
| 583 | 256 | Version bytes |
| 839 | 512 | License-expression bytes |

Unused suffix bytes in each text slot are ignored. As in Rust's
`Vec<u8>` ordering, declared text is compared as unsigned bytes, not decoded,
normalized, or case-folded. The order is name, version, source digest,
checksum, license expression, then Boolean (false before true). An equal
prefix sorts before a longer entry. Equal entries are not deduplicated.
The bounded selection pass accepts 0–64 rows,
with at most 64 scans of at most 64 rows. This is a private ABI/work bound,
not the original 100,000 package bound and not a change to release policy.

Each member hashes the domain `trnm.release.sbom-package.v0`, then the
six original fields above in canonical sort-field order, with a big-endian
u64 byte count for each part, including the domain. The aggregate hashes
the 20 raw domain octets `trnm.release.sbom.v0` followed by each 32-byte
member digest in sorted order. It includes no count or delimiter. Empty,
duplicate, non-printable or invalid UTF-8 typed values may have an exact
digest but are not thereby valid entries or an admissible release.

The output must have at least 32 bytes, and scratch at least 4,868 bytes.
Success returns `0`, preserving the output suffix. `100` rejects an
invalid extent, oversized declared slot/count or non-Boolean flag;
`102` rejects short output or scratch. Both leave all regions unchanged
and check the entire input framing before checking capacity.
`103` is an internal failure, preserves output, and may alter scratch.
The input and scratch suffix always remain unchanged.

The native differential compiles the unchanged original Rust V0 types,
derived ordering, member and set methods. GNU coreutils supplies SHA-256
at the external `sha2` seam; an independent hashlib implementation
also checks the aggregate and each sorted member digest. Controls cover
all order ties, equal prefixes, UTF-8 including supplementary characters,
binary bytes, changed padding, late refusal, both Boolean values,
empty and duplicate sets, and 64 maximum-width rows. In test only, the
result supplies the [native V0 bundle-binding entry](BUNDLE_BINDING.md);
a repeated package changes the commitment and is refused by the original
bound metadata. This is not production integration or full Cargo testing.

```sh
python3 -B -m unittest -v hia.tests.test_release_sbom_digest
```
