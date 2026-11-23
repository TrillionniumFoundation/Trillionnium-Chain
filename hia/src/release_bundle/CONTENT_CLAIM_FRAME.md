# ReleaseArtifact CCH1 byte framing

The [native frame](content_claim_frame.hepta) emits the exact 149-byte header
or 213-byte claim produced by the original Rust
[ContentContextV1 and ContentClaimV1](../../../trillionnium/crates/trnm-protocol/src/content_commitment.rs).
This is release-artifact producer framing only, not a generic claim parser.
The unchanged CCH1 output is:

```text
"CCH1" || profile_id[64] || 0x02 || instance[64] || be64(generation)
       || be64(RAC1_header_len + raw_artifact_len) [|| supplied_digest[64]]
```

The private input uses a separate 152-byte frame:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII CCF1 |
| 4 | 1 | 0 = header, 1 = claim |
| 5 | 1 | release-artifact kind (2) |
| 6 | 64 | nonzero caller-supplied profile ID |
| 70 | 64 | nonzero caller-supplied instance |
| 134 | 8 | generation, little-endian unsigned |
| 142 | 8 | raw artifact byte length, little-endian unsigned |
| 150 | 2 | previously validated RAC1 header length, little-endian unsigned |
| 152 | 64 | opaque supplied digest, present only in claim mode |

The producer accepts raw artifact lengths 1 through 128 GiB inclusive and
actual [RAC1 header](ARTIFACT_HEADER.md) extents 127 through 893 bytes;
the latter bound follows its name/media limits. Generic CCH1 encoding and
decoding do not impose these private composition bounds. The caller must still
supply a real RAC1 header length from matching original metadata and an
independently bound candidate profile; a nonzero ID is not proof of that
policy. A supplied digest is copied unchanged, including zero, and is not
checked or produced by this operation.

The borrowed `f0` returns the exact byte count, `0xffffffff` for invalid
framing or `0xfffffffe` for short output. Invalid input precedes a capacity
refusal. The whole output remains unchanged on refusal and its suffix is
preserved on success. Input, output and scratch regions are disjoint; scratch
is unused.

The [parity suite](../../tests/test_release_content_claim_frame.py) compiles
the original Rust header and claim encoder method bodies, field declarations
and release artifact size bound. It also supplies lengths returned by actual
native RAC1 calls. It does not implement read-budget reservation, EOF,
SHA-512 domain absorption, legacy SHA-256 comparison, signed approval,
observation, or any production Rust/Node route.
