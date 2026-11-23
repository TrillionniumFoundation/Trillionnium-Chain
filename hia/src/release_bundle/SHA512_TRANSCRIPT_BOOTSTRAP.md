# Release full-content transcript bootstrap

The [native bootstrap](sha512_transcript_bootstrap.hepta) starts the existing
[full SHA-512 stream](../crypto/sha512_stream.hepta) over

```text
"TRNM/CPQ1/FullContent/SHA512/v1\0" || CCH1 header || RAC1 metadata
```

The prefix must be the caller-owned, admitted bytes produced by the existing
[CCH1](CONTENT_CLAIM_FRAME.md) and [RAC1](ARTIFACT_HEADER.md) kernels. Never
treat arbitrary concatenated bytes as validated metadata or an authenticated
context. The bootstrap independently checks the input extent (276–1,042
bytes), both tags, ReleaseArtifact kind and raw-length consistency. This is not
full metadata, candidate profile, or instance validation.

The private borrowed function `f0(input, unused, state)` takes disjoint regions.
Input contains precisely a 149-byte CCH1 header followed by the RAC1 header,
without a claim digest or raw byte. It leaves input and the unused output
unchanged. On success (`0`) it initializes the SHA-512 state, feeds the fixed
32-byte domain and both headers, and leaves bytes past SHA-512's 131,232-byte
working region untouched. It uses the existing stream's workspace gap for
the fixed domain bytes; it must not be mixed with another owner of that
state. Malformed envelopes (`100`) and insufficient state capacity (`101`)
leave all buffers untouched; `102` would identify an internal shared helper
failure, not an accepted hash. The state remains private and is not a
checkpoint or wire format.

A test-only in-memory owner uses both genuine machine emitters. It validates
RAC1, reserves the original cumulative length plus the one-byte EOF probe,
uses actual native CCH1/RAC1 outputs as bootstrap input, and feeds both
SHA-512 and the [raw SHA-256 lifecycle](RAW_ARTIFACT_SHA256.md) from the
same reads. After reading exactly the declared bytes and observing EOF via
one extra read on the same stream, it finishes both hashes and refuses a
mismatched legacy locator before publishing the actual 213-byte CCH1 claim.
A trailing byte is consumed by the EOF probe but cannot create a claim.
The original reader privately feeds that probe byte to its doomed SHA-256
state. The fixture instead discards both hash states on the same refusal,
without exposing a digest or overfeeding the exact-length native lifecycle.
The original reader's rejection priority is preserved in the exercised
cases: scope/metadata, budget, truncation/read errors or trailing content,
then legacy consistency. Denied observations expose no claim bytes.

The fixture compiles the original
[ReleaseBundle observer](../../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
and [generic content observer](../../../trillionnium/crates/trnm-protocol/src/content_commitment.rs)
and budget code using pinned Rust. It replaces only the SHA dependency at
its update/finalize seam with independent digest utilities and constructs
the fixture's context; it does not execute the original external Rust
`sha2` crate or the candidate-profile admission path. Cross-checks compare
all 213 bytes, reservations, actual read sizes and consumption, no-claim
outcomes, partition invariance, and changed metadata/context with unchanged
raw content. The owner and injected reader faults are qualification code,
not a runtime replacement.

```sh
python3 -B -m unittest -v hia.tests.test_release_transcript_composition
```

No production caller, file API, budget, custody, live routing, signature,
release authority, or package retirement changes.
