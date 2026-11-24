# ReleaseBundle ExactSourceV0 candidate

[The HIA kernel](exact_source.hepta) implements the pure candidate validation
and canonical digest of
[the original ExactSourceV0](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs).
It does not derive or attest those identifiers from a repository or grant
release authority. It reuses the [repository's HIA SHA-256 stream helpers](../crypto/sha256_stream.hepta)
for the fixed-length transcript.

The private borrowed entry `f0(input, digest, scratch)` requires disjoint
regions. The input must be exactly 193 bytes, in declaration order:
repository, commit, tree, Cargo.lock, toolchain, and production-closure digests
(32 bytes each), then a one-byte dirty flag (`00` clean, `01` dirty). Each
digest must be individually nonzero; embedded zero bytes, high-bit bytes
and repeated nonzero digests preserve the original behavior.

On success (`0`), the first 32 output bytes are SHA-256 of the exact original
transcript. Each of the following eight parts is preceded by its own
unsigned 64-bit big-endian byte count:

- the 28 ASCII bytes `trnm.release.exact-source.v0` (no NUL);
- the six 32-byte digests, each a separate part in declaration order;
- the single clean byte `00`.

The transcript is 285 bytes. Minimum output and scratch sizes are 32 and
1,493 bytes. The scratch contains 1,208 private SHA-256 state bytes followed
by the transcript. It is initialized on each accepted invocation and is not
a cross-process checkpoint. The input, output suffix and scratch suffix are
unchanged. Refusals are ordered: `100` for wrong input extent or a non-Boolean
flag, `101` for a typed but invalid candidate, `102` for insufficient output
or scratch capacity. These refusals leave both writable buffers unchanged.
`103` reserves an internal hash-helper refusal, publishes no digest and
does not promise to preserve scratch. The Rust type has no framing/capacity
errors, and the HIA entry intentionally does not hash invalid candidates.

The differential compiles the unchanged Rust types and methods extracted
from current source, including `validate`, `canonical_digest` and
`Digest32V0::hash`. It uses coreutils `sha256sum` only at the external
`sha2` seam. A known digest, an independent hashlib calculation and direct
inspection of every native transcript check both machine emitters. Each
field independently exercises zero and all single-nonzero-byte positions,
with field swaps, dirty flags, malformed frames and shortage precedence.
This does not run the complete Cargo crate or its production caller.

```sh
python3 -B -m unittest -v hia.tests.test_release_exact_source
```

The kernel is not called by production. It does not validate actual checkout
cleanliness, source authenticity, complete SBOMs, provenance, signature
quorum, file custody or release readiness.
