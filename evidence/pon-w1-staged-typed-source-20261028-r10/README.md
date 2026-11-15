# Reconstructed typed W1 negative-control dispatch

This packet records a new host-only correction to the recovered staged pilot.
It does not recover the lost unpublished repair commit or qualify a new proof.
The earlier real complete W1 leaf remains available under
[full-proof](../pon-w1-complete-succinct-20261028/full-proof/manifest.json).

The pinned SDK's `VerificationError` implements `Debug` by calling `Display`.
The old `starts_with("ClaimDigestMismatch")` checks therefore tested the wrong
representation. The replacement matches the exact enum variant and both digest
fields after the existing inner-STARK, complete-claim, metadata and one-real-
assumption checks. It never replaces those checks or accepts arbitrary verifier
errors. The wrong-image existing-leaf control receives the same strict dispatch.

Primary sources, authenticated by their existing Cargo checksums:

- [risc0-zkp 3.0.5 error enum and formatting](https://docs.rs/risc0-zkp/3.0.5/src/risc0_zkp/verify/mod.rs.html).
- [risc0-zkvm 3.0.6 receipt verifier](https://docs.rs/risc0-zkvm/3.0.6/src/risc0_zkvm/receipt.rs.html).

The direct `risc0-zkp = 3.0.5` dependency uses `default-features = false`.
No package version, registry checksum, guest lock, original W1 source, guest
image, relation or WorkID changes. The only lock change is the direct host edge.
The new unit test rejects successful verification, unrelated verifier errors,
incorrect or exchanged digest fields and equal-digest fake mismatch reports.
It requires a real native run before any passed-test claim.

The [source readback](source-review.json) distinguishes Python public-byte and
dependency-identity checks from unexecuted compilation, cryptographic proof,
native unit tests, independent operator acceptance and production activation.
Read the [pilot contract](../../formal/pon-nakamoto-v1/w1_batch/STAGED_PILOT_CONTRACT.md)
for the complete statement and remaining gates. A one-leaf successful resolve
would still provide one existing work and no additional ticket or demonstrated
batch benefit.
