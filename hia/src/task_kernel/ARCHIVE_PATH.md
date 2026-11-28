# Private original archive inclusion path
The private diagnostic takes the exact canonical Borsh policy and batch
envelope of the existing bounded archive batch validator, followed by
one additional 32-byte query Task ID. It validates the immutable batch
before looking up that ID, including the earlier policy, seal, record,
order, charge, root and range rules. It never accepts prehashed external
leaves or an external root as a substitute for that validation.

For a matching record the native module recomputes the at-most-eight
validated record hashes, materializes the exact sibling sequence
(including self-duplication for an odd tail at every level) and emits
the original Borsh `TaskArchiveInclusionProofV1` bytes: version u16,
seal hash, leaf index u32, sibling count u32, and ordered 32-byte siblings.
A missing valid query returns original NotFound; earlier validation
errors retain priority. Test comparison is the unchanged public
`TaskArchiveBatchV1::inclusion_proof` on ordinary local generated batches.
The comparator also verifies those genuine Rust results through the
unchanged public archive verifier.

The private caller supplies 138 disjoint output bytes (the fixed maximum
for eight leaves; only actual bytes are written) and 1,864 disjoint scratch
bytes. Transport refusals are 100/102; internal bounded hash failure 103.
No refusal publishes output. This is not proof-of-work, a trust decision,
verification of externally claimed history, storage access/deletion,
signing, publication authorization, or a production path.
