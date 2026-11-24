# Release PQ V0 callback shadow checkpoint proposal

This bounded private shadow entry borrows the exact
[NodeSoftware metadata and state frame](PQ_BUNDLE_STATE.md). It applies the
same native state predicate, then uses the shared
[canonical V1 signing message writer](PQ_SIGNING.md) against the first 155
bytes of that same input. It accepts no previous PASS, no supplied digest of an
intermediate message and no token. The caller supplies disjoint borrowed
input, output and scratch buffers through the existing HIA test ABI.

The first 32 output bytes reproduce the original Rust `next_checkpoint`:

```text
SHA256("TRNM/Release/PQ/Checkpoint/v1\0" ||
       owner_checkpoint[32] || observed_at_BE64 ||
       canonical_message_length_BE64 || canonical_message)
```

The suffix at 32 through 63 is
`SHA256("TRNM/HIA/PQ/BundleShadowSnapshot/v1\0" || borrowed_state_frame)`.
This distinct qualification identity names the exact checked metadata,
independent anchor and all supplied ordered history. It is not a root
identity, signature-set locator, fresh state attestation or reusable
capability. Distinct bounded state descriptors may produce the same original
proposed checkpoint but a different qualification identity.

Output and input remain unchanged on every refusal and bytes beyond the
64-byte output are untouched. The existing state refusal order applies before
capacity refusal; at least 1,504 scratch bytes are required. No scratch bytes
past that extent are written. No physical state, stable storage or previous
checkpoint is mutated.

The [staged differential](PQ_BUNDLE_CALLBACK.md) runs actual V0 content
verification, locator and native quorum math before calling this entry, and
compares the resulting checkpoint to the actual locked Rust authority's
accepted checkpoint. State/metadata guard success is not release
authorization. The original Rust borrowed quorum capability and durable
transition remain authoritative; the staged composition is not a single
native owner.
