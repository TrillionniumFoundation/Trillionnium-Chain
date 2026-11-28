# Detached CCH1 claim comparison for TCM2 and TCC2

This private native value owner matches the frozen
`ContentClaimV1::verify` over a freshly computed declaration observation.
It does not accept a caller-supplied observed digest, and neither the expected
claim nor the independent observation context establishes trust or authority.

The immutable input to `f0(readbuf, mutbuf, mutbuf) -> u32` is
`CCH1 context prefix (141) || max reads BE64 || max bytes BE64 ||
expected complete CCH1 (213) || mode byte || complete declaration`.
Mode 0 is TCM2; mode 1 is TCC2. No host result is imported.
The declared contents, proof/authorization, storage and release rules
are not evaluated.

The native owner checks the canonical declaration, then decodes the complete
expected CCH1. It validates the independent ModelManifest observation context
and the pure fresh read/byte allowance using the same validated hash owner as
[TCM2](CELL_CONTENT_MANIFEST_OBSERVE.md) and [TCC2](CELL_CONTENT_CLOSURE_OBSERVE.md).
It computes the original SHA-512 over the domain, freshly derived CCH1 header
and supplied declaration bytes. Verification compares all original typed
context fields, the exact observed declaration length and all 64 digest
bytes. No external reader or persistent budget is created.

Success returns 0 and leaves the entire output untouched. Code 38 is the
original typed claim mismatch, not a syntax error. Expected claim encoding
and invalid expected context report 36 and 37. Declaration, observation,
frame and buffer refusals preserve the original shared status classes.
The hash requires 131,232 bytes of private scratch; a valid comparison with
too little scratch returns 102. There is no output-size requirement and
no comparison result publishes bytes to output. Scratch is private working
state and may contain the computed digest even for mismatch.

Qualification executes the actual unchanged locked Rust public declaration
observer and `expected.verify(&observed)` with deterministic inert fixtures,
both pinned stock native backends, and independent SHA-512 checks. There are
no payload/dependency readers, owner budgets, custody, cache, store,
network, auth or production operations.
