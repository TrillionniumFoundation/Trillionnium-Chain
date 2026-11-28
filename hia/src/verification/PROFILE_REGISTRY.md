# Closed verification profile registry

The native component implements the original
[`VerificationProfileRegistryV1::closed` and `resolve_exact`](../../../trillionnium/crates/trnm-verification-profiles/src/lib.rs)
over a private, borrowed table. It runs the actual per-profile validation,
duplicate-kind and duplicate-`(profile_id, version)` checks, closed roster
requirement, then exact lookup. It does not silently fall back to another
profile, version, or evaluator. An admitted lookup returns the selected
unchanged typed row. The length and empty values are also observed.

This is an immutable in-process representation, not a wire protocol or a
persistent provider registry. No signatures, payments, challenges, resolver
backend calls or Node/production activation are performed.

## Private VPR1 argument

Integers are little-endian. The prefix is exactly 92 bytes: magic
`VPR1`, u32 operation (0 = close only, 1 = close and resolve), u64 row
count, a 32-byte query identity, u32 query version, 32-byte expected
hash, and u64 query height. Closing alone does not inspect query fields.
The exact suffix is the input-ordered sequence of 97-byte rows.

Each row contains a 32-byte identity, 32-byte profile hash, u32 version,
u64 first valid height, u64 expiry, u64 revocation, and five one-byte
fields: kind, enabled, expiry presence, revocation presence, objective
settlement allowed. Valid kind tags are `0,1,2,3,5,6`; booleans are
`0,1`. An absent option has zero payload, while `Some(0)` is distinct.
Both height values and versions preserve their full original widths.

The private framing admits at most 64 input rows. This is not a Rust
registry limit: the closed registry can have only the six specified
kinds, and any well-typed input of seven or more rows must reach its
first validation or duplication failure by row seven.

## Results

Original policy order is preserved for representable typed inputs:
nonzero identity/hash, nonzero version, valid ranges, subjective
objective-authority refusal, duplicate kind, duplicate identity,
then incomplete roster. Lookup checks exact identity/version, hash,
enabled, first valid height, expiry and revocation in order. Expiry
is inclusive; revocation takes effect at the stated height.

Status codes 1–13 are mapped in the exact Rust differential. Code
100 is malformed private framing, and 102 is insufficient result
capacity. Success writes `[len=6, is_empty=0, 0, 0]`, then the 97-byte
selected row for a lookup. No added scratch bytes or partial output
are written on any outcome; output suffixes remain caller-owned.

The [original differential](../../tests/test_verification_profile_registry.py)
compiles the exact unchanged Rust declarations and methods with pinned
Rust and no Cargo dependencies. Both pinned native emitters replay
all 720 permutations, 80 seeded cases, explicit compound first-error
rows and malformed/capacity controls. This tests the profile registry
boundary, not the separate statement, evidence, backend or challenge
lifecycles.
