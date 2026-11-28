# Original RootRecovery V3 policy and bootstrap values

The private byte entry in `root_recovery_checkpoint_v3.hepta` takes an
unaltered 64-byte scope and eight-byte big-endian Unix time, followed by the
original custom `RootPolicyV3` encoding. It admits the policy and fixed
dual-family roster from the same immutable input: complete wire rules,
ML-DSA-87 and SLH-DSA-SHA2-256s SPKI shape, original per-key SHA-512 identities,
duplicate refusal and the canonical family/identity ordering. It uses the
original typed policy expiry and bootstrap scope checks. Time equal to the
exclusive expiry is a refusal.

Success returns the two original 64-byte SHA-512 values from
`RootPolicyV3::commitment` and `RootStateV3::bootstrap(...).checkpoint()`.
The latter uses generation one, sequence zero, the exact validated policy,
the supplied scope and time, and three empty collection counts. It does not
accept a host-provided policy digest or bootstrap-state encoding. Output
requires 128 disjoint bytes and scratch requires 132,256; no refusal writes
any output. Tests run the unchanged locked original release and crypto
primitive crates on generated inert SPKI bytes, then compare Direct and
Selfhost byte results.

This is a value-only bootstrap projection. No key expansion or signature
verification, actual root authority, operator controls, nonempty state,
recovery effects, external writes or production routing are moved.
