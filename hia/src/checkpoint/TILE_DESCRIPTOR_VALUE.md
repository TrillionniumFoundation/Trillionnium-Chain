# Private inert tile descriptor serialization

TDV1 serializes bounded immutable, caller-provided metadata to the compact
lexicographically sorted JSON used by the original typed Rust serializer.
It does not validate descriptor values, construct a task, or verify
numeric material, provenance, demand, training, or authority.
The five Boolean fields are always false and consume no input bytes:
`chain_authority`, `full_forward_verified`, `genuine_demand_verified`,
`hardness_accepted`, and `marginal_contribution_accepted`. The
`matrix_task` field is opaque ASCII text, not a work computation,
authorization, or validated witness.

The private typed frame starts with `TDV1\0\0\0\0`. Fields follow
the output key order (see the fixed schema in the frozen differential).
Text is a u64 little-endian length followed by 0–256 ASCII bytes;
integers are eight little-endian bytes, with original u8 fields range
checked, original usize treated as the pinned x86-64 u64, and i64 using
two's complement. A coordinate or shape pair holds two u64 words. The
frame is exactly consumed and must not exceed 4,096 bytes. This bound
does not cover arbitrary original Unicode or string lengths.

On success the output is u64 little-endian JSON length then exactly
those JSON bytes. Output capacity is checked before publication. Shape
failure (100) or insufficient scratch/output (102) never changes public
output. Scratch must be at least 32,776 bytes; it is private and can
change on failure. The typed input caps keep the largest possible
escaped output below the original 32 KiB descriptor writer's limit.

The differential calls the unchanged original `canonical_descriptor_observed`
on actual typed records with an inert test-only progress callback. The
native entry invokes no observer and is not a descriptor admission step.
