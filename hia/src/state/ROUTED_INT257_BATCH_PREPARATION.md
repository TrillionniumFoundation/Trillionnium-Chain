# Private Int257 preparation and input commitment

This candidate mirrors the deterministic portion of the unchanged Rust
`PreparedModel::prepare_batch` with an explicit synthetic `now_ns`.
It checks only the numerical window. It has no actual clock, trusted
model identity, application admission, statement output, proof, or W1.

The three disjoint `f0` loans are input, output, and scratch. Its private
input is:

- LE32 count; LE64 now; the 32-byte model commitment as ordinary data.
- Four verbatim 32-byte context fields: chain, parent, challenge, batch ID.
- One 1108-byte row per request: ID and scope (32 bytes each); LE64
  arrival and deadline; 257 consecutive signed LE32 coordinates.

First require exact framing, then count 1–64. For each row in source order,
reject an ID repeated in any earlier row, then a bad time window
(`arrival < deadline`, `arrival <= now < deadline`), then any coordinate
outside [-8,8] or last coordinate not 8. Refusals 4/5/6/7 are batch size,
time window, duplicate ID and range/bias, respectively. Duplicate checking
needs no mutable state or scratch, and is bounded by 2016 fixed-width
comparisons. Private framing (100) and insufficient capacity (102) are
not Rust errors. All these refusals preserve source, result, and scratch.

On success, scratch requires exactly 1498 + 2136*count bytes. At offset
1208 it holds the full original `trnm.domain.hash.v1` transcript, framing
`pon-routed-int257-grouped-input-v0`, the original research profile, the
32-byte model digest, and a body. The body is verbatim context + BE64
count, then request ID/scope, BE64 arrival/deadline and sign-extended
BE64 coordinates. It excludes `now_ns`. The 32-byte result is published
only on hash success. The fixed common maximum is 71,084 bytes of input,
138,202 bytes of scratch. Neither output tail nor scratch tail is written.

The differential builds the frozen locked crate. Public `prepare_batch`
provides exact status; as there is no public prepared-batch digest access,
the fixed isolated original `observe_direct` supplies only its actual
`input_commitment` on accepted synthetic data. No native or fixture
statement is exposed. Both frozen emitters are checked against original
statuses, digests, and an independently reconstructed entire transcript.
