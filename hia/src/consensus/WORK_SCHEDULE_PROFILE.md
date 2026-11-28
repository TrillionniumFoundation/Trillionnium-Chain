# Native research work-schedule profile ID

The private `trnm_consensus_work_schedule_profile_v1` entry implements the
immutable metadata validation and ID of the original Rust
`research_work_schedule::Profile::new(inputs).id()`.

Call `f0(input, output, arena)` with disjoint caller-owned spans. The input is
exactly 202 bytes for fixed policy or 218 bytes for anchored ASERT:

| Offset | Field |
| ---: | --- |
| 0 | Eight bytes `NWSP0001` |
| 8, 40, 72 | Network, parameters, and genesis, each 32 bytes |
| 104, 136 | Initial target and limit, each 32 unsigned big-endian bytes |
| 168, 176, 184, 192 | Genesis time, legacy interval, spacing, and future skew, each u64 little-endian |
| 200 | Native wire byte: PNH1 = 1, PGH2 = 2 |
| 201 | Policy byte: fixed = 0, anchored = 1 |
| 202, 210 | Anchored only: activation height and half-life, each u64 little-endian |

The component checks nonzero ordered targets, inclusive interval range
16..4096, nonzero spacing, and the original checked `(interval - 1) *
spacing * 4` bound. The anchored variant also requires activation height
1..4095 and a nonzero half-life. The canonical ID is the existing PoN
domain hash with tag `pon-branch-work-schedule-research-v1` and a single
serialized part. That part omits the private frame tag and inserts the
native constant 4096 as u64 LE at byte 192, immediately before the wire byte.

Status 0 returns 32 digest bytes into the output prefix; remaining bytes
are untouched. Status 1 is an untyped frame, 32 is original
`SCHEDULE_PARAMETERS`, 2 is an undersized output, and 3 is an undersized
arena (requires 132256 bytes for the existing SHA-256 implementation).
The native defensive internal status is 255. No refusal publishes output;
shape, semantic and span refusals do not write the arena either.

This is not a node profile binding, header or branch-state verifier, proof
of work, network admission, or a change to any active difficulty policy.
