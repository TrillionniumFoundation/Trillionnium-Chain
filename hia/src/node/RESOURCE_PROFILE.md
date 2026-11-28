# Native local resource profile value

This private helper mirrors the original typed
`trnm_pon_node::resource_owner_v1::ResourceProfileV1::{validate,id}` without
opening a node, starting an owner, taking a reservation, or charging resources.
Call `f0(input, output, arena)` with disjoint, caller-owned spans.

The 128-byte input is fixed:

| Offset | Field |
| ---: | --- |
| 0 | Eight bytes `NRPF0001` |
| 8 | 32 raw owner ID bytes |
| 40, 56, 72 | Three pairs of u64 LE CPU nanoseconds and I/O bytes: bootstrap, committed, recovery |
| 88, 92, 96 | Three u32 LE operation-slot maxima |
| 100, 104, 108 | Three u32 LE in-flight maxima |
| 112, 120 | u64 LE overshoot CPU nanoseconds and I/O bytes |

The original order is owner ID, each lane's unit bounds, each lane's
nonzero grant and its slot validity plus checked u32 accumulation, final
slot maximum (1024), overshoot bounds, and nonzero overshoot CPU. Units
are bounded by 2^60, and each lane has 1..16 in-flight slots no greater
than its operation maximum.

Status 0 writes only the 32-byte original ID. The preimage is ASCII
`pon-local-resource-owner-v1` directly followed by the original compact
Serde JSON of the validated structure, in field order; there is no colon,
NUL or length delimiter between domain and JSON. The caller's semantic
input includes typed values only, no supplied JSON or digest.

Returns 32 for original `RESOURCE_OWNER_ID`, 33 for
`RESOURCE_OWNER_UNITS`, 34 for `RESOURCE_OWNER_GRANT`, 35 for
`RESOURCE_OWNER_SLOTS`, and 36 for
`RESOURCE_OWNER_OVERSHOOT_REQUIRED`. Malformed private frame is status 1,
short output is 2, and short SHA arena is 3 (minimum 132256 bytes).
All listed refusal codes leave the output and arena unchanged; an
unexpected internal hash failure returns 255 and publishes no output.
Only the output ID is a result; arena contents are caller-owned transient
working bytes, observed during differential testing.

This value is not proof of resource access or a replacement for the
actual journal/accounting/admission owner.
