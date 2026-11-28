# Native local resource request value

The private `resource_request.hepta` helper implements the frozen original
`ResourceRequestV1::{validate,total}` relation from
`trnm-pon-node/src/resource_owner_v1.rs`. It returns the execution-plus-cleanup
amounts only after the original validation succeeds. Call
`f0(input, output, arena)` with live, disjoint, caller-owned spans.

This is **not** a reservation. The helper does not validate an actual deadline
against a clock, authenticate a parent state or recovery target, issue an
operation binding, or inspect available principal. No Node, journal, filesystem,
network, admission or completion owner participates.

## Private typed frame

The input is exactly 184 bytes. Multi-byte integers are little-endian.

| Offset | Bytes | Value |
| ---: | ---: | --- |
| 0 | 8 | `NRRQ0001` |
| 8, 40, 72 | 32 each | Operation ID, request digest, parent state |
| 104 | 8 | Deadline value |
| 112 | 1 | Class: bootstrap 0, committed 1, recovery 2 |
| 113 | 1 | Recovery link: absent 0 or present 1 |
| 114 | 6 | Zero, reserved |
| 120, 136 | 16 each | Execution and cleanup, each CPU nanoseconds then I/O bytes |
| 152 | 32 | Recovery target; zero padding if absent |

The absent-frame padding is transport metadata, not a semantic check on a
present link. A zero parent state or a present zero link is not validated by
the selected original relation and is therefore not rejected here.

| Status | Result |
| ---: | --- |
| 0 | Exact two u64 totals in the first 16 output bytes |
| 1 | Malformed private frame |
| 2 | Otherwise valid value but output shorter than 16 bytes |
| 32 | Original `RESOURCE_OWNER_BINDING` |
| 33 | Original `RESOURCE_OWNER_UNITS` |
| 34 | Original `RESOURCE_OWNER_RESERVATION` |
| 35 | Original `RESOURCE_OWNER_RECOVERY_LINK` |

The original first checks the operation ID, request digest and nonzero
deadline. Individual amounts must remain within 2^60, and both execution
and cleanup CPU must be nonzero; I/O can be zero. The componentwise sum
cannot overflow u64 after the original individual bounds and must itself
remain within 2^60. Recovery class then requires a present link; the other
two classes require absence. These checks preserve original error precedence.
Refusals leave all mutable bytes unchanged. Success changes only the 16-byte
output prefix and never uses the arena.

The [differential](../../tests/test_node_resource_request.py) compiles the
hash-pinned, unchanged Rust method bodies, declarations (omitting Serde-only
attributes), and string-error helpers in a std-only process. That process
exchanges typed test cases over pipes and never calls an owner. Both the
Direct and Selfhost native implementations are checked, including exact
totals, failure order, and untouched output/input/arena bytes.
