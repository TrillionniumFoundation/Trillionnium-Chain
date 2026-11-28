# Immutable TCA3 outer term predicates

This diagnostic ports only the original typed configuration and scalar
outer-term predicates. It is **not** a TCA3 decoder, whole-contract
validation, commitment, owner, or retention decision.

The bounded input begins with `NVT30001` followed by store ID (as an
opaque value); unsigned big-endian u64 capacity, u32 obligations, u32
versions, and u64 metadata limit; four opaque 32-byte outer declarations
(operation, funding operation, owner and failure domain); big-endian u16
replica index and count; and big-endian u64 start, end, and repair heights.
The optional snapshot flag is at offset 220. Zero ends the 221-byte frame.
One adds a 32-byte schedule, big-endian u64 ordinal and due height,
and two 32-byte predecessor declarations. That frame is 333 bytes.
Both mutable arguments are ignored and remain unchanged.

The original predicates are applied in their relative order: arena
configuration, version configuration, four nonzero IDs, replica terms,
half-open retention and repair interval, then optional snapshot fields
and self-predecessor inequality. Number zero means **these selected terms
only**, never the whole contract. The test's original oracle uses a
model/environment pair, two tiny declared manifests, correct pins and
an ordered typed object roster constructed in memory. It invokes only
unchanged public `validate`, not a loader or store, and separately
records original failures that occur after these selected predicates.
No actual identity, capacity allocation, obligation, funding,
snapshot or owner action occurs.

A complete one-loan TCA3 path remains separate: the two declared pins
must be bound to their canonical TCV1 model/environment closures,
with independent byte/chunk/required-role bounds; optional TMA1 must
match the same model root; the ordered object manifests must match
exact nested TCM1 bytes; the original two identity sets need uniqueness
and cross-alias checking, exact term coverage, alignment and capacity
accounting, with unchanged precedence. Existing standalone metadata
and digest owners are useful inputs but do not jointly prove those
relations. This entry emits no digest and must not be treated as such.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_retention_outer_terms
```
