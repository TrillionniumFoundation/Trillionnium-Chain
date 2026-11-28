# Standalone native research ASERT target

This entry implements the exact integer target from
`trnm_pon_node::research_work_schedule::asert_target`. It retains full raw target
bytes; it does not round to Bitcoin compact nBits. It is separate from both
legacy retargeting and research history validation. It does not run a proof
search, set work policy, admit a branch, mutate a node, or supply work credit.

The private borrowed-buffer interface is
`f0(readbuf input, mutbuf output, mutbuf scratch) -> u32`, over disjoint buffers.
The 112-byte input has an eight-byte `NASA0001` marker, 32-byte big-endian
anchor and limit, a two's-complement i128 little-endian time delta, and U64
little-endian interval count, interval spacing and half-life in that order.
Success writes the first 32 output bytes in big-endian order. Refusal never
writes output, and the suffix beyond the first 32 bytes is never touched.
Scratch needs 768 bytes; its suffix is untouched. Bad framing and short
scratch are refused before mutation. A well-formed semantic error precedes
a short-output error.

| Result | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Wrong local extent or marker |
| 2 | Local output capacity |
| 3 | Local scratch capacity |
| 32 | Original `SCHEDULE_ASERT_PARAMETERS` |
| 33 | Original `SCHEDULE_ASERT_I128_RANGE` |

Signed intermediates use sign and magnitude over existing native Work
digits. The positive product has the original i128 range, and multiplying the
signed difference by 65,536 admits exactly the negative edge -2^127. The
signed division truncates to zero before Euclidean decomposition of the
result. The maximum 16-bit fractional polynomial including its rounding term
fits u64; the subsequent Work multiplication, bounded bit shift, and clamps
retain all target bits. This is testable arithmetic, not a timing or network
qualification.

The differential adapter links the actual unchanged original Node library
built with locked Rust dependencies, then calls the public method for the
retained 18 BCH-compatible numeric fixtures, boundary cases and ordinary
seeded numerical cases. Both pinned native emitters must match its outcomes
and output canaries.
