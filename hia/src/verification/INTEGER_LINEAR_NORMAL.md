# Integer-linear normal report

`integer_linear_normal.hepta` emits the exact canonical JSON returned by
`CheckedIntegerLinearUpdateV1::normal_bytes` in
[`exact_integer_linear_v1.rs`](../../../trillionnium/crates/trnm-verification-profiles/src/exact_integer_linear_v1.rs).
This is a **reporting** component. Its inputs are an opaque caller-supplied
contract ID and an already-computed, typed integer matrix. It neither derives
the ID nor checks whether the matrix or ID comes from a verified update. In
particular, it does not replace the Rust formatter's internal fingerprint
caller, verify factors, authenticate a model, or participate in admission,
state changes or production execution.

## Local argument and result

The entry is `f0(readbuf input, mutbuf output, mutbuf scratch) -> u32`.
The caller provides separate, nonoverlapping input and output buffers and
keeps the input unchanged during the call.

| Input offset | Extent | Meaning |
| --- | ---: | --- |
| 0 | 4 | Exact ASCII `ILN1` local tag |
| 4 | 4 | Four zero reserved bytes |
| 8 | 32 | Opaque contract ID, emitted as 64 lowercase hex characters |
| 40 | 3,084 | Three rows of 257 signed little-endian i32 coordinates, each in `[-32767, 32767]` |

The exact input extent is **3,124 bytes**. The local encoding is not a signed
domain, a stored schema, proof of validity, or a replacement Rust API.

| Return value | Meaning | Write effect |
| --- | --- | --- |
| 100 | Wrong extent, tag or reserved bytes | None |
| 101 | At least one coordinate is out of bounds | None, even if the output is too short |
| 102 | Valid frame and coordinates, but insufficient output | None |
| 1,680–5,535 | Exact serialized byte count | Only that prefix of the output |

The first pass checks all 771 coordinates and adds their decimal widths
(including signs) to the fixed 909-byte punctuation, contract and schema
overhead. It writes nothing. A second fixed traversal writes only after the
complete output extent fits. Its final input coordinate begins at offset 3,120
and reads through byte 3,123. Each coordinate emits one to six bytes; the
decimal divisor starts at at most 10,000 and is never zero. Input, output
suffix and all scratch bytes are unchanged, and no scratch bytes are required.
The successful output is UTF-8 JSON without a terminator or newline.

## Qualification

`hia/tests/test_integer_linear_normal.py` compares independently emitted direct
and self-hosted HIA images with the unchanged original Rust formatter, compiled
using the repository-pinned Rust. Only its external SHA dependency is adapted
to system `sha256sum` for this isolated build; the original module and formatter
are not rewritten. A test-only adapter inside that module can provide typed
matrices for formatting without fabricating a public verified witness.

The tests also run the unchanged named
[`integer_linear_normal_form`](../../../trillionnium/crates/trnm-verification-profiles/examples/integer_linear_normal_form.rs)
example on three lawful local rank-one fixtures. Actual original `run` still
calls the original verifier and prints its result; only the exact `normal`
field is compared with the HIA output. This establishes a candidate seam for
the example's presentation call, not a replacement of that call or of any
production path. Tests cover signed extrema, all decimal width transitions,
row boundaries, an invalid final coordinate, short capacity after full
validation, reserved/framing refusals and byte-for-byte canaries.
