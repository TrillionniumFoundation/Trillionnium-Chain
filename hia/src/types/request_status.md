# Request status

[request_status.hepta](request_status.hepta) implements every explicit public
operation in the original [request_status module](../../../trillionnium/crates/trnm-types/src/request_status):
`RequestStatus::parse`, `as_str`, `is_terminal`, `can_transition_to`, `transition`,
both `Display` implementations and `RequestStateError::stable_code`.
All seven variants and all 49 transition pairs retain their original meaning.

The parser uses the existing Oracle Unicode trimming functions and the shared
UTF-8 validator. It trims exactly Rust's Unicode White_Space characters, changes
ASCII space and hyphen to underscore, and folds ASCII case only. Unknown-state
errors retain the trimmed input with its original spelling and separators.
The two stable error codes and complete error messages match the original.

## Native interface

The exported entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. Its input is a local
value envelope, with all integer fields little-endian:

| Offset | Field |
| --- | --- |
| 0 | Four bytes `RQS1` |
| 4 | Operation, one byte |
| 5 | Source state ID, one byte |
| 6 | Target state ID, one byte |
| 7 | Reserved zero byte |
| 8 | Body byte length, u64 |
| 16 | Exact body bytes |

| State ID | Original variant | Canonical display |
| --- | --- | --- |
| 0 | `Open` | `OPEN` |
| 1 | `Assigned` | `ASSIGNED` |
| 2 | `CommitQueued` | `COMMIT_QUEUED` |
| 3 | `RevealSubmitted` | `REVEAL_SUBMITTED` |
| 4 | `Rejected` | `REJECTED` |
| 5 | `FailedAdapter` | `FAILED_ADAPTER` |
| 6 | `FailedSubmission` | `FAILED_SUBMISSION` |

Operation 0 parses the complete body as a Rust string; source and target must
both be zero. Operation 1 observes the source value and requires a zero target
and empty body. Operation 2 evaluates the source-to-target transition and
requires an empty body. Numeric IDs outside 0–6 are malformed local inputs.

A successfully executed request returns zero and writes this result:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `RQSR0001` |
| 8 | Result variant, u64: 0 state, 1 unknown state, 2 invalid transition |
| 16 | Source state ID, u64 |
| 24 | Target state ID, u64 |
| 32 | Flags, u64: bit 0 source terminal, bit 1 transition allowed, bit 2 target terminal |
| 40 | Display byte length, u64 |
| 48 | Error input byte length, u64 |
| 56 | Stable error code byte length, u64 |
| 64 | Display, error input and stable error code bytes, in that order |

For a parsed or observed state, source and target are identical. Unknown-state
results use 255 for both IDs, zero flags, and retain the complete trimmed input.
Invalid-transition results retain both actual IDs, the terminal flags, the
original `Display` text and `RequestStateInvalidTransition`. Semantic errors
are values in this result, not successful transitions.

Return 100 rejects malformed envelopes or numeric values. Return 101 rejects
invalid UTF-8 before entering the Rust-string domain. Return 102 reports
insufficient output space. Every such refusal preserves the complete output;
successful writes preserve its suffix. Scratch is unused and unchanged. No
artificial string length ceiling is introduced: available buffer extents are
the limit, and doubled unknown-state output is checked without overflow.

## Qualification

[test_request_status.py](../../tests/test_request_status.py) runs the emitted
native artifact, the unchanged original `trnm-types` library through
[rust_request_status_reference.rs](../../tests/rust_request_status_reference.rs),
and all seven original request-status unit tests. The comparison corpus has
1,242 observations. Further controls cover the complete transition matrix,
all 25 Unicode whitespace characters on both sides, unknown input preservation,
ASCII-only normalization, invalid UTF-8, all invalid byte-sized state IDs,
every insufficient output size, long strings and native-result-driven transitions.

The original library is compiled with the locked Cargo graph. CI may provide
`TRNM_HIA_RUST_TYPES_RLIB` from the actual Cargo compiler-artifact event; when
absent, the test builds that library itself with `cargo build --locked --offline`.
Missing dependencies or a failed original run fail the test. The original source
bytes are checked again after execution.

```bash
python3 -B -m unittest hia.tests.test_request_status -v
```

The [native guide](../../README.md) supplies the pinned HIA compiler environment.
This component implements the explicit value methods. Generic Serde provider
integration, all other `trnm-types` modules, queue ownership and durable Node
consumption retain their own migration requirements.
