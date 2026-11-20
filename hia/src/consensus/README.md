# Native M02 Work, target and time policy

`work.hepta` implements the complete pure consensus arithmetic and time-policy
closure in the original `trnm-pon-node/src/consensus.rs`. Its HIA instructions
execute directly in an artifact emitted by the pinned self-hosted compiler.
The module provides checked 512-bit work arithmetic, target conversion and work
credit, bounded retargeting, checked parent-window selection and median-time
admission. Original error identities and their ordering are retained.

The owning Node uses these operations before admitting or selecting a branch.
Database ownership, ancestry authentication, work verification, publication,
reorganization and consensus security remain separate integration gates.

## Public byte interface

The export is `f0(readbuf input, mutbuf output, mutbuf scratch) -> u32`.
The buffers are disjoint, private borrowed regions. Input starts with the eight
ASCII bytes `NCWV0001`, followed by a `u64le` operation. Numeric counters and
lengths use little endian; original Work and target byte arrays retain their
original big-endian representation. The format is a new local HIA ABI and does
not change a signed wire, stored schema or network domain.

| Operation | Payload after the 16-byte header | Successful output |
| --- | --- | --- |
| 0: checked add | Two 64-byte Work values | 64-byte Work |
| 1: checked subtract | Two 64-byte Work values | 64-byte Work |
| 2: multiply by small integer | 64-byte Work, factor `u64le` | 64-byte Work |
| 3: divide | 64-byte numerator, 64-byte divisor | 64-byte quotient |
| 4: required work | 32-byte target | 64-byte Work |
| 5: retarget | 32-byte parent target, 32-byte limit, first/last/interval/spacing as four `u64le` | 32-byte target |
| 6: checked target conversion | 64-byte Work | 32-byte target |
| 7: compare | Two 64-byte Work values | `u64le`: 0 less, 1 equal, 2 greater |
| 8: target to Work | 32-byte target | 64-byte Work |
| 9: branch target window | Parent height, interval and count as three `u64le`; then count records `(timestamp:u64le, target:32 bytes)` in parent-first order | 56 bytes: kind `u64le`, target 32 bytes, first and last `u64le` |
| 10: time admission | Candidate, now, skew and count as four `u64le`; then count `u64le` ancestor times in parent-first order | No output bytes |

Window kind 0 is the original `TargetWindow::Parent`; its unused first/last
output words are zero. Kind 1 is `Retarget`. The parent target always comes from
the first history record. A retarget window takes `first` from record
`interval - 1` and `last` from record 0. The input must contain exactly the
declared bytes, including history records that the selected policy does not use.
There is no fixed history-count limit beyond the supplied input extent. Count
validation divides the available byte extent before any multiplication, avoiding
wraparound in a malformed length claim.

Every operation needs at least **768 scratch bytes**. Bytes after that prefix
remain untouched. A successful call writes exactly the output extent in the
table and preserves the output suffix. Every refusal leaves all output bytes
unchanged. Malformed framing and insufficient scratch are refused before scratch
mutation; a semantic or output-capacity refusal can modify the private scratch
prefix. Input is read-only throughout. This is a stateless operation: no context,
borrow, work credit or authority survives return.

| Status | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Local frame/version/operation/extent refusal |
| 2 | Local output capacity, checked after original semantic errors |
| 3 | Local scratch capacity |
| 16 | Original `CHAINWORK_OVERFLOW` |
| 17 | Original `CHAINWORK_UNDERFLOW` |
| 18 | Original `DIVISION_BY_ZERO` |
| 19 | Original `TARGET_OVERFLOW` |
| 20 | Original `TARGET` |
| 21 | Original `TARGET_PARAMETERS` |
| 22 | Original `HEIGHT` |
| 23 | Original `UNKNOWN_PARENT` |
| 24 | Original `TIME` |
| 25 | Original `TIME_DEFERRED` |

Frame/capacity statuses describe this local borrowed-buffer ABI. The original
Rust API has no equivalent borrowed scratch argument. Original error codes are
compared only after a well-formed HIA frame has been admitted.

## Arithmetic construction

The private arena holds six Work values at offsets 0, 128, 256, 384, 512 and 640.
Each uses sixteen base-2^32 digits, with the least significant digit first and
each digit stored in a `u64le` slot. Public inputs are decoded inside HIA.
Bytewise loads and stores require no alignment assumption.

Addition propagates the carry of a sum bounded by `2^33 - 1`. Subtraction
propagates a one-bit borrow and retains the low 32 result bits. The checked
entry compares the full Work values before subtraction; the same modular
subtractor is reused by division. All 512 result bits are represented.

The multiplier is split into two 32-bit digits. The lower pass propagates
`x[i] * factor_low + carry`; the shifted upper pass propagates
`x[i] * factor_high + existing_digit + carry`. The latter is at most
`(2^32 - 1)^2 + 2(2^32 - 1) = 2^64 - 1`, so the HIA u64 operation is exact.
A nonzero final carry or discarded upper product produces the original overflow
error before any output is written.

Division uses restoring long division over all 512 numerator bits. At each step
it shifts the private remainder, compares against the complete divisor,
subtracts when required, and writes that quotient bit. The remainder's shifted
carry is explicit, and subtraction is modular at 512 bits. The loop invariant
is the already processed numerator prefix equals `quotient * divisor + remainder`
with `0 <= remainder < divisor`. Division by zero is checked before the loop.
This algorithm is independent of the original aligned-divisor implementation,
which makes their actual differential useful beyond a transcription check.

Required work is exactly `floor(2^256 / (target + 1))` for a nonzero target.
The 512-bit representation handles the denominator for target `2^256 - 1`.

Retarget first checks `interval >= 16`, positive spacing, a nonzero parent and
`parent <= pow_limit`. It separately checks both original u64 products,
`desired = (interval - 1) * spacing` and `4 * desired`, before adjusting work.
Observed time uses saturating subtraction, a minimum of one, and the original
`[ceil(desired/4), 4*desired]` clamp. The exact quotient is clamped to the range
`[1, pow_limit]` before conversion to a 256-bit target.

## Parent and time policy

Window selection checks parent-height successor overflow before examining
history, checks missing history before zero interval, and reads an interval
boundary only when the checked successor height is a multiple of the interval.
It preserves the original separation between choosing a target window and
validating retarget parameters. The executed target is Linux x86-64, matching
the locked HIA target and original adapter's `usize` width.

Time admission uses only the first eleven ancestors, sorts those actual u64
values in HIA, and selects the original upper median for even short windows.
A candidate must be strictly greater than the median. That `TIME` error precedes
`TIME_DEFERRED`. The future-time comparison retains overflow from `now + skew`,
which is equivalent to the original u128 sum for two u64 inputs; it does not
truncate or saturate a valid upper bound to a smaller value.

## Qualification

The six methods in `hia/tests/test_consensus_work.py` execute the source through
the repository's isolated emitted-machine runner. They cover the 158 retained
integer vectors, every one of the 512 quotient positions, wide random and
boundary arithmetic, target/window/time policy, error precedence, exact and
short buffers, malformed lengths, truncation, suffix preservation and immutable
inputs. Python arbitrary-precision integers are an independent test oracle.
No Python arithmetic or supplied verdict participates in the native program.

`test_actual_original_consensus_module` is mandatory. It inserts the **complete
unchanged original module bytes** at the single source marker in
`rust_consensus_reference.rs`, compiles that separate test binary with `rustc`,
and calls the original functions. Two small wrappers expose the actual private
division and window functions without copying their algorithms. The original
source hash is compiled into the reference and checked on readback; the original
and adapter bytes are checked again after execution. A missing compiler,
compilation failure, missing observation or mismatch fails the test.

Run the complete suite, with the repository's three pinned HIA build environment
variables set and a real Rust compiler available:

```sh
python3 -B -m unittest hia.tests.test_consensus_work -v
```

The initial local native run passed five methods and 6,308 actual calls. A
separate operator-host Rust 1.95 compiler subsequently built the unchanged
original module and executed the same 5,344 semantic inputs; every result
matched the independent oracle also checked by HIA. The retained development
record binds both original source and adapter hashes, input and output digests,
compiler and artifact. The exact-head hosted method still runs its direct
original/native comparison as a mandatory test. The common qualification report
binds every HIA source, adapter, test, original module, vector file and artifact.
