# Bench decimal and environment candidates

These components continue the [Bench migration](README.md). They implement text
conversion and the effective configuration consumed by the existing native
scheduler. An allowlisted byte selector also accepts a supplied ordered startup span. The
original Bench package remains required; none of these components reads a live
process environment, parses CLI arguments, acquires clocks or owns persistence.

## Exact finite decimal conversion

[`decimal.hepta`](decimal.hepta) accepts raw, untrimmed decimal bytes through
`f0(readbuf, mutbuf, mutbuf) -> u32`. Output needs 8 bytes and scratch needs
`8192 + input_bytes`; size arithmetic is checked first. The output is the exact
binary64 bit pattern in little-endian order. Successful conversion returns 0;
invalid decimal grammar or a nonfinite result returns 1; insufficient capacity
returns 100. Capacity refusal changes neither mutable buffer. Syntax refusal
leaves output unchanged but may use private scratch. Output tails remain intact.
This is the finite conversion used inside the original environment getter;
`NaN` and infinity spellings do not become accepted configuration values.

All production arithmetic is HIA integer arithmetic. The parser recognizes the
optional sign, digits and decimal point, and optional signed exponent. It builds
an exact rational numerator/denominator using 128 base-2^32 limbs, each kept in a
64-bit cell. It finds the binary exponent, forms the normal or subnormal quotient,
and compares twice the remainder with the denominator. Rounding is nearest with
ties to even. Signed zero, gradual underflow, carry into the next exponent, and
overflow past the largest finite number are explicit paths.

At most the first 800 significant decimal digits are accumulated. Every remaining
input byte is still checked; a nonzero discarded digit sets a sticky bit. This
bound covers every finite binary64 rounding boundary: its exact decimal expansion
has at most 768 significant digits. A discarded suffix can therefore only change
an exact halfway tie in the retained prefix; it cannot conceal a boundary inside
the interval represented by that prefix. The sticky bit changes a tie upward in
magnitude, including the half-minimum-subnormal boundary. Arbitrarily long leading
zeros and exponents are still scanned and validated. Positive/negative exponent
accumulation overflow is handled without wrapping into a plausible small value.

The exponent range retained for big-integer work is bounded by the decimal order
and 800-digit prefix. Three 4096-bit work arrays suffice for the exact numerator,
denominator and shifted divisor; no heap allocator or floating-point host call is
used. Scratch 4096..8192 is excluded from the parser workspace so the environment
owner can retain its live configuration there. The input copy starts at 8192.

## Environment byte interface

[`environment.hepta`](environment.hepta) uses the same borrowed three-buffer ABI.
Its input is `BENV0001`, twelve little-endian u64 lengths, then the present values
concatenated in the order below. Length `UINT64_MAX` means missing and consumes no
payload; length zero means present but empty. The header is 104 bytes. The frame
must end exactly after its declared values. Embedded NUL is rejected because it
cannot represent an actual Unix environment value. Invalid UTF-8 instead follows
the original `std::env::var` failure path and selects that field's default.

| Input slot | Original variable | Effective value |
|---|---|---|
| 0 | `TRNM_AGGR_DEEP_SCAN` | Flag bit 0; default false |
| 1 | `TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS` | Flag bit 1; default true |
| 2 | `TRNM_AGGR_SCAN_ROUND_ROBIN` | Flag bit 2; default true |
| 3 | `TRNM_AGGR_SCAN_WINDOW` | Grouped unsigned integer, capped at 4096; default 0 |
| 4 | `TRNM_AGGR_SCAN_RR_SEED` | Grouped full-width unsigned integer; default 0 |
| 5 | `TRNM_HOT_BUCKETS` | Loose unsigned integer clamped to 4..64; default 8 |
| 6 | `TRNM_AUTO_MIN_BATCH_LEN` | Grouped unsigned integer clamped to 64..4096; default 512 |
| 7 | `TRNM_AUTO_SAMPLE_LEN` | Grouped unsigned integer clamped to 64..2048; default 2048 |
| 8 | `TRNM_AUTO_HOT_STREAK_RATIO` | Finite binary64 clamped to 0..1; default 0.22 |
| 9 | `TRNM_AUTO_REORDER_MIN_MARGIN` | Same; default 0.04 |
| 10 | `TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE` | Same; default 0.0075 |
| 11 | `TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE` | Same; default 0.01 |

Output requires 80 bytes: ten u64 words in scheduler configuration order: flags,
buckets, minimum batch, configured sample, window, seed, threshold bits, margin
bits, minimum hot-share bits, minimum gain bits. The sample word is the configured
limit; the scheduler applies `min(actual_batch_size, configured_sample)` at the
same point as the original algorithm. Output tails remain unchanged. Scratch needs
`8194 + total_input_bytes`, including two bytes of headroom for normalization.

Return codes are 0 success, 1 invalid frame/NUL, 2 magic, and 100 capacity. The full
frame and NUL check precede capacity checking. All those refusals leave output and
scratch intact. Parsing an individual invalid value is successful configuration
selection using its default. The owner first computes all ten words in private
scratch and only then writes the output.

## Unix startup byte selection

[`envp.hepta`](envp.hepta) accepts a supplied span of ordered Unix startup
entries separated by NUL, including the final entry's NUL. An empty span
represents no entries. No live environment, file or process is read.
Only the twelve listed names are eligible. A name matches exactly, including
case, and must be followed immediately by its first `=`. The first matching
entry wins, including a zero-length value or invalid UTF-8; a later valid
duplicate does not take its place. The rest of the selected entry is value
data, including any other `=`. Entries without `=`, empty names, unrelated
entries and name prefixes do not contribute to the result. Only selected values
enter the output.

The borrowed ABI `f0(readbuf, mutbuf, mutbuf) -> u32` returns a complete
`BENV0001` frame in the output prefix; compute its extent from the twelve
lengths as above. The output tail is untouched. The 192-byte scratch prefix
holds twelve private offset/length pairs and its tail is untouched. Return
code 1 is an unterminated nonempty input; 100 is insufficient capacity or
unrepresentable extent. In either case output is untouched. Frame failure
and inability to hold the fixed 104 output/192 scratch bytes precede all
writes. An output capable of holding the header but not the selected values
may have used private scratch before refusal.

The selector uses one forward scan, at most a constant twelve exact key checks
per candidate name and one copy of each selected value; there is no new value
or entry-count cap. Name comparison reads complete eight-byte pieces and a
bounded tail only after matching a known name length. Stored ranges are
disjoint subsets of the input; the total frame is at most input length plus
104, checked for representability before scratch is written. The caller
provides nonoverlapping borrowed buffers and is responsible for acquisition,
serialization and ownership of the source span.

[The differential](../../tests/test_bench_envp.py) starts the pinned Rust
reference via real Linux `execve` using only synthetic entries, preserving
duplicates and invalid UTF-8. It compares both separately built native
backends with the original `std::env::var_os` lookups byte for byte, then
passes the native frame through the canonical parser to compare all ten
effective words against the active executor's unmodified original getters.
This tests the startup projection on Linux x86-64, not a replacement startup
ELF, a platform-independent libc contract, or arbitrary environment capture.
The native Bench CLI and acquisition boundary are still open.

## Preserved text rules

The implementation calls the canonical strict HIA UTF-8 validator, trims exactly
the Rust Unicode whitespace set, removes at most one matched outer single- or
double-quote pair, and trims the resulting interior. Unmatched and nested quotes
are not silently discarded.

Toggles use ASCII case folding. Empty text or a string containing only underscores
and commas selects the field default. Exactly `0`, `false`, `off` and `no` disable;
any other nonempty value enables. Separators inside ordinary toggle text remain.

Loose unsigned integers remove underscores and commas. Grouped integers remove
underscores, require a nonempty first digit segment when commas are present, and
require each following segment to contain exactly three ASCII digits. The first
segment has no three-digit upper bound. Full-width overflow is refused before
multiplication. The actual original has two successive optional-plus removals on
its no-grouping path: its getter strips one plus and Rust's unsigned parser accepts
another. Consequently `++1` is accepted, while `+++1` is not; a grouped value such
as `++1,024` is refused by grouped getters but accepted by the loose getter after
commas are removed. This behavior is observed from the unchanged source, not
normalized away by the port.

Floating text removes underscores and handles the original comma rules exactly.
One comma is decimal or grouping according to the whole-part, zero-prefix and
three-digit checks. Malformed-looking single-comma scientific forms follow the
original fallback that removes the comma, so `1e,3` parses as `1e3`. Multiple commas
without a decimal point require valid groups; an existing point uses the original
comma-removal path. A final percent sign divides the already rounded binary64
value by binary64 100 using the canonical HIA integer implementation. Negative
inputs are divided by magnitude and their sign restored before clamping, preserving
negative zero after percentage underflow. Nonfinite results choose the default.

## Reproducible observations

[`test_bench_environment.py`](../../tests/test_bench_environment.py) builds each
canonical HIA component with a real `NativeModule` and standard self-hosted build
receipt. Its [Rust adapter](../../tests/rust_bench_environment_reference.rs) includes
the complete unchanged executor source and sets actual Unix environment bytes
before calling its private effective getters. Numeric conversion is compared with
actual Rust `str::parse::<f64>()` followed by the original finite check. Midpoints,
subnormal and overflow boundaries, long tails and atomic capacity refusals are
explicit controls.

The suite then carries actual native parser output into all seven native scheduler
strategies, compares all 17 raw profile and 10 adaptive fields with the real original
Bench/executor path, and exercises native repeats using those configurations. The
existing reader-high-water safety correction is preserved and recorded separately;
its independent repaired model and pairwise conflict graph remain mandatory.

With the explicit existing compiler/toolchain pins and a fresh external
`HIA_BENCH_ENV_OBSERVATIONS` directory, run:

```bash
python -m unittest hia.tests.test_bench_environment -v
```

These tests establish only their recorded component scope. The complete Bench CLI, real OS environment acquisition, clock and persistence
remain separate requirements before the old package can be retired.
