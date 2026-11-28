# Integer implementation of binary64 operations

`binary64.hepta` provides real native HIA helpers for the nonnegative finite
binary64 domain, plus negative zero. The functions use only Core integer and
buffer operations. They implement conversion from the full unsigned 64-bit
integer range, addition, multiplication, division and integer ratios with
round-to-nearest, ties-to-even. Subnormal inputs/results, gradual underflow,
signed zero and overflow to infinity are preserved. This is not a full signed
IEEE-754 library: negative finite operands, input infinities/NaNs and zero
division are outside its accepted public domain.

The scheduler's effective thresholds are finite [0,1], including -0. Its counts
are nonnegative; the ratio helper casts numerator and denominator separately
before division, matching the original Rust expression's operation order. Exact
rational comparison would change its threshold boundaries and is not used.

The standalone export is `f0(readbuf input, mutbuf output, mutbuf scratch)->u32`.
Input is exactly 32 bytes: `EXFP0001` followed by u64 operation, operand A and
operand B. Operations are 0 u64-to-binary64 (B ignored), 1 addition, 2 multiply,
3 divide. A/B are binary64 bits except for conversion. Output requires 8 bytes;
on success only the first 8 bytes receive the result bits. Scratch and all tails
are unchanged. Codes are 0 success, 1 input length, 2 magic, 3 operation, 4 operand
domain/zero divisor, 100 insufficient output. All refusals leave buffers intact.

Composition imports named helper functions explicitly and excludes the public
f0 adapter; one canonical source supplies their behavior. The unchanged pinned
compiler emits machine code from this HIA source. Tests compare native result
bits with independent hardware floating-point operations over conversion
rounding boundaries, full finite exponent ranges, subnormals, ±0, extreme finite
values and deterministic random pairs. That evidence does not establish a
decimal parser, logarithm implementation or all signed IEEE operations.
