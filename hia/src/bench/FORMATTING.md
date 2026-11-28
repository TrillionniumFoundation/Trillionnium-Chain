# Native four-decimal formatting candidate

[`format_fixed.hepta`](format_fixed.hepta) implements the finite binary64
`{:.4}` formatting operation used throughout the original Bench report. It is a
numeric conversion component; the complete report layout and native CLI remain
separate work.

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. Input is exactly 16 bytes:
`BFXD0001` followed by the binary64 bits as a little-endian u64. Output requires
323 bytes and scratch 4608 bytes. These fixed capacities cover the sign, all
309 integral digits of the largest finite magnitude, the point and four fractional
digits, plus an 8-byte length prefix. Success writes that prefix and the ASCII
text, preserving the rest of output. The text has no trailing newline or NUL.

Codes are 0 success, 1 input length, 2 magic, 3 nonfinite value and 100 capacity.
Input and finite-domain validation precede capacity checking. Every refusal
leaves both mutable buffers unchanged. The full finite binary64 domain is admitted,
including both signs, subnormal values and negative zero.

The algorithm extracts the exact binary significand/exponent and multiplies the
significand by integer 10,000 in the canonical HIA base-2^32 workspace. Positive
binary shifts are exact. Negative shifts keep the guard and sticky bits and round
nearest with ties to even before decimal conversion. It never multiplies the
value by a rounded floating-point 10,000. Repeated integer division by ten produces
the final digits; padding, point and sign placement are HIA code. A negative value
that rounds to zero prints `-0.0000`, preserving the original formatting behavior.

The maximum intermediate integer needs fewer than 1040 bits; the existing
4096-bit integer array leaves a substantial explicit bound. Only scratch
1024..2048 and the reversed-digit region starting at 4096 are used. No Python,
Rust, C formatter, system math library or foreign runtime algorithm is part of
the native artifact.

The [Bench environment qualification](../../tests/test_bench_environment.py)
compares actual native output with Rust formatting in the freshly built original
observer. It includes halfway ties and adjacent values, sign symmetry, exponent
boundaries, subnormals, the largest finite values, deterministic random bit
patterns, exact output tails and atomic refusals. The ordinary component
qualification recorder captures its real canonical build and native calls.
