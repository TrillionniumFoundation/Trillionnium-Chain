# Native natural logarithm

`logarithm.hepta` evaluates the natural logarithm using HIA integer operations.
It has no runtime call to libm, MPFR, Python, C or Rust. The MPFR and unchanged
Rust implementations are independent qualification references only. This module
does not close the Bench executable, its report renderer or its OS owner.

## Interface and special values

The public entry accepts exactly `BLOG0001` followed by one little-endian u64
containing the binary64 input bits. It requires at least 16 output bytes and
1024 private scratch bytes. The output is the result bits followed by the actual
fixed-point precision used: 0 for special cases, 128 or 256 for the interval
calculation. Trailing output and scratch bytes are outside the borrow.

Status 1 rejects the frame length, 2 rejects the magic, and 100 rejects capacity.
Those checks occur before any mutable write. They do not reject any binary64
value. Both signed zeros produce negative infinity, positive infinity is
unchanged, negative finite values and negative infinity produce a quiet NaN,
and input NaNs are quieted while preserving their sign and payload. `ln(1)` is
positive zero. The native choice of NaN bits is recorded separately from the
actual Rust platform's observation; a NaN payload comparison must not silently
be substituted for a numeric comparison.

The finite positive calculation returns round-to-nearest, ties-to-even binary64.
Rust documents [platform-dependent precision for `f64::ln`](https://doc.rust-lang.org/std/primitive.f64.html#method.ln); an observed Rust bit
difference must therefore remain in the differential report, together with the
independent correctly rounded reference and the final four-place text. The test
must not accept a tolerance in place of those records.

## Fixed-point calculation

Write a positive finite input as `x = m * 2^k`, with `1 <= m < 2` and
`-1074 <= k <= 1023`. The shared native binary64 mantissa and exponent helpers
perform this normalization, including subnormals. Put

```text
t = (m - 1) / (m + 1),       0 <= t < 1/3
ln(m) = 2 * sum(t^(2n+1) / (2n+1), n >= 0)
ln(2) = 2 * sum((1/3)^(2n+1) / (2n+1), n >= 0)
ln(x) = k * ln(2) + ln(m).
```

For precision `P`, `Q = 2^P`. Each limb contains a base-`2^32` digit in an
eight-byte cell. There are `L = P/32` fractional limbs and one integer limb.
`blog_fraction` performs exact binary long division to obtain `T = floor(t*Q)`.
The series uses `Z = floor(T*T/Q)` and
`A[0] = T`, `A[n+1] = floor(A[n]*Z/Q)`. Each summand is
`floor(A[n]/(2n+1))`. All arithmetic here is integer arithmetic; the stopping
condition is an actually zero integer power.

The first calculation uses `P=128`. It constructs a closed interval around the
result and rounds both endpoints. It returns only if those two binary64 values
are equal. Otherwise it repeats the complete calculation at `P=256`, with no
reuse of a lower-precision approximation.

## Error bound and termination argument

This is the mathematical argument used to choose the second precision. It is
not an assertion that the test corpus exhaustively enumerates binary64 inputs,
or a proof of the native compiler. The argument depends on the published
worst-case bound stated below and on the explicit integer invariants here.

Let `u = 1/Q`. The initial truncation error is less than `u`, and

```text
0 <= t^2 - Z/Q < (5/3)*u.
```

If `e[n] = t^(2n+1) - A[n]/Q`, then `0 <= e[0] < u` and

```text
e[n+1] < e[n]/9 + (1/3)*(5/3)*u + u.
```

Induction gives `e[n] < 2*u`. The extra division truncation contributes less
than `u`, so each included summand has error less than `3*u` before the outer
factor of two. The integer inequality `3 * 9^82 > 2^256` shows that at most 82
summands can be nonzero at either supported precision. When `A[N]` is zero,
the omitted true power is less than `2*u`; its geometric tail, including the
outer factor of two, is less than `(9/2)*u`. Consequently the complete series
underestimates either logarithm by less than

```text
2 * 82 * 3*u + (9/2)*u < 512*u.
```

The construction of `k*ln(2) + ln(m)` therefore has absolute error less than
`512*(abs(k)+1)/Q`, which is less than `2^20/Q` over the entire input range.
The implementation forms integer endpoints `V-2^20` and `V+2^20`, where `V/Q`
is its computed magnitude. This encloses the true magnitude. Either endpoint
is less than `2^21/Q` from that true value.

For a binary64 input other than one, the nonzero magnitude of its logarithm is
greater than `2^-53`. Thus at `P=256` each endpoint's mantissa distance from the
true result is less than `2^(21+53-256) = 2^-182`.

Lefevre and Muller give `2^-118` as a sufficient mantissa-distance bound for
rounding the natural logarithm of a binary64 input throughout its domain,
including the subnormal input range: [Property 2 and Table 5, *Worst Cases for
Correct Rounding of the Elementary Functions in Double Precision*](https://perso.ens-lyon.fr/jean-michel.muller/TMDworstcases.pdf).
Property 2 is on printed page 13 (PDF page index 12); Table 5 is on printed
page 15 (PDF page index 14). Its input intervals are `[2^-1074,1)` and
`(1,2^1024]`; the exact input one is handled separately here. The definition
of mantissa distance is on printed page 3 (PDF page index 2): divide the
absolute difference by `2^floor(log2(abs(y)))`. The calculation above uses
that quantity directly, without replacing it by an unadjusted relative error.
For a subnormal with highest set-bit position `b`, normalization gives
`k=-1074+b`, so the input interval includes every positive subnormal rather
than assuming a normal exponent field.
The later [de Dinechin, Lauter and Muller paper, *Fast and Correctly Rounded
Logarithms in Double-Precision*, DOI 10.1051/ita:2007003](https://perso.ens-lyon.fr/jean-michel.muller/log.pdf)
states the same logarithm bound and explains the two-stage rounding decision.

Since `2^-182 < 2^-118`, both 256-bit endpoints must round identically under
that published bound. The final `trap user` is an assertion of this invariant,
not an error branch assigned to a legitimate mathematical input. Reaching it
in any actual run is a correctness failure that blocks qualification. A few
hard-case examples by themselves would not justify this conclusion; the
termination argument is the bound above.

## Integer and workspace invariants

- The mantissa ratio numerator is at most `2^52-1`, its denominator is less
  than `3*2^52`, and a doubled division remainder is below `2^55`.
- The schoolbook multiplication performs each full product in separate scratch
  before writing its destination. With digits and carry at most `2^32-1`,
  `a*b + old_digit + carry <= 2^64-1`; no high product bits are discarded.
- Small-division remainders are smaller than an odd divisor of at most 163.
  Shifting such a remainder by 32 is representable in u64.
- The series is nonnegative and below `ln(2)`. The scaled final magnitude is
  below `745*Q`, so the extra integer limb is sufficient. Subtracting the
  interval error cannot make a legitimate magnitude negative: even at 128 bits
  the minimum nonzero logarithm is much larger than `2^21/Q`.
- `blog_combine` explicitly propagates a base-`2^32` carry or borrow. Each
  stored cell remains a u32 value. Normalization, bit extraction and sticky-bit
  rounding do not read outside the initialized limbs.
- Put `S=8*(L+1)`. The two atanh calls use `[0,8*S)`. Saved `ln(2)`, saved
  `ln(m)`, the combined magnitude, and its two endpoints occupy slots 8 through
  12 respectively. The highest touched byte is 935 at 256 bits. The resolution
  flag occupies `[992,1000)` and the precision occupies `[1008,1016)`.
- Every atanh scratch cell is initialized during the current call. The second
  atanh clears only `[0,8*S)`, preserving the saved first result. The two
  precision stages have independent initialized digits; external prior scratch
  bytes are never treated as a cached result.

These invariants explain the required 1024-byte capacity. Qualification also
checks the complete backing image, boundary refusals and the two real precision
paths. The published worst cases are test inputs with source attribution, not
hardcoded output shortcuts.
