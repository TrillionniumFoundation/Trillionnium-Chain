# Bench integer and civil date text

`text.hepta` contains the native unsigned 64-bit, signed 64-bit, unsigned
128-bit, and original civil date formatting used by the report renderer.
It uses integer HIA operations and writes decimal ASCII directly. There is
no host formatting function, libc date conversion, or runtime lookup table.

The private borrowed entry takes exactly 40 bytes: `BTXT0001`, then four
little-endian u64 words: operation, low word, high word, minimum width.
Operations 0/1/2 render u64/i64/u128 respectively. Operation 1 interprets the
low word as a two's-complement i64. Operation 2 combines the high and low
words. Width is in 0..40 and includes a negative sign, with zero padding
after that sign. For operations 0/1 the high word must be zero.
Operation 3 renders a captured epoch second; high word and width must be zero.
Output capacity is at least 48 bytes: a u64 byte count followed by the text.
The remaining output and the entire third scratch argument are preserved.
Statuses 1/2/3/100 mean framing, magic, field, or capacity refusal, before
either mutable argument changes.

The u128 formatter divides four base-2^32 digits by ten without losing any
of the 128 input bits. The largest value requires 39 decimal digits. The
signed formatter handles i64::MIN without overflowing signed negation.

The civil algorithm preserves the original `civil_from_days`, including its
negative-era adjustment before Euclidean division. Epoch bits are cast to
i64 as in the original formatter. For a real Linux `SystemTime`, the valid
nonnegative seconds fit i64; the private helper additionally has the same
defined cast and civil arithmetic for every u64 bit pattern. This does not
claim that every such synthetic value can be constructed as a host clock.
A clock before the Unix epoch must be converted to zero by the future clock
owner, matching the original `duration_since(...).unwrap_or_default()`.

The test adapter includes the entire unchanged original Bench source. Date
qualification calls its real `chrono_like_iso` with actual constructible
`SystemTime` values; integer qualification calls Rust's standard formatting.
Whole command-line, clock ownership, and persistence qualification remain
separate from these private functions.
