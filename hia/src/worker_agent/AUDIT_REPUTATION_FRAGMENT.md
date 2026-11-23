# Active Worker audit: numeric reputation fragment

[audit_reputation_fragment.hepta](audit_reputation_fragment.hepta) emits the six
optional numeric reputation columns from the
[active Rust Markdown row](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs).
Its bytes start with the separator before `reputation_delta` and end with the
last byte of `reputation_gap_bps_from_best`. For example, the all-absent frame
produces ` | - | - | - | - | - | -` (no newline). This excludes the preceding
label cell, closing ` |\n`, and the rest of the row. Absent is `-`; present
zero is `0`. There is no clipping or normalization of any admitted typed value.

The private fixed-size 21-byte input is:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `WAR2` |
| 4 | 1 | Presence mask in row order; bits 6 and 7 must be zero |
| 5 | 4 | Delta, little-endian two's-complement `i32` |
| 9 | 1 | Tier, `u8` |
| 10 | 2 | Weight, little-endian `u16` |
| 12 | 4 | Score, little-endian two's-complement `i32` |
| 16 | 1 | Rank, `u8` |
| 17 | 4 | Gap, little-endian two's-complement `i32` |

Each absent field has a zero payload; setting its mask bit distinguishes
present zero. Input, output, and scratch are disjoint borrowed regions, in
that order in the pinned export `f0`. Scratch is unused. Complete frame
validation and exact measurement precede emission: `0xffffffff` means
invalid frame, `0xfffffffe` means insufficient output capacity, and either
status leaves every byte unchanged. Success returns the written byte count,
leaves the output tail untouched, and is at most 62 bytes (six separators,
three 11-byte signed values, two 3-byte unsigned values, one 5-byte unsigned
value). Signed values reuse the WAR1 unsigned decimal routine by writing a
minus sign and computing the magnitude in `u64` without negating an `i32`.

After the repository preflight and pinned compiler bootstrap, run:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_reputation_fragment
```

The differential compiles the exact active Rust type body (minus Serde
field attributes) and active renderer using the pinned Rust toolchain.
The fixture passes the typed fields and extracts the substring after a
known label; it does not format the numeric cells itself. This does not
replace or modify active CLI dispatch, label handling, row/header assembly,
record selection, file publication or the original package.
