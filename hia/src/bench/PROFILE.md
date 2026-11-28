# Native derived Bench profile

`profile.hepta` implements the 50 public methods of the retained executor's
`GroupingProfile`, followed by the Bench report's `conflict_hit_rate` expression.
`format_value.hepta` formats every binary64 value as the original Rust `.4`
float field. Together with the existing raw scheduler profile, these are native
components of the report calculation. The executable's argument owner, complete
report construction, clock observations and persistence are still separate work.
The original `trnm-bench` package remains retained.

## Profile interface

The input is exactly 144 bytes: `BPRO0001` and the following 17 little-endian u64
words in the original struct order. The two float fields contain binary64 bits.

| Word | Original field |
| --- | --- |
| 0 | `tx_count` |
| 1 | `group_count` |
| 2 | `grouped_count` |
| 3 | `max_group_size` |
| 4 | `min_group_size` |
| 5 | `avg_group_size` |
| 6 | `hot_object_share` |
| 7 | `conflict_checks` |
| 8 | `conflict_hits` |
| 9 | `candidate_groups_scanned` |
| 10 | `retry_fallback_new_groups` |
| 11 | `stage_ww_checks` |
| 12 | `stage_ww_hits` |
| 13 | `stage_wr_checks` |
| 14 | `stage_wr_hits` |
| 15 | `stage_rw_checks` |
| 16 | `stage_rw_hits` |

The entry requires at least 416 output bytes and 2048 private scratch bytes.
Output starts with `BPROOUT1` and contains 51 little-endian u64 results. The
first 50 follow the method declaration order in the original `impl
GroupingProfile`; the last is `conflict_hits as f64 / conflict_checks as f64`,
or positive zero when there are no checks. The exact named order is also pinned
by `METHODS` in `test_bench_profile.py`, and the unchanged Rust include adapter
calls every named method explicitly.

Results 8, 16, 35, 38, 39, 42 and 45 are integer counts. Result 32 is the dominant
stage: 0 `none`, 1 `ww`, 2 `wr`, 3 `rw`, 4 `mixed`. All other results are binary64
bits. Results 48 and 49 are stage concentration and normalized entropy. The
raw average and hot-share fields are transported without participating in these
derived methods, just as in the original methods.

Status 1 rejects length, 2 rejects magic, and 100 rejects insufficient output or
scratch capacity, in that order. Each rejection precedes any mutable write.
Scratch belongs exclusively to the call: logarithm storage is below byte 1024;
the 17 copied profile words occupy `[1024,1160)`. All input fields are read
before scratch initialization. No prior scratch bytes are trusted. The three
buffers are disjoint borrowed ranges supplied by the owner. Trailing output
bytes and scratch bytes at or beyond 1160 remain unchanged.

## Arithmetic and failure behavior

Ratios retain the original operation order: independently convert each integer
to binary64 using ties-to-even rounding, then divide. A zero denominator returns
positive zero. Saturating differences, minimums, maxima, tie handling and the
three-term left-associated concentration calculation match the original code.
The existing integer-only `binary64.hepta` implements the numeric operations;
there are no runtime host float or math calls.

The original `attributed_retry_hits` adds its three usize stage counts, and
`retry_reuse_salvage_rate` adds reused placements and fallback groups. Their
overflow behavior is preserved against the actual unoptimized Rust reference:
the original panics and the native checked addition traps. These observations
do not claim that an unchecked Rust release build has the same overflow policy.
Normal reachable scheduler counters are bounded by the actual workload and
available memory. All 51 values are calculated before publication of any output
word, so a checked-arithmetic failure does not publish a partial profile.

Entropy uses the positive stage weights in original `ww`, `wr`, `rw` order. It
computes `-share * ln(share)`, folds the terms from negative zero, and divides by
`ln(3)`. The native logarithm is specified in [LOGARITHM.md](LOGARITHM.md).
Zero weights do not evaluate a logarithm. An empty attribution returns positive
zero. With a nonzero representable stage sum, each converted share lies in
`[0,1]`; each nonzero entropy term is nonnegative. This is the finite domain
required by the shared binary64 addition helper.

Rust documents platform-dependent `ln` precision. The correctly rounded HIA
logarithm may therefore differ from the actual Rust platform in low result bits.
The qualification retains every such difference for both direct logarithms and
derived entropy, including both raw bit patterns and the actual final `.4`
strings. It requires exact equality for the other 50 derived values and exact
equality of all observed final strings. There is no tolerance comparison and no
replacement of a successful input with an approximation error status. A finite
corpus establishes those observations, not full executable equivalence.

## Complete float field interface

`format_value.hepta` accepts exactly `BFLD0001` followed by the input binary64
bits. It requires 323 output bytes and 4608 private scratch bytes. The output is
a u64 byte length followed by ASCII text. Finite values call the unchanged
[fixed four-place formatter](FORMATTING.md). Positive infinity is `inf`, negative
infinity is `-inf`, and every NaN is `NaN`, matching Rust display precision
formatting. Signed finite zero is preserved. Frame and capacity statuses follow
the profile entry's order, and all checked rejections leave both buffers intact.

## Repeatable qualification

Run the standard test module with the pinned native compiler and current HIA
toolchain. Set `HIA_BENCH_PROFILE_OBSERVATIONS` to a new directory outside the
checkout to retain the complete evidence:

```sh
python -m unittest hia.tests.test_bench_profile -v
```

The suite builds canonical native artifacts and a fresh locked, offline original
Bench executable. The Rust adapter includes the entire current executor source
without editing its algorithms. MPFR is required only by the qualification
process: a directly rounded 53-bit result supplies the independent binary64
reference, and directed 400-bit results check both actual native interval
endpoints. Its actual loaded library version and file hash are recorded.

Coverage includes every finite exponent field, every subnormal binade, neighbors
of one, attributed published hard cases, both native precision paths, signed
zero, infinities, signaling and quiet NaNs, saturation and tie boundaries,
original overflow failures, malformed frames and every capacity family. The
profile bridge also consumes real outputs from all three original workloads and
all seven native scheduler strategies. Existing reader-high-water repair
differences are recorded separately; original unsafe groups are not reinstated.
Actual native input and full returned buffers are retained in a gzip JSONL file,
alongside all native ELF artifacts, build receipts, raw Rust process streams and a
before/after source fence. The ordinary qualification recorder sees the real
`NativeModule` builds and invocations.
