# Bench native components

This directory is the partial HIA migration of the retained
[`trnm-bench` executable](../../../trillionnium/crates/trnm-bench/src/main.rs).
The original crate remains required. These primitives do not constitute a native
Bench CLI, a complete executor-crate replacement, a throughput result or a Node
activation.

`workload.hepta` implements the three original transaction generators.
`digests.hepta` implements both canonical SHA-256 digests. `repeat.hepta` owns the
initial native grouping and every requested replay, comparing both the digest and
the complete ordered membership. All production algorithms in these modules are
HIA instructions executed through the pinned native compiler. The Python builder
and tests transport buffers, build artifacts and observe results.

The [environment-value implementation](ENVIRONMENT.md) adds all 12 original
parsers/defaults and exact decimal conversion; [fixed formatting](FORMATTING.md)
adds native four-decimal output. These value layers preserve the same existing
scheduler contract. OS environment acquisition, the complete CLI, derived
logarithmic profiles, clock measurement and persistence remain separate owners.

## Original observable contract

### CLI and normalization — CLI remains OPEN

The original is a Clap-derived executable with the following long options:

| Option | Default | Original behavior |
|---|---|---|
| `--txs <usize>` | 20000 | Normalize zero to one after parsing |
| `--keys <usize>` | 2000 | Normalize zero to one after parsing |
| `--read-fanout <usize>` | 3 | Normalize zero to one; printed even for Classic |
| `--write-every <usize>` | 1 | Normalize zero to one; printed even for Classic |
| `--workload <value>` | `classic` | `classic`, `mixed`, `hot-streak` |
| `--strategy <value>` | `original` | Seven names listed below |
| `--profile` | false | Add the complete profile report |
| `--persist-profile` | true | A SetTrue flag; no CLI false-valued counterpart |
| `--determinism-repeats <usize>` | 0 | Reject values over 1000 before generating work |

`-h` and `--help` return help. Clap owns unknown-option, invalid-value, missing-value,
duplicate-option and enum-spelling diagnostics and its parse exit status. The
native CLI must reproduce the admitted argument and error contracts; a binary
request frame is not a substitute for this layer. In particular,
`--persist-profile=false` does not disable persistence in the retained CLI.

The explicit repeat-limit error is
`--determinism-repeats exceeds bounded maximum 1000`, written to stderr with exit
status 2. A grouping replay mismatch also exits 2 before printing the accumulated
normal report. Successful normal execution exits 0.

### Workloads — implemented

All generated transaction IDs are their zero-based input indices. Every reference
has version 1 and every payload is empty. Access-list order and repeated references
are part of the workload digest, even though the scheduler deduplicates domains.

| Workload | Read references for transaction `i` | Write references |
|---|---|---|
| Classic | One reference `i % keys` | The same reference, on every transaction |
| Mixed | In order, `(i + 7*j) % keys` for `j` in `0..read_fanout` | `(13*i + 3) % keys` when `i % write_every == 0` |
| HotStreak | First `(i / 16) % keys`; each later side read starts at `(i + 11*j) % keys` and advances modulo `keys` while it matches an earlier read, with at most `keys` probes | The first hot reference when `i % write_every == 0` |

HotStreak retains the requested number of reads when the keyspace is exhausted;
references can therefore repeat when fanout exceeds key count. Classic ignores
fanout and write stride when constructing transactions, but the original report
still prints the normalized configured values. Its effective profile values are
one read and write ratio 1.0.

### Scheduler and environment — native configuration values implemented

The seven strategies are `original`, `footprint-desc`, `write-first`, `write-last`,
`hot-bucket-interleave`, `auto-adaptive` and `aggressive-greedy`. Printed names are
Rust Debug spellings: `Original`, `FootprintDesc`, `WriteFirst`, `WriteLast`,
`HotBucketInterleave`, `AutoAdaptive`, `AggressiveGreedy`.

The existing [HIA scheduler contract](../executor/README.md) defines transaction
ordering, its 17 raw profile fields and its 10 adaptive-decision fields. Its
reader-high-water correction is intentionally retained. A later reader must not
replace a higher reader group with a lower one. This correction can alter group
membership and counters even for an original result that happened to be safe.
The Bench tests execute the unchanged Rust library, record each difference,
require the repaired independent reference and separately check the conflict
graph. They do not make the original unsafe result an acceptance target.

The original scheduler reads these process environment variables:

| Variable | Default | Effective restriction |
|---|---|---|
| `TRNM_AGGR_DEEP_SCAN` | false | Toggle parser |
| `TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS` | true | Toggle parser |
| `TRNM_AGGR_SCAN_ROUND_ROBIN` | true | Toggle parser |
| `TRNM_AGGR_SCAN_WINDOW` | 0 | Grouped unsigned integer, maximum 4096; zero is unlimited |
| `TRNM_AGGR_SCAN_RR_SEED` | 0 | Grouped unsigned integer, full usize range |
| `TRNM_HOT_BUCKETS` | 8 | Loose unsigned integer, clamped to 4..64 |
| `TRNM_AUTO_MIN_BATCH_LEN` | 512 | Grouped unsigned integer, clamped to 64..4096 |
| `TRNM_AUTO_SAMPLE_LEN` | 2048 | Grouped unsigned integer, clamped to 64..2048, then limited by actual batch size |
| `TRNM_AUTO_HOT_STREAK_RATIO` | 0.22 | Finite parsed binary64, clamped to 0..1 |
| `TRNM_AUTO_REORDER_MIN_MARGIN` | 0.04 | Same |
| `TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE` | 0.0075 | Same |
| `TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE` | 0.01 | Same |

Missing, non-Unicode, empty or invalid environment values fall back to their
respective defaults. Numeric parsers trim Rust Unicode whitespace and optionally
one matched single- or double-quoted pair, trimming its interior. The loose
integer parser removes underscores and commas and allows one leading plus.
Grouped integers remove underscores, allow one leading plus and accept commas
only when every segment after the first has exactly three ASCII digits. The
first segment is not restricted to three digits.

The float parser removes underscores; accepts percent suffixes; distinguishes a
single decimal comma from a thousands comma using the original zero-prefix and
three-digit rules; validates repeated grouping commas; parses the normalized
text as Rust binary64; rejects nonfinite values; divides percentages by binary64
100; then clamps. Negative zero is preserved. This contract requires precise
text conversion, not a host-side configuration approximation.

Toggle parsing trims whitespace and one matching quoted pair, lowercases ASCII,
and treats empty or all-underscore/comma strings as default. Exactly `0`, `false`,
`off` and `no` are false; every other nonempty value is true.

### Digests and replay — implemented for canonical Bench transactions

Input SHA-256 starts with `TRNM-BENCH-INPUT-V1\0`, followed by each transaction:
ID as u64 LE, read count as u64 LE, ordered `(object ID, version)` u64 LE pairs,
write count and ordered write pairs, payload length as u64 LE, then payload bytes.
There is no transaction-count word in this digest.

Group SHA-256 starts with `TRNM-BENCH-GROUPS-V1\0`, followed by group count as u64 LE.
For each ordered group it hashes its zero-based group index, member count and
ordered transaction IDs, all u64 LE. Bench transaction IDs equal input indices,
so the scheduler's returned index array is exactly the ID sequence hashed here.
Hex text output is lower case; the primitives return the equivalent 32 raw bytes.

Zero requested repeats means `determinism.replay_match=not-requested`. Otherwise
the original performs precisely that many additional schedule calls after the
initial call. Each replay must match both the SHA-256 digest and every ordered
member vector. A digest alone is insufficient. The HIA owner executes this loop
itself; Python test loops are not the implementation.

### Timing and complete profiles — OPEN; fixed formatting implemented

The original captures SystemTime after workload construction. It times only the
first scheduler call with Instant. Digest generation, all deterministic replays,
derived metrics and persistence occur after the timed interval. `elapsed_ms` is
the integer millisecond count. Times before the Unix epoch use zero; ISO text uses
the original `civil_from_days` routine and UTC `Z`, with minimum-width numeric
fields. Timing and the capture stamp remain real observations, never fabricated
constants in equivalence tests.

Normal stdout begins with `bench_parallel_grouping` and, in order, workload,
strategy, normalized transaction/key/fanout/stride values, persistence flag,
estimated conflict rate, group count, grouped count, elapsed milliseconds,
input hash, groups hash, requested repeats and replay status. Each line ends in
LF. Booleans are lowercase; workload names use `Classic`, `Mixed`, `HotStreak`.

With `--profile`, the report additionally contains:

- Workload/strategy/configuration, effective reads and write ratio, workload
  signature, persistence flag, capture epoch and ISO, capture-stamp family and
  repeated epoch fields, elapsed time, estimated conflict rate, coverage,
  ungrouped count, completeness, groups per 1000 transactions, grouping
  efficiency and the literal persisted-profile-capture hint.
- All 17 raw scheduler profile fields in declaration order.
- Conflict-hit ratio; checks, hits and candidate groups per transaction;
  reused placements and their share; new-group share; retry pressure;
  fallback shares relative to transactions, new groups, retry hits, scans and
  retry misses; candidate groups per retry hit and reused placement; retry reuse,
  salvage and hit rates; scan misses, miss rate, misses per transaction/group and
  overhang per retry hit/reused placement.
- Per-stage WW/WR/RW hit rates, hits per transaction and retry shares; dominant
  stage (`none`, `mixed`, `ww`, `wr`, `rw`), dominant share and attributed share;
  dominant lead hits and its two shares; attributed and unattributed hits/shares;
  attribution coverage; overlap hits and its shares; singly attributed hits and
  its shares; stage concentration and normalized stage-mix entropy.
- For AutoAdaptive only, all 10 adaptive fields, including exact reason text and
  binary64 threshold, margin, hot-share and expected-gain values.

Ratios with a zero denominator return positive zero. Counts use the original
saturating differences where specified. Attributed retry hits are the ordinary
sum of the three stage counters; dominance ties produce `mixed`. Concentration is
the sum of the three squared retry shares. Entropy skips zero stage weights and
computes `sum(-p * ln(p)) / ln(3)` using attributed hits as its denominator.

The estimated conflict rate is binary64 `1 - min(keys/n, 1)`; this must not be
silently replaced with `(n-keys)/n`, whose rounding can differ. Groups per 1000
transactions multiply by binary64 1000 before dividing. Every displayed float
uses the original fixed four-decimal formatting and operation order. Existing
nonnegative binary64 arithmetic does not complete signed subtraction, natural
logarithms, decimal text parsing or formatting.

### Persistence — OPEN

Persistence runs only when profiling and the persistence flag are true. Its
default directory is the original compile-time Cargo manifest directory joined
with `../../run/bench`. The file name is
`executor-profile-summary-{capture_started_at_epoch}.txt`. Same-second runs
replace that file using the original `fs::write` behavior.

The implementation creates directories recursively, attempts directory
canonicalization, then appends `profile.report.path` and
`profile.report.artifact_basename` to the output lines. It clones the lines and
iterates the persisted `profile.report.output_line_count` and
`profile.report.output_bytes` values to a fixed point. Those last two metadata
lines are present in the file, not the stdout line vector. The file contains a
final LF, and byte length counts UTF-8 bytes.

Directory-creation failure happens before the path lines are appended. Write
failure happens after those lines. Either error appends
`profile.report.persist_error={original I/O error display}` and normal stdout
continues without changing the successful process exit status. Canonicalizing
the final file falls back to the original output path. A native owner must retain
these ordering, replacement, failure and path-display contracts.

## Native buffer contracts

All words are unsigned u64 LE. Borrowed input, output and scratch live extents
must be exclusive and must not overlap. Caller pointers may be unaligned. There
is no new transaction, key or fanout ceiling: checked arithmetic and the actual
buffer extents bound each call. Existing SHA full-length helpers enforce the
SHA-256 bit-length representation limit; the legacy 2,098,176-byte default SHA
entry is not used.

### Workload `f0(input, output, scratch) -> u32`

Input is exactly 64 bytes: magic `BNCHGEN1`, workload 0..2, transaction count, key
count, fanout, write stride, strategy 0..6, and a zero reserved word. Counts are
normalized as described above. Output is an eight-byte length followed by a
complete `EXSCH001` schedule request with the scheduler's default effective
configuration. If R is the actual reads per transaction and W is the number of
writing transactions, total required output is `136 + 32*N + 16*(N*R + W)`.

Codes are 1 for wrong input length, 2 for wrong magic, 3 for workload/strategy or
reserved-word errors, and 100 for capacity or capacity-arithmetic failure. These
refusals leave output and scratch unchanged. Success writes exactly the declared
prefix and leaves all scratch unchanged.

### Digest `f0(input, output, scratch) -> u32`

The input is either an exact `EXSCH001` request or an exact `EXSCOUT1` schedule
result. Request hashing preserves raw list order, duplicates, versions, IDs and
payload. Result hashing preserves the ordered Bench IDs represented by indices.
It checks framing, group offsets and final member count before mutable work.
Output requires 32 bytes and scratch requires 1208. Code 1 is invalid framing;
code 100 is insufficient output/scratch. Those errors are atomic. Success writes
32 output bytes and uses only the 1208-byte SHA arena.

### Repeat `f0(input, output, scratch) -> u32`

Input uses schedule-request layout with magic `BNCHREP1`, operation zero, repeat
count 0..1000 at offset 112 and zero at offset 120. All other effective scheduler
configuration fields retain their original validation. Let `B = 264 + 16*N` and
`S = 4096 + 168*N + 72*M`, where M counts raw reference pairs. Output capacity is
`2*B + 112`; scratch capacity is S.

The first output region is the current scheduler result. At offset B, six words
contain magic `BNCHRES1`, requested repeats, match state (0 not requested, 1 match,
2 mismatch), actual schedule execution count, first-result byte length and first
group count. Input and first-group digests occupy B+48..B+112. A saved first
schedule result starts at B+112. It is disjoint from every live scheduler write.
Unwritten gaps and trailing bytes remain unchanged. Every replay resets the
scheduler arena before its next use; SHA state never survives as scheduler state.

Codes 1/2/3/100 reject frame, magic, config or capacity before output/scratch
mutation. Within-transaction version skew has the existing scheduler code 5
(output unchanged, parsing scratch may change). Code 6 reports an actual replay
mismatch. The snapshot and metadata are private to the call, not trusted cached
external memory. Only ordered groups and their digest participate in the replay
comparison; raw profile telemetry is excluded, matching the original check.

## Reproducible qualification and remaining boundary

The [builder](../../platform/bench/build.py) captures canonical function bodies,
actual compiler input/output, pinned compiler identity, preflight dependencies,
original crate sources and build receipts. Both object and shared artifacts use
the canonical `toolchain.build_native` entry with the explicit component includes;
their real receipts bind the exact compiler wire and source inputs. Tests create
standard `NativeModule` instances and require their independently rebuilt images
to equal the retained builder artifacts. The general qualification recorder sees
both the direct builds and the module initializations and calls. The comparator
probe has an explicit generated-fixture test owner and preserves unchanged
canonical dependencies. Every build and test target lives outside the repository.

Run [the formal tests](../../tests/test_bench_native.py) with the existing explicit
HIA toolchain/compiler pins and a fresh `HIA_BENCH_OBSERVATIONS` directory:

```bash
python -m unittest hia.tests.test_bench_native -v
```

The Rust adapter uses `include!` on the unmodified original Bench source and
links actual Cargo-produced dependencies. The suite also runs all 11 retained
original tests and the real original CLI repeat path. It covers all workloads and
strategies, zero normalization, duplicates and side-read exhaustion, stable
hashes, known scheduler correction differences, replay counts 0/1/3/1000, malformed
and undersized buffers, comparator negative controls, default 20,000-transaction
workloads, inputs exceeding 2 MiB, physically unaligned buffers and sequential
arena reuse. Hash, membership, output-tail, input and arena guards are checked.

The CLI parser, environment text parsing, derived profile methods and entropy,
four-decimal formatting, clock capture and persistent-file owner remain OPEN.
The original `trnm-bench` package and executor dependency must remain until those
contracts and their complete real-original qualification are closed.
