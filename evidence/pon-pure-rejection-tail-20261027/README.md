# Finite rejection-tail supplement — 2026-10-27

This is an independent supplement. All earlier eafaa evidence and reports remain unchanged. It adds complete per-call clocks and C positions spanning the serialized product through its last element. It does **not** establish a global worst rejection cost or close the correct-C/false-transcript P0 cost problem.

## Source and one actual execution

- Source: `bfcc21c08f14685dce27b7e4f99b567f3b6f34f0`; tree `9cd8fee8e5faa6ebf688400e6f52aed67a7317eb`.
- Binary SHA-256 before and after: `9c4648ff61071fe03da4635b869ac09306a6323e6b43d6b6d4430470ae2b5574`.
- UTC execution: **09:16:40.274845–09:16:41.695582**, 2026-10-27; capture wall **1.420457 seconds**, exit 0.
- Rust 1.95.0; Cargo test profile; crypto/protocol/SHA-2 opt-level 3; debug 0; incremental off; one build job. The small successful build completed beforehand in 10.17 seconds.
- Complete raw JSONL: **915,061 bytes**; lossless gzip: **95,938 bytes**. There was one native campaign, no omitted failed native attempt, no warmup/outlier removal and no retry to improve timings.

[Capture manifest](native-run/capture.json) · [Complete raw JSONL gzip](native-run/stdout.jsonl.gz) · [Checked results and all per-case statistics](native-run/consistency.json) · [Build observation](build-observation.json)

The exact PNH1 header is taken from the earlier complete matrix's pinned native-winning header. Public maintenance A/B are reconstructed independently, and a real W1 proof is produced and verified for that header and its unchanged `7f…ff` native development target. The reader independently checks the header/task/ticket hashes, mathematical A/B/C and every mutated proof's exact bytes/hash. The primitive experiment does not submit these malformed proofs for native admission.

The host was not exclusive. The proof owner reported a single-job host build/receipt-boundary tests around this interval while preparing actual proving. Exact scheduling, cache, frequency and memory contention were not controlled. Completion was immediately reported to that owner; no additional build or native campaign was started afterward.

## Fixed coverage and paired measurements

**83 cases × 9 rounds = 747 paired sample rows / 2,988 measured calls.** Every case measures the same original valid proof as a control, the mutated proof through the original full verifier, PublicProduct alone, and PublicProduct followed by the full verifier whenever the filter passes. Case and path order rotate deterministically.

The fixed cases are:

- **64 wrong-C indices:** `floor(i × 4095 / 63)`, hence **0, 65, …, 4095**. These uniformly span serialized offsets, including the last element. In matrix coordinates they are diagonal entries; this is not all 4,096 cells or all possible values. Each canonical value increments modulo q.
- **Three false final-digest bytes:** positions **0, 16 and 31**, with unchanged correct A/B/C. Every chosen false trace first passes the original native target. The single-byte searches took 9, 1 and 2 attempts; every failed attempt, trace, ticket and preparation time is retained.
- **Nine noncanonical field values:** first/middle/last of each A/B/C set to q.
- **Four illegal lengths:** 0, 3, proof length minus one and proof length plus one.
- One invalid version, one wrong task and one separately labeled trace with a failing ticket.

Each measured call retains wall time, thread-CPU observations before/after, the CPU delta or null, and an explicit unknown flag. All 2,988 calls had available Linux `CLOCK_THREAD_CPUTIME_ID` observations in this run. Unsupported/failing/overflowing clocks remain unknown; the reader refuses zero substitution. CPU timing surrounds the wall timer and includes timer/clock observation overhead. It is a slightly larger observation interval; very short refusals can be dominated by that overhead.

## Actual rejection stages

Progress probes are separate from the uninstrumented timing samples.

| Input | Original full verifier | PublicProduct | Filter then full verifier |
|---|---|---|---|
| Valid original | All 512 tiles, product correction, `BeforeVerifiedWork` | Mathematical fact match only | Accepted by full verification |
| Wrong C at any sampled position | All 512 tiles and product correction, then `Product` | `Product` refusal | Refused before replay |
| Correct C / false digest byte 0, 16 or 31 | **All 512 tiles**, then `Transcript`; no product correction or verified-work event | **`FactMatchOnly`** | Still performs full replay, refuses `Transcript` |
| Invalid field/length/version | No replay callback | Corresponding early encoding refusal | Same early refusal |
| Wrong task/failing ticket | No replay callback | `Task`/`Target` | Same early refusal |

Bytes 0/16/31 refer to the final 32-byte digest, **not internal transcript tiles**. PNW1 carries only that final digest: even the first mismatching digest byte follows complete transcript replay. A passing exact-product fact never constitutes verified work. Correct-C false traces remain a P0 verification-cost concern.

## Finite observed p99 and maxima

Units are **milliseconds per call**. Percentiles use nearest rank `ceil(0.99 × n)`. These are finite observed values, without confidence bounds or a global maximum guarantee. The original valid proof is held fixed throughout.

| Class/path | n | Wall p99 | Wall max | Thread CPU p99 | Thread CPU max |
|---|---:|---:|---:|---:|---:|
| Valid control, full verifier | 747 | 1.440438 | 5.902336 | 1.441699 | 5.907774 |
| Wrong C, full verifier | 576 | 1.270392 | 2.387345 | 1.271677 | 2.390977 |
| Wrong C, filter then full | 576 | 0.093150 | 0.241523 | 0.093538 | 0.242149 |
| Correct C / false trace, full verifier | 27 | 0.845593 | 0.845593 | 0.846736 | 0.846736 |
| Correct C / false trace, filter only (not work) | 27 | 0.070646 | 0.070646 | 0.071115 | 0.071115 |
| Correct C / false trace, filter then full | 27 | 0.961588 | 0.961588 | 0.962407 | 0.962407 |
| Noncanonical field, full verifier | 81 | 0.043466 | 0.043466 | 0.043985 | 0.043985 |
| Illegal length, full verifier | 36 | 0.006089 | 0.006089 | 0.006379 | 0.006379 |
| Wrong version, full verifier | 9 | 0.001643 | 0.001643 | 0.002083 | 0.002083 |
| Wrong task, full verifier | 9 | 0.065499 | 0.065499 | 0.066238 | 0.066238 |
| Failing ticket, full verifier | 9 | 0.064808 | 0.064808 | 0.065547 | 0.065547 |

For endpoint visibility, the following predetermined positions are shown separately. All 83 cases and all four paths are in the checked JSON. Each individual case has n=9, so nearest-rank p99 equals its observed maximum.

| Position | Original wall max | Original CPU max | Filter-then-full wall max | Filter-then-full CPU max |
|---|---:|---:|---:|---:|
| C index 0 | 1.028488 | 1.029547 | 0.106740 | 0.107379 |
| C index 2080 | 1.088859 | 1.090708 | 0.234052 | 0.234669 |
| C index 4095 | 1.083391 | 1.085209 | 0.027532 | 0.028011 |
| Digest byte 0 | 0.845593 | 0.846736 | 0.916580 | 0.917622 |
| Digest byte 16 | 0.704421 | 0.705237 | 0.828026 | 0.829130 |
| Digest byte 31 | 0.718181 | 0.719047 | 0.961588 | 0.962407 |

The final C index was not the slowest observed sample. That does not make an earlier index the universal adversarial optimum. The much slower valid-control maximum was also retained. One short-path example of observation overhead is a field/filter-then-full CPU maximum of 0.119377 ms versus that family's wall maximum of 0.018057 ms: the clock intervals include different surrounding observation work, as declared above. No subtraction, zeroing or replacement sample was used.

## Reproduction and reader checks

```sh
cargo build --locked --profile test --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_pure_rejection_tail_campaign
python3 scripts/ci/capture_pure_pon_rejection_tail.py \
  --binary "$CARGO_TARGET_DIR/debug/examples/pon_pure_rejection_tail_campaign" \
  --output /absolute/new-output-directory
python3 scripts/ci/check_pure_pon_rejection_tail.py \
  /absolute/new-output-directory/stdout.jsonl.gz --output /absolute/new-result.json
```

The capture requires a clean tracked tree and fresh output directory, retains failures, records source and binary hashes, and enforces a timeout and report bound. Eight evidence-reader tests pass. Negative cases cover an omitted last-C case, an early mutation relabeled as late, a false trace not passing the native target, digest positions mislabeled as tiles, filter success promoted to work, incorrect early/replay stages, erased unknown CPU, omitted paired controls and fabricated global qualification. These are mutations of retained observations for checker tests, not replacement measurements.

The supported conclusion remains narrow: the known public-product fact cheaply rejects the sampled wrong-C cases; correct-C false traces still require complete replay. **Non-amortizable hardness, unrestricted-network availability and a hard worst-case physical CPU bound remain unproved.**
