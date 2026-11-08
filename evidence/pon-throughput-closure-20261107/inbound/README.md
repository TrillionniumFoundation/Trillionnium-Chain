# Retained inbound component checks — 2026-11-07

These are **native tests and wall-time microbenchmarks of extracted transport
functions**, not a whole-Node build, a release-profile comparison, confirmed
throughput, WAN evidence, or passage of the original four-second service gate.
The Rust benchmark was compiled with `rustc -O`, but it reused **debug-profile
serde / serde_json dependency artifacts** from the integration build. Do not
apply the ratios below to a release Node or to the complete request path.

The candidate removes a redundant JSON parse / canonical re-serialization after
the exact packet-request envelope and complete lowercase hex grammar have
already been checked. It also reads the original bounded socket quantum into
initialized, already-reserved destination storage. The production admission
budgets, authentication, body digest, Packet / Work / State checks, cancellation
callbacks, and Host observations are not replaced by these component checks.

## Exact provenance

| Item | Identity |
| --- | --- |
| Baseline commit | `e70f13448aad715286fb8eb56fc802b09db643a3` |
| Production source | `trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs` |
| Baseline full-source SHA-256 | `325c3d0fd88e7bd361255d2d50f0e89155a3b735483f302bf2d3bcfe8851ba93` |
| Candidate full-source SHA-256 | `d8b06f0612b55a2537f9857ebe57b72a7ad7b2e126772bf7ae3e92fa59ff27ac` |
| Generated extraction SHA-256 | `9fc367fed3dab70992929d1ac96ee2c3651207acb0ced7a251051cc046cc4d8e` |
| Compiler | `rustc 1.95.0 (59807616e 2026-04-14)`, LLVM `22.1.2` |
| Compiler host | `x86_64-unknown-linux-gnu` |

The original [manifest](manifest.json), [extraction driver](run_extracted.py),
and complete [generated Rust input](extracted.rs) are retained byte for byte.
The baseline was read with `git show` at the commit above; the candidate was read
from the working tree. The extraction includes the Request enum, relevant
constants / helpers, canonical decoder, socket reader, and the new transport
tests in both modules. Small stand-in `Result` and `ensure` definitions support
the extracted code; the production Node and its owners are not linked.

The driver records its original absolute workspace / target paths. It selected
`libserde-9d830d9fb05068c2.rlib` and
`libserde_json-d9de496d4ac3237b.rlib` from the existing debug dependency directory.
This is a mixed build configuration, not a Cargo release build. No additional
whole-workspace build ran for this evidence. The raw files have their own
[SHA-256 inventory](SHA256SUMS).

## Tests and retained outcomes

The [test output](tests.log) reports **8 passed, 0 failed** in 2.43 seconds:
the same four tests ran against each extracted implementation. They exercise:

- Every one-byte substitution (all 256 byte values), each prefix truncation,
  each one-byte deletion, and trailing garbage for the three packet envelopes,
  using an independently serde-parsed canonical oracle.
- Empty, one-byte, exact-maximum, and over-maximum packet text.
- Real loopback nonblocking sockets: idle polls, partial input, EOF, preservation
  of bytes for the next frame, original read quantum, and overflow rejection.
- Destination capacity and removal of unreceived zero padding.

The transport tests are also in the production crate under
`ingress::public_v3::input_decode_tests`; this extraction is not evidence that
the integrated Node test target passed. That result belongs to the integration
test records.

[Test compilation output](tests-build.log) is empty. The retained
[benchmark compilation output](bench-build.log) includes its warning about
imports used only by the test build. This invocation had no failed test or
build arm to discard. No arm or raw timing row was filtered from
[the ABBA output](abba.jsonl). The separate original pressure failures remain
documented in the [acceptance evidence](../acceptance/README.md); these tests
and ratios do not supersede them.

## ABBA results and limits

Each case ran baseline, candidate, candidate, baseline in the same process.
There was no separate warm-up, hardware isolation, CPU affinity control,
original 0.25-CPU / 2-GiB service budget, or statistical confidence calculation.
The measurement is elapsed monotonic wall time, not thread CPU or peak memory.
There are only two observations per arm per case.

The decode input is an exact packet-request envelope containing repeated `ac`
hex text; it is not a valid signed block. Per-arm decode iterations are
`max(4, floor(16777216 / encoded_request_bytes))`. The idle socket case performs
100,000 reads per arm with no bytes sent. Timing includes the decoder result
allocation and drop; it does not execute signatures, proofs, replay, storage,
receiver admission, or independent confirmation.

The following values are the arithmetic mean of each arm's wall time divided
by its iteration count. The ratio is baseline wall time / candidate wall time.
The full 40 rows are retained in [abba.jsonl](abba.jsonl).

| Component | Packet bytes | Baseline ns / call | Candidate ns / call | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Submit decode | 64 | 1,474.07 | 143.65 | 10.26 |
| Submit decode | 49,603 | 422,797.23 | 81,835.57 | 5.17 |
| Submit decode | 1,048,576 | 8,720,137.36 | 1,780,278.50 | 4.90 |
| GrowthSubmit decode | 64 | 1,151.12 | 129.37 | 8.90 |
| GrowthSubmit decode | 49,603 | 449,895.56 | 84,248.20 | 5.34 |
| GrowthSubmit decode | 1,048,576 | 10,001,057.14 | 1,881,544.71 | 5.32 |
| GrowthPacketStatus decode | 64 | 1,247.12 | 133.05 | 9.37 |
| GrowthPacketStatus decode | 49,603 | 434,543.78 | 83,179.87 | 5.22 |
| GrowthPacketStatus decode | 1,048,576 | 8,990,517.71 | 1,818,523.21 | 4.94 |
| Idle Hello socket read | — | 907.57 | 153.92 | 5.90 |

## Replaying the captured component input

Keep the tracked raw output unchanged. A new invocation should use a fresh
output directory and retain its own command, dependencies, and failures. With
the compiler above and the matching dependency directory available, the
following recompiles the captured extraction without re-extracting newer code:

```sh
task_repo=$(git rev-parse --show-toplevel)
task_evidence="$task_repo/evidence/pon-throughput-closure-20261107/inbound"
task_deps=/path/to/matching/target/debug/deps
task_output=$(mktemp -d)
rustc --edition=2021 "$task_evidence/extracted.rs" \
  -L "dependency=$task_deps" \
  --extern "serde=$task_deps/libserde-9d830d9fb05068c2.rlib" \
  --extern "serde_json=$task_deps/libserde_json-d9de496d4ac3237b.rlib" \
  --test -o "$task_output/tests"
"$task_output/tests" --test-threads=1 --nocapture
rustc --edition=2021 "$task_evidence/extracted.rs" \
  -L "dependency=$task_deps" \
  --extern "serde=$task_deps/libserde-9d830d9fb05068c2.rlib" \
  --extern "serde_json=$task_deps/libserde_json-d9de496d4ac3237b.rlib" \
  -O -o "$task_output/bench"
"$task_output/bench"
```

A rerun with different dependency features or optimization settings is a new
observation. The original acceptance workload still needs its complete current
Node, exact budgets, hostile workers, failure / retry / cancellation accounting,
and independently confirmed business outcome.
