# W1 zero-v2 paired cost accounting

This is a narrow P0-B research increment on top of
`adb9a386e109cdd80942020a4fc479a9b52730bc` (tree
`8ded756b16c3e26ada4367fbb7ab599ba0f80b0b`). It changes no native
producer/verifier, challenge or ticket domain, consensus, default mining path,
capacity limit, transaction or recovery policy. It does not complete P0-A or
qualify the maintenance task as unavoidable work.

## Executable observer and responsibility boundary

`scripts/ci/analyze_zero_paired_cost.py` accepts two retained native zero-v2
stdout files and their explicit SHA-256 identities. It checks the complete
five-producer/two-mode/two-target grid, actual balanced invocation order,
per-search outcomes and full-stream pairing. It computes exact integer ratios
without timing thresholds. The existing native/schema/artifact checks remain
a prerequisite: this observer does not independently replay W1 cryptography,
authenticate a GitHub run or identify hardware. Its output says so explicitly.
Architecture labels on its command line are caller labels, not hardware proof.

Every fixed implementation retains every sample. Cold and reused construction,
distinct targets, campaigns and architectures stay separate. Both generic and
old blocked-zero references are reported; the new producer is not assumed to
be the strongest comparison. Slow results and finite-budget exhaustion remain
in the arithmetic. Individual zero-winner cohorts remain visible even when a
larger group has winners. No per-sample hindsight mixture is presented as an
implementable producer.

For a fixed arm, target, mode, architecture and campaign, let `G` be the sum of
all setup and search elapsed nanoseconds, `A` the total attempted full proofs,
`W` the observed winners, and `V` the sum of measured production-verifier time
on those winners. The observer reports `G/A`, `G/W`, `V/W` and `G/V` as exact
numerator/denominator objects. All target misses and exhausted searches are
included in `G`; a zero denominator produces null. `G/V` is a finite observed
pipeline ratio, not an intrinsic generation/verification lower bound. The
comparison between two fixed arms is the ratio of total costs, not the mean
of per-sample ratios. Paired sample ratios and their actual invocation positions
are also retained. A zero generation clock does not establish the fastest arm.

The observer emits no PASS qualification, confidence interval, fastest-adversary
claim, proof-hardness claim or deployment permission. Shared streams across arms
and architectures are not independent observations.

## Retained round10 observations, not new native executions

Original native source: the commit/tree above. Original GitHub Actions run:
[37292461916](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/37292461916).
The two cost jobs completed successfully when retrieved. This does not say that
the run's Rust head/merge or full-capacity gates completed.

Original artifacts: x64 `11337580627`, arm64 `11337057923`. Their downloaded ZIP
SHA-256 values are, respectively:

- `ee78470cee261f3c260df77f0d49ade52866dcf95159bfd2c2a8d9a56dd1f8c0`
- `b7afbd91a441ce3f946914a420e74c8baf7d2ad56940737288e1960bf3234006`

The replay checked the zero-suite manifest file inventories, unchanged binary
hashes, source-before/source-after identities and recorded run IDs. This is a
file-integrity/source-binding check, not a replacement for the existing full
artifact checker or an independent hardware qualification.

Campaign 0 is `(samples=4, searches=4, attempt_budget=64, seed=0)`; campaign 1 is
`(2, 4, 8, 1)`. All 16 architecture/campaign/target/mode aggregate comparisons
retain **old blocked-zero** as the lowest observed fixed arm. The following is
new `blocked-zero-integer-paired` generation cost divided by old `blocked-zero`
generation cost, including actual setup and every search:

| Campaign | Architecture | Target | Mode | New / old total cost |
| --- | --- | --- | --- | --- |
| 0 | x64 | `7f…ff` | `cold-per-search` | 1.187833 |
| 0 | x64 | `7f…ff` | `reused-one-setup` | 1.179360 |
| 0 | x64 | `07…ff` | `cold-per-search` | 1.253646 |
| 0 | x64 | `07…ff` | `reused-one-setup` | 1.239047 |
| 0 | arm64 | `7f…ff` | `cold-per-search` | 1.209591 |
| 0 | arm64 | `7f…ff` | `reused-one-setup` | 1.210343 |
| 0 | arm64 | `07…ff` | `cold-per-search` | 1.210511 |
| 0 | arm64 | `07…ff` | `reused-one-setup` | 1.210347 |
| 1 | x64 | `7f…ff` | `cold-per-search` | 1.107337 |
| 1 | x64 | `7f…ff` | `reused-one-setup` | 1.171489 |
| 1 | x64 | `07…ff` | `cold-per-search` | 1.209094 |
| 1 | x64 | `07…ff` | `reused-one-setup` | 1.229497 |
| 1 | arm64 | `7f…ff` | `cold-per-search` | 1.209729 |
| 1 | arm64 | `7f…ff` | `reused-one-setup` | 1.211358 |
| 1 | arm64 | `07…ff` | `cold-per-search` | 1.212784 |
| 1 | arm64 | `07…ff` | `reused-one-setup` | 1.211597 |

These are post-hoc descriptive ratios from hosted VM observations, not confidence
bounds or universal slowdowns. In this retained data, fewer counted multiplications
did not make the new integer-paired producer faster. Retain it as an explicit
research arm; these observations do not justify replacing a default producer.
Preparation reuse, fastest legal adversaries, different hardware and energy,
qualification of recurring maintenance work, full admission cost and malformed
proof worst-case rejection remain separate research/engineering obligations.

## Reproduction and tests

Unpack the original two cost artifacts into `cost-x64` and `cost-arm64` without
modifying them. For each selected campaign, pass the following raw stdout hashes:

| Architecture | Campaign | Raw stdout SHA-256 |
| --- | --- | --- |
| x64 | 0 | `a80c7a404f1902948eff18fde4ecabc29cf358ec808adc85a7e152776fbbb7d6` |
| x64 | 1 | `3800c10845b14df5f4ce495599a4ac414fe8e4c69d42211f0ee7b0029776e6e6` |
| arm64 | 0 | `78db5851d5160116d4352c2817338e8117fbe2fba0789b1ad053b80d4f80b488` |
| arm64 | 1 | `6e1d8fbfb745f73279684d934e68ecef755f3c20d1cd05a29421bb12fd6ca255` |

```sh
python3 scripts/ci/test_zero_paired_cost.py -v
python3 scripts/ci/analyze_zero_paired_cost.py \
  --x64 cost-x64/cross-arch-zero-locality-cost/campaign-0.stdout \
  --x64-sha256 a80c7a404f1902948eff18fde4ecabc29cf358ec808adc85a7e152776fbbb7d6 \
  --arm64 cost-arm64/cross-arch-zero-locality-cost/campaign-0.stdout \
  --arm64-sha256 78db5851d5160116d4352c2817338e8117fbe2fba0789b1ad053b80d4f80b488 \
  --output paired-campaign-0.json
```

Output is create-only; existing
observations are not overwritten. The 27 manufactured unit cases test accounting,
null denominators, complete pairing, byte binding, refusal of dropped/changed
outcomes, no hindsight selection, scope flags and CLI overwrite refusal. They are
not native proof, storage-capacity or service measurements. The existing
`repository-truth` lane additionally invokes these tests; no job, timeout,
acceptance threshold or existing test is removed or weakened.
