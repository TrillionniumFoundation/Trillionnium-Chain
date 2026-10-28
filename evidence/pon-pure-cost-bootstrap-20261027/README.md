# Pure PoN bootstrap and finite adversarial cost evidence — 2026-10-27

## Result and exact scope

The explicit `public-pure-pon-development-v1` route fetches a public genesis maintenance bundle, mines through the unchanged W1 relation and submits with **zero transport hash trials**. The exact-public-product filter rejects a known wrong C early; a correct C never grants work authority. The original native verifier still rejects fabricated traces. These observations do not qualify useful model demand, a general non-amortization theorem, Sybil liveness or production operation.

The two full campaigns below completed with every configured cohort and request tail retained. The 105-second ingress campaign and the 718-second cost campaign ran sequentially with each other, but the host was **not exclusive**. Concurrent RISC0 host release LTO (parent report: about 08:44–08:52 UTC), root source/format checks and single-job strict Clippy were disclosed. See [environment-disclosure.json](environment-disclosure.json). Process CPU observations do not remove shared-cache, frequency or memory interference. The ratios below describe this observation; they are not stable speedup estimates or lower bounds.

All campaign binaries were built from commit `a26623359d01ba6b9429726f3b05cb2e4145d4e6`, tree `446b9d1411888324588ec4aeb971104aab1e4a10`, using Rust 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`, LLVM 22.1.2), Cargo `--profile test`, package optimization levels node=3, crypto=3, M06=1, debug=0, incremental=0 and one build job. Exact arguments, source/lock/manifest hashes, binary hashes before/after and lossless raw-output hashes are in each `capture.json`. Neither executable changed during its capture. The historical RSS field uses `RUSAGE_CHILDREN` high water and may include previously reaped preflight children; it is not isolated per-child RSS evidence.

## Complete fixed producer matrix

[Native capture](cost-long/capture.json) · [Complete raw JSONL, gzip](cost-long/stdout.jsonl.gz) · [Consistency result](cost-long/consistency.json) · [All fixed cohorts as JSON](cost-long/fixed-cohorts.json) · [All fixed cohorts as CSV](cost-long/fixed-cohorts.csv)

The full command used `--searches 256 --attempts 8 --rounds 2 --seed 1 --seconds 900`; the outer capture bound was 930 seconds. Observed wall time was 718.104 seconds, with 536.316 seconds user CPU and 6.525 seconds system CPU for the child. Complete raw output is 24,402,751 bytes, below the unchanged 32 MiB native/reader bound; gzip is 6,447,598 bytes. No horizon, round, unsupported arm, failed search or tail was removed.

The matrix contains **3,456 offered cohorts**: 12 fixed strategies × 9 material classes × 4 horizons (1/8/64/256) × 2 targets × 2 preparation policies × 2 rounds. There are 1,600 supported cohorts and 1,856 explicit unsupported-constructor observations, each retaining its setup cost. The complete supported streams contain 605,024 attempted productions, 80,836 winning verifier calls and 50,764 exhausted searches. Arms and nested horizons share challenge streams, so these are **calls, not independent cryptographic samples or unique accepted blocks**. Only actual genesis maintenance at the native target is native-admitted; the other materials and harder target are primitive experiments.

Every timing denominator includes actual setup plus every attempted production, including all losing trials and exhausted searches. Setup is paid per search in `cold` mode and once per cohort in `reuse` mode. No warmup sample was discarded. Verification, native admission, harness stream hashing and report I/O are outside that producer denominator and are not silently represented as free end-to-end work. All winning proofs passed the unchanged original verifier; supported arms produced identical complete header/proof/ticket stream hashes within each paired context.

### Batch length and preparation cost

Numbers are summed producer CPU divided by summed attempts across both rounds, in **milliseconds per attempt**. H1 is intentionally a tiny retained observation, not an estimator of steady performance. Native target is `7f…ff`; harder target is `07…ff`.

| Material (ranks A/B) | H1 cold, native | H256 cold, native | H256 reuse, native | H256 reuse, harder |
|---|---:|---:|---:|---:|
| periodic-dense-fixture (31/37) | 0.731 | 0.754 | 0.486 | 0.525 |
| full-rank-field (64/64) | 0.890 | 0.699 | 0.582 | 0.577 |
| zero (0/0) | 0.759 | 0.720 | 0.572 | 0.510 |
| identity (64/64) | 0.687 | 0.717 | 0.532 | 0.588 |
| rank-one (1/1) | 0.880 | 0.762 | 0.545 | 0.544 |
| sparse-diagonal (64/64) | 0.743 | 0.742 | 0.564 | 0.595 |
| zero-left-rank-one-right (0/1) | 1.172 | 0.697 | 0.573 | 0.530 |
| rank-one-left-zero-right (1/0) | 0.871 | 0.763 | 0.647 | 0.543 |
| genesis-maintenance (56/32) | 0.736 | 0.748 | 0.593 | 0.621 |

### Every general kernel at H256 with one reused preparation

Each cell is `native / harder` CPU milliseconds per attempted production. All four always-supported strategies are shown, including slower ones.

| Material | Prepared general | Tiled classical | One-level Strassen | Paired field products |
|---|---:|---:|---:|---:|
| periodic-dense-fixture | 0.486 / 0.525 | 0.609 / 0.569 | 0.928 / 0.850 | 0.778 / 0.756 |
| full-rank-field | 0.582 / 0.577 | 0.602 / 0.629 | 0.878 / 0.945 | 0.821 / 0.811 |
| zero | 0.572 / 0.510 | 0.605 / 0.590 | 0.883 / 0.874 | 0.785 / 0.830 |
| identity | 0.532 / 0.588 | 0.574 / 0.632 | 0.824 / 0.874 | 0.794 / 0.780 |
| rank-one | 0.545 / 0.544 | 0.587 / 0.609 | 0.900 / 0.916 | 0.775 / 0.774 |
| sparse-diagonal | 0.564 / 0.595 | 0.649 / 0.647 | 0.910 / 0.857 | 0.787 / 0.801 |
| zero-left-rank-one-right | 0.573 / 0.530 | 0.640 / 0.635 | 0.874 / 0.817 | 0.762 / 0.760 |
| rank-one-left-zero-right | 0.647 / 0.543 | 0.584 / 0.736 | 1.040 / 0.982 | 0.817 / 0.902 |
| genesis-maintenance | 0.593 / 0.621 | 0.651 / 0.638 | 1.034 / 0.855 | 0.826 / 0.773 |

### Every supported specialized kernel

Unsupported combinations remain in the complete CSV/JSON with their measured setup costs. This table includes every specialized strategy on each material that it actually supports; it does not choose the fastest strategy after observing the result.

| Material / fixed strategy | H1 cold, native | H256 cold, native | H256 reuse, native | H256 reuse, harder |
|---|---:|---:|---:|---:|
| zero / structured | 0.703 | 0.708 | 0.679 | 0.697 |
| zero / blocked-zero | 0.480 | 0.444 | 0.444 | 0.457 |
| zero / blocked-zero-integer-paired | 0.752 | 0.711 | 0.676 | 0.575 |
| identity / structured | 0.557 | 0.554 | 0.524 | 0.585 |
| rank-one / structured | 0.611 | 0.618 | 0.583 | 0.545 |
| sparse-diagonal / structured | 0.552 | 0.566 | 0.573 | 0.563 |
| zero-left-rank-one-right / structured | 0.590 | 0.587 | 0.565 | 0.538 |
| zero-left-rank-one-right / blocked-one-zero-rank-one | 0.695 | 0.594 | 0.577 | 0.520 |
| rank-one-left-zero-right / structured | 0.578 | 0.616 | 0.572 | 0.588 |
| rank-one-left-zero-right / blocked-one-zero-rank-one | 0.526 | 0.567 | 0.614 | 0.555 |
| genesis-maintenance / maintenance-split-limb | 0.551 | 0.559 | 0.559 | 0.507 |
| genesis-maintenance / maintenance-periodic | 0.601 | 0.599 | 0.561 | 0.559 |
| genesis-maintenance / maintenance-prefix | 1.096 | 1.174 | 1.036 | 0.857 |
| genesis-maintenance / maintenance-integer-paired | 0.826 | 0.862 | 0.820 | 0.742 |

The batch changes the comparison. For native maintenance at H256, split-limb costs 0.559 ms/attempt against general 0.748 ms with cold preparation, but 0.559 against 0.593 ms after both reuse preparation. The observed reference/strategy CPU ratios are about 1.34 and 1.06 respectively. For the zero fixture, blocked-zero costs 0.444 ms/attempt against 0.572 ms for reused general at H256. The rank-one structured strategy is 0.583 ms versus reused general 0.545 ms in the same H256/native context. The observation therefore does not support treating every structural shortcut as uniformly faster, or interpreting a cold H1 advantage as a persistent amortized advantage.

Failed searches materially change the unit cost. In the H256/reuse maintenance reference across two rounds, the native target has 1,055 attempts, 509 wins and 3 exhausted searches: 0.593 ms/attempt but **1.230 ms per win**, including unsuccessful searches. At the harder target it has 3,671 attempts, 119 wins and 393 exhausted searches: 0.621 ms/attempt but **19.155 ms per win**. Both denominators and both rounds remain in the complete tables. These field-matrix fixtures do not establish the cost of arbitrary quantized, sparse or low-rank real LLM jobs.

### Exact-product reject-only comparison

The same native maintenance proof was altered into 64 distinct wrong-product claims. The original verifier took 77.268 ms total; the new filter took 1.712 ms total, plus 0.280 ms once for the independent exact-product fact. Order alternated between original and filtered paths. The immutable fact occupies 49,216 software bytes. This is a specific wrong-C observation; an attacker retaining the correct public A/B/C and forging the transcript still reaches full W1 verification, as the ingress campaign below deliberately exercises.

## Unique false-trace ingress, honest interleaving and cold reopen

[Native capture](ingress-105s/capture.json) · [Complete raw JSONL, gzip](ingress-105s/stdout.jsonl.gz) · [Strict consistency result](ingress-105s/consistency.json)

The actual run used a 15-second honest cold baseline, 45 seconds of attack after a cold reopen, then another 45 seconds after a second cold reopen. There were two independent receiver Nodes, each with two TCP listeners sharing that receiver's original CPU/intake owners, four malicious workers and one honest worker. One real W1 seed was acquired once. Each adversarial packet then used the correct original A/B/C but a newly fabricated target-winning trace and fresh caller identity; the same newly prepared packet was fanned out once to each receiver. Identity checks found no repeated packet at a receiver and no missing receiver observations. Every transport reported zero hash trials.

| Phase | Honest accepted calls / calls | Distinct honest packets accepted by both receivers | Honest p99 | Accepted receiver calls/s | Distinct malicious packets / refused receiver calls |
|---|---:|---:|---:|---:|---:|
| Honest cold | 478 / 478 | 239 | 68.910 ms | 31.849 | 0 / 0 |
| Attacked cold reopen | 784 / 784 | 392 | 175.711 ms | 17.371 | 1,518 / 3,036 |
| Second attacked cold reopen | 732 / 732 | 366 | 131.831 ms | 16.258 | 1,689 / 3,378 |

All **3,207 distinct invalid packets / 6,414 receiver calls** were refused with `WORK:Transcript`; none was accepted. Malicious-call p99 was 257.662 ms and 167.949 ms in the two attack phases. The packet-count guard did not end any phase early. Goodput denominators include client deadline tails. Each honest packet in this test is an empty sibling of the fixed genesis parent: height remains 1, so these rates are **validation/admission service observations, not chain growth, transaction TPS or finality throughput**.

All six receiver epochs began with exactly zero stored CPU credit. Each receiver retained the same policy of 250,000,000 ns CPU refill per second, a 2,000,000,000 ns storage cap and two worker slots. The first attack charged about 11.187 and 10.847 CPU seconds at the two receivers; the second charged 11.074 and 10.860. Each recorded flow equation balanced, settlement tail was charged once, and all live-owner/reservation counters returned to zero. This establishes those observed local-accounting properties; it does not provide one global budget shared across unrelated machines or guarantee honest service against arbitrary Sybils.

Across the two attack phases, measured malicious packet preparation was 4.966 CPU seconds and client transport was 9.319 CPU seconds; seed acquisition adds 0.006 seconds once. The corresponding measured receiver dispatch intervals total 22.377 CPU seconds. The observed two-receiver dispatch/sender ratio is about 1.566. The nested full-W1 intervals total 7.861 CPU seconds and **must not be added** to dispatch. Reactor CPU and physical network cost are outside those interval measurements; this is not a bound on the cheapest attack, its economic profit or fanout to an unlimited number of machines.

## Reproduction, retained failures and verification

Use the committed capture/reader commands described in [the campaign protocol](../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_COST_CAMPAIGNS_V1.md). The two smoke captures are retained separately and are not substituted for either full run. `summarize_pure_pon_cost_campaign.py` emits every fixed group, unsupported setup included; ratios compare only the same material/target/horizon/preparation policy. Neither timing quality nor source authenticity is established by the reader itself.

The original compile failure (two return-type mismatches, six missing observation fields) is retained as a compact observed-diagnostic record. The original CLI test assertion failure is retained with its actual log; the assertion was fixed to reflect the CLI's existing top-level response and the corrected native CLI test passed in the tool session. That previous pass was not silently re-recorded against an updated shared binary. The original seven bootstrap/pure-profile unit checks have their real logs; the later integration owner runs final-source gates separately. The Cargo SQLite I/O-boundary build warning remains unqualified and is not closed by these tests.

Evidence inventory also found an unattributed incomplete raw sibling of the ingress output. It is a strict 7,560,711-byte prefix of the complete captured stream, not a different run. It was losslessly retained as [incomplete-prefix.jsonl.gz](ingress-105s/incomplete-prefix.jsonl.gz), with its own [provenance limitation](ingress-105s/incomplete-prefix.json); the strict reader rejects it as `incomplete campaign`. Only the complete gzip matching the capture hash contributes to results. No partial tail is promoted to a pass.

The combined evidence-reader suite has 15 passing tests. Its negative cases reject dropped losing attempts, omitted strategy cohorts, broken paired streams, false native scope, forged CPU zeroes, dropped receiver calls, repeated packets, reminted restart credit, hidden settlement tails, false invalid acceptance, manipulated percentiles and shortened duration/qualification claims. These tests check accounting and evidence interpretation, not a mathematical work lower bound.

Remaining blockers include a proof or defensible reduction relating W1 acceptance to non-amortizable cost, unrestricted-network service behavior and a typed permissionless supply of useful neural tasks. Public maintenance remains **zero useful-model credit**. Finite successful observations do not close those blockers.
