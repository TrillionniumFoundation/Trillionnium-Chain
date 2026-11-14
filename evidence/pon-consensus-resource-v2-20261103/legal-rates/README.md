# Retrospective finite legal-work rates

**Record readback PASS; qualification HOLD.** This is a new analysis of the
[existing complete V3 capture](../../pon-w1-factorial-v3-20261102/README.md).
No native producer or verifier was executed and no new timing was measured.

The measured native source remains `2b250859e7c07088e6c3c01f75006372c684de61`,
tree `12c414a565f58fde6e98ec6eba503d9389ddd06f`, with native binary SHA-256
`e075ff7ff0dd04f9ad9d02855ad6f31b38414be617c4cb417c69497bff5b1c53`.
The current reader is separately identified by SHA-256
`88657a45b22a350c140ae8bcbe7f294544e8d9788c86592238cc9c6437bd58ff`.
Its source bytes were unchanged across readback; no final candidate commit or
new-source native qualification is inferred.

[Provenance](provenance.json) binds all eight compressed archive parts, the
assembled archive, every legal input, historical execution metadata and current
reader/helper/profile sources. All **84 archive members** were hashed; only the
**30 legal factorial shards** were parsed by the updated reader. Every original
shard-reader field matches its retained historical result. Complete-grid and
shared-prefix checks passed. Temporary raw inputs were removed after each shard.

## Complete denominators

[rates.json](rates.json) retains all **120 fixed-strategy groups and 960 sample
cohorts**, with no removed samples and no semantic alerts. Their actual recorded
invocations contain 960 setups, 23,360 searches, 389,788 complete attempts,
23,360 target hits and zero exhausted searches. The four verifier paths record
93,440 legal `Accepted` outcomes and 93,440 separate `Product` refusals.
A target hit counts once in the rate, rather than once per verifier call.

All **61 historically flagged timing groups** are preserved. The new diagnostic
also retains **66 sample cohorts whose raw CPU cost exceeds twice the median of
their own strategy/shard group**. This descriptive comparison includes different
paid attempt counts and does not identify a causal slowdown or justify removing
samples. All 5,120 indexed search streams remain covered; repeated strategy and
horizon observations do not become independent work.

For each fixed class, target, horizon and strategy, rates divide complete counts
by the sum of inclusive producer **thread CPU** intervals. Actual setup, losing
attempts, exhaustion and the cell's materialization work stay in that denominator.
Common material preparation, evidence construction, verification, transport and
node execution retain their separate scopes. No rate is pooled across horizons,
and no per-sample fastest strategy or mean of sample rates is substituted.

## Selected fixed-grid observations

Each row below contains all eight samples and 512 hits at reuse horizon **64**.
The complete exact integer fractions are in `rates.json`; displayed rates are
rounded to two decimals. Target 0 has required weight 2; target 1 has weight 32.
The work-equivalent column multiplies recorded relation-valid hits by that
weight. These standalone relation fixtures provide **no admitted ledger
chainwork, service throughput, network work share or confidence bound**.

| Class / target | Fixed strategy | Producer CPU (s) | Hits / CPU s | Hypothetical work-equivalent / CPU s |
| --- | --- | ---: | ---: | ---: |
| full-rank-field / 0 | eager-transposed | 0.497802278 | 1028.52 | 2057.04 |
| full-rank-field / 0 | lazy-transposed | 0.506306977 | 1011.24 | 2022.49 |
| full-rank-field / 0 | eager-full-limb | 0.378837431 | 1351.50 | 2703.01 |
| full-rank-field / 0 | lazy-full-limb | 0.370960298 | 1380.20 | 2760.40 |
| zero / 0 | eager-transposed | 0.522452415 | 979.99 | 1959.99 |
| zero / 0 | lazy-transposed | 0.659306687 | 776.57 | 1553.15 |
| zero / 0 | eager-full-limb | 0.389088027 | 1315.90 | 2631.80 |
| zero / 0 | lazy-full-limb | 0.797971203 | 641.63 | 1283.25 |
| continuity-maintenance-v1 / 1 | eager-transposed | 7.734044449 | 66.20 | 2118.43 |
| continuity-maintenance-v1 / 1 | lazy-transposed | 7.791827717 | 65.71 | 2102.72 |
| continuity-maintenance-v1 / 1 | eager-full-limb | 6.034121456 | 84.85 | 2715.23 |
| continuity-maintenance-v1 / 1 | lazy-full-limb | 5.757968762 | 88.92 | 2845.45 |

The zero/target-0/horizon-64 group preserves sample 5: eager FullLimb uses
47.028051 ms CPU and lazy FullLimb 458.632492 ms, each paying 133 complete
attempts for 64 hits. Its +411.604441 ms difference remains within the group's
+408.883176 ms net difference. The source capture already contained this
observation; the new rate display neither explains its cause nor establishes
a stable regression. Lazy materialization has no uniform throughput benefit
across these retained cases.

## Reproduce this readback

From the repository root, select a fresh output directory:

```sh
python3 -B evidence/pon-consensus-resource-v2-20261103/legal-rates/readback.py --out /tmp/pon-legal-rates-readback
```

The script streams the existing archive, temporarily retains one legal shard,
checks its full historical output and writes compact rates and provenance. It
refuses to overwrite an existing rates/provenance result. It never launches the
retained native executable. Byte consistency cannot authenticate historical
clocks or establish cheapest-work, hardware, learning, public-service or
production qualification; all original false qualification flags remain false.
