# Retained sample diagnostic: zero / target 0 / reuse 64

Measured source: `2b250859e7c07088e6c3c01f75006372c684de61`. This is a read-only analysis of the completed local 8 CPU / 8 GiB V3 campaign. It does not rerun the producer, change native receipts, remove samples, or replace the original thirty-shard totals.

## Observation

Across all eight samples, lazy FullLimb used 797.971203 ms producer CPU versus eager FullLimb 389.088027 ms: **+105.087576%**. The same lazy FullLimb arm exceeded lazy transposed by **+21.031869%**.

The large positive contribution is concentrated in sample 5. Its lazy FullLimb producer CPU is 458.632492 ms, or 57.474817% of that arm's eight-sample total. Its difference versus eager FullLimb is +411.604441 ms, exceeding the whole-shard net difference of +408.883176 ms. The other seven signed differences sum to -2.721265 ms.

Against lazy transposed, sample 5 contributes +393.545818 ms, while the full eight-sample net difference is +138.664516 ms. All seven other sample differences have the opposite sign and sum to -254.881302 ms. These signed sums locate the concentration; they are not a filtered performance estimate.

**Cause remains unassigned.** Matching streams and equal paid-attempt counts establish comparable work records. They do not identify why this timing observation is larger. No inference is made about scheduler behavior, clocks, allocation, thermal state, kernel stability, or a durable regression/speedup.

## Eight matched samples

CPU values are milliseconds of the complete producer interval, including setup and all winning/losing attempts. All four arms share the recorded nonce stream within each row. Each row has 64 successful searches per arm and no exhaustion. Paid attempts include all misses. The strict pinned reader confirms full-stream matching and no semantic alerts.

| Sample | Paid attempts / arm | Eager transposed CPU ms | Lazy transposed CPU ms | Eager FullLimb CPU ms | Lazy FullLimb CPU ms | Lazy vs eager FullLimb | FullLimb vs transposed, lazy |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 123 | 51.103590 | 145.312827 | 58.983813 | 52.506019 | -10.9823% | -63.8669% |
| 1 | 135 | 61.228897 | 87.589313 | 53.301487 | 63.713674 | +19.5345% | -27.2586% |
| 2 | 128 | 58.397923 | 76.227529 | 53.975157 | 52.662884 | -2.4313% | -30.9136% |
| 3 | 110 | 63.624882 | 59.910719 | 50.442853 | 33.774935 | -33.0432% | -43.6246% |
| 4 | 108 | 59.890583 | 72.682396 | 35.285112 | 47.748008 | +35.3206% | -34.3060% |
| 5 | 133 | 90.794418 | 65.086674 | 47.028051 | 458.632492 | +875.2318% | +604.6488% |
| 6 | 126 | 59.328845 | 76.022639 | 42.364598 | 39.976733 | -5.6365% | -47.4147% |
| 7 | 134 | 78.083277 | 76.474590 | 47.706956 | 48.956458 | +2.6191% | -35.9834% |

Totals per arm: 8 actual setups, 512 searches, 997 complete attempts, 512 target hits, 485 misses, 0 exhausted searches. Four verifier paths yield 2,048 Accepted legal verifications and 2,048 Product rejections per arm.

## Interpretation retained in the full report

- All eight samples and all thirty configurations remain in the results. This diagnostic neither censors sample 5 nor supplies a replacement/trimmed estimate.
- Separately measured attempt-evidence CPU does not remove the exceptional direction: this shard remains +100.470330% lazy versus eager FullLimb and +20.468152% FullLimb versus transposed for lazy, on the producer-plus-measured-evidence subtotal.
- In the original full campaign, eager FullLimb producer CPU is lower than eager transposed in all 30 configurations. This statement describes that retained campaign only; it does not establish a universal speedup.
- The full-campaign aggregate lazy FullLimb change must not be described as a stable 1.44% regression. The retained per-configuration and per-sample dispersion remains material.
- Qualification remains HOLD. No fastest-adversary lower bound, independent hardware qualification, or original public Host acceptance follows.

Inputs: `analysis.json` and `independent-reader-readback.json` in this directory; their SHA-256 values, exact nanosecond CPU/wall values, and the complete paired arithmetic are retained in `zero-target0-reuse64-sample-diagnostic.json`.
