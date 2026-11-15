# Value-pool finite component result

Overall preregistered result: **PASS**.

Data: 700/700 unique planned samples; 10/10 processes. Data quality: PASS.

CPU statistic is the median of five paired candidate/baseline ratios. Each warm process value sums eight correlated complete calls.

| Case | API | Phase | Baseline CPU ms/call | Candidate CPU ms/call | Median paired ratio | Limit | Result |
|---|---|---|---:|---:|---:|---:|---|
| repeated | root | warm | 42.8302 | 6.2687 | 0.1464 | 0.85 | PASS |
| repeated | commitment | warm | 91.8122 | 60.5107 | 0.6210 | 0.95 | PASS |
| unique | root | cold | 139.0444 | 141.2808 | 1.0161 | 1.05 | PASS |
| unique | root | warm | 44.5655 | 45.3908 | 1.0067 | 1.05 | PASS |
| unique | commitment | cold | 194.5594 | 194.3240 | 0.9988 | 1.05 | PASS |
| unique | commitment | warm | 97.7433 | 96.2005 | 0.9739 | 1.05 | PASS |
| collision | root | cold | 146.4254 | 143.0347 | 0.9485 | 1.05 | PASS |
| collision | root | warm | 45.1375 | 42.5983 | 1.0497 | 1.05 | PASS |
| collision | commitment | cold | 192.9147 | 193.8384 | 0.9827 | 1.05 | PASS |
| collision | commitment | warm | 91.8886 | 97.4551 | 0.9864 | 1.05 | PASS |

Separate median CPU columns are descriptive; the acceptance statistic is the median of paired ratios, not the ratio of these medians.

## Data quality and retained observations

All planned processes, reference roots/errors, complete input hashes, unchanged failed-input observations, clocks, and exposed original 2 MiB bounds passed.

| Variant | Case | Retained payload range (bytes) | Retained entries range |
|---|---|---:|---:|
| baseline | repeated | 2094369–2094369 | 445–445 |
| baseline | unique | 2094369–2094369 | 445–445 |
| baseline | collision | 2094369–2094369 | 445–445 |
| candidate | repeated | 455566–459720 | 2100–2100 |
| candidate | unique | 2093030–2093030 | 438–438 |
| candidate | collision | 2093030–2093030 | 438–438 |

## Limits

- Five separately launched process pairs determine the median of paired ratios; eight warm calls within each process are correlated. Statistical independence and p95/p99 behavior are not established.
- Whole-process VmHWM is not the bounded retained material charge and includes setup and references.
- FullRootArithmetic private charge/failed-cache observation is not exposed by the public API; it remains null, with semantic unit controls separate.
- Cold is an empty arithmetic owner after common setup, not cold OS/allocator/global hash state.
- No new gate, threshold, profile, workload, provider, budget or Host-check frequency was changed.

All raw samples, pair ratios, setup costs, change/restore/error timing, whole-process VmHWM and binary/source identities are preserved in benchmark-result.json and measurements/.
