# Original F0: actual v2 CPU and owner-lifecycle coverage

This readback uses the repository functions `cpu_settlement_summary`, `request_owner_lifecycle_summary`, and `stats` directly on the unchanged original confirmation report. No native program or test was rerun. The input report SHA-256 is `3e7ca3825361fe9df23d3827c92af5f6411316c2e42f1a4085fcc05a2aef024d`; its identity matches the original finalized manifest. Counts below retain all **644 actual receiver records**: 95 baseline and 549 pressure.

## Settlement population

| Original cohort | Retained records | v2 extension | Legacy v1 | Missing extension | v2 fields unknown |
|---|---:|---:|---:|---:|---:|
| Baseline | 95 | 7 | 0 | 88 | 0 |
| Pressure | 549 | 442 | 0 | 107 | 0 |
| Combined | 644 | 449 | 0 | 195 | 0 |

Every numeric field below has known/unknown coverage **7/88** in baseline, **442/107** under pressure, and **449/195** combined. All unknowns here come from missing extension scope; none of the 449 retained v2 records has an unknown numeric field. Missing scope is not measured zero.

| Original value, known sum in ns | Baseline | Pressure | Combined |
|---|---:|---:|---:|
| `owner_cpu_ns` | 37,930,700 | 978,043,461 | 1,015,974,161 |
| `scoped_worker_cpu_ns` | 0 | 0 | 0 |
| `total_cpu_ns` | 37,930,700 | 978,043,461 | 1,015,974,161 |
| `live_paid_cpu_ns` | 37,927,495 | 977,681,021 | 1,015,608,516 |
| `residual_cpu_ns` | 3,205 | 362,440 | 365,645 |

All 449 observed settlements succeeded; all have no continuous-journal scope. This does not establish native dispatch success. In particular, **435 rejected pressure records** retain known original total CPU of **854,722,222 ns**. Pressure accepted records retain seven known totals summing **123,321,239 ns** and 92 unknown totals; its 15 unknown dispatch outcomes retain 15 unknown totals. The 435 rejected records are not removed from either cost or request denominators.

## Owner closure and wall-tail population

| Observation | Baseline | Pressure | Combined |
|---|---:|---:|---:|
| Lifecycle records / retained records | 95/95 | 549/549 | 644/644 |
| Connection closed, created task also closed | 95 | 534 | 629 |
| Connection closed, created task still open | 0 | 0 | 0 |
| No task created | 0 | 15 | 15 |
| Known task-ownership wall tails | 95 | 534 | 629 |
| Unknown eligible tail clocks | 0 | 0 | 0 |
| Task closed strictly after connection | 0 | 0 | 0 |
| Eligible tail minimum / maximum / sum, ns | 0/0/0 | 0/0/0 | 0/0/0 |

The original reader clamps a task that closed before its connection to a measured zero wall tail. The 15 records without a task are outside that eligible tail cohort; they are not inserted as zero-duration task samples. No positive post-close cohort occurred here, so its CPU sample cohort is empty, not an observed zero CPU cost. No task remains open in this final snapshot.

## Scope

Known worker samples are genuinely zero in this campaign, so known total equals the separately retained owner sample. This equality is not used to reconstruct the 195 missing totals. The measurements exclude reactor CPU and later budget/journal work; the overlapping settlement phase cannot be added. Task ownership includes buffered completion, wall tails are not CPU, and connection closure does not timestamp cancellation. This campaign demonstrates real v2 coverage and retained rejected-work costs; it does not demonstrate nonzero post-cancellation worker drain. The separate cancellation unit test covers that behavior. No whole-request CPU, population p99, or confirmation TPS is inferred.
