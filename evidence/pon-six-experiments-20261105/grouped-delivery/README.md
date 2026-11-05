# Experiment 4: paired complete local delivery observation

Initial base: integration candidate `f9977c5d6d1b57880967ef36dcd1570010cbbe4f`.
This continues the existing integer grouped relation and owners. It is an actual
Python/NumPy execution over the existing frozen model, task partition and
evaluation bundle. It is **not** native Rust, CUDA Grouped-GEMM, ordinary Hepta,
external request demand, or original fixed-Host service acceptance.

The [runner](../../../formal/pon-nakamoto-v1/experiments/grouped_delivery_cost_v1.py)
compares selected direct contractions with packed grouped contractions. Both
produce the complete router, route, ordered group, logits and prediction result.
After canonical serialization and decode, an independent scalar implementation
recomputes the complete relation using the original base and delta coefficients.
Each arm actually reloads and validates model/tasks/bundle, prepares merged
weights, commits inputs and outputs, serializes, decodes and fully verifies.
Phase times are subsets of the total and are not added twice.
Source/input evidence hashing and diagnostic journal/report persistence occur
outside the per-delivery timer; they are not included in the compared CPU ratios.

## Observed results, with the complete denominator

The corrected v2 observation contains 48/48 planned arm executions: four batch sizes,
six repeats, and two arms with alternating execution order. All 48 produce exact
outputs within the declared **local diagnostic** four-second budget. All 1,020
request occurrences are retained. There are only 64 distinct retrospective
input rows; repetitions and arm copies do not create new business demand.

| Batch size | Packed/direct paired CPU median | Packed/direct aggregate CPU | Paired ratio range |
| --- | ---: | ---: | --- |
| 1 | 1.029 | 1.061 | 0.921–1.190 |
| 4 | 1.040 | 1.058 | 0.853–1.536 |
| 16 | 1.060 | 1.054 | 0.903–1.313 |
| 64 | 0.972 | 1.001 | 0.922–1.101 |

A value below one favors packed execution for that statistic only. The broad
ranges and differences between aggregate and median costs are retained. This
shared-host sample does not establish a stable speedup. Loading and independent
verification materially affect the delivered-work cost. Earlier observations
are retained separately; they are not replaced by the most favorable repeat.

A separately declared one-millisecond negative control executes all eight arms
and retains all 170 request occurrences. Each output is mathematically exact but
late; zero outcomes receive timely-delivery credit, and all speedup fields are
null. This is a reader/deadline negative control, never a changed F0 threshold.

## Reproduction

From the repository root, after project preflight:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_grouped_delivery_cost_v1.py' -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 formal/pon-nakamoto-v1/experiments/grouped_delivery_cost_v1.py --repetitions 6 --out /tmp/pon-grouped-delivery-new
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 formal/pon-nakamoto-v1/experiments/grouped_delivery_cost_v1.py --repetitions 1 --budget-ms 1 --out /tmp/pon-grouped-late-new
```

Twenty delivery controls check both implementations against independent
arithmetic, reject rehashed wrong outputs, bind paired identities and deadlines,
retain failed/missing samples and reject false timely-delivery claims. Existing
`test_grouped*.py` CI discovery includes these tests. The complete local grouped
selection reports 50 passing controls and two explicitly skipped native
integration tests because no native executable was available. The twenty
delivery controls are a subset of those fifty, not an additional count. See
[the retained log](grouped-tests-v2.log). These counts are not native execution
or production qualification.

## Review corrections and source identity

The distinct `pon-grouped-local-delivery-cost-v2` namespace fixes four reader
boundaries found by independent review. The budget is supplied from the frozen
plan, so both arms cannot jointly relax it. Independent scalar arithmetic now
uses the actual committed model and requests, with exact envelope/model/row
bindings. Successful observations require real input and product digests.
Zero observed CPU preserves the pair and its unavailable ratio rather than
dropping the pair or crashing a median calculation. Boolean aliases and partial
plans are rejected.

Each v2 run records all 12 loaded repository Python module paths plus four
loaded configuration files before and after execution. Their byte observations
match. These are 16-file observations, not whole-source, interpreter, NumPy,
native-library or loaded-bytecode attestation. The exact frozen source hashes
remain in each plan and report.

The original three v1 directories remain byte-for-byte intact. Their observations
were reanalysed under their originally frozen budgets with the corrected v2
reader; all originally reported counts and statistics agree. Fields absent from
the earliest report are explicitly identified in the reanalysis. The
[readback](v1-reanalysis.json) does not relabel those executions as v2 runs.

## Retained boundary

The original F0 resource envelope and external queue trace were not available in
this local run. OS page-cache state is uncontrolled; these are actual reloads,
not isolated cold-process starts. External queue/fill waiting, process imports,
device loading, WAN transport, PoN proof generation/verification, independent
confirmation and energy remain unmeasured. Full-system cost stays null. No model,
adoption/reward decision, work profile, original budget or activation flag changes.

The [manifest](manifest.json) hashes every original plan, observation journal and
report. `paired-v2-final/` is the corrected-source measurement, and
`late-v2-negative-control/` retains the corrected-source failed deadline cases.
`initial-observation/`, `paired-final/` and `late-negative-control/` preserve the
earlier v1 source hashes and all original outcomes. Journals are local diagnostic
records; no external anti-rollback or power-loss durability claim is made.
Experiment 4's complete original-resource acceptance remains **HOLD**.
