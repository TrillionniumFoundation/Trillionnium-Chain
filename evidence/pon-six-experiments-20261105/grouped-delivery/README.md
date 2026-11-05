# Experiment 4: paired complete local delivery observation

Base: integration candidate `f9977c5d6d1b57880967ef36dcd1570010cbbe4f`.
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

## Observed results, with the complete denominator

The final observation contains 48/48 planned arm executions: four batch sizes,
six repeats, and two arms with alternating execution order. All 48 produce exact
outputs within the declared **local diagnostic** four-second budget. All 1,020
request occurrences are retained. There are only 64 distinct retrospective
input rows; repetitions and arm copies do not create new business demand.

| Batch size | Packed/direct paired CPU median | Packed/direct aggregate CPU | Paired ratio range |
| --- | ---: | ---: | --- |
| 1 | 1.104 | 1.543 | 0.500–6.695 |
| 4 | 0.862 | 0.406 | 0.092–1.251 |
| 16 | 0.998 | 1.084 | 0.908–1.488 |
| 64 | 1.201 | 1.847 | 0.762–2.966 |

A value below one favors packed execution for that statistic only. The broad
ranges and disagreement between aggregate and median costs are retained. This
shared-host sample does not establish a stable speedup. Loading and independent
verification materially affect the delivered-work cost. An earlier observation
is retained separately; it is not replaced by the most favorable repeat.

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

The nine new controls check both implementations against independent arithmetic,
reject rehashed wrong outputs, bind paired identities and deadlines, retain
failed/missing samples and reject false timely-delivery claims. Existing
`test_grouped*.py` CI discovery includes these tests. The preexisting local
grouped suites reported 30 passing controls and two explicitly skipped native
integration tests because no native executable was available. These counts are
not native execution or production qualification.

## Retained boundary

The original F0 resource envelope and external queue trace were not available in
this local run. OS page-cache state is uncontrolled; these are actual reloads,
not isolated cold-process starts. External queue/fill waiting, process imports,
device loading, WAN transport, PoN proof generation/verification, independent
confirmation and energy remain unmeasured. Full-system cost stays null. No model,
adoption/reward decision, work profile, original budget or activation flag changes.

The [manifest](manifest.json) hashes every original plan, append-only observation
journal and report. `paired-final/` is the final-source measurement;
`initial-observation/` preserves the earlier source hashes and result;
`late-negative-control/` preserves the separately declared failed deadline cases.
Experiment 4's complete original-resource acceptance remains **HOLD**.
