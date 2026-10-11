# Same-target costs on the native-session source

Measured clean implementation: `1a512c613951af5640dac06cc663392d08927e00`.
Measured tree: `be23902744141ca769d1b11b3a0f50d8b62a4ed3`.
Binary SHA256: `6ff2ae3b1e68ebcfb80820b5225f8c7226e3d04a7c027ed1a873c7cd42bf0756`.

The original collector built and ran the actual native example with locked/offline
dependencies. All four structured classes use the same committed half-range target.
These are new measurements; the older contract-authority costs remain historical.
Raw outputs, command exits, full source inventory and derived summaries are retained.

| Class | Samples | Invalid rejection / forgery | Honest winner / valid verification |
|---|---:|---:|---:|
| dense | 8 | 557.91 | 1.86 |
| rank-one | 8 | 544.68 | 2.36 |
| sparse | 8 | 572.29 | 2.79 |
| zero | 8 | 531.06 | 1.40 |

Ratios compare medians within each class and target, not public attack rates.
The uniform-ticket probability is conditional, not a qualified hardness claim.
Fastest adversarial shortcuts, public honest-service fairness, independent
operators, GPU memory and production activation are not established.

Verify current inputs with `python3 scripts/pon_work_cost_report.py --verify evidence/pon-native-session-v1/work-cost`.
Use `--historical` only to check retained observations without current applicability.
