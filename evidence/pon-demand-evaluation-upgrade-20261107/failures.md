# Failures and their disposition

Raw observations are inside `observations.tar.xz`; paths below start at `validation/`.

| Observation | Original evidence | Disposition |
| --- | --- | --- |
| Offline Node build missing `foreign-types 0.3.2` | `node-build.log` | Original locked dependencies fetched through the ordinary configured network; lockfiles unchanged. `cargo-fetch.log` retained. |
| Full Node lib test harness compilation terminated by SIGKILL, exit 101 | `node-build-2.log` | Unresolved qualification gap. This was a pre-freeze development build, without a full exact-source receipt. Do not claim a full Node test pass or a proven cause of the signal. |
| Wrong fuzz manifest path under `trillionnium/tests` | `frozen/fuzz-cargo-graph.{json,log}` | Failed command preserved. Correct root `tests/fuzz/Cargo.toml` graph passed separately on both frozen source versions. |
| Initial seven demand counterexamples | `demand-adversarial-before.*`, `demand-adversarial-before-source/` | Original time-travel dispute/bonus, net-fee outcome dependence, retroactive control audit, same-candidate bonus replay and spent-source queue classifications preserved. Corrected source and final runs are separate. |
| Refund/unresolved queue and no-delivery pay-service cases | `demand-adversarial-refund-{before,after}.{json,log}` | Fixed with explicit dispute/delivery eligibility; refusals preserve snapshots. |
| Audit expiry after observation | `demand-provenance-expiry-{before,after}-result.{json,log}` | V2 observations retain provenance expiry; later queue queries exclude expired attached attestations. Original source pair and runnable probe retained. |
| Evaluator/auditor/adopter as improvement beneficiary | `demand-bonus-recipient-{before,after}-result.{json,log}` | Provider-only improvement beneficiary; valid re-signed contracts cannot route positive-result bonus to a reviewer account. Original script retained. |
| Upgrade development fixture supplied bet greater than 1 | Contemporaneous worker report: 20 passed, 1 error; no raw log available | Corrected the invalid fixture, not the admissible bet rule. This report is not fabricated into a raw observation. Final 23 upgrade tests passed in both frozen runs. |
| Git HTTPS dry-run lacked terminal credentials | `publish-dry-run.log` | Used the existing authenticated GitHub connector, preserved review commits and checked each returned tree; ordinary public Git fetch independently read the result. |

An initial publication payload export exceeded its chosen output budget before any
API mutation; bounded chunk reads replaced it. No runtime pass is inferred from
that transport repair. Source-check negative tests intentionally preserve expected
fixture failures, while the containing test suite must actually exit successfully.

The new Node integration target exercises six local backend scenarios through real
native APIs. It neither reruns the failed monolithic lib harness nor certifies the
SQLite I/O boundary, production economics, real training or external independence.
