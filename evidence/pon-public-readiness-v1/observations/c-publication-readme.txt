# Source-bound local engineering evidence

Measured source: `1213a8bea81dc47cce5345971a99235b67d1ad6d`; tree: `d343c8f5b1738204e169ecb116fc8a626549e732`.
The root qualification records all 15 commands, the existing 48-command native/reference
regression, tool versions, source/binary hashes, raw packets, actual durable databases,
measured outcomes and failure denominators. Source/runtime/config/workflow bytes must
still match that commit. Later documentation/evidence publication is not a new measurement.

**Public network readiness, production activation, independent acceptance, future-window
acceptance, qualified work hardness and physical power-loss acceptance remain false.**
This is candidate engineering evidence, not authorization to launch a public network.

## Live continuous transfer observations

Each case uses 20 blocks of 256 signed tag1 transfers at 10-second pacing, then 6 empty
confirmation-drain blocks. Two durable owners run on one host through real TCP.
The client independently observes transaction membership and local depth/work policy.
The workload is closed loop with no transaction RPC/mempool, WAN or saturation claim.

| Case | Confirmed transfers | Whole-campaign confirmed transfers/s | Inclusion p95 ms | Confirmation p95 s | Two-owner ledger bytes |
|---|---:|---:|---:|---:|---:|
| hot-legacy | 5120 | 20.471 | 58.141 | 60.074 | 4964352 |
| hot-protected | 5120 | 20.471 | 214.248 | 60.224 | 4964352 |
| disjoint4-protected | 5120 | 20.462 | 142.707 | 60.365 | 5038080 |
| growth-protected | 5120 | 20.219 | 2368.255 | 62.824 | 9945088 |

Inclusion-window rates are separately retained in each summary. Front-edge inclusion
windows and the whole campaign have different denominators. Twenty block samples permit
empirical p95 resolution only; p99 and confidence guarantees are unavailable. Measurements
use CPU work; deployment GPU/VRAM remains unmeasured. Ledger bytes exclude measurement
artifacts. Both SQLite owners are closed and checkpointed before final disk observations.

## Protected ingress and model scope

The four 10-second socket phases are baseline, unpaid false transcript, paid false
transcript, and rotating partial-Hello/body-hold occupancy. The v2 log separates one
request template size, successfully written attacker bodies and unknown write outcomes.
It retains all honest attempts/failures/retries and all attacker connection outcomes.
The campaign submits pre-generated distinct empty blocks; it does not measure online
mining or business-transaction confirmation under attack. No universal fairness or attacker
lower bound follows from observed service success. Paid false proofs still require full rejection.

The attribution campaign actually runs the existing small integer classifier trainer and
consumer on retained public retrospective inputs. Functional-copy, rank-padding,
repeat/stale/re-execution and controlled complementary-group cases are replayed.
It is not an LLM forward/decode runtime, independent future-task experiment or public reward.
The four new reference suites also test attribution, utility accounting, evaluator lifecycle
and the LLM adapter material contract. Off-chain lifecycle observations are not native rewards.

## Preserved failures and version boundaries

`observations/failed-qualification-a` preserves the first incomplete run: its original
historical corpus Git object was missing. Exact declared corpus preparation was added;
the original log/source/failed flags remain unchanged.

`observations/pre-correction-b` preserves the second complete command run. Its original
aggregate checker exited 1 (`baseline attack contamination`) because it confused serialized
request template length with total attacker body traffic. The attached original-checker
log was reproduced using its exact detached measured source; it is not a dirty-source
substitution. The v2 accounting fixes that distinction with negative and real-socket tests.
This predecessor also records a growth-workload caller bottleneck: eager nonce lookup
reloaded authenticated state per transfer. Current code reads once per sender per block.
Both runs retain remaining persistence/query costs and make no public throughput claim.

Nested original manifests, qualifications and logs are immutable. The root manifest adds
their byte hashes solely as preserved observations; it does not grant them current acceptance.
Earlier repository evidence packages are likewise unchanged and use historical validation.

The current acceptance requirements and remaining engineering/owner dependencies are in
[PUBLIC_READINESS](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md).
Validate the published package with `python3 scripts/ci/check_public_readiness_evidence.py`
from a tracked checkout with the pinned Python dependencies and original Git objects available.
