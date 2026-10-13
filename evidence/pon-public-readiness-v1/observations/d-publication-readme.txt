# Source-bound local engineering evidence

Measured source: `a77db766925029f92886c851eca8494e4257a497`; tree: `32842e0717c495de999e9cfa057853055aa471bf`.
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
| hot-legacy | 5120 | 20.471 | 61.952 | 60.074 | 4964352 |
| hot-protected | 5120 | 20.470 | 150.139 | 60.164 | 4964352 |
| disjoint4-protected | 5120 | 20.468 | 529.770 | 60.544 | 5038080 |
| growth-protected | 5120 | 20.260 | 2210.112 | 62.651 | 9945088 |

Inclusion-window rates are separately retained in each summary. Front-edge inclusion
windows and the whole campaign have different denominators. Twenty block samples permit
empirical p95 resolution only; p99 and confidence guarantees are unavailable. Measurements
use CPU work; deployment GPU/VRAM remains unmeasured. Ledger bytes exclude measurement
artifacts. Both SQLite owners are closed and checkpointed before final disk observations.

## Protected ingress and model scope

The four 10-second socket phases are baseline, unpaid false transcript, paid false
transcript, and rotating partial-Hello/body-hold occupancy. The v2 log separates one
request template size, successfully written attacker bodies and unknown write outcomes.
It preserves high-level honest/attacker attempt outcomes and retry-inclusive elapsed
times, plus aggregate server socket/refusal counters; individual reconnect attempts
are not separately attributed.
The campaign submits pre-generated distinct empty blocks; it does not measure online
mining or business-transaction confirmation under attack. No universal fairness or attacker
lower bound follows from observed service success. Paid false proofs still require full rejection.

The attribution campaign actually runs the existing small integer classifier trainer and
consumer on retained public retrospective inputs. Functional-copy, rank-padding,
repeat/stale/re-execution and controlled complementary-group cases are replayed.
It is not an LLM forward/decode runtime, independent future-task experiment or public reward.
The four new reference suites also test attribution, utility accounting, evaluator lifecycle
and the LLM adapter material contract. Off-chain lifecycle observations are not native rewards.

## Updated dependency and exact-source gate

This run uses cryptography50.0.2 and records its actual bundled OpenSSL/CFFI alongside
NumPy/Python. The exact dependency pins are checked against both outer and baseline
observations. The source-preparation log is checked against declarations read from the
measured Git snapshot, rather than the subsequently published root manifest. Preparation
also retrieves the root measurement source after squash publication without importing
arbitrary nested observation declarations.

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

`observations/pre-correction-c` preserves the third raw qualification: all15 commands
and actual aggregate replay passed on its original1213 source/environment. The later
published CI job failed because it combined `--historical` with the current-only
`--native-node` flag. The original failure log and publication manifest/README are retained
separately; the README snapshot uses a.txt extension to preserve its bytes without
reinterpreting relocated relative Markdown links. This run fixes that selector and upgrades
the vulnerable41.0.7 conformance pin to50.0.2. It does not relabel C as the new environment.

Nested original manifests, qualifications and logs are immutable. The root manifest adds
their byte hashes solely as preserved observations; it does not grant them current acceptance.
Earlier repository evidence packages are likewise unchanged and use historical validation.

After this raw D qualification and aggregate replay, the full publication CI job failed
in the historical native-session negative-test setup: it compared closed-round source
against the newer runtime. The original failure log is retained in
`observations/d-publication-external-evidence-failure.log`. This 15-command qualification
is not a passing whole-publication CI claim. A later source change requires its own
qualification; D may only be used with its exact measured source and environment.

The current acceptance requirements and remaining engineering/owner dependencies are in
[PUBLIC_READINESS](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md).
Validate the published package with `python3 scripts/ci/check_public_readiness_evidence.py`
from a tracked checkout with the pinned Python dependencies and original Git objects available.
