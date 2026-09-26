# M16 Global Control Plane technical specification v1

Status: **implementation contract; observer-first and non-authoritative**

## Authority

M16 observes versioned module descriptors and measurements, evaluates bounded
local plans and records their effects. It cannot sign, vote, finalize, create
roots, change validator sets or SafetyRules, bypass admission, erase evidence,
rewrite history or activate production. Consensus must continue without M16.
The selected first delivery is **observer-only**; applying plans is disabled.

### Source map and present behavior

`trillionnium/crates/trnm-control-plane-v0/src/lib.rs` implements
`ModuleDescriptorV0`, `WorkloadMeasurementV0`, `ObserverRegistryV0`,
`OptimizationPlanV1`, `ParameterBoundV0`, `LocalPlanGuardV0::evaluate` and
`ActionReceiptV1`. These are pure data/decision contracts, not a networked
controller, persistent generation owner or live reconfiguration service.

`evaluate` checks shape, signature port, source graph, next generation, height
window and parameter bounds; it returns a receipt. It does not apply settings,
advance its own generation or prove caller-supplied result digests correspond to
real configuration. `PlaceIsolatedWorker` is currently rejected; governance or
determinism arguments do not make critical changes supported. Integration must
preserve these restrictions rather than treating an accepted decision as applied.

## Interfaces

### Observation ports and identity

Planned `RegisterDescriptorV1` accepts exact existing `ModuleDescriptorV0` plus
authenticated producer identity. The node guard, not the remote planner, owns
the allowlist mapping module ID to producer and permitted parameters.
Each descriptor binds contract, implementation, dependency graph, config and
invariant digests, generation and sorted capabilities. Same generation/different
digest is substitution; lower generation is rollback. Unknown modules are rejected.

Planned `SubmitWindowV1` adds a measurement envelope around
`WorkloadMeasurementV0`: producer/node ID, source/config/descriptor digests,
workload and validity-region IDs, process-instance ID, monotonic sequence,
window start/end, sample count, drop count and raw evidence digest.
Authentication proves who sent a sample, not whether its value is true.

Existing `ObserverRegistryV0` permits only one immutable measurement per
`(module_id, workload_digest)`. The host uses one registry per sealed window;
the persistence key is `(node,module,workload,window_id)`. It must not overwrite
an old measurement or change workload identity merely to fit a mutable time series.

### Plan and guard ports

`ProposePlanV1` constructs existing `OptimizationPlanV1` fields: source graph,
contract set, workload assumptions, expected effect, rollback plan, generation,
height validity window, actions, signer and canonical digest/signature binding.
Plan signing uses a distinct operational key and `PlanSignatureVerifierV0`.
It conveys no validator or release authority.

Planned `EvaluatePlanV1` runs the local guard in dry-run mode. Its receipt is
labelled `decision_only:true` until actual application readback exists.
Planned `ApplyLocalPlanV1` and `ReadAppliedPlanV1` are future host ports; initial
observer builds expose neither. Every API includes candidate/source/config
identity, so a remote controller cannot silently widen the node's local policy.

### Selected local parameter policy

The table specifies future dev-only application scope. Initial observer mode
rejects **all** application requests with `OBSERVER_ONLY` while retaining proposals.
Bounds are proposed operator-signed local defaults, not production tunables.

| Parameter / class | Future dev adapter policy | Reason |
|---|---|---|
| `M14.rpc_query_concurrency`, OperationalLocal | 1..48; default 32; reserve submission/status capacity outside this pool | Read-only service resource |
| `M14.index_apply_batch_events`, OperationalLocal | 1..1000; default 250; only at completed index transaction boundary | Projection throughput, no canonical mutation |
| `M17.telemetry_sample_interval_ms`, OperationalLocal | 1000..10000; default 1000; noncritical diagnostic export only | Bounded diagnostic overhead |
| Execution worker count / DeterminismCritical | Reject in this version, including 1/2/4/8 changes | Needs M06 invariant evidence and separate deployment config |
| Consensus timeout, quorum, validator weights, block/fee limits | Reject | Native protocol/governance authority |
| Signing, journal retention, replay floors, finality trust anchor | Reject | Safety/durability authority |
| Worker placement, shell commands, URLs, filesystem paths | Reject | Unsupported action or executable payload |
| Queue-size decrease with occupied entries | Reject rather than evict | Never drop acknowledged or durable work |

One application plan changes exactly one field on one node in the initial future
dev adapter. The library's 128-action ceiling is not permission to perform an
unproven distributed transaction. Unknown parameters, aliases and case variants
are errors; no best-effort application of an accepted subset.
The telemetry setting cannot downsample mandatory safety/fault events or the
1 s guard feed below. A deployment that cannot keep those feeds independent
must reject this parameter as `CAPABILITY_UNAVAILABLE`.

## State machine

```text
DescriptorAccepted -> WindowOpen -> WindowSealed -> ProposalRecorded
ProposalRecorded -> GuardRejected | ShadowObserved
future application: ShadowPassed -> CanaryApplied -> Stable | RolledBack | Frozen
```

### Windowing and comparison algorithm

1. Collect a sample each 1 s by default into non-overlapping 10 s monotonic
   windows. Restart starts a new process-instance ID; windows cannot straddle it.
2. Bind each window to one source/config/descriptor and workload/validity-region
   tuple. A change closes the current window as incomplete; never mix distributions.
3. Require at least 8 samples and no more than 2 missing samples per 10 s window.
   Counter decreases without process restart, nonfinite values, impossible
   percentiles (`p50>p95` or `p95>p99`) and queue pressure >1000 are rejected.
4. Aggregate counter deltas, bytes and histogram counts, not averages of p99s.
   Use the histogram/quantile contract in M17; retain sample count and units.
   No finality samples means `insufficient_data`, not zero finality latency.
5. Use six consecutive complete windows as the 60 s baseline. Compare only
   windows with the same explicit workload shape/rate and validity-region ID.
   Uncontrolled production traffic is advisory; causal improvement is not asserted.
6. Observe the proposed change in shadow for another six windows without
   applying it. Verify configuration/resource feasibility and build a signed
   proposal with baseline, thresholds and exact rollback configuration digest.

Observer mode stops here. The controller may rank proposals; it cannot execute
them. A low-latency workload does not overrule a safety or durability violation.

### Future local application algorithm

1. Read node-local mode, immutable allowlist, current descriptor/config and
   durable generation. Require a valid independent operational signature,
   unexpired height window and issued generation exactly `current+1`.
2. Run existing `LocalPlanGuardV0::evaluate`. Require every action accepted.
   Ignore remote claims of permission to change consensus/determinism classes.
3. Recompute the proposed resulting config and invariant digest locally. Validate
   memory/concurrency sums and service-reservation floors; compare with the plan.
4. Check actual config digest still equals the planned predecessor. Wait at most
   5 s for the relevant query/index batch boundary; otherwise `APPLY_BUSY`.
5. Persist `ApplyIntent(plan,old_config,new_config,generation)` before mutation.
   Atomically replace the one local setting; read it back; persist Applied receipt.
   Do not acknowledge `Applied` from a decision-only receipt.
6. Canary exactly one node at a time for twelve complete 10 s windows. Do not
   expand to another node until canary passes and an operator authorizes a new
   plan. This version has no autonomous fleet rollout.
7. Persist Stable only after all thresholds pass. Consume the generation even
   when later rolled back; an old plan cannot be replayed against restored values.

### Guard and rollback thresholds

For the proposed development canary, any safety/determinism/durability alarm or
config readback mismatch immediately freezes application and requests rollback.
Two consecutive complete windows with service p99 >120% of matched baseline,
error ratio increased by >1 percentage point, or queue pressure >900/1000 also
trigger rollback. Three missing/incomplete windows trigger rollback because the
canary cannot be assessed. These are conservative **dev experiment thresholds**,
not guarantees about the network's latency or capacity.

Rollback CAS requires the current digest to equal the applied target. Restore
only the previously verified local setting, wait for its safe batch boundary,
read back and persist a RolledBack receipt. If config differs, I/O is uncertain,
or the old limit cannot be restored safely, enter Frozen and require operator
repair. Never roll back chain state, signatures or external evidence. A canary
failure ends that experiment; automatic alternating retries are forbidden.

## Persistence and recovery

The planned host stores descriptors/windows/plan intents/receipts append-only
in a service namespace, not in the consensus database. Each record includes
sequence, previous digest and source/config identities; snapshots are rebuildable
from retained signed records. Storage authentication cannot make telemetry true.

On restart compare the actual setting with the last complete intent/receipt.
If it equals old_config and no Applied receipt exists, finish as NotApplied.
If it equals new_config, record observed application and roll back an unfinished
canary before accepting another plan. If it equals neither, freeze. Keep the
largest durably observed generation; never reset it to reuse an old signature.
Pure guard construction must use this recovered generation, not a constant zero.

Controller loss during steady Stable state leaves the last safe local setting.
Controller loss during an unassessed canary triggers node-local rollback; it
cannot rely on the missing controller to send the rollback command. Telemetry
loss never resets consensus or overrides a module's admission checks.

## Resource bounds

The following proposed dev service limits are stricter operational bounds than
the existing pure library's 64 modules/128 actions/256 capabilities ceilings.

| Resource | Dev limit |
|---|---|
| Registered modules | 18 known IDs; no arbitrary module-name labels |
| Measurement envelope | 16 KiB, <=64 fixed metrics, <=128-byte label values |
| Retained hot windows | 360 windows/module/node; older sealed windows move to bounded archive |
| Observation ingress | 32 envelopes/s/node, burst 64; excess dropped with counter |
| Plan | 16 KiB, exactly one application action; dry-run may validate library-shape limits |
| Rollout | One canary/node and one node per experiment |
| Control RPC deadline | 2 s evaluate, 5 s local apply boundary |
| Service memory/disk | 128 MiB memory, 1 GiB retained diagnostic data initially |

Reject config that exceeds local capacity before sampling/applying. Eviction
can remove derived telemetry after sealing with explicit loss markers; unresolved
application intent/receipt records cannot be evicted. No arbitrary commands,
model prompts, executable expressions or opaque code blobs exist in a plan.

## Security

Authenticate producers and planner separately; the guard runs with only bounded
service-setting capability. It has no signer handle or canonical database write
port. Replayed samples require process/window sequence checks; conflicting signed
samples are retained as evidence. Unknown critical actions fail closed even if a
planner labels them `OperationalLocal`. Parameter class comes from the local
allowlist, not caller declaration.

Private prompts, transaction bodies, bearer tokens and raw user data are not
metrics. Signed measurements can still be poisoned; compare independent node and
client observations before accepting a performance conclusion. No plan may erase
the failing run that caused rollback.

## Observability and SLO

Expose descriptor drift, complete/incomplete windows, decision rejection codes,
shadow duration, pending intent age, current generation, canary state, rollback
latency and actual/configured digest mismatch. Include `apply_enabled:false` in
initial service capabilities and `decision_only` in guard output.
`non-authoritative-service-v1` measures controller overhead separately from chain
SLOs. Optimization order is zero safety/determinism/durability/compatibility
violations, then service tails/cost, then committed goodput.

## Verification and evidence

| Operation | Positive | Required negative/fault |
|---|---|---|
| Register/observe | Exact descriptor and window retry idempotent | Same generation changed descriptor, old process sample, invalid quantiles |
| Evaluate | Signed next-generation known bounded integer receives decision | Forged signature, stale generation, unknown field, critical class, placement |
| Observer mode | Proposals and reports work while apply remains unavailable | Accepted pure decision cannot change config or advance host generation |
| Future apply | One field changes at safe boundary with exact readback | Partial I/O, concurrent manual config change, capacity shrink, dropped ACK |
| Future canary | Matched baseline and twelve complete windows stable | Tail regression, missing windows, poisoned counter, controller death |
| Recovery/rollback | Restart resolves old/new config and preserves generation | Third config value, rollback CAS failure, attempted chain-state rollback |

Existing pure-crate tests are regression evidence only. The network service,
persistent generation owner, local application port and canary campaign remain
planned and must be tested independently before enabling writes. Producers are
M04/M05/M06/M08/M14/M17; only M14/M17 settings listed above are future consumers.

## Activation boundary

Initial deployment is read-only observation. Applying even the listed local
settings requires a real host guard, authenticated planner, durable receipts and
fault-tested rollback. No M16 configuration can activate production or introduce
consensus/governance changes; those require their own module/version contracts.
