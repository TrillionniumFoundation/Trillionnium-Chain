# Complete-version custody observations and finite continuation v1

Status: candidate local M09 observer and planning API. The original PN4/PN5
funding, independent-administrator, sustained-WAN and production gates remain
**HOLD**. This extends the storage/repair interface in the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and composes the existing [TCA2 archive](CELL_MODEL_STORAGE_V1.md) and
[native-funded retention owner](CELL_RETENTION_V1.md).

## Concrete behavior

`observe_release_custody` reads one TMR1 component from the exact existing
`CellReleaseRetentionStoreV2` owners. It obtains each original contract and calls
`verify_release`, which hashes every actual retained dependency through the
physical arena owner. Supplied ACKs, provider advertisements, filenames and
aggregate cached bytes are not accepted as observations. It does not call copy,
reconciliation, repair, retirement, payment or network methods.

One component policy identifies one complete model root. A usable count requires a
fresh complete target readback for each declared replica, matching the exact
TMR1 root, physical store, original contract commitment, owner, replica slot,
service interval and original member identities. Three archives holding
different fragments do not count as three replicas, even when their union
contains every object. Another generation with identical payload bytes cannot
substitute for this version.

The initial development target is three complete replicas. The reusable API
accepts a finite owner-selected requirement from one through sixteen; the
policy pins that requirement before probing. No result or missing sponsor
reduces it. A lower requirement is a separately reviewed owner policy and does
not satisfy the three-replica PN5 target.

### Complete TCV1 model and environment composition

`observe_version_custody` is the complete-version entry point. It validates the
complete `CellVersionManifestV1` and its independently pinned 64-byte commitment,
plus separate owner pins for both custody policies. The model policy root must
be the exact version model. The environment policy root must be the canonical
`CellModelReleaseRootV1::new(version.environment().clone(), vec![])`; an absent,
substituted or differently parented environment root cannot qualify.

The two policies must have the same required count and corresponding replica
slot, store, responsible owner, administrator, failure domain and domain-evidence
identity. Different renewal/repair owners and finite service terms remain
explicit component contracts. The complete version is counted only on the
intersection of slots with fresh **model and environment** readback from the
same original store. A complete model at one provider and a complete environment
at another cannot be combined into one full replica.

Both component observations consume the same mutable probe reservation and
original deadline. No new allowance is created between them. Runtime refusals
from either component and all before/after counters remain in the private-field
`CellVersionCustodyReportV1`, including when the first component exhausts the
budget. Pin/root/topology defects refuse before probing. A successful model-only
report cannot stand in for this full-version report.

The complete version's payload size is the unique TCV1 manifest union. Resource
reservations still charge each actual component scan, including any shared bytes
read twice. This is a count of declared bytes observed at local targets; it
cannot discover omitted executable dependencies, authenticate domain evidence,
create native funds or establish independent WAN availability.

## Policy and independence boundary

`CellReleaseCustodyPolicyV1` contains the complete TMR1, required replica count,
positive renewal lead time in blocks and exactly one pin for each replica slot
in canonical order. Each `CellCustodyReplicaPinV1` binds:

| Input | Meaning |
| --- | --- |
| Store, operation and contract commitment | Exact existing physical target and complete immutable TCA2 terms. |
| Responsible owner | Original contract owner; also retained in native funding composition. |
| Administrator, failure domain and evidence digest | Owner-declared topology and the identity of separately retained evidence. |
| Renewal owner and repair owner | Explicit parties responsible for obtaining the next funded service or repair. |
| Replica slot and original lease/repair heights | Finite existing promise; no sliding deadline or inferred extension. |

The API refuses repeated store, responsible-owner, administrator or failure-domain
identities, noncanonical slots, missing evidence identities and invalid service
windows. These checks reject aliases in the declared topology. They do **not**
prove that different keys or labels represent independently administered
machines, organizations, power, disks or networks. The evidence digest is a
reference; the API does not read or authenticate the evidence behind it.

The policy ID is SHA-256 under the fresh domain
`trnm.cell-release-custody-policy.v1\0`. The canonical preimage contains a
big-endian u64 length and complete encoded TMR1, u16 required replica count,
u64 renewal lead time, then each canonical slot's ten fixed 32-byte identities,
u16 slot and three u64 service heights, all integers big-endian. The fixed slot
count is the required replica count. The independent expected policy ID must
come from the existing release/storage owner. A peer cannot choose it. This
new local policy digest is not a signature, PQ migration or identity proof.

`from_contract` obtains the contract commitment using the actual target's
configuration. Domain and continuation-owner declarations remain the caller's
responsibility. Physical independence still needs separately verified operator
evidence and the original independent failure campaign.

## Observations, deadlines and accounting

`current_height` is the existing chain owner's checked observation. M09 has no
chain authority and cannot verify an arbitrary supplied height. Production
composition must obtain it through the ordinary Node owner and retain its
anchor. The API is not an alternate native funding or finality path.

| Replica result | Counted toward complete byte coverage? |
| --- | --- |
| `Observed` | Yes, after exact complete physical readback in the sampled service interval. |
| `StoreUnavailable` | No; absence of a supplied original owner stays explicit. |
| `NotStarted` / `Expired` | No; intact bytes do not extend the original service promise. |
| `ContractMismatch` | No; a substituted root, owner, slot, term or commitment cannot count. |
| `ReadbackRefused` | No; preserve the actual refusal reason. It is unresolved, not proof that all physical bytes are lost. |
| `ProbeRefused` | No; the original observation budget/deadline is exhausted. This is not diagnosed as physical corruption. |

`CellCustodyProbeBudgetV1` contains one absolute deadline, a maximum number of
store probes and a maximum potential payload-read byte reservation. Before a
store attempt, the observer commits one probe and that component root's unique
payload bytes. The model and environment are separate attempts under the same
reservation. Early refusal, corruption or deadline exhaustion does not refund
that reservation. A retry using the same budget retains the previous debits.
Missing, not-started and expired stores do not trigger payload scans. Reported
reserved bytes are conservative admissions, not measurements of actual I/O.

Accounting is local and in-process. Constructing a fresh budget starts a new
caller-authorized reservation; this module does not replace M12's durable
lifetime resource journal. Payload-byte bounds exclude bounded metadata reads,
CPU, RSS, physical disk amplification and filesystem stalls. Existing archive
deadline checks are cooperative, not kernel preemption. Node integration must
keep those original resource owners.

The report retains before/after counters, every slot outcome, the sampled height
and whether the whole observation finished before its original deadline. A late
whole report cannot return complete byte coverage. Reports are sequential local
observations; they do not establish simultaneous future availability, independent
WAN retrieval or a sustained storage SLA. The report's fields are read-only to
callers and only the actual observer constructs one. A historical report grants
no new service, money, retirement or CURRENT/FinalUse capability.

## Finite renewal and repair work items

`CellReleaseCustodyReportV1::plan_continuation` derives bounded work items for
one observed component root. It does not dispatch them. Sponsor information
describes only owner-reported contactability:
`Unobserved`, `Contactable` or `Unavailable`. Unknown/duplicate sponsor identities
are refused. A reachable sponsor is never treated as available coins or proof
of a paid successor.

| Condition | Required next work |
| --- | --- |
| Healthy component outside the renewal lead interval | Keep the original promise and scheduled observation duties. |
| Renewal due, sponsor unobserved | Reconcile the named renewal owner before the original expiry. |
| Renewal due, sponsor contactable | Obtain a separately admitted native-funded successor; funding remains required. |
| Renewal due, sponsor unavailable | Obtain a replacement sponsor or explicitly lose the next promise at expiry. |
| Missing/refused target within the original repair window | Reconcile the original effect, then use the existing separately funded repair/replacement path. |
| Original repair deadline passed | Report `RepairWindowClosed`; do not move the deadline or replay the old copy operation. |
| Probe budget/deadline refused | Obtain a new admitted observation reservation; do not infer data loss. |
| Original service interval ended | Report `PromiseExpired`; this does not permit deletion, reset accounting or create a refund. |

Each item carries the exact store/operation, named renewal/repair owners,
original expiry, original inclusive repair-dispatch deadline and
`component_payload_bytes`. Repeated planning cannot slide these deadlines.
A component repair item targets the complete component root; its payload size
does not describe the full TCV1 union or assert that every byte must be rewritten.

`CellVersionCustodyReportV1::plan_continuation` composes both components into a
`CellVersionCustodyContinuationV1`. For every original store and replica slot it
returns a `CellVersionCustodyReplicaContinuationV1` with separate model and
environment actions, plus read-only references to both original slot
observations. Each component retains its exact contract, responsible owner,
renewal/repair owners, service start, expiry and repair deadline. No later
component expiry or repair deadline replaces the other component's earlier
term. An available model cannot hide an environment readback refusal, missing
renewal sponsor or exhausted probe allowance.

The complete plan borrows its private original report. The original TCV1
commitment, both independently pinned policy IDs, sampled height and all
reservation counters remain available without copying an 8 MiB manifest or
making an alternative observation. `unique_complete_version_payload_bytes`
is the declared TCV1 manifest union, distinct from each action's
`component_payload_bytes` and the report's committed scan reservations.

Both component reports must exist, and the complete observation must have
finished within its original deadline. A component-level observation error or
late complete report refuses the whole planning call and explicitly requires
a new admitted observation. The underlying error and previous debits remain
on the original report. Per-slot `ReadbackRefused` and `ProbeRefused` outcomes
in an otherwise returned report remain explicit recovery or re-observation
work; they do not disappear when the other component is healthy.

The complete planner accepts one finite sponsor list for the union of both
components' renewal owners, with at most thirty-two distinct identities.
Unknown or repeated owners are rejected before either component planner runs.
The same declared state is then supplied to both components when they share
an owner; the caller cannot describe that owner as available for one component
and missing for the other. A successful planning call means only that these
finite work items were derived. It establishes no complete byte coverage,
available funds, successor admission, completed repair or execution permission.

The original TCA2 and physical member contracts remain immutable. Existing
shared references may cover a new release only while their original physical
leases already cover it. This observer does not extend those leases. Actual
successor funding, native payment ancestry, new repair identity, target byte
verification and rooted GC continue through their existing owners. A sponsor
leaving does not erase unexpired duties, pending effects, repair debt, shared
base references or historical monetary facts.

## Source verification and remaining acceptance

The dedicated `cell::custody::tests` controls construct real allocated archive
files and exercise source/cache loss, a missing provider, complementary partial
archives, post-ACK corruption, conservative failed-attempt reservations,
duplicate stores/domains, policy substitutions, another version with identical
bytes, deadline exhaustion, pre-service/expired promises, sponsor loss, original
repair deadlines and cold reopen. Four additional physical-archive controls
exercise complete model/environment recovery after source loss, a partial
environment despite three complete models, a complete environment in the wrong
store and exhaustion of the original budget before environment scans. They run
on a local test host with synthetic
payloads; they do not establish independent operators, a funded long-term market
or a real model's availability.

Five continuation controls cover a missing environment with its unavailable
sponsor, distinct original component terms and owners, the thirty-two-owner
union and conflicting/shared sponsor states, incomplete component reports and
late completion, and environment probe refusal after model scans consumed the
original budget. The incomplete-report cases deliberately compose actual
successful readbacks with an actual expired-budget refusal, and separately
exercise the late-completion flag, as negative composition controls. They are
not measurements of physical corruption or a timed deadline race. The payload
controls compare unique declared version bytes with separate component sizes
and actual reservations; they do not claim a cross-context shared-manifest
fixture.

An implementation run is attributed only to its recorded exact source and
retained command outcome:

```sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --lib cell::custody::tests -- --nocapture
```

Production qualification still requires independently verified custody topology,
per-version recovery after author and provider loss, source-preserving renewal,
actual native payment and repair integration, funded archival growth, sustained
72-hour PN5 WAN/churn measurements and exact model-loader/current-use evidence.
No result here promises permanent storage or makes published plaintext revocable.

## External protocol boundary

[IPFS's persistence documentation](https://docs.ipfs.tech/concepts/persistence/)
distinguishes opportunistic caches from retained pins and describes the operating
and funding responsibility of pinning services. The
[pinning guide](https://docs.ipfs.tech/how-to/pin-files/) explains protection from
garbage collection. Content addressing and a downloaded copy establish neither
an independently funded storage promise nor an execution right. This observer
preserves that same separation for the existing Chain archive.
