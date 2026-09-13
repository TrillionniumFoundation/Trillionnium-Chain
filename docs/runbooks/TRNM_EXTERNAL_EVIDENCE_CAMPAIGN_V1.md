# TRNM external evidence campaign v1

Status: **execution-ready runbook; no real evidence is included**

This runbook executes the remaining real-world blockers after repository candidates and independent package reviews are accepted. It is subordinate to the canonical Plan, Agent control contract, exact-head replay policy and machine/release truth. The empty machine envelope is `docs/evidence/g3-g5/EXTERNAL_EVIDENCE_CAMPAIGN_TEMPLATE_V1.json`.

## 1. Freeze the campaign source tuple

Before provisioning any host, record and independently verify:

```text
repository
release commit and tree
binary SHA-256
SBOM SHA-256
genesis SHA-256
configuration root
toolchain identity
validator-set root
operator identity root
custody identity root
network topology root
```

The campaign is invalid if any value changes without a new campaign ID. A PR merge ref, mutable branch name, uncommitted worktree, locally rebuilt unbound binary or unsigned configuration is not an acceptable source identity.

## 2. Independence and duties

At minimum, separate these roles:

```text
package author
campaign operator
independent reviewer
security custodian
external auditor
operations lead
governance authority
```

The package author cannot independently accept the package, review all retained P0 mutants, administer every signer key, operate every validator, issue the audit decision and authorize activation. Every role declaration is signed and content-addressed.

## 3. Prerequisite gate

Do not start a claim-bearing campaign until G0, G1, G1.5, G2.0 and G2A–G2F carry independent accepted evidence on exact source tuples. Every retained P0 mutant must have a second replay. Open Critical or High findings block execution or invalidate the result.

Harness dry-runs may occur earlier, but they must use a distinct campaign ID and keep every claim false.

## 4. HSM/KMS and external monotonic anchor ceremony

The A05 security custodian provisions an authority outside the rollbackable node namespace.

Required controls:

1. Keys are generated inside a hardware or managed security boundary and are non-exportable.
2. Administration uses quorum custody across independent custodians.
3. The checkpoint/monotonic authority cannot be rolled back by restoring the node filesystem, VM image, container volume or database.
4. Generation, rotation and revocation ceremonies are separately signed.
5. A cloned namespace, same-height fork, stale predecessor and lower checkpoint are rejected.
6. Disaster recovery restores service without accepting an older monotonic state.
7. Firmware/service versions, policy, key IDs, custody membership and audit records are committed.

Record the ceremony, rollback-rejection, clone-rejection, recovery and custody audit roots in the campaign envelope. A local HMAC, a second SQLite database, a file watermark, another directory on the same host or a software key exported to the validator does not satisfy this step.

## 5. Physical fault campaign

A06 executes the accepted fault schedule against the exact binary and storage inventory.

Required cuts include:

```text
power removal after intent durability and before acknowledgement
power removal after application commit and before Safety/checkpoint acknowledgement
host reboot during state-sync staging and atomic namespace swap
controller-cache loss around journal/checkpoint fsync boundaries
disk full during append, publication, rename and parent-directory sync
torn or truncated journal/checkpoint records
signer outage during proposal, vote and timeout paths
```

Recovery occurs in a separately started process after the fault. The oracle accepts only exact source recovery, exact target recovery or permanent quarantine. It records the raw cut trace, storage/controller identity, readback roots, retained residue and final decision. SIGKILL-only testing remains valuable candidate evidence but is not physical power-loss evidence.

## 6. Four- and seven-validator campaigns

A07 provisions multiple physical hosts, operators and custody domains.

Required scenarios:

```text
four validators, equal weight, normal finality
four validators, 3-1 partition and heal
four validators, 2-2 safe stall and heal
seven validators, unequal weight, normal finality
seven validators, 5-2 partition and heal
seven validators, weight-selected 4-3 progress/stall boundary
leader crash and timeout-certificate recovery
offline validator rejoin
process restart and catch-up
state sync from an accepted checkpoint
epoch transition and validator-set rotation
signer key rotation and signer outage
disk/I/O degradation
```

Each process has a stable process ID, host ID, operator ID, region ID and custody-domain ID. Results include signed raw traces and exact Order/application/Safety/checkpoint roots. Any conflicting finality, double-sign or accepted root divergence is a `STOP_CONDITION`.

Loopback-only process farms, a single operator controlling every key, transport smoke and unsigned summaries cannot satisfy this campaign.

## 7. Benchmark campaign

The benchmark manifest binds the exact release, workload, topology, fault schedule, comparator and raw trace roots.

Rules:

- Report submitted TPS separately from committed goodput.
- Report Order, result and settlement p50/p99 finality.
- Use identical hardware and workload for comparator claims.
- Repeat campaigns and retain each repetition root.
- Reject orphan metrics that cannot be joined to committed operations.
- Scope any superiority claim to the exact workload and comparator; universal claims are forbidden.

A synthetic decision root validates the claim gate only and is never performance evidence.

## 8. Independent audits and red team

A17 coordinates independent consensus, cryptography and economic audits plus a red-team campaign. Reports bind the exact source release and topology. Findings use stable IDs, severity, affected source, reproduction, remediation commit, retest evidence and closure decision.

No public-testnet, superiority, release or production claim proceeds with an open Critical or High finding. Reopening a finding invalidates downstream decisions.

## 9. Wall-clock soak and drills

Execute with real wall-clock time:

```text
72-hour chaos campaign
7-day public-testnet soak
30-day production-candidate soak
```

Required drills:

```text
incident declaration and escalation
restore from accepted checkpoint
HSM/signer key rotation and revocation
state sync and corrupted-peer rejection
observability/SLO alerting
operator and custody failover
```

Record start/end timestamps, trace roots, SLO windows, every breach, remediation and rerun. Simulated time, shortened durations or concatenated unrelated runs are invalid substitutes.

## 10. Governance and activation ceremony

Only after all prerequisite evidence is accepted may the governance authority issue a source-bound proposal. Record proposal ID/root, eligible voter-set root, votes, approval root, activation parameters, activation height and ceremony root.

The package author, campaign operator or CI system cannot independently authorize production activation. Activation remains false until the authorized ceremony completes and a separate truth-only change is reviewed and merged.

## 11. Final claim gate

The evidence envelope may set a claim to true only when all required fields are complete, independently signed and source-consistent. Missing, false or null fields are failures, not unknown successes.

Until then:

```text
benchmark_results_present=false
scoped_surpass_claim_allowed=false
public_testnet_ready=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```

## 12. Invalidation

Create a new campaign or invalidate affected evidence when any of these changes:

```text
source commit/tree or release binary
SBOM, toolchain or dependency graph
genesis or consensus parameters
validator/operator/custody membership
HSM/KMS firmware, service version, policy or key generation
checkpoint, proof, wire or state-root semantics
workload or comparator
threat model or audit finding state
critical deployment configuration
```

Never edit an old signed envelope in place. Publish a successor with explicit predecessor and invalidation links.
