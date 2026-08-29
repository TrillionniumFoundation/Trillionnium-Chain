# Remaining blocker execution matrix v1

Status: **A00 control-plane candidate; project terminal state remains `BLOCKED_UPSTREAM`**

This document converts every remaining independent or real-world blocker into a source-bound execution contract. It does not convert missing evidence into completion, authorize package-owner self-acceptance, merge any PR, or promote Gate, release, production, activation, node-support or normative-freeze truth.

The machine source is `REMAINING_BLOCKER_EXECUTION_MATRIX_V1.json`.

## Evidence law

Only a completed, successful replay on the exact current package head is eligible as repository evidence. Synthetic merge refs, stale heads, skipped, cancelled, queued, in-progress or failed runs are not evidence. A package author cannot independently accept or merge the package. Fixtures, models and simulations cannot substitute for real multi-host, power-loss, HSM/KMS, audit, soak or governance evidence.

## Execution packages

### EXT-REVIEW-001 — independent package and interface acceptance

Each package requires a reviewer who is not the package author. The reviewer must bind the exact commit, tree, handoff digest, retained mutant corpus and exact-head run, replay every P0 mutant, publish an independence declaration, and issue an accepted or rejected interface digest plus downstream invalidation set.

Any source, handoff, mutant, workflow or toolchain change invalidates the decision.

### EXT-G1-CAMPAIGN-001 — real 4/7-node campaign

A07 may execute only after independent acceptance of G1-R2 through G1-R4. Evidence must bind the exact binary, SBOM, genesis, validator set and consensus parameters. It must use multiple physical hosts, operators and custody domains and produce signed raw traces for partition/heal, restart, state sync, epoch/key rotation, signer faults and disk/I/O faults. Transport-only smoke, loopback-only farms and unsigned summaries are invalid.

### EXT-ANCHOR-HSM-001 — external anti-rollback and signer custody

A05 requires an externally administered monotonic authority and device-backed HSM/KMS custody outside the rollbackable node namespace. Required evidence includes non-exportable key generation, quorum custody, rotation, revocation, rollback rejection, cloned-namespace rejection, disaster recovery and an auditable custody trail. Local HMAC, SQLite, file watermark or a second path on the same host is not sufficient.

### EXT-POWERLOSS-001 — physical durability evidence

A06 must execute physical power interruption, host reboot and controller-cache-loss cuts on the accepted package tuple. Recovery must happen in an independent fresh process and prove exact root/readback recovery or permanent quarantine. SIGKILL-only and same-process simulations remain useful candidate tests but do not satisfy this blocker.

### EXT-AUDIT-001 — independent security and economic review

A17 must collect independent consensus, cryptography and economic audits plus red-team evidence. Every finding is source-bound and carried in a remediation ledger. Gate progress requires zero open Critical and High findings; changing the release, cryptography, economics or threat model invalidates affected decisions.

### EXT-SOAK-ACTIVATION-001 — wall-clock operations and governance

A17 must obtain real 72-hour chaos, 7-day public-testnet soak and 30-day production-candidate soak evidence, together with incident, restore, signer/key-rotation, state-sync and observability drills. Simulated time cannot substitute wall-clock duration. Governance and activation records must be issued by authorized actors after all prerequisite evidence is accepted.

## Truth boundary

```text
all_plan_gaps_closed=false
g0_exit=false
g1_exit=false
g2_exit=false
g3_exit=false
g4_exit=false
g5_exit=false
production_candidate=false
production_consensus_activation=false
release_ready=false
normative_freeze=false
node_support=false
```

A repository package may reach `MODULE_CLOSED_CANDIDATE`. The project cannot reach complete closure until the six execution packages above carry independently accepted, exact-source evidence.
