# Trillionnium Chain release readiness

Updated: **2026-09-01**

This file is the human-readable release projection. It is not an independent
truth source. The machine-readable authority is
`config/consensus-mainline.json`; repository merge policy is
`config/repository-policy-v1.json`; the only execution, modularization, and
promotion contract is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

Generate a commit/tree-bound status document with:

```bash
python3 scripts/ci/generate_release_status_v1.py --check-deterministic
```

## Current conclusion

**NO-GO: not public-testnet-ready, not production-ready, and not release-ready.**

Native PoCO-BFT v0 is the only future production consensus route. All release
and activation flags remain false:

| Claim | Value |
|---|---:|
| G0 exit | `false` |
| G1 exit | `false` |
| G1.5 exit | `false` |
| G2.0 exit | `false` |
| G2 exit | `false` |
| G3 exit | `false` |
| G4 exit | `false` |
| G5 exit | `false` |
| Public-testnet ready | `false` |
| Production candidate | `false` |
| Production consensus activation | `false` |
| Release ready | `false` |

A passing crate test, simulation, candidate fixture, local process campaign,
carrier workflow, or repository CI check cannot independently change these
values.

## Current source state

Protected `main` was observed at
`b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`. The latest assessed candidate is
Draft PR #58 at `3c46293e78a125dec9504e51c355a20216341338`
(tree `875a1e6366df7cd9da80de145e25584ae309cee8`). It combines ordered application
finalization, durable terminal history, and native finalized replay-floor work.
It remains unaccepted and has requested changes.

Merge-blocking repair includes descriptor-bound SQLite namespace and sidecar
identity, closed-world schema validation, fresh-connection revalidation, and
removal of read/exact-replay returns before post-operation checks. PR #58 must
become the sole A04/A19/A23 successor, with overlapping lineage superseded, and
must receive non-skipped exact-head and prospective-merge validation plus
independent acceptance.

The default `trnm-poco-node` startup path remains fail-closed. Candidate process
commands and local fixtures are not a persistent production network, validator
signer, live pacemaker/finality loop, production state-sync service, HSM custody,
physical power-loss proof, or activation artifact.

## Major repository-owned blockers

- protected-main integration of one canonical Native PoCO source train;
- one generated protocol/schema/error registry and independent conformance;
- bounded QC/TC/admission work and long-running fuzz evidence;
- authoritative persistent SafetyRules/Core, pacemaker, epoch and catch-up path;
- Node Commit Ledger and exact whole-node crash/replay convergence;
- full body/parent/runtime validation and deterministic MVCC-to-JMT-to-finality
  integration;
- production authenticated networking, transaction lifecycle, state sync,
  recovery owner, checkpointing and durable apply;
- production/devnet/v1/lab dependency-closure separation and node decomposition;
- trusted migration source verification, target root recomputation, rehearsal,
  cross-peer activation, and one-way cutover;
- bounded resource, denial-of-service, observability, packaging and supply-chain
  closure;
- guarded out-of-band global optimization without consensus authority.

## External blockers

The following cannot be generated honestly by a repository commit:

1. `EXT-REVIEW-001` — independent exact-source package/protocol review and mutant
   replay;
2. `EXT-G1-CAMPAIGN-001` — real 4/7/31/100-process, multi-physical-host,
   multi-operator and multi-custody campaign with signed traces;
3. `EXT-ANCHOR-HSM-001` — device-backed non-exportable keys, external monotonic
   anchor, quorum custody, rotation, revocation and rollback evidence;
4. `EXT-POWERLOSS-001` — physical power interruption, controller-cache loss,
   reboot, independent recovery and exact-root readback;
5. `EXT-AUDIT-001` — independent consensus, cryptography and economic audits plus
   red team, with zero open Critical or High findings;
6. `EXT-SOAK-ACTIVATION-001` — 72-hour chaos, 7-day public-testnet and 30-day
   production-candidate wall-clock runs, operational drills, and an authorized
   governance/activation record.

The schema, template and validator are under `docs/evidence/external/`.
Fixtures, single-host simulations, local watermarks, SIGKILL-only tests,
self-review, shortened runs, mutable URLs, or simulated time do not close these
gates.

## Promotion rule

A claim may become true only when protected branch, plan, machine truth,
protocol/schema/formal inputs, dependency locks, reproducible artifacts,
independent reviews, external evidence, governance record, and activation bundle
all bind the same exact source and artifact digest set.

Any source, protocol, dependency, compiler, feature, configuration, validator
set, key policy, state-root format, migration input, or release-input change
invalidates the downstream evidence declared by the canonical plan and requires
replay before promotion.
