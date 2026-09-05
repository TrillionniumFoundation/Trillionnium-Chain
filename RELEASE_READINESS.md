# Trillionnium Chain release readiness

Updated: **2026-09-02**

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

A passing crate test, hosted workflow, self-hosted workflow, simulation,
candidate fixture, local process campaign, carrier qualification, or generated
report cannot independently change these values.

## Current source state

Protected `main` was observed at
`b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`. Draft PR #62 on
`work/plan-v2-full-gap-closure-20260902` is the sole selected integration
successor. The plan assesses ancestor baseline
`af691ea5005e1f0262e90c4fc878ba0a70dbe7ea`
(tree `af09e389b1a462b3839508b7ef305596c76384c6`); the current PR head and
prospective-merge identities are derived by CI at verification time.

The selected line contains repository implementations for:

- descriptor-bound SQLite namespace and sidecar identity;
- closed-world SQLite schema/pragma validation;
- post-close/post-operation validation before trusted return;
- a monotonic Node Commit Ledger and recovery coordinator;
- persistent deterministic 1/2/4/8-worker execution equivalence;
- one active development plan with exact source/merge validation;
- M00-M17 technical references and unique primary ownership for all active
  workspace crates, contracts, Web4, formal, fuzz, transport and CI tooling.

These are **implementation-present, acceptance-pending** facts. They are not
protected-main, production, release, protocol-activation, or independent-review
authority. Every new commit invalidates prior exact-head conclusions and must
rerun applicable checks.

The default `trnm-poco-node` startup path remains fail-closed. Candidate process
commands and local fixtures are not a persistent production network, validator
signer, live pacemaker/finality loop, production state-sync service, HSM
custody, physical power-loss proof, or activation artifact.

## Major repository-owned blockers

- all required checks on one unchanged PR #62 head and its prospective merge;
- independent module-owner, consumer, security/evidence, and release acceptance;
- protected-main merge and post-merge replay;
- actual Cargo dependency and feature closures for production, devnet,
  v1-candidate, and lab/evidence binaries;
- decomposition of node composition into host, authority coordinator, I/O,
  composition, CLI, and lab boundaries;
- authoritative persistent SafetyRules/Core, pacemaker, Vote/Timeout, epoch,
  catch-up, finality and restart path;
- production authenticated networking and complete transaction lifecycle;
- authenticated non-destructive state sync and arbitrary trust-path
  verification;
- complete generated protocol/schema/error registries, independent parser, and
  long-running fuzz/formal/conformance evidence;
- trusted migration source verification, target projection/root recomputation,
  rehearsal, cross-peer activation and one-way cutover;
- bounded resource/denial, observability, packaging, reproducible build, SBOM,
  provenance, incident and disaster-recovery closure;
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

The schemas, templates, submissions, and validators are under
`docs/evidence/external/`. Fixtures, single-host simulations, local watermarks,
SIGKILL-only tests, self-review, shortened runs, mutable URLs, or simulated time
do not close these gates.

## Promotion rule

A claim may become true only when protected branch, plan, machine truth,
protocol/schema/formal inputs, module and dependency closures, reproducible
artifacts, independent reviews, external evidence, governance record, and
activation bundle all bind the same exact source and artifact digest set.

Any source, protocol, dependency, compiler, feature, configuration, validator
set, key policy, state-root format, migration input, failed invariant, or
release-input change invalidates the downstream evidence declared by the
canonical plan and requires replay before promotion.
