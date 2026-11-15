# Funded demand, evaluation and upgrade: frozen implementation evidence

Status: **reviewable candidate; HOLD for full native/external acceptance**.
The [sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [contract](../../docs/development/specs/pon/DEMAND_EVALUATION_UPGRADE_V1.md)
retain the original consensus, PQ, work-security and activation decisions.

## Exact source and publication

- Executed local commit: `99220dd03626760d6cb015f66bb133d1d61217ec`.
- Published source commit: `ed0ad15c5aaf0b0ca0c6edbb1c67b9976a5019dd`.
- Complete shared source tree: `a4db639e2c346b914ade186697182727a7e43ca4`.
- Initial integration base: `3d1b6507671ec694ce58e86d4063a125c8deeb66`.
- Preserved concurrent integration head: `adebe0bd78e6e1bdb55a599179ffe2313997170e`.

HTTPS Git push had no shell credentials. Authenticated Git Data publication
preserved ten separate source commits and verified every returned Git tree against
its local counterpart. Commit metadata differs; the executed commit must not be
renamed to the published SHA. [The mapping](publication-source-map.json) retains
both identities. An ordinary public Git fetch then confirmed the published source
commit and complete tree. The archive includes a Git bundle of the local source
history with its verification log and prerequisite base.

Every final command captured all tracked bytes, blob IDs, modes and SHA-256 hashes
before and after execution. All 15 final commands ran against the local commit
above, with a clean source and unchanged complete manifests. Earlier frozen
`a4121fe4` results remain separately named and were not transferred to this tree.
This evidence-only continuation does not claim that subsequently added archive
bytes were present during runtime tests.

## Actual results

| Final gate | Observed result | Archive log |
| --- | --- | --- |
| New demand and upgrade references | 52 passed: demand 29, upgrade 23 | `final-new-references.log` |
| Retained model/reward/evaluation boundaries | 131 passed | `final-retained-model-boundaries.log` |
| M12, all targets and features | 49 passed | `final-m12.log` |
| Native Node NoGain integration target | 2 passed; 6 backend scenarios | `final-native-no-gain.log` |
| CI registration/mutation controls | 102 passed | `final-ci-contract.log` |
| Source-integrity, PQ and repository negatives | 130 passed | `final-source-integrity.log` |
| Strict workspace Clippy, all targets/features | exit 0; `-D warnings` | `final-strict-clippy.log` |
| Workspace formatting | exit 0 | `final-rustfmt.log` |
| Locked/offline root Cargo graph | 26 members; 180 resolved packages | `final-root-cargo-graph.log` |
| Locked/offline fuzz Cargo graph | 1 member; 147 resolved packages | `final-fuzz-cargo-graph.log` |
| Repository and local Markdown links | exit 0; 3,464 links checked | `final-repository.log` |
| Source-pin corpus | 564 exact blobs; original HOLD flags retained | `final-pq-source-pins.log` |
| Project boundary and patch whitespace | both exit 0 | `final-preflight.log`, `final-patch-whitespace.log` |
| Selected tools and lock identities | exit 0; versions and SHA-256 captured | `final-toolchain.log` |

All log paths above have prefix `validation/frozen/` inside the archive. Commands,
exit codes, timings and source identities are in matching JSON receipts and the
[machine summary](validation-summary.json). Expected mutant `FAIL` observations
inside a passing negative-test suite are not failed whole-suite executions.
No Cargo lock, compiler optimization, debug profile or lint requirement was
relaxed to obtain these results.

## What the native tests establish

The [public-API integration target](../../trillionnium/crates/trnm-pon-node/tests/no_gain_fees.rs)
executes real signed Task reserve, provider output and payer acceptance through
the local Node. Task/Contribution and Task/Evaluation each run on Legacy,
Authenticated and Growth backends, with exact provider credit of 2,000 native
development units. Actual native payment readback and a completed M12 effect are
both required. Missing payment, incomplete effect, conflicting operation, a second
nonce payment and NoGain-to-Positive relabel are refused.

Each scenario closes/reopens twice and activates a stronger branch that removes
current payment membership. Historical M12 operation/payment facts remain;
completed effects cannot be redispatched or claimed again. No model, release or
contribution record is created by that negative-result service fee.

The NoGain outcome, resources and training material are controlled test inputs.
These are not six independently operated organizations, six beneficial model
upgrades or a real training benchmark. SQLite I/O-boundary `UNQUALIFIED` output
remains an unqualified boundary. The target does not replace the failed full Node
unit-test harness described below.

## Preserved failures and adversarial repair

[Failure provenance](failures.md) identifies setup failures, the unresolved full
Node lib compilation SIGKILL, and the original observer counterexamples.
The archive retains runnable attacks, old source pairs and before/after outputs.
Later fixes include expired provenance in queue selection and the cross-account
reviewer bonus attack: a fixed evaluation fee of 7 had allowed 5 extra bonus units
for a positive vote. The provider-only bonus beneficiary rule now refuses that
contract for evaluators, auditors and adoption owners, even with valid signatures.
All reported Python receipts remain synthetic; no production payment capability
is created. Legitimate provider bonuses and unknown-origin queue controls remain.

## Evidence archive

- [observations.tar.xz](observations.tar.xz): 116 members, 815,768 bytes.
- SHA-256: `6f44cd25007340171a6f22b048e6cb295a1ec62d298d8bca50759389c8a87e2b`.
- [Member index](observations-index.json): exact path, size and SHA-256 for every member.

The archive includes original and final command logs, complete source manifests,
development failures, attack scripts and snapshots, local Git history, publication
identity checks and the exact execution wrapper/recorders. It contains no live
service data, account credentials or user keys; deterministic test keys are
explicitly synthetic fixtures. Archive members were reopened and matched to
every indexed hash before committing this record.

## Acceptance that remains open

The demand observer and upgrade policy do not export or enforce native funding,
dispatch tasks, pay bonuses, install a model or prove independent demand. Their
authorization flags remain false. Full native statement export/reconciliation,
request/model/output-bound admission, enforceable dispute resolution, durable
cross-epoch evidence ownership, audited independent customers/evaluators and
fresh cost-matched evaluation still need their actual owners and evidence.
Ordinary Hepta canary/install/next-task/rollback and full Node harness qualification
also remain open. A capped subsidy bounds exposure; it does not make an internal
customer/provider transfer proof of outside demand.

The upgrade error bound is conditional on full-history sampling assumptions and
retained attempt history. Exact rational arithmetic does not certify cost truth,
freshness, causal adoption or permanent improvement. No production activation,
main merge, release approval or independent-acceptance declaration is made here.
