# M11 Independent model evaluation and qualified work verification profiles — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M11; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/MODEL_COMMONS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own pinned evaluation and challenge semantics for public model benefit, distinct from M01
work-proof cryptography and M02 fork choice. No evaluator majority, model rank, stake or
subjective truth assertion creates chainwork.

## PoN Interfaces

EvaluationPlan; EvaluationReceipt; VerifyPublicEvaluation; AdmitAttestedEvaluation;
EvaluateComposition; ResolveChallenge; WorkProfileQualificationEvidence. Work-profile
qualification is independent acceptance, not a callable boolean that enables arbitrary proofs.

## PoN State machine

Lock exact candidate/reference, compatibility, data strata, metrics, uncertainty, resource
allowance and composition recipe before testing. Run isolated independent cross-node held-out
and future-window evaluations. Test whole composition and old-task regression, not just local
training loss. A deterministic public profile verifies reproducible outputs; private/human
assessments have explicit attested trust classes. Apply bounded rules to current chain state
without retroactively changing valid block work.

## PoN Persistence and recovery

Store immutable plan/evidence identity, accepted result and challenge responsibility under the
existing owner. Reorged acceptance is not current adoption; retain source-bound evidence and
failed observations. Evaluator failure or unavailable data is not a fabricated positive or fraud
verdict.

## PoN Resource bounds

Maximum benchmark work, tensor/proof bytes, concurrent evaluators, composition ablations, appeal
stages and retention horizon. Verification/adjudication must fit reserved budgets; do not call
remote LLMs or unbounded datasets during block validity.

## PoN Security

Evaluation leakage, adaptive reward-oracle probing, colluding evaluators, dishonest
attestations, poisoned/backdoored parameters, loader execution and utility metric gaming.
Commit-reveal cannot establish operator independence. A computation proof does not prove utility
or computational hardness.

## PoN Verification and evidence

Candidate/reference/input/profile replacement, repeat benchmark gaming, bad loader/backdoor
probes, whole-model degradation despite expert gain, complementary bundles, evaluator conflicts,
timeout/Unknown preservation and independent work-primitive shortcut attacks.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-oracle`](../../trillionnium/crates/trnm-oracle/README.md): `cargo test --locked -p trnm-oracle --all-targets --all-features`.
- [`trnm-verification-profiles`](../../trillionnium/crates/trnm-verification-profiles/README.md): `cargo test --locked -p trnm-verification-profiles --all-targets --all-features`.
