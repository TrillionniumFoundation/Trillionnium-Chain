# M01 Cryptography, neural-work verification and local identity — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M01; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/NEURAL_WORK.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own strict cryptographic verification and private context-bound verified work/identity carriers.
Mining keys identify producer and payout; they do not define a validator set or voting weight.
Evaluation attestation and local authorization are separate proof types.

## PoN Interfaces

VerifyWork(profile, exact_statement, proof, budget) -> VerifiedWork or Invalid/Unavailable;
VerifyContributionSignature; VerifyEvaluationAttestation. Historical proof readers are not
retained in this module. Constructors
remain restricted, but Rust type privacy is not a cross-host proof.

## PoN State machine

Authenticate the installed work profile and expected template/challenge, then exact-decode and
verify the complete relation. Bind model/input, miner, payout, parent, dimensions and canonical
output. Charge failed cryptographic attempts to the local budget. Return work validity only; M02
derives target/chainwork and M11 evaluates usefulness. Proof-of-execution does not demonstrate
an adversarial work-cost lower bound by itself.

## PoN Persistence and recovery

Keep verification stateless except bounded non-authoritative caches keyed by complete
profile/statement/proof context. Cache hits cannot mint additional lottery outcomes. Key
rotation preserves historical verification while fresh local grants require current authority.

## PoN Resource bounds

Prove/check proof size, verifier time, memory and security parameter per exact shape/cost class.
Reject unknown algorithms and missing setup material. Isolate long proving from the
verifier/consensus hot path.

## PoN Security

Qualify challenge influence, shortcut resistance, output uniqueness, setup trust and matrix/ML
arithmetic correspondence. TEE, logs and rational incentive proofs cannot silently satisfy
Byzantine mining security. Copying a model may be a contribution dispute but cannot yield
parent-bound work.

## PoN Verification and evidence

Independent verification implementation; invalid proof/weak key/wrong context/payout/template
mutations; proof-randomness replay; degree/range/field mismatch; verifier-flood resource bounds;
research attacks from NEURAL_WORK.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-crypto-primitives`](../../trillionnium/crates/trnm-crypto-primitives/README.md): `cargo test --locked -p trnm-crypto-primitives --all-targets --all-features`.
- [`trnm-governance-guard`](../../trillionnium/crates/trnm-governance-guard/README.md): `cargo test --locked -p trnm-governance-guard --all-targets --all-features`.
