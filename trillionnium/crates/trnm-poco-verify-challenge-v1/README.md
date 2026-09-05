# PoCO Verify/Challenge v1 candidate kernel

This crate is a **candidate-non-normative**, local SQLite kernel for one
bounded `StakeQuorum` verification profile. It exists to make the first
receipt → atomic two-record evaluation → challenge evidence → provider
response → quorum adjudication path executable without claiming the full v1
Compute plane.

The explicit `VerifyChallengeFreshGenesisTrustBundleV1` is verifier/store
input, not a consensus object. It registers one active task/lease/attempt, a
provider, challenger, verifier set, challenge bond, exact profile, and a
fresh order-finality anchor. Every call supplies a monotonic
`VerifyOrderFinalizedExecutionContextV1` compare-and-swap fact; that fact is a
Node trust input and is not itself a consensus object or proof. The candidate
supports one canonical receipt, one Result, one fixed four-member verifier set,
and at most one Challenge.

Implemented local properties:

- strict Ed25519 attribution for provider receipts, challenger actions,
  provider responses, and every verifier claim;
- complete inline verifier claims, strictly sorted unique verifier identities,
  checked unique-signer weight, exact shared statement/evidence/sequence
  binding including the committed required-DA-policy hash, and no
  verification-class fallback;
- duplicate actor/verifier key IDs or public keys fail closed; committed
  verifier-set and profile hashes are independently recomputed;
- operation 22 semantics represented as one SQLite transaction containing the
  virtual `BeginEvaluation` and committed `EvaluationDecision` history hashes;
- atomic Result/Challenge/bond transitions through evidence, response, and
  Upheld/Rejected adjudication, with checked revision/bond arithmetic and a
  hard maximum of 64 evidence entries;
- exact command replay, direct-successor finalized-block markers for empty and
  multi-command blocks, gap-free operation sequence, durable state,
  operation-tail and finalized-block roots on every verified access,
  immutable read-only existing-store preflight before writable access, fresh
  reopen, schema/sidecar refusal, and permanent third-state fencing.

Not implemented: the other six verification classes, global CEV1 wire,
ArtifactEvidence DA proof verification, AgentTransaction authorization,
multiple/concurrent challenges, window-close/settlement, Agent/Market store
integration, state tree, whole-store anti-rollback authority, Node integration,
normative freeze, production activation, or global G2 completion.
