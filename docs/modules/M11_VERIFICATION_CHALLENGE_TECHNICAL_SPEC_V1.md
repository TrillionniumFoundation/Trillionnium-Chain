# M11 Verification and Challenge technical specification v1

Status: candidate contract. Profile selection and extension rules below are
design requirements, not evidence that all verifier backends are implemented.

## Authority

M11 binds evidence to the exact task/lease/attempt/result and computes a
profile-specific decision plus challenge maturity. It cannot reorg Order,
authorize voting weight or directly debit settlement. M12 consumes only the
complete mature-result predicate; M13 reports the actual proof class.

The [verification draft, sections 3-10](../protocol/poco-ai-native-v1/05-compute-receipts-verification-and-challenges.md)
defines receipt/result/profile/challenge objects. Current source is
`trillionnium/crates/trnm-poco-verify-challenge-v1/src/`.
**The durable current kernel implements one bounded StakeQuorum profile.**
The generic `VerificationBackendV1` interface and seven registry kinds do not
mean that deterministic, ML, ZK, TEE, optimistic or subjective backends exist.
See the crate README's explicit scope. No frozen v0 codec is changed here.

## Interfaces

`VerifyChallengeStoreV1` exposes `execute_order_finalized`,
`advance_empty_order_finalized_v1`, `preview_before_vote_v1`,
`fresh_confirm_receipt` and `fresh_readback`.
Inputs are `VerifyOrderFinalizedExecutionContextV1` and `VerifyCommandV1`;
the finalized context is a node-supplied CAS fact, not proof authentication.
Outputs bind operation ID, prior/successor revision, state/history roots and
exact receipt. Preview has no durable logical effect.

Current commands are `AdmitReceipt`, `Evaluate`, `OpenChallenge`, `AddEvidence`,
`Respond`, and `Adjudicate`. Evaluate is kind 22; challenge advance variants are
kind 23. Do not infer global wire enum tags from Rust variant ordinal.
Current local types/codecs use candidate Borsh and domain-separated hashes from
`types.rs`/`codec.rs`, not transport JSON or a newly frozen CEV1 registry.

`VerificationProfileV1` in `profile_registry_v1.rs` binds ID, version, hash,
kind, enabled flag, valid-from, optional expiry/revocation, and permitted
objective-settlement/PoCO roles. `closed` requires exactly one entry for every
kind; an unsupported kind is present but disabled, not missing or a fallback.
`resolve_exact` matches ID/version/hash, requires enabled, then checks heights.
At height equal to expiry the profile is still in range; at height equal to
revocation it is revoked. Tasks pin the exact profile before work begins.

`VerificationStatementV1` and `VerificationEvidenceV1` bind exact statement and
backend payload digests and evidence window. `verify_statement_v1` validates
these before backend dispatch. Backend outcomes are `Verified`, `Rejected`,
`Unavailable`; all returned generic decisions keep economic/order-reorg/PoCO
authority false. A later authorized consumer must verify its own predicate.

### Owned oracle admissibility package: `trnm-oracle`

`OracleSnapshot` contains canonical feed ID, signed `i128` value, sorted unique
`OracleSourceId`s, sample count, optional median/MAD, window start/end, snapshot
time and hash. `OracleSnapshot::new` validates these fields and computes SHA-256
using the source-defined framing in `src/lib.rs`: feed/value delimiters, source
count and strings, sample count, option tags and little-endian numeric fields.
Consumers use `validate_hash`; a JSON field order or self-supplied hash is no
substitute. `OraclePolicy::validate_snapshot(snapshot, now_ts_ms)` applies
canonicality, window/freshness, source-count and dispersion checks.
`validate_snapshot_observed` emits a classified report/metrics, not an authority
token for M12 or a bridge.

The exact policy fields are `min_sources`, `max_staleness_ms`,
`max_deviation_bps`, and `max_update_rate_per_window`. Current validation requires
positive sources/staleness/update rate, sources <= update-rate cap and deviation
<=10,000 basis points. Sample count may exceed unique sources, but not be smaller.
Source names and the snapshot hash do not authenticate independent publishers,
prove observation truth or enforce a network-wide update budget by themselves.
If consumed deterministically, the enclosing finalized transaction must bind
source signatures/keys and the authenticated time/window context; validator
wall clocks must not decide validity. M15's source-chain finality/replay checks
remain separate from this admissibility result.

Select planned **ORACLE-DEV-1** only for adapter integration: 3 minimum sources,
30,000 ms maximum staleness, 100 basis-point maximum deviation and 32 maximum
updates/window. The signed adapter configuration pins feed IDs and exactly
allowed source keys; local decode caps are 32 sources, 128 bytes/feed or source
ID and 64 KiB/snapshot. Enforce these before allocation and enforce the update
counter in the enclosing durable profile; the library alone is stateless.
An absent source signature or unknown key rejects the integration input, even
if the underlying snapshot passes all library checks. Enabling real price or
settlement authority additionally requires its explicit economic/trust profile.

`InvalidPolicy`, noncanonical/duplicate source errors, `SnapshotHashMismatch`,
`FutureSnapshot`, `StaleSnapshot`, `InsufficientSources`, `DeviationExceeded`
and sample-count errors preserve the original downstream state; never fall back
to the last price silently. Persist only an accepted enclosing operation and its
exact snapshot/profile identity, not a success flag detached from its bytes.
Source tests in `src/tests/policy.rs`, `snapshot.rs`, and `observed_report/`
cover these classes. Adapter vectors must reject a valid-looking 2-source report
under ORACLE-DEV-1, a modified value with old hash, an unregistered signing key,
and two nodes receiving the same authenticated time context must agree despite
different wall clocks. This package does not implement another M11 verifier class.

## State machine

### Current StakeQuorum operation sequence

1. Commission `VerifyChallengeFreshGenesisTrustBundleV1`: one task/lease/attempt,
   provider, challenger, four distinct verifier identities/keys, funded bond,
   exact profile and initial ordered head. Recompute all committed profile/set hashes.
2. `AdmitReceipt` checks provider signature, environment/input/output/task/lease/
   attempt/profile binding and creates the exact Result from the signed receipt.
3. `Evaluate` matches result revision, round, shared statement/evidence, decision
   and nonce; checks sorted unique claims and strict signatures, sums weight
   once/member, requires both weight threshold and minimum unique signers.
4. Persist BeginEvaluation and EvaluationDecision history effects atomically
   in one transaction. A partially appended evaluation is never a valid state.
5. `OpenChallenge` verifies challenger authority and current result revision,
   deadline, evidence binding and funded bond; reserve bond and increment open count.
6. `AddEvidence` accepts only exact challenge/result revisions, authorized actor,
   retained artifact/certificate references and bounded unique entries.
7. `Respond` requires named provider and response deadline, exact challenge and
   statement. `Adjudicate` verifies a new matching quorum and updates Result,
   Challenge and bond accounting atomically.

The kernel supports one Result, one fixed four-member verifier set and at most
one Challenge, with 64 evidence entries. Its artifact certificate IDs are trust
inputs; actual ArtifactEvidence DA verification and global multi-challenge,
window-close/settlement integration are not implemented by this kernel.

### Planned profile commissioning; no category-only activation

Before any backend can be enabled, an independently authorized deployment
manifest pins the complete descriptor bytes/hash, backend binary/source digest,
schema, deterministic verifier configuration, trust material, limits, test
corpus digests, activation/expiry/revocation heights and allowed proof meanings.
The manifest signer is validated against the previously trusted deployment key;
the candidate descriptor cannot introduce its own root of trust.
Unknown backend/version/key format rejects commissioning. Missing backend or
required evidence yields `Unavailable`; malformed supplied proof yields rejection.

| Class | Selected implementable boundary and required exact configuration |
|---|---|
| DeterministicReexecute | Planned DEV-DRE-1: M06's bounded Add/Transfer/Revert program only, exact runtime/profile/input bytes, integer arithmetic, outcome and write/receipt-root equality; no external I/O, clock, RNG or floating point. Pin backend and 1/2/4/8-worker vectors before enabling. |
| ReproducibleML | Unsupported by default. Enable only a named model+operator-set+runtime/backend image, tensor shapes/types, seeds, integer/fixed-point rounding/overflow and comparison predicate. Initial development choice permits exact integer output equality only; nondeterministic GPU kernels and unspecified tolerances reject commissioning. |
| ZkValidity | Unsupported by default. Select exactly one audited proof-system implementation/version and curve/field/security parameters; pin verifying-key bytes/hash, circuit/image/method ID, ordered public-input schema and maximum proof bytes/work. Recompute key hash from loaded bytes and self-test positive/negative corpus before enabling. No universal acceptance of a `proof_system` string. |
| TeeAttested | Unsupported by default. Select one quote format/verifier, vendor root certificate set, allowed measurements/security versions, freshness and revocation-snapshot rules. Pin exact root/CRL/TCB digests and validity intervals to finalized input. Verify certificate chain→quote signature→measurement→statement nonce/input/output binding. Missing/expired revocation data is unavailable; no host wall clock selects consensus validity. |
| StakeQuorum | Implemented local kernel: exact four-member set, unique keys, threshold and minimum signers, statement/evidence/profile hash equality. Development choice is four weights 1, threshold 3, minimum signers 3; provider/challenger keys cannot count as verifiers. This attests a statement under committee honesty, not objective truth. |
| OptimisticChallenge | Unsupported by default. Planned profile must name deterministic dispute predicate/backend, funded challenge bond, evidence/response/decision/appeal windows and retention. Development variant may use DEV-DRE-1 as the dispute oracle; no challenge alone cannot mean mathematically proven correctness. |
| SubjectiveEvaluation | Unsupported by default. Commission exact evaluator set, conflict exclusions, signed response schema and integer aggregation/quorum, abstention/appeal rules. Even if enabled its objective-settlement and PoCO flags stay false; its result is policy acceptance, not cryptographic truth. |

For DEV-DRE-1, fee/revert semantics come from the complete M06 profile, not an
unpriced toy interpreter. The ZK/TEE/ML rows are commissioning contracts; no
particular proof system, vendor key or model is silently chosen by this document.
Their disabled status is a complete operational decision: requests for them
return disabled/unsupported until an exact signed descriptor passes this process.

### Planned multi-challenge and maturity rules

Index challenges by `(result_id, result_revision, challenge_id)`; duplicate
IDs replay, concurrent distinct challenges each reserve a bond and increase
the open count. The result cannot mature while any challenge/appeal is open.
Every transition checks exact predecessor revision and the draft's height
predicate before debit. Deadline service runs on empty finalized blocks too.
Unavailable evidence is not adjudicated as invalid by local timeout.

The planned development windows are: 20 blocks to challenge, 10 for evidence,
10 for response, 10 for decision and 20 for appeal, all checked additions.
They are a selected candidate profile, not mainnet constants. An appeal uses
a separately pinned reviewer set and exact prior decision; it cannot erase
the earlier record. Final resolution changes application state forward only.
M12 obtains the exact final result revision, closed challenge count, profile
hash, maturity height and retained evidence from authenticated M08 state.

## Persistence and recovery

Persist Result, Challenge, bond, operation journal and finalized-block markers
in one transaction. Validate schema, config hash and durable state/operation/
marker roots on reopening. `fresh_confirm_receipt` must match the exact stored
operation and current authenticated lineage, not merely a nonzero digest.
Response loss after Evaluate/Adjudicate cannot debit the bond twice.
Before-commit recovery is source; after-commit recovery is exact target;
third-state recovery permanently fences the local owner.

Planned artifact retention extends through the maximum of challenge, appeal
and settlement windows. Release requires final resolution plus authenticated
M12/M09 acknowledgement; terminal status alone cannot delete evidence.
Whole-store rollback and physical storage qualification remain M03/M08 duties.

## Resource bounds

Existing kernel: four verifiers, one result/challenge, at most 64 evidence entries.
Planned networked development limits: 1 MiB evidence payload, 64 KiB signed
receipt/claim, 32 claims/request, 8 simultaneous challenges/result, one queued
backend task per result and 16 globally. Reject over-limit decode before allocation.
Every enabled descriptor supplies positive `max_proof_bytes`, `max_public_inputs`,
`max_verify_work`, `max_evidence_entries`, and finality-height windows bounded by
the host profile. The development ceilings are 1 MiB, 256, 1,000,000 work units,
64 and 10,000 blocks respectively; backend-specific work calibration must be pinned.
These planned ceilings do not enlarge any existing protocol/source limit.

## Security

Current kernel errors include `InvalidReceipt`, `InvalidClaim`, `InvalidSignature`,
`Unauthorized`, `UnderQuorum`, `StaleRevision`, `Expired`, `Conflict` and
`ConservationViolation`; rejection leaves revisions/bond/roots unchanged.
Registry errors separately distinguish `ProfileNotFound`, `ProfileHashMismatch`,
`ProfileDisabled`, `ProfileNotYetValid`, `ProfileExpired`, `ProfileRevoked` and
`SubjectiveAuthorityEscalation`. Never fallback to another profile on failure.
`StoreFailure`/backend unavailability are local; `CommitUncertain` reopens;
`SchemaMismatch`, `TamperDetected`, `ThirdStateFenced` fence.
Failed cryptographic work consumes its declared verification budget.

## Observability and SLO

Measure class-specific verification latency/work, backend unavailable rate,
challenge queue age, evidence retrieval failures, open bond amount and time to
final resolution. Distinguish ordering, verified result and settled result in
all metrics. Zero duplicated bond debits and zero profile fallback are invariants.
Measure the chosen backend on maximum legal proofs before commissioning limits.

## Verification and evidence

| Case | Input and expected result |
|---|---|
| M11-Q | Four weights 1, threshold 3: two claims `UnderQuorum`; three exact unique claims accept; duplicate member never adds weight |
| M11-PIN | Same ID/version, different profile hash: `ProfileHashMismatch` before backend invocation |
| M11-HEIGHT | Expiry 100/revocation 90: at 90 revoked; for unrevoked profile at 100 allowed, 101 expired |
| M11-UNAVAILABLE | Backend lacks pinned key or evidence: `Unavailable`, no switch to StakeQuorum, no final settlement |
| M11-BOND | Funded 100, challenge requires 30: open holds 30 once; exact retry leaves held=30 |
| M11-EVIDENCE | 65th evidence entry against cap 64 rejects with same revision/bond/root |
| M11-SUBJECTIVE | Subjective profile with objective settlement or PoCO flag true: commissioning rejects |
| M11-DRE, planned | Program Add(A,1), A=9, claimed A=11: deterministic reexecution computes 10 and rejects claim |

Replay `receipt_and_atomic_two_transition_evaluation_are_durable`,
`challenge_evidence_response_and_upheld_adjudication_are_atomic`,
`challenge_evidence_entries_are_hard_bounded`, and registry test
`disabled_expired_revoked_and_unknown_profiles_do_not_fallback`.
Independent vectors must include exact statement/key/proof bytes, expected
code and unchanged state, not production-generated expected values alone.
The [verify/challenge inventory](../protocol/poco-ai-native-v1/vectors/cev1-verify-challenge-kernel-v1.json)
lists the current StakeQuorum source cases; it is not interoperability evidence
for any of the six unimplemented backend classes.

## Activation boundary

Only the bounded StakeQuorum store is currently an executable durable backend.
Do not call the six other class names implemented solely because registry
dispatch exists. Every additional backend needs a complete descriptor, actual
implementation, interoperability corpus and specialist review; multi-challenge,
DA and M12 joins require real producer/consumer replay. No flag is promoted here.
