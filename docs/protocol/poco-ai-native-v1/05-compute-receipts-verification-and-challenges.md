# 05 — Compute receipts, verification, and challenges

Status: **DRAFT / design-only / not implemented / not activated**

## 1. Purpose and separation

PoCO-Compute binds off-chain execution claims to exact task, lease, artifacts,
metering, verification, challenge, and settlement contexts. It does not make
general AI inference deterministic consensus execution.

Three questions remain separate:

1. **What did the provider claim happened?** — `ExecutionReceiptV1`.
2. **Does the selected verification profile accept that exact claim?** —
   verification claims and `EvaluationResultV1`.
3. **What payment, refund, slash, or retry follows?** — result and settlement
   state transitions.

A cryptographically valid provider signature proves attribution, not correctness.
A valid ZK proof proves only its exact public statement. A valid TEE quote proves
only the profile-defined attestation statement. Neither proves external tool
data, social usefulness, fair price, party independence, or confidentiality not
included in that statement.

## 2. Artifact commitment

`ArtifactCommitmentBodyV1` names exact stored bytes independently from any DA
batch or availability certificate; the admitted object is
`ArtifactCommitmentV1`. `ArtifactTaskBindingV1` is:

```text
task_id                         TaskIdV1
lease_id                        Option<LeaseIdV1>
attempt                         Option<u32>
```

If `lease_id` is absent, `attempt` MUST be absent. If `lease_id` is present,
`attempt` MUST be present and the lease must belong to that task/attempt.

`ArtifactCommitmentBodyV1` has this exact logical field order:

```text
schema_version                  u16  // 1
genesis_hash                    Hash32
chain_id                        ConsensusString
protocol_version                u32  // 1
stack_profile_hash              Hash32
artifact_class                  u16
creator_agent_id                AgentIdV1
creator_key_id                  AgentKeyIdV1
task_binding                    Option<ArtifactTaskBindingV1>
content_codec_id                Hash32
content_digest                  Hash32
content_bytes                   u64
plaintext_commitment            Option<Hash32>
encryption_commitment           Option<Hash32>
verification_profile            Option<VerificationProfileRefV1>
retention_policy_hash           Hash32
metadata_commitment             Hash32
artifact_nonce                  Hash32
```

`artifact_class` is a closed `u16`: `0 Model`, `1 Dataset`, `2 TaskInput`,
`3 ResultOutput`, `4 ComputeCheckpoint`, `5 Transcript`, `6 MeterEvidence`,
`7 VerificationProof`, or `8 ChallengeEvidence`. A later class requires a new
protocol version or an already enumerated profile extension.

```text
content_digest = DigestV1(
  "trnm.poco-ai.artifact-content.v1",
  exact_stored_bytes_as_CEV1_Bytes
)
artifact_id = DigestV1(
  "trnm.poco-ai.artifact.v1",
  ArtifactCommitmentBodyV1
)
```

`exact_stored_bytes_as_CEV1_Bytes` means the raw stored bytes represented as the
CEV1 `Bytes` primitive; transport compression is never hashed in its place.
`ArtifactCommitmentV1` is the body, recomputed `ArtifactIdV1`, and its unique
creating operation-kind `9` `AgentTransactionIdV1`. The transaction's
authorization statement binds that exact transaction ID
under `trnm.poco-ai.artifact-commitment-signature.v1`; signing the typed ID
alone and submitting a bare artifact object are not authorization. `artifact_nonce` distinguishes intentionally
separate artifacts with identical content. A low-entropy content digest is not
confidentiality.

An availability certificate is issued later and binds the exact `ArtifactIdV1`
and stored-content commitment through the ArtifactEvidence DA namespace. It is
not part of `artifact_id`; certificate renewal or retention extension therefore
does not rename the artifact. Every task, checkpoint, receipt, verification
claim, or challenge reference MUST resolve the typed artifact ID and require the
DA status selected by its exact `VerificationProfileRefV1`.

## 3. Execution receipt

`ExecutionReceiptBodyV1` has this logical field order:

```text
schema_version                  u16  // 1
genesis_hash                    Hash32
chain_id                        ConsensusString
protocol_version                u32  // 1
stack_profile_hash              Hash32
task_id                         TaskIdV1
task_revision                   u64
lease_id                        LeaseIdV1
attempt                         u32
provider_agent_id               AgentIdV1
provider_key_id                 AgentKeyIdV1
provider_capability_id          Option<CapabilityIdV1>
provider_session_generation     u64
execution_outcome               u8
failure_code                    Option<u32>
execution_environment_hash      Hash32
model_commitment                Hash32
input_commitment                Hash32
parent_checkpoint_id            Option<CheckpointIdV1>
output_artifact_id              Option<ArtifactIdV1>
output_commitment               Hash32
transcript_artifact_id          Option<ArtifactIdV1>
evidence_artifact_ids           List<ArtifactIdV1>
meter_id                        Bytes
meter_version                   u32
meter_root                      Hash32
usage_totals                    List<ResourceUsageV1>
artifact_availability_ids       List<AvailabilityCertificateIdV1>
verification_profile_id         Bytes
verification_profile_version    u32
verification_profile_hash       Hash32
receipt_sequence                u64
provider_nonce_lane             u16
provider_nonce                  u64
submitted_height_upper_bound    u64
```

`execution_outcome` is `0 Success`, `1 Failed`, or `2 CancelledAtCheckpoint`.
`failure_code` is absent for Success and required for the other outcomes. A
failure receipt is an explicit claim about a failed attempt; it is not itself an
invalid receipt. The selected verification and settlement policies decide
whether the claim is credible and which allocation follows.

`ResourceUsageV1` is the single exact record also used by document 08:

```text
resource_class              u16
resource_id                 Bytes
meter_id                    Bytes
meter_version               u32
amount                      u128
unit                        u16
measurement_commitment      Hash32
```

Usage entries are strictly ordered by `(resource_class, resource_id,
meter_id, meter_version)`, duplicate-free, checked, and within the exact
task/lease/meter bounds. No compact `(u16, u16, amount, commitment)` encoding
is an alias for this record.

The three consecutive verification-profile fields are the exact inline
`VerificationProfileRefV1` and MUST equal the task and lease references.

```text
execution_receipt_id = DigestV1(
  "trnm.poco-ai.execution-receipt.v1",
  ExecutionReceiptBodyV1
)
```

`ExecutionReceiptV1` is the body, recomputed `ExecutionReceiptIdV1`, and its
unique creating provider operation-kind `10` transaction ID. The transaction's
statement binds that exact transaction under
`trnm.poco-ai.execution-receipt-signature.v1`; signing the typed
ID alone is not authorization. Signature bytes are not part of the ID. The
receipt is accepted only for the exact active Running lease and
attempt, with exact provider authority and nonce, compatible environment and
profile, valid meter version, required artifacts and availability certificates,
and internally consistent outcome fields.

Provider agent, key sentinel-or-key, capability, session generation, lane, and
nonce MUST equal the exact authorization statement and nonce namespace in
documents 02 and 03. Its live `capability_generation` and exact
`session_key_grant_id` come from the signed statement. A receipt that
substitutes `capability_generation` for `session_generation` is invalid.

Only one canonical receipt may enter verification for one lease/attempt. A
conflicting second receipt is rejected and retained as potential accountability
evidence; it does not overwrite the first.

## 4. Result object

`ResultBodyV1` contains:

```text
schema_version               u16  // 1
genesis_hash                 Hash32
chain_id                     ConsensusString
protocol_version             u32  // 1
stack_profile_hash           Hash32
task_id                      TaskIdV1
lease_id                     LeaseIdV1
attempt                      u32
execution_receipt_id         ExecutionReceiptIdV1
execution_outcome            u8
output_commitment            Hash32
verification_profile_id      Bytes
verification_profile_version u32
verification_profile_hash    Hash32
challenge_policy_hash        Hash32
settlement_policy_hash       Hash32
result_nonce                 Hash32
```

```text
result_id = DigestV1("trnm.poco-ai.result.v1", ResultBodyV1)
```

`ResultV1` is the immutable body and recomputed `ResultIdV1` created by the
receipt-admission transition. Mutable revision and status are `ResultStateV1`
keyed by `ResultIdV1`.

`ResultStateV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, result_id:ResultIdV1, revision:u64,
status:ResultStatusV1, accepted_height:u64,
challenge_close_height:Option<u64>,
latest_transition_hash:Option<ResultTransitionHashV1>,
transition_history_root:Hash32, challenge_index_root:Hash32,
open_challenge_count:u32, terminal_height:Option<u64>,
settlement_maturity:SettlementMaturityV1, pending_settlement_id:
Option<SettlementIdV1>)`. Receipt admission creates revision `0`, status
`Submitted`, chain-assigned `accepted_height = current_height`, both optional
fields absent, exact empty challenge-index/history roots, no terminal height,
`NotStarted`, and no settlement ID. The first admitted evaluation sets both a
present transition ID and close height; every later revision keeps them
present. An unchallengeable immediate-finality profile uses its chain-assigned
evaluation height as the present close height, never a numeric sentinel. Any
other presence combination is invalid.

`ResultTransitionBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1, result_id:ResultIdV1, prior_revision:u64,
next_revision:u64, prior_status:ResultStatusV1,
next_status:ResultStatusV1, transition_kind:u16,
authorizing_object_ids:List<TypedObjectIdV1>, applied_height:u64,
prior_transition_hash:Option<ResultTransitionHashV1>,
resulting_challenge_index_root:Hash32,
resulting_open_challenge_count:u32)`. `ResultTransitionHashV1 = DigestV1(
"trnm.poco-ai.result-transition.v1", ResultTransitionBodyV1)`. IDs are
strictly ordered and unique, contain the complete evaluation/challenge/window
objects required by the transition kind, and `next_revision = prior_revision +
1`; `applied_height` is chain-assigned current height.

`transition_kind` is closed through `6 SettlementFinalized`: `0 BeginEvaluation` is Submitted->Evaluating and
its authorizing list is exactly one tag-10 ExecutionReceipt ID (the profile is
the Result body's registry-resolved reference, not a TypedObjectId); `1
EvaluationDecision` is Evaluating to one of the
four profile-permitted outcomes and names exactly one
VerificationDecisionId plus its claims; `2 ChallengeOpened` is
ProvisionalValid->ChallengeOpen and names the new ChallengeId; `3
ChallengeUpdated` is ChallengeOpen->ChallengeOpen and names exactly the tag-14
ChallengeId plus the tag-21 enclosing kind-23 AgentTransactionId; `4
ChallengeResolved` is ChallengeOpen to the profile-derived terminal result and
names every terminal tag-14 ChallengeId plus its corresponding tag-21 kind-23
authority transaction ID;
and `5 WindowClosedUnchallenged` is ProvisionalValid->FinalValid, requires
`current_height > challenge_close_height`, zero open/total challenges, and
names the exact evaluation decision. `6 SettlementFinalized` preserves the
terminal ResultStatus, requires maturity `NotStarted -> Final` in the same
atomic kind-26 settlement write, leaves the challenge root/count unchanged,
and names exactly the tag-20 SettlementId. Unknown kind/pair/cardinality is invalid.
Operation 22 is one atomic two-transition operation. When the current result is
`Submitted` at revision `n`, it first derives `BeginEvaluation` at revision
`n+1` and then `EvaluationDecision` at revision `n+2`; both use the same
chain-assigned `current_height`, and neither intermediate state is externally
committed. The first transition's prior hash is the current state's last
transition hash and its resulting hash becomes the second transition's prior
hash. Both hashes are appended, in that order, to the complete history; the
challenge index/root and open count remain unchanged across the first record
and take their decision-derived values in the second. The operation's
`expected_result_revision` MUST equal `n`, `accepted_height` is that common
current height, and `challenge_close_height` is derived from it exactly once.
The only committed post-state has revision `n+2` and the decision outcome.
An operation-22 input already in `Evaluating`, any attempt to persist the
virtual intermediate state, or an implementation emitting only one of the two
records is invalid. Supporting asynchronous evaluation would require a new
protocol version and carrier.

Kinds 0/1 are therefore emitted only as that atomic pair by operation 22;
kinds 2–4 are emitted by operations 11/23. Kind 5
is emitted by operation 23 action `4 CloseExpired` targeting the result with no
challenge ID; that permissionless action carries the expected result revision
and exact close height. There is no automatic wall-clock or optional state
write at a boundary.

`ChallengeIndexEntryV1` is exactly `(challenge_id:ChallengeIdV1,
challenge_revision:u64, challenge_status:ChallengeStatusV1,
resolution_result_revision:Option<u64>,resolution_authority_id:
Option<TypedObjectIdV1>)`, strictly ordered by
raw challenge ID. `challenge_index_root` is `DigestV1(
"trnm.poco-ai.result-challenge-index-root.v1",
List<ChallengeIndexEntryV1>)`; the list is complete, not a selectable subset,
and `open_challenge_count` is the checked count of nonterminal entries.
Both resolution fields are absent for nonterminal entries and present for a
terminal entry; the revision is the uniquely resulting Result revision and the
authority ID is the exact terminal decision/withdraw/expiry operation object.
Neither field contains the ResultTransition hash, so the index and transition
hash construction is acyclic.
`transition_history_root` is `DigestV1(
"trnm.poco-ai.result-transition-history-root.v1",
List<ResultTransitionHashV1>)` over the gap-free revision order. These are
authenticated state values, not `RootKindV1` block-list aliases.

The three consecutive verification-profile fields are the exact inline
`VerificationProfileRefV1` and MUST equal the receipt, lease, and task
references.

The only result-status enum is `ResultStatusV1`:

```text
0 Submitted
1 Evaluating
2 ProvisionalValid
3 ChallengeOpen
4 FinalValid       // terminal
5 FinalInvalid     // terminal
6 Inconclusive     // terminal for this result
```

Allowed transitions are:

```text
Submitted -> Evaluating
Evaluating -> ProvisionalValid | FinalValid | FinalInvalid | Inconclusive
ProvisionalValid -> ChallengeOpen | FinalValid
ChallengeOpen -> FinalValid | FinalInvalid | Inconclusive
FinalValid -> FinalValid
FinalInvalid -> FinalInvalid
Inconclusive -> Inconclusive
```

The three status-preserving terminal edges are legal only for kind 6 in the
atomic `NotStarted -> Final` settlement-maturity write; no other
self-transition is legal.

Every transition consumes the exact preceding logical `ResultStateV1` (the
operation-22 second record consumes its uniquely derived virtual intermediate),
verifies the complete closed transition body and challenge index, increments its revision,
and records all authorizing evaluation/challenge IDs. `FinalValid` means the exact receipt
claim met the selected profile; it does not imply `execution_outcome = Success`.
`FinalInvalid` means the claim failed the profile. `Inconclusive` means the
profile's bounded process ended without an accepted positive or negative result;
it MUST NOT be converted to valid. The task policy determines refund, failure,
or a new attempt through migration.

Documents 08 and 09 MUST expose the exact `ResultStatusV1`; they MUST NOT create
parallel states named `Ordered`, `ResultProvisional`, `ResultResolved`,
`ResultMatured`, `Provisional`, `Challenged`, or `Matured`. Human-facing labels
map without changing state as follows:

| `ResultStatusV1` | Client meaning | Result-finality proof |
|---|---|---|
| `Submitted` | pending admission/evaluation | forbidden |
| `Evaluating` | pending evaluation | forbidden |
| `ProvisionalValid` | provisional, challenge window openable | forbidden |
| `ChallengeOpen` | challenged | forbidden |
| `FinalValid` | profile accepted the exact receipt | permitted |
| `FinalInvalid` | profile rejected the exact receipt | permitted |
| `Inconclusive` | terminal without positive/negative decision | forbidden |

Settlement maturity is a separate closed enum, `SettlementMaturityV1`:

```text
0 NotStarted
1 Pending
2 Final
```

The canonical proof/API view is the pair
`ResultSettlementStatusV1(result_status: ResultStatusV1,
settlement_maturity: SettlementMaturityV1)`; neither component is inferred from
the other. In reference v1, `Pending` exists only in the kind-26 deterministic
candidate intent during execution and MUST NOT appear in committed
`ResultStateV1`; persisting that phase requires a later protocol version. The
atomic successful write changes NotStarted directly to Final and records the
exact conserved receipt; a client reports/proves Final only after the containing
block is order-finalized. `FinalValid` and `FinalInvalid` may both lead to payment,
refund, slash, or mixed settlement according to the frozen policy.
`Inconclusive` remains without a positive or negative result-finality proof, but
its task policy may independently create a refund/failure settlement or a new
attempt. Settlement never rewrites a terminal `ResultStatusV1`.

## 5. Verification profile

`VerificationProfileBodyV1` is a complete immutable context-free value:

```text
schema_version                  u16  // 1
protocol_version                u32  // 1
profile_id                      Bytes
profile_version                 u32
verification_class              u8
statement_schema_hash           Hash32
required_binding_fields         List<u16>
required_artifact_classes       List<u16>
required_da_policy_hash         Hash32
verifier_set_hash               Option<Hash32>
verifier_quorum_rule            Option<QuorumRuleV1>
cryptographic_policy_hash       Option<Hash32>
tee_trust_policy_hash           Option<Hash32>
reexecution_environment_hash    Option<Hash32>
comparison_policy_hash          Option<Hash32>
maximum_evidence_bytes          u64
maximum_verification_cost       u128
initial_decision_rule           u8
challenge_policy_hash           Hash32
result_finality_rule            u8
inconclusive_action             u8
settlement_policy_hash          Hash32
poco_eligibility_policy_hash    Hash32
active_from_epoch               u64
inactive_after_epoch            Option<u64>
```

`QuorumRuleV1` is the exact record `(threshold_weight: u128,
minimum_unique_signers: u32, conflict_rule: u8)`. `conflict_rule` is `0 Reject`
or `1 ResolveByDecisionRound`; unknown values fail closed. A present rule
requires a present `verifier_set_hash`, positive threshold and signer count, and
checked threshold no greater than the committed verifier-set total.

The profile is a context-free registry value: its hash preimage MUST NOT contain
`genesis_hash`, `chain_id`, `stack_profile_hash`, or a chain object ID. The task
and result supply that context when they commit its exact hash. This prevents a
circular dependency between the genesis descriptor, stack profile, verification
registry, and verification profiles.

```text
verification_profile_hash = DigestV1(
  "trnm.poco-ai.verification-profile.v1",
  VerificationProfileBodyV1
)
```

`VerificationProfileV1` is the exact body plus
`VerificationProfileRefV1(profile_id, profile_version,
verification_profile_hash)`. Its content digest is the
`verification_profile_hash`; `(profile_id,
profile_version)` in the active verification registry MUST resolve to that exact
hash. An unknown, inactive, or mismatched profile fails closed. A profile is
fixed for a task and cannot be switched after receipt submission.

The required binding set MUST include at least genesis, chain, protocol, stack
profile, task, lease, attempt, provider, execution environment, input,
execution outcome, output, receipt ID, meter root, and verification profile.
A profile may require more but cannot omit those fields.

## 6. Verification classes

`verification_class` is:

```text
0 DeterministicReexecute
1 ReproducibleML
2 ZkValidity
3 TeeAttested
4 StakeQuorum
5 OptimisticChallenge
6 SubjectiveEvaluation
```

The classes have these minimum rules:

### 6.1 DeterministicReexecute

The profile freezes complete canonical inputs, environment/runtime, resource
bounds, outcome/failure semantics, and exact comparison. Every voting validator
deterministically reexecutes before accepting the evaluation transition. Local
resource exhaustion is `Unavailable`, not an invalid result.

### 6.2 ReproducibleML

The profile freezes model/environment/input commitments, deterministic seeds,
numeric representation, hardware/backend eligibility, number of repetitions,
and a canonical integer or fixed-point comparison predicate. Unspecified
floating-point tolerance, library behavior, or hardware-dependent comparison is
forbidden. The profile names a verifier set and quorum or another exact decision
rule; ordinary consensus validators need not repeat the ML run unless named.

### 6.3 ZkValidity

The profile freezes proof system, proof schema, verification key/image/method
commitment, public statement encoding, bounds, and deterministic verifier. A
valid proof establishes only the bound statement. Missing backend, key, or proof
data is `Unavailable`/`Inconclusive`, never valid.

### 6.4 TeeAttested

The profile freezes accepted TEE technology, trust roots, measurement policy,
quote schema, freshness source, revocation data, workload/input/output binding,
and deterministic quote verification. It explicitly states rollback,
side-channel, operator, and supply-chain assumptions. Quote acceptance is not a
general claim that the output is true.

### 6.5 StakeQuorum

The profile freezes an independently committed verifier set, signer weights,
quorum, conflict policy, and slash/bond scope. Signers attest the exact result
statement. Provider/self/related-party signers are excluded unless the profile
explicitly permits them while preserving its fault assumption. A verifier QC is
not a PoCO-Order QC and cannot finalize a block.

### 6.6 OptimisticChallenge

The exact receipt becomes `ProvisionalValid` after deterministic admission and
remains non-final through a height-bounded challenge window. No provider payment
or PoCO eligibility becomes final before the window closes and all challenges
terminate. Absence of challenge is a policy acceptance condition, not proof of
objective correctness.

### 6.7 SubjectiveEvaluation

The profile freezes evaluator identities/selection, response schema, quorum or
aggregation, conflicts, abstention, appeal, timing, compensation, and disclosed
subjective criteria. Its `FinalValid` means only that the declared evaluator
policy accepted the result. It MUST NOT be presented as objective cryptographic
or deterministic validity.

There is no automatic fallback between classes. A profile cannot try ZK, then
silently accept TEE or stake quorum on failure. A task that permits alternatives
must select one exact composite profile before lease creation, including its
decision tree and binding rules.

## 7. Verification claim and evaluation result

`VerificationClaimBodyV1` contains:

```text
schema_version              u16  // 1
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32  // 1
stack_profile_hash          Hash32
result_id                   ResultIdV1
execution_receipt_id        ExecutionReceiptIdV1
verification_profile_id     Bytes
verification_profile_version u32
verification_profile_hash   Hash32
decision_round              u32
verifier_id                 Bytes
verifier_key_id             Bytes
verdict                     u8
statement_digest            Hash32
evidence_root               Hash32
evidence_artifact_ids       List<ArtifactIdV1>
availability_certificate_ids List<AvailabilityCertificateIdV1>
claim_sequence              u64
```

`verdict` is `0 Valid`, `1 Invalid`, or `2 Indeterminate`. A verifier signs:

```text
verification_claim_id = DigestV1(
  "trnm.poco-ai.verification-claim.v1",
  VerificationClaimBodyV1
)
```

The three consecutive profile fields are the exact inline
`VerificationProfileRefV1`. `VerificationClaimV1` is the body, recomputed
`VerificationClaimIdV1`, and verifier signature over `DigestV1(
"trnm.poco-ai.verification-claim-signature.v1", verification_claim_id)`.
Claims are valid only under the exact profile role, key, set, round, statement,
artifact and DA rules. Duplicate verifier claims do not add weight. Conflicting
claims from one verifier are rejected and retained as accountability evidence.

`EvaluationResultBodyV1` has this exact field order:

```text
schema_version                u16  // 1
genesis_hash                  Hash32
chain_id                      ConsensusString
protocol_version              u32  // 1
stack_profile_hash            Hash32
result_id                     ResultIdV1
expected_result_revision      u64
execution_receipt_id          ExecutionReceiptIdV1
verification_profile_id       Bytes
verification_profile_version  u32
verification_profile_hash     Hash32
decision_round                u32
accepted_claims              List<VerificationClaimV1>
accepted_claim_ids            List<VerificationClaimIdV1>
unique_signer_weight           u128
class_proof_digest             Hash32
decision                       u8
decision_rule_digest           Hash32
evidence_root                  Hash32
requested_challenge_extension_blocks Option<u64>
decision_nonce                 Hash32
```

Accepted claim IDs are strictly increasing by raw typed-ID bytes and
duplicate-free and are the exact one-to-one projection of the complete inline
signed claims in that same order. Every claim ID/signature/profile/result/round
and verifier-set membership is reverified; a hash-only claim reference is
invalid. `decision` is `0 Valid`, `1 Invalid`, or `2 Inconclusive`; the
claimed signer weight is recomputed and ignored as authority. A
class-specific proof digest is mandatory even when it is the canonical empty
proof value selected by the profile.

```text
verification_decision_id = DigestV1(
  "trnm.poco-ai.verification-decision.v1",
  EvaluationResultBodyV1
)
```

`EvaluationResultV1` is the body and recomputed
`VerificationDecisionIdV1`; it has no additional evaluator signature and is a
deterministic aggregate submitted under the outer transaction's fee/nonce
authorization. The inline signed claims are its sole verifier authority. It has
no submitter-chosen evaluation height. The
chain records `accepted_height = current_height` in its evaluation state after
successful execution and derives
`challenge_close_height = checked_add(accepted_height,
profile.minimum_challenge_blocks)`. The minimum is positive for every
challengeable profile. A requested extension, when allowed by the exact
profile, may only increase this duration up to the committed maximum; it never
shortens it. Overflow or a past/zero effective window is invalid. An
unchallengeable deterministic profile requires both minimum and requested
extension to be zero and follows its separately enumerated immediate-finality
rule. Every full node independently verifies the aggregate against the selected
profile before applying a result transition. A claimed weight or decision is
informational; it is recomputed from exact state.

## 8. Challenge

`ChallengeBodyV1` contains:

```text
schema_version                u16  // 1
genesis_hash                  Hash32
chain_id                      ConsensusString
protocol_version              u32  // 1
stack_profile_hash            Hash32
result_id                     ResultIdV1
execution_receipt_id          ExecutionReceiptIdV1
verification_profile_id       Bytes
verification_profile_version  u32
verification_profile_hash     Hash32
challenger_agent_id           AgentIdV1
challenger_key_id             AgentKeyIdV1
challenger_capability_id      Option<CapabilityIdV1>
challenger_session_generation u64
challenger_nonce_lane         u16
challenger_nonce              u64
challenge_kind                u16
challenged_statement_digest   Hash32
counter_statement_digest      Hash32
evidence_artifact_ids         List<ArtifactIdV1>
availability_certificate_ids  List<AvailabilityCertificateIdV1>
challenge_bond_id             BondIdV1
challenge_bond_asset_id       Hash32
challenge_bond_amount         u128
requested_remedy              u8
evidence_deadline_height      u64
response_deadline_height      u64
decision_deadline_height      u64
challenge_nonce               Hash32
```

Deadlines are nondecreasing. The challenge kind, standing, bond, evidence,
remedy, window, evaluator and decision rule MUST be enumerated by the result's
frozen challenge policy.

```text
challenge_id = DigestV1(
  "trnm.poco-ai.challenge.v1",
  ChallengeBodyV1
)
```

The three consecutive profile fields are the exact inline
`VerificationProfileRefV1`. `ChallengeV1` is the body, recomputed
`ChallengeIdV1`, and its unique creating challenger operation-kind `11`
transaction ID. The transaction statement binds that exact transaction under
`trnm.poco-ai.challenge-signature.v1`;
signing the typed ID alone is not authorization. The challenger authorization
fields MUST equal the exact five-component nonce namespace and active
`AuthorizationStatementV1`; live capability generation and session-key grant
are independently bound by that statement.

`opened_height` is not submitter-controlled and is not part of
`ChallengeBodyV1`, `challenge_id`, or the signature. On successful execution the
chain creates `ChallengeStateV1` with `opened_height = current_height`, revision
zero, and status `Open`. It then requires
`opened_height <= evidence_deadline_height <= response_deadline_height <=
decision_deadline_height` and every profile-relative maximum. Exact replay is
idempotent and cannot assign a second opening height.

The exact mutable record is `ChallengeStateV1 = (schema_version:u16=1,
context:ProtocolContextV1, challenge_id:ChallengeIdV1, result_id:ResultIdV1,
revision:u64,status:ChallengeStatusV1,opened_height:u64,
evidence_entries:List<ChallengeEvidenceEntryV1>,evidence_root:Hash32,
response_entries:List<ChallengeResponseEntryV1>,response_root:Hash32,
decision_entries:List<ChallengeDecisionEntryV1>,decision_root:Hash32,
challenge_bond_id:BondIdV1,bond_state_version:u64,last_transition_hash:Hash32,
terminal_height:Option<u64>)`. Creation uses canonical empty roots, revision
zero/Open, chain-assigned opened height, and no terminal height. Every kind-23
update consumes the exact revision/deadlines, appends and recomputes the owning
root, increments once, and sets terminal height exactly once for a terminal
status.

Challenge creation declares the exact tag-47 BondState Write and requires its
owner/asset/purpose/source result to equal the challenge body, its available
amount to cover `challenge_bond_amount`, and its version to equal the created
state field. Reserve, reward, release, or slash is one atomic BondState version
transition with the Challenge/Result update; a bond ID cannot be reused for a
second live challenge obligation.

`ChallengeStatusV1` is:

```text
0 Open
1 EvidenceWindow
2 Adjudicating
3 Upheld       // terminal
4 Rejected     // terminal
5 Withdrawn    // terminal
6 Expired      // terminal
```

The three append-only collections are exact. `ChallengeEvidenceEntryV1` is
`(submitter_agent_id:AgentIdV1,artifact_id:ArtifactIdV1,
availability_certificate_id:AvailabilityCertificateIdV1)`;
`ChallengeResponseEntryV1` is `(respondent_agent_id:AgentIdV1,
response_statement_digest:Hash32,artifact_ids:List<ArtifactIdV1>,
availability_certificate_ids:List<AvailabilityCertificateIdV1>)`; and
`ChallengeDecisionEntryV1` is `(decision:u8,decision_rule_digest:Hash32,
accepted_claims:List<VerificationClaimV1>,
accepted_claim_ids:List<VerificationClaimIdV1>,class_proof_digest:Hash32)`.
The IDs are the strict one-to-one ordered projection of the complete signed
claims and every signature/profile/verifier weight is reverified.
Inner lists are strictly ordered/unique and paired artifacts/certificates must
prove the exact DA relation. Evidence entries are ordered by
`(submitter,artifact_id,certificate_id)`; response and decision entries are in
accepted revision order. Their roots are respectively `DigestV1(
"trnm.poco-ai.challenge-evidence-root.v1",List<ChallengeEvidenceEntryV1>)`,
`DigestV1("trnm.poco-ai.challenge-response-root.v1",
List<ChallengeResponseEntryV1>)`, and `DigestV1(
"trnm.poco-ai.challenge-decision-root.v1",
List<ChallengeDecisionEntryV1>)`. Creation uses the canonical empty lists.
The state retains the three complete bounded lists as well as their recomputed
roots; a hash without its list is not sufficient state-sync authority.

`ChallengeTransitionBodyV1` is exactly `(schema_version:u16=1,
context:ProtocolContextV1,challenge_id:ChallengeIdV1,
prior_revision:u64,next_revision:u64,prior_status:ChallengeStatusV1,
next_status:ChallengeStatusV1,action_kind:u8,action_commitment:Hash32,
prior_evidence_root:Hash32,next_evidence_root:Hash32,
prior_response_root:Hash32,next_response_root:Hash32,
prior_decision_root:Hash32,next_decision_root:Hash32,
result_transition_hash:ResultTransitionHashV1,applied_height:u64)`;
`last_transition_hash = DigestV1("trnm.poco-ai.challenge-transition.v1",
ChallengeTransitionBodyV1)`. The chain constructs it from the exact prior
state/action/current height; callers do not supply successor roots or status.

`ChallengeUpdateOperationBodyV1` is the exact kind-23 body
`(schema_version:u16=1, context:ProtocolContextV1,
challenge_id:Option<ChallengeIdV1>, result_id:ResultIdV1,
expected_challenge_revision:Option<u64>, expected_result_revision:u64,
action:ChallengeUpdateActionV1)`, where the closed action union is:

```text
0 AddEvidence {
    evidence_artifact_ids:List<ArtifactIdV1>,
    availability_certificate_ids:List<AvailabilityCertificateIdV1>
  }
1 Respond {
    response_statement_digest:Hash32,
    evidence_artifact_ids:List<ArtifactIdV1>,
    availability_certificate_ids:List<AvailabilityCertificateIdV1>
  }
2 Adjudicate {
    decision:u8, decision_rule_digest:Hash32,
    accepted_claims:List<VerificationClaimV1>,
    accepted_claim_ids:List<VerificationClaimIdV1>,
    class_proof_digest:Hash32
  }
3 Withdraw { reason_code:u16 }
4 CloseExpired { expected_deadline_height:u64 }
```

Decision is the closed enum `0 Uphold` or `1 Reject`; unknown values fail
closed. Evidence/IDs are strictly ordered and unique and every root recomputes. Action
0 requires challenger authority before the evidence deadline; action 1 the
profile-named respondent before its deadline; action 2 the exact verifier/
adjudicator rule and complete proof; action 3 the challenger under the profile;
and action 4 is permissionless but only after the authenticated applicable
deadline. For no-challenge result-window closure `challenge_id=None` is
mandatory and every challenge action except 4 is invalid; otherwise it is
present and equals the target. The expected challenge revision is absent iff
the challenge ID is absent and present/equal to current otherwise. Every action verifies current challenge/result state and atomically
updates both challenge index and result transition history; no local clock or
missing-evidence default can decide it.

Allowed transitions are:

```text
Open -> EvidenceWindow | Withdrawn | Expired
EvidenceWindow -> Adjudicating | Withdrawn | Expired
Adjudicating -> Upheld | Rejected | Expired
```

Action 0 performs only `Open -> EvidenceWindow` or appends while remaining
EvidenceWindow; action 1 performs `EvidenceWindow -> Adjudicating` or appends
while remaining Adjudicating; action 2 performs only `Adjudicating -> Upheld`
for decision 0 or `Adjudicating -> Rejected` for decision 1; action 3 performs
Open/EvidenceWindow to Withdrawn; action 4 performs any nonterminal state to
Expired after its exact authenticated deadline. Challenge opening changes
Result `ProvisionalValid -> ChallengeOpen`. While any challenge remains open,
updates keep Result `ChallengeOpen -> ChallengeOpen`; an Upheld terminalizes it
as `FinalInvalid` or `Inconclusive` exactly as the frozen profile dictates.
Rejected/Withdrawn/Expired leaves it ChallengeOpen while another challenge is
open, otherwise returns to ProvisionalValid before the close height, and becomes
FinalValid only after the close height and all profile conditions pass. Every
case emits the one linked `ResultTransitionBodyV1` and updates both states in
the same atomic write set.

Each transition consumes exact challenge revision. Evidence additions are
append-only, content-addressed, profile-bounded, available under the required DA
contract, and closed at the evidence deadline. Unknown challenge kinds,
late evidence, missing data, unavailable adjudicators, or inconclusive checks
MUST NOT become an upheld challenge by default.

The profile bounds simultaneous challenges and defines deterministic ordering,
coalescing of identical claims, conflicts, appeal, and deadline outcomes. A
challenge bond is reserved atomically at creation. Upheld/rejected/expired/
withdrawn outcomes allocate that bond and any provider/verifier accountability
consequence exactly once.

## 9. Challenge effects and forward finality

An upheld challenge against `ProvisionalValid` changes the result to
`FinalInvalid` or `Inconclusive` according to the frozen policy. It may cause
provider/verifier slash, challenger reward, requester refund, or a new task
attempt through `Migrating`. It cannot delete or rewrite the receipt, prior
evaluation, or order-finalized blocks.

A rejected challenge permits the result to become `FinalValid` only when every
other challenge is terminal and the profile's window/finality rule is satisfied.
Expired or withdrawn challenges follow the explicit profile rule; neither is
silently treated as evidence that the result is correct.

If a fault is discovered after result or settlement finality, any remedy is a
new forward order-finalized compensation, slash, reputation, or governance
transition under a separately authorized accountability rule. It never reorgs
the finalized prefix and cannot silently mutate a historical result status.

## 10. Result and settlement finality

Result finality occurs only at `FinalValid` or `FinalInvalid`; `Inconclusive` is
terminal for the particular result but is not a positive or negative proof.
The result-finality proof named in document 09 must authenticate order finality
of the exact terminal transition and the selected profile/claims/challenges.

Settlement finality is separate. It requires either `FinalValid`/
`FinalInvalid`, or an `Inconclusive` task-policy terminalization that explicitly
authorizes refund/failure settlement; it additionally requires the exact task
settlement policy, conserved escrow/bond/fee transition, and order finality of
that transition. `FinalValid` can settle differently for Success, Failed, and
CancelledAtCheckpoint receipts. No provisional result, open challenge, or mere
receipt signature authorizes final payment or PoCO-weight eligibility.

## 11. Consumption eligibility

Execution receipts and meter roots are inputs to later ConsumptionRollup
construction; they are not themselves PoCO voting weight. A task contributes
only after the exact settlement is final, every challenge is terminal, the
meter/profile/related-party policies pass, the consumption claim matures, and
the later epoch snapshot applies caps and bond ceilings. Document 08 defines the
rollup and settlement accounting; document 07 defines validator weight.

## 12. Required invariants and vectors

Conformance MUST cover:

- explicit Success/Failed/Cancelled receipt outcomes and field consistency;
- exact task/lease/attempt/provider/environment/input/output/meter/profile
  binding and conflicting-receipt rejection;
- all seven verification classes, with missing backend/data, indeterminate,
  wrong statement, wrong profile, duplicate/conflicting verifier, and threshold
  edges;
- no fallback between verification classes and no profile switch after task
  creation;
- result lifecycle, revision monotonicity, challenge boundary heights, evidence
  closure, duplicate challenge, and bounded concurrent challenge ordering;
- atomic challenge-bond and provider/verifier bond accounting;
- no payment or PoCO eligibility before result and settlement finality;
- an upheld post-order challenge producing forward effects without changing any
  previously finalized block; and
- independent reproduction of all CEV1 bytes, typed IDs, statement digests,
  signatures, evaluation aggregates, and mutation rejection.
