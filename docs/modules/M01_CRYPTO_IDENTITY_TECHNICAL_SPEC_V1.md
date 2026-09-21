# M01 Cryptography / Identity / Capability technical specification v1

Status: **module-specific implementation design; frozen v0 verification retained;
planned identity adapters are not implemented production authority**.
Primary module: M01. Producers: M00/M03/M10/M13. Consumers: M02/M04/M05/M08/M14.

## Authority

Use `TRNM_DOCUMENTATION_AUTHORITY_V1.md`, frozen v0 specifications 01/03/04/06
and their key/signature/PoP vectors. PCC1 uses v0 cryptography unchanged.
AI identity and capability objects belong to the separately selected `ai-v1`
profile; a valid AI credential is not a validator vote, and validator membership
is not application spending authority.

Existing verification lives in `trnm-consensus-crypto/src/lib.rs`,
`strict_finality.rs` and `epoch_transition.rs`; canonical public types live in
`trnm-consensus-types`. M01 verifies and issues private capabilities. M03 owns
secret custody, durable signing decisions and recovery; M01 never opens keys.
The target is one strict, budgeted verification boundary per authority class,
with producers unable to choose their own trust roots.

## Interfaces

### Existing strict finality interface

```text
decode_verify_finality_proof_strict_v0(
  proof_class: &str,
  bytes: &[u8],
  trusted_validator_set: &ValidatorSet,
  trusted_parameters: &ConsensusParametersV0,
  expected: FinalityExpectationV0,
  budget: &mut Cev0AdmissionBudgetV0
) -> Result<StrictFinalityProofV0, StrictFinalityErrorV0>
```

`proof_class` must equal `poco-three-chain-v0`.
`FinalityExpectationV0` contains block_id, height, state_root, receipts_root,
evidence_root, parent_id, parent_height and parent_timestamp_ms. These public
fields are claims supplied from the consumer's authenticated state, not proof.
`StrictFinalityProofV0` has private construction and no public Clone/Deserialize;
it is verification evidence, not permission to commit, sign or activate.

Existing `StrictFinalityErrorV0` distinguishes `UnsupportedProofClass`,
`TargetMismatch`, `ParentMismatch`, `Decode(DecodeError)` and
`Consensus(ValidationError)`. Preserve this typed chain; never identify errors
by matching display text. A wrong expected target is not repaired by choosing
the newest QC from the proof.

### Pre-certificate handoff and first-epoch finality consumers

`verify_pre_handoff_context_strict_v1` in `pre_handoff.rs` takes the old
checkpoint/two-seal finality, next-epoch commitment, exact handoff descriptor,
both validator sets/parameter preimages and the independently authenticated
checkpoint parent. It admits all keys in both sets, verifies old-set signatures
and parent geometry, reconstructs every descriptor field, and returns private
`StrictPreHandoffContextV1`. Its binding covers all input identities. It needs
no joint certificate: M03 must obtain this context before collecting the two
role quorums. It does not prove checkpoint execution or grant signing authority;
the native host must separately join a freshly read committed execution receipt
before asking the durable signer journal to sign the role-specific intent.

`decode_verify_epoch_first_finality_strict_v1` accepts the eight exact activation
preimages plus a first-new-epoch three-chain proof, independent old-set trust,
`FinalityExpectationV0` and one mutable admission budget. It bounds their aggregate
raw length before decoding, strictly verifies complete activation evidence, and
checks the proof's target against all expected fields and the actual terminal
seal's ID/height/timestamp. The oldest header is the exact authorized
`EpochHandoff` at C+3; its children are ordinary blocks. Every proposal, QC, TC
entry and referenced QC is strictly verified under the authenticated new set.
Skipped views use a TC whose synthetic epoch references match the already
verified activation authority; no generic verifier is given an accept-anchor flag.

The private result `StrictEpochFinalityProofV1` retains strict finality, the
verified old checkpoint header and new configuration. M13 compares that
checkpoint to its current trusted head before advancing; M05 uses the returned
new parameters for receipt bounds. Ordinary finality decoding remains a separate
entrypoint and rejects an epoch anchor. Neither result activates Core or commits
application state. Typed failures include `EpochEvidence` and `EpochActivation`
in addition to the existing decode, context and consensus causes.

### Complete first-proposal verification (implemented candidate)

```text
verify_first_epoch_proposal_strict_v1(
  activation: &StrictSameVersionEpochActivationAuthorityV0,
  proposal: SignedProposalV0,
  budget: &mut Cev0AdmissionBudgetV0
) -> Result<StrictFirstEpochProposalV1, ValidationError>
```

`epoch_proposal_v1.rs` verifies the actual canonical application payload and
bounded evidence root, exact C+3 handoff header/terminal parent, exact synthetic
justify/authorization, leader signature and all required skipped-view TC/QC
references. Its private no-Clone result exposes the exact proposal,
`RootBoundEpochBodyV1` summary and activation binding. It grants no application
Valid result, P record, Core migration or signing lease. Consumers still require
M06/M08 execution against the authenticated application parent.

The shared strict witness verifier is also used by first-epoch finality, avoiding
a second TC policy. Raw resource, all QC references, nested TC shares, proposer
and evidence signature work are reserved before cryptographic verification;
an insufficient budget rejects without starting that work, and an invalid
signature does not refund a reserved budget. Existing header-only first-proposal
and ordinary finality APIs keep their distinct authority and anchor restrictions.
Real Ed25519 tests cover view1, a skipped view with exact TC, one-short budgets,
substituted payload and bad signature. These establish cryptographic admission,
not live Core/new-signer activation.

### Full epoch runtime context (implemented inert candidate)

`StrictEpochRuntimeContextV1::from_activation_v1` consumes a complete
`StrictSameVersionEpochActivationAuthorityV0`. It retains all eight evidence
roots and exposes only their exact anchor/authorization context for strict
QC/TC/proposal/finality consumers. Closed exact decoders may reconstruct a
structural `EpochRuntimeContextDataV1` from complete decoded evidence, but this
value grants no cryptographic, signing, Core or application authority. No generic
verifier gains an accept-anchor flag. Runtime verification charges shared QC/TC
and proposer/evidence work before cryptographic verification. Every retained
synthetic reference must equal the context's exact new view-zero anchor, including
skipped-view TC entries; old-context certificates are rejected on active ingress.

The three explicit V1 exact decoders are
`decode_epoch_runtime_qc_reference_v1_exact_with_budget`,
`decode_epoch_runtime_timeout_certificate_v1_exact_with_budget`, and
`decode_epoch_runtime_finality_proof_v1_exact_with_budget`. All use the complete
structural context and caller-owned byte/signature budget, exhaust the root,
and require canonical re-encoding. `verify_proposal_v1` verifies the real parent;
`verify_proposal_without_parent_v1` only preauthenticates Regular/checkpoint
carriers to request missing ancestry, and cannot establish timestamp or parent
state. `verify_proposal_at_parent_timestamp_v1` additionally checks an already
authenticated compact timestamp; seals and handoffs require the full-parent API.
Real Ed25519 tests cover TC-bearing first finality, exact work boundaries,
foreign old QCs, bad shares and parent timestamp substitution. Core 14E and the
pure SafetyRules context consume this verifier; live Core/custody activation is
still unavailable at this checkpoint.

### Identity and domain binding

| Authority | Required independently authenticated context |
|---|---|
| Validator vote/timeout | Genesis, chain, protocol, epoch, exact validator set and parameters, author, view and message kind. |
| Proposal | Same context, scheduled leader and exact header/justify/optional TC digests. |
| Validator PoP | Exact identity/key, registration/rotation nonce, chain and target epoch per frozen PoP preimage. |
| Handoff role | Old and new configuration commitments, exact descriptor and old/new role under that role's set. |
| P2P session | Peer identity, session/generation, transcript and role-specific M04 authority. |
| Application signer | Authenticated parent policy, signer/key generation, exact envelope and replay/expiry rules from M05/M10. |

Do not conflate a key's possession with its authorization. An old-set member is
not automatically a registered future candidate; a signed relationship claim
does not prove independent operators or real demand.

Planned pure adapter signature:

```text
verify_authorized_statement(
  context: AuthenticatedAuthorityContext,
  statement: DecodedInert<SelectedStatement>,
  expected: ExpectedStatementTarget,
  budget: &mut VerificationBudget
) -> Result<VerifiedStatement, VerificationFailure>
```

The context stores profile/role, chain/genesis, authenticated set or policy root,
epoch or key/session generation, and validity interval. The expected target is
owned by the consuming module. The private result retains all these bindings
and the exact canonical statement bytes/digest; no bare `bool` grants authority.
This is a target local API, not a new Rust symbol or wire type today.

### Owned remote-signer data protocol

`trnm-consensus-remote-signer-protocol` is a `no_std` data-only package.
`RemoteConsensusCommandV1` accepts complete canonical vote/timeout intents;
`RemoteSignerRequestV1` couples the command with
`RemoteSignerRequestBindingV1`, nonce and request fingerprint. The binding's
service/client/role profiles, process generation, lease and checkpoint witness
are public claims which M03's independently commissioned service must check.
They are not credential bytes or a safe-vote permit.

Use `decode_remote_signer_request_v1_exact` and
`decode_unverified_remote_signer_response_v1_exact` for the ordinary purpose.
Proposal requests have separate magic/purpose profile and the exact
`decode_remote_proposal_signer_request_v1_exact` /
`decode_unverified_remote_proposal_signer_response_v1_exact` pair. Preserve
that separation: ordinary command decoding must reject proposal frames.
`UnverifiedRemoteSignerResponseV1` remains unverified until M03 checks exact
request/response fingerprint, binding, nonce and strict signature against the
commissioned validator key. M01 owns byte/ID validity; M03 owns nonce freshness,
Safety authorization, lease/generation continuity and signature publication.

Retain `RemoteConsensusCommandValidationErrorV1`, `RemoteSignerIdErrorV1` and
`RemoteSignerProtocolErrorV1` at their boundaries. Invalid canonical bytes or
purpose/binding mismatches reject before key access; transport unavailability
does not become a protocol-valid response. Allocate at most the corresponding
`MAX_REMOTE_SIGNER_REQUEST_BYTES_V1`, `MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1`,
proposal variants and `MAX_REMOTE_SIGNER_PUBLIC_DESCRIPTOR_BYTES_V1`; M03 may
apply a smaller signed deployment limit. This crate persists no nonce or key.
Required vectors cover changed purpose, lease, generation, checkpoint, nonce,
fingerprint and trailing bytes, plus a validly encoded response with an invalid
signature. A protocol round trip alone must never satisfy signer acceptance.

### Owned auxiliary contract: governance-guard

`contracts/governance-guard/src/lib.rs` implements an in-memory reference guard,
not a signed on-chain governance executor. `new(admin,guardian,min_delay)` owns
role/key allowlists, proposal nonce/map, parameter values+versions, pause flag
and event log. `set_role`, `set_guardian` and `set_allowed_param_key` require admin.
Its `caller: &str` and `now: u64` are supplied values; a production adapter must
resolve caller from authenticated execution and time from the selected finalized
height/timestamp contract, never accept them as public RPC authority.

`propose(caller,key,old,new,eta,reason,now)` checks proposer/key/timelock and
captures parameter base_version. `queue` requires that still-authorized original
proposer and is idempotent for an already queued ParamChange.
`execute(caller,id,now)` rechecks executor, queued status, ETA, current key allowlist,
old value and base version before changing value/version and finalizing once.
Current normal ParamChange execution does not prohibit proposer=executor; do not
claim universal separation of duties from the emergency-unpause policy.

`emergency_pause` is guardian-only and idempotent. `schedule_unpause` requires
active pause, guardian, delay and no other active restore; it creates Queued
EmergencyUnpause. `execute_unpause` requires an authorized non-guardian executor
separate from its proposer, the original guardian still authorized and pause
still active. `cancel` requires active guardian or the still-authorized original
proposer for that proposal kind; terminal proposals cannot be requeued/executed.

Existing typed failures include `Unauthorized`, `InvalidEta`, `InvalidParamKey`,
`WrongProposer`, `NotQueued`, `NotReady`, `AlreadyFinalized`,
`CurrentValueMismatch`, `ParamVersionMismatch`, `SelfExecutionForbidden`,
`GuardianExecutorConflict` and `PauseRestoreAlreadyScheduled`. Preserve unchanged
proposal/parameter/pause/audit state on rejection. Current saturating nonce,
version and ETA arithmetic is reference behavior; a production adapter must add
checked exhaustion rejection before mutation, not claim strict overflow safety.

Planned persistence atomically records authenticated operation ID, exact proposal
predecessor/status/version, resulting guard state and emitted event. Restore
rechecks canonical ordered maps, nonce uniqueness and no duplicate effect;
audit-log clearing cannot erase the authoritative operation/decision journal.
Development fixture bounds (unsigned u64) are 1024 live proposals, 128 keys,
256 principals per role, 128-byte IDs/keys, 4096-byte values/reasons and 8192
retained event rows; admission/compaction must reject or archive before exceeding
these limits. They are opt-in test inputs, not existing guard limits or mainnet
policy. No storage/actor authentication exists in the present value library.

Reuse existing tests `timelock_bypass_fails_closed_without_side_effects`,
`execute_rejects_if_param_version_drifts_without_value_change`, role revocation,
queue idempotence and emergency distinct-executor cases. Add authenticated-caller
substitution, u64 exhaustion, durable lost-ack replay and event/state atomicity
vectors before allowing this auxiliary guard to affect any production policy.
It cannot directly change v0 consensus parameters mid-epoch or bypass handoff.

## State machine

Verification has no external effects:
`ContextAdmitted -> KeysAdmitted -> StructureBounded -> SignaturesVerified -> RelationsVerified`.
Return a capability only after all phases succeed. A consumer may inspect
failure without obtaining a partially verified capability.

1. Admit the context against its prior trust root. Check the parameter preimage
   hash and exact chain/genesis/protocol/epoch relations before using its limits.
2. Strictly admit every active set key, including non-signers: canonical
   Ed25519 encoding, permitted curve point and no weak/small-order key.
3. Enforce unique validator IDs and public keys, positive weights and checked
   total weight. Certificate IDs must be canonical, unique and actual members.
4. Reconstruct the exact domain-separated signing root from M00's admitted
   value. Signatures cover the 32-byte digest, not transport bytes or hex text.
5. Charge signature work before each strict verification attempt. Invalid
   signatures still spend that work. Reusing a verification cache requires the
   complete tuple below and never refunds work already charged by the caller.
6. Sum each admitted signer's committed weight once with checked u128; require
   `floor(2*W/3)+1`. Never trust a certificate's claimed total weight.
7. Verify semantic relations: leader schedule, exact QC digest links, TC
   selected-high-QC rule, target roots, parent and epoch contexts.
8. Return a private, non-forgeable result to its selected consumer. Persistence
   serializes inert inputs, not the capability itself.

For three-chain proofs verify all three proposal signatures and QCs, relevant
TCs and every referenced QC; finalize the oldest certified block only. Reject
mixed signing sets/epochs. A synthetic genesis or epoch anchor is legal only
in the exact independently authorized anchor context and is not a signed QC.

`recover_epoch_activation_authority_strict_v0` re-verifies the eight exact
preimages against independent old trust and expected binding. The resulting
`StrictSameVersionEpochActivationAuthorityV0` is still not a live Core switch.
`verify_first_epoch_proposal_header_strict_v0` covers the view-1 header only.
The v1 first-epoch finality consumer above admits skipped-view TCs with complete
activation evidence; live Core proposal/vote admission and complete payload
execution remain separate consumers. Do not turn a header-only token into a
voting permit.

### Error dispositions

| Failure | Disposition and effect |
|---|---|
| Malformed/weak key, bad signature, duplicate signer, context/target mismatch | `Reject`; no capability or state change. Preserve existing typed cause. |
| Unknown profile/algorithm/proof class | `Reject(Unsupported)`; no downgrade. |
| Local budget exhausted / unavailable trusted-policy resolver | `Unavailable`; no accusation of Byzantine invalidity. |
| Conflicting authenticated trusted roots | `Halt(TrustConflict)` at consumer; retain bounded evidence. |
| Unexpected verifier/library invariant failure | `Halt(VerifierInvariant)`; never convert to successful or invalid-transaction result. |

The planned dispositions do not allocate v0 wire error discriminants.

## Persistence and recovery

M01 caches only performance facts. A planned cache key is
`(profile, role, canonical bytes digest, signature bytes, exact key bytes,
trust-context digest, expected-target digest, verifier implementation version)`.
A hit cannot bypass context admission, revocation generation or resource policy.
Cache capacity/eviction affects latency only; eviction does not invalidate truth.

On restart, M03/M08/M13 reopen inert evidence and independently restore the
trusted context before asking M01 to re-verify. A checksum-only restore is
insufficient. A serialized `verified=true`, type name or event is never accepted.

Rotation keeps historical consensus keys valid for old-epoch evidence under
its retained validator set; it does not let them authorize a new epoch or fresh
session. Application revocation follows the authenticated effective height and
key generation specified by that profile. Do not apply present-day revocation
retroactively to invalidate correctly finalized historical consensus signatures.

## Resource bounds

Use the M00 context-bound `Cev0AdmissionBudgetV0` and hard source ceilings.
Bound keys, signatures, proof bytes and nested references before verification.
The TC budget includes all referenced QC shares; outer signatures also count.
Independent retries share the caller's remaining admission allowance.

Planned deployment profile fields are verification CPU/work allowance per
admission and per peer, cache entries/bytes, trust-history retention and resolver
queue/deadline. Each is authenticated by M15's deployment profile, positive and
checked against maximum enabled object size. Operational deadlines cannot change
the mathematical validity of a signature. Missing limits disable that adapter.
No new production numeric defaults are established here.

## Security

A generic `SignatureVerifier` used by tests must not enter the production
capability constructor; existing strict boundaries hard-code
`StrictEd25519Verifier`. Alternative algorithms require a versioned profile and
independent vectors, never negotiation inside v0.

The same validator may hold old and new handoff roles, but each role verifies
against its own set and domain-bound preimage. Count a signature only in its
intended quorum. Host attestation, TLS identity, a P2P lease, an HSM success
response and a valid consumption certificate grant different capabilities.
None substitutes for complete consensus verification.

Compile-time privacy is a defense against accidental in-process authority
forgery, not protection against arbitrary code execution in the process. M15
keeps fixture/accept-all implementations outside production build closures.

## Observability and SLO

Measure signature attempts/successes/failures and charged work by proof class,
cache hit rate, context-resolution latency and verification p50/p95/p99.
Never export secret material or unlimited attacker-selected labels. Trace only
bounded object/context digests and stable error classes. Qualified SLOs must
include worst-case distinct TC QCs, not only repeated-cache happy paths.

## Verification and evidence

Existing starting points: `vectors/ed25519-v0.json`, wire-authenticated vectors,
`qc-tc-threshold-v0.json`, `anchor-finality-v0.json`,
`handoff-certificate-kernel-v0.json`, and
`trnm-consensus-crypto/tests/pcc1_strict_finality.rs`.
`rejects_retargeting_to_newest_qc_or_different_root` is an existing regression.

Required module cases:

- `M01-KEY`: weak, zero, noncanonical and duplicate keys, including a non-signing member.
- `M01-SIG`: mutate each signature independently; exact failed-work consumption.
- `M01-TARGET`: substitute chain, root, parent, epoch, set, parameter or newest QC.
- `M01-CAP`: external code cannot construct/deserialize/clone authority or invoke a test verifier.
- `M01-REVOKE`: old generation cannot authorize a fresh action; historical proofs remain correctly scoped.
- `M01-ROLE`: old-only/new-only/dual members and wrong-role signature/quorum substitution.
- `M01-CACHE`: same bytes under changed trust/role/revocation context misses and revalidates.
- `M01-EPOCH`: exact view-1 proof and skipped-view anchored TC; no mixed-epoch three-chain.

`epoch_activation_recovery.rs` additionally exercises a real signed 1/2/3 and
3/5/8 new-epoch chain, every proposal/TC signature corruption, target/parent
substitution, truncation/trailing bytes, aggregate admission bounds and ordinary
entrypoint rejection. These library tests do not stand in for node crash/restart,
independent verifier or external activation acceptance.

M00 supplies independently generated bytes; M01 supplies expected verification
outcomes; M02/M03/M08/M13 must consume them at real boundaries. Fuzzing and
same-library replay supplement, rather than replace, independent verifier work.

### First-new execution commitment projection

`BlockBodyV0::validate_epoch_handoff_commitments_v1(header, receipts, parameters,
expected_state_root, active_validator_set, verifier)` is a distinct static
commitment producer. It requires EpochHandoff at its exact epoch start, complete
canonical payload/evidence/receipt roots and size limits, the independently
supplied execution state root, active-set context and evidence signatures.
It returns `ValidatedBlockCommitmentsV0` without weakening the Regular-only
producer. `NonEpochHandoffBlock` is the additive local semantic error code 17;
existing error values and frozen bytes remain unchanged. The result alone is
neither epoch admission nor durable application validation: Core must separately
join complete strict handoff evidence, actual fresh P and exact dual-parent
overlay. The Core regression covers first-new acceptance and wrong state root,
wrong kind and missing edge rejection with real Ed25519 signatures.

## Historical header ancestry (M01-HISTORY-V1)

This versioned contract authorizes a shared verification-only implementation in
`trnm-consensus-crypto`, consumed independently by M13 admission and M08 recovery.
It does not install application state. Frozen v0 state roots do not authenticate
the global command-ID and signer/nonce replay sets; M06 must subsequently derive
those sets by executing every application body from its own audited local anchor.

The public `verify_historical_header_ancestry_v1` accepts an independently trusted
decoded anchor header, its validator set and parameters, a borrowed ordered slice
of canonical successor header bytes, ordered eight-root activation preimages,
the original terminal finality proof, `HistoricalAncestryLimitsV1`, and one mutable
`Cev0AdmissionBudgetV0`. Inputs are claims. The private-field, non-Clone
`StrictHistoricalHeaderPathV1` retains decoded headers, boxed strict activation
contexts, exact terminal proof and terminal configuration with immutable getters.
It issues no P, execution receipt, signer permission or install capability. M08
never depends on M13 to recreate this verification after a crash.

Admission first checks positive path length, at most 256 consensus headers,
independently at most 32 transitions, and at most 64 MiB aggregate supplied bytes.
Caller limits can only narrow these ceilings. Headers and parameter/commitment
roots are at most 4096 bytes, validator-set roots at most 1 MiB, other roots at
most 8 MiB. Checked length sums precede decoding/copying. Each activation still
obeys the existing decoder's aggregate logical-root allowance; the path ceiling
does not enlarge an 8 MiB CEV0 root. All cryptographic decoders share the supplied
remaining work meter; no fresh per-step budget or retry refund is allowed.

The anchor must be a positive-height application header in its exact authenticated
chain/genesis/protocol/epoch/set/parameter context. Decode successor headers
exactly, then walk once without recursion. Require exact parent ID, height +1,
unchanged chain/genesis/protocol, scheduled block kind and leader, positive view,
and the existing parent-relative timestamp bound. Same-epoch views must increase;
skipped views are permitted. At epoch change, require the next epoch and the
scheduled EpochHandoff following EpochSeal2, never a fabricated ordinary link.
M00's inert `validate_historical_header_link_v1` shares these structural checks;
it does not assert an absent ancestor proposal witness or QC.

Each transition consumes exactly one ordered activation bundle. Decode against
the preceding authenticated old set/parameters and strictly verify its original
checkpoint finality, terminal seal QC and both handoff roles. Match its checkpoint,
seal1 and seal2 byte-exactly to the supplied chain (the checkpoint may be the
anchor); match its checkpoint-parent header to the preceding chain header where
present, otherwise to the pinned checkpoint's parent ID/height. The signed
checkpoint hash authenticates that supplied parent preimage. Require the first
new header to use the resulting configuration and authorization geometry. Do not
use the view-1-only proposal preimage helper to reject a valid skipped-view first
block; such a terminal uses the existing strict epoch-first proof verifier.
Reject missing, duplicate, reordered and unused evidence. Seals preserve the
checkpoint state/commitment and empty payload/receipt/evidence roots, and never
create an application/replay version.

Strictly verify terminal Regular/Checkpoint finality in the resulting context.
When the path contains an activation, reuse its latest decoded evidence and
strict authority with the existing epoch-runtime decoder/verification kernel,
including TC references to that exact synthetic anchor. Terminal EpochHandoff
uses the same retained activation with the existing epoch-first proof
decoder/verifier, with work charged once. Without a crossed activation, the
ordinary strict decoder remains fail-closed: an ordinary proof needing a
pre-anchor synthetic handoff context cannot be admitted using only the current
anchor header/set/parameters. Supplying that additional independently trusted
context is subsequent adapter work, not a permissive decoder retry. Seal targets
are rejected. The entire finalized header must equal the last chain header;
its proof children are not replay records. Exact backward hash linkage from this
strict target authenticates ordinary ancestors without requiring an individual
finality proof or proposer witness for each. This is not permission to remove
proofs required by the source owner's existing storage schema.

Required cases include a genuine repeated-epoch C18 to C32 path containing four
seals and ten application headers, C31 handoff terminal, ordinary single-epoch
ancestry, missing/forked/reordered/trailing headers, wrong trust/configuration,
all activation joins, terminal proof/signature substitution, exact and one-over
byte/count limits, failed crypto retaining charged work, and external capability
construction/Clone rejection. Header authentication alone makes no statement
about body execution, replay completeness, snapshot installation or network
acceptance. The genesis/wiped-node history source join remains separate work.

## Contextual successor verification (M01-SUCCESSOR-ACTIVATION-V1)

This primary-M01 candidate is implemented in `epoch_successor_v1.rs`. Its scope
is strict verification and recovery of the next activation, including
checkpoint/seal TC references to the current epoch's already authorized synthetic anchor. It grants
no application commit, Core readiness, signer lease or production activation.
Frozen v0 evidence bytes and the existing eight-root binding digest do not change.

`decode_verify_successor_epoch_activation_strict_v1(predecessor,
retained_ancestry, preimages, budget)` requires an existing private-field
`StrictSameVersionEpochActivationAuthorityV0`. Its independently verified new set
and parameters must exactly equal the successor evidence's old set and parameters.
Use M00-SUCCESSOR-EVIDENCE-V1 to decode all eight roots under the predecessor's
complete context. Never construct context from a bare synthetic reference.

The retained ancestry contains both endpoints: the predecessor terminal seal and
the successor checkpoint's authenticated immediate parent. Bound it to at most 256
headers and 1 MiB of canonical bytes before copying. Check every consecutive
height, exact parent ID, genesis/chain/protocol, active geometry/set/parameters,
elected proposer, increasing view and timestamp with the existing historical link
validator. The first edge is the authorized handoff. Every endpoint must match
its exact evidence header, and the target checkpoint proof must bind the final
parent header. Equal configurations alone cannot connect unrelated histories.

The existing `StrictEpochRuntimeContextV1::compose_successor_v1` entrypoint must
apply the same bounded historical-link validator, including when its successor
was independently verified through the context-free v0 constructor. Strict
checkpoint signatures do not replace validation of the retained intermediate
headers. Both entrypoints retain their exact context and endpoint checks and
share one implementation of the count/byte bounds and every historical link
rule. The original public APIs and existing context/endpoint/edge error classes
remain stable. A genuine signed v0 successor with a complete, correctly hashed
ancestry containing repeated ordinary views must fail composition; a broken
hash chain alone is not sufficient regression evidence.

After complete structural admission, reuse M01's existing
`verify_epoch_finality_precharged_v1` with the predecessor authority for the
checkpoint and two seals. This checks all proposal, ordinary QC and optional TC
signatures and exact synthetic references. Reuse the existing strict certificate
kernel for the terminal old QC and both old/new handoff roles. Validate all old
and new validator keys, including nonsigners. Shared M00 joint relations then
supply inert facts; they are never sufficient to mint the strict return value.
Do not introduce another TC/QC/proposal signature algorithm or accepting verifier.
The caller's remaining meter covers every reserved signature check; failure after
cryptographic work starts does not refund that work.

A successful authority caches only its completely derived inert runtime context
in a private `Box`, keeping that complete context out of every inline authority
stack frame. This is an ownership/layout choice, not a larger thread-stack limit.
`StrictEpochRuntimeContextV1::from_activation_v1` retains the strict authority
and borrows its cached context for decoding, rather than passing valid contextual
evidence through the old context-free decoder again.
The v0 constructor derives the same data from its complete accepted evidence, so
no public unchecked context constructor or restored serialized authority appears.
Recovery and the historical walker reuse their complete decoded evidence through
a private strict verifier, which repeats all key, parent and joint signature
checks before minting authority. They do not nest a second raw decoder inside
Core recovery; admission charges and the eight-root binding remain unchanged.
Recovery takes the independently reverified predecessor, the same retained ancestry,
original eight roots and expected current binding, and repeats this verification.
Persisting a predecessor association belongs to the enclosing bounded owner prefix;
its digest cannot replace strict reconstruction or silently change the v0 binding.

The historical verifier selects this entrypoint after its first verified activation
and supplies the exact previously authenticated header interval. A starting anchor
without earlier activation evidence still cannot authorize an unknown pre-anchor
synthetic reference. M08 prefix/checkpoint recovery and history export, M13's
historical consumer and M02 recovery must use the same contextual result where
needed; each missing integration remains an explicit boundary, never a fallback
to unchecked evidence or a fabricated anchor.

Required evidence uses a real successor checkpoint/two-seal proof whose skipped
view TC includes both an ordinary highest QC and the exact predecessor-authorized
terminal-seal/view0 reference. The context-free path rejects it; contextual
verification, runtime construction and recovery accept it. Wrong predecessor,
missing or substituted ancestry, altered terminal seal/commitment, any proposal,
QC, timeout or handoff signature corruption, and insufficient work budgets reject.
Existing frozen checkpoint/joint/activation vectors and their negative cases remain
required. `epoch_runtime_successor.rs` exercises real mixed-reference TCs on
the checkpoint and both seals, twelve signature-family mutations that still pass
structural admission, all eight trailing-root cases, exact/one-short budgets and
next-successor context reuse. Its C28→C41 historical case verifies thirteen
linked headers, two original activations and a genuine C41/C42/C43 terminal
proof; a changed terminal signature and missing interval header reject.
Imported-base checkpoint execution, default-node signing and multi-host acceptance are outside this cryptographic result and remain independently gated.

## Activation boundary

Existing strict v0 operations remain unchanged. Planned general identity/cache
adapters require concrete codec/error/profile registration and consumer tests
before use. A new-role handoff result cannot be activated until M03 custody and
M02/M08 epoch-state contracts are implemented together. No cryptographic token
alone promotes testnet, release, economic weighting or network activation.
