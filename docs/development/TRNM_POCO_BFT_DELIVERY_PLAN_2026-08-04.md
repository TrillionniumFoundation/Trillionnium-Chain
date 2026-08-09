# TRNM PoCO-BFT Delivery Plan — 2026-08-04

Status: **active engineering plan; no phase is complete**

Working branch: `feature/chain-poco-bft-v0`

## 2026-08-08 execution-order reset

The current implementation order is closed around recoverability rather than
additional private carrier types:

1. make the existing dirty tranche reviewable and recoverable;
2. freeze the six host/Core production contracts in
   [`../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md);
3. finish the already-dispatched PoCO/validator semantic slice, then stop
   expanding the carrier graph;
4. implement durable validation jobs plus callback outbox and invoke the real
   `Core::step` path;
5. close SafetyState codec/WAL and complete canonical SignIntent before a real
   single-node driver;
6. only then add speculative execution/finalize, epoch rollover, networking
   and PoCO shadow observation in that order.

The frozen contracts are release gates. A test-only carrier or an in-memory
simulation cannot satisfy them.

This plan supersedes schedules that promote the CometBFT application fixture
to production consensus authority. CometBFT remains a differential oracle;
the existing deterministic runtime and JMT/ICS23 assets remain integration
targets.

## Execution boundary

- The development workstation may edit source, compile with Cargo, run unit,
  property, simulator, formal, and isolated integration tests, and build
  immutable release artifacts.
- Repository remote CI is budget-constrained and must use only the dedicated
  X230 self-hosted GitHub Actions runner selected by the labels `self-hosted`,
  `Linux`, `X64`, `x230`, and `trillionnium-chain`. GitHub-hosted or other paid
  runners are not authorized. The runner identity has no sudo, Docker,
  deployment credentials, operator-home access, or `/srv/trillionnium-chain`
  access; host packages and pinned language toolchains are root-provisioned and
  read-only to the job identity. Every job is also gated to the canonical private repository,
  trusted initiating/triggering actor, and same-repository PR provenance
  (scheduled default-branch work is the only actor exception).
  `scripts/check_ci_runner_policy.sh` enforces these invariants from worktree,
  staged-index, and pushed-HEAD preflight paths. Cold-cache job timeouts are
  sized for the X230's two physical cores and clean per-job checkout; the
  single runner serializes jobs, and real first-run wall times will be used to
  tighten those bounds without weakening gates.
- It must not run persistent validator, node, signer, RPC, monitoring, fault,
  or soak services and must not hold live node state or validator keys.
- Deployment, LAN/public validation, fault campaigns, and soak run through
  ordinary OpenSSH on `p4-x230`, following
  `../runbooks/TRNM_POCO_BFT_X230_DEPLOYMENT_BOUNDARY.md`.

## Phase board

| Phase | Target window | Current state | Exit authority |
| --- | --- | --- | --- |
| P0 protocol freeze | 2–4 weeks | In progress | Normative spec, full vectors, required bounded/exhaustive formal evidence, independent consensus review |
| P1 deterministic core | 6–8 weeks | Prototype in progress | Pure core, crash journal model, verifier, fault simulator, trace/property/formal agreement |
| P2 real node | 6–10 weeks | Not started | Authenticated P2P, WAL/sign journal, sync, remote signer, runtime/JMT adapter, remote 4/7-node campaigns |
| P3 PoCO economic safety | 8–12 weeks | Spec/reference profile only | Certificate pipeline, bond/jail/slash, deterministic snapshots, anti-collusion simulation, staged observation/review |
| P4 public validation | after P3 gates | Not started | 7→20 nodes, multi-region attacks, 7–30 day soak, external audits, independent light client |

Windows are planning estimates, not readiness promises. A later phase may be
prototyped early, but it cannot inherit a completed label from partial work in
an earlier phase.

## P0 work packages

### Present in the branch

- PoCO-BFT v0 architecture decision, system/threat model, chained-QC rules,
  CEV0/domain separation, epochs/upgrades, PoCO/bond weights, light-client
  rules, conformance obligations, and reference parameters.
- Bounded protobuf transport projections. Protobuf bytes are never signing
  bytes; strict validation reconstructs CEV0.
- Normative Consumption Certificate v0 logical body.
- Bounded Quint kernels for three-chain/lock safety, persist-before-sign
  crashes, 4-/7-node weighted quorum, heterogeneous TC selection,
  partition/heal, joint handoff, light-client commitment/freshness,
  upgrade atomicity, deterministic PoCO weight snapshots, and synthetic-anchor
  first-leader view change, with retained negative mutants.
- Independent Python CEV0 parameter encoder and committed byte/digest vector.
- Independent foundational wire vectors for all frozen domains, common
  context, block ID, signing roots, and validator-set hash.
- The independent B1 QC/TC corpus now freezes complete ordinary-QC and
  corrected full-TC objects with real RFC 8032 Ed25519 signatures, unequal
  validator powers `4/3/2/1`, exact `floor(2W/3)+1` acceptance, and one-below-
  threshold rejection. Rust reconstructs the same public corpus through the
  strict verifier. This closes B1 only, not the B2 parser/source-of-truth or
  remaining protocol-object corpus.
- Review-corrected exact synthetic-anchor, signed CertifiedHeader/finality,
  handoff-descriptor-domain, and first-leader view-change schemas; obsolete
  experimental proof/handoff digests are explicitly invalid.
- Frozen host payload-validation trichotomy: terminal `Valid`, retryable
  non-poisoning `Unavailable`, and terminal `DeterministicallyInvalid`, with
  persist-before-effect fail-stop for authenticated/durable and terminal-
  result conflicts. The active v0 runtime profile now freezes success-only
  receipts: 21 typed transaction rejects invalidate the complete block without
  a receipt or mutation, while 7 typed authenticated-state/internal invariant
  faults require host fail-stop. The taxonomy value is opaque and its source
  match is exhaustive. Runtime `TryStateViewV0`/`try_execute_v0` now preserves
  a typed state-read failure separately from deterministic runtime semantics
  and returns an opaque real-attempt failure with no public constructor. A
  module-private, still-unwired planning adapter consumes the authenticated-
  execution-input token into the real attempt; both success and failure retain
  that exact token, so no second same-generation body/parent/runtime join can
  be spliced during promotion. A typed state failure is returned unchanged and
  is not terminalized, a deterministic reject is promoted only from the token
  carried by its real attempt, and success yields only
  `AppliedRuntimeAttemptV0`.
  `Valid` still requires a roots-match capability that owns that applied
  attempt, with no production constructor. A typed self-head reader and an
  opaque snapshot that owns one SQLite `Connection` have landed. One `BEGIN`
  transaction validates the store bindings, canonical committed height and
  app hash, query floor, latest root version, and exact head root; every object
  in a multi-key read comes from that same snapshot, and typed `finish`
  explicitly ends it. Snapshot begin uses a non-blocking maintenance
  `try_lock`. Core now freezes the exact positive-height parent header inside
  its private payload-validation request, and a production store constructor
  consumes that capability to open the committed head only when height and
  state root match exactly. Synthetic genesis remains explicitly headerless,
  and a non-head/speculative parent returns typed retryable source mismatch
  until a canonical overlay store exists. The general host/ABCI runtime view
  remains unwired, while the bounded production validation cursor owns a
  private `prior delta -> exact authenticated snapshot` fallible view. Legacy
  `load_object` remains its old direct read, and no ABCI outcome path changed.
  A separate legacy test-only inert regular-block
  seam now exact-compares the retained header/body, parent `BlockId`, validator
  set, parameters, and signer-policy material; opening it binds that policy to
  the actual test-store configuration and the parent height/root to the same
  connection-owned snapshot. The same fixed snapshot now proves the
  validator-lifecycle leaf through JMT/ICS23, checks its authenticated record
  against the physical singleton and store bindings, and joins its active
  validator projection to the retained native set. Its internal cursor alone derives each raw outer
  transaction's index, bytes, target height, and target `BlockId` in body
  order. A finished inert traversal exists only after every body item was
  visited and the owned snapshot finished successfully; snapshot-finish errors
  take precedence over incompleteness and cursor rejection. Obtaining a cursor
  classification requires explicitly finishing its consumed traversal; Drop
  produces neither that classification nor a finished capability. The cursor now decodes the exact outer
  bytes as a real `SignedCommandEnvelopeV1`; the consensus-app command helper
  applies dalek `verify_strict` plus the existing chain/header-time semantics
  against the exact store-bound signer
  list, decodes the exact inner bytes as `CanonicalTxV1`, and binds payload
  type, sender, and nonce. It does not reserialize either byte string as
  authority. Signer-policy admission now exact-decodes the Ed25519 point and
  rejects weak/small-order keys. This command-envelope-specific tightening
  leaves generic `verify_hex`, vote/QC languages, and the live-node development
  oracle unchanged; it is not the PoCO `StrictEd25519Verifier` type. If a
  retained production history already exists, the narrower app acceptance set
  requires an explicit app/protocol activation boundary rather than silent
  reinterpretation. A separate legacy test-only owning runtime session now consumes
  that same exact input bundle and snapshot. It derives `ExecutionContext`
  only from the retained header/envelope facts, executes the canonical
  transactions in body order through the real fallible `try_execute_v0`, and
  uses one `changes -> fixed snapshot` view so a later transaction sees the
  earlier transaction's private delta. Successful runtime receipts are mapped
  to native receipt *shape* only, and every mutation set is first applied to a
  cloned delta with an exhaustive account/task/fee/monetary canonical
  key/type/value check plus unique-key, object-type, expected-version, and
  exact-successor checks. Task mutations additionally reuse the runtime's full
  status/field-group/version/height validator through an independent opaque
  read-only failure type. The two-transaction fixture proves that `CreditAccount`
  followed by `CreateTask` observes the first write; reversed order, a second-
  transaction runtime rejection, or a later mutation invariant destroys the
  whole session's prior delta and receipts. The failed session still retains
  its exact block/configuration inputs, authenticated lifecycle, failed index,
  and decoded observation/transaction as one non-cloneable opaque value; it
  accepts no second input join and exposes no standalone cause. Both success
  and failure require explicit snapshot finish, and a finish error takes
  precedence over the runtime/cursor cause. The successful legacy test-only path now
  also encodes the complete private delta and plans the exact next JMT version
  on the same still-open SQLite transaction after a full parent-state
  revalidation; it never calls the latest-head planner and accepts no caller
  target version or expected root. Planning or completeness remains inert
  until the owned snapshot finishes successfully, and a finish failure
  destroys the plan. A second legacy test-only comparator consumes that whole
  finished value, reconstructs native receipts from the retained raw body and
  real `RuntimeReceipt`s, hard-codes `StrictEd25519Verifier`, and exact-compares
  state, payload, receipts, and evidence roots together with the retained
  configuration and `BlockId`. Positive two-transaction and empty-write
  controls, canonical state/receipt-root substitutions, and finish-error
  precedence are non-ignored tests; the planning connection is query-only and
  the committed height/app hash remain unchanged. A same-path independently
  opened WAL writer may commit a competing exact-next sibling after the first
  runtime read; the original session's later reads and JMT plan remain fixed to
  its old parent until finish, after which the handle observes the sibling.
  A production, process-local validation carrier now consumes the Core request,
  loads the complete namespace-8 active validator set and parameters plus the
  validator lifecycle from that same still-open exact-parent transaction, and
  joins them to the retained header commitments before exact body validation.
  Application-payload admission now uses the authenticated
  `max_consensus_message_bytes` only as the bounded staged exact-decode/root-
  binding ceiling. A non-canonical payload or source payload/evidence root
  mismatch remains retryable `Unavailable`; only after the complete canonical
  body reproduces those header roots does full logical-block size above the
  authenticated `max_block_bytes` become `DeterministicallyInvalid`.
  It accepts no caller-supplied parent/height/root/set/parameters, opens no
  second connection or cache path, is non-cloneable/non-serializable, and a
  sibling writer cannot move its view. Foreign roots/configuration splices fail
  closed and snapshot-finish failure outranks any joined result. The exact Core
  request is now first held by a private owning open carrier. A host failure
  before snapshot begin returns that owner directly; after begin, source or
  body-admission failure returns the same `ValidationId`, target block, and
  parent only after the snapshot is closed. A body that never passed admission
  is not relabeled as authorized. If close itself fails, that typed snapshot
  cause replaces the pending source/invalid/invariant cause without discarding
  the Core-issued owner. No bare ID, generation, block, parent, or cause can
  reconstruct this ownership. The original Core-issued
  `PayloadValidationRequest` and every `Clone` descended from that same object
  graph share one process-local Arc-backed atomic one-shot gate. Exactly one
  claimant in that graph can become the owning validation carrier; a losing
  clone is suppressed/coalesced by the current private native-admission branch
  before snapshot open or failure taxonomy, so that branch produces neither a
  classification nor a callback for it. This is not process-wide uniqueness by
  complete `ValidationId`: independently started Cores from the same
  obligation-free durable state may accept the same ingress and materialize
  separate request/gate object graphs, and the public Core `Input` API is not a
  capability callback. Distinct generations remain independent. An existing
  old object graph remains suppressed after its one claim, but this fact alone
  provides neither cross-instance nor cross-restart exactly-once behavior.
  The Core now also binds `PayloadValidationRouteV0::Proposal` or
  `PayloadValidationRouteV0::Synced` privately inside that request. Native app
  admission consumes the complete Core `Effect`, first verifies that the outer
  `ValidatePayload`/`ValidateSyncedPayload` variant agrees with the inner
  route, and only then attempts the object-graph claim or reads host state. An
  outer-wrapper/inner-route splice is a transport invariant; it does not
  consume the correctly wrapped clone and is neither `Duplicate`,
  `Unavailable`, nor `DeterministicallyInvalid`. The route remains owned with
  the request through open/body/cursor/runtime/post-state/comparator and final
  process-local disposition. No naked bool or route can be injected into those
  constructors. Separately from application-store schema v5, Core
  `SafetyState` schema v5 introduced a canonically ordered
  `DurablePayloadValidationObligationV0` before either `ValidatePayload` or
  `ValidateSyncedPayload` may escape a `PersistSafetyState -> StorageAck`
  barrier. Each obligation binds the Core-selected route, full `ValidationId`,
  exact `SignedProposalV0`, exact `PayloadValidationParentV0`, and
  `first_recorded_revision`; the live invariant also requires the validation
  generation to equal that first revision. `StorageAck` reconstructs the
  request only from this durable record and its exact volatile proposal mirror.
  Core `SafetyState` schema v6 now adds a separately canonically sorted
  `DurablePayloadValidationCompletionV0` set keyed by `(route, full
  ValidationId)`. Every direct or synced callback atomically replaces its
  exact obligation with the same-key completion before persistence; the
  completion retains all three results, including full
  `ValidatedBlockCommitmentsV0` for `Valid`, plus its
  `first_recorded_revision`. Exact same-result replay is therefore idempotent
  across restart. An opposite-route reuse, a different result or `Valid`
  commitment under the same key, or any source/owner splice is invariant or a
  typed integration conflict and cannot overwrite the tombstone.
  `Unavailable` closes only that generation, so a fresh generation for the
  same block may still be registered. These completion tombstones are distinct
  from the block-ID-level terminal payload facts, which still carry only
  `Valid`/`DeterministicallyInvalid` cross-generation semantics. Exact synced
  cancellation removes the matching obligation behind the persistence barrier
  without inventing a callback result. A safety halt clears all obligations in
  the same durable revision while retaining prior completions. Core admits no
  automatic completion eviction: `completions + obligations` is bounded by
  authenticated `max_observed_messages`, and registration reserves the future
  completion slot before an obligation is issued. Core
  admission accounts for the complete signed-proposal durable resource --
  logical block plus exact certified-tail witness -- under authenticated
  `max_consensus_message_bytes`; the aggregate obligation budget additionally
  covers fixed route/ID/revision/parent facts and any exact parent header.
  Recovery first validates every schema-v6 obligation and completion and then
  rejects any non-empty obligation set with `InvalidRecovery`; it does not
  reissue a pending request.
  Safety-state schema v5 has no implicit migration. Completion-only recovery
  provides exact-result suppression, but non-empty obligations remain
  fail-closed. This closes durable pre-effect capture, cleanup ordering, and
  callback-result idempotence, not crash replay, callback exactly-once, or
  liveness.
  After wrapper/route congruence and the object-graph claim, but
  before any host/snapshot read, application-store schema v5 now reserves
  `(route, full ValidationId)` in the same SQLite database under one
  `BEGIN IMMEDIATE` unique-insert transaction. A versioned, domain-separated
  fingerprint covers the exact raw target header/application payload/ordered
  evidence and exact parent source together with that route and ID. An exact
  existing row coalesces/suppresses the duplicate across independently
  materialized request graphs or processes; reuse of the full ID with another
  route, raw source, target, or parent is an invariant. The table is capped at
  65,536 rows, admits no eviction, and still coalesces an exact duplicate at
  capacity. State-sync snapshot construction deletes reservation rows only
  from its temporary copy before checkpoint/VACUUM and verifies the copy is
  empty; the source database remains untouched. This is durable reservation
  and cross-instance congruence only, not process-wide callback exactly-once.
  Its only host value is borrowed
  from the initialized `AppCore`, and the canonical signer-policy preimage is
  recomputed against both store metadata and the authenticated lifecycle
  before it is frozen into the same carrier. The cursor selects its own exact
  body index, strictly verifies and decodes that retained envelope and
  `CanonicalTxV1`, and derives target height, native `BlockId`, header time,
  signer id/role, and exact inner-byte length without caller inputs. The
  prepared transaction still owns the cursor and snapshot; there is no
  production seek, repeat, skip, caller-directed advance, or tuple/parts
  conversion. A decode failure closed after an earlier successful transaction
  retains the exact authorized owner, next internal index, private delta, and
  applied receipts; a finish error replaces only the pending decode cause.
  One consuming production attempt now invokes the real fallible
  runtime over `prior delta -> that same snapshot`, converts the successful
  receipt to native receipt facts, atomically validates/stages the complete
  mutation set, and only then returns the cursor at `index + 1`. Runtime,
  typed state-read, receipt-conversion, or mutation-invariant failure destroys
  all prior delta/receipts but closes into one owner retaining the authorized
  body, failed index, exact outer/inner bytes, decoded transaction, and derived
  context. A finish failure replaces the pending attempt cause while retaining
  those facts. Non-runtime payloads retain their exact bytes, verified
  envelope/context, cursor, and snapshot in an opaque routing carrier and do
  not advance or become invalid.
  Before complete-body planning, the runtime-only production cursor replays
  every retained real `RuntimeReceipt` mutation set separately and in
  transaction order against that same authenticated snapshot. Repeated keys
  across transactions are permitted only through one continuous expected/next
  object-version chain; duplicate keys within one receipt remain invalid. The
  receipt-derived final map must exactly equal the cursor's canonical private
  delta, and only that replayed map is encoded into object/JMT writes for the
  unique parent-height-plus-one plan. Planning also emits an opaque process-
  local seal over the plan's exact version, root, nodes, values, stale-node
  indices, and key preimages. The snapshot closes before the sealed inert
  finished plan escapes. Incomplete-body, receipt-replay, authenticated-read,
  or planning failure closes into one carrier retaining the exact authorized
  owner, next index, canonical delta, and applied receipts. When finish fails,
  the pending planning cause and any successfully computed plan/seal are
  discarded, while the exact owner and cursor facts remain. One consuming
  comparator rebinds retained receipts to that replayed delta and exact plan,
  verifies the complete seal before any
  header-root mismatch classification, rebuilds native receipts, and hard-codes
  strict Ed25519 for the ordinary static commitment kernel. Seal failure, root
  computation failure, or any post-authorization payload/evidence, static-
  commitment, `BlockId`, provenance, or internal drift is invariant/fail-stop.
  Its process-local owning result has only `Valid`,
  `DeterministicallyInvalid(State|Receipts)`, and `InvariantFault`; every branch
  retains the complete owner, while `SourceUnavailable` is structurally handled
  before this comparator and cannot enter it. This applies or persists no plan
  or state. One consuming private
  bridge now promotes that exact owning classification into the app-private
  `ExecutionOutcomeV0`: `Valid` accepts only the complete matched carrier and
  derives its generation from the retained Core `ValidationId`; computed
  state/receipt mismatches become whole-block no-receipt invalid outcomes; and
  comparator drift becomes a non-terminal fail-stop invariant outcome while
  retaining the failed plan. A second consuming private carrier derives the
  route, full `ValidationId`, result and valid commitments only from that
  outcome, maps `Proposal` to `Input::PayloadValidated` and `Synced` to
  `Input::SyncedPayloadValidated`, and structurally refuses to produce a Core
  input for an invariant fault. It does not call `Core::step`, persist or
  deliver a callback/outbox, or provide
  `AuthorizedNativeCheckpointExecutionV0`, checkpoint, or ABCI authority. All
  open/reservation/decode/runtime/planning failure owners are likewise private,
  non-cloneable, non-serializable, and have no `From`/`TryFrom`/parts escape or
  standalone-cause conversion. They now have exhaustive owner-derived mappings
  into the same outcome kernel: source/database/storage/resource/capacity loss
  stays `Unavailable`; strictly verified body evidence and transaction
  encoding/authorization failures become whole-block invalid; authenticated
  state, host, cursor, reservation, and planning drift fails stop. Every bridge
  retains the complete failed owner and none emits a Core callback.
  A consuming non-runtime dispatcher also selects only PoCO application,
  validator transition, or unsupported from the retained, strictly verified
  envelope. A second consuming step strictly decodes canonical PoCO operations
  and canonical validator transitions, binds PoCO target height plus validator
  schema/chain/command/operator facts to that retained owner, and preserves
  the exact family owner on every typed decode mismatch. The next consuming
  step now reloads the production PoCO projection only through that pinned
  snapshot, derives its application-authority context from the retained parent
  configuration/lifecycle, and applies the operation to an unsealed overlay;
  validator transitions schedule against a clone of the lifecycle authenticated
  by the same owner. Decoded PoCO values are exact-reencoded against their
  retained raw bytes before use, and there is no caller-supplied projection or
  lifecycle loader. Semantic and family failures explicitly finish the owned
  snapshot before exposing a closed failure; finish failure outranks the pending
  cause. Closed causes distinguish authenticated-source loss, only the
  deterministically invalid facts and invariant faults. Validator scheduling
  now returns a closed typed reason set, uses checked nonce/delay arithmetic,
  and clone-and-swaps only after its postcondition validates; native family
  mapping preserves its deterministic versus invariant class without diagnostic
  text. PoCO application now also exposes a closed, data-free apply failure:
  raw-owner/re-encode/derived-state faults fail stop, while exact height,
  authority-revision, capacity, duplicate, nullifier-proof, validator-rule,
  validator-PoP, and signed semantic-change rejects map without
  diagnostic-string matching. An authenticated negative authority fact is a
  deterministic missing-fact reject, while a present-but-malformed companion,
  malformed authenticated semantic predecessor, or derived CAS/mutation
  failure remains invariant. Decision-ID mismatch and authenticated cap/window
  rejection are deterministic; counter, epoch, retention, and aggregate
  arithmetic exhaustion fail stop with typed reasons. Nullifier count, family,
  identifier, encoding, and proof-key shape rejects are deterministic
  `NullifierProof`; a correctly bound key whose non-membership proof does not
  verify against the authenticated root is the narrower deterministic
  `NullifierNonMembershipRootMismatch`; authenticated accumulator-count
  exhaustion fails stop as `ProtocolCounterExhausted`.
  Consumer-key authorization/revocation now preserves existing typed failures,
  rejects untyped signed shape/height/semantic faults as `SemanticTransition`,
  and treats an authenticated negative key lookup as deterministic
  `MissingRequiredAuthorityFact`. Revocation additionally binds its signed
  logical key to the body identity, classifies a present-but-divergent active
  semantic predecessor against the exact key authority as
  `AuthenticatedOverlay`, and keeps signed revoked successors deterministic;
  no error diagnostic participates.
  Consumer-key prune also rejects a missing authority record before clone as
  the same deterministic negative fact; signed identifiers/delete shape and
  retention/reference blocks are deterministic, while authenticated retention
  arithmetic, certificate-reference decoding, and nonce-watermark corruption
  fail stop. Meter definition now preserves nested typed failures, maps signed
  policy/semantic shape to `SemanticTransition`, maps authenticated-parameter
  cap rejection to `ProtocolWindowOrCap`, and uses one shared prepared carrier
  across capacity admission and execution. For `DefineMeterPolicy` only, the
  frozen first-error order is structural block/raw/aggregate bounds, exact
  owner/context/revision/replay plus cheap field admission, signed policy and
  exact semantic preparation plus authenticated nullifier-count arithmetic,
  family/defensive-total record caps, then clone-and-swap with late nullifier
  root verification and mutation. Saturated/cap-minus-one collisions prove
  that signed semantic and counter faults precede record caps, record caps
  precede a correctly shaped proof with the wrong authenticated root, and a
  rejection preserves the whole block overlay. Other operation families still
  require an explicit capacity-order audit before terminal failure mapping.
  Meter prune maps a pre-clone missing authority to
  `MissingRequiredAuthorityFact`. Meter retirement separately
  treats signed ID/height/next-fact drift as `SemanticTransition`, an absent
  authenticated policy as `MissingRequiredAuthorityFact`, an already-retired
  policy as `ProtocolWindowOrCap`, and old semantic-fact/authority divergence
  as `AuthenticatedOverlay`. Meter prune now rejects malformed signed IDs as
  `SemanticTransition` before lookup, missing policy as the negative-fact
  reason, unauthorized nullifiers as `NullifierProof`, and active/retained/
  referenced state as `ProtocolWindowOrCap`; authenticated retention arithmetic
  or certificate decoding remains invariant. `FundSettlement` now preserves
  nested nullifier/counter/CAS reasons and maps
  only its remaining signed certificate/commitment/units/semantic-shape
  failures to `SemanticTransition`; it reads no authenticated companion.
  `ReleaseSettlement` now validates its signed certificate ID and reservation
  negative fact before clone, preserves nested typed failures, treats a signed
  non-delete as `SemanticTransition`, and treats authenticated settlement-leaf/
  reservation divergence as `AuthenticatedOverlay`.
  `OpenChallenge` pre-clone admission validates signed IDs,
  active-certificate existence, and duplicate pending facts. Execution binds
  the exact body-derived kind-12 logical key before source selection, then
  joins the authenticated `Accepted` predecessor state and effective height to
  kind-16 authority; missing, malformed, or divergent old lifecycle is
  `AuthenticatedOverlay`, while same-height/expired-window rejection is
  `ProtocolWindowOrCap` and signed key/next-lifecycle drift is
  `SemanticTransition`.
  `ResolveChallenge` now validates signed IDs, pending identity, active
  certificate presence, and authenticated lifecycle before clone; not-pending
  is its existing exact deterministic reason, too-early resolution is
  `ProtocolWindowOrCap`, signed next-resolution drift is `SemanticTransition`,
  and pending/old-lifecycle companion drift is `AuthenticatedOverlay`.
  Governance proposal now preserves nested typed errors and maps its remaining
  signed target/phase/parameters/semantic and duplicate-target rejects to
  `GovernanceRule`. Governance approval validates signed hash/next epoch,
  proposal existence, and finalized duplication before clone; missing proposal
  retains `GovernanceApprovalMissing`, too-early approval is
  `ProtocolWindowOrCap`, signed approved-state drift is `GovernanceRule`, and
  authenticated proposal/parameters/pending-fact divergence is
  `AuthenticatedOverlay`.
  Certificate acceptance pre-clone admission now validates the signed
  certificate ID, funded-reservation negative fact, duplicate active record,
  exact signed certificate semantic envelope, consumer-key/meter authority
  facts, per-key nonce cap, and authenticated rolling span with closed reasons:
  signed shape is `SemanticTransition`, certificate decoding/proof is
  `CryptographicProof`, missing authorities are `MissingRequiredAuthorityFact`,
  cap rejection is `ProtocolWindowOrCap`, and authenticated arithmetic/span
  failure is invariant. The later acceptance execution join is still being
  refined separately. Its first execution segment is now also typed: signed
  certificate/funding/units mismatch is `SemanticTransition`, certificate
  decode or signature failure is `CryptographicProof`, key validity-window
  rejection is `ProtocolWindowOrCap`, and authenticated reservation/key
  semantic/authority corruption is `AuthenticatedOverlay`. The nonce join is
  now typed too: signed next identity/value mismatch is
  `SemanticTransition`, non-advancing nonce or exhausted per-key provider slots
  is `ProtocolWindowOrCap`, and authenticated semantic/watermark presence,
  logical-key, or value divergence is `AuthenticatedOverlay`. The tuple/meter
  join is now typed as well: signed tuple identity/fact/key drift is
  `SemanticTransition`; duplicate tuple, meter activity/output/task/cap, and
  unit-scaling rejection is `ProtocolWindowOrCap`; missing, malformed, or
  divergent authenticated meter policy/semantic companions are
  `AuthenticatedOverlay`. The settlement/measurement join now separates
  signed next settlement/evidence drift as `SemanticTransition`, premature
  settlement consumption as `ProtocolWindowOrCap`, and authenticated funded-
  settlement/reservation divergence as `AuthenticatedOverlay`. Relationship,
  provider, and usage-counter joins remain separate. The relationship/provider
  join now preserves exact missing-fact rejection, maps unresolved/expired or
  billing-outliving relationships to `ProtocolWindowOrCap`, and maps malformed
  relationship/registration facts or registration-history companion drift to
  `AuthenticatedOverlay`. The acceptance lifecycle/usage tail is now typed:
  signed accepted-lifecycle drift is `SemanticTransition`; authenticated
  policy/counter decoding is `AuthenticatedOverlay`; usage-cap and bucket-cap
  rejection is `ProtocolWindowOrCap`; and usage/prune-window arithmetic
  exhaustion is `ProtocolCounterExhausted`. No unclassified acceptance leaf
  remains. Future-candidate registration now also types its pre-clone ID/
  duplicate gate and execution predecessor/history join: signed epoch,
  predecessor, nonce, duplicate, and consensus-key reuse rejection is
  `ValidatorRule`; proof decoding/verification is `CryptographicProof`; and
  authenticated active-projection or registration-history drift is
  `AuthenticatedOverlay`. Its insertion slot is fixed before nullifier
  mutation. Active validator registration/rotation now also types pre-clone
  semantic/key admission and its history join: signed epoch, predecessor,
  nonce, shape, and key-change rejection is `ValidatorRule`; an already-active
  consensus key retains its exact reason; missing rotation history retains the
  missing-fact reason; PoP failure is `CryptographicProof`; revoked or actively
  referenced registrations are protocol rejects; and authenticated history/
  semantic-predecessor drift is `AuthenticatedOverlay`.
  Validator revocation/history prune now preserve missing-history rejection,
  classify signed transition/delete drift as `ValidatorRule`, retention,
  revocation, and active-certificate references as `ProtocolWindowOrCap`, and
  authenticated history/semantic/reference corruption as invariant. The
  clone-before-capacity preflight now also validates first-registration and
  both prune identities plus their exact target facts before applying record
  deltas, requires the one exact active kind-9 successor to bind the body
  validator identity, and preserves exact operation-ID replay before these
  state-dependent checks. The cloned history-prune candidate then rebinds its
  predecessor to the exact revoked key/nonce/proof history; a signed body/
  delete-identity mismatch remains `ValidatorRule`. A malformed or duplicate
  validator and an absent prune target therefore cannot be masked by a
  capacity result or checked-subtraction invariant. Certificate prune now
  classifies signed ID/delete-set drift as `SemanticTransition`, an absent
  active certificate as `MissingRequiredAuthorityFact`, retention or live
  challenge/reservation references as `ProtocolWindowOrCap`, and authenticated
  settlement/lifecycle/authority companion corruption as
  `AuthenticatedOverlay`; nested nullifier and mutation-postcondition reasons
  remain intact. No unclassified certificate-prune leaf remains.
  Leaf errors not yet assigned a narrower reason remain conservatively typed
  as an authenticated-overlay invariant. Success keeps the exact decoded owner plus
  the still-open snapshot and unsealed family state. These attempts do not yet
  seal family writes, merge multiple family operations into the cursor, advance
  it, form receipts, or promote a terminal result. Remaining PoCO leaf-reason
  refinement is required before terminal family-failure mapping.
  Future orphan value/node/stale-index
  rejection still depends on the startup full scan, and the in-memory pin
  spans one cloned store family rather than independent handles or processes;
  no external watermark or OS lock has landed. The exact parent/`BlockId`, peer
  body, and committed-head active configuration now have one bounded production
  validation constructor, and authoritative transaction
  decode/index/context plus runtime-gated success-only advance now share one
  snapshot-owning production cursor. Complete-body same-snapshot JMT planning
  and the four-root comparator are now production-compiled process-local
  carriers, and clones within one request object graph now share process-local
  one-shot exclusion. Schema-v5 reservation supplies a durable cross-instance
  congruence boundary, but it stores no evaluated artifact or result and has no
  crash-takeover lease. Core's completed `StorageAck` cleanup barrier and
  schema-v6 completion tombstone are not a host callback-outbox delivery
  acknowledgement. The future validation-time
  transaction that must
  atomically retain a revalidatable evaluated artifact and callback outbox, and
  the distinct Finalize-time transaction that must revalidate authority and
  atomically apply JMT/domain state, persist roots/native head, and advance the
  head, both remain open. Authenticated replay tickets, completion retirement
  after durable host-delivery acknowledgement, speculative-parent/BlockTree
  reconstruction,
  application-reservation takeover, revalidatable evaluated-artifact
  persistence, non-runtime family decode/execution and cursor advance,
  plan/state persistence, host callback-outbox scheduling/delivery acknowledgement,
  actual `Core::step` callback
  delivery, and ABCI wiring remain absent. In particular, the object-graph
  gate is not callback authority and the private admission branch emits no
  callback for a losing clone. The new consuming bridge proves only the exact
  route/full-ID Core input shape; it is not a delivered or exactly-once
  callback.
  Snapshot-closed real runtime-attempt failures now also enter the same outcome
  kernel without diagnostic-string classification: the opaque runtime token's
  transaction-reject branch becomes whole-block invalid, its invariant branch
  fails stop, typed database/storage/resource/pruned/source failures remain
  `Unavailable`, and authenticated-state/host/receipt/mutation invariants fail
  stop. The resulting outcome retains the complete closed failed attempt. This
  runtime-failure bridge does not yet construct a Core callback. The matching
  open/reservation/body-decode/post-state mappings are now present but likewise
  stop at an owner-retaining app-private outcome.
  Runtime resource estimation now has its own fallible
  `try_estimate_resources_v0` boundary and a distinct opaque estimate-failure
  token: deterministic validation/arithmetic failures remain separate from the
  state view's exact typed dependency error, operator recovery estimation does
  not read the on-chain fee policy, and no receipt or mutation can be produced.
  The legacy infallible estimator remains the only application caller; the new
  seam is not wired to simulation, ABCI, or terminal execution authority.
  Typed historical cutoff/projection reads, the exact estimate-input carrier,
  host wiring and terminal promotion, speculative
  parent storage, and ABCI transport mapping remain explicit P1 blockers; ABCI
  has no honest `Unavailable` proposal status.
- Mutation-calibrated symbolic Apalache evidence for finalized-prefix safety
  through depth 10. The revised model retains singleton vote paths, reaches
  legal finality at depth 4, and exposes conflicting finality at depth 8 when
  the safe-vote/lock gate is disabled. The older per-vote depth-10 result is
  retained but marked superseded because its bad state required a deeper run.
- `trnm-consensus-types` implementation scaffold and a pure core prototype
  with transactional steps, durable signing/finality outboxes, replay gates,
  validated ancestry, trusted synthetic genesis, exact `FinalityProofV0`, and
  persistent conflicting-QC fail-stop. Signed inputs are preauthenticated
  before the transactional clone, immutable payload bodies are shared through
  `Arc<[u8]>`, and the durable TC target synchronizes every ordinary referenced
  QC and runs its full high-QC/lock/finality transition. Standalone missing QCs
  use an exact durable active target plus a canonical non-preempting backlog,
  and bounded terminal payload facts survive core recovery and block-tree
  eviction. Pruned QCs strictly below durable finality are treated as already
  subsumed.
- Proposal-carried ordinary QCs with missing parent context now create the same
  exact durable active/backlog obligation as direct QC ingress. A first-arrival
  proposal carrying a complete multi-reference TC instead persists the full TC
  obligation, including lower referenced QCs, and processes every ready
  reference through the ordinary QC transition. At the durable finalized
  height, a different-view competing QC is subsumed only after same-view/
  different-block conflict detection; a TC selecting such a stale competitor
  can advance only its authenticated timeout view. Direct QC, proposal carrier,
  and direct/carried TC conflicts cross pending-sign, pending-finalize, and
  recovery-replay busy gates only after authentication and then share the same
  durable halt transition.
- Core `SafetyState` schema v5 introduced durable capture of every direct or
  synced payload-validation obligation before its validation effect. Schema v6
  atomically replaces an exact callback obligation with a canonically sorted
  `(route, full ValidationId)` completion tombstone containing the complete
  three-result value, full `Valid` commitments, and first revision; exact
  result replay remains idempotent after restart. There is no automatic
  eviction, and registration reserves the future tombstone under the shared
  `completions + obligations <= max_observed_messages` bound. Safety halt
  clears obligations atomically while retaining prior completions. Recovery
  validates both record sets but deliberately rejects a non-empty obligation
  set until authenticated replay tickets and speculative-parent reconstruction
  exist; schema v5 is not implicitly migrated. This ordering and tombstone are
  distinct from, and do not implement, an application callback outbox,
  delivery acknowledgement, type-level callback authority, or callback
  exactly-once.
- The epoch-zero core now derives a checked `EpochGeometryV0` from the exact
  active parameter preimage and enforces a unified fail-closed boundary before
  the mandatory checkpoint height. Regular proposals/replay, votes, QCs,
  timeout high-QCs, every direct/carried TC reference, persisted sign intents,
  finalized state, finality proofs, and pending sync obligations cannot cross
  that boundary. The last pre-checkpoint regular block retains the complete
  durable vote pipeline; checkpoint, seals, handoff, and epoch activation are
  still unsupported rather than partially implemented.
- The current source inventory contains 110 focused `trnm-consensus-core`
  tests. `trnm-consensus-sim` now provides an epoch-0 deterministic scaffold
  with 25 tests: 9 focused unit tests and 16 end-to-end scenarios. The suite
  covers cross-layer finalized-prefix comparison across volatile core,
  persisted, pending persistence/proof, and application-applied state,
  persistence-before-sign crash rollback, a running crash from nonzero durable
  state through safety replay, durable conflicting-QC halt and restart,
  4-/7-validator quorum-loss boundaries, 2+2 partition/heal, and consumed
  drop/duplicate/delay/reorder rules with repeat-stable traces. Scripted
  payload outcomes cover `Unavailable -> Valid` generation retry,
  generation-bound replay gating, durable certified-invalid halt/recovery, and
  standalone QC-before-proposal crash/recovery; they are not a real
  source/body/runtime model. Every simulator-created `Valid` callback now
  carries a real private-field B2-D `ValidatedBlockCommitmentsV0`; the core
  rejects a capability for another block before consuming the exact request
  generation. When one replay generation replaces another, the driver cancels
  only the exact old volatile pending mirror plus its matching durable synced-
  validation obligation behind the cleanup persistence barrier before
  optionally re-registering the overlapping block under a fresh ID. Real-
  obligation tests
  cover both callback-first and replacement-`ReplayNext`-first orderings; the
  stale result cannot consume the current fault script or leave an orphaned
  pending slot. One short-epoch scenario proves the simulator
  reaches the checkpoint fence without producing a boundary vote or QC.
- The completed post-B2-F sweep passes 212 tests: types 74, crypto 15
  (including raw B1 and B2-B through B2-F CEV0 consumption), core 99, and
  simulator 24. Four-crate warning-denying
  Clippy, rustfmt, `git diff --check`, all twelve
  parameter/wire/anchor-finality/ordered-root/B1/B2-A/B2-B-structure/
  B2-B-crypto/B2-C/B2-D/B2-E/B2-F gates, the full current lock-pinned Quint
  `0.32.0` formal gate with retained mutants, pinned `protoc 29.3` descriptor
  compilation, and
  project preflight form the local gate set. The same set is now wired into
  `.github/workflows/trnm-poco-bft-v0.yml`; that new workflow has not yet run on
  GitHub and supplies no remote CI evidence in this worktree. This remains
  regression and bounded B2-A/B2-B/B2-C/B2-D/B2-E/B2-F evidence only; it cannot
  satisfy the independent consensus review, remaining cross-implementation,
  epoch, or real-node exit authorities.
- B2-G adds one independent snapshot-candidate schema/vector gate and the
  matching Rust deterministic calculation/PoP kernel to this recorded
  post-B2-F baseline. Aggregate test counts are intentionally left to the next
  completed full sweep. The new evidence is bounded to caller-supplied
  transcript computation and cannot satisfy snapshot/runtime provenance or
  epoch-transition exit authority.

### B2-A certificate-kernel tranche (closed)

B2-A is deliberately limited to the ordinary certificate kernel. Its closed
logical-object set is CEV0 primitives, `MessageKindV0`,
`CommonConsensusContextV0`, `ValidatorV0`, `ValidatorSetV0`,
`SignatureShareV0`, `VoteSignV0`, `QuorumCertificateV0`,
`HighQCSummaryV0`, `TimeoutSignV0`, `TimeoutEntryV0`, and
`TimeoutCertificateV0`, together with the validator-set, vote, QC, timeout,
and TC domains. Proposal, block, epoch/handoff, receipt/evidence, Consumption
Certificate, and light-client objects remain outside this tranche.

B2-A is closed under that exact boundary. The ordered manifest fixes all ten
covered objects, five domains, ten protobuf projections, hard bounds, mapping
roles, and layered stable errors. A standard-library Node.js implementation
independently consumes eight committed B1 raw objects, exact-round-trips them,
recomputes their digests and weighted threshold, uses an auditable strict
RFC 8032 verifier, and rejects 4,486 non-complete prefixes plus the committed
boundary and semantic corpus. Rust exact bounded ordinary validator-set/QC/TC
decoders consume the same raw values before strict Ed25519 verification. The
projection source-drift gate checks field/mapping drift while the separate
proto gate compiles the descriptor. This closure does not close B2 overall or
make the node wire-conforming.

### B2-B anchor/handoff certificate-kernel tranche (closed)

B2-B extends the machine-readable/exact-decoder boundary through
`BlockKindV0`, `BlockHeaderV0`, `HandoffDescriptorV0`,
`HandoffVoteSignV0`, `HandoffCertificateV0`, and an inert three-part
epoch-anchor kernel. The extension imports the B2-A QC/signature definitions
and fixes seven protobuf projections, four domains, role-scoped redundancy,
relations, bounds, and six additional stable Rust errors.

The structural Node.js lane consumes six raw/derived objects and rejects 3,435
incomplete prefixes, 13 boundary cases, and 25 semantic/relationship cases;
its source fixture explicitly makes no cryptographic claim. The independent
crypto lane publishes 11 artifact classes and 36 negative cases using distinct
old/new weighted Ed25519 sets (`4/3/2/1`, `W=10`, quorum `7`) and covers exact-
threshold plus one-below terminal QC and both handoff roles. Rust exact-decodes
the same committed raw objects before strict verification.

The epoch-anchor decoder returns only an inert private-field kernel whose
verification method returns `Result<()>`; no peer-controlled bytes can produce
or authorize an `EpochAnchorQC`. The committed anchor candidate is only an
exact field/byte binding. Complete epoch authorization, checkpoint/two-seal
ancestry, authenticated snapshot/state provenance and committed set/parameter
preimage reconstruction, PoP, activation/upgrade authority, first-new-block
rules, remaining canonical bodies, envelope admission, evidence/receipts,
light-client proofs, B2 overall, and `wire_conformance` stay open. B2-C
separately closes the exact inert `NextEpochCommitmentV0` kernel; it does not
close those authorization and provenance obligations. B2-E later closes only
the ordinary old-set checkpoint/two-seal semantic chain, not the external
provenance or authorization obligations in this list. B2-F later composes
those exact witnesses for same-version fields 1--11, but remains inert and
still cannot mint an anchor or activate the transition. B2-G separately
closes exact PoP and deterministic candidate/fallback computation over an
unauthenticated transcript; it does not supply the missing state provenance.

### B2-C next-epoch commitment kernel tranche (closed)

B2-C closes only `NextEpochCommitmentV0` and its inert same-version v0
context-binding kernel. The ordered manifest fixes the 15 canonical fields,
one derived protobuf digest, enum/optional/bool semantics, nonzero required
hashes, checked outgoing-epoch geometry, exact fallback identity, and four
additional stable Rust decoder errors.

The independent Node.js lane exact-decodes and byte-identically re-encodes
three committed raw objects, recomputes their commitment digests, rejects all
608 incomplete prefixes and three trailing-byte variants, exercises 25 parser
boundaries and 21 context relations, accepts two complete same-version
contexts, and confirms one shape-valid upgrade fixture remains inert. Rust
consumes the same raw CEV0, round-trips it exactly, recomputes its digest, and
returns a private-field `NextEpochCommitmentV0`. Context validation returns
only `Result<()>`; neither decoder nor validator can mint an epoch anchor,
transition capability, or trusted runtime context.

Snapshot/state authority, full independently decoded parameter preimages,
governance and upgrades, complete epoch authorization, first-new-block rules,
and atomic core epoch transition remain open. B2-G closes candidate
computation, lowest fallback-reason selection and exact PoP only for one
caller-supplied unauthenticated transcript. B2-E later closes only one ordinary old-set
checkpoint/two-seal semantic chain; authenticated snapshot/runtime/set/
parameter provenance and core transition integration remain open. B2-F later
binds the exact supplied B2-B/B2-C/B2-E witnesses without adding provenance or
authority. The
certificate-only B2-B verifier was also hardened so production proposal and TC
verification reject every epoch anchor until those dependencies exist.

### B2-D ordinary block-validation kernel tranche (closed)

B2-D closes the ordinary epoch-local canonical body slice without widening the
epoch boundary. Its machine-readable contract fixes the exact
`ApplicationPayloadV0 = List<Bytes>`, execution event and receipt commitment
values, `VoteEvidenceRecordV0`, mandatory `DoubleVoteEvidenceV0`, all three
ordered-root bindings, exact logical-block-size arithmetic, the ordinary
`Block` protobuf projection, and the already-frozen ordinary
`ProposalSignV0` binding. Receipt values are intended to be supplied by the
locally authorized deterministic runtime, but this kernel only checks
caller-supplied typed commitments and proves no execution provenance. They are
not a peer transport authority.

Rust now has bounded exact decoders for payload, one receipt commitment,
and DoubleVote evidence; stable parser and admission error taxonomies; and a
private-field `ValidatedBlockCommitmentsV0`. That capability is returned only
after a Regular header, canonical payload/evidence, caller-supplied receipt
relations, active parameter/set context, three roots, exact size limits, and
every evidence record is accepted by the caller-supplied `SignatureVerifier`.
The token does not attest verifier identity or intrinsically prove strict
Ed25519; production integration must pass
`trnm_consensus_crypto::StrictEd25519Verifier`, and the crypto corpus exercises
that concrete path. It deliberately does not authenticate a parent state,
prove that the receipts came from an authorized runtime, execute or authorize
a runtime, classify transaction failure, or authorize a vote, checkpoint,
seal, handoff, anchor, or epoch transition. Protocol integration must supply
those receipts from the locally authorized deterministic runtime.

The Rust raw-consumer lane takes the committed valid header, payload,
receipts, evidence, and active-set preimage through the complete ordinary
commitment capability. It also exact-decodes the valid ordinary QC and
independently reconstructs the valid `ProposalWitnessV0` signing root and
proposer signature. The independent Node lane consumes the complete corpus,
including all 24 proposal/QC negative fixtures plus the active-context and
size-boundary campaigns. This split does not claim that Rust consumes every
proposal negative or that either lane is a raw protobuf `Proposal` decoder;
the proposal closure remains one next-view logical/projection fixture only.

The existing core `Block` remains a legacy opaque-payload prototype holder, but
`PayloadValidationResult::Valid` now carries the B2-D capability and both
ordinary and synced callback paths require its exact block ID before consuming
the request generation. Core regressions cover direct and synced mismatches;
the simulator constructs the capability from its canonical payload, typed
receipts, ordered evidence, active parameters/set and real B2-D validation
path. This closes the callback capability gate, not authenticated parent state,
authorized-runtime/receipt provenance, canonical durable replay context,
checkpoint bodies, permanent journals, B2 overall, or `wire_conformance`.

### B2-E checkpoint/two-seal semantic-kernel tranche (closed)

B2-E closes one deliberately narrow old-epoch finality slice. Its
machine-readable contract fixes the complete 54-field, 341-byte
`ConsensusParametersV0` preimage plus the ordinary old-set
`CertifiedHeaderV0` and `FinalityProofV0` forms needed for
`checkpoint <- seal-1 <- seal-2`. The bounded, root-exhausting Rust entry
points are `decode_consensus_parameters_v0_exact`,
`decode_ordinary_certified_header_v0_exact`, and
`decode_checkpoint_finality_proof_v0_exact`. They require the exact supplied
old validator set, decoded old parameters, next-epoch commitment, and
authenticated checkpoint-parent timestamp; they do not discover or
authenticate those inputs.

The specialized semantic path first performs complete ordinary finality
admission, then fixes the old-set geometry and block kinds, direct ancestry,
canonical leaders, bounded timestamp steps, frozen empty seal roots,
checkpoint-state preservation through both seals, one exact repeated
`NextEpochCommitmentV0` digest, and the old schedule's snapshot-cutoff and
activation-height relations. The committed raw corpus uses real Ed25519
proposer and ordinary-QC signatures and is consumed through
`trnm_consensus_crypto::StrictEd25519Verifier`. Successful verification returns
only the private-field inert `CheckpointTwoSealKernelV0`; it cannot authorize
an epoch anchor, handoff signature, first-new-epoch proposal or vote, or epoch
transition. The fixture is next-view-only; B2-E makes no new TC semantic claim
and B2-A remains authoritative for ordinary TC behavior.

The committed `snapshot_state_root` is only an authenticated claim inside the
next-epoch commitment. B2-E does not prove snapshot/JMT/ICS23 ancestry or
membership, runtime or receipt provenance, validator-set or parameter
selection provenance, governance, complete epoch-anchor/handoff/activation
authority, or checkpoint
body execution. The epoch-zero core does not consume this B2-E finality
capability. B2-G separately closes deterministic candidate/fallback and PoP
relations over caller-supplied facts, not their provenance. Permanent
terminal/QC/conflict journals, checkpoint-grade sync and full ancestor
delivery, transport admission, and light-client verification remain open. The
PoCO gate set is present in `.github/workflows/trnm-poco-bft-v0.yml`, but has
not yet produced a remote GitHub run. B2 overall, P0, P1, and
`wire_conformance` therefore remain open.

### B2-F same-version joint-handoff composition tranche (closed)

B2-F closes only the field-1-through-11, same-version-v0 composition of
`EpochHandoffProof`. Its ordered manifest imports the already frozen B2-B,
B2-C, and B2-E objects instead of inventing another logical bundle. The
transport message has no aggregate CEV0 preimage, domain, digest, or authority;
each nested object remains exact-decoded, re-encoded, and verified under its
own frozen domain.

`verify_same_version_joint_handoff_kernel_v0` binds the exact supplied old/new
set and parameter preimages, the next-epoch commitment, complete old-set
checkpoint/two-seal proof, exact terminal seal and certifying-QC digest,
handoff descriptor, and independent old/new handoff roles. It rejects protocol
version changes and a present upgrade hash because field 12 is outside this
tranche. Success returns only private-field `JointHandoffKernelV0` bound facts;
there is no method to construct an `EpochAnchorQC`, authorize handoff signing,
accept a first-new-epoch proposal, advance finality, or activate a transition.
The generic verifier parameter is not a verifier-identity attestation;
production integration must still supply `StrictEd25519Verifier`.

The independent Node gate locks all 11 transport fields, consumes four source
corpora and exactly 14 committed raw objects, rebuilds, serializes, reparses,
and strictly verifies distinct-set and exact-fallback positive compositions,
and rejects 10 semantic/cryptographic classes. Nine fail in composition; the
one-below-quorum bundle fails earlier in the exact decoder. Snapshot/JMT/runtime provenance,
candidate/fallback state provenance and governance, checkpoint body
execution, upgrade field 12, first-new-epoch proposal field 13, new-epoch
finality field 14, epoch-anchor authority, activation, and atomic core
transition remain open. B2-G separately supplies inert deterministic
candidate/fallback/PoP computation evidence for caller-supplied facts.

### B2-G deterministic candidate/fallback computation kernel (closed)

B2-G freezes exact validator-key PoP plus deterministic candidate/fallback
calculation for one caller-supplied normalized snapshot transcript. The
machine-readable schema and shared corpus cover input-permutation invariance,
deterministic internal canonical sorting, uniqueness, normalized contribution
and candidate bounds, maturity/expiry
and decay, hierarchical relationship caps, PoCO/bond/raw ceilings,
descending-raw/ascending-ID selection followed by canonical set ordering,
rollout-specific effective weights, full set constraints, successful shadow
reason-0 carry, numeric-minimum fallback reason, and exact old-configuration
fallback. Invalid PoP is a complete-candidate reason-4 failure, never an
entry-local repair.

`ValidatorKeyProofOfPossessionV0` exact-encodes the seven frozen signing fields
plus its fixed Ed25519 signature; both independent and Rust lanes verify the
`trnm.poco-bft.validator-key-pop.v0` root. The frozen corpus has 9 exact PoP
objects, 1,744 rejected non-complete prefixes, 110 real Ed25519 verification
checks, 4 positive rollout cases, 1 full-input permutation, 9 calculation
boundaries, 14 atomic fallback cases, 14 retained PoP negatives, and 0
authorization outputs. Rust additionally rejects noncanonical `S`,
noncanonical `R`, and a small-order public key through the strict production
verifier. Every contribution, eligibility,
finalization epoch, relationship, registration/nonce, jail, bond, old-set,
parameter, rollout/governance, and cutoff fact remains caller-supplied. This is
not a complete Consumption Certificate wire/admission closure, and PoP alone
does not prove registration freshness, eligibility, or finalized-state
membership.

Rust success returns only private-field inert `CandidateSelectionKernelV0`
computation evidence. It cannot construct or authorize a next-epoch
commitment, `EpochAnchorQC`, handoff signature, first-new-epoch proposal,
activation, or core transition. B2-H1 and B2-H2 closed the first two arrows.
B2-H3a additionally freezes exact semantic-value envelopes and an atomic
next-version entry/manifest transition kernel, but does not close authorized
runtime execution. The remaining dependency is strictly:

```text
closed finalized cutoff header
  -> closed JMT/ICS23 manifest projection and membership/non-membership
  -> closed H3a exact semantic-value + atomic transition kernel
  -> closed H3b1 production persistence/restore projection seal
  -> production runtime mutation authority, profile and checkpoint body/receipt provenance
  -> authenticated normalized projection and B2-G rerun
  -> exact candidate/commitment/handoff join
  -> EpochHandoffProof fields 13/14
  -> epoch-anchor activation authority and atomic core transition
```

Field 12 governed-upgrade authority remains a separate open branch.

### B2-H1 cutoff-header and Consumption Certificate wire kernel (closed)

`AuthenticatedFinalizedCutoffHeaderV0` is produced only after the complete
ordinary three-header finality proof verifies and the finalized header equals
the protocol-derived `checkpoint_height - snapshot_lead_blocks`. Its private
fields bind the proof ID, outgoing epoch, exact cutoff height/block ID, and the
header's state root; it accepts no independent state-root assertion.

`ConsumptionCertificateBodyV0` and `ConsumptionCertificateV0` freeze all
sixteen normative body fields, CEV0 `u128` and optional-root encoding, the
signature-free certificate ID, bounded opaque IDs, billing interval, exact
decode, and strict consumer-signature verification boundary. The shared raw
corpus contains one complete 349-byte object, 349 rejected non-complete
prefixes, trailing-data rejection, and a real Ed25519 signature. Independent
standard-library Node and Rust lanes reproduce the body bytes/digest,
signature, certificate ID, and complete bytes; Rust uses
`StrictEd25519Verifier`.

This is logical wire and cryptographic admission, not application-state
authority. Consumer-key authorization, nonce and tuple/ID uniqueness, active
meter, settlement and measurement validity, acceptance/revocation/challenge
state, and the complete cutoff snapshot projection remain for the next
JMT/ICS23 plus authorized-runtime tranche. Neither token can mint candidate,
anchor, handoff, activation, or Core-transition authority.

### B2-H2 cutoff-rooted JMT/ICS23 namespace kernel (closed)

The existing AppHash v4 `Sha256Jmt` integration is now joined to the B2-H1
cutoff relation through a bounded PoCO snapshot namespace. Because JMT orders
key hashes rather than key preimages, v0 does not make an invalid prefix-range
completeness claim. Instead, one manifest leaf at the cutoff version commits
the canonical `(kind, logical_key)` entry count and an ordered root over every
entry's exact kind/key/value bytes. The verifier requires that manifest's real
ICS23 membership, every listed entry's membership at the same root/version,
and canonical explicit non-membership proofs for queried absent entries.

The private-field cutoff join additionally requires JMT version equal the
finalized cutoff height and raw JMT root equal the cutoff header state root.
The shared corpus freezes namespace discriminant 8, 15 entry kinds, exact key
preimages, three canonical members, one absence query, manifest bytes and
ordered root. Rust exercises four real JMT membership proofs and one real
ICS23 non-membership proof; independent Node code reproduces the key/entry/
manifest/root contract and rejects omission, reordering, and duplication.

Completeness is manifest-relative by design: leaves not named by the manifest
are outside the authoritative projection. The next runtime/checkpoint tranche
must enforce that every PoCO state write atomically updates this manifest and
must semantically decode the values. B2-H2 alone cannot prove execution,
receipts, candidate selection, checkpoint body validity, or epoch transition.

### B2-H3a semantic-value and atomic transition kernel (closed)

All fifteen snapshot roles now have one bounded exact value envelope, a
kind-specific payload decoder, and a logical key derived from the exact
`(kind, identity)` preimage. Existing exact decoders are reused for the full
Consumption Certificate, validator-key PoP, validator set, and consensus
parameter payloads. A canonical compare-and-set mutation binds expected and
next values, and a count-bound ordered mutation root commits the whole batch.

`plan_poco_snapshot_transition_v0` re-verifies the complete source proof
bundle and exact entries root/count in the same call, exact-decodes every
source and next value, rejects stale/noncanonical/duplicate mutations and raw
namespace-8 bypasses, checks compare-and-set against both the manifest and the
physical JMT leaf, computes the manifest from the complete post-state, and
places every nonempty entry batch plus its manifest into one exact-next-version
JMT plan. Creates require revision 1, updates require the exact successor, and
the bounded planned-tree overlay proves that the target remains representable
under the H2 proof-bundle limits without cloning full tree history. Empty
ordinary batches carry the last manifest height; a scheduled cutoff explicitly
refreshes it even when empty. Application replans the bounded exact writes on
the supplied tree and requires the same target root, preventing a batch from
an equal-root but different NodeKey history from being transplanted. Applying
a stale sibling plan fails closed.

This is intentionally H3a rather than full H3. The sealed plan is not yet
integrated into every production `ConsensusApplication`, persistent,
migration, genesis and state-sync mutation path. The current runtime lacks the
frozen chain/genesis/protocol/profile/parameter and authenticated-parent
context required for authority; checkpoint body execution and receipt
provenance remain open. H3a deliberately produces no checkpoint-state binding:
height/root equality alone is not chain scope, cutoff ancestry, execution, or
receipt provenance. Full cross-entry certificate/key/nonce/tuple/meter/
settlement/evidence/governance semantics and authenticated B2-G rerun remain
the next ordered tranche.

### B2-H3b1 production persistence and restore seal (closed)

Production storage and restore paths now admit namespace 8 only as one exact
physical projection: either no PoCO leaves before activation, or exactly one
47-byte manifest plus the physical entries named by its canonical count/root.
Every physical key uses the frozen manifest/entry layout, every entry value is
kind-specific exact-decoded, the manifest height is not ahead of committed
state height, and hidden, duplicate, malformed or unreferenced leaves fail
closed.

The shared validator runs on in-memory state encode/decode, SQLite startup and
schema-migration load, and ABCI snapshot restore v3/v4. SQLite transition and
empty-state replacement additionally reconstruct the authenticated source
namespace, overlay the planned namespace writes, and validate the exact target
projection inside `BEGIN IMMEDIATE` before any domain or JMT row is written;
failure rolls back with the committed head unchanged. A fixed shared corpus
binds the manifest/entry physical keys and rejects missing manifest, hidden
leaf, future manifest, trailing semantic value and malformed namespace key.

H3b1 does not authorize a production PoCO mutation input. The authoritative
chain/genesis/protocol/profile/parameter/parent context, checkpoint body
execution and receipt provenance, full cross-entry business rules, and the
authenticated B2-G rerun remain B2-H3b2. Therefore this seal produces no
checkpoint binding, handoff, activation or Core-transition authority.

### B2-H3b2a production checkpoint authority and execution binding (closed)

The production application now authenticates one PoCO authority object at
genesis and requires exact equality on startup and ABCI snapshot v3/v4
restore. That object binds the nonzero genesis hash and protocol-profile hash;
the configured chain ID, protocol v0, old validator set, active consensus
parameters, and live CometBFT validator lifecycle must agree with the exact
cutoff projection before a private checkpoint-execution capability exists.

`ProcessProposal` and `FinalizeBlock` both recompute that capability from the
actual block hash, timestamp, contiguous parent height/AppHash, one sealed
historical scheduled-cutoff JMT version/root/exact projection, ordered
transaction body, exact protobuf `ExecTxResult` bytes, and post-execution
AppHash. The cutoff projection must also equal the immediate-parent
projection, so post-cutoff PoCO mutation is rejected until the complete
state-machine policy is closed. The shared vector binds canonical bytes of
length `404 + chain_id.length` (405..532); its fixed 21-byte-chain-ID case is
425 bytes and includes the cutoff manifest root/count and ordered
payload/receipt roots. Independent Node and Rust implementations bind the same
execution ID. The former 389-byte draft omitted the manifest root/count and is
noncanonical. Transaction bytes and encoded receipt bytes each have an 8 MiB
aggregate ceiling, transaction count is bounded by `u32`, and all checked
count/size admission runs before receipt encoding or ordered-root hashing.
The emitted checkpoint event and execution ID are telemetry only, never a
capability input. A four-entry `(JMT version, state_root)` authenticated
projection cache is strictly a performance layer: it rereads the real root on
hit and after a miss/load, and hit, miss, eviction, or disabling the cache
cannot change the result or capability bytes. A first-version or key index
remains an optional derived-cache optimization, not authority and not an
H3b2b1 closure condition.

H3b2a establishes authoritative checkpoint context and receipt provenance;
it does not yet authorize PoCO business writes. Complete certificate/key/
nonce/tuple/meter/settlement/evidence/governance cross-entry rules and the
authenticated B2-G rerun remain H3b2b.

### B2-H3b2b0 pure semantic transition kernel (closed, non-authorizing)

The H3a exact decoder now returns one shared typed semantic fact that the
compare-and-set path uses directly for transition admission. H3b2b0 freezes
every v0 state discriminant, block-height and target-epoch clock boundary,
and the conservative create/update policy for all fifteen kinds. Kind 3's
existing `u64` wire field is canonically `max_accepted_nonce`: absence means
no accepted nonce, and every update stores a strictly larger accepted nonce
without permitting regression or deletion. Consumer-key public key and
`active_from`, and meter `unit_scale` and `active_from`, are immutable; their
only updates are one-way revoke/retire. Settlement, validator registration,
certificate lifecycle, and rollout approval follow their frozen one-way
graphs. All other values are create-only, semantic no-op revision bumps are
invalid, and deletion is rejected for every one of the fifteen kinds. Initial
creation is also fail-closed: keys and meters start unrevoked/unretired,
settlement/registration/lifecycle start in state 1, and rollout governance
starts proposed rather than approved. Revision create/update uses exact `1` or
checked `+1`; an existing `u64::MAX` revision is exhausted. Absent key/meter
upper bounds remain active through `u64::MAX`, and a billing window ending at
`u64::MAX` is inclusive but cannot admit a later acceptance height.

This is a pure validation kernel, not a production business-write authority.
It does not prove the funded-and-unused ledger, meter task/output/caps or
evidence, a challenge decision ID, governance decision/approval height, or a
  validator's previous registration nonce/history. At the H3b2b0 boundary,
  lifecycle `effective_height` is only a strictly increasing declaration;
  H3b2b1 subsequently binds same-operation equality to the authenticated
  transition target height.
It produces no candidate,
handoff, activation, or Core-transition output. H3b2 therefore remains open.
H3b2b1 has since extended the authenticated layouts/data authorities and added
one coherent operation planner. H3b2b2 reconstructs the B2-G transcript from
that authenticated projection and reruns `StrictEd25519Verifier` plus B2-G in
the same call; the old unauthenticated inert computation token is not an input
and MUST NOT be bound or reused.

### B2-H3b2b1 authenticated application authority and atomic planner (closed)

Kinds 1 through 15 retain their frozen wire layouts and H3b2b0 meanings.
Kind 16 appends one exact `trnm.poco.application-authority.v0` state to the
same namespace-8 manifest. The exact kind-16 decoder, bidirectional
semantic/authority validator, strict Ed25519 certificate/PoP verification,
pre-clone capacity admission, and common
`PocoApplicationBlockOverlayV0::seal` path are implemented and gated. Legacy
projections without kind 16 remain non-authorizing. A status label, normalized
truth-table row, operation summary, telemetry value, or other caller side fact
is never authority and cannot replace exact raw state, exact raw operation,
proofs, or authenticated context.

The production application constructs the operation context privately from
the committed parent height/AppHash, exact next target height, chain/genesis,
active epoch/parameters, and the AppHash-authenticated governance signer-policy
commitment. Caller-supplied telemetry or a generic operator role cannot replace
those facts. Operations execute in transaction order in one bounded block
overlay, so same-block nonce, tuple, decision, settlement and key conflicts are
visible. Sealing produces canonical entry writes plus exactly one successor
manifest; those writes are merged with ordinary authenticated writes into the
block's single JMT plan/version/root. The SQLite `BEGIN IMMEDIATE` projection
validation remains a second atomic boundary. Business writes are admitted only
through the scheduled cutoff, and every configured `snapshot_lead_blocks` must
fit the retained authenticated JMT history (`<= 8192`) on genesis, live load,
migration and restore.

Five non-prune operation automata are now reachable through the exact planner,
capacity checks, strict verifier and common seal in implementation tests. Their
fixed sequence-local schedule for the shared corpus is:

- both certificate/challenge branches use one H1 composite block
  (`authorize_consumer_key`, `define_meter_policy`, provider
  `register_validator`, and `fund_settlement`), H2 certificate acceptance, H3
  challenge open, and H4 rejected or sustained resolution, with cutoff H6;
- governance uses H1 proposal followed by H2 approval;
- validator history uses H1 registration followed by H2 rotation; and
- settlement release/replay uses H1 funding, H2 release, and H3 rejection of a
  new funding attempt, with `writes=0` and the H2 head unchanged.

The committed shared raw corpus now reconstructs the complete active-genesis
AppHash/history, carries 18 successful raw operations with exact sparse proofs,
binds every step to the actual preceding full JMT root, and reproduces each
successor manifest/entries root in independent Node and Rust consumers. Nine
negative replays freeze the authoritative first error, `writes=0`, and an
unchanged head. Consumer-key, meter, and validator prune replay specifically
hit permanent nullifier families 10, 12, and 14 rather than a temporary
decision nullifier. Business lineage v1 binds the normalized operation body
and exact semantic identity/facts; only target-bound height/revision and the
operation's decision identifier are normalized.

Replay protection is one checked-count, 256-level sparse-Merkle accumulator
with fourteen domain-separated nullifier families and exact 8,230-byte
non-membership proofs. Generic deletion remains invalid. Certificate,
consumer-key, meter, and validator prune logic exists only as four isolated
prune-transition/real-JMT test kernels; it is not a production-authorized prune
surface.

All useful prune retention boundaries cross epochs, while the production
application context remains restricted to the active epoch. Production prune
reachability therefore depends on Core activation plus an authenticated
next-epoch configuration transition. Unit, formal, or isolated-JMT witnesses
MUST NOT be reported as production or authenticated cross-epoch closure.

The 210-case Node constraint gate and focused Rust kernel tests remain useful
lower-layer evidence. Closure comes from the canonical nine-sequence corpus:
18 successful production/JMT steps, nine authoritative no-write/head-unchanged
negatives, independent Node `check-final`, and the non-ignored Rust production
replay consumer. The bounded Quint model separately checks eight application-
atomicity invariants, six positive witnesses, and the retained
`partial_cross_entry_commit` and `prune_without_nullifier` mutants.

H3b2b1 is closed by that evidence. It authorizes no B2-G result, production
cross-epoch prune closure, handoff, activation or Core epoch transition.

### B2-H3b2b2 application-authenticated candidate reconstruction (bounded shared and ABCI/restart evidence landed; remaining closure in progress)

H3b2b2 now provides one crate-private checkpoint/candidate join. It holds the
same authenticated historical cutoff projection while constructing the
checkpoint-execution capability, repeats the full physical/bidirectional
application audit, rebuilds every candidate/contribution/parameter/bond/jail
fact from raw cutoff state, hard-codes `StrictEd25519Verifier`, and executes a
fresh B2-G calculation. It accepts no caller-supplied transcript, eligibility,
generic verifier, current-head state, event/status, or old inert B2-G token.

Kind 16 gains one append-only, bounded future-candidate registration family.
An old-set ID/key is a proof-free candidate only with a matching active,
non-revoked kind-9/kind-16 registration; old-set membership alone cannot mint
registration authority. A new identity or changed old key must target exactly
the successor epoch with strict PoP. Changed keys bind the exact authenticated
predecessor nonce/history head and a strictly increasing nonce; new identities
have no predecessor; unchanged old keys cannot create redundant future
records. Certificate providers use their exact retained active registration
and the PoP's own authenticated registration epoch; the proof epoch may be
historical, and the provider need not already belong to the old validator set.

The normalized mapping is frozen conservatively. A finalized target approval
selects its exact role-2 parameters; no approval carries exact active
parameters as reason-0 no change, and pending governance has no authority.
Historical certificate `finalized_epoch` is derived from its finalized
acceptance height. Only independent relationships contribute; accepted with no
pending challenge and challenge-rejected are eligible, while sustained or
pending challenges are not. Bond counts only for `active_slashable` with
checked `target_epoch + evidence_window_epochs < locked_until`; absent,
unbonding or insufficiently locked bond is zero. Jail applies exactly while
`target_epoch < jailed_until`, with absence/not-yet-proved completeness kept
distinct.

The private result binds the checkpoint, candidate-parameter hash, canonical
transcript digest, canonical result digest and authorization ID, including on
fallback. `ProcessProposal` and `FinalizeBlock` independently reconstruct it
from the committed parent/cutoff before pending/commit effects.

Cross-epoch retained certificates require a separate normalized kind-16 usage
rollover. Meter usage keeps only the bucket for the new rolling span;
consumer/provider, task/provider and provider usage keep only exact new-epoch
buckets. Older usage is removed, never relabeled or copied, while still-mature
certificates remain historical facts. A bounded compaction helper and fixture
test exist, but production Core activation cannot yet drive the atomic active-
configuration/kind-16/manifest/JMT rollover. This remains an H3b2b2a
production gap.

The bounded shared machine-readable contract/vector has landed. Its two
continuous-history scenarios cover a four-candidate, mature-contribution
reason-0 result and a complete authenticated pending-challenge reason-3
fallback. Node independently reconstructs the raw cutoff/head projection,
strict PoPs, B2-G and every checkpoint/transcript/result/authorization seal;
a non-ignored Rust test rebuilds the same JMT fixture and one-call authority
and requires byte-for-byte equality with the committed vector. A third shared
control freezes the jail-expiry equality boundary. The Node consumer also
recomputes every historical JMT root, requires exact physical namespace
completeness, exact-decodes every retained kind payload, and executes the
root-consistent rejection families enumerated by the machine-readable schema.

The production-path evidence now consumes both canonical outcomes through
independent application instances. Each instance starts from the exact
production-valid epoch-0 empty-authority genesis; at height 24 the test
explicitly installs the corresponding canonical source using the documented
test-only epoch bootstrap, which is not an application operation, Core epoch
transition or production rollover claim. The normal scheduler then refreshes
the cutoff manifest at height 25, commits parent 27, and independently obtains
the same private candidate capability from the production execution used by
`ProcessProposal` and from `FinalizeBlock` at checkpoint 28. The same result is
recomputed after a V3 parent restore, after a real periodic SQLite V4 cutoff-25
restore followed by parent 27, across SQLite restart and projection-cache
miss/hit, and by fresh reconstruction from retained cutoff 25 after checkpoint
commit/restart. A zero checkpoint block hash is rejected with committed head,
pending block and cutoff projection unchanged, including after restart. This
closes the earlier ABCI/cache/restart/restore evidence subcampaign for both
canonical scenarios. A separate targeted SQLite test advances the retained
query floor through the production pruning authority, physically removes
cutoff 25, advances the floor to 26, and proves ProcessProposal rejection,
FinalizeBlock fail-stop, two restart-stable unreadable cutoffs, and unchanged
head/pending/source state.

The bounded H3b2b2 evidence is closed except for two explicitly partitioned
hardening items: a mutation that races cache/restart source state beyond the
already deterministic replay evidence, and an AST/type-aware API-surface gate
stronger than the current source check. The source still uses an explicit
fixture-only epoch bootstrap because production Core activation cannot perform
the required configuration/usage rollover. The production join also does not yet consume the
B2-H1 finalized cutoff-header capability, proof ID or cutoff block ID, so only
application-authenticated candidate/fallback reconstruction is implemented.
Complete finalized-cutoff authority, `NextEpochCommitmentV0`, field 12,
fields 13/14, handoff, activation, production cross-epoch prune and the atomic
Core epoch transition remain open.

### B2-H3b2b3 finalized cutoff, commitment, handoff and activation bridge (private H3b2b3a/H3b2b3b kernels and checkpoint-only preparation sidecar landed; production composition remains open)

The next same-version production bridge is four ordered authority boundaries,
not a wrapper around the H3b2b2 capability:

1. **H3b2b3a — finalized cutoff plus candidate to derived commitment.** The
   crate-private pure bridge has landed. One call exact-decodes the raw parent
   header, binds its ID/time/context to the strictly verified ordinary parent
   QC and finalized child, fresh-verifies raw B2-H1 with hard-coded strict
   crypto, fresh-verifies H2, joins their block/root/manifest/count tuple to the
   H3b2b2 cutoff, and derives every `NextEpochCommitmentV0` field from
   authenticated old configuration and the private candidate outcome. Caller
   timestamps, commitment fields, new configuration, fallback, activation,
   generic verifiers and old inert tokens are forbidden. This test-level
   capability now has two domain-separated forms: the original
   post-execution consistency witness and a cutoff-only pre-header witness.
   Both derive the same commitment from the same raw H1/H2 facts. Neither is
   yet reachable from a production block-building host or persisted across the
   two seal blocks.
2. **H3b2b3b — checkpoint/two-seal/B2-F authority.** Raw checkpoint, two seal,
   terminal-QC and old/new handoff evidence are fresh-verified under strict
   crypto and joined to the derived commitment. The crate-private verification
   boundary has landed. Runtime receipts retain the exact `u128` fee and
   ordered events; native payload/receipt roots are derived independently of
   `ExecTxResult`; and a checkpoint-specific body validator binds all four
   native roots. The pre-header path now retains the complete certified
   height-27 H1 grandchild and accepts only an opaque execution-provenance
   token bound to the authenticated parent/root and post-state root. Its
   two-phase prepare/bind capability places the cutoff-only commitment before
   computing the exact native `BlockHeader::id()`. The subsequent raw wrapper
   exact-decodes the checkpoint parent, checkpoint/two-seal finality and anchor
   kernel, hard-codes strict Ed25519, structurally joins seal 2 to the terminal
   header/QC, and re-runs B2-F. A dedicated same-chain checkpoint-28 vector
   covers reason 0 and authenticated reason 3; its result seal is application-
   private and is not an aggregate protocol proof. It deliberately contains no
   Comet hash. The independent Node consumer recomputes H3a/H2 ICS23, every
   native private seal, strict B2-E/B2-F, descriptor/certificate, and both
   old/new role signatures and quorums. A separate application-private SQLite
   sidecar now durably reserves and binds checkpoint preparations. It is
   independent of the application store, JMT, ABCI snapshots and state-sync
   replacement; configures WAL plus `synchronous=FULL`; and performs mutations
   with `BEGIN IMMEDIATE`. One immutable transition binding is shared by slots
   keyed as `(transition, checkpoint kind, height, view)`. Exact reserve/bind
   replay is idempotent, while a changed transition binding or second value for
   an occupied slot sets a process-sticky halt and, when storage remains
   available, records that halt durably. Stored replay bytes are inert
   comparison material and never recreate an opaque authority. The
   crate-private reserve/bind wrappers return durable checkpoint capabilities
   only after the sidecar transaction succeeds; the focused Rust suite covers
   same-process reopen idempotence, same-slot and binding conflicts, higher-view retry,
   bound-header conflict, corrupt/future schema, failed halt persistence and
   path independence. This is not process-restart evidence; cross-process
   coordination and whole-file rollback detection still require an external
   signer/journal watermark. This is checkpoint-only preparation safety state: it is
   not wired into ABCI startup or a production block-building host, it does not
   cover seal 1 or seal 2, and it is not the validator/signer
   persist-before-sign journal. Remaining boundaries are production
   host/carrier and sidecar-lifecycle integration, seal preparation and live
   proposal/vote plumbing, a signer-co-located persist-before-sign journal,
   and a non-empty shared receipt vector. A Comet header hash is
   neither a complete Comet `BlockID` nor a native PoCO `BlockId`; any future
   adapter must bind two strong types from complete host evidence rather than
   compare their 32-byte values. Application-local checkpoint roots cannot be
   silently substituted.
3. **H3b2b3c — field 13 and live activation.** The first new-epoch proposal is
   authorized from the private joint-handoff result, exact seal-2 parent,
   activation height, new configuration, leader/signature, anchor and body/
   receipt/state execution. Persisting this authority precedes the atomic Core
   safety/configuration rollover and any new-set vote or timeout signature.
4. **H3b2b3d — field 14 finality completion.** After field 13 activates the new
   set, strict new-epoch three-chain finality binds field 13 and authenticated
   ancestry for the light-client/handoff completion object. Field 14 cannot be
   a prerequisite for live activation: the new set must first activate before
   it can produce that finality proof.

The field-12 governed-upgrade path remains a separate branch. The same-version
H3b2b3 path fixes protocol v0 and an absent upgrade-plan hash; later field-12
work must bind a complete finalized `UpgradePlanV0` and use a version-changing
composition entry rather than weakening the same-version path.

### P0 blockers

- Resolve every remaining schema/spec/implementation mismatch and publish a
  machine-readable source of truth for all frozen logical objects.
- Extend the closed B2-A/B2-B/B2-C/B2-D/B2-E/B2-F/B2-G/B2-H1/B2-H2/
  B2-H3a/B2-H3b1/B2-H3b2a/B2-H3b2b0/B2-H3b2b1 logical-schema/parser
  source-of-truth contract across the rest of B2. The real-Ed25519 unequal-weight
  B1 corpus and ordinary
  certificate-kernel parser rejection, narrow anchor/handoff kernel, inert
  next-epoch commitment kernel, ordinary block-validation kernel, narrow
  old-set checkpoint/two-seal finality kernel, same-version joint-handoff
  composition, and deterministic candidate/fallback/PoP computation are
  closed, but complete checkpoint/epoch Block and proposal
  bodies, epoch-anchor/activation authority, the remaining production campaign
  and production-host integration for the landed B2-H1/commitment/checkpoint-
  handoff joins, `EpochHandoffProof` fields 12--14 and
  remaining epoch/upgrade objects, non-DoubleVote evidence,
  network-envelope admission, and same-/cross-epoch
  light-client vectors plus independent reproduction of that remaining corpus
  remain release-blocking.
- Deepen formal coverage from the present 4-/7-node weighted kernels,
  heterogeneous TC selection, one-shot partition/heal, persist-before-sign,
  joint handoff, upgrade atomicity, application cross-entry/prune atomicity,
  weight snapshots, and trusting-period boundary models to all persistence
  crash points, repeated/adversarial
  partitions, multiple skipped anchor views, weighted anchor timeouts, complete
  fallback construction, and multi-hop light-client transitions. Retain and
  expand the failing-mutant suite.
- Obtain independent consensus-engineer review. Economic constants and slash
  policy remain non-production and separately block P3 activation.

## P1 critical path

1. Align Rust protocol types and canonical digests byte-for-byte with P0.
2. Keep the core free of network, database, filesystem, clock, randomness, and
   signer side effects.
3. Enforce `PersistDecision -> StorageAck -> RequestSignature ->
   SignatureReady -> Broadcast`; no error path may skip the durable boundary.
4. Complete and harden proposal validation, leader schedule, safe vote,
   weighted QC, heterogeneous-high-QC TC, monotonic lock/high-QC, direct
   three-chain commit, double-sign evidence, epoch checkpoint/seals/handoff,
   and crash recovery; the epoch transition and full evidence surface remain
   unimplemented.
5. Complete the present three-result callback scaffold with canonical
   body/evidence/authenticated-context inputs, durable terminal facts and
   certified-sync obligations; freeze the active runtime's deterministic
   transaction-failure predicate and never let a driver invent failed-receipt
   versus block-invalid semantics.
6. Expand the existing deterministic fault simulator into the complete
   canonical replay corpus. The current 22-test epoch-0 scaffold covers
   consumed loss/duplication/delay/reorder faults, quorum-loss stalls,
   partition/heal, equivocation evidence, durable conflicting-QC halt,
   pre-ack crash rollback, one nonzero-state safety replay, and cross-layer
   finality comparison. It also drives scripted `Valid`, `Unavailable`, and
   `DeterministicallyInvalid` callbacks, including retry/replay/halt recovery,
   plus standalone QC-before-proposal catch-up across crash/recovery. Its
   ordinary `Valid` path now mints and returns the real B2-D commitment token,
   including a wrong-block callback regression which cannot consume the exact
   request generation.
   P1 still requires a self-contained trace decoder/replay API, real
   multi-source body/runtime validation, the remaining persist/sign/broadcast
   crash points, stale disk/signer disagreement, heterogeneous certificate
   races, unequal weights, epoch-transition scenarios, and checkpoint-backed
   ancestry recovery beyond `max_blocks` without the global in-memory archive.

The direct standalone-QC, proposal-carried ordinary-QC, direct full-TC, and
first-arrival proposal-carried full-TC paths now share a persist-before-request
missing-data contract. A standalone active target is immutable, newer
non-conflicting QCs enter a bounded canonical backlog, a complete TC retains
all ordinary references rather than only its selected maximum, and recovery
re-verifies/reissues the exact active certificate after any required safety
replay or TC-priority work before rotating one item at a time. Same-view
conflicts halt before finalized subsumption; a different-view competitor at the
durable finalized height is a no-op, except that an independently valid TC may
advance only its authenticated timeout view. The remaining catch-up blockers
are distances beyond `max_blocks`, which require trusted checkpoint/state sync,
and complete ordered ancestor-finalization delivery instead of exposing only
the latest coalesced proof.

Preauthentication and shared payload storage close the clone-amplification
path, but handlers still repeat cryptographic verification. The Rust
trichotomy enum/effect state machine is now present, including bounded
durable terminal collision handling and referenced-invalid halts. It is not
P1-complete: the terminal-fact cache is bounded rather than a permanent
execution log, and the effect does not yet carry a full canonical
body/runtime/parent-state context or a frozen runtime failure predicate.

An eager terminal `Valid` callback received while durable finalization is
pending now retains one bounded, exact, already-authenticated current-view
proposal. In the same incarnation, `FinalizationApplied` re-verifies its
leader, signature, parent timestamp, ancestry, lock, vote watermark, and
durable terminal fact, then atomically clears the finalization outbox and
persists the vote intent; only the following storage acknowledgement releases
the signing request. Recovery from that new durable state resumes the exact
signing root. A crash before that atomic write deliberately does not reconstruct
the volatile proposal from a terminal fact alone: canonical body, parent state,
and frozen runtime context must be replayed before any retry. P1 therefore no
longer depends on leader/network retransmission in the uninterrupted path, but
the durable cross-crash body/context replay contract remains open. This narrow
retry slot is specific to the finalization outbox; a `Valid` result blocked by
a timeout-signing or another durable outbox still requires authenticated local
proposal replay after that outbox clears.

The historical observed-QC cache used to pair same-view conflicts is bounded
and volatile. A finalized-subsumed QC retained only there is not evidence-
continuous across a crash; the certificate must be replayed to reconstruct the
pair. This does not roll back durable finality or signing state, but it blocks
claims of permanent cross-crash conflict evidence and audit continuity.

P1 output is a library and simulator, not a locally running service.

## P2 remote validation ladder

P2 begins only after the safety types/core gates are green. Build immutable
artifacts locally, checksum them, transfer them to X230, and deploy remotely.

1. One-node storage/signer recovery fixture.
2. Four-node authenticated fixture: one crash/Byzantine-equivalent tolerance.
3. Seven-node fixture: two crash/offline/equivocating participants.
4. Partition campaigns: quorum/minority, non-quorum splits, delayed/reordered
   traffic, heal, catch-up, stale-state rejection, corrupt/incomplete chunks.
5. Runtime/JMT equivalence against the CometBFT oracle, including speculative
   overlays for multiple unfinalized blocks.

Every run records immutable evidence on the remote host. Expected stalls under
quorum loss are acceptable; conflicting finality, journal rollback, or root
divergence is a zero-tolerance failure.

## P3 staged activation

Consumption Certificates and weights enter `shadow` first. The reference
profile has `production_activation = false` and forbids leaving shadow.
Eligibility-only, capped-weight, and full-weight activation each require a
finalized epoch-boundary decision, the minimum observation window, deterministic
snapshot/fallback evidence, anti-reciprocal-consumption analysis, bond coverage,
and the applicable external review. Promotion is never automatic.

## P4 public gate

The public ladder expands 7→20 nodes across regions and providers. It includes
data-availability withholding, disk-full/slow disk, OOM/CPU/file-descriptor
pressure, network flood/delay/reorder/partition, signer outage/replay, sync
poisoning, and operator-error drills. The final gate requires a continuous
7–30 day soak, independent light-client implementation, and external consensus,
cryptography, and economic audits.

No throughput number, uptime percentage, or soak duration overrides a failed
safety invariant or unresolved protocol ambiguity.
