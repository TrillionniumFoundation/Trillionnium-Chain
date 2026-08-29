# G1-R4C Safety/checkpoint interface-change requests v1

Status: **PROPOSED / BLOCKED_UPSTREAM / candidate-only**

This file freezes the smallest interfaces that A05 needs from A03, A04, the
whole-node authority owner, and the remote-signer custody owner. It is a
request ledger, not an implementation or an authority grant. No request in
this file changes a production, activation, release, or normative-freeze
flag.

## Common source tuple

```text
repository = TrillionniumFoundation/Trillionnium-Chain
candidate_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
candidate_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
candidate_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
assessed_plan_ref = refs/heads/docs/chain-poco-bft-mainline-20260825
assessed_plan_commit = 8198fea0307eb368df34ff77ffc272a6b0e655ec
assessed_plan_tree = a1be71bba1b54c428493d186fafb656d081b31a9
observed_plan_tip = 92449b8e101642f39d644d863db7bb60dea488f7
observed_plan_tree = cf8f1ab4f5065cb0551a30ec0e036cd44cb31766
observed_main_tip = b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
observed_main_tree = ffbad926850a12159336126390271abffc1d99a6
embedded_snapshot_main = e73d1a930991f0e308bf72854b334b6191c7fcc3 # historical control snapshot
release_truth_path = RELEASE_READINESS.md
release_truth_sha256 = 1659693f0662f8a19b526c602379fe9fa54626afefe33d35917983f699f2dfa4
live_scan_at_utc = 2026-08-29T13:10:49Z
live_scan_result = authenticated connector scan found PR22 at 4936caeba16656dd196e95a60dc7455d9cca43d3/tree 056e32bf9a62fbd8e55e0439a36fa5a224138014 and no pre-existing remote A05-owned G1-R4C branch or path overlap (local package branch unpushed); re-scan is required immediately before push and after Draft PR creation
# Complete candidate/control/main and PR7/8/9/20/21/22 commit/tree tuples for
# this scan are recorded in TRNM_G1_R4C_MANIFEST_V1.toml; abbreviated
# references are not used as source truth.
control_docs_ref = refs/heads/docs/agent-fleet-plan-v1-20260829 (assessed alias; see observed_control_docs_*)
control_docs_commit = a3bdc659d42b92574e591ab687d92a6672ec7cc0 (assessed alias)
control_docs_tree = c36032581897d86f2f6b8d295af2b685622f8f90 (assessed alias)
assessed_control_docs_ref = refs/heads/docs/agent-fleet-plan-v1-20260829
assessed_control_docs_commit = a3bdc659d42b92574e591ab687d92a6672ec7cc0
assessed_control_docs_tree = c36032581897d86f2f6b8d295af2b685622f8f90
observed_control_docs_ref = refs/heads/docs/agent-fleet-plan-v1-20260829
observed_control_docs_commit = 8bfd73f0cf1b785a29ae212f13212e51fe34231e
observed_control_docs_tip = 8bfd73f0cf1b785a29ae212f13212e51fe34231e
observed_control_docs_tree = cfedd363147934f50d1352dae31b7d87d79aa8d9
assessed_control_contract_sha256 = 54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e
observed_control_contract_sha256 = 54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e
assessed_registry_sha256 = c43a8470def968f78676787b1220b1f9a1d5faa53ec93137f73a9a71fbeb43a8
observed_registry_sha256 = cafffe3c45c32a838485a4e6502ccb25b5a5a15245a6d6893f981905ff8d24a3
observed_active_pr_ledger_sha256 = 374fe528e57152fcb9aebab21810adfa907d2d6314c3018d2da23bec357ddb01
assessed_plan_content_sha256 = 3e0fade83c72c9a8ee16efd94f4f2605057610dac8abb1f8b6a71b844038be03
observed_plan_content_sha256 = aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd
parent_r4_contract_commit = 0e059c1c3d96d75f3fa301a8219de6b987a551d3
parent_r4_contract_tree = 59c78557fb6dab482288fc72751fdaa697891960
parent_r4_contract_sha256 = e370a9ad10e67f2bc11e35768fa11949ea1291eac017355558c20006c721d0d3
```

Each `current_interface_digest` below is the SHA-256 of the complete UTF-8
bytes of the named source file at `base_commit` (computed with
`sha256sum <path>`). It is an observed source-file digest, not a normalized
API-extraction digest; owners must publish a canonical interface extraction
and a new accepted digest before implementation. `normative_freeze=false` is
the assessed plan/machine-truth state, and `release_ready=false` is the state
recorded by `RELEASE_READINESS.md`; neither is changed here.

The current remote plan branch has a later tip
(`92449b8e101642f39d644d863db7bb60dea488f7`), but the manifest and machine
truth pin the assessed commit above. The later tip is recorded, not
substituted. `assessed_plan_content_sha256` is the hash of the assessed Plan
file; `observed_plan_content_sha256` is the hash of the Plan bytes at the
observed plan tip (the same canonical blob is present on the candidate) and is
recorded separately. The default `main` tip is separately
observed as `b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`; it is not the A05
candidate base. The control-tip snapshot's embedded
`default_branch_head_observed=e73d1a930991f0e308bf72854b334b6191c7fcc3` is
historical and is not substituted for the live main observation.

The control-docs ref moved after the assessed snapshot. The contract bytes
remain identical, while the registry bytes changed because A00/A01 ownership
of `CURRENT_SNAPSHOT_V1.*` and its checker was resolved; the A05 registry
entry and its owned/forbidden surfaces are unchanged. The active PR ledger
blob is observed at the live tip with SHA256
`374fe528e57152fcb9aebab21810adfa907d2d6314c3018d2da23bec357ddb01`; its
embedded source-head tuple is historical metadata. A live authenticated PR scan
supersedes that inventory snapshot. This is recorded as control-plane drift and
revalidated for A05 scope; it is not silently substituted for the assessed
authority snapshot. Any prior control-tip/registry/inventory evidence is
invalidated and must be regenerated from the observed tip.

## ICR-A03-001 — Safety admission bound to the checkpoint

```text
request_id = G1-R4C-ICR-A03-SAFETY-ADMISSION-CHECKPOINT-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A03
owner_package = G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = CoreSafetyRulesAuthorityV1
current_interface_version = candidate-v1
current_interface_digest = 8e5151b4dc99e19d95d0526968c182a062d4a3493b514ce968d6a9fe912ca4b3
current_interface_source = trillionnium/crates/trnm-consensus-core/src/core.rs
related_interface = SafetyRulesDurableTransitionStoreV1
related_interface_source = trillionnium/crates/trnm-consensus-safety-rules/src/authority.rs
related_interface_digest = d4dd7c21b99076a9f39bc019ba4785dd892215e1806f08b7d8a6711d5c7bff6b
current_owner = A03 / trnm-consensus-core
proposed_interface = "additive non-Clone one-shot SafetySignAdmissionV1 bound to the exact Core/Application/Safety/checkpoint cut"
safety_rationale = "generic signing callback lacks an unforgeable durable cross-store admission"
version_impact = "new versioned capability; existing candidate APIs remain explicitly non-authoritative until migrated"
required_vectors = "Vote and Timeout positives; stale/mixed/foreign/altered/duplicate admission; SIGKILL/I-O/response-loss/restart"
downstream_invalidation = "A04 adapter; A05 signer/checkpoint; A06 fault matrix; A07 campaign; G1 exit; G2F/release evidence"
reviewer = "A00 and A06 (unassigned; required)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "awaiting owner acceptance; no implementation authority granted"
```

### Requested interface

Add an additive, non-`Clone` `SafetySignAdmissionV1` (or an equivalent
versioned capability) issued only after the real SafetyStore has durably
persisted and freshly read back the exact transition and the whole-node
authority has accepted the exact predecessor. The capability must be
consumed exactly once by the signer boundary.

The canonical fields and domain must bind, at minimum:

- chain/genesis, epoch, validator-set and purpose profile;
- Core process/owner affinity and the exact predecessor and successor Safety
  revisions;
- transition digest, canonical intent fingerprint, signing root, operation
  kind, and (for Vote) the authenticated application-validation statement;
- whole-node scope, predecessor checksum, target generation and external
  anchor version;
- a bounded request nonce and an idempotency key.

The issuer must be the one Core/Safety owner. The value must be linear and
non-`Clone`; raw `CanonicalSignIntentV0` is not a substitute. Bounds are one
operation per capability, 32-byte digests, `u64` revisions/nonces, and the
existing consensus message/intent limits. Errors must distinguish stale or
mixed cuts, owner/process mismatch, external-anchor unavailability, duplicate
consumption, and uncertain commit. A response-loss retry may return only the
same durable admission or a typed permanent quarantine.

Required vectors and faults: exact Vote and Timeout positives; lower/equal
Safety revision; same-view/different-block; wrong validator/profile; foreign
Core owner; altered intent/root; missing or mismatched application statement;
stale/forked checkpoint; duplicate nonce; signer-before-admission; SIGKILL,
I/O failure, response loss, and restart between Safety readback, checkpoint
CAS, and capability consumption.

### Rationale and safety analysis

The current authority persists a candidate and then calls a generic signing
adapter. It does not carry an unforgeable proof that Application, Safety,
Signer, and the external checkpoint observed one cut. A05 cannot add this
proof by editing A03's Core owner. This request does not create production
authority until A03, A04, the checkpoint owner, and an independent reviewer
accept the exact version and digest.

```text
new_authority_created = false
production_reachability_changed = false
signing_or_settlement_authority_changed = true (if accepted; currently false)
serialization_boundary_changed = true (if accepted; currently false)
```

### Evidence and invalidation

```text
positive_vectors = exact Vote + Timeout admission and one idempotent retry
negative_mutants = stale/mixed/foreign/duplicate/altered admission cases
fault_matrix = Safety fsync/readback, checkpoint CAS, signer consume, SIGKILL, I/O, response-loss, restart
exact_commands = bash scripts/project-preflight.sh --dev; pinned X230 cargo fmt/test/clippy commands
independent_replay = required in A06 after acceptance
downstream_invalidation = A04 finalization adapter; A05 signer/checkpoint adapters; A06 fault matrix; A07 campaign; G1 exit; G2F and release evidence
```

## ICR-A04-001 — Application finalization readback and CAS binding

```text
request_id = G1-R4C-ICR-A04-APPLICATION-FINALIZATION-CAS-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A04
owner_package = G1_R4_APPLICATION_FINALITY_V1
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = NativeApplicationV0 and NativeApplicationCommitResultV0
current_interface_version = candidate-v0
current_interface_digest = 2b9eba5fdc9d6c64f8443de8b730b4b1122b7e30e931802ee654a1f4fada98f7
current_interface_source = trillionnium/crates/trnm-native-application/src/application.rs
current_owner = A04 / trnm-native-application
proposed_interface = "versioned finalization permit bridge returning a non-Clone exact application/JMT/queue readback capability"
safety_rationale = "A05 cannot prove application commit, fresh JMT readback, and queue CAS through the current data-only trait"
version_impact = "new host/adapter boundary; NativeApplicationV0 serialization and ownership remain unchanged"
required_vectors = "ascending ancestors; duplicate/fork/root/parent/receipt/queue/store mutations; SIGKILL/I-O/disk-full/torn-write/response-loss/restart"
downstream_invalidation = "A05 tag-3/checkpoint admission; A06 matrix; A07 campaign; G1/G2F/release evidence"
reviewer = "A00 and A06 (unassigned; required)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "awaiting owner acceptance; no implementation authority granted"
```

### Requested interface

Add a versioned host/adapter bridge (outside the dependency-free
`NativeApplicationV0` trait if necessary) that consumes one exact Core
finalization permit and returns a non-`Clone` application readback capability.
The readback must contain the canonical application JMT root, committed
block/height/view, finalization queue identity, receipt/overlay commitment,
application-store identity, and the exact Safety predecessor/checkpoint
binding. It must expose explicit outcomes for applied, exact idempotent retry,
commit-uncertain, and permanent rejection.

One transaction must make the application commit and its durable readback
visible before A05 can request tag-3 Safety persistence. A response-loss retry
accepts only the exact same idempotency key and target; a different root,
parent, queue front, or store identity fails closed. Bounds are the existing
application/JMT and record limits, one ancestor per operation, and the existing
bounded receipt count. The bridge must not expose mutable JMT objects or permit
a caller-supplied AppHash.

Required vectors and faults: ascending multi-block ancestors; duplicate and
losing-fork applies; wrong parent/JMT/receipt; stale queue head; app-store
replacement; SIGKILL before/after commit and readback; disk-full/I/O/torn
write; response loss and exact retry; restart with an incomplete marker.

### Rationale and safety analysis

`NativeApplicationV0` currently offers initialize/execute/commit/state-proof/
snapshot/recover. The candidate host helpers are private and do not form a
process-wide atomic boundary with Safety, Signer, or the external checkpoint.
A05 must not mutate ApplicationStore/JMT ownership.

```text
new_authority_created = true (if accepted; currently false)
production_reachability_changed = true (if accepted; currently false)
signing_or_settlement_authority_changed = false
serialization_boundary_changed = true (versioned bridge only)
```

### Evidence and invalidation

```text
positive_vectors = one exact finalization permit, one exact retry, two ascending blocks
negative_mutants = root/parent/receipt/queue/store-identity substitutions and duplicate apply
fault_matrix = application transaction/readback/queue-ack cuts under SIGKILL, I/O, disk-full, torn-write, response-loss, restart
exact_commands = pinned X230 package and process-matrix commands from A04/A06
independent_replay = required from a clean clone by A06
downstream_invalidation = A05 tag-3/checkpoint admission; A06 matrix; A07 campaign; G1/G2F/release evidence
```

## ICR-ANCHOR-001 — Independent whole-node anti-rollback anchor

```text
request_id = G1-R4C-ICR-WHOLE-NODE-EXTERNAL-ANCHOR-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A00 (authority designation) / A05 (candidate adapter)
owner_package = CONTROL / G1_R4_SAFETY_CHECKPOINT_V1
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = ExternalNodeCheckpointStoreV0 and ExternalMonotonicWatermarkV0
current_interface_version = candidate-v0
current_interface_digest = cf47b1851fb742d649543d88624f8188d9eb74d64f8b78c9f2164d74d0cd244f
current_interface_source = trillionnium/crates/trnm-consensus-external-node-checkpoint/src/lib.rs
current_owner = A05 local candidate; independent authority owner not designated
proposed_interface = "independent process-scoped monotonic anchor with exact successor CAS and durable target/source/third-state readback"
safety_rationale = "a local journal and local anchor can be restored together, so local CAS is not coherent anti-rollback authority"
version_impact = "new externally authenticated anchor protocol; data-only checkpoint types remain authority-free"
required_vectors = "lower/equal/foreign/stale/forked predecessor; copied/renamed namespace; coherent rollback; torn/WAL/anchor outage/response-loss/SIGKILL/restart"
downstream_invalidation = "A05 admission/signing; A06 fault matrix; A07 network; G1-S03; G2F/light-client/release evidence"
reviewer = "A00 (authority designation) and A06 (unassigned; required)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "authority owner is not designated; local adapter remains candidate-only"
```

### Requested interface

Designate one process-scoped whole-node CAS authority with a monotonic anchor
outside every rollbackable Application/Safety/Signer database and sidecar. The
request/response must bind the immutable namespace identity, chain/profile,
generation, predecessor checksum, target checksum, Safety revision, signer
watermark, application root/receipt, and anchor sequence. The anchor must
support exact `load` and successor-only `compare_and_advance`, with durable
readback and a distinct ambiguous/third-state error. Replacing, copying,
renaming, or restoring the local journal plus anchor together must be detected
before authority use; an operator-retained checksum is not sufficient.

The implementation owner must be an independently authenticated service,
HSM/KMS, or quorum. A local file-backed anchor may remain a test double only.
The data-only `trnm-whole-node-checkpoint-types` crate must remain authority-
free. Bounds are one successor per operation, monotonic `u64` generation/
sequence, fixed 32-byte checksums, and existing checkpoint byte limits.

Required vectors and faults: lower/equal target; foreign scope; stale/forked
predecessor; copied/renamed journal, lock, anchor, or namespace; coherent
record+anchor rollback; torn/WAL/SHM rollback; anchor outage; CAS commit with
lost response; SIGKILL and restart at every CAS edge.

### Rationale and safety analysis

The current external watermark and checkpoint daemons provide local hash-chain
and CAS tests, but their log and anchor can be restored as one coherent old
namespace. This is the explicit G1-S03/G2F hard-authority gap.

```text
new_authority_created = true (if accepted; currently false)
production_reachability_changed = true (if accepted; currently false)
signing_or_settlement_authority_changed = true (if accepted; currently false)
serialization_boundary_changed = true (versioned wire; currently false)
```

### Evidence and invalidation

```text
positive_vectors = exact source->successor CAS and exact target readback
negative_mutants = all rollback/identity/stale/fork/third-state cases above
fault_matrix = external anchor/CAS SIGKILL, I/O, response-loss, restart and namespace restoration
exact_commands = pinned X230 external-watermark and external-node-checkpoint suites
independent_replay = required from a second implementation and clean clone
downstream_invalidation = A05 admission/signing; A06 fault matrix; A07 network; G1-S03/G2F/light-client/release evidence
```

## ICR-SIGNER-001 — Remote signer admission and HSM/KMS custody

```text
request_id = G1-R4C-ICR-REMOTE-SIGNER-CUSTODY-ADMISSION-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A00 / remote-signer service owner
owner_package = CONTROL / remote-signer protocol-service
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = RemoteSignerRequestV1 plus SqliteSignerJournalV0::sign_exact_v0
current_interface_version = candidate-v1
current_interface_digest = 32189e49825fe9c8fbed72a23e7d89ff6e4912a76ab3e1302f02ff6a5541173e
current_interface_source = trillionnium/crates/trnm-consensus-remote-signer-protocol/src/lib.rs
current_owner = remote-signer protocol/service owner
proposed_interface = "versioned remote-signer request carrying opaque one-shot Safety admission, checkpoint witness, and HSM/KMS custody result"
safety_rationale = "the current wire is data-only and the service fixture path cannot establish production custody or cross-store ordering"
version_impact = "new versioned request/response and custody adapter; existing fixture remains test-only and rejects production authority"
required_vectors = "Vote/Timeout positives; missing/stale/mixed/duplicate admission; raw-key/default-node; HSM outage/rotation/revocation; remote-timeout from_binding sequence-zero/request-facts offset versus explicit per-reservation mode; SIGKILL/response-loss/I-O/restart/replay"
downstream_invalidation = "A05 sign gate; A06 fault matrix; A07 campaign; G1-S02/G1-S03; G2F/release evidence"
reviewer = "A00 and A06 (unassigned; required)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "awaiting custody owner and upstream admission acceptance"
```

### Requested interface

Extend the request/response only after ICR-A03 and ICR-ANCHOR are accepted:
carry an opaque, non-`Clone` Safety admission, exact whole-node predecessor
and anchor witness, process/lease generation, request nonce, and canonical
intent fingerprint. The service must verify the witness, consume the admission
once, append the intent before invoking an HSM/KMS, append and verify the
signature event, and return a response bound to the same bytes. HSM/KMS key
generation, rotation, revocation, attestation, timeout, and
crash-after-sign-before-event semantics must be explicit. The default node
must never receive or store a raw private key; the existing Ed25519 key remains
a fixture-only test dependency.

Vote and Timeout must share the same admission and journal ordering. Missing,
stale, mixed, duplicate, unavailable, or unverifiable evidence fails closed;
response loss resolves only by exact journal/HSM replay or quarantine. Bounds
are existing wire/message limits, one operation per nonce, and fixed witness
sizes.

Required vectors and faults: Vote/Timeout positives; raw-key/default-node
negative; missing/altered admission; signer/Safety/App skew; duplicate nonce;
HSM unavailable/rotation/revocation; intent-before-producer and event-before-
intent mutants; SIGKILL, response loss, I/O, restart and replay.

### Rationale and safety analysis

The current wire is data-only and the service's external-authority path is
timeout-only with a fixture key. Its production constructor is explicitly
per-reservation (the first request occupies sequence zero with request facts),
while the public `from_binding` constructor defaults to pair mode; this
sequence/genesis mismatch is an unresolved owner contract. A05 cannot make it
a production signer or invent custody semantics locally.

```text
new_authority_created = true (if accepted; currently false)
production_reachability_changed = true (if accepted; currently false)
signing_or_settlement_authority_changed = true (if accepted; currently false)
serialization_boundary_changed = true (versioned request/response; currently false)
```

### Evidence and invalidation

```text
positive_vectors = exact admitted Vote/Timeout plus deterministic replay
negative_mutants = missing/stale/mixed/duplicate admission and raw-key paths
fault_matrix = intent/journal/HSM/signature/response-loss/restart/rotation cuts
exact_commands = pinned X230 remote-signer protocol/service suites
independent_replay = required from an independent signer verifier and clean clone
downstream_invalidation = A05 sign gate; A06 fault matrix; A07 campaign; G1-S02/G1-S03/G2F/release evidence
```

## ICR-A05-001 — Explicit signer-journal lifecycle attestation

```text
request_id = G1-R4C-ICR-A05-SIGNER-JOURNAL-LIFECYCLE-ATTESTATION-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A05
owner_package = G1_R4_SAFETY_CHECKPOINT_V1
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = ExternalMonotonicWatermarkV0::semantic_per_reservation_v0
current_interface_version = candidate-v0
current_interface_digest = 962398ee310a5b14828e2fbebbbeab787b35efdb7c04efd4fffbd443c9031700
current_interface_source = trillionnium/crates/trnm-consensus-signer-journal/src/model.rs
current_owner = A05 / trnm-consensus-signer-journal
proposed_interface = "additive semantic_signer_journal_pair_v0 attestation; default false and unknown lifecycle rejected before pair-journal use"
proposed_interface_digest = "pending normalized owner digest; patched source SHA is recorded after implementation commit"
safety_rationale = "a bool that only reports per-reservation mode cannot distinguish an explicitly paired authority from an adapter that silently inherits the default"
version_impact = "additive trait method; existing opaque authorities are unchanged; semantic adapters must explicitly attest pair lifecycle"
required_vectors = "explicit pair positive with signer_journal_lifecycle_nonce_v0(seq=1,2); per-reservation rejection; omitted/unknown attestation; contradictory pair=true + semantic_mode=false; altered loaded facts; non-genesis direct-predecessor event/checksum/row tamper (content mutation remains an unexecuted mutant); lifecycle-bit TOCTOU and exact replay"
downstream_invalidation = "A05 signer evidence; A06 wrapper/process matrix; A07 campaign; G1-S03/G1 exit/G2F/release evidence"
reviewer = "A00 and A06 (required independent review)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "candidate local freeze; implementation remains non-authoritative until independent review and execution"
```

### Requested interface

Add an explicit, immutable lifecycle attestation to the semantic watermark
trait. `semantic_signer_journal_pair_v0() == true` must be the only accepted
proof that a semantic authority emits the signer journal's odd prepared/even
signed pair. The default is `false`; an omitted or unknown method therefore
fails closed. `semantic_per_reservation_v0() == true` remains incompatible
with the pair lifecycle, and pair=true while semantic mode is false is a
contradictory third state that must also fail closed. The signer loader must
validate the target and non-genesis direct predecessor intent/event/chain checksums and
run the complete semantic journal audit before producer dispatch. The positive
fixture asserts `signer_journal_lifecycle_nonce_v0` for sequence 1 and 2 and
that the values differ. The mode/pair bits must be an immutable lifecycle
snapshot or token captured once at open; independently changing `&self`
reports are not an admissible attestation and any observed TOCTOU fails
closed. This additive seam prevents wrappers from converting an unknown mode
into signing authority.

### Evidence and invalidation

```text
positive_vectors = explicitly attested pair authority completes both CAS records and derives distinct seq1/seq2 lifecycle nonces
negative_mutants = omitted/unknown or contradictory attestation; per-reservation mode; altered facts; non-genesis direct-predecessor checksum/row mutation; lifecycle-bit TOCTOU
fault_matrix = semantic lifecycle attestation, full-journal audit, mode-marker durability, restart, response-loss and wrapper replay
exact_commands = pinned X230 signer-journal and external-watermark suites
independent_replay = required before any semantic signer evidence is accepted
downstream_invalidation = A05 signer evidence; A06 process matrix; A07 campaign; G1/G2F/release evidence
```

## ICR-A06-001 — Lab watermark lifecycle-mode forwarding

```text
request_id = G1-R4C-ICR-A06-LAB-WATERMARK-LIFECYCLE-MODE-V1
requester_agent = A05
requester_package = G1_R4_SAFETY_CHECKPOINT_V1
owner_agent = A06
owner_package = G1_R4_FAULT_MATRIX_V1
created_at = 2026-08-29
status = proposed
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface = LabFileWatermark as ExternalMonotonicWatermarkV0
current_interface_version = candidate-v0
current_interface_digest = a2f5a43911f8809c21d1e13141d52d2dae3a73f4f7ab8671f0d3b729f143099c
current_interface_source = trillionnium/crates/trnm-poco-lab-validator/src/crypto.rs
current_owner = A06 / trnm-poco-lab-validator
proposed_interface = "forward semantic_per_reservation_v0 and semantic_signer_journal_pair_v0 exactly from the wrapped authority and reject unknown lifecycle mode"
safety_rationale = "the wrapper currently forwards semantic facts but its default lifecycle bits can hide an incompatible authority from the signer-pair lifecycle guard"
version_impact = "test/harness adapter contract only; no production semantics or authority is created"
required_vectors = "pair-lifecycle direct and wrapped authorities; per-reservation rejection; altered facts; wrapper restart/SIGKILL/response-loss replay"
downstream_invalidation = "A05 signer-journal semantic evidence; A06 process/fault matrix; A07 campaign; G1-S03/G1 exit/G2F/release evidence"
reviewer = "A00 and A06 independent reviewer (required)"
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = "none"
accepted_interface_digest = "none"
source_commit = "none"
source_tree = "none"
notes = "A05 direct adapter is fail-closed; wrapper remains an unaccepted test/integration path"
```

### Requested interface

`LabFileWatermark` must expose the wrapped authority's lifecycle mode without
defaulting an unknown value to signer-journal-pair compatibility. A wrapped
per-reservation semantic authority must be rejected before journal creation or
producer use, and an unknown/missing bit must return a typed configuration
error. The wrapper must preserve the semantic facts and exact scope/journal
binding across restart and response-loss replay. This is an A06-owned harness
change; A05 must not edit `trnm-poco-lab-validator` directly.

### Evidence and invalidation

```text
positive_vectors = pair-lifecycle wrapper forwards pair=true and per-reservation=false only when explicitly attested
negative_mutants = wrapped per-reservation authority; omitted/unknown lifecycle bit; contradictory pair=true + semantic_mode=false; altered facts
fault_matrix = wrapper SIGKILL, response-loss, restart and external-head replay
exact_commands = pinned X230 A06 process-matrix and clean-clone replay commands
independent_replay = required before any wrapped semantic evidence is accepted
downstream_invalidation = A05 semantic fence evidence; A06 process matrix; A07 campaign; G1/G2F/release evidence
```

## Decision rule

All six requests remain `proposed` and are the reason this A05 run terminates
as `BLOCKED_UPSTREAM`. A05 must not edit the A03/A04/Core/Application or
authority-designation/A06 wrapper surfaces, and no generic callback or fixture
signature can be promoted into a substitute. Once an owner accepts a request,
the owner must publish the exact interface version/digest and invalidate the
listed downstream evidence before A05 resumes.
