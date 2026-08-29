# ICR-G1-R3-A04-001 — authenticated positive-height application parent

Status: **proposed** (routing/acceptance required before implementation)

## Request identity

```text
request_id = ICR-G1-R3-A04-001
requester_agent = A03
requester_package = G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1
owner_agent = A04
owner_package = G1_R4_APPLICATION_FINALITY_V1
created_at = 2026-08-29
```

## Current authority

```text
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface_version = candidate-v0
current_interface = the current process path uses CoreConfig::new with a
                    trusted-genesis parent plus the private native P host's
                    authenticated_application_head binding
current_interface_digest = 2551075bc14fc187f2e5d1bb29b60f87b61c7d175c77859b1d5dd5c7cca02bddba
current_owner = Core/application activation owner (A04 routing required)
```

The digest is the SHA-256 of the exact `sha256sum` lines for
`trillionnium/crates/trnm-consensus-core/src/core.rs` followed by
`trillionnium/crates/trnm-poco-node/src/native_proposal_p_host.rs` in the
candidate base. It is a source snapshot, not an acceptance decision.

## Requested interface

Provide one approved candidate-only handoff that lets an ordinary non-empty
Proposal begin from an authenticated positive-height application parent. The
handoff may be a Core-owned activation constructor or an A04-owned
positive-height application-prefix bundle, but it must bind, in one opaque
non-cloneable capability:

- chain id, genesis hash, protocol/version and runtime-profile digest;
- exact parent header/block id, height, timestamp, JMT/state root and overlay;
- active validator-set id and consensus-parameter hash;
- authenticated Safety predecessor/revision and Core instance affinity; and
- the native application's durable head/readback identity.

It must support a real non-empty ordinary h1 (or an explicitly approved
positive-height successor), reject a header-less trusted-genesis parent for
native execution, and preserve the existing Core-owned application-seal and
SafetyRules authority boundaries. It must not expose a caller-selected root,
receipt, finality proof, signer, or application-commit authority.

## Rationale, safety, and compatibility

The current effect-driver process path uses plain `CoreConfig::new` and thus
starts with a header-less trusted-genesis parent, while the existing offline
h1 bootstrap is limited to a synced empty-prefix successor. Consequently the
native P host correctly marks this generic process parent incomplete and
refuses P→D. A03 cannot repair this by changing `core.rs`, fabricating a JMT
root, or importing A04/A05 state. (Core has a separate commissioning-only
authenticated-parent constructor; no accepted process handoff currently
supplies it.)

```text
new_authority_created = false
production_reachability_changed = false
signing_or_settlement_authority_changed = false
serialization_boundary_changed = false
```

The interface is additive and candidate-only. Existing trusted-genesis callers
must remain fail-closed; callers using an unaccepted or mismatched prefix must
be rejected explicitly.

### Frozen capability details

```text
semantic_version = 1 (candidate additive handoff)
canonical_domain = trnm.consensus.application-parent-activation.v1
canonical_bytes = exact parent header, block id, JMT/state root, overlay,
                  chain/genesis/version, validator-set/parameter/profile and
                  authenticated Safety/native-head bindings
issuer = approved Core/application activation owner (A04 routing required)
caller_authority = A03 consumes only an opaque, live-owner-affined capability
linearity = non-Clone, non-Serialize, private constructor, one successor
bounds = one positive-height prefix; fixed header/body/evidence limits;
         no arbitrary caller-selected roots or finality receipts
exact_errors = ParentUnavailable | ParentBindingMismatch |
               RuntimeProfileMismatch | SafetyAffinityMismatch |
               CommitAmbiguous (all fail closed)
compatibility = trusted-genesis ordinary callers remain fail-closed; an
                 unaccepted prefix cannot be used as a fallback
```

## Required vectors and invalidation

Positive: one canonical non-empty transaction at the first admitted ordinary
height, exact native preview/execute roots, P readback, Core D, and same-owner
AuthorityVote.

Negative/fault: parent block/state/JMT/overlay mutation; chain/genesis,
validator-set, parameter, protocol, profile, timestamp, and height mismatch;
foreign Core/application authority; duplicate prefix; response loss and
restart before/after P and D; stale Safety revision; and any attempt to enter
finality or application apply through this interface.

Acceptance invalidates A03's current process-parent and native positive-path
evidence, plus dependent R4/A06 vectors. A03 will regenerate all hashes and
rerun the full negative/fault/replay set after independent review.

### Required evidence (before acceptance)

```text
positive_vectors = canonical non-empty transaction at an authenticated
                    positive height; exact native preview/execute/P readback
negative_mutants = parent/header/JMT/overlay/chain/genesis/version/set/params/
                   profile/timestamp/height and foreign-authority substitutions
fault_matrix = response loss and SIGKILL before/after parent handoff, P, D,
               and restart; duplicate-prefix and stale-Safety revisions
exact_commands = source-bound Core/application tests, process tests, and
                 independent replay commands with artifact hashes
independent_replay = required by A06 and a reviewer outside A03/A04; pending
```

## Review decision

```text
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = pending
accepted_interface_digest = pending
source_commit = pending
source_tree = pending
notes = request routes the missing Core/application activation boundary; A03 does not edit it
```
