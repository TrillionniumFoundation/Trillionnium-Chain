# Post-quantum authority boundary inventory — candidate snapshot v1

This is a **source-bound inventory of known classic cryptographic admission and authorization implementations**, not a declaration that any path is deployed or activated. A path being present in a repository is not proof of current production reachability, and removal of a marker is not proof of post-quantum security. The claim gate always reports `pq_chain_qualified: false`.

The candidate snapshot is based on the exact #593 head `6ec0bc9274cce37a83642686350e4a945daf23f8`; #593 stacks on #591 and ultimately the unqualified research baseline. Every path below is audited against checkout bytes by `scripts/security/pq_claim_gate.py` and is a trigger of `pq-production-claim-gate.yml`. The trust root and caller reachability must still be independently reviewed before any acceptance.

| Scope | Candidate code boundary | Current classic mechanism | PQ migration requirement |
| --- | --- | --- | --- |
| Hepta artifact handoff | `trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs` | `SignedHeptaAdmissionV1` Ed25519 | Require independently pinned V2 ML-DSA authority; refuse V1-as-PQ fallback; prove actual caller uses new gate |
| Cell provider discovery | `trillionnium/crates/trnm-data-availability/src/cell/discovery.rs` | `CellProviderRecordV1` Ed25519 | Independently pinned PQ provider roster/lease; no classic discovery downgrade |
| DA committee, batch author and attestations | `trillionnium/crates/trnm-data-availability/src/types.rs` | `DaCommitteeDescriptorV1`, `DaBatchAuthorV1` and strict Ed25519 verifier | Pin a versioned PQ committee/author/attestor registry and prove full retrieval/acceptance caller graph |
| DA full-range retrieval | `trillionnium/crates/trnm-data-availability/src/retrieval.rs` | Strict Ed25519 requester and responder receipts | Bind independent PQ requester and responder authority, epoch, replay and roster freshness without V1 fallback |
| Node authenticated ingress | `trillionnium/crates/trnm-pon-node/src/ingress.rs` | Development peer allowlist + `verify_hex_strict` from Ed25519 primitive | Record real listener and dispatch authorization; enforce independently owned PQ identities, no legacy fallback |
| Transfer transaction | `trillionnium/crates/trnm-types/src/transfer.rs` | `TransferTx` accepts `ed25519` signature scheme and address derivation | Versioned, domain-separated PQ native transaction, nonce and reorg/rollback ownership rules |
| Native M06 PNX1 application envelope | `trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs` | `prepare` selects PQ2/PQ1 only under their installed profile; otherwise `Envelope` is checked with classical `verify_hex_strict` | Trace selected genesis profile and all ordinary call sites; prove PQ-only selection never accepts PNX1, including restart/reorg/downgrade cases |
| Research command | `trillionnium/crates/trnm-research-protocol/src/command.rs` | `SignedResearchCommandV1` with Ed25519 Nakama/Hepta role | Replace authority-root verification and revoke old authorization at activation epoch |
| Research state authorization | `trillionnium/crates/trnm-research-protocol/src/state.rs` | `ResearchProtocolState::apply` validates `SignedResearchCommandV1` then permits Nakama/Hepta public keys via `self.authorities.authorizes` | Pin an independent PQ authority registry and version/epoch; verify all state apply/handoff callers and refuse old signed commands after PQ activation |
| Agent market task store | `trillionnium/crates/trnm-task-kernel/src/store.rs` | Ed25519 session/controller verification | PQ owner/session binding, replay, provenance and final-use checks on actual dispatch path |
| Bilateral settlement | `trillionnium/crates/trnm-service-settlement/src/engine.rs` | `SIGNATURE_SCHEME_ED25519_V1`, registered bilateral keys | PQ provider+consumer settlement, independent registry, failure/reorg and anti-downgrade tests |
| Release bundle acceptance | `trillionnium/crates/trnm-release-bundle/src/lib.rs` | `ReleaseSignatureVerifierV0` supplied by host; algorithm and signer roster unspecified by trait | Pin release authority and algorithm, independent signer custody, downgrade/revocation/rollout proofs and actual release installer call graph |
| State import and cutover | `trillionnium/crates/trnm-state-import/src/lib.rs` | Host-provided source finality, checkpoint-context and cutover-attestation verifiers | Pin PQ-authorized source finality and cutover quorum, trusted epoch/chain binding, migration reorg refusal and irreversible effect recovery |
| Mempool signed admission | `trillionnium/crates/trnm-mempool/src/typed_admission.rs` | `SignedAdmissionHooks` and `PendingNonceAuthority` supplied by canonical transaction owner | Trace exact host hooks; verify PQ-only and hybrid-AND selection, nonce ownership, reorg, timeout, cancellation and restart without classical fallback |
| DID and capability registry | `trillionnium/crates/trnm-types/src/interop_identity.rs` | `IdentityRegistry` compares supplied actor string with recorded DID controller; no in-method cryptographic actor proof | Verify authenticated caller mapping to independent PQ DID/controller roster, revocation and height/epoch at every capability mutation and bridge execution |

**Not closed by this inventory**: production reachability and all authority callers; governance, upgrade, release and rescue ownership; original classic key custody; hybrid AND-verification transition policy; capacity under invalid ML-DSA inputs; W1 transparent prover/FRI and PQ-128 external security assessment; quantum cheapest-legal PoN attack lower bound and difficulty/chain-selection analysis; external monotonic rollback anchor with independently durable witness roster. A new version must record each owner, last classic fallback, caller and threat model with positive and adversarial evidence.

A test pins every candidate marker to real source bytes. If an implementation changes or disappears, update the inventory only after reviewing the effective new trust root; do not mark the chain qualified on an absent grep match.

## Fail closed on unreviewed authority-source transitions

The standalone `--assert-unqualified` check now rejects a missing or
renamed classical verifier marker with
`unreviewed_classical_authority_boundary_change` (exit 2). Previously, such
an edit could make the known-open finding disappear while leaving the source
path present and the CLI green. This is not proof that the old authority is
gone, that its callers have migrated, or that a new PQ trust root is valid.
Every inventory migration requires an explicit audit of actual call sites,
algorithms, independently pinned keys, downgrade behavior and rollout epoch.
A clean unqualified baseline continues to report `pq_chain_qualified=false`
and exit 0; this guard does not activate production.


## Additional unqualified boundary controls

Child of #597. `types.rs` signs/validates batch authors and DA
committee attestations using the classical `STRICT_ED25519_SCHEME_V1`;
`retrieval.rs` verifies classical requester and responder signatures.
Both are candidate code paths, **not evidence of production exposure**.
The runnable inventory now tracks their source bytes, roles and PR
workflow path changes. Neither path is silently categorized as PQ secure.

The `--assert-unqualified` guard now treats only explicit
`classical_authority` and `unqualified_proof` findings as expected
unqualified baseline observations. **Any newly emitted finding kind is
fatal by default**, including an accidental change of the report's
negative PQ/authority/security assertions. Future audit work must
explicitly review and classify a new kind before it can be ignored.
This guard is not an externally audited PQ trust root or a runtime gate.

## Native M06 and research state owner decisions (additional Gate A coverage)

The previous source-bound inventory missed an **ordinary native M06 admission
decision**, not just an imported Ed25519 helper: `pon_executor::prepare`
checks PQ2 and PQ1 configuration first, but reaches `verify_hex_strict` on
legacy PNX1 when both installed PQ profiles are disabled. The separate
`validate_main_envelope` entry also calls that preparation path.
This is a development-profile fallback, **not evidence of a PQ-mode bypass
or an activated public listener**; qualification requires a concrete
genesis-profile/caller trace and adversarial cross-profile execution.

`ResearchProtocolState::apply` checks the signed
command and then authorizes its Nakama/Hepta signer against a stored
classic public-key roster. Tracking `command.rs` alone was not a complete
trust-root audit, because a separately stored authority set and its caller
are part of the decision. This still does not prove deployed
governance or model FinalUse authority.

The two source paths now trigger the focused claim workflow on both push
and PR, and inherit every known classical-marker positive and single-marker
removal negative test. Gate A remains open until real owner/caller/revision
proof and independently managed PQ identity are established.

## Do not accept a truncated unqualified finding report

The claim-gate assertion now requires **all 11 reviewed classical path+role
observations exactly once**, plus the one W1 `unqualified_proof` observation
at the pinned manifest path. Empty, missing, duplicated, role-swapped or
unexpected findings refuse `--assert-unqualified`. It also checks the
report schema and all four explicit false production flags rather than relying
only on inspector-generated error messages. An independent test snapshot
prevents simultaneously deleting one boundary from the source map and role
map and silently reducing coverage. This validates only a conservative
NO_GO audit report, never a cryptographic PQ authorization decision.

## Delegated governance/control authorities are not PQ roots

The `trnm-governance-guard` library authorizes `set_role`, `execute`
and `emergency_pause` from a caller-provided `&str` and membership sets.
It does **not** authenticate that string cryptographically in the library.
The caller's trusted identity source, epoch, replay protection and actual
entrypoints must be audited before classifying this path as safe, classical-only,
or production reachable. This is an authentication *dependency*, not proof that
an attacker can impersonate an actual deployed governance caller.

The `trnm-control-plane` `LocalPlanGuardV0::evaluate` delegates signature
verification through host-provided `PlanSignatureVerifierV0`. This trait does
not prescribe ML-DSA, a pinned PQ public key, hybrid AND semantics or
reorg-safe recovery. Determine each real host implementation, trust-root
custody and caller reachability; the source alone neither proves nor denies
that a particular host can implement secure PQ verification.

The source-bound gate preserves these **two distinct delegated-authority
findings**, separately from the 11 classic-crypto paths. An absent/renamed
marker, missing/duplicated finding or altered role fails the standalone
`--assert-unqualified` check; positive default output stays explicitly
`pq_chain_qualified=false`. Both source paths trigger the focused workflow
on push and PR. No runtime authority is changed and #562 Gates A–F remain
OPEN / NO_GO until independent caller-root and acceptance evidence exists.


## Release, migration, mempool and DID trust-root dependencies (Gate A increment)

These four additional *delegated* authorization boundaries were observed on
the frozen protected main `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`
and rechecked against this candidate's parent #611 source. They do not
establish production reachability or an exploitable impersonation route.

- Release: `verify_release_bundle_v0` calls host-supplied
  `ReleaseSignatureVerifierV0::verify_release_signature`; digest validation
  does not select ML-DSA or authenticate an external release owner.
- Migration: `verify_export_v0` calls a supplied source-finality verifier;
  `verify_cutover_agreement_v0` calls a supplied cutover signature verifier.
  Source-checkpoint verification is also delegated. A structurally valid
  signed-weight record is not a post-quantum signer roster.
- Mempool: `admit_signed` and `admit_signed_with_pending_nonce` rely on
  host-provided signature/replay implementations. The trait's rejecting
  default is useful but cannot attest the actual installed hook or persistent
  nonce owner.
- Identity: `IdentityRegistry` checks a caller-provided actor identifier
  against DID controller strings; the host must prove that the actor was
  authenticated and that capability/revocation/bridge effects honor the
  independent PQ trust root.

The focused gate now keeps six delegated path/role findings, including the
original governance/plan checks. Removing or changing any pinned source
marker or removing/duplicating its finding must fail --assert-unqualified.
Workflow path filters cover all four paths on both push and PR.

**Unclosed:** real ingress-to-host implementation trace, independent PQ key
provisioning, versioned epoch and anti-downgrade policy, signature-size and
failure-load limits, reorg/cold recovery, external-operator evidence. This
is a source-bound *inventory/negative-claim* improvement, not an enabled
signature verification policy, native test, production release or whole-chain
PQ128 qualification. #562 Gates A-F remain NO-GO.


## Source-byte freeze for all seventeen reviewed authority paths (follow-on)

The previous boundary audit matched representative Rust strings, so changing
an authentication call or its surrounding control flow while keeping all old
markers could still produce the accepted unqualified baseline. Source-string
presence is not itself a source review. At the **exact** parent #613 HEAD
`298f09505bebbf1b7befcd725a1b90e04c15548b`, 11 classical and six
injected/delegated authority files are now pinned by raw-source SHA-256 in
`scripts/security/pq_claim_gate.py`. Any changed bytes (including a refactor
or a retained-marker comment-only edit) produce
`unreviewed_authority_source_digest_change`; the standalone
`--assert-unqualified` must refuse them until explicit re-audit and repinning.

The negative suite independently checks all checked-out source SHA-256 bytes,
mutation of each source with markers preserved, genuine CLI rejection, and
restoration of the previously accepted **NO_GO** baseline. Pinned file digests
are neither a PQ cryptographic authority nor proof that their callers are
reachable, safe, or installed in a binary. This does not replace source-to-binary
reproducibility, quantum-work bounds, externally operated rollback anchors,
W1 qualification, or any of #562 Gates A–F. A signature-policy or runtime
change still requires positive and adversarial tests before deployment.

## Exported relay callback and public test-signature compatibility boundary (follow-on)

The audited `trillionnium/crates/trnm-types/src/lib.rs` publicly re-exports
`RelayAuthEnvelope` and `RelayAuthVerifier` from
`trillionnium/crates/trnm-types/src/relay.rs`. On parent #615
`9d83890975bdf29ab4818b248e0dea9f6d516e45`, the exact exported source
has SHA-256
`610bba86023958c903e82e4bdff654297edf72be99bd9a5f8aee8f2f78357672`.
The separately present `src/relay/{verifier,auth_envelope}.rs` files are not
imported by the exported `relay.rs` module and must not be substituted for its
actual behavior in source reviews.

The exported `RelayAuthVerifier::verify` accepts a caller-supplied
`verify_signature: impl Fn(&RelayAuthEnvelope) -> bool`. This *delegates*
cryptographic identity and signer authorization to its actual caller. The
public `verify_test_sig_compat` helper hashes message bytes and caller
"key material" using SHA-256; it is explicitly a skeleton test helper, **not**
a PQ signature verifier or proof of independent identity. The current
`new` and `legacy_compatible` constructors on this candidate both select
strict legacy-v0 refusal, unlike an older mainline snapshot. No default
legacy-v0 acceptance is alleged for this candidate.

New `relay_auth` **delegated-authority** inventory and original source-byte
pin stop reviewed-role drift being silently treated as an unchanged NO_GO
baseline. The actual consumer chain must still establish: which verifier
closure runs in ordinary task/relay receive paths; which authenticated
network/chain/DID/key and nonce owner provides the trusted identity; whether
test-signer compatibility is unreachable in authority; and whether any
migration, restart or replay chooses a legacy or classical-only fallback.
The claim gate detects unreviewed source edits and does **not** establish
caller reachability, authentic ML-DSA signing, protocol safety or production
qualification.

The new source path triggers the unchanged focused PQ claim workflow for
both push and pull requests. Tests verify exact exported source, the 18th
reviewed path/role, intact known NO_GO findings and CLI refusal of a
marker-preserving change to legacy refusal. They do not replace original
native x64/ARM or external-operator results. #562 A–F and #596 remain OPEN;
whole-chain PQ128, public and production remain **NO_GO**.

## Relay pre-signature cheap rejection (separate child of #622)

The exact exported `trnm-types/src/relay.rs` on this child changes the
receiver order: canonical/version/chain/payload checks, then time skew,
authenticated-session sequence/replay and bounded replay-ledger capacity,
then the **unchanged caller-provided** signature callback. Only a successful
callback can advance the `last_seq` and `seen_nonce` maps.

This prevents stale, duplicate and out-of-order packets from repeatedly
causing an expensive *caller-chosen* signature verification. The associated
real Rust unit test records whether the callback runs, rejects replays/gaps/
expired timestamps without a call, refuses a forged signature and then
accepts the correct signature at the same not-yet-consumed sequence. This
is a **source/test change**, not a measured ML-DSA CPU or p99 improvement.

The complete modified exported source is pinned by SHA-256
`285a9468c3a62815fa77a92981a7cbf9bf7110a23c57b70cd16a6ac592211b5e`.
The prior `610bba...` is the historical parent #622 source identity; it
must not be treated as the current child source.

Since replay and time checks now precede signature verification, a packet
with multiple faults may report the cheap rejection first. Both fail closed.
The verifier must still be given an independently authenticated PQ signature
callback; `verify_test_sig_compat` remains a noncryptographic test helper
and MUST NOT authorize deployed communication. In-memory replay tracking
is not crash-safe or externally monotonic. #562 A/B/E/F and every remaining
whole-chain quantum work/proof qualification gate remain OPEN.

## Post-signature trusted time check (separate child of #623)

A timestamp that was fresh at the first check can expire **during** an
expensive, caller-selected signature verification. The new opt-in
`verify_with_fresh_time` demands a caller-trusted clock reading *after*
signature acceptance and *before* committing a nonce/sequence. This fails
closed on post-authentication skew or backward time. Unit regressions exercise
time expiry, exact skew boundary, backward clock, forged signatures, no
replay-state consumption on refusal, and callback ordering.

The legacy one-sample `verify` remains source-compatible but is **not** a
post-verification freshness API. Production callers must explicitly adopt
the new API with their trusted clock; this PR does not demonstrate such a
caller. Its signature callback is still not proven an authentic PQ trust root;
the in-memory replay map is not durable and the clock is not an externally
monotonic witness. No changes to PoN, consensus, wire format, proof security
or production activation. Whole-chain #562 A-F remain NO-GO.

Exact exported relay source SHA-256 on this child: `87312a7827d546b9470d3ec0528006def951046c68da96f5896302718cd342db`.
The #623 pin `285a9468c3a62815fa77a92981a7cbf9bf7110a23c57b70cd16a6ac592211b5e` remains only historical parent evidence.

## ML-DSA-65 signature transport size (separate Gate E follow-on)

The exported relay receiver formerly capped `sig` at 256 UTF-8 bytes.
A FIPS 204 ML-DSA-65 signature is 3,309 raw bytes, which requires exactly
6,618 lowercase hex characters. The 256-byte default rejects such a wire
candidate **before** invoking any independently configured verifier.

This isolated child adds an **opt-in, shape-only** constructor
`for_chain_with_mldsa65_hex_wire`. It requires precisely 6,618 lowercase
ASCII hex characters, rejects missing, shortened, overlong, upper-case and
non-hex signatures before the signature callback, and preserves the existing
256-byte default as well as the caller-owned clock and replay ordering.
A dedicated Rust negative matrix exercises the ordinary receive path and
checks that rejected bytes never reach an expensive callback or mutate
replay state. The callback used by the unit test is synthetic, **not** a
cryptographic ML-DSA verification or authorization.

No scheme negotiation, signer provenance, real ML-DSA verification,
PQ key pin, identity migration, hybrid-AND policy, durable monotonic replay
anchor, production caller, true packet p95/p99 or throughput is established.
The eventual real wire format requires independent versioning and policy;
this candidate introduces no new signed wire version and no activation.
Never use a callback that accepts a string only because its hex shape matches.

Exact new `trnm-types/src/relay.rs` source SHA-256: `50a41e5135cc5f1d1c2edd0afd1b8452180751b2e3488eb3c6af4c182a5a56c5`.
Parent #624 `87312a78...` is historical only. All six #562 gates
and P0 #596 remain OPEN; whole-chain PQ128/public/production = NO_GO.

## Relay SHA-256 rejection-cost ordering (separate Gate E child of #625)

The previous exported relay receiver recomputed SHA-256 over up to 2 MiB of
untrusted payload in `verify_envelope_fields` before its timestamp, sequence,
nonce-replay and capacity preflight. Repeating a known stale/replayed envelope
could therefore trigger full payload hashing even when the signature callback
was correctly skipped. This is a *research candidate* source-level cost gap,
not a measured network exploit or evidence of a deployed production caller.

This child first rejects malformed SHA-256 hexadecimal **shape** (exactly 64
lowercase ASCII hex bytes) at fixed cheap cost, then checks trusted initial
time and replay/sequence/capacity without mutating state. Actual SHA-256 over
the bounded payload runs only for a fresh, in-order, not-yet-replayed candidate,
**before** the caller's existing signature callback and before any nonce or
sequence commit. Even a correctly shaped forged hash still fails with
`PayloadHashMismatch`. Previously accepted canonical envelopes and all
signature/chain/domain/replay policy remain unchanged. Mixed-invalidity error
precedence is intentionally cheap-first; both violations are rejected.

The new real Rust regression uses a 2 MiB envelope, forges its payload with
the same claimed hash, then asserts that a previously authenticated replay
returns `SeqRegression` and an expired in-order envelope returns `TimeSkew`.
It separately asserts malformed and incorrect digest refusal before any
signature callback, plus recovery on the same previously unused nonce/seq
with correct bytes. Error ordering establishes the intended code path;
there is **not** a measured SHA-256 benchmark or independently operated
performance receipt.

Exact reviewed `trnm-types/src/relay.rs` SHA-256: `de09a8fd0f79d430c23236346738551edc6b855bb6154e4df7fb63b857b6b943`.
This hash is pinned in the fail-closed source audit; #625's prior
`50a41e5135cc...` applies only to its historical parent. This change adds
no ML-DSA verifier, PQ ownership/roster, network deployment, persistent
monotonic replay, quantum-mining bound, STARK qualification, production
activation or whole-chain PQ certification. #562 A–F remain NO_GO.
