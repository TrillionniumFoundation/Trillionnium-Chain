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
| Research state authorization | `trillionnium/crates/trnm-research-protocol/src/state.rs` | `ResearchProtocolStateV1`-style apply validates `SignedResearchCommandV1` then permits Nakama/Hepta public keys via `self.authorities.authorizes` | Pin an independent PQ authority registry and version/epoch; verify all state apply/handoff callers and refuse old signed commands after PQ activation |
| Agent market task store | `trillionnium/crates/trnm-task-kernel/src/store.rs` | Ed25519 session/controller verification | PQ owner/session binding, replay, provenance and final-use checks on actual dispatch path |
| Bilateral settlement | `trillionnium/crates/trnm-service-settlement/src/engine.rs` | `SIGNATURE_SCHEME_ED25519_V1`, registered bilateral keys | PQ provider+consumer settlement, independent registry, failure/reorg and anti-downgrade tests |

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

`ResearchProtocolStateV1`'s command apply path checks the signed
command and then authorizes its Nakama/Hepta signer against a stored
classic public-key roster. Tracking `command.rs` alone was not a complete
trust-root audit, because a separately stored authority set and its caller
are part of the decision. This still does not prove deployed
governance or model FinalUse authority.

The two source paths now trigger the focused claim workflow on both push
and PR, and inherit every known classical-marker positive and single-marker
removal negative test. Gate A remains open until real owner/caller/revision
proof and independently managed PQ identity are established.
