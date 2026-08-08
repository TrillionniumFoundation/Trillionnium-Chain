# 04 — Epochs, Validator Sets, and Upgrades

## 1. Height-to-epoch schedule

Protocol version `0` uses fixed-length epochs. Let `L = epoch.length_blocks`, with `L >= 3`. For every block height `h >= 1`:

```text
epoch(h) = floor((h - 1) / L)
epoch_start(e) = e * L + 1
epoch_end(e) = (e + 1) * L
checkpoint_height(e) = epoch_end(e) - 2
seal_1_height(e) = epoch_end(e) - 1
seal_2_height(e) = epoch_end(e)
```

For every transition authorized by protocol version `0`, let `outgoing_L` be
the active old-epoch `ConsensusParametersV0.epoch_length_blocks`. The
activation height is computed exclusively from the outgoing schedule, using
checked arithmetic:

```text
activation_height = seal_2_height(old_epoch) + 1
```

Candidate next parameters MUST encode the same `epoch_length_blocks`.
Protocol v0 does not authorize changing epoch length, including in a
transition that also activates a later protocol version. A different epoch
schedule requires that later version to define explicit cumulative epoch-start
semantics in a future freeze. A v0 candidate that changes this value is
invalid committed parameters and triggers fallback reason `8`; the boundary
is never recomputed from candidate parameters.

The synthetic genesis block is height `0`. The first `L - 2` blocks of each epoch are payload-bearing slots; the last payload-bearing slot is the mandatory epoch checkpoint. The final two blocks are mandatory empty epoch seals that allow the checkpoint to be finalized by the ordinary three-chain rule under the old set.

Views start at `1` in each epoch and are independent of height. Skipped views do not add heights.

## 2. Immutable active configuration

The following are immutable for all blocks in epoch `e`:

- protocol version;
- active `ValidatorSetV0`, including each effective weight and consensus key;
- consensus parameter commitment;
- leader schedule semantics;
- hash, signature, canonical-encoding, and finality semantics.

Application transactions, certificate finalization, bond changes, jail events, and governance actions during epoch `e` MUST NOT change voting eligibility or weight inside epoch `e`. They may affect only a later committed snapshot.

The genesis document commits epoch `0`'s validator set, manual genesis weights, consensus parameters, protocol version, chain ID, genesis timestamp, and genesis hash. Manual genesis weights are a one-time bootstrap exception and MUST be explicitly identified as such.

## 3. Snapshot cutoff and candidate construction

For transition from epoch `e` to `e + 1`:

```text
snapshot_cutoff_height = checkpoint_height(e) - snapshot_lead_blocks
```

`snapshot_lead_blocks` MUST be at least the committed
`finality_certified_chain_length` and strictly less than
`checkpoint_height(e) - epoch_start(e) + 1`. Protocol v0 fixes the certified
chain length at `3`; therefore lead `2` is invalid and lead `3` is the minimum
accepted boundary. This guarantees that the cutoff block can acquire its
direct child and grandchild certificates before the checkpoint height. The
snapshot uses only the state of the finalized block at exactly
`snapshot_cutoff_height`. If that block is not finalized, the checkpoint
proposal is not yet valid. The relation is checked independently for both the
old and candidate parameter preimages used by the same-version commitment
context.

The deterministic snapshot reads:

- eligible Consumption Certificates and their finalization epochs;
- active slashable bond and pending unbond state;
- jail and objective evidence state;
- registered validator IDs, consensus keys, and key proofs of possession;
- finalized governance decisions for rollout phase, parameters, and upgrades.

It applies the exact algorithm in `05-poco-weights-bond-and-slashing.md`. Later state changes do not alter the candidate for this transition.

The B2-G calculation boundary represents those reads as a caller-supplied
`UnauthenticatedCandidateSelectionTranscriptV0`. Candidate and contribution
input permutations are accepted and sorted internally by their canonical
raw-byte keys; duplicates are invalid. The transcript carries normalized
calculation facts; it is not the full wire encoding of a
`ConsumptionCertificateV0`, an application-state proof, or an execution
receipt. A B2-G verifier MUST treat every eligibility, finalization-epoch,
relationship, bond, jail, registration, governance, and cutoff fact as
untrusted input until a later provenance layer binds it to authenticated
state. Passing the pure calculation kernel proves only that one supplied
transcript has one deterministic result.

The local inert-kernel admission surface checks cardinality before cloning:
at most 100 candidate entries and 10,000 contribution entries, with nonempty
task and consumer IDs of at most 128 bytes. Cardinality overflow is reason `1`
and atomically carries the old configuration without candidate diagnostics.
These bounds do not freeze production certificate transport or throughput.

The next configuration is selected atomically as
`(protocol_version, validator_set, consensus_parameters, rollout_phase,
upgrade_plan_hash)`. Any invalid or mutually inconsistent component
invalidates the complete candidate tuple; no valid-looking component from that
candidate survives.

Fallback deterministically selects:

- the old active protocol version;
- a `ValidatorSetV0` re-encoded for epoch `e + 1` with identical ordered
  validator IDs, consensus keys, and effective weights, bound to the carried
  parameter hash;
- the complete old active `ConsensusParametersV0` unchanged;
- that parameter set's existing rollout phase; and
- an absent `upgrade_plan_hash`.

Only epoch-dependent wrapper fields and their hashes are recomputed. A valid
governance proposal may remain in application state, but fallback does not
activate it. Implementations MUST NOT partially activate a parameter,
rollout, validator-set, or upgrade change and MUST NOT repair an invalid
candidate with local policy. If the old active configuration cannot itself be
reconstructed and validated, the node halts instead of inventing a fallback.
The fallback reason is committed in state. Candidate diagnostics and any
computed candidate set are cleared on fallback; invalid partial results are
not exposed as reusable evidence.

`shadow` carry-forward is not fallback. A valid shadow calculation computes
and commits its diagnostic candidate facts, but the selected next set carries
the old ordered membership, consensus keys, and effective weights re-encoded
for `new_epoch`, bound to the independently validated selected parameter
preimage. Shadow does not force the old parameters or old rollout phase. It
MUST use `fallback_used = false` and reason `0`. The
nonzero fallback reasons above are reserved for an invalid complete candidate
tuple, not for the configured shadow rollout rule. Shadow exposes raw
candidate diagnostics but no computed candidate validator set, and validates
the actual old carry against the candidate parameters.

### 3.1 B2-G deterministic candidate/fallback computation kernel

B2-G freezes a pure relation over caller-supplied typed inputs:

1. validate the supplied old and candidate parameter preimages, exact
   `snapshot_height == committed_snapshot_cutoff`, checked adjacent target
   epoch, deterministic internal transcript sorting and uniqueness, bounded
   normalized facts, validator
   identities and keys, and every supplied `ValidatorKeyProofOfPossessionV0`;
2. compute certificate maturity, decay and the three relationship aggregates
   plus the provider cap using checked `u128`, floor-only arithmetic;
3. compute the PoCO and bond ceilings, take their minimum with the validator
   cap, filter below-minimum or ineligible registrations, rank by descending
   raw capacity then ascending raw validator-ID bytes, truncate to
   `max_validators`, and re-encode the selected set in ascending validator-ID
   order;
4. assign effective weights exactly for the committed rollout phase, with
   `shadow` selecting the old membership/keys/weights without setting
   fallback;
5. validate all individual, total-power, cardinality, uniqueness and
   concentration constraints; and
6. either return the exact candidate with reason `0`, or select the exact
   carry-forward configuration and the lowest applicable nonzero reason in
   the frozen `1..9` taxonomy.

The normative equations and precedence rules are in
`05-poco-weights-bond-and-slashing.md`. Success yields only a private-field,
inert `CandidateSelectionKernelV0` carrying deterministic outcome evidence for
the supplied normalized inputs. It is not an exact-transcript commitment and
has no aggregate digest or domain. There is no conversion from this token to
an `EpochAnchorQC`, handoff
signature, first-new-epoch proposal, activation authorization, or core epoch
transition. The kernel does not authenticate a cutoff header or state root,
does not verify JMT/ICS23 membership, non-membership, namespace, or
completeness, does not identify or execute an authorized runtime, and does not
prove checkpoint-body or receipt provenance.

Production PoP verification MUST use `StrictEd25519Verifier`; a generic or
accept-all `SignatureVerifier` is not attested and cannot grant authority.
Every kernel getter remains unauthenticated diagnostic output.

The required next provenance join is ordered and fail-closed:

```text
finalized exact cutoff header
  -> JMT/ICS23 proofs for the frozen snapshot namespace and completeness
  -> authorized runtime plus checkpoint execution/state-transition provenance
  -> exact candidate/commitment/handoff composition
  -> EpochHandoffProof fields 13 and 14
  -> epoch-anchor authorization, activation, and atomic core transition
```

A later authority layer must re-run B2-G over the authenticated normalized
projection after proving every prior arrow, or introduce a future
exact-input-binding wrapper. It cannot join the present inert token itself to
a cutoff or transcript. Peer-supplied transcript bytes, a matching
`snapshot_state_root`, or a valid PoP alone never authorize a set or
transition.

### 3.2 Application-authenticated candidate reconstruction

B2-H3b2b2 uses one crate-private call to bind the production checkpoint
execution and its exact historical cutoff projection, reconstruct the complete
normalized transcript internally, hard-code `StrictEd25519Verifier`, and run a
fresh B2-G calculation. The call accepts no caller-supplied transcript,
eligibility bit, signature verifier, status/event, current-head projection, or
earlier `CandidateSelectionKernelV0`. Its private result binds the checkpoint,
candidate-parameter hash, canonical transcript digest, canonical result digest,
and one authorization identifier; the wrapped inert B2-G kernel is not exposed.

The v0 candidate universe is exact and conservative:

- old-set membership alone is not registration authority. An old identity/key
  is included only when the cutoff contains the matching active, non-revoked
  kind-9 registration and kind-16 history. Its canonical B2-G entry omits both
  the PoP and previous nonce;
- kind-16 appends a bounded, ordered future-candidate registration without
  reinterpreting kind 9. It MUST target exactly `old_epoch + 1`, retain the
  complete strict-PoP bytes and digest, registration decision/height, and, for
  a changed old key, the exact predecessor nonce and history head;
- a changed old key MUST prove a strictly increasing nonce over that exact
  predecessor. A new identity MUST have no predecessor. An unchanged old key
  MUST use the proof-free old-registration path and therefore cannot create a
  redundant future record; and
- duplicate target identities or keys, key ownership drift, incomplete
  predecessor history, and malformed or wrong-scope future PoP state invalidate
  the authenticated projection. They are not repaired by dropping one entry.

Candidate parameters come from the exact finalized approval for the target
epoch and its matching role-2 kind-14 preimage. If no such finalized approval
exists, the exact active parameters are the reason-0 no-change candidate
preimage. A pending proposal has no candidate authority. A present finalized
approval with a missing or mismatched kind-14/kind-15 companion is malformed
authenticated state and fails before B2-G rather than becoming fallback.

Every contribution is reconstructed from the retained authenticated
certificate companion. `finalized_epoch` is the epoch of its finalized
acceptance block, derived from `accepted_height` under the immutable v0 epoch
geometry; it is neither submitter supplied nor relabeled as the current epoch.
Only `independent` relationships contribute. Lifecycle `accepted` contributes
only with no pending challenge, `challenge_rejected` restores eligibility, and
`challenge_sustained` does not contribute. Related, reciprocal, unresolved,
revoked, or pending facts contribute zero.

For target epoch `t`, a bond contributes its full amount only when it is
`active_slashable` and checked arithmetic proves
`t + evidence_window_epochs < locked_until`; absence, `unbonding`, insufficient
coverage, or withdrawable state contributes zero. Jail is absent when no exact
kind-11 fact exists and otherwise applies exactly while
`t < jailed_until`; equality is expired. These normalized zero/ineligible
facts remain part of the complete transcript rather than being omitted by
local policy.

Cross-epoch retention does not relabel admission-cap usage. When the active
epoch changes, kind-16 meter usage retains only the canonical current rolling-
span bucket, and consumer/provider, task/provider and provider usage retain
only the exact new-epoch bucket. Older buckets are removed atomically with the
new active configuration/kind-16/manifest/JMT root; their quantities are never
copied into a new epoch. Mature retained certificates remain historical facts
and are independent of that rollover. The helper/fixture boundary exists, but
production Core activation does not yet drive this transition, so normalized
usage rollover remains an H3b2b2a production gap.

The implementation of this one-call application-authenticated join and its
bounded raw shared schema/vector evidence have landed. Node independently
rebuilds the two raw-history scenarios and a non-ignored Rust test reconstructs
the committed JMT fixture/one-call result byte-for-byte. A second non-ignored
production-path test consumes both canonical outcomes. Independent applications
start from the exact production-valid epoch-0 empty-authority genesis, install
the matching canonical source through the explicitly test-only height-24 epoch
bootstrap, and then execute the normal height-25 cutoff refresh, height-27
parent and height-28 checkpoint. The private result from the execution used by
`ProcessProposal` equals the independent `FinalizeBlock` result. It remains
equal after V3 parent restore, periodic SQLite V4 cutoff-25 restore followed by
parent 27, SQLite restart, projection-cache miss/hit and fresh reconstruction
from retained cutoff 25 after checkpoint restart. Zero-hash rejection leaves
the committed head, pending block and cutoff projection unchanged. The
height-24 bootstrap is fixture-only and proves no production application/Core
epoch transition or usage rollover. Node now recomputes the historical JMT,
enforces exact physical namespace completeness, exact-decodes every kind
payload and runs the shared root-consistent mutation families. A targeted
SQLite pruning test advances the floor to 26 and physically removes cutoff 25
through the production pruning authority, proving restart-stable reject/
fail-stop without head, pending or source changes. Only cache/restart TOCTOU
mutation hardening and a stronger
AST/type-aware API gate remain in the bounded evidence partition.
Moreover, the current production join does not yet consume the B2-H1 finalized
cutoff-header capability, proof ID, or cutoff block ID. It therefore authorizes
only application-authenticated candidate/fallback reconstruction. It does not
yet establish the complete `finalized cutoff -> application projection` join,
mint a `NextEpochCommitmentV0`, fill handoff fields 13/14, authorize an anchor,
activate a configuration, or move the Core across an epoch.

## 4. Validator key proof of possession

A new or changed consensus key is eligible only after a finalized proof-of-possession registration. The key signs the digest of:

```text
schema_version       u16
genesis_hash         Hash32
chain_id             ConsensusString
target_epoch         u64
validator_id         Bytes
public_key           PublicKey32
registration_nonce   u64
```

under:

```text
trnm.poco-bft.validator-key-pop.v0
```

`ValidatorKeyProofOfPossessionV0` encodes those seven signing fields in that
exact order followed by `signature: Signature64`. The signature is not part of
the signing preimage. Verification uses strict Ed25519 against the exact
embedded `public_key`; accepting a PoP under any other domain, target epoch,
identity, key, or nonce is invalid candidate-registration input.

The registration nonce is strictly increasing per validator identity. A proof for another chain, genesis, validator, key, target epoch, or nonce is invalid. Key rotation takes effect only through the next-set commitment and joint handoff.

## 5. Next-epoch commitment

`NextEpochCommitmentV0` contains, in this exact order:

```text
schema_version                 u16
genesis_hash                   Hash32
chain_id                       ConsensusString
old_epoch                      u64
new_epoch                      u64
snapshot_cutoff_height         u64
snapshot_state_root            Hash32
new_protocol_version           u32
new_validator_set_hash         Hash32
new_consensus_parameters_hash  Hash32
rollout_phase                  u8
upgrade_plan_hash              Optional<Hash32>
fallback_used                  bool
fallback_reason_code           u16
activation_height              u64
```

It is hashed under `trnm.poco-bft.epoch-commitment.v0`. `new_epoch` MUST equal
`old_epoch + 1`, and `activation_height` MUST equal
`seal_2_height(old_epoch) + 1` under the outgoing active schedule.

For every commitment, whether fallback or not:

- `new_validator_set.epoch == new_epoch`;
- `new_validator_set.protocol_version == new_protocol_version`;
- `new_validator_set.consensus_parameters_hash == new_consensus_parameters_hash`;
- the decoded new parameters' `protocol_version == new_protocol_version`;
- `rollout_phase` equals the decoded new parameters' `rollout_phase`.

A mismatch is invalid committed parameters. The duplicate `rollout_phase`
field is an authenticated consistency check, not an independently selectable
value.

`fallback_reason_code` is deterministic:

```text
0  no fallback
1  malformed or internally inconsistent snapshot input
2  checked-arithmetic failure
3  fewer than min_validators eligible candidates
4  duplicate or invalid validator identity/key/registration
5  individual weight outside committed bounds
6  zero or excessive total voting power
7  concentration constraint violated
8  invalid or inconsistent committed parameters
9  invalid authorized upgrade/activation data
```

If more than one nonzero reason applies, commit the lowest numeric code. Code `0` is invalid when `fallback_used = true`, and a nonzero code is invalid when it is false. Unlisted values are invalid in v0.

`snapshot_state_root`, `new_validator_set_hash`, and
`new_consensus_parameters_hash` MUST be nonzero. An absent
`upgrade_plan_hash` is distinct from a present hash; when present, the hash
MUST be nonzero. These are intrinsic object-shape rules and do not prove that
the referenced state, set, parameters, or upgrade preimage is authorized.

The checkpoint block at `checkpoint_height(e)` MUST have `block_kind = epoch_checkpoint` and MUST commit this digest in `next_epoch_commitment_hash`. It may contain ordinary application transactions, but its resulting state MUST include the complete preimage needed to reconstruct and verify the next commitment.

## 6. Epoch seals and checkpoint finality

The blocks at `seal_1_height(e)` and `seal_2_height(e)` MUST have `block_kind = epoch_seal_1` and `epoch_seal_2`, respectively. Each seal MUST:

- use epoch `e`, the old protocol version, old set, and old parameters;
- encode the empty application payload as CEV0 `List<Bytes>` count `0`
  (`00 00 00 00`) and contain no application transactions;
- use the exact ordered-root empty payload, receipts, and evidence constants
  frozen in the wire document;
- preserve exactly the checkpoint state root;
- repeat the checkpoint's `next_epoch_commitment_hash`;
- extend the preceding block by one height;
- satisfy the ordinary timestamp, proposal, vote, QC, lock, and view rules.

The direct certified chain

```text
checkpoint <- seal_1 <- seal_2
```

finalizes the checkpoint when `QC(seal_2)` is learned. No handoff vote is valid before the signer has verified this complete finality proof.

Because seals do not mutate application state, the state transitioned into the next epoch is exactly the finalized checkpoint state. Seal QCs still remain consensus objects and are required by the bridge proof.

## 7. Handoff descriptor

After checkpoint finality, construct `HandoffDescriptorV0` in this order:

```text
schema_version                     u16
genesis_hash                       Hash32
chain_id                           ConsensusString
old_epoch                          u64
new_epoch                          u64
old_protocol_version               u32
new_protocol_version               u32
old_validator_set_hash             Hash32
new_validator_set_hash             Hash32
old_consensus_parameters_hash      Hash32
new_consensus_parameters_hash      Hash32
checkpoint_height                  u64
checkpoint_block_id                Hash32
checkpoint_state_root              Hash32
next_epoch_commitment_digest       Hash32
terminal_old_height                u64
terminal_old_block_id              Hash32
terminal_old_qc_digest             Hash32
terminal_old_view                  u64
activation_height                  u64
initial_new_view                   u64
```

The terminal old block is `seal_2`; `initial_new_view` MUST be `1`. It is the
new epoch's pacemaker and handoff-signing start view, not a promise that the
first block will be proposed in view 1. All referenced blocks, QCs, sets,
parameters, state commitments, heights, and versions MUST verify. The
descriptor digest is:

```text
Digest("trnm.poco-bft.handoff-descriptor.v0", HandoffDescriptorV0)
```

## 8. Joint handoff certificate

Every active old-set validator and candidate new-set validator may sign at most one handoff descriptor for a given `old_epoch` and signer role.

An old-set handoff vote uses `message_kind = old_set_handoff_vote`, the old signing set in its common context, and binds the descriptor digest. A new-set handoff vote uses `message_kind = new_set_handoff_vote`, the new signing set, and binds the same descriptor digest. Both use `trnm.poco-bft.handoff-vote.v0`.

`HandoffVoteSignV0` has this exact field order:

```text
schema_version                 u16
genesis_hash                   Hash32
chain_id                       ConsensusString
signing_protocol_version       u32
signing_epoch                  u64
signing_validator_set_hash     Hash32
signing_view                   u64
message_kind                   u8
handoff_descriptor_digest      Hash32
```

For the old role, the signing version/epoch/set/view are the descriptor's old version, old epoch, old set, and terminal old view. For the new role they are the new version, new epoch, new set, and `initial_new_view`. The message-kind discriminant distinguishes the roles. Each signature is over `Digest("trnm.poco-bft.handoff-vote.v0", HandoffVoteSignV0)`.

The old signer MUST first verify checkpoint finality, the next-epoch commitment, and the terminal old QC. The new signer MUST independently verify the same proof, reconstruct its candidate set and parameters, verify its own inclusion/key, and confirm support for the activated protocol version.

`HandoffCertificateV0` contains, in order, `schema_version: u16`, the full descriptor, a strictly ordered unique `List<(validator_id: Bytes, signature: Signature64)>` for the old set, and the same list type for the new set. Its digest is `Digest("trnm.poco-bft.handoff-certificate.v0", HandoffCertificateV0)`. It is valid only if:

```text
old_signer_weight >= quorum(old_total_weight)
new_signer_weight >= quorum(new_total_weight)
```

Both weights are recomputed from their respective exact set commitments.

Persist-before-sign applies to both roles. Old validators MUST NOT sign two different descriptors for the same transition. New validators MUST NOT sign two different descriptors for the same transition. This rule applies even if one descriptor would carry the current set as fallback.

## 9. First block of the new epoch

No normal vote, QC, finality, or application progress in epoch `e + 1` is valid before a joint handoff certificate exists.

The first new-epoch block MUST:

- be at `epoch_start(e + 1)` with epoch `e + 1`, an actual proposal view
  `v >= 1`, and `block_kind = epoch_handoff`;
- extend the exact terminal old `seal_2` block named by the handoff descriptor;
- carry one atomic `EpochAnchorAuthorizationV0` containing the terminal old
  header, terminal old QC, and full joint handoff certificate;
- use the new protocol version, validator set, parameters, and scheduled
  new-set leader for the actual view `v`;
- begin execution from the finalized checkpoint state root;
- commit no alternative next-epoch descriptor.

The new epoch initializes the exact synthetic `EpochAnchorQC` preimage frozen
in the wire document at epoch `e + 1`, view `0`, pointing to the terminal old
block and authenticated by the atomic authorization. It is a safe-vote and
timeout high-QC anchor, not an ordinary QC, carries no voting weight, and
cannot by itself certify or finalize a block.

The first proposal's `justify_qc` is the reconstructed `EpochAnchorQC`; the old
terminal QC never masquerades as a new-set QC. At view `1` no TC is present.
At view `v > 1`, a valid `TC(v - 1)` selecting that exact anchor is required,
so a faulty initial leader cannot permanently stall the transition. Until the
first new-set QC forms, timeout votes and TCs may reference the authorized
anchor. After that QC forms, all QC, lock, timeout, and three-chain rules are
entirely epoch-local and the authorization sidecar is no longer admissible in
ordinary proposals.

Old-set seal blocks are not application-state successors of the checkpoint; they repeat its state. Therefore the new block's execution parent state is unambiguous even though its consensus parent is `seal_2`.

## 10. Handoff safety and liveness boundary

A valid joint certificate requires an old quorum and a new quorum over exactly one descriptor. Safety assumes less than one third Byzantine weight separately in both sets and correct persistent one-descriptor signing.

The handoff cannot silently switch to a locally preferred candidate. If the valid committed new set lacks an online quorum, the chain may stall safely. Operators or governance cannot bypass the missing new quorum inside protocol v0; recovery requires a separately authorized protocol/genesis procedure whose safety assumptions are explicit.

Once an old validator has durably signed a handoff descriptor, it MUST NOT sign an alternative transition or any old-epoch block beyond the terminal height. It MAY continue serving old blocks, proofs, and state chunks.

## 11. Protocol and parameter upgrades

An `UpgradePlanV0` becomes authoritative only after its governance result is finalized in application state. Its exact logical field order is:

```text
schema_version                    u16
genesis_hash                      Hash32
chain_id                          ConsensusString
governance_decision_id            Hash32
current_protocol_version          u32
target_protocol_version           u32
approval_epoch                    u64
approval_height                   u64
activation_epoch                  u64
activation_height                 u64
artifact_manifest_hash            Hash32
target_consensus_parameters_hash  Hash32
state_migration_hash              Optional<Hash32>
```

Its `upgrade_plan_hash` is `Digest("trnm.poco-bft.upgrade-plan.v0", UpgradePlanV0)`. The finalized application state MUST expose this complete preimage, not only a peer-supplied hash. `approval_height` is the finalized height of the governance result. An absent state migration is distinct from an all-zero hash.

For v0:

- activation occurs only at an epoch boundary through the joint handoff;
- checked arithmetic MUST satisfy `activation_epoch >= approval_epoch + upgrade_notice_epochs`;
- a version jump MUST NOT exceed `max_protocol_version_jump`;
- the old protocol version authorizes the next-epoch commitment and old-set handoff votes;
- the new set signs its handoff role only if it supports the new version;
- the first new block uses exactly the authorized new version;
- an unknown, unsupported, early, late, or in-epoch version is rejected;
- there is no automatic rollback.

The concrete governance transaction encoding and the target version's migration execution semantics are `UNDECIDED`. They MUST be frozen before a real upgrade depends on them. The wrapper and activation checks above are frozen. The finalized state result and epoch commitment are consensus authoritative; an off-chain release announcement is not.

Parameter changes that affect consensus validity follow the same notice,
commitment, and handoff process even when `protocol_version` does not change.
The v0 `epoch_length_blocks` exception above remains immutable. A semantic
change requires a new protocol version rather than a parameter
reinterpretation.

## 12. Recovery and rollback

Normal recovery selects the highest locally verified finalized checkpoint and replays certified descendants without decreasing epoch, view, lock, high QC, or sign-journal history.

Protocol v0 defines no automatic chain rollback, emergency validator-set replacement, or unilateral upgrade cancellation after activation. Any recovery that changes finalized history or bypasses a handoff is a new trust event and must use a separately specified chain/genesis operation. A node MUST NOT infer such authority from operator configuration alone.
