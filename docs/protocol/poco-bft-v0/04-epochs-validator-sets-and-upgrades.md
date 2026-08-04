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

`snapshot_lead_blocks` MUST be positive and strictly less than `checkpoint_height(e) - epoch_start(e) + 1`. The snapshot uses only the state of the finalized block at exactly `snapshot_cutoff_height`. If that block is not finalized, the checkpoint proposal is not yet valid.

The deterministic snapshot reads:

- eligible Consumption Certificates and their finalization epochs;
- active slashable bond and pending unbond state;
- jail and objective evidence state;
- registered validator IDs, consensus keys, and key proofs of possession;
- finalized governance decisions for rollout phase, parameters, and upgrades.

It applies the exact algorithm in `05-poco-weights-bond-and-slashing.md`. Later state changes do not alter the candidate for this transition.

If the computed candidate violates any validator-set validity rule, arithmetic check, required key proof, or committed parameter bound, the deterministic result is to carry the current active validators, keys, and effective weights into a new `ValidatorSetV0` for epoch `e + 1`. The fallback reason is committed in state. Implementations MUST NOT repair an invalid candidate with local policy.

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

It is hashed under `trnm.poco-bft.epoch-commitment.v0`. `new_epoch` MUST equal `old_epoch + 1`, and `activation_height` MUST equal `epoch_start(new_epoch)`.

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

The checkpoint block at `checkpoint_height(e)` MUST have `block_kind = epoch_checkpoint` and MUST commit this digest in `next_epoch_commitment_hash`. It may contain ordinary application transactions, but its resulting state MUST include the complete preimage needed to reconstruct and verify the next commitment.

## 6. Epoch seals and checkpoint finality

The blocks at `seal_1_height(e)` and `seal_2_height(e)` MUST have `block_kind = epoch_seal_1` and `epoch_seal_2`, respectively. Each seal MUST:

- use epoch `e`, the old protocol version, old set, and old parameters;
- have an empty application payload and no application transactions;
- have the protocol-defined empty receipts and evidence roots;
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

Parameter changes that affect consensus validity follow the same notice, commitment, and handoff process even when `protocol_version` does not change. A semantic change requires a new protocol version rather than a parameter reinterpretation.

## 12. Recovery and rollback

Normal recovery selects the highest locally verified finalized checkpoint and replays certified descendants without decreasing epoch, view, lock, high QC, or sign-journal history.

Protocol v0 defines no automatic chain rollback, emergency validator-set replacement, or unilateral upgrade cancellation after activation. Any recovery that changes finalized history or bypasses a handoff is a new trust event and must use a separately specified chain/genesis operation. A node MUST NOT infer such authority from operator configuration alone.
