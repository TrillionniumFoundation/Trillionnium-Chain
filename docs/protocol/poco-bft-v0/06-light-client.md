# 06 — Light Client and Weak Subjectivity

## 1. Trust model

PoCO-BFT v0 light clients begin from an explicitly trusted checkpoint. They verify every validator-set/protocol transition from that checkpoint to a target finalized header. They do not discover an authoritative validator set merely by observing that the set signed itself.

The light client shares the full-node cryptographic, canonical-encoding, weighted-quorum, and less-than-one-third-Byzantine assumptions for every set it trusts within the verification path. It additionally assumes that its starting checkpoint is canonical and recent enough for the weak-subjectivity window.

## 2. Trusted checkpoint

`TrustedCheckpointV0` stores:

```text
schema_version                  u16
genesis_hash                    Hash32
chain_id                        ConsensusString
protocol_version                u32
epoch                           u64
height                          u64
block_id                        Hash32
state_root                      Hash32
header_timestamp_ms             u64
active_validator_set            ValidatorSetV0
active_validator_set_hash       Hash32
consensus_parameters_hash       Hash32
finality_proof_digest           Hash32
trusted_at_local_time_ms         u64   // local metadata, not consensus-signed
trust_source_description         Bytes // local metadata, not consensus-signed
```

The client MUST recompute the set hash and verify that the stored finalized header and proof match all consensus fields. The initial checkpoint's authenticity is an external trust decision; its local metadata is not hashed into chain objects.

A checkpoint can be installed from genesis, a previously verified update, or an explicit weak-subjectivity recovery. Network peers MUST NOT be allowed to replace it automatically.

## 3. Same-epoch finality verification

To accept target block `b0` as finalized inside one epoch, the client verifies a direct three-chain `(b0, b1, b2)` and QCs `(q0, q1, q2)` exactly as a full node does:

- all canonical encodings, domains, headers, block IDs, and QC digests;
- the complete signed proposal envelope for every certified header, including
  the scheduled proposer signature, exact justify-QC signer subset, and any
  skipped-view TC;
- exact chain, genesis, protocol version, epoch, set hash, and parameter hash;
- unique signers, strict Ed25519 signatures, and recomputed weighted thresholds;
- exact parent, height, justify-QC-digest, and increasing-view relationships;
- `b1`'s exact signed justify digest equals `digest(q0)` and `b2`'s equals
  `digest(q1)`; block/view equality does not permit substitution of another
  valid QC signer subset;
- every skipped-view proposal carries a valid TC for the immediately preceding
  view whose selected high QC is that same exact digest;
- deterministic timestamp bounds;
- ancestry from the currently trusted finalized block.

A `CertifiedHeader` containing only a peer-asserted justification digest and
no proposer signature is not a finality witness.

The client MUST obtain a contiguous authenticated header path, or another future protocol-version proof with equivalent authenticated ancestry. Matching height numbers do not prove ancestry.

The client need not execute application payloads to verify consensus finality, but it MUST NOT claim application-state validity beyond the assumption that the quorum executed correctly. A full verifier may additionally execute payloads.

## 4. Epoch-transition verification

`EpochHandoffProof` is a bounded transport bundle for the nested objects below;
v0 assigns it no independent canonical preimage or digest domain. A verifier
recomputes and verifies every nested commitment, descriptor, certificate,
proposal, and finality-proof digest instead of trusting an aggregate transport
identifier.

To cross from epoch `e` to `e + 1`, the client verifies, in order:

1. ancestry from its trusted checkpoint to the old epoch checkpoint;
2. the checkpoint, both seal blocks, and all three old-set QCs that finalize the checkpoint;
3. the preimage and digest of `NextEpochCommitmentV0` from the finalized checkpoint state/header;
4. the complete new validator set and parameters against their committed hashes;
5. the full handoff descriptor and terminal old QC;
6. unique, canonically ordered old-set handoff signatures reaching the old quorum;
7. unique, canonically ordered new-set handoff signatures reaching the new quorum;
8. the first new-epoch block's exact height, parent, atomic epoch-anchor
   authorization, version, set, parameters, and leader for its actual view;
   view 1 has no TC, while a later first view requires a TC selecting the exact
   authorized `EpochAnchorQC`;
9. an epoch-local new-set three-chain that finalizes a new-epoch block before adopting it as the next trusted checkpoint.

The light client MUST reject:

- a new set supplied out of band even if that set has a valid self-QC;
- a next-set hash not committed by the finalized old checkpoint;
- a handoff with only one quorum;
- an early/in-epoch/unknown protocol version;
- a first new block that extends any block other than the handoff terminal;
- a fallback set or parameter set different from the committed value.

## 5. Weak-subjectivity window

The reference relationships are:

```text
trusting_period_epochs < evidence_window_epochs
evidence_window_epochs <= unbonding_delay_epochs
```

with reference values:

```text
21 < 28 <= 30
```

A client persists two logically separate checkpoints:

1. the **verification cursor**, which is the highest durably accepted
   finalized checkpoint; and
2. the **weak-subjectivity anchor**, whose epoch and block ID were established
   by the most recent explicit external trust event.

Ordinary cryptographic verification may advance the cursor. It MUST NOT move
the weak-subjectivity anchor, renew freshness, or restart the trusting-period
calculation. A client may automatically advance only while:

```text
anchor_epoch <= target_epoch
target_epoch - anchor_epoch <= trusting_period_epochs
```

using checked arithmetic.

Before each automatic-update session, the embedding application MUST
explicitly authorize freshness for the exact chain, genesis, anchor block, and
anchor epoch using its configured independent trust sources. That
authorization includes an externally observed canonical epoch satisfying:

```text
anchor_epoch <= target_epoch <= observed_canonical_epoch
observed_canonical_epoch - anchor_epoch <= trusting_period_epochs
```

It applies only to that update session. An ordinary peer response, claimed
tip, header timestamp, local wall-clock age, previously verified intermediate
checkpoint, or self-signed set cannot establish or renew it. Without current
authorization the verifier may parse and diagnose a proof, but it MUST fail
closed before promoting the cursor or reporting a trusted update.

A multi-epoch bundle is verified as the ordered sequence
`e -> e + 1 -> ... -> target_epoch`; every intervening handoff is mandatory.
Each link's old checkpoint and active configuration MUST equal the preceding
link's verified output. Gaps, reordering, branches, or independently supplied
sets are invalid. Every link is bounded against the unchanged
weak-subjectivity anchor, not a rolling cursor, so individually short hops
cannot wash an expired anchor into a fresh one.

An operator or embedding application MUST also determine whether the canonical network has advanced beyond the trusted window while the client was offline. A stale client cannot safely infer that fact from an untrusted peer's claimed tip alone. Deployment profiles SHOULD use multiple independent current-epoch observations.

If the checkpoint is or may be stale, the client MUST fail closed and require an explicitly installed newer trusted checkpoint. It MUST NOT resolve competing long-range histories by height, accumulated certificate units, validator count, reported wall time, or self-signed voting power.

## 6. Weak-subjectivity recovery

Recovery is an external trust event, not ordinary protocol verification. It is
the only operation that may atomically replace both the verification cursor
and weak-subjectivity anchor. A new checkpoint MUST be presented with:

- exact chain ID and genesis hash;
- finalized header, state root, complete active set, parameter hash, and finality proof;
- its epoch/height and a human-auditable source description;
- corroboration from the operator's configured independent sources.

The number and identity of external sources is a deployment policy and is `UNDECIDED` for mainnet. The client MUST require explicit operator/application authorization and atomically replace the checkpoint; a peer response alone is insufficient.

The old checkpoint SHOULD be retained for audit. If two trusted recovery sources disagree, the client MUST stop rather than choose automatically.

## 7. Application state proofs

After a header is finalized and trusted, an ICS23/JMT-style membership or non-membership proof may establish a value relative to that header's `state_root`. The client verifies:

```text
consensus finality -> trusted header -> state_root -> application proof
```

An application proof against an unfinalized or untrusted root proves nothing about canonical chain state. Proof specification/version, key path, and value encoding MUST match the runtime's committed authenticated-tree rules.

## 8. Client state and rollback protection

The client persists its trusted checkpoint and monotonically highest accepted finalized height/epoch before reporting a successful update. A crash MUST NOT permit silent rollback to an older checkpoint without explicit recovery mode.

For the same chain/genesis, the client rejects any update that:

- conflicts with an already trusted finalized block;
- lowers finalized height or epoch;
- changes a state root at an already trusted height;
- changes the validator set or parameters without a verified transition;
- crosses more epochs than the configured trusting period.

## 9. Independent verifier requirement

P4 requires an independently implemented light-client verifier that does not reuse the full node's parser, QC verifier, or state-transition code. It must reproduce all golden vectors and reject parser, threshold, transition, and long-range mutants before public-validation exit.
