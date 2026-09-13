# PoCO AI-native v1 bounded Order-finality verifier

This candidate crate independently decodes and exactly re-encodes raw CEV1
`FreshGenesisTrustBundleV1` and `OrderFinalityProofV1` bytes for one bounded,
FreshGenesis-rooted, direct-view certified chain. It recomputes every
validator-set, parameters, epoch, header, block, vote, QC, and proof digest;
enforces checked weighted quorum; and verifies each QC signature with strict
Ed25519. The compatibility entry point remains FreshGenesis-target-only. The
direct entry point selects either FreshGenesis or an Ordinary target at the
exact `chain_len - finality_chain_length` position.

The exact `ProtocolContextV1`, eight-root `BlockHeaderV1`, typed `BlockIdV1`,
`VoteStatementBodyV1`, and `QuorumCertificateV1` codecs now come from the
lower-level `trnm-poco-order-types-v1` crate. This verifier no longer carries a
second private header/vote/QC encoding. The shared crate contains public data
and content addressing only; this crate remains the owner of trust, quorum,
signature, certified-chain, and finality validation.

Before hashing or decoding either untrusted input, the verifier applies two
independent, verifier-local absolute byte ceilings: 64 KiB for the trust bundle
and 256 KiB for the proof. The committed `max_cev1_value_bytes` remains an
additional inner bound. The exact bounded certified chain must also fit the
committed `max_retained_views`; a canonical trust bundle that lowers that bound
below three is rejected before QC authority is considered.

The trust bundle is not self-authorizing. The caller must supply a separately
pinned SHA-256 digest of the exact trust bytes. The returned verifier carrier
has private fields and is neither `Clone` nor `Copy`.

The crate also parses one strictly bounded, candidate-only
`ExecutionBindingClaimV1`. Its exact CEV1 body order is:

```text
schema_version:u16=1
order_proof_id:Hash32
chain_id:Bytes
genesis_hash:Hash32
protocol_version:u32
stack_profile_hash:Hash32
finalized_epoch:u64
finalized_block_id:Hash32
finalized_height:u64
finalized_post_state_root:Hash32
candidate_height:u64
candidate_block_id:Hash32
candidate_composite_root:Hash32
final_execution_root:Hash32
witnesses:List<ExecutionBindingStateWitnessV1>
```

The list contains exactly one witness: `(state_tree_version:u16, object_kind:u16,
object_id:Hash32, object_version:u64, value_bytes:Bytes,
siblings:List<Hash32>)`. It must name registered object kind 50 at outer
version zero and has exactly 256 siblings whose left/right side is derived from
the domain-separated typed state key. The body is followed by
`claim_id = DigestV1(
"trnm.poco-ai.global-execution-order-state-binding.claim.candidate.v1",
body)`. The verifier applies a 4 MiB absolute claim bound before decode,
requires exact decode/re-encode bytes, then binds all Order context/finality
facts and exact candidate/final roots before verifying every sparse path.

This claim schema is an implementation-candidate envelope only and its domain
cannot authorize itself. Object kind 50 is registered as a create-only
`GlobalExecutionBindingV1`: its typed ID covers context, strict-ancestor
candidate height/block, candidate composite root and final execution root; its
paired state and outer version are fixed at zero. The Rust verifier strictly
decodes both inner values, recomputes the typed ID/key, and rejects root,
context, version, state, path and ancestry substitutions.

The direct verifier retains a private `(height, block_id)` ancestry map only
for the fully verified certified prefix through the selected target. Every
entry was authenticated by its strict Ed25519 QC and exact parent/height/view
successor relation; callers cannot supply or extend that map. A deeper bounded
direct chain can therefore prove an earlier Ordinary candidate is a strict
ancestor of its later Ordinary target.

The public `GlobalExecutionBindingCreateMaterialV1` is intentionally cloneable
data, not a capability. It deterministically derives the tag-50 typed ID,
state key, outer version zero and exact immutable/mutable bytes, and rejects
`materialized_at_height <= candidate_height`. It does not prove parent-key
absence or authorize a state write.

The positive `VerifiedOrderStateExecutionBindingV1` carrier now has one normal
issuer. The independent `trnm-poco-order-state-v1` writer consumes a real
linear terminal owner into an exact-parent create-once permit, commits tag 50,
freshly rebuilds its height/root/value/256-sibling receipt, and projects that
receipt into `OrderStateExecutionBindingReceiptProofV1`. The typed verifier
requires separately verified later Order finality for the exact receipt
height/root, authenticates the complete sparse path, decodes the candidate
tuple from the admitted value, generates the canonical claim bytes, and then
runs the same strict raw-claim verifier. `ExecutionBindingWriterUnavailable`
is retained only as a reserved compatibility error code and is not returned by
the exact writer path.

The typed receipt projection has public fields because this independent crate
does not depend on the writer crate. It is evidence, not authority: a copied or
fabricated projection cannot mint a carrier without genuine
`VerifiedOrderFinalityV1` authority and exact membership beneath its
`post_state_root`. Conversely, the public raw CEV1 claim remains transport
data; it still requires that same finality carrier, caller-expected exact
candidate/composite/final roots, strict certified ancestry, and the full
membership proof. The global consuming seam finally checks all four candidate
facts against its retained non-Clone terminal owner before returning that
owner.

The accepted scope is deliberately narrow: epoch zero, one pinned
FreshGenesis-rooted chain of 3–16 certified headers, direct height/view
successors, FreshGenesis or Ordinary target, no timeout certificate, no epoch
handoff, and no v0 activation. The crate is not a complete light client, wire
implementation, trust-path iterator, weak-subjectivity selector, Node
authority, commissioned Node Order-state, production candidate, or activation
mechanism.
