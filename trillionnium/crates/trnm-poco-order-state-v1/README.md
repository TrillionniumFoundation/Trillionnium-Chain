# PoCO AI-native v1 Order-state writer candidate

This crate owns one independent, append-only reference-v1 sparse application
state and the sole create transition currently implemented for it: registered
object kind 50 (`GlobalExecutionBindingV1`). Each write consumes a non-Clone
`OrderStateWritePermitV1`, requires the store's exact current parent height and
root, proves the derived key absent at that parent, creates outer version zero,
and atomically persists the exact successor height, root, value, and
hash-chained history. Every successful return is rebuilt from a fresh read and
contains a canonical 256-sibling membership proof.

Normal builds expose exactly one permit issuer. It consumes a real non-Clone
`WholeNodeFinalizationOwnerV1` together with an unforgeable exact local head
pin, borrows that owner only to derive the canonical tag-50 material, and then
retains the owner inside the private permit. Public cloneable create material,
raw bytes, decoded terminal facts, and generic state mutations cannot issue a
permit. A failed write returns the intact permit for fail-closed exact retry; a
successful write returns `MaterializedOrderStateOwnerV1`, which keeps the
terminal owner paired with the fresh receipt until a separately verified
`VerifiedOrderStateExecutionBindingV1` is consumed by the global owner's
binding seam.

The receipt and materialized-owner APIs now expose the sole typed normal
binding issuer. They project only the private writer's exact materialized
height/root/state key/value/256 siblings into the independent verifier. That
verifier requires later `VerifiedOrderFinalityV1` for the identical
height/post-state root, proves strict certified ancestry for the candidate
encoded by tag 50, and returns the non-Clone binding carrier. The
materialized owner is retained across verification; consuming
`bind_verified_order_state_v1` then checks chain context, candidate
height/block, composite root, and final execution root against its exact
linear terminal commitment.

The store audits its complete contiguous history and live-leaf projection on
every operation. A trusted external head pin detects a coherent database-file
rollback; an attacker who can roll back both database and trusted pin remains
outside this crate's authority. The present store is an empty-anchor,
tag-50-only reference state and is not yet commissioned as the Node's complete
multi-object canonical Order state. Its positive receipt/finality carrier and
consuming global seam close only the local Order-state membership binding;
they do not change G2, Node integration, normative-freeze, production, or
activation truth.

The T0-E foundation adds one normal-build inert planning seam for the
manifest-bound G2 path. It accepts only a
`RecoveredCanonicalOrderApplicationParentV1` issued by this store, performs a
complete fresh audit before and after sealing, keeps the recovered store/head
pin exact, and requires the sealed header to be the unique direct successor.
The private inner `OrderApplicationParentV1` never escapes. This seam still
does not write Order state or grant finality, process, vote, signing,
checkpoint, G2-completion, production, or activation authority.
