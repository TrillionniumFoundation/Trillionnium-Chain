# PoCO global execution checkpoint v1 candidate

This crate owns one bounded candidate-only path from a freshly authenticated,
completely retrieved local DA batch through the real Agent/Market,
Verify/Challenge, MVCC/Fee, and Consumption/Settlement preview reducers. A
successful path commits those results into a domain-separated candidate
composite root and advances an independent validation sequence through an
exact successor-only SQLite compare-and-swap before it returns a private,
non-cloneable pre-vote carrier. Independent verified Order finality for that
exact candidate can then drive deterministic, exact-replayable application
into all five source stores and issue the terminal owner only after fresh
terminal readback matches the prepared commitment.

A second bounded owner can seal one exact five-plane terminal-facts cut and a
candidate-local final execution root as the direct successor of that prepared
tip. The checkpoint history row, terminal commitment and metadata CAS are
written in one SQLite transaction. Exact retries are idempotent; reopen audits
the complete predecessor chain and all prepared/finalized evidence rows;
stale, forked, partial, torn and logical-row rollback mutants fail closed.

The finalization owner is private and non-cloneable. Its only normal-build
issuer requires the exact prepared checkpoint, a verified Order-finality
carrier naming that candidate, deterministic source application, and fresh
terminal readback from every plane. Consequently pre-vote comparison data
cannot trigger this CAS or pretend to be an Order proof, state-membership
proof, or Node permit. The crate still cannot detect rollback of an entire
checkpoint file without a future external anti-rollback authority.

The candidate item is not the normative `AgentTransactionV1` wire. The
candidate composite root is not the application JMT root or an Order
`post_state_root`. This crate has no multi-level speculative overlay,
Order-proof/state-membership authority, Node/process
integration, state sync, signing, broadcast, activation, or G2 completion
authority.

The separate manifest-bound v2 seam remains read-only and candidate-ID-free.
Its certified DA item commits the exact manifest, workload/trust bindings,
Order parent and four typed command inventories before a containing header
exists. After full DA retrieval it derives an internal local execution
coordinate from the manifest input ID, runs the existing plane previews only
as transition oracles, and normalizes their roots and receipts in v2 domains.
It maps those facts into the seven ordered Order lists while leaving the
application state-create inventory empty, so `post_state_root` remains the
exact parent JMT root. A non-Clone inert binding can later compare the input,
plan, height and all eight roots with `G2FinalizeBindingRequestV2`; that join is
not a global-store write, vote, finality, Node, or production capability, and
does not promote the legacy candidate-ID-bearing preview path.

A crate-private capability-preserving seam now describes the only acceptable
future normal owner refinement: it consumes both an already-issued, non-Clone
`WholeNodeFinalizationOwnerV1` and the non-Clone
`VerifiedOrderStateExecutionBindingV1` from the independent Order verifier,
then rechecks chain context, strict-ancestor candidate height/block, candidate composite root,
and final execution root byte-for-byte before returning the same linear owner.
The crate can also borrow an existing owner to derive cloneable, inert tag-50
create material for a strictly later height. That material fixes the typed ID,
state key, version zero and canonical value bytes, but deliberately carries no
write authority and does not consume the owner.
The public, deserializable terminal commitment is validated data, never
authority. The terminal owner has the bounded verified-finality source
described above, and the independent `trnm-poco-order-state-v1` crate now owns
the authoritative local tag-50 create transition. It consumes the real linear
owner, proves exact-parent nonmembership, commits and freshly reads the
successor receipt, then joins that typed receipt to separately verified later
Order finality. Raw proof bytes, a bare `post_state_root`, a claim ID, or a
locally computed root cannot call the seam. The global crate does not issue the
positive carrier itself, so `order_binding_positive_carrier_issuer=false`
remains exact; the cross-crate local path supports
`candidate_local_normal_build_finalization_owner_issuer=true` and
`order_state_membership_binding=true`. This does not provide Node
commissioning, coherent whole-store rollback authority, G2 completion, or
production activation.

The fail-closed boundary is checked by
`scripts/ci/check_trnm_poco_global_execution_v1_boundary.sh`.
