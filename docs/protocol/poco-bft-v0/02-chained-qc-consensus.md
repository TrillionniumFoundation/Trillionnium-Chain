# 02 — Chained-QC Consensus

## 1. Terminology and state

A **block** is identified by the canonical digest of its header. Except for the synthetic genesis block, every block has exactly one parent at height `height - 1`.

A **vote** is an Ed25519 signature by an active validator for one block in one epoch and view. A **quorum certificate (QC)** is a canonically ordered set of valid, unique validator votes for the same block whose recomputed effective weight reaches the epoch quorum.

For total effective voting weight `W`:

```text
quorum(W) = floor(2 * W / 3) + 1
```

All multiplications and additions used to verify a threshold MUST use checked `u128` arithmetic. Overflow makes the certificate invalid. A QC's claimed weight is informational; verifiers MUST recompute it from the exact committed validator set.

Each validator's consensus safety state contains at least:

```text
active_epoch
current_view
last_vote: optional (epoch, view, block_id, vote_digest)
last_timeout: optional (epoch, view, timeout_digest)
locked_qc
high_qc
last_handoff_decision: optional (old_epoch, role, descriptor_digest)
```

The persisted implementation may retain additional history. It MUST retain enough journal entries to reject conflicting requests throughout the slash/evidence window and MUST NOT derive safety solely from the last entry if older entries can still conflict.

`high_qc` is the highest valid QC the validator has learned. `locked_qc` is
the QC on the block on which the validator is locked. QCs are ordered by
`(view, block_id, qc_digest)` for deterministic storage. The digest is the
final tie-break because two valid QCs may certify the same block with different
quorum-signature subsets. If a validator verifies two QCs with the same epoch
and view and different block IDs, it MUST treat that as a safety-assumption
violation, retain both as evidence, stop signing, and require operator
recovery; the lexicographic tie-break does not make that condition benign.

The synthetic genesis block has no ordinary block header and has
`block_id = genesis_hash`. The genesis configuration reconstructs one exact
`GenesisQC` at epoch `0`, view `0`, height `0` using the empty-signature QC
preimage frozen in the wire document. It is valid only in trusted-anchor
contexts and MUST NOT be accepted from the network as an ordinary or
certifying QC.

## 2. Canonical validator order and leader

The validator set is sorted by raw `validator_id` bytes in strictly increasing lexicographic order. Duplicate IDs or consensus public keys make the set invalid.

For a validator set of size `n`, the leader for view `v >= 1` is:

```text
leader_index(v) = (v - 1) mod n
```

This schedule is intentionally unweighted. PoCO affects membership and quorum weight in v0, not leader frequency. Weighted leader selection is deferred to a future protocol version.

Views reset to `1` at a successfully activated epoch. A proposal from any validator other than the scheduled leader is invalid.

## 3. Proposal structure and admissibility

A proposal contains:

- the complete block header and payload;
- a valid `justify_qc` naming the proposed parent;
- optionally, a timeout certificate for the preceding view;
- for the first block of a non-genesis epoch, the complete atomic epoch-anchor
  authorization;
- the leader's proposal signature over the exact digests of all of the above.

For an ordinary, non-handoff proposal in epoch `e`, view `v`, a validator MUST reject it unless all of these conditions hold:

1. the genesis hash, chain ID, protocol version, epoch, active-set hash, parameter hash, height, and block kind are valid;
2. the proposer is the scheduled leader for `v` and its proposal signature is valid;
3. the parent block is available, its ID equals `header.parent_block_id`, and its height is exactly one less;
4. `justify_qc` is valid for the parent, the same epoch, protocol version, and active set;
5. if no timeout certificate is present, `justify_qc.view == v - 1`;
6. if a timeout certificate is present, `tc.view == v - 1`, the TC is valid, and `justify_qc` is exactly the TC's deterministically selected `highQC`;
7. `v` is greater than the proposal's justify-QC view;
8. the proposal extends the unique certified ancestry claimed by its parent;
9. the entire payload is locally available, within limits, deterministically valid, and hashes to the header payload root;
10. deterministic execution from the parent state produces exactly the committed state, receipts, and evidence roots;
11. the parent-relative timestamp rule is satisfied;
12. all mandatory evidence, checkpoint, seal, or handoff constraints for the height are satisfied.

The first proposal of genesis and the first proposal of every non-genesis
epoch follow the anchor rules in the wire and epoch documents. Their
`justify_qc` is the exact context-authorized view-0 synthetic QC, not an
old-epoch QC masquerading as a new-epoch certificate. If the initial view-1
leader fails, view `v > 1` is valid only with `TC(v - 1)` selecting that exact
anchor. The complete epoch authorization independently contains and verifies
the old terminal header and old-set QC.

## 4. Safe-vote rule

Let `P` be an otherwise valid proposal and `J = P.justify_qc`. An honest validator may vote for `P` only if at least one of the following is true; both may be true. The trusted view-0 genesis or epoch anchor initializes both `high_qc` and `locked_qc` for its epoch and participates in this comparison without certifying its referenced block:

```text
extends(P, locked_qc.block_id)
```

or

```text
J.view > locked_qc.view
```

`extends(P, X)` means that following locally verified parent links from `P` reaches block `X`. A validator MUST obtain enough ancestry to evaluate this predicate; an asserted ancestry path is not sufficient.

Before voting, the validator MUST also confirm that it has not already signed a different vote for the tuple:

```text
(genesis_hash, chain_id, protocol_version, epoch, view)
```

The validator signs at most one normal vote for that tuple. PoCO-BFT v0 has no Tendermint-style prevote/precommit phases; a phase value MUST NOT be invented to permit additional votes in the same view.

## 5. Persist-before-sign

The following sequence is normative for votes, timeouts, and handoff votes:

1. validate the complete request and calculate its canonical signing digest;
2. calculate the resulting monotonic safety state;
3. atomically commit the decision record and resulting safety state to durable storage;
4. force the durability boundary required by the storage profile, including an `fsync`-equivalent for both data and metadata needed after power loss;
5. request or create the signature for exactly the committed digest;
6. only after successful journal verification, release the signature to the network.

A remote signer MUST enforce the same non-equivocation decision independently or be coupled to a single authoritative monotonic journal. A node response saying that a write “will be persisted later” is non-conforming.

If durability cannot be established, the journal is corrupt, the recovered state regresses, or the signer and node journals disagree, the validator MUST fail stop and MUST NOT sign. Operator recovery may restore availability only after proving that no conflicting signature can be emitted.

A crash after step 4 but before step 6 may lose liveness but cannot authorize a different decision. On restart, the validator MAY reproduce the same signature for the same digest; it MUST reject a conflicting digest.

## 6. QC processing, high QC, and lock update

When a validator learns a valid QC `Q` for block `B`, it performs these deterministic logical updates:

1. if `Q` is higher than `high_qc`, set `high_qc = Q`;
2. obtain and validate `B` and `B.justify_qc`;
3. if `B.justify_qc.view > locked_qc.view`, set `locked_qc = B.justify_qc`;
4. evaluate the three-chain finality rule;
5. advance `current_view` to at least `Q.view + 1`.

The new state MUST be durably committed before it is used to authorize a subsequent signature. A validator MUST NOT lower either QC by view during ordinary operation or crash recovery.

A proposal or QC received from a future view may advance local operational state only after its complete justification verifies. A bare view number never advances safety state.

## 7. Three-certified-block finality

A block is **certified** only when a valid QC for that exact block has been verified.

A **direct three-chain** is a tuple of three verified signed proposal
envelopes `(p0, p1, p2)` for headers `(b0, b1, b2)` and three certifying QCs
`(q0, q1, q2)` satisfying all of the following:

- `q0` certifies `b0`, `q1` certifies `b1`, and `q2` certifies `b2`;
- all three blocks and QCs use the same genesis hash, chain ID, protocol version, epoch, and validator-set hash;
- `b1.parent_block_id == b0.block_id` and `b2.parent_block_id == b1.block_id`;
- the proposer signatures over `p0`, `p1`, and `p2` verify against their exact
  embedded justifications;
- `digest(p1.justify_qc) == digest(q0)` and
  `digest(p2.justify_qc) == digest(q1)`; matching only block/view coordinates
  is insufficient because valid signer subsets may give one block different
  QC digests;
- if `p1` or `p2` skips a view, its complete TC verifies for the immediately
  preceding view and selects that same exact justify-QC digest;
- `b1.height == b0.height + 1` and `b2.height == b1.height + 1`;
- `q0.view < q1.view < q2.view`; the views need not be consecutive;
- each block header's own view equals the view of the QC that certifies it.

Upon learning and verifying `q2`, a validator finalizes `b0` and every unfinalized ancestor of `b0`. Finalization is monotonic and irreversible within a chain instance. A correct validator MUST reject any later object that would require replacing a finalized block or state root.

Ordinary three-chain finality does not span validator-set or protocol-version changes. Epoch checkpoint finality is completed under the old set before the joint handoff, as specified in the epoch document.

## 8. Timeout messages and timeout certificates

For a local timeout in epoch `e`, view `v`, a validator creates at most one `Timeout` message. It binds:

- the full common consensus context;
- `v`;
- the digest, epoch, view, height, and block ID of the validator's current valid `highQC`.

The referenced full QC MUST be available for the timeout to count toward a TC.
The one context-authorized view-0 synthetic anchor is the only
empty-signature exception and must be reconstructed from trusted genesis or a
verified epoch authorization. Advertising a nonexistent, unauthorized, or
otherwise invalid higher QC makes that timeout ineligible.

A timeout certificate `TC(e, v)` is valid only if:

- every timeout has the exact same genesis, chain, protocol version, epoch, set hash, and timed-out view;
- signer IDs are unique and canonically ordered;
- every signature and every referenced high QC verifies as an ordinary signed
  QC or as the one context-authorized view-0 anchor;
- no two referenced QCs have the same epoch/view and different block IDs;
- the recomputed signer weight reaches `quorum(W_e)`;
- its selected high QC is the deterministic maximum of the referenced valid
  QCs by `(qc.view, qc.block_id, qc_digest)`;
- the selected full QC is included and its canonical digest matches the TC field.

Learning `TC(e, v)` permits a validator to enter view `v + 1`. The leader of `v + 1` MUST extend the TC's selected high QC. A TC:

- does not certify a block;
- does not finalize a block;
- does not lower or clear a lock;
- does not make an otherwise unsafe vote safe;
- does not change the validator set or protocol version.

A validator may have voted and later timed out in the same view. That is not equivocation. It may not sign two different vote digests or two different timeout digests for the same view.

At genesis and immediately after an epoch handoff, timeouts may continue to
reference the corresponding synthetic anchor until the first ordinary QC is
formed. This permits the pacemaker to bypass a faulty initial leader without
granting the anchor certification or finality power.

## 9. Pacemaker

The pacemaker is a liveness component. Local expiration time is not consensus data. The reference timeout starts at `base_timeout_ms`, grows by the configured rational multiplier after unsuccessful views, uses floor-only checked integer arithmetic, and is capped at `timeout_max_ms`. An implementation MAY choose a longer timeout but MUST NOT reinterpret a local timer as evidence of a QC, TC, finality, or wall-clock validity.

On a valid QC for view `v`, a node enters at least view `v + 1`. On a valid TC for view `v`, it enters at least view `v + 1`. Stale messages may be retained for evidence or sync but do not reduce the local view.

## 10. Certified ancestry and catch-up

Before voting or finalizing, a validator MUST possess and validate the relevant header chain, QCs, active validator set, parameter commitment, and execution state or proof needed by its trust model. Catch-up data is untrusted input.

A node that is missing ancestry MUST pause the dependent vote rather than infer parentage from heights or peer claims. State sync may install a finalized checkpoint only after verifying the associated consensus finality proof or an operator-provided trusted checkpoint under the light-client rules.

## 11. Objective equivocation evidence

The minimum safety evidence type is `DoubleVoteEvidence`: two individually valid Ed25519 vote signatures by the same validator over different block IDs with identical

```text
(genesis_hash, chain_id, protocol_version, epoch, validator_set_hash, view, message_kind)
```

The evidence object canonicalizes the two vote digests in lexicographic order. Its ID is domain-separated and therefore independent of submission order. Evidence verification is objective and deterministic; economic disposition is governed by `05-poco-weights-bond-and-slashing.md`.

Conflicting handoff votes, proposal equivocation, and conflicting timeout signatures SHOULD be retained as additional objective evidence types, but their mainnet slash fractions remain `UNDECIDED`. A timeout and a normal vote in the same view are not conflicting message kinds.

## 12. Safety-critical rejection rules

A conforming validator MUST fail closed on, at minimum:

- an unknown protocol or canonical-encoding version;
- a wrong genesis, chain, epoch, set hash, or parameter hash;
- a duplicate signer, unknown signer, invalid signature, zero weight, or threshold overflow;
- a block whose header view differs from its vote/QC view;
- a non-parent justify QC, unavailable certified ancestry, or invalid state transition;
- a TC that selects anything other than its maximum valid referenced QC;
- a TC used as an unlock or finality proof;
- a recovered safety state older than any known emitted signature;
- a conflicting finalized block or state root.
