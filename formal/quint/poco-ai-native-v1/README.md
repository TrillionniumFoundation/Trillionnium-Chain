# PoCO AI-native Stack v1 bounded formal candidates

Status: **candidate evidence only; non-normative, incomplete, not frozen, not
implemented, and not activated**

This directory contains the first independently authored Quint tranche for the
draft v1 foundation/order-kernel candidate. It does not copy or relabel the
frozen v0 models. The models use v1 candidate object and field names and are
bound by the dedicated gate to:

- `docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json`;
- `docs/protocol/poco-ai-native-v1/vectors/cev1-foundation-order-kernel-v1.json`;
- `docs/protocol/poco-ai-native-v1/07-order-consensus-epochs-and-finality.md`; and
- `docs/protocol/poco-ai-native-v1/10-invariants-formal-obligations-and-conformance.md`.

The repository-wide truth remains `formal_model_complete=false`. This tranche
closes only the bounded properties listed below. It is not a proof beyond its
bounds and does not establish semantic consistency for the complete v1 stack.

## Candidate suite

### `weighted_order_kernel.qnt`

Maps the following candidate fields:

- `ValidatorMemberV1.validator_id` -> bounded validator `0..3`;
- `ValidatorMemberV1.voting_weight`,
  `ValidatorSetDefinitionV1.total_weight`, and `quorum_threshold` -> checked
  model weight map, total, and threshold;
- `VoteStatementBodyV1.(block_id, epoch, consensus_context.view)` ->
  `VoteStatementV1.(block_id, epoch, view)`;
- `QuorumCertificateV1.body.signatures` -> unique voter set and weighted sum;
- `BlockHeaderV1.(parent, height, view, justify_qc_id)` -> the fixed,
  authenticated two-branch ancestry corpus; and
- durable `locked_qc`, `last_voted_view`, and order-finalized block -> model
  lock, vote watermark, and finality state.

It checks weighted quorum accounting, honest per-view non-equivocation,
safe-vote/lock behavior, certified locks, exact direct three-chain finality,
and prefix-comparable order finality. Initialization covers both the exact
four-member weight-1 candidate fixture (`W=4`, threshold `3`) and a legal
non-equal-weight definition (`3,3,2,2`, `W=10`, threshold `7`) so cardinality
cannot silently replace weight.

### `timeout_lock.qnt`

Maps `TimeoutCertificateBodyV1.(timed_out_view, target_view)` and the selected
`HighJustificationObjectV1` view to bounded integers. It checks that
`target_view=timed_out_view+1`, view/high-QC state is monotonic, and accepting a
TC does not change the locked QC, create a QC, or advance order finality.

### `epoch_handoff_activation.qnt`

Maps the current vector fixture exactly: `old_epoch=7`, `new_epoch=8`,
`terminal_height=99`, `activation_height=100`, `initial_new_view=1`, four
weight-1 validators per role, and threshold `3`. The fully overlapping source
and target identities are deliberately represented by separate
`EpochHandoffSignatureEntryV1.role` sets. The model checks finalized-checkpoint
precondition, independent old/new weighted quorums, exact handoff-ID activation
anchor, monotonic activation coordinates, and role separation.

## Bounds and assumptions

- Four validator identities are modeled. Validator `0` is the only Byzantine
  identity in the order model, so Byzantine weight is strictly below one third
  in both weight modes.
- Two conflicting chains of three non-genesis blocks are modeled in one epoch,
  with heights `1..3` and views `1..6`. Integer IDs abstract already verified,
  domain-separated `BlockIdV1` values; hash/signature collision and decoder
  failures are outside this model.
- Parent ancestry is complete and locally authenticated. Missing ancestry,
  batch retrieval, execution, DA, persistence, signer-journal, and crash
  behavior are separate required models and are not inferred here.
- QC ingress is represented when a proposal learns its justify QC; independent
  background QC fetch/cache/recovery interleavings are not modeled in this
  tranche.
- Timeout views are bounded to `4..8`; selected safe-parent QC views are
  bounded to `0..7`. The model assumes the TC entries, signatures, context,
  and safe-parent object have already passed candidate schema verification.
- One v1 epoch handoff (`7 -> 8`) is modeled. Source and target sets have the
  candidate fixture's complete identity overlap. Cryptographic signature
  verification is abstracted to an admitted role entry; signer uniqueness and
  weight are modeled.
- Random simulation is bounded and seeded. Deterministic positive witnesses
  prove reachability of one legal three-chain, one legal TC view advance, and
  one legal dual-quorum activation inside these bounds.

## Retained failing mutants

The gate requires recognizable counterexamples for all retained mutants:

- `duplicate_signer_weight.qnt`: counts one signer twice;
- `unsafe_lock_vote.qnt`: bypasses `extends(lock) || higher justify` and reaches
  conflicting finality;
- `tc_unlocks.qnt`: clears the durable lock on TC acceptance;
- `tc_finalizes.qnt`: lets a TC advance order finality;
- `two_chain_finality.qnt`: finalizes after only two certified blocks;
- `single_quorum_handoff.qnt`: activates with only the OldSet role; and
- `wrong_activation_anchor.qnt`: installs a successor anchor naming an
  unsigned handoff ID.

## Reproducible check

The gate uses the repository's lock-pinned Quint `0.32.0` installation from the
v0 toolchain directory; only the tool binary is shared, never v0 model state or
evidence:

```bash
bash scripts/ci/check_poco_ai_native_v1_foundation_formal.sh
```

The gate typechecks every model, runs all listed invariants, reaches all legal
witnesses, rejects every mutant with a counterexample, and statically verifies
that the exact schema/vector fixture and global false truth values still match
these bounds. A missing pinned Quint binary is a failure, not silent evidence.

## Remaining formal obligations

No claim is made yet for partition/heal, persist-before-sign, DA durability,
BatchRef retrieval, capabilities/budgets/nonces, task/escrow lifecycle,
verification/challenges/dual finality, MVCC, rollup eligibility, accounting,
v0-to-v1 no-fallback activation, or multi-hop light-client/state-sync. Those
remain required before any change to `formal_model_complete=false` or
`normative_freeze=false`.
