# PoCO Consumption / Settlement v1 candidate

This crate is a candidate-only, locally executable kernel for the narrow G2E
slice: bilateral `ConsumptionReceiptV1`, a gap-free atomic
`ConsumptionRollupV1`, a chain-assigned challenge-close height, and a one-shot
single-asset conserved settlement.

Its trust bundle bootstraps exactly one provider, consumer, task, lease,
final-valid result, escrow, price table, evidence-certificate allowlist, and
settlement policy. Those values and each order-finalized execution context are
verifier inputs, not v1 consensus objects and not proof that Agent, DA,
Verify/Challenge, Order, or MVCC authority was exercised.

The durable SQLite journal has no automatic migration. Existing files are
preflighted through an immutable read-only URI after rejecting WAL/SHM/journal
sidecars. Every open/read/write replays the complete canonical operation
journal from fresh genesis; exact source, exact target, and permanently fenced
third state are the only crash outcomes. A checksummed direct-successor block
marker records every finalized block, including consecutive empty blocks and
multiple settlement commands in one block, and is fully audited on reopen.

Deliberately out of scope: multiple assets/results/rollups, invalid or
inconclusive result policies, bonds/slashing, legal/DA/challenge holds beyond
the bounded trust input, real Agent key-state reads, real Result/Challenge
state reads, global MVCC final apply, authenticated state proofs, whole-store
rollback authority, Node integration, normative freeze, production candidacy,
and activation.
