# PoCO Consumption / Settlement v1 candidate

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M12. Target responsibility: Mining rewards, model contribution allocation and free-use budgets.
See [M12 technical contract](../../../docs/modules/M12_SETTLEMENT_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse exact escrow/resource conservation, typed settlement and replay principles. Existing
consumption-rollup formulas and bond-weight selection are legacy-only, not adopted PoN reward or
work rules.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


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
