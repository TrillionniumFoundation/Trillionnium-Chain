# P1 continuous-owner History: fail-closed until original durable CPU operation

Status: **DRAFT / HOLD_NO_GO / development-only**.
Exact source parent: Chain PR #497
`6f0977ee752fa186e61cfbf6ae0346b32122e7b8`.
No modification to PNW1, transcript, target, fork-choice, Chainwork,
signed V3 Cookie, consensus, model selection or production activation.

## Remaining source-level accounting bypass

The ordinary standalone History CPU import uses the original
`ServiceMutationCpuDomain` with one durable ordinary-V3-epoch metadata
marker and real per-W1/M06 CPU operations. That is a conservative local
crash fence for an ordinary Node, but **not** a continuous owner
operation journal.

The continuous mode4 Node holds an independent durable operation ledger,
linked owner permits, Final-use/resource fences, and a
`DurableOperation::begin` path that explicitly records operation ID,
CPU allowance, startup links and metadata before native work.
`ServiceMutationCpuDomain::begin` alone never creates that durable
operation record.

At PR #497:
- `Node::begin_remote_history_cpu_epoch` returned `Ok(false)`
  for continuous mode, allowing History import to proceed using only
  a volatile CPU operation, without beginning the durable continuous
  journal.
- `peer_polling.rs::admit_page` also started a raw CPU domain operation
  on signed remote History data, not a durable continuous operation.
- A process crash between full W1/M06 CPU charging and post-commit
  reconciliation could therefore erase the authoritative owner
  operation-ID/debt boundary. Physical cgroup throttling does not
  reconstruct a lost operation claim.

## Conservative correction

1. The Node refuses unjournaled continuous History import before the
   original decoded full W1 or M06 begins:
   `OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED`.
2. Pinned-peer History `admit_page` checks the same actual Node owner
   **before** starting an unjournaled paid W1. A pinned peer identity
   is not a durable CPU/authority permit.
3. This is a typed local `DependencyUnavailable` stop condition for
   native pinned-polling owner recovery. The exact same literal received
   from a remote peer is a remote refusal and **cannot** impersonate
   this local stop condition.
4. Ordinary and V3-backed **noncontinuous** Nodes retain the original
   #493/#497 metered CPU/Host/epoch path. Already admitted blocks retain
   their actual consensus and durable State facts. This is not a new
   genesis namespace or an automatic fallback to another PoW/BFT.

This deliberately disables the unqualified continuous History path:
absence of a durable operation journal cannot be masked by increasing
Cookie difficulty, trusting signed peers or declaring a CPU observation
as a persistence receipt.

## What is required to restore the path

A subsequent independently qualified candidate must use the **existing**
continuous owner to bind exact request identity and generation, and
acquire a real durable operation scope with the correct task/owner policy:

- original signed caller/source/task/current-parent context and permission;
- a single persistent operation ID and startup/recovery link, committed
  before W1 and any externally retained effect;
- no new CPU burst, new Node or fresh debt allowance on peer/key rotation;
- live CPU checkpoints, joined scoped M06 workers and full durable settlement;
- crash at every phase, original receipt replay/unknown resolution and
  false StateRoot/Transcript rejection that preserve ledger invariants;
- actual Linux cgroup readbacks and 3 independent failure domains where
  the relevant public service proof claims are made.

Until that exists, **keep the continuous remote History import denied**.

## Validation and remaining gates

Added typed-error negative selector
`error::tests::continuous_history_without_a_durable_claim_is_a_local_owner_stop`.
Remote error text is explicitly not treated as local authority. Native
W1 and M06 receipt tests of previous source remain mandatory.

The complete Rust checkout and Cargo are not available in this isolated
execution container. This file does not assert compiled native tests,
physical kill, actual A03 results, GPU/ASIC attacker cost, useful-work
hardness or external independent P6 review. Every original P0–P6 gate
remains separate; the public PoN production flag stays false.

No self-approval, protected-main modification, automatic merge or
production activation.
