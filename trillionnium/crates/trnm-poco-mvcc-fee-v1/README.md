# PoCO object-MVCC and fee v1 candidate kernel

This crate is a **candidate-non-normative** local single-block execution
kernel. It speculates every transaction against one parent snapshot, validates
in gap-free transaction-index order, and deterministically re-executes an
attempt when an observed object version/value no longer matches. Canonical
serial execution remains the semantic oracle.

The bounded program supports Add, Transfer and explicit Revert over typed
versioned `u128` objects. It emits complete Success, Reverted and OutOfResource
receipts with exact read/write sets, object versions, roots, resource usage,
fee deltas, conflict sets and retry counts. Ordered bytes, state-read bytes,
state-write bytes and deterministic compute units use checked integer-ceiling
prices. Each transaction debits only its payer and emits fee deltas; configured
destinations are credited once per destination at block end in sorted order,
so no global collector is a per-transaction write hotspot.

SQLite schema v1 atomically commits the object set, complete receipts,
resource totals, aggregated fee deltas, block journal and durable roots. An
existing store is immutable-read-only preflighted before writable access.
Every open independently replays the complete block journal from immutable
genesis and compares exact receipts and object rows. Exact command replay,
applied/not-applied acknowledgement loss, permanent third-state
fencing, fresh reopen, schema/sidecar refusal and row/root tamper rejection are
covered.

Not implemented: global `AgentTransactionV1`, signature/capability/nonce
authorization, create/delete objects, the full resource/fee schedule, a real
parallel worker pool, JMT/global state proof, Order proof authority,
Agent/Market/Verify/Settlement store integration, whole-store anti-rollback,
Node integration, G2 completion, normative freeze or production activation.
