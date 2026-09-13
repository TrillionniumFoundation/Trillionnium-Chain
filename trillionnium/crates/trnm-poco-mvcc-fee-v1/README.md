# PoCO object-MVCC and fee v1 candidate kernel

This crate is a **candidate-non-normative** local single-block execution
kernel. It speculates every transaction against one parent snapshot, validates
in gap-free transaction-index order, and deterministically re-executes an
attempt when an observed object version/value no longer matches. Canonical
serial scheduling remains the journal-audit and differential-test oracle; it
shares transaction semantics and codecs, not the worker scheduler. Primary
module: M06.

Workers compute the complete bounded program, resource usage, fee debit,
successor objects and transaction-local roots against the immutable parent.
They return private tentative deltas and cannot write canonical state. The
canonical transaction loop validates every version/value dependency, reuses
unchanged computations and re-executes stale computations exactly once. A
speculative failure is retained until its read set validates: an earlier
transaction can fund a later payer or transfer source. Fees, conflict/retry
fields, intermediate roots and final receipt bytes retain canonical ordering.

Root construction for the complete intermediate state, pending fee reduction,
canonical commit and durable journal audit remain serial. Every authoritative
open/operation still performs the existing complete-history audit. This change
does not remove schema, tamper, replay or rollback checks and does not establish
throughput, speedup or production readiness. Moving the audit out of the hot
path requires an authenticated checkpoint/anchor and bounded suffix recovery
contract; no unchecked audit cache or pruning shortcut is introduced.

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
authorization, create/delete objects, the full resource/fee schedule,
JMT/global state proof, Order proof authority, Agent/Market/Verify/Settlement
store integration, whole-store anti-rollback,
Node integration, G2 completion, normative freeze or production activation.

The focused parallel-execution regressions cover completed computation on
separate worker threads, immutable parent state, disjoint and shared-sponsor
loads, Reverted/OutOfResource receipts, stale success and stale failure,
canonical error selection, atomic rejection, reopen and exact journal replay
at 1/2/4/8 workers. They establish correctness of the bounded computation path,
not an independent protocol implementation or an end-to-end performance result.
