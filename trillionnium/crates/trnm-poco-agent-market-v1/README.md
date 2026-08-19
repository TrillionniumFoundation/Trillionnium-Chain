# PoCO Agent + Market v1 local kernel

This crate is a **candidate, non-normative, local execution kernel** for the
first bounded PoCO-Agent/PoCO-Market tranche. It cannot activate protocol v1 or
serve as a production node.

The implemented transition order is intentionally exact:

1. a controller-authorized capability is admitted;
2. a controller-authorized session grant creates all declared nonzero nonce
   lanes atomically;
3. task creation debits an existing requester account and creates both the
   immutable Task offer/Open state and its fully funded Escrow in one SQLite
   transaction;
4. an active provider bid binds the exact Open task revision;
5. requester lease acceptance atomically consumes the Bid, changes
   `Task Open -> Leased`, reserves Escrow, holds provider Bond, and creates the
   Lease as Offered; and
6. provider acceptance changes only `Lease Offered -> Active`.

Every delegated operation verifies a strict Ed25519 statement binding context,
operation body, capability generation, session grant/generation, lane, exact
nonce, and expected lane version. All lanes share the capability budget.
Exact replay returns the original durable receipt without another state or
nonce change.

The bounded verifier enforces every representable Task, model, tool,
verification-profile, privacy-lane and exact resource-list scope. A market or
endpoint scope has no carrier in this tranche and therefore fails closed;
`CommittedSet` likewise remains unusable until its commitment verifier exists.
Provider acceptance resolves `Lease -> Task` before applying any task-scoped
capability.

Fresh-genesis trust is immutable. Execution height is supplied separately by
an `OrderFinalizedExecutionContextV1` whose expected height/block ID is an
exact durable compare-and-swap and whose successor is monotonic. This input is
not yet backed by Node Order-proof authority, so Node integration remains
false.

The SQLite store uses schema version 3, checksummed metadata/object/operation
rows, a direct-successor finalized-block marker chain (including empty blocks
and multiple operations in one block), gap-free operation sequence, immutable read-only preflight for an
existing file, sidecar rejection, no migration, fresh-connection confirmation,
durable state, operation-journal and finalized-block roots checked on every verified
open/read/write, and a permanent fence for an ambiguous third state. It has no whole-store
anti-rollback authority; that still requires the future whole-node checkpoint
and CAS contract.

Deliberately out of scope:

- global `AgentTransactionV1`, access-list, fee-payer and MVCC wire semantics;
- identity/key/account/bond creation or administration;
- capability delegation/revocation and successor session generations;
- task start, execution, result, challenge, settlement, cancel, timeout, or
  migration;
- authenticated state-tree roots, Node/P2P integration, production signing;
- complete PoCO AI-native v1 implementation, freeze, activation, or G2 global
  completion.
