# Retained account archive and bounded witness prototype

This technical contract is subordinate to the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It describes an explicit research sidecar in
[account_archive_prototype.rs](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs).
No Node constructor, production store, M05/M06 execution, mining path, fork-choice
rule, transaction format or installed profile selects it. The existing full-state
root and the [revision12 capacity invariant](CONTINUITY_V1.md) remain authoritative.
No current ledger limit is enlarged by this module.

## 1. Architectural decision being tested

The current finite limit protects mandatory execution, but retained accounts and
their nonces eventually consume all available state keys. Removing an account with
zero balance would let the existing missing-account read default to nonce zero.
After another credit, an old signed transaction could then be replayed. The present
prototype therefore never removes an account leaf and never resets its nonce.

It separates three quantities that the current complete in-memory State combines:

1. **Authenticated retained account space:** every created account remains represented
   by its complete address, balance and nonce in an immutable account root.
2. **An operation's checked account view:** at most32 requested membership or
   nonmembership proofs are accepted together. Dropping this view discards only a
   disposable local copy; it does not delete a committed account.
3. **Persistent availability and history:** SQLite retains the node bytes and old
   branch roots that produce the proofs. This storage grows and has explicit local
   research budgets. A commitment alone does not make the committed bytes available.

The proposed direction for a later protocol is persistent authenticated account
storage with bounded witness/working-state access and explicit state-growth and
availability responsibility. This prototype tests retention, authentication,
branch identity and atomic publication. It is not an account-rent or eviction
protocol and does not establish unlimited permissionless entry.

## 2. Retained leaf and root relation

An account value is exactly `{balance: u64, nonce: u64}`. Projection from an actual
State requires `account:` followed by64 lowercase hexadecimal characters and rejects
extra or missing value fields, booleans, negative values and other malformed types.
Non-account records are not moved into this archive. The existing complete State
root is checked independently before its account projection is recorded.

All hashes use the existing `pon_wire::hash` framing: SHA-256 over `TRNM-PON1\0`,
the little-endian u16 tag length and tag, then a little-endian u32 length before
every part. The new domains do not reinterpret any installed state-tree domain:

| Value | Exact relation |
| --- | --- |
| Account path | `H("account-archive-key-v1", [owner32])` |
| Account leaf | `H("account-archive-leaf-v1", [owner32, balance_u64le, nonce_u64le])` |
| Empty leaf | `E[256] = H("account-archive-empty-v1", [])` |
| Empty subtree | `E[d] = H("account-archive-branch-v1", [E[d+1], E[d+1]])` |
| Nonempty branch | `H("account-archive-branch-v1", [left, right])` |

Path bits are consumed most-significant-bit first. Leaves occur at depth256.
The logical root is the complete256-level sparse relation, even though the
persistent representation omits unary paths. Address bytes are retained in every
leaf, so a path collision is rejected rather than merging two account identities.

A zero-balance account with nonce7 is a present leaf. A valid proof of that leaf
cannot be changed into nonmembership or into nonce zero. Genuine nonmembership
only states that the requested account is absent from this exact checkpoint; it
does not authorize deleting a previously present account or accepting a transaction.

## 3. Compressed persistent representation

SQLite uses a separate namespace, `pon-account-archive-prototype-v1`, and four tables:

| Table | Stored responsibility |
| --- | --- |
| `archive_meta` | Exact schema and network/parameters/genesis context |
| `archive_nodes` | Immutable content-addressed compressed leaf/fork records |
| `archive_checkpoints` | Immutable branch-unique checkpoint and complete binding |
| `archive_active` | Explicit selected checkpoint and local monotone generation |

Opening a database with other table names or another context is rejected. The
module is not an importer for the Node branch database. All checkpoint records are
checked against their stored id and branch columns at opening; the active root
record is also read and checked. Opening does not scan every descendant of every
retained tree and does not establish complete data availability.

A leaf record is49 bytes: tag0, owner32, balance u64le, nonce u64le. A fork record
is163 bytes: tag1, depth u16le, path32, left node id32, right node id32, left lifted
subtree hash32, right lifted subtree hash32. Its id is
`H("account-archive-node-record-v1", [record_bytes])`. Child hashes refer to depth
`fork_depth+1`. A loaded child must have strictly greater depth, the correct common
prefix and branch-side bit, and the exact committed lifted hash. Leaf owner bytes
derive the leaf path; no stored leaf path can replace that derivation.

Point reads use a bounded SQL substring before decoding: at most164 bytes for a
node and312 bytes for a checkpoint, including the extra byte needed to detect an
oversize record. Fixed-size context, active and index fields are bounded likewise.
An absent referenced row returns `DataUnavailable`; a present row with wrong bytes,
hash, depth, prefix or index returns an error. Neither outcome becomes an empty tree
or an absent account. Physical SQLite pages, its caches and operating-system memory
are outside these decoded-payload bounds.

Initial bulk construction sorts the complete input by account path and persists
only the final compressed shape. A nonempty single snapshot has at most `2N-1`
reachable nodes. Successor updates use copy-on-write paths. Old branch nodes and
transaction-local intermediate versions that were successfully committed remain
stored: cumulative table rows are not bounded by the last snapshot's `2N-1` shape.
Every observation therefore reports actual cumulative row count and logical payload
bytes separately from account count. These are not an RSS or physical-disk limit.

## 4. Checkpoints and actual State projection

A checkpoint binds network, parameters, genesis, observed branch id, optional parent
checkpoint id, height, optional original State root, account root, optional root-node
id and total account count. Its unsigned encoding concatenates those fields in that
order. Every optional hash is one presence byte plus32 bytes, with all-zero payload
required when absent. Heights and counts are u64 little-endian. This is275 bytes.
The id is `H("account-archive-checkpoint-v1", [unsigned_bytes])`; storage adds `AAC1`
and that id, for311 bytes. A missing root reference is valid only for count zero and
the exact empty root.

The two input classes stay explicit:

- `project_initial` and `project_successor` take supplied complete native-format
  State maps. The existing full root is computed and checked; a successor requires
  its complete before-root to equal the retained parent's original State root and
  its height to be exactly parent height plus one. It independently reconstructs
  both complete account projections and compares them with the parent root and
  final copy-on-write result. A supplied account cannot disappear or reduce its
  nonce on this parent-child transition. Actual signature, proof, funds and admission
  provenance remain the caller's responsibility. The separate Node regression
  supplies only states read from actually admitted packet ids.
- `seed_research_accounts` and `research_successor` operate on an explicitly supplied
  synthetic account collection. Their original State root is always absent. They
  can exercise an authenticated account space larger than the current ledger's
  65,536 **total state key** limit. The successor authenticates each supplied old
  leaf, forbids nonce decrease, admits at most32 distinct updates and cannot be
  used on a checkpoint that has a native State source root. It performs no M06
  execution and claims no native ledger entry.

Both complete State-root construction and projection reconstruction remain O(N)
scans; initial canonicalization, input collection and sorting include nonpreemptive
stages. This module does not turn the current executor into a witness-based executor.
The supplied complete account collection and the writer's input memory also remain
separate from the32-account checked read view.

## 5. Witness bytes and checked views

The `AAW1` research encoding is: four-byte magic, checkpoint id32, owner32, presence
byte, balance/nonce u64le only when present, then exactly256 sibling hashes in depth
order0 through255. It is8,277 bytes for membership and8,261 for nonmembership.
Malformed magic, presence, length, truncation and trailing bytes reject. JSON is an
observation encoding and is larger; the binary bound is not a JSON, allocation or
wire-service bound. No public transport uses this encoding.

A proof builder follows at most257 compressed node point reads, plus the checkpoint
lookup. When the requested key diverges inside a compressed path, it puts the entire
existing subtree, correctly lifted, at the first differing depth's sibling position.
All other omitted unary siblings are their exact empty hashes. Thus nonmembership
is an exclusion proof against the actual root, including the existing subtree.
It is never inferred from a failed database lookup. The builder re-verifies the
expanded proof before returning it.

`CheckedAccounts::verify` requires the exact context, checkpoint id, complete set of
distinct requested owners and one complete proof per owner. All proofs must pass
before the private checked map is constructed. A missing requested witness returns
`MissingWitness`; it is distinct from a verified `account=None`. Account and nonce
queries from this type convey no transaction signature, funds or admission authority.
An old branch witness remains usable as a historical observation against its own
checkpoint, but rejects when presented as evidence for a newly selected checkpoint.

## 6. Atomicity, branch selection and availability

Each seed or successor records its nodes and checkpoint in one SQLite immediate
transaction. A late invalid before-value, duplicate update, reduced nonce, budget
failure, conflicting branch identity or progress cancellation rolls back that
operation. Tests compare complete table contents for the small emitted fixtures,
not only equal row counts. Successful inactive checkpoints are intentionally retained.

Activation is a separate explicit immediate transaction using the expected complete
`(checkpoint_id, generation)` pair. A stale pair rejects before publication. The
generation increases locally even when selecting an earlier branch root. It does
not select a chain by work: the real Node test first applies actual required-work
fork choice, then projects the chosen native branch into this sidecar. A failed
activation does not erase an already committed inactive checkpoint.

This distinction preserves legitimate fork-specific nonces. A child cannot reset
nonce2 to nonce1, but switching from one admitted branch to another can expose a
different valid nonce at their different roots. There is no global nonce-max cache
that would reject a valid competing branch, and no local operational history is
rewound by the sidecar.

The current implementation checks only data needed by the requested operation.
An unavailable untouched descendant may remain undetected at opening or activation;
a later query that needs it returns `DataUnavailable`. A valid root is not an
availability certificate. Transactions use SQLite WAL and `synchronous=FULL`, but
the included interruption tests inject callback cancellation inside transactions.
They do not simulate physical power loss, a broken filesystem, or independent
availability providers.

Default local research budgets are1,000,000 accounts,2,000,000 cumulative node rows
and2,048 checkpoints, with at most4,096 changed accounts in a complete native-format
projection. Those finite operator budgets deliberately stop further writes rather
than silently pruning account nonces or old commitments. They are not consensus
parameters, a liveness guarantee or a proof that these limits are economically
adequate. No pruning or archive retention policy is activated.

## 7. Executable development evidence

The [component regressions](../../../../trillionnium/crates/trnm-pon-node/tests/account_archive_prototype.rs)
cover a real12-bit shared-prefix exclusion, exact binary round trips and malformed
proofs, zero-balance nonzero nonces, missing witness identity, cross-context/branch
rejection, callback rollback, competing active-generation CAS, missing/corrupt
records, checkpoint id-column corruption, source-root and account-schema mismatch,
nonce/deletion rejection and local budgets. Execution results must be attached to
the exact tested source; this document does not manufacture a passing run.

The separate [native projection regression](../../../../trillionnium/crates/trnm-pon-node/tests/account_archive_projection.rs)
starts from the installed development genesis. Its planned actual sequence comprises
43 admitted native packets,132 signed transfers,129 new transfer recipient accounts,
one matured initially absent miner account, two heavier-branch reorganizations and
three Node/archive reopens. It drains an account to zero, credits it again, rejects
the original signed nonce after that credit, and accepts its next nonce. It reads
each actual fork State by admitted packet id before projecting it. None of these
blocks executes from archive witnesses, and the regression does not approach the
old full-state capacity limit.

The explicit release-only synthetic campaign creates65,537 accounts in the independent
archive, beyond the old count of65,536 total ledger state keys. It retains its complete
input collection,32 full proofs, one copy-on-write update and proof, immutable old
root, active-generation observation, working SQLite database, a separately exported
SQLite snapshot, actual row/payload counts and page observations. Initial
construction, checked queries, update and reopening are
separate assertions. Its new output directory is mandatory; evidence is not erased
by a temporary test directory after success.

```bash
cargo test --locked -p trnm-pon-node --test account_archive_prototype
cargo test --locked -p trnm-pon-node --test account_archive_projection
TRNM_ACCOUNT_ARCHIVE_LARGE_OUTPUT=/tmp/new-account-archive-large \
  cargo test --release --locked -p trnm-pon-node --test account_archive_prototype \
  synthetic_archive_beyond_legacy_cap_retains_nonce_and_bounds_views \
  -- --ignored --exact --nocapture
cargo build --release --locked -p trnm-pon-node --example account_archive_vectors
target/release/examples/account_archive_vectors /tmp/new-account-archive-vectors
```

Both output paths and their sibling names ending in `-working` must be new. The small
[native vector producer](../../../../trillionnium/crates/trnm-pon-node/examples/account_archive_vectors.rs)
records synthetic and native-source snapshots separately, exports complete account
sets, exact checkpoints, all queried proofs and their binary bytes, original signed
native packet bytes, and complete SQL table snapshots before and after negative
operations. Each exporter creates its working archive in a fresh sibling directory:
an export directory named `native` uses `native-working/archive.sqlite`. The small
producer's original Node database also lives under `native-working/native-node/`.
All working files and sidecars remain separate retained originals. The independent
consumer's export directory contains exactly `archive.sqlite`, `observation.json`
and `finalization.json`.

Both exporters finish all archive-handle scopes before opening their final source
control connection. Their shared research-fixture helper verifies the actual main
database path reported by SQLite, records its synchronous setting and source page
geometry, and requires the actual `wal_checkpoint(TRUNCATE)` tuple `(0,0,0)`.
While this source connection remains open, it executes `VACUUM main INTO ?1` with
the fresh export filename as a bound parameter. SQLite creates a logically
consistent snapshot. An existing target is rejected; there is no main-file copy,
alternate export method or retry after a failed step.

The source control connection is explicitly closed. Its WAL sizes before and after
checkpoint and after close are observations; they do not establish that its
sidecar paths will remain stable. The export's qualification is checked separately.
An export reader opens with `SQLITE_OPEN_READ_ONLY`, requires journal mode `delete`,
reads the target's page count and page size, and explicitly closes. The actual
export header must have SQLite's magic and read/write versions `1/1`; its physical
size must equal its own page geometry, and its `-wal`, `-shm` and `-journal` files
must be absent. The exported page metrics in the large observation come from this
target. Source page metrics remain separately named in the receipt because
`VACUUM INTO` may compact the physical layout.

The receipt schema is `pon-account-archive-snapshot-finalization-v1`. It records the
method, source and export paths, actual source queries/checkpoint/close, export
SQL/open/queries/close, header bytes and file observations. Steps that did not run
are explicitly `NOT_ATTEMPTED`; actual errors remain errors. The helper writes the
receipt before its final acceptance decision. A receipt write or sync error also
fails and may leave a partial receipt. The same completed receipt object is
included in `observation.json`, whose `database` names the exported snapshot and
whose `working_database` names the original working archive. No original working
file or failed partial export is cleaned up by the helper. Consumers must check
the entire export file set and hashes through their own read-only validation;
successful source close does not substitute for that check.

Native regressions hold a real reader snapshot across a second connection's write
and confirm that a busy checkpoint prevents export. Another regression directly
exercises the shared `VACUUM INTO` step with committed data still in a nonempty WAL
while the main-file bytes remain unchanged. It then verifies the accepted export,
changes the source, and checks that the exported values and complete file bytes
remain unchanged. These regression receipts live in temporary test directories;
the exported large and small campaigns retain their artifacts in explicit output
directories. None of these observations certifies power-loss durability.

A separately implemented Python oracle reconstructs the uncompressed root relation from complete
account inputs and checks observations; agreement is implementation evidence, not
independent network service or future protocol acceptance.

## 8. Required work before a new capacity protocol

The experiment supports further architecture work only within its observed scope.
Replacing the current capacity limit requires a fresh selected context and a full
protocol contract covering at least the following:

1. **Complete execution relation.** M06 currently scans balances, obligations and
   other state, constructs a complete root, and verifies aggregate funds. An account
   witness alone does not implement these scans or authenticate aggregate sums.
   Exact block access sets, shared proof accounting, aggregate checks and all
   mandatory transitions require their own design and executable equivalence tests.
2. **Availability responsibility at admission.** Account creation, new miners,
   funded refunds and archives must identify who retains and serves the required
   bytes, who pays, how missing providers are replaced, and how already accepted
   mandatory obligations can still be serviced. Requiring an unavailable witness
   and then stopping is safe rejection, but does not establish chain liveness.
3. **Growth and retention costs.** Persistent nodes, old branches, recovery data,
   witness bytes and proof-serving work must be priced and bounded separately.
   A finite local resource budget can reject new writes; it cannot promise ongoing
   permissionless entry. Pruning needs exact retention/finality assumptions.
4. **Migration and replay protection.** This direction retains full nonces. Any
   later actual eviction or incarnation scheme would change existence and signed
   replay domains and requires a separately versioned protocol, exact old-signature
   rejection vectors and a migration rule. Silent zero-account deletion is excluded.
5. **Real service and recovery evidence.** Measure actual admitted account growth,
   large-state transaction execution, proof refresh after forks, provider loss,
   unavailable witnesses, bounded progress under competing reads/writes, process
   interruption and storage failures. The synthetic archive and its callback rollback
   tests do not replace these observations.

The prototype therefore advances the permanent-account design with executable
retention, bounded query authentication and explicit failures, while keeping current
ledger capacity, work qualification and production acceptance unchanged.
