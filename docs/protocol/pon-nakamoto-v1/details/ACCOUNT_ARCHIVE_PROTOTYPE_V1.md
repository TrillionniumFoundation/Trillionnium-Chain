# Retained account archive and bounded witness prototype

This technical contract is subordinate to the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It describes an explicit research sidecar in
[account_archive_prototype.rs](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs).
No default Node constructor, production store, M05/M06 path, mining path,
fork-choice rule, transaction format or installed profile selects it. The explicit
[research execution wrapper](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_execution.rs)
can require archive proofs at semantic account point accesses while retaining the
complete native State and ordinary M06 relation. It does not execute from a partial
State. The existing full-state root and the [revision12 capacity invariant](CONTINUITY_V1.md)
remain authoritative. No current ledger limit is enlarged by these modules.

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
stages. The explicit research execution below does not replace these complete
inputs, scans or roots with a partial-State executor.
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

### Complete-State research execution

`account_archive_execution::execute` and `execute_with_progress` take immutable
`Settings`, an archive, one parent checkpoint id, the complete native parent State,
`BlockInput { transactions, height, miner, parent_id }`, and the complete required witnesses
within the execution-specific bound described below.
The wrapper derives the application configuration from Settings and fixes one
execution worker. It has no caller-supplied Config, worker override, activation
request or work-proof capability. The separate point-query interface retains its32-account bound; execution verifies
proofs in bounded slices and does not impose that fixed query cap on a whole block.
For the current M06 transaction tags1..23, each original parent record can require at
most one mandatory recipient, each transaction accesses at most two identities, and
the block can reserve one miner. The conservative checked bound is therefore
`parent_state_keys + 2 * transactions.len() + 1`, at most66,049 under the existing
65,536-key and256-transaction limits. New transaction kinds must revisit this bound.
A complete-State discovery pass records actual ordered semantic account accesses;
its result does not replace independently checked original-parent proofs. Neither
the discovery pass nor a larger proof set changes a Node consensus limit.

Before execution it checks the checkpoint's branch against `parent_id`, exact
successor height, complete parent State root, complete account projection/root and
account count. `CheckedAccounts::verify` binds every supplied proof to the exact
Settings context and checkpoint. Duplicate owners or invalid proofs refuse. Each
proven original value, including genuine absence, must equal that owner's value
in the independently reconstructed complete parent account map.

The shared M06 implementation then invokes a point-access gate before its semantic
account lookup. This includes transaction debits/credits, mandatory maturity and
expiry credits, and the recipient-existence reads required by the selected
continuity rules. Legacy contexts do not acquire revision12 reservation rules from
this wrapper. A missing witness is `MissingWitness`, even when the complete State
has an answer; no full-State fallback fills that missing proof. A valid parent-root
nonmembership proof permits the ordinary relation to create an account where that
relation allows it. It never permits erasing an existing nonce.

Witnesses authenticate the original parent. Current ordered values still come
from the complete State and the transaction write overlay, so an earlier credit
or transaction in the same block can legitimately change the next read. The gate
records each used owner. A successful computation rejects unused supplied proofs,
any account deletion or nonce decrease on that parent-child transition, and any
changed account that never passed the gate. Thus the final sorted requested and
used owner sets match. Non-account scans, aggregate balances/obligations, fees,
subsidy, conservation, capacity and complete successor roots remain ordinary
complete-State operations. The API does not authenticate aggregate sums using only
account point proofs or avoid the complete parent/successor scans.

The public M06 `execute_with_account_point_access` is only a serial callback hook.
It does not itself authenticate callbacks or create a checked archive capability;
the Node research wrapper supplies the checks above. Default M06 entrypoints pass
no research gate and keep their existing execution and worker behavior.

The returned `CheckedExecutionOutput` contains the actual M06 Output and a
`pon-checked-account-execution-v1` observation. That observation records context,
parent/checkpoint/height, complete State and account roots/counts, requested/used
owners and optional continuity capacity observations. Its flags require
`workers=1`, `complete_state_required=true`, `aggregate_account_scans_are_full=true`,
`consensus_admission=false` and `archive_mutated=false`. Serialization does not
construct authority. A historical checkpoint may support a replay of its own
parent; the wrapper does not certify that parent as the Node's current selected
head, verify its work, choose a fork or publish an archive successor. The caller
must separately perform ordinary Node validation/admission and any archive
projection/activation. Failure or cancellation returns no completed observation,
and neither the supplied parent nor archive is mutated by this computation.

### Authenticated complete-state companion

The separate `account_archive_execution::state_witness` research relation tests the
missing aggregate and mandatory-action commitments. It preserves the original
`pon-checked-account-execution-v1` observation, account witness bytes, account-tree
hashes and SQLite namespace. Its own schemas are
`pon-authenticated-state-commitment-v1` and
`pon-authenticated-state-execution-v1`, with a fresh
`checked-state-commitment-v1` digest domain. No ordinary Node constructor, header
field or installed context selects this digest as a ledger state root.

`prepare_state_witness` constructs serializable input claims from a checked complete
parent. `execute_with_state_witness` and
`execute_with_state_witness_and_progress` recheck those claims on every call and
take `StateExecutionInput { accounts, state }` alongside the original complete
parent and block input. They return the original checked execution output plus
the separate state observation. The M06
`execute_with_authenticated_state_input` hook does not authenticate a caller by
itself: the Node wrapper binds the evidence, while M06 also checks the complete
supplied non-account partition against its parent before using it.

The complete native parent remains the authority used to construct a private
anchor. The anchor binds Settings context, actual parent/checkpoint/height, native
State root, account root/count/balance total, and the complete non-account
partition with its count, escrow/reward funds and issued amount. Point membership
proofs alone cannot establish those aggregate values. A caller-supplied digest or
JSON observation cannot construct the private anchor or replace its full-parent
checks.

The digest uses the framing in section 2, with the following parts in this exact
order. Every count and amount is a checked u64 encoded little-endian; overflow is
an error, not a modular balance operation.

| Part | Meaning |
| --- | --- |
| network, parameters, genesis | The three 32-byte Settings context identities |
| state_root | The unchanged complete native State root |
| account_root | The unchanged archive sparse-account root |
| account_count, account_balance | Complete retained account count and balance sum |
| non_account_root | The ordinary native root algorithm applied to the complete non-account map |
| non_account_count | Number of rows in that complete map |
| escrow_balance | Sum of `remaining` over `task:`, `quota:` and `release:` rows |
| reward_balance | Sum of `amount` over `reward:` rows |
| issued | The exact u64 `meta:issued` value |

The constructor requires
`account_balance + escrow_balance + reward_balance == issued`, using checked
addition. This is the current native funds partition, not a generic interpretation
of every future namespace. The commitment schema and all recorded fields must
equal the full-parent reconstruction. The accompanying `StateWitness` separately
binds `parent_checkpoint`, `parent_id` and `parent_height`; those branch identities
are checked against the retained checkpoint and containing operation. They are
not additional parts of the state-commitment digest. An equal State on two branches
does not make one branch's witness an authority for the other.

The companion requires all non-account rows in canonical order, including retained
rows in namespaces that the current block does not modify. It compares their exact
partition commitment, count and funds against the anchor before using those rows
as actual execution input. A missing task, quota, release, reward or other row must
not disappear merely because a producer omitted it from the witness. Unknown
non-account namespaces remain committed bytes; committing them does not establish
application semantics for an unsupported command or model-cleanup profile.

Original-parent account proofs are combined before deriving each changed account
root. Shared sparse-tree paths must agree, every changed account needs its checked
old presence/value, and unchanged subtrees remain bound by the same parent root.
An inserted account increases count from proved absence. A retained account keeps
its identity and nonce when balance becomes zero. Deletion and nonce decrease on
one parent-child transition remain invalid. Balance/count deltas update the
anchored aggregates rather than summing only the presented membership proofs.
Every original path is checked before leaf updates. A recursively partitioned,
path-sorted frontier combines changed subtrees and checked unchanged siblings, so
later overlapping changes cannot restore an earlier sibling root. Its auxiliary
frontier holds O(P) proof references and a depth256 stack for P supplied proofs;
the full expanded proofs themselves still use O(256P) sibling hashes. Changed accounts are
ordered by owner bytes. All removed balances are subtracted from the anchored
sum before changed balances are added, avoiding a transient overflow caused only
by account ordering. Both the prologue and final change lists are relative to the
original parent; the final list is not a delta from the prologue.

The actual M06 mandatory prologue is an explicit comparison boundary. Its complete
non-account input and resulting account changes are checked before transaction
execution continues; the final ordered result is checked separately. The companion
compares the proof-derived account root and aggregates with full State rebuilding
at those boundaries. Missing account access, omitted non-account obligations,
mismatching shared paths or altered delta values cannot obtain a completed result.
The original executor still owns fees, subsidy, conservation, capacity, transaction
order and the complete native output root.

The observation records parent, mandatory and successor commitments, the exact
account and non-account changes, receipts, supplied non-account row count and its
compact JSON byte length. Non-account changes distinguish an absent record from
a present JSON-null value: an absent side is `null`, while a present-null side is
`{"value": null}`. The mandatory phase preserves the parent's issued amount;
the ordinary final M06 subsidy and conservation rules remain in force. Required
scope flags are `complete_non_account_partition=true`,
`account_roots_from_merged_proofs=true`, `full_state_reference_checked=true`,
`complete_state_required=true`, `consensus_admission=false` and
`archive_mutated=false`. These booleans describe a successfully checked observation,
not capabilities that a decoded caller can mint.

This is a complete-partition research witness, not a bounded partial-State backend.
The non-account input, anchor construction and full reference rebuilding still
scale with State. Execution uses the checked complete bound above; the standalone
archive query limit remains32. Missing, duplicate, unused or altered proofs still
refuse. The module itself grants no Node admission or archive mutation. Its checked
relation is also used by the separate [durable authenticated-state archive](AUTHENTICATED_STATE_ARCHIVE_V1.md),
which anchors actual admitted Node packets before publishing its own versioned
checkpoint and delta in one SQLite transaction. That sidecar does not install a
new Node root or establish proof availability or chain-liveness qualification.

The explicit non-account list is limited to 65,536 rows, while native canonical
key/value and total-State limits still apply. Its reported JSON length does not
bound allocation, SQLite pages, process RSS or network service. Cooperative checks
surround binding, mandatory-result checking, successor checking and output, and run
between original account proofs and account updates. Full scans, individual hashes,
serialization, signatures and native deep stages remain nonpreemptive.
`BeforeMandatoryVerification` and `AfterMandatoryVerification` name the checking of an already executed
native prologue, before any transaction follows it; they do not add callbacks
inside each due action. `BeforeSuccessorVerification` and
`AfterSuccessorVerification` similarly bracket the final result checks.

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

### Signed checked-execution campaign

The separate [checked-execution regressions](../../../../trillionnium/crates/trnm-pon-node/tests/account_archive_execution.rs)
exercise same-block creation/spend and self-transfer, original-parent proof coverage,
canonical transaction errors, complete source/branch/context binding, new-miner
reservation, reward maturity before a nonce-bearing spend, cancellation without
publication and old-branch witness rejection. A legacy-profile expiry-refund test
isolates the mandatory credit gate without continuity reservation checks or a
transaction account read masking it. These are source-defined tests; the exact
native command and its result remain separate evidence.

[`account_execution_vectors`](../../../../trillionnium/crates/trnm-pon-node/examples/account_execution_vectors.rs)
defines a distinct signed campaign under the continuity Settings. Its required
sequence is43 admitted native packets with20 signed transactions, two branch
reorganizations, three Node/archive reopens and29 original negative cases. These
counts are not the earlier43-packet/132-transfer projection fixture. For each
positive case it compares proof-gated serial M06 output with ordinary four-worker
execution and an actually mined/admitted packet, then separately projects and
selects the observed archive branch. Native before/after assertions retain the
unchanged parent and archive on failure. The research wrapper itself never performs
that admission, projection or activation.

The new `pon-account-execution-native-observation-v1` JSON retains the original
signed transactions and packet bytes, complete parent/successor States, exact
checkpoint/proof sets, native M06 receipts/roots/access observations, rejection
inputs/results, and branch/reopen observations. Its standalone archive snapshot
uses the same helper and exact three-file export described above; its working
archive and Node remain in the separate sibling `-working` directory. The original
`account_archive_vectors` schema and its `archive_used_for_native_execution=false`
scope retain their original meaning.

The account execution CI wrapper reads each UTF-8 JSON input with its own
32 MiB byte limit. It rejects symlinks, duplicate object keys, nonfinite constants
and malformed JSON. This delivery bound accommodates the complete signed fixture;
it does not change the 16 MiB cost-observation reader or the native relation.

[`account_execution_oracle.py`](../../../../formal/pon-nakamoto-v1/account_execution_oracle.py)
derives the configured development genesis and independently executes the exact
signed fixture relation for tags1–5,10 and11. It verifies main/consumer signatures,
ordered fees, task settlement/cancellation, quota use, expiry and reward maturity,
full State/account roots, proof coverage and the reported negative cases against
its own transition computation. Observed successor States and native deltas are
comparison outputs, not its transition inputs. Unsupported transaction tags fail
closed. Pure regressions cover the independent rules before any native comparison.

The oracle consumes only the emitted JSON and reports
`pon-account-execution-oracle-observation-v1`. It does not open the SQLite snapshot,
independently inspect its rows, rerun native recovery, verify W1/difficulty or
establish fork choice. Its branch/reopen checks compare the recorded states and
identities under the specified fixture sequence. The CI wrapper separately checks
the native snapshot receipt, physical header/page geometry, absence of sidecars,
complete export-file inventory and unchanged hashes. Complete native transitions,
JSON arithmetic agreement and consistent snapshot delivery have distinct scopes;
none establishes production capacity expansion or independent public availability.

From the repository root, using the default Cargo target directory:

```bash
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test account_archive_execution
cargo build --release --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example account_execution_vectors
trillionnium/target/release/examples/account_execution_vectors /tmp/new-account-execution-vectors
python3 formal/pon-nakamoto-v1/account_execution_oracle.py \
  --native-json /tmp/new-account-execution-vectors/observation.json
```

If `CARGO_TARGET_DIR` is explicitly set, use the actual built executable there.
The output directory and sibling `-working` directory must both be new. As with
the other examples, these commands require the actual built source and retained
execution identities; listing them declares no passing campaign.

### Authenticated-state companion campaign

The same vector producer accepts an explicit companion destination:

```bash
trillionnium/target/release/examples/account_execution_vectors \
  /tmp/new-account-execution-vectors \
  --state-witness /tmp/new-state-witness-vectors
python3 formal/pon-nakamoto-v1/state_witness_oracle.py \
  --native-json /tmp/new-account-execution-vectors/observation.json \
  --state-witness-json /tmp/new-state-witness-vectors/observation.json
```

The native destination and its working sibling must be new as above; the companion
destination must also be new. Omitting the option retains the original native
observation schema and exact three-file export. The companion destination contains
exactly `observation.json`, under `pon-state-witness-native-observation-v1`. It binds
the completed original native JSON bytes by SHA-256, its schema and exact context;
it does not add a fourth file inside the standalone SQLite export.

The required companion covers the same 43 block labels, with each supplied
`StateWitness` and its `StateExecutionObservation`, plus 22 native state-witness
refusal/cancellation cases. Each positive block checks two transitions, the actual
mandatory prologue and final successor, both relative to the original parent.
These are 86 checked state transitions on 43 existing block inputs, not 86 admitted
blocks or a second independent account-growth workload. The original 20 signed
transactions and 29 application-negative cases retain their separate denominators.

The [companion oracle](../../../../formal/pon-nakamoto-v1/state_witness_oracle.py)
independently derives the complete supported signed application fixture before
comparing the supplied commitments. It reconstructs all funds/count components,
complete non-account roots, mandatory receipts and original-parent account and
non-account deltas. Its sparse-path merger verifies the account witnesses and
derives updated roots/counts/balances, then compares them with its own complete
account-root reconstruction. A self-consistent forged aggregate digest is not an
authenticated parent. Missing, reordered or injected partition rows, altered
before-values, inconsistent shared paths and present-null/absence substitutions
are rejected by the separately defined relation.

Its `pon-state-witness-oracle-observation-v1` report requires 43 blocks, 86 state
transitions and 43 complete partition checks, and separately records the 29 source
application negatives and 22 companion negatives. The pure tests in
[`test_state_witness_oracle.py`](../../../../formal/pon-nakamoto-v1/test_state_witness_oracle.py)
exercise proof merging, aggregate arithmetic, partition completeness and companion
binding before native comparison. A test definition or required count is not an
execution receipt.

The existing CI wrapper has a separate v2 receipt for this expanded invocation.
It retains the original three-file native map and the one-file companion map,
checks the cross-file digest and complete file inventories, and requires all bytes
to remain unchanged through the original and companion JSON oracles and final
retention. Each input keeps the32 MiB JSON reader bound. Earlier v1 wrapper receipts
and their failures remain historical; neither version's source binding promotes
the other to executed evidence. Both oracles remain JSON-only for this fixture:
no SQLite inspection, new W1/difficulty/fork-choice validation, native recovery
rerun, generic model-cleanup semantics or public availability is established.

## 8. Required work before a new capacity protocol

The experiment supports further architecture work only within its observed scope.
Replacing the current capacity limit requires a fresh selected context and a full
protocol contract covering at least the following:

1. **Complete execution relation.** M06 currently scans balances, obligations and
   other state, constructs a complete root, and verifies aggregate funds. An account
   witness alone does not implement these scans or authenticate aggregate sums.
   The original research wrapper checks actual semantic point access. The separate
   companion now binds aggregate accounting and merges original-parent proofs at
   mandatory and final execution boundaries, retaining a complete non-account
   partition and full-State reference. A replacement backend must carry those
   commitments through persistent updates, replace the full-partition input with
   complete bounded discovery where appropriate, cover all mandatory accesses,
   and preserve executable equivalence against the full relation. The research
   proof limit cannot exclude otherwise valid forced obligations in a new profile.
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

The prototype advances the permanent-account design with retention, checked point
access and a full-parent-bound aggregate/mandatory relation, while keeping current
ledger capacity, work qualification and production acceptance unchanged. Its full
reference and complete non-account input remain explicit implementation costs.
