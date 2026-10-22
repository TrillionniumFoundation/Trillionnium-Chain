# Explicit native permanent-account growth v2

This document specifies the `permanent-account-growth-native-v2` development
profile. It is an implementation detail of PN2 in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not change historical PNH1/PNP1 networks, activate a production network,
or certify a throughput target. Test source and an observed successful run are
separate evidence; the commands below must be run on the exact integrated tree.

## Native state and authority

The selected backend is `StateBackend::PermanentAccountGrowthV2` in the existing
`Node`. It keeps the existing single-writer lock, initialization intent,
`native.sqlite`, WAL/FULL durability, `blocks`, actual `deltas`, `active`, and
reorganization/event journals. It adds immutable `archive_nodes` and one
`growth_states` record per admitted block. It does not put every account into
`kv`, a complete-State snapshot, an account sidecar, or an execution cache.

Each retained block has a COW account-tree root and a complete bounded working
partition. The commitment contains:

- Network, parameters and genesis identifiers.
- Permanent-account root, count, balance, and the declared maximum count.
- Working root, key count and the declared maximum working-key count.
- Outstanding escrow balance, pending reward balance and total issued units.

The commitment identifier uses `permanent-account-growth-commitment-v2`. Its
conservation relation is account balance + escrow balance + pending reward
balance = issued units. A public serialized commitment is an observation. It
cannot construct the private native parent source or verified wrapper.

A native operation binds the actual block header root to the actual stored
record and account-root pointer. The original-parent AAM1 multiproof authenticates
both membership and absence. Execution hydrates only proved present accounts
alongside the complete working partition. Every account read, including mandatory
credit reservation and credit, passes the checked proof gate. The gate rejects a
missing account witness; finalization rejects an unused witness and an account
write outside the original proof. Existing signature checks, transaction order,
nonce increments, mandatory expiry, reward maturity, fees, receipts and working
state transitions remain the shared M06 implementation.

The parent account aggregates are updated by the exact difference between the
proved original values and the executed successor values. The successor root is
calculated from that proof. The native writer independently applies the actual
account deltas to the parent's COW tree and requires its root, count and balance
to equal the executed commitment before commit. A zero-balance account remains a
leaf, including its last nonce. Deletion and nonce decrease are rejected.

## Explicit limits and continued mandatory work

| Quantity | Bound in this profile |
| --- | ---: |
| Permanent accounts | 1,000,000 |
| Working keys including reserved mandatory keys | 65,536 |
| Encoded working bytes including reserved mandatory bytes | 262,144 |
| Distinct future monetary owners | 32 |
| Accounts in one original-parent multiproof | 1,024 |
| Encoded account multiproof | 786,432 bytes |
| Complete PNP2 packet | 1,048,576 bytes |
| Transactions per packet | 256 |
| Transaction envelope | 2,048 bytes |
| M06 execution workers | 1 |

The working-byte calculation includes key bytes, eight bytes of per-row framing
and canonical value bytes. It reserves 256 bytes for each future reward-queue
entry, and 4,096 + 160 + 8 bytes for each future evaluation-archive entry. Existing
key-level reservations are split between working rows and future account credits.
Accepting an optional obligation cannot consume those reserved keys or bytes.
The future-owner bound includes every pending reward owner and every positive
escrow owner, not only records due at the next height. This bounds the worst-case
mandatory account witness even when the optional transaction list is empty.

These are new consensus limits selected by new parameters. The account limit is
a finite safety bound, not a claim of unlimited storage. Crossing the historical
65,536-account barrier is enabled by authenticated partitioned execution and COW
storage. Raising a complete-State limit alone would not supply those properties.
The original M06 complete-State root and historical continuity cap are unchanged.

## New network and wire profile

`Settings::with_permanent_account_growth_v2(namespace)` derives a fresh network,
parameters, genesis and native storage schema from the exact source genesis and
namespace binding. Context-bound bootstrap records are regenerated for the new
network. Transaction signatures bind the new network, preventing replay of an
old network's signed envelopes. This constructor is an explicit development
bootstrap, not a live-chain migration. Operator-owned external task deployment
settings are refused by this constructor.

The wire profile string is `PGH2/PNP2/AAM1/local-working-v2`.

| Object | Exact framing |
| --- | --- |
| Growth header | `PGH2` + 318-byte PNH1 field encoding + 32-byte witness digest; 354 bytes total |
| Work challenge | Domain `permanent-account-growth-challenge-v2` over the complete growth header |
| Block identifier | Domain `permanent-account-growth-block-v2` over the complete growth header and W1 trace |
| Witness digest | Domain `native-growth-account-witness-v2` over canonical AAM1 bytes |
| PNP2 packet | `PNP2`, growth header, u16 transaction count, u16 length + bytes per transaction, u32 witness length, AAM1 bytes, fixed W1 bytes |

Integer lengths are little endian. Packet decoding checks the total byte ceiling,
transaction bounds, AAM1 declared account count and exact remaining W1 length
before admitting the values. The growth header binds the original-parent witness,
transaction root, successor commitment and receipt root into the PoN challenge.
An old packet parser cannot accept PNP2. The existing public ingress remains on
its explicitly selected older wire profiles; these CLI operations do not silently
turn an old peer session into a growth session.

The current native growth builder and validator use the existing full
consensus-maintenance work primitive and full W1 verification. They do not accept
a digest-only substitute for work. General external model-task operator plumbing
and a public PNP2 peer admission protocol are outside this entrypoint.

## Cold validation and hot operations

Cold open checks the explicit genesis and reexecutes every retained non-genesis
block, including its original-parent account proof and actual W1. It checks
cumulative work, stored deltas, successor commitments and receipts. A single
frozen snapshot audits the union of all retained COW nodes, validates branch
links, independently recovers account count/balance, and rejects missing or
orphaned nodes. It also verifies active generation and the complete activation
journal. A highest-work admitted block may then be recovered through an atomic
activation.

Only after cold validation succeeds does the owner publish a process-local
SQLite `data_version` and exact-schema epoch. Hot calls recheck namespace identity,
context, schema and that epoch. A foreign SQLite write invalidates the epoch and
refuses service until a new cold audit. This is an explicit single-writer local
storage assumption, not a durable certificate or a statement that all historical
bytes are rescanned for every request. The epoch never authenticates a new peer
packet. Every new packet still undergoes full W1, account-proof and M06 checks.

Hot account proof construction reads only requested Patricia paths. Hot admission
clones only the bounded working partition and proved accounts, copies changed
account paths, and writes one bounded working record plus actual deltas. Difficulty
and median-time ancestry read fixed headers and trace identities rather than each
ancestor's complete witness and W1 body. Cold audit remains proportional to
retained history and COW nodes. The immutable genesis input remains in Settings
for exact reopen; it is not cloned into the hot execution view.

All admitted fork roots remain pinned. Reorganization changes the active root,
generation and undo/apply event history in one SQLite transaction. Old account
nonces, obligations and roots remain queryable on their original branches. Local
physical-operation or revocation histories are not undone by this root switch.
Pruning, root garbage collection and bounded total disk retention are not yet
implemented by this backend. Exhausted physical storage is a failed transaction,
not permission to delete an account or interpret an unavailable node as absence.

Explicit growth activation now checks its cancellation callback before each pair
of ancestor reads, each ordered undo/apply journal write pair, and each actual
steps/events read including EOF and the final reorg singleton. Cancellation keeps
the original error and rolls back all rows, active root and generation. Journal
readback streams exact rows in the original steps, events, singleton order rather
than collecting three duplicate journal vectors; the undo/apply paths still grow
with fork depth. `GrowthProgress` is a process-local API, with no signed or stored
schema change. These are cooperative boundaries, not preemption within one SQL
operation or hash. The original complete checks and the cold-open replay remain;
this change does not supply public PNP2 admission, global retention or PN2
qualification.

## Existing authenticated-v1 cost boundary

The separately selected growth backend does not change the original
`AuthenticatedV1` validation contract. In that backend, final admission reads the
complete parent for task eligibility and again before M06 execution. Post-write
parent/child readback and `check_active_before_commit` inspect actual stored
State and account graphs. Ordinary direct-extension activation uses the same
final integrity fence. These checks detect missing writes, trigger corruption and
changed persisted state while rollback can still prevent publication.

`native_authenticated::verify_history_with_cache` reads every ancestor from the
selected tip to genesis and checks actual record, packet and delta bindings.
Admission checks the previous active history and activation checks the new active
history. At height H these walks are O(H); admitting and activating consecutive
heights through H therefore performs O(H²) cumulative history reads. The existing
exact-input caches reuse arithmetic only after reading and comparing actual
bytes. They do not cache history validity or remove the complete-State/account
scan. `activate_observed` separately walks the target's headers to check their
timestamps against the current observed clock. The bounded `recent` header
reader is already batched and does not read complete historical packet bodies.

Safe constant-cost work may share repeated parent inputs, a recent-header window,
or already read parent records **within one fixed SQL snapshot**, while retaining
all applicable task, owner, root, error-order, cancellation and final writeback
checks. No cross-request validity cache, old-generation snapshot substitution or
omitted pre-COMMIT check is authorized by this analysis. Replacing those checks
requires an explicitly specified storage trust/epoch relation and its fault
coverage, as in the separate growth profile. Source analysis alone does not
attribute measured CPU to a phase or establish a throughput gain.

The existing `Node::native_history_arithmetic_observation()` reports cumulative
CPU and wall observations for sixteen nested stages, including `state_at`,
`admission`, `activation`, `verify_history`, `account_graph` and parent binding.
Nested stage totals must not be added as independent costs. Public-service
experiments must still charge actual proof, execution, activation and response
work to the original total CPU budget. A successful growth fixture cannot qualify
the unchanged authenticated-v1 public-service campaign. The relevant existing
implementations are [Node admission and activation](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
and [authenticated history checks](../../../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs).

## Current working snapshot and funding adapters

`Node::growth_current_working()` returns `GrowthWorkingSnapshot` with block,
height, generation, the complete growth commitment and complete bounded working
rows, all from one native read transaction. An adapter must select the actual
`task:`, `quota:`, `release:` or `reward:` row from that snapshot. A caller's amount
or a row from a different block is not funding authority. The account root and
working root are separate, so the adapter must bind the growth commitment ID
rather than pretend that the working-only map is the entire historical State.

`growth_account`, `growth_account_multiproof`, `growth_observe`, and
`growth_working` also require the selected backend and current storage epoch.
The historical `read_active` and complete `state_at` interfaces explicitly refuse
this backend. `GrowthPacket`, `admit_growth` and `growth_activate_with_progress`
are the versioned native transaction interfaces.

## Native funding and exact payment observations

`Node` implements the M12 `NativeFundingOwnerV1` contract for the legacy,
authenticated and permanent-account growth backends. `observe_funding` reads the
actual current anchor and requested monetary row in one native snapshot. Missing
rows remain absent; an API-supplied amount cannot become an escrow balance.

`observe_payment` independently verifies an ordinary payment already executed on
the currently active ancestry. A read-only M06 `CanonicalTransitionObserver`
observes the exact mandatory transition or selected canonical transaction patch.
The owner publishes the observation only after the complete payment block passes
W1, parent/task eligibility, signatures, M06 execution, successor state and receipt
root checks. Growth verification also rechecks the original account witness,
actual stored working record and actual deltas. A partial callback observation
from a failed block is discarded.

| Source | Exact ordinary transition | Subject | Gross / beneficiary credit |
| --- | --- | --- | --- |
| Task | Signed provider receipt followed by owner tag5 settlement | The receipt output hash | Entire task escrow / entire escrow |
| Release | Mature tag9 claim with the actual allocation path | Contribution ID in the allocation | Exact native budget × score / total / the same amount |
| Quota | Tag11 provider envelope plus the actual consumer signature | Result hash in that use | Units × native unit price / gross minus the actual native fee |
| Reward | Actual mandatory maturation of the original reward row | Original reward ID | That individual reward amount / the same amount |

The operation is the exact signed transaction ID, or the original reward ID for
maturation. The query's maximum gross amount is an upper bound, never the source
of the observed amount. Quota use may validly have zero net beneficiary credit
when its gross cost equals its fee. Account net differences and escrow remaining
differences alone do not prove an individual payment: other transfers, fees or
maturing rewards can affect the same account in that block.

The current bounded lookup scans at most 4,096 active ancestors and reads at most
16 MiB of candidate packets. Actual per-source deltas only locate candidates;
they do not grant payment authority. An older or unavailable proof is explicitly
refused. This bounded lookup is not an indefinitely retained public payment index.

M12 records local resource use, external operation intent and historical native
payment observations in its separate durable journal. It issues no replacement
currency. After reorganization the Node refuses a payment absent from the new
active ancestry, while the local journal preserves an earlier observation and
irreversible physical cost. Replaying that recorded operation does not issue a
second payment or dispatch an external effect again. An external effect operation
ID and a later ordinary payment transaction ID are distinct replay identities.

## PN6 source-preserving rehearsal candidate

`Node::rehearse_growth_migration_v2(destination, namespace)` materializes an inert
candidate for a quiescent legacy or authenticated development source. The source
owner and an IMMEDIATE SQLite transaction fence concurrent writers. Every retained
branch is rechecked using its original W1, original task context, ordinary signed
transactions, receipts, state root, deltas, snapshots and ancestry. The complete
old-schema tables, including replay/outbox records, local pool removals and
reorganization history, are copied without changing their namespace or content.
The source directory's durable bytes remain unchanged.

The published directory contains:

- `source/native.sqlite`: the complete original schema and retained history;
  an existing authenticated-migration receipt is preserved alongside it.
- `native.sqlite`: a distinct **rehearsal-only** schema containing actual COW
  account nodes and a growth checkpoint, with all non-account rows unchanged.
- `growth-rehearsal.json`: exact source anchor and generation, typed per-table
  digests, fresh candidate context, roots, aggregate balances and file hashes.

The checkpoint preserves the source's actual height. It neither resets absolute
maturities/deadlines to height zero nor rewrites account nonces. All task, quota,
release, reward and other working rows retain their original bytes. Old work and
signed history stay in the source archive; they receive no weight or execution
authority in the fresh candidate context. Ordinary Node openers reject the
rehearsal schema, which has no admission or activation interface.

`verify_growth_rehearsal_v2(source_settings, directory)` independently opens the
source archive with READ_ONLY SQLite, replays all retained branches and local
history, rebuilds the candidate relation from its actual State and audits every
COW node. It does not trust a previous migration process or cached verification.
The expected original Settings remain an explicit input. File hashes supplement
these semantic checks; editing a hash in a receipt cannot repair a rewound nonce
or invalid historical block. Candidate receipt hashes must still be bound by the
later external release/governance decision; this format supplies no signature or
production authority of its own.

Publication uses descriptor-bound directories and no-replace rename. A durable
pending marker fences interrupted candidates, including a process exit after
publication and before the final seal. Failed stages remain available for review;
retry uses a fresh destination. Existing destinations and late racing destinations
are never replaced. External task/mining/continuous owners, active or unknown
public-service domains, incomplete reorganization and unrecognized source files
are refused by this rehearsal.

This is **materialized rehearsal evidence**, not an executable cross-network
migration. All `migration_executed`, `old_work_promoted`, `consensus_activation`
and `production_enabled` flags remain false. Separate M09/M12 physical-operation
journals are not silently copied or reset (`external_journals_imported=false`).
Draining/reconciling those owners, defining all context-bound work/evaluation
transitions, independent acceptance and governed activation remain separate PN6
requirements. The existing fresh development genesis constructor does not close
those requirements.

## Local CLI

The existing `trnm-pon-node` executable exposes explicit `growth-*` commands.
Every command requires `--development`, `--store`, `--growth-namespace` and
`--genesis-time`. Reopening the store requires the same namespace and timestamp.
Input transactions are externally signed envelope hex strings in a JSON array.
The CLI does not read signing secrets or manufacture transaction signatures.

```sh
trnm-pon-node growth-status --development --store /tmp/growth-node \
  --growth-namespace example-v2 --genesis-time 1

trnm-pon-node growth-mine --development --store /tmp/growth-node \
  --growth-namespace example-v2 --genesis-time 1 \
  --transactions /tmp/signed-transactions.json --miner <64-lowercase-hex-public-key> \
  --timestamp 11 --output /tmp/first.pnp2

trnm-pon-node growth-submit --development --store /tmp/growth-validator \
  --growth-namespace example-v2 --genesis-time 1 --packet /tmp/first.pnp2

trnm-pon-node growth-working --development --store /tmp/growth-validator \
  --growth-namespace example-v2 --genesis-time 1 --key meta:issued
```

Other commands are `growth-recover`, `growth-account --owner`,
`growth-witness --owners`, `growth-make`, `growth-export --block --output`, and
`growth-activate --block`. Witness owners are a bounded JSON array of owner hashes.
`growth-submit` also accepts bounded `--packet-stdin` instead of a file.
New output packet files use no-clobber publication. Unknown options, old backend
selectors, malformed packet inputs and output collisions are refused before
opening or creating the namespace.

## Observed development runs — 2026-10-22

The following are completed local native observations on implementation increments
based on `1131d067f7ae4e6ccb1bf27e05df34818311daec`. They are not final combined
source/merge qualification: later PN1 and PN4 edits were still in progress, and
no final combined source manifest had been sealed for this batch.

| Observation | Actual result | Scope of the result |
| --- | --- | --- |
| Initial release-mode growth scale run, through growth increments 02/03 | PASS in 216.25 seconds; 65,520 explicit genesis accounts became 65,552; 34 signed transfers, two cold reopens and one heavier-fork reorganization | Actual Node/SQLite/W1/M06 execution; the initial dormant accounts were preallocated fixture input |
| First growth block in that run | 35 original-parent witness accounts; six working keys; 417 additional COW nodes relative to genesis | This is one declared finite block, not a million-account acceptance or total disk bound |
| Separate four-owner proof query after that block | 59 archive point reads; 3,722 encoded witness bytes; no expanded witnesses allocated | Query owners are development accounts 0, 999, 40,000 and absent account 777; these numbers are **not** the whole block's witness size or all admission I/O |
| PN6 native rehearsal suite, job `1a16282a4b9-1b6abb-2da2` | Exit 0; six tests passed; actual legacy-source and authenticated-source candidate directories exported | Full source/history preservation and inert checkpoint verification; no migration execution or activation authority |

The PN6 log is `pn6-growth-rehearsal-tests.log` under the actual local run root
`/home/qian-qi/work/pon-upgrade-implementation-20261018/pn-closure-20261022`.
The exported candidates are its `pn6-growth-rehearsal-candidates` directory,
containing separate `legacy-source-candidate` and
`authenticated-source-candidate` outputs. This is an operator-local evidence
locator, not a repository artifact link or a source-manifest substitute.

The six PN6 tests cover preserved zero-balance nonce and live liabilities;
corrupt inactive history; cancellation and late checkpoint mutation; a rewound
archived nonce with a resealed file hash and forged activation flags; actual
child-process exit before publication; and a late destination collision without
replacement. Each successful candidate is independently reopened from its
archived source and checkpoint. A child-process exit is not physical power-loss
coverage. The [retained rehearsal tests](../../../../trillionnium/crates/trnm-pon-node/src/store/authenticated_migration_tests.rs)
define those exact boundaries.

The earlier scale run preceded the optional evidence exporter, so its temporary
SQLite directory was not retained after the successful test. Its original log
and measured values remain a historical observation. A fresh create-only scale
export and all applicable final committed-source/binary/merge gates remain
required; no successful earlier run may be relabeled as that final result.
The [scale fixture](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/tests.rs)
retains the same account counts and failure assertions for the rerun.

## Reproducible verification

Run project preflight before building. The repository still requires the complete
exact-tree gates in AGENTS.md; the following commands isolate the new behavior.

```sh
bash scripts/project-preflight.sh
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-protocol native_growth_v2
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_growth_v2 -- --test-threads=1
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen \
  -- --ignored --nocapture --test-threads=1
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test native_growth_cli -- --test-threads=1
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_budget_bridge -- --test-threads=1
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_payment_bridge -- --test-threads=1
CARGO_BUILD_JOBS=6 cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib growth_rehearsal -- --test-threads=1
```

Set `TRNM_NATIVE_GROWTH_V2_EXPORT_DIR` to a new, nonexistent directory when
running the ignored scale test to preserve its actual SQLite database, full
explicit genesis/settings input, every admitted PNP2 packet, source hashes
embedded at compilation, test binary hash and measured observations. Export is
create-only; a failed or successful earlier directory is never overwritten. The
recorded Git HEAD is informational for a dirty checkout, and does not replace
the embedded relevant-source hashes or exact-tree integration gates.

The explicit scale fixture starts with 65,520 dormant/funded genesis accounts.
Thirty-two signed transfers create actual new recipients, crossing to 65,552;
a funded dormant account then signs nonce 8 and empties its balance without losing
its nonce or existence. The test checks actual native admission, full account-root
reference agreement, COW writes, compact point reads, cold reopens and a heavier
fork. The preallocated dormant genesis is declared fixture input, not claimed
65,520-account historical growth. Its measured path counts are observations of
that workload, not a throughput extrapolation or an acceptance result at one
million accounts.

Other tests cover native task escrow settlement/expiry, reward maturity, old/new
wire separation, independent fixed header/hash vectors, fully re-proved invalid
account witnesses, SQLite disk-full rollback, cancellation and an abruptly exited
child process before commit. Failed observations must be preserved alongside
subsequent successful runs.

The payment tests execute actual signed task and quota lifecycles, multiple
payments and further spending in one block, a complete attested development
release/evaluation/claim sequence, individual reward maturity, cold reopen and
reorganization on all three native backends. Attested development evaluation in
that fixture is not evidence of real model gain.

Set `TRNM_GROWTH_REHEARSAL_EXPORT_DIR` to a new absolute directory when running
`growth_rehearsal_preserves_all_native_facts_nonce_liabilities_and_cold_checkpoint`
to retain both native source-format candidates and their original fixture Settings.
The export is create-only. Additional rehearsal tests reject corrupt inactive
branches, cancellation, process exit, late disk mutation, late destination races,
a nonce rewind with an updated file hash and fabricated activation flags.
