# Whole-tree inventory and HIA migration audit

## Scope and conclusion

The audited consolidated baseline is `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`.
The whole tracked tree, active Cargo package graph and all M00–M17 ownership
boundaries were inventoried. Detailed semantic comparisons and native tests cover
the implemented components listed in [the native guide](README.md). This is not
a claim that every one of the 702,001 retained Rust physical lines was manually
reviewed, or that every historical campaign passed.

**The full replacement is incomplete.** Twenty-seven kernel units and four native
foundations account for all 36 current HIA source files. Native connected-stream
I/O and a finite transaction owner now exist, but no whole original package has
an accepted retirement witness. There is no complete HIA node executable,
typed branch/replay/outbox owner or complete native identity/signing stack. The
nine integration/qualification gates remain open.

## Baseline inventory

| Measure | Baseline count |
| --- | ---: |
| Tracked files | 41,834 |
| Tracked bytes | 3,999,565,648 |
| Evidence files | 36,222 |
| Evidence bytes | 3,804,721,963 |
| Active Cargo packages | 26 |
| Rust files inside those packages | 1,621 |
| Rust physical lines, including tests | 702,001 |

About 95% of tracked bytes are evidence. This is not 4 GB of independent active
application implementations. No identical Git blobs were found among active
workspace Rust source files in the cleanup inventory. Deleting whole source
packages merely because another file has a similar name would remove behavior.
The empty root README was an existing owner choice and is unchanged.

## All original package owners

The table preserves the original ownership contract. “Partial” means that only
named kernels are implemented; it never means the package can be removed.

| Package | Module | HIA coverage | Original retained responsibility |
| --- | --- | --- | --- |
| [trnm-types](../trillionnium/crates/trnm-types) | M00 | Unported | Shared task/identity/transcript/transaction data; delete consumption-consensus governance controls. |
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Partial: `executor/schedule`, `math/binary64` | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Unported | Retained executor microbenchmark; not ledger throughput. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Unported | Bounded admission, nonce reservations and durable handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Unported | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Unported | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Unported | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Unported | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Unported | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Unported | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Partial: `state/json_string`, `state/json_value` | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Unported | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Unported | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Unported | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Unported | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Unported | Independent exact CAS and durable Unix service; generalized owner frontier only. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena`, `crypto/sha512_arena`, `crypto/ed25519_group`, `crypto/ed25519_verify`, `crypto/sha256_stream` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
| [trnm-verification-profiles](../trillionnium/crates/trnm-verification-profiles) | M11 | Partial: `verification/closed_round` | Reusable evaluation/profile contracts and exact bounded integer BA normal form; no stake-quorum backend, model-parent authentication or general functional-equivalence authority. |
| [trnm-transport](../trillionnium/crates/trnm-transport) | M04 | Partial: `transport/replay` | Extract generation-bound authenticated frame admission; delete pacemaker and node scaffold. |
| [trnm-audit-events](../trillionnium/crates/trnm-audit-events) | M17 | Unported | Normalized local audit event data; no consensus or durable owner. |
| [trnm-governance-guard](../trillionnium/crates/trnm-governance-guard) | M01 | Unported | Local proposal/timelock, role separation and optimistic version checks; no network governance authority. |
| [trnm-escrow-vault](../trillionnium/crates/trnm-escrow-vault) | M12 | Unported | Pure in-memory escrow conservation reference; no second production ledger or durability claim. |
| [trnm-pon-node](../trillionnium/crates/trnm-pon-node) | M15 | Partial: `transport/authenticated_request` | Native development composition with a single branch/replay/outbox SQLite owner, explicit maintenance choice, bounded public entrypoints, typed local error identity, checked history projections, explicit revision16 model/task-window CLI context binding, and optional fresh PQ transport-only ownership; account/task/install authorization is not PQ-migrated and no publicly qualified deployment is claimed. |
| [trnm-sqlite-io-boundary](../trillionnium/crates/trnm-sqlite-io-boundary) | M15 | Unported | Reused process-owned native SQLite boundary and executed-mutation transaction observer from c165; bounds History graph readback reuse to the same immediate transaction and fixed SQLite build. It adds no consensus or deployment authority. |

## Native toolchain boundary

The exact Hepta main revision was re-read as
`f33d8da316de8fdf27b504371f1a5310997ff548`. The actual compiler used by the tests
has SHA-256 `87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
The original cold gate passed, with its original execution/cleanup budgets;
[the binding](qualification/compiler-binding.json) retains the complete scope.

Core v8 has a closed arithmetic/buffer/resource opcode set and internal calls.
The standard standalone ABI is a bounded stdin/stdout filter. Specialized Hepta
file publishers have real Linux adapters for file creation, writes, fsync and
atomic publication, but those adapters are not a general HIA node I/O API.
A complete node requires an explicit platform ABI, a real durable transaction
owner, network readiness, clock/randomness/stop handling and separate native
fault/recovery qualification. A byte buffer containing a descriptor number or a
caller-supplied “authorized” boolean cannot provide those capabilities.

The [Linux platform fixture](platform/README.md), [stream reactor](platform/reactor/README.md)
and [transaction owner](storage/README.md) use the fixed compiler to emit native
adapters around compiled HIA policy. The static ELFs perform actual syscalls;
no invented foreign-call opcode or host-language runtime implements the policy.
The first finite fixture's blocked-call deadline failure remains retained.
The reactor admits connected FIFOs/streams and uses epoll, monotonic absolute
deadlines, cancellation and private generation/rights slots. It does not admit
ordinary files or certify a hard fsync deadline. The transaction owner performs
actual locking, immutable transaction publication, HEAD replacement and sync,
then validates persisted data on reopen. Its 16 MiB / 4,096-commit profile and
fail-closed interrupted initialization do not replace the original Node's full
capacity, typed state transitions or initialization recovery.

The [state-root implementation](STATE.md) matched an independent bottom-up oracle
at 65,536 actual entries in 299.705821145 seconds in exact `96a0846` CI. The prior
353.568397442-second local observation remains retained. The same artifact's source,
maximum-count observation and later final-driver controls are bound separately
in [the retained report](qualification/state-root-development.json). Maximum
count with short values is not a test of every row holding its maximum value.
The unchanged original four-second service acceptance is not qualified.
The real Node directly owns `rusqlite::Connection` in `Node.db`, implemented
in `store.rs`. `TransactionScope` records SQLite operation boundaries; the
optional `OwnedConnection` wrapper is not that owner. Replacing checkpoint
values alone cannot retire this branch/replay/outbox store.

The fixed source evidence is linked in [the native guide](README.md). No
specialized filesystem, socket, cryptographic or full-node qualification is
inferred from the compiler fixed point.

## Observed integration failures

The fourth repaired candidate `96a0846e383745f88e033c7db2abc0611f1dae63` passed
[both HIA jobs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43746877132):
160 tests, 36,222 shared-runner native calls, zero skips, failures or errors.
All four then-existing original Rust adapters and 17 original Rust tests ran.
The [exact report](qualification/native-ci.json) binds only that source set.
OS 25/25, reactor 49/49 plus 13 native contracts, and storage 48/48 plus 14 native
contracts passed; actual traces were captured. State-root's separate 86 raw
calls include the complete 65,536-row case. The source job passed 113 original
PQ negative tests and the full historical readers.

Later scheduler, typed Value and full request sources require their own exact
CI. Their reports distinguish real native execution from original Rust NOT_RUN.
The source-derived scheduler reader-group regression is repaired in HIA while
retaining the original library as an independent oracle. The seven-strategy
port is repository work outside the normal Node dependency closure. The Value
profile is explicitly finite; complete-State grammar-before-limit order is open.
The full request executes strict signature verification over the complete domain,
but private owner integration and original service budgets remain open.

The complete original CI also exposed these distinct outcomes:

| Finding | Classification and action |
| --- | --- |
| Fourth storage CLI startup failed without ambient Python path | Run `43746152828` failed with `ModuleNotFoundError` before storage/Rust/kernel tests. Explicit repository-root imports and fresh-cwd regressions were added in `96a0846`; exact run `43746877132` passed. |
| Hosted-cost missing-index dispatch could overwrite an old receipt in a copied candidate | Independent temporary-view reproduction found the prepublication fallback. Current CLI always uses the read-only checker; both missing and dangling index paths return 2 without modifying retained bytes. The actual failure is retained. |
| Three original retained stderr logs were absent from the third published tree | Introduced by ignored-file staging. The unchanged PQ archive reader failed in run `43741641815`; exact original bytes were explicitly tracked in `79fc1d4`, whose run `43741974022` passed. The failure and repair remain visible. |
| Distributed source inventory omitted `config/hia-migration-v1.json` | Introduced by the migration. Baseline had exactly 1,745 matching entries; candidate required 1,746. The unchanged original generator now adds the missing include and its original check passes. |
| PQ source corpus retains stale plan and generated-inventory blob pins | Introduced by the first and second migration commits, respectively. Those exact current-source bindings were refreshed under the existing reconciliation procedure. The fourth cleanup also requires the precise current public-readiness CLI binding because it adds archive dispatch; original checker functions remain unchanged. All 1,177 evidence pins and all unrelated source pins remain fixed. The unchanged checker succeeds with status HOLD_NO_GO, and all 113 original negative tests pass. This repairs source consistency and grants no native PQ acceptance. |
| Historical artifact `11531476198`, run `37730166589`, is unavailable | Existing retained evidence gap. The current download job found zero matching artifacts. No new sample substitutes for the missing original. |
| W1 original/fresh and arm64 pressure confirmation miss the original deadline | Actual service failure. All seven honest submission ACKs were observed, but independent native history replay reached the four-second deadline before six-depth confirmation. The three pressure outcomes remain 0/1. |
| Main baseline arm64 service gate already failed | Confirmed from run `43729710156`, job `132859243865`; only its outer controller was inspected, so its detailed cause is not asserted to equal the current deadline diagnosis. |

Current failure sources, exact job/artifact identities, ZIP hashes and refusal
observations are retained in [development-observations.json](qualification/development-observations.json).
The candidate service ZIPs were read and verified independently. Original
business code and relevant service scripts were unchanged between the baseline
and first candidate. Successful compilation, setup, invariant/accounting checks
and native unit tests do not turn a failed business confirmation into a pass.

## Cleanup result and limits

The current tree removes 607 obsolete checkout-repair files, 14 sealed CI ZIPs,
13 joint-resource archives, four large PQ triage streams, 885 public-readiness
pre-correction payloads and 32 hosted-cost containers/shards: **1,555 removed
copies totaling 1,312,946,846 original bytes**. All remain recoverable by exact historical Git object with original
SHA-256/size bindings. The PQ capture's other 29 smaller records remain as
byte-identical current copies in its retained directory. This cleans current-tree
copies; Git history is not rewritten.

- [Checkout preparation archive](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json)
- [Sealed CI ZIP archive](../evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json)
- [Joint-resource archive](../evidence/pon-joint-resource-contract-20261109/ORIGINAL_ARCHIVE_INDEX.json)
- [PQ triage capture](../evidence/pq-authority-preflight-20261108-9d315/NATIVE_TRIAGE_ARCHIVE.json)
- [Public-readiness pre-correction archive](../evidence/pon-public-readiness-v1/PRE_CORRECTION_ARCHIVE.json)
- [Hosted-cost archive](../evidence/pon-work-security-eight-samples-20261101/HOSTED_COST_ARCHIVE.json)

The sealed reader still checks all 810 original checksum entries and the exact
original seal, source observations and HOLD/FAIL counts. Missing or changed
retained files fail; they are not silently skipped or fetched from arbitrary
sources. The joint-resource reader preserves all 74 original checksums, 13
sidecars and the 4,052-member denominator. The PQ reader preserves all 1,050
original stored hashes, 147 gzip byte bindings and 543 followup bindings,
including the original startup UNKNOWN, red/green receipts and HOLD. Current
tests, authoritative ownership and historical counterexamples remain.
The public-readiness reader reconstructs the exact historical package and runs
its unchanged original checker against the measured source. It verifies 1,334
manifest entries, 2,588 source blobs, 793 source SHA-256 values and current plus
original Git tracking. Its [actual local PASS](qualification/public-readiness-cleanup.json)
retains all false current/public/native/activation claims. Only the present CLI
dispatch changes; the original checker functions stay byte-identical.

The hosted-cost reader executes the original checker in a private exact view,
validating all 208 manifest entries and 808 archive members. Five retained small
records and the original receipt remain unchanged. Its 16 negative tests and
actual prepublication dispatch failure are preserved in
[the report](qualification/hosted-cost-cleanup.json).

The remaining large archive candidates identified by this inventory total
315,364,273 bytes in 68 large files. Their exact historical readers and
retained small records must be qualified before current copies are removed:

| Candidate | Files / bytes | Existing obligation |
| --- | ---: | --- |
| Historical CI SQLite snapshots | 8 / 176,597,049 | Preserve compressed/uncompressed hashes and immutable readback; no Node recovery |
| Complete-work original containers | 60 / 138,767,224 | Preserve FILE_INDEX, CAPTURE_INDEX and all archive member checks |

The current PQ corpus pins 1,177 evidence files totaling 183,286,178 bytes across
46 packages; its validator actually reads those bytes. Other Rust tests embed
specific evidence with `include_str!`. A historical-object resolver must preserve
those readers' exact contracts before their current-tree inputs can be removed.
The audit checked Git object existence/type/size for the candidate set; complete
new SHA-256 archive manifests have been made for the six completed sets. The
remaining candidate objects have also been compared against their actual Git
blobs and SHA-256 values, but that read-only inventory alone does not authorize
a weaker reader or deletion of a required retained record.

## Retirement decision

Every original package remains represented in
[config/hia-migration-v1.json](../config/hia-migration-v1.json). The current
`--require-retirement` command refuses all 26 retirements. The remaining gates
are system I/O, persistent node/recovery, cryptography, node integration, the
original service budget, cross-target behavior, model loop, consensus research
and complete replacement/cleanup. Implemented parsers and pure proposals do not
mint the original private authorization types or commit state.

The sole sequence of further work remains the
[repository development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
