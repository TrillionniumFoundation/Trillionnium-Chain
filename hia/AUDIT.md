# Whole-tree inventory and HIA migration audit

## Optimized Python qualification refusal — 2026-11-16 UTC

The native StoreOwner's physical test controller had assertion-based disk,
readback and crash-cut checks, which Python `-O` and `PYTHONOPTIMIZE` would
otherwise remove. Its startup now refuses optimized execution before any
native operation. Three actual isolated optimized-interpreter refusal controls
(`-O`, `-OO`, `PYTHONOPTIMIZE=2`) and compilation of both changed Python
files passed. Exact-head hosted native/PQ qualification remains pending.
This changes neither the HIA machine code nor Node transaction ownership,
original service budgets, the 26 retained Rust packages or nine OPEN gates.


New M05 opcode 24 is a one-call **pure QoS snapshot proposal** with five
original-headroom/admissibility fields. Its qualification requires emitted HIA
machine code to match one actual original Rust `qos_snapshot` for each real
ingress/dequeue case; the preceding opcode-23 CI has six SUCCESS jobs, but
cannot qualify newly changed source. Nothing here owns the Node queue or
reduces any of the nine open migration gates.

The newest M05 candidate adds a single-call pure five-field post-dequeue projection (LQV1 opcode 23), checked against one actual original Rust dequeue observation plus an independent fairness-module differential. Exact-head CI qualification is pending. The projected fields do not authorize or mutate the real mempool; the complete Node owner and retirement gates remain OPEN.

## New M05 projection candidate and source-bound qualification

The `5524ce8b` six-job native CI completed successfully on its exact source:
222 tests and 70,998 shared native calls, with mandatory original Rust execution.
The newer queue post-pop count and dequeue-presence opcodes (20–22) require a
new exact-head run. The complete Node owner, all 26 original Rust packages, all
nine OPEN migration gates and PQ HOLD_NO_GO are unchanged.

## Scope and conclusion

The audited consolidated baseline is `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`.
The whole tracked tree, active Cargo package graph and all M00–M17 ownership
boundaries were inventoried. Detailed semantic comparisons and native tests cover
the implemented components listed in [the native guide](README.md). This is not
a claim that every one of the 702,001 retained Rust physical lines was manually
reviewed, or that every historical campaign passed.

**The full replacement is incomplete.** Thirty-seven kernel units and seven native
foundations account for all 52 candidate HIA source files. Native connected-stream
I/O, complete classical response codecs, Settings and streaming persistence exist, but no whole original package has
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
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Partial: `mempool/lane_quota` pure predicates; native CI pending | Bounded admission, nonce reservations and durable handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Unported | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Unported | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Unported | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root`, `protocol/state-root-compact` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Unported | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Unported | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Unported | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Partial: `state/json_string`, `state/json_value`, `codec/json_primitives`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode` | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Unported | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Unported | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Unported | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Unported | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Unported | Independent exact CAS and durable Unix service; generalized owner frontier only. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena`, `crypto/sha512_arena`, `crypto/ed25519_group`, `crypto/ed25519_verify`, `crypto/sha256_stream`, `crypto/ed25519-sign` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
| [trnm-verification-profiles](../trillionnium/crates/trnm-verification-profiles) | M11 | Partial: `verification/closed_round` | Reusable evaluation/profile contracts and exact bounded integer BA normal form; no stake-quorum backend, model-parent authentication or general functional-equivalence authority. |
| [trnm-transport](../trillionnium/crates/trnm-transport) | M04 | Partial: `transport/replay` | Extract generation-bound authenticated frame admission; delete pacemaker and node scaffold. |
| [trnm-audit-events](../trillionnium/crates/trnm-audit-events) | M17 | Unported | Normalized local audit event data; no consensus or durable owner. |
| [trnm-governance-guard](../trillionnium/crates/trnm-governance-guard) | M01 | Unported | Local proposal/timelock, role separation and optimistic version checks; no network governance authority. |
| [trnm-escrow-vault](../trillionnium/crates/trnm-escrow-vault) | M12 | Unported | Pure in-memory escrow conservation reference; no second production ledger or durability claim. |
| [trnm-pon-node](../trillionnium/crates/trnm-pon-node) | M15 | Partial: `transport/authenticated_request`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode`, `transport/authenticated-response`, `transport/signed-response`, `node/settings-development` | Native development composition with a single branch/replay/outbox SQLite owner, explicit maintenance choice, bounded public entrypoints, typed local error identity, checked history projections, explicit revision16 model/task-window CLI context binding, and optional fresh PQ transport-only ownership; account/task/install authorization is not PQ-migrated and no publicly qualified deployment is claimed. |
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
then validates persisted data on reopen. The fresh-v2 format has executed the
complete 279,445,512-byte original State extent and 4,105 commits, with checked
file-offset and sequence exhaustion limits. It passed 52 physical controls and
170 native function controls. The exact parent rebuild matches that ELF. Typed
state transitions, interrupted initialization recovery and original service
latency remain unqualified; the local trace is UNKNOWN after ptrace denial.

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

The fifth repaired candidate `4cc0464ff9632f2a493cb76d5b8b51eaad332dac` passed
[all three HIA jobs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43751782144):
189 tests, 56,884 shared-runner native calls, zero skips, failures or errors.
All five original Rust adapters ran. The [exact report](qualification/native-ci.json)
binds only that source set. OS 25/25, reactor 49/49 plus 13 native contracts,
and storage 48/48 plus 14 native contracts passed, with actual traces captured.
The complete-request job also passed 178 native request controls, 14 stream SHA
controls, 170 actual original-Node comparisons and six original tests. The source
job passed all 113 PQ negative tests and full historical readers; PQ stays HOLD.

The separate [actual executor comparison](qualification/executor-original-ci.json)
ran 5,274 cases against the unchanged original Rust library. It recorded 131
unsafe original results, 181 intentional differences and 27 expected version-skew
panics. HIA preserves the maximum reader dependency and satisfies the independent
conflict graph. Its status explicitly retains the original safety defect rather
than asserting identical unsafe behavior. This crate is outside the normal Node
dependency closure. Earlier source-derived model observations remain distinct.

Later sixth-batch sources require their own exact committed qualification.
Locally, complete response passed 11,420 controls, typed Delta passed 8,551,
Settings passed 16 tests (102 shared-runner plus 14 raw-pointer calls), and the
private-stack repair passed its 11 explicit observations. The bare signer spill
failure and slow storage attempt remain recorded failures. The integrated
response producer actually refused publication after denied cleanup. Original
Rust for these additions remains NOT_RUN until the dedicated mandatory CI jobs.
Typed Value construction and complete-State ownership remain distinct; complete
private owners and the original service budgets remain open. Earlier maximum-count state-root evidence stays bound to
its exact fourth candidate and does not imply a later full-State owner pass.

The complete original CI also exposed these distinct outcomes:

| Finding | Classification and action |
| --- | --- |
| Fifth executor adapter could not link transitive dependencies | Run `43749946614` passed the main suite but failed with E0463 before original executor execution. Exact Cargo-event library directories and twelve controls were added in `4cc0464`; run `43751782144` actually executed all 5,274 original/native comparisons. The failed run remains FAIL. |
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
pre-correction payloads, 32 hosted-cost containers/shards, eight D26 compressed
SQLite snapshots and 59 W1 complete-work containers: **1,622 removed copies
totaling 1,628,294,407 original bytes**. All remain recoverable by exact historical Git object with original
SHA-256/size bindings. The PQ capture's other 29 smaller records remain as
byte-identical current copies in its retained directory. This cleans current-tree
copies; Git history is not rewritten.

- [Checkout preparation archive](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json)
- [Sealed CI ZIP archive](../evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json)
- [Joint-resource archive](../evidence/pon-joint-resource-contract-20261109/ORIGINAL_ARCHIVE_INDEX.json)
- [PQ triage capture](../evidence/pq-authority-preflight-20261108-9d315/NATIVE_TRIAGE_ARCHIVE.json)
- [Public-readiness pre-correction archive](../evidence/pon-public-readiness-v1/PRE_CORRECTION_ARCHIVE.json)
- [Hosted-cost archive](../evidence/pon-work-security-eight-samples-20261101/HOSTED_COST_ARCHIVE.json)
- [D26 SQLite archive](../evidence/pon-business-gates-readback-20261107/D26_SQLITE_ARCHIVE.json)
- [W1 complete-work archive](../evidence/pon-w1-complete-work-20261101/W1_COMPLETE_ARCHIVE.json)

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

The D26 reader validates the full 617-file original package, all 614 prepared
files and 232 gzip streams against their stored and decoded hashes, complete
tails and preparation-plan bindings. It preserves all 609 other original files.
The original and archived reader observations agree; 15 negative controls pass.
It does not open SQLite, recover a Node or promote historical HOLD fields.

The W1 reader executes its unchanged original verifier in the complete 172-file
view, checking all 170 FILE_INDEX rows, 171 SHA256SUMS entries and 60 archives:
4,960 members / 4,463,919,709 decoded bytes. All 91 small records remain exact
retained copies, including ten logs explicitly added despite ignore rules.
The original and archived observations agree, and 15 negative controls pass,
including a genuine original-member verification failure. The 16,712-byte root
validation archive remains an unchanged required input. The four historical W1
service failures and incomplete CodeQL result retain their original identities.

The current PQ corpus pins 1,177 evidence files totaling 183,286,178 bytes across
46 packages; its validator actually reads those bytes. Other Rust tests embed
specific evidence with `include_str!`. A historical-object resolver must preserve
those readers' exact contracts before their current-tree inputs can be removed.
The audit checked Git object existence/type/size for the candidate set; complete
new SHA-256 archive manifests have been made for all eight completed sets.
Exact readers, complete original denominators and retained small records remain
mandatory; an inventory alone does not justify a weaker reader or deletion of
a required retained record.

## M05 lane admission source boundary

A new bounded HIA quota/fairness decision kernel encodes the original
`trnm-mempool` critical-reserve, borrowing and prefer-normal predicates. It
does not read authoritative queues, repair stale deduplication caches, reserve a
nonce, enqueue/dequeue a transaction, enforce admission locks or commit an
outbox. The [isolated M05 protocol](MEMPOOL.md) uses an original-Rust adapter
that includes `lane_quota.rs` and `lane_fairness.rs` unchanged, rather than
replicating their logic in a handwritten Rust oracle. A preliminary local run
checked 1,345 caller-model/actual-original-Rust cases. HIA native and full
original 26-package differential are **NOT_RUN** for this new source until CI
provides exact source/artifact evidence; no source-only verification changes a
migration gate.

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
