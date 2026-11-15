# Whole-tree inventory and HIA migration audit

## Scope and conclusion

The audited consolidated baseline is `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`.
The whole tracked tree, active Cargo package graph and all M00–M17 ownership
boundaries were inventoried. Detailed semantic comparisons and native tests cover
the implemented components listed in [the native guide](README.md). This is not
a claim that every one of the 702,001 retained Rust physical lines was manually
reviewed, or that every historical campaign passed.

**The full replacement is incomplete.** Seventeen HIA source units currently
implement tested deterministic boundaries; no whole original package has an
accepted retirement witness. There is no complete HIA node executable, durable
node owner, native network stack or native identity/signature stack in this
candidate. The nine integration/qualification gates remain open.

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
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Unported | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Unported | Retained executor microbenchmark; not ledger throughput. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Unported | Bounded admission, nonce reservations and durable handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Unported | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Unported | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Unported | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Unported | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Unported | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Unported | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Unported | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Unported | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Unported | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Unported | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Unported | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Unported | Independent exact CAS and durable Unix service; generalized owner frontier only. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
| [trnm-verification-profiles](../trillionnium/crates/trnm-verification-profiles) | M11 | Partial: `verification/closed_round` | Reusable evaluation/profile contracts and exact bounded integer BA normal form; no stake-quorum backend, model-parent authentication or general functional-equivalence authority. |
| [trnm-transport](../trillionnium/crates/trnm-transport) | M04 | Partial: `transport/replay` | Extract generation-bound authenticated frame admission; delete pacemaker and node scaffold. |
| [trnm-audit-events](../trillionnium/crates/trnm-audit-events) | M17 | Unported | Normalized local audit event data; no consensus or durable owner. |
| [trnm-governance-guard](../trillionnium/crates/trnm-governance-guard) | M01 | Unported | Local proposal/timelock, role separation and optimistic version checks; no network governance authority. |
| [trnm-escrow-vault](../trillionnium/crates/trnm-escrow-vault) | M12 | Unported | Pure in-memory escrow conservation reference; no second production ledger or durability claim. |
| [trnm-pon-node](../trillionnium/crates/trnm-pon-node) | M15 | Unported | Native development composition with a single branch/replay/outbox SQLite owner, explicit maintenance choice, bounded public entrypoints, typed local error identity, checked history projections, explicit revision16 model/task-window CLI context binding, and optional fresh PQ transport-only ownership; account/task/install authorization is not PQ-migrated and no publicly qualified deployment is claimed. |
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

The fixed source evidence is linked in [the native guide](README.md). No
specialized filesystem, socket, cryptographic or full-node qualification is
inferred from the compiler fixed point.

## Observed integration failures

The first candidate `893210a45b44742edfe2510fea1d92e9974b5f95` passed the new
HIA workflow: 72 tests, 21,593 native calls, no skips or failures. Its original
Rust replay and round references actually compiled and ran. That result applies
to that source set; later components require new CI observations.

The complete original CI also exposed these distinct outcomes:

| Finding | Classification and action |
| --- | --- |
| Distributed source inventory omitted `config/hia-migration-v1.json` | Introduced by the migration. Baseline had exactly 1,745 matching entries; candidate required 1,746. The unchanged original generator now adds the missing include and its original check passes. |
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

The current tree removes 607 obsolete checkout-repair files and 14 historical CI
ZIPs, totaling 403,944,723 original bytes. Both sets remain recoverable by exact
historical Git object with original SHA-256/size bindings. This is cleanup of
current-tree copies, not an erasure or rewrite of Git history.

- [Checkout preparation archive](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json)
- [Sealed CI ZIP archive](../evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json)

The latter reader still checks all 810 original checksum entries and the exact
original seal, source observations and HOLD/FAIL counts. Missing or changed
retained files fail; they are not silently skipped or fetched from arbitrary
sources. Current tests, authoritative source ownership and necessary historical
counterexamples remain. Other evidence packages require their own consumer and
seal audit before removal.

The remaining large archive candidates identified by this inventory total
1,224,366,396 bytes. Their current consumers prevent immediate deletion:

| Candidate | Files / bytes | Existing obligation |
| --- | ---: | --- |
| Public-readiness pre-correction payloads | 885 / 413,594,755 | Preserve exact historical file sets and execution of the original checker |
| PQ authority hosted triage large payloads | 4 / 189,121,668 | Preserve artifact-index/compression mappings and original startup UNKNOWN |
| Work-security hosted-cost containers | 32 / 180,351,232 | Verify the exact archive roster, shard order and internal manifests |
| Historical CI SQLite snapshots | 8 / 176,597,049 | Preserve compressed/uncompressed hashes and immutable readback; no Node recovery |
| Joint resource contract archives | 13 / 125,934,468 | Preserve all artifact/checksum inventories and original HOLD/NO-GO |
| Complete-work original containers | 60 / 138,767,224 | Preserve FILE_INDEX, CAPTURE_INDEX and all archive member checks |

The current PQ corpus pins 1,177 evidence files totaling 183,286,178 bytes across
46 packages; its validator actually reads those bytes. Other Rust tests embed
specific evidence with `include_str!`. A historical-object resolver must preserve
those readers' exact contracts before their current-tree inputs can be removed.
The audit checked Git object existence/type/size for the candidate set; complete
new SHA-256 archive manifests have only been made for the two completed sets.

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
