# Current HIA rewrite audit

## Decision and scope

The complete HIA-native replacement is **IN PROGRESS**. The current inventory has
**70 kernel components, 30 native foundations and 303 HIA source files**. All
26 original Rust packages remain: 22 are partially ported and 4 are not ported.
No package has an accepted retirement witness. All nine whole-project gates
remain OPEN; `whole_chain_native`, `old_stack_can_be_removed` and
`production_activation` remain false. Component counts are not a completion percentage.

This audit accounts for all 41,494 paths in the baseline Git tree and every
original package and registered HIA source. The baseline has 291 HIA sources,
with no omitted or duplicate source owners. The current graph adds four research
kernels, six Bench kernels and the two Task provider/witness sources. All kernel and foundation Node-integration flags remain false. Of the
70 kernels, 69 are implemented finite units and `mempool/lane_quota` remains a
candidate awaiting its separate qualification. The baseline original Rust source
and the retained package graph are unchanged.

The audited continuation parent is
`267989537b255f168ac132edfbe317aba6c0e34a`, with original `main` baseline
`59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`. Test observations below retain their
actual source identity; successful development checks do not assign a hosted
result to a later commit.

Current component discovery contains **682 methods** in five disjoint groups:
521 general, 95 crypto-types, seven State-root, 22 Oracle and 37 ML-DSA. General
includes the new Research payload, Bench environment and metadata-boundary methods. The workflow expands to
67 jobs and 55 native compiler bootstrap invocations from 49 source admission
blocks. Discovery and workflow enumeration do not establish successful execution.

Use the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[migration inventory](../config/hia-migration-v1.json),
[original ownership inventory](../config/portability-inventory-v1.json) and
[native implementation guide](README.md) together. This page is the current audit,
not another development plan. The full chronological audit, including prior
failures and source identities, remains in
[immutable Git history](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2601aa95250d888cafe9bb4fdfe04a8aad0b7626/hia/AUDIT.md).

## Current implementation and observed failures

### Task dynamic compiler regression

The complete local `2679895` Task gate failed after 144.481 seconds in its
records-policy build. The fixed compiler exited 2 on the actual retained input;
there was no timeout or missing successful output to infer. The provider and
original test stages had already passed. A complete dynamic-build audit found
123 named entries and 75 distinct native compiler inputs. The baseline compiler
accepted 72 inputs and rejected three: the StorePolicy family had 8,525
operations and KernelPolicy had 8,547, exceeding the unchanged 8,192 limit.
Static registered-kernel admission alone had not covered these dynamic units.

The fix only changes the canonical `tk_metadata` initializer to reuse the
existing eight-byte writer's returned cursor. All 648 writes retain their values
and order. Its body shrinks from 1,414 to 816 operations; StorePolicy now has
7,927 and KernelPolicy 7,949. Three explicit include maps add that existing
writer. All 75 distinct actual inputs now pass the same pinned native compiler
and all six original structural limits. A separate actual-native comparator
checks 5,220 complete/truncated/unaligned cases, 10,440 calls, every modified
backing byte and the original SIGILL/partial-write behavior. A second reviewer
found no blocking difference. The complete Task runtime, original 180-second
allocation phase and independent reader remain required on the new candidate.

### Research payloads

The new native payload component implements all seven `ResearchCommandV1`
variants from the retained public Rust crate. It handles exact canonical bytes,
strict decoding and round-trip comparison, validation order and typed errors,
checked contributor work totals, exact ownership shares, reference ordering,
command types and primary object references. Its 51-function composition has
3,226 operations and 522 blocks. Seven actual tests passed 6,968 original/native
comparisons and 20 ABI controls in 72.254 seconds, including every fixture
truncation, all first bytes, collection and numeric limits, deterministic CBOR
mutations and multi-error precedence. Signed envelopes, generic Serde, protocol
state, handoff and Node integration are separate remaining work.

The existing canonical/hash and ExternalKey observations remain source-specific:
29,821 canonical comparisons, 45 original hash comparisons and 5,463 public-key
value comparisons. The original Research crate's 53 active tests and strict
Clippy/fmt passed; its existing ignored test was preserved. Full primitive and
payload contracts are in the [Research guide](src/research_protocol/README.md).

### Bench environment, decimal conversion and fixed formatting

Three new HIA sources implement all 12 environment-value parsers and defaults,
decimal-to-binary64 conversion, and four-decimal formatting. Seven methods passed
2,110 actual native calls under the unmodified formal recording hooks, including
457 original decimal comparisons, 398 complete configuration comparisons, 744
original formatting comparisons and their separate refusal controls. Six actual
native builds and their exact provenance were recorded. Six configurations over
three workloads and seven strategies produced 126 complete scheduler/profile
comparisons. All 74 unchanged-original results matched; the 52 cases affected
by the already documented reader-high-water corrections matched the repaired
independent model and conflict graph. Another 54 native repeats matched complete
ordered membership and digests. These corrections remain explicit differences.

The previous eight Bench methods retain their 1,566 native calls, 307 workload
comparisons, 64 actual original CLI executions, 1,148 internal scheduling
executions and 11 retained Rust tests. Full CLI, process environment acquisition,
clock/persistence ownership, logarithmic derived profiles and complete report
presentation remain open. See the [Bench contract](src/bench/README.md),
[environment ABI](src/bench/ENVIRONMENT.md) and
[fixed-format ABI](src/bench/FORMATTING.md).

### CI dependency and provenance correction

The `2679895` general job completed 498 tests and failed while setting up the
eight Bench methods: the original `cargo build --locked --offline -p trnm-bench`
exited 101. The original job and its 60-member artifact did not retain Cargo's
stderr, so the exact original diagnostic is unavailable. A controlled isolated
cache containing only the 85 crate archives explicitly downloaded by that job
reproduced exit 101 with missing `anstream v1.0.0`; its index copy is explicitly
local, not an asserted replica of the entire hosted filesystem.

The general workflow now fetches the unchanged locked workspace graph before
the offline reference tests. Bench retains actual process commands, statuses,
stdout and stderr for both success and failure. The global qualification source
map now includes the original Bench Rust implementation and its contracts, and
independent readback rejects missing, changed or stale maps. The repaired eight
methods passed their actual recorder regression again: 13 builds, 1,558 shared
calls and eight raw calls. Fifteen existing partition controls, three source-map
rejections, four actual process diagnostics and four bootstrap controls passed.
Fresh full general execution and readback must still succeed on the new head.

### Exact hosted and local Settlement findings

On published `267989537b255f168ac132edfbe317aba6c0e34a`, the
[hosted Settlement job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44733380774/job/136278536658)
completed its complete component and independent-reader step, full committed
source recheck, head/run binding, and complete observation-archive reread. All
four steps report success. The internally redirected raw phase counters and
individual native timing are not printed in the job log and are not inferred
from the total step duration.

Its official artifact 14627533250 is 689,199,037 bytes with SHA-256
`04737e1abe8889f7a1af018e45239621f78f2343a481755b0fbf1d9b19b94884`.
The current artifact retrieval tool rejects files above 536,870,912 bytes, so
local complete-member verification of this particular archive is not yet
claimed. The separately attempted local whole gate failed an unchanged Unix
socket test with `EPERM` after 135 of 136 tests passed; its native phase never
started. This local failure remains distinct from the hosted success.

On the same published source, Task Boundary and source/archive admission passed;
Task Store and general/readback failed for the recorded reasons above. These
source-specific results do not qualify the newly integrated source graph.
Published `25d0e73` Metadata retains its complete 481.005-second hosted PASS and
49,069 independently verified regular archive members. Its Body/whole-Peer and
four-second-service obligations remain open.

### Retained earlier evidence

The native Task provider's six lifecycle entries and 29 operations, the shared
field/SHA changes, Node composition, earlier current owners and failed runs are
preserved in the
[preceding immutable audit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/267989537b255f168ac132edfbe317aba6c0e34a/hia/AUDIT.md)
and their existing qualification records. The production provider and witness
are HIA-emitted machine objects; external SQLite/system libraries remain. No
whole-package or pure-HIA SQLite claim follows from provider replacement.
Historical failures and actually executed evidence are retained; repeated
running commentary is consolidated into this current audit and Git history.

## Original package coverage

“Partial” means named method/kernel or finite owner coverage, including native
foundations described in the guide. It does not permit removal of the package.
The exact component-to-source mapping is machine checked in the migration inventory.

| Package | Owner | Current coverage | Retained responsibility |
| --- | --- | --- | --- |
| [trnm-types](../trillionnium/crates/trnm-types) | M00 | Partial: `types/request-status`, `types/transfer`, `types/transcript` | Shared task/identity/transcript/transaction data; delete consumption-consensus governance controls. |
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Partial: `executor/schedule`, `math/binary64` | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Partial: `bench/workload`, `bench/digests`, `bench/repeat`, `bench/decimal`, `bench/environment`, `bench/format-fixed` | Native workload, scheduling, configuration and exact text/numeric primitives; complete CLI/profile/persistence remains open. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Partial: `mempool/lane_quota`, `mempool/lane_owner` | Typed signed admission, nonce reservations and durable local-pool/Node handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Not ported: — | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Partial: `oracle/values`, `oracle/serde-json` | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Partial: `research-protocol/canonical`, `research-protocol/hash`, `research-protocol/external-key`, `research-protocol/payload` | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root`, `protocol/state-root-compact` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Partial: `peer-lease/values` | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Partial: `data-availability/rs46` | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Partial: `platform/task-kernel-main-store` | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Partial: `state/json_string`, `state/json_value`, `codec/json_primitives`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode` | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Partial: `platform/service-settlement-engine` | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Partial: `control-plane/core`, `control-plane/registry`, `control-plane/local-guard` | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Not ported: — | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Not ported: — | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Partial: native `platform/checkpoint-store` authority, CLI, Unix client/daemon and separate ledger | Full original methods and finite recovery qualified; Node.db integration, cross-target acceptance and dependency retirement remain open. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena`, `crypto/sha512_arena`, `crypto/ed25519_group`, `crypto/ed25519_verify`, `crypto/sha256_stream`, `crypto/ed25519-sign`, `crypto/sha512-stream`, `crypto/keccak-stream`, `crypto/ml-dsa-poly` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
| [trnm-verification-profiles](../trillionnium/crates/trnm-verification-profiles) | M11 | Partial: `verification/closed_round` | Reusable evaluation/profile contracts and exact bounded integer BA normal form; no stake-quorum backend, model-parent authentication or general functional-equivalence authority. |
| [trnm-transport](../trillionnium/crates/trnm-transport) | M04 | Partial: `transport/replay` | Extract generation-bound authenticated frame admission; delete pacemaker and node scaffold. |
| [trnm-audit-events](../trillionnium/crates/trnm-audit-events) | M17 | Partial: `audit/event` | Consumer integration and dependency retirement remain open; the value has no consensus or durable authority. |
| [trnm-governance-guard](../trillionnium/crates/trnm-governance-guard) | M01 | Partial: `governance/guard` | Local proposal/timelock, role separation and optimistic version checks; no network governance authority. |
| [trnm-escrow-vault](../trillionnium/crates/trnm-escrow-vault) | M12 | Partial: `escrow/vault` | Pure in-memory escrow conservation reference; no second production ledger or durability claim. |
| [trnm-pon-node](../trillionnium/crates/trnm-pon-node) | M15 | Partial: `transport/authenticated_request`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode`, `transport/authenticated-response`, `transport/signed-response`, `node/settings-development`, `consensus/work`, `mempool/raw-bindings-owner` | Native development composition with a single branch/replay/outbox SQLite owner, explicit maintenance choice, bounded public entrypoints, typed local error identity, checked history projections, explicit revision16 model/task-window CLI context binding, and optional fresh PQ transport-only ownership; account/task/install authorization is not PQ-migrated and no publicly qualified deployment is claimed. |
| [trnm-sqlite-io-boundary](../trillionnium/crates/trnm-sqlite-io-boundary) | M15 | Not ported: — | Reused process-owned native SQLite boundary and executed-mutation transaction observer from c165; bounds History graph readback reuse to the same immediate transaction and fixed SQLite build. It adds no consensus or deployment authority. |

## Whole-project acceptance gates

| Gate | Remaining required result | State |
| --- | --- | --- |
| `system-io` | HIA v8 general filesystem/network/process syscall and host capability boundary | **OPEN** |
| `persistent-node` | single durable Node owner, SQLite semantics, crash cuts, rollback floor and reorg | **OPEN** |
| `cryptography` | complete PQ signatures, authenticated TLS/identity and signature-domain parity | **OPEN** |
| `node-integration` | full transaction/application flow, mempool, cancellation, private authority types and end-to-end use | **OPEN** |
| `service-budget` | original 0.25 CPU / 2 GiB / zero-swap / 256 PID / 4-second / 16-request acceptance | **OPEN** |
| `cross-target` | original architecture/OS support and exact artifact qualification | **OPEN** |
| `model-loop` | actual train, independent evaluation, Adopt/NoUpdate, subsequent task and cold recovery | **OPEN** |
| `consensus-research` | original work-cost, public consensus, STARK/QROM and economic qualification | **OPEN** |
| `retirement` | equivalent complete replacement of all 26 retained Rust packages and their indispensable tools | **OPEN** |

The current held-disk Node/M05 owner constructs private State, consumes typed
requests through actual PNX1/SHA/Ed25519 admission and now implements private
Some/CheckedApply snapshots. Complete live successor authentication, expected
root acceptance, durable Node.db COMMIT, crash/reorg/rollback-floor/replay/outbox/ACK
ownership and the same request's deadline, Paid account and Host permit remain.
An isolated buffer codec, successful root computation or private fixture result
cannot stand in for these capabilities.

The original Node directly owns `rusqlite::Connection` in `Node.db`.
`TransactionScope` records SQLite operation boundaries; the optional
`OwnedConnection` wrapper is not the Node owner. The existing fresh-format native
store and Genesis owner do not implement all of the original SQLite semantics.
PQ signatures, TLS/identity, every Config/profile, original architecture/OS
support, the real independent model loop and consensus research qualifications
also remain mandatory.

## Observed service failure

The initial branch's exact-source
[required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44338859069)
failed `CONFIRMATION_TARGET` on both x64 and arm64 despite successful individual
native test processes. Both no-attack phases confirmed 1/1 request (about 1.387 s
on x64 and 1.887 s on arm64). Under the original 16-worker pressure and four-second
limit, both confirmed **0/1**. Both retained 7/7 submit acknowledgements; timely
replay was 6/7 on x64 and 5/6 on arm64. No final Host error was reported.
These are actual business failures, not missing-test syntax errors. Submission
acknowledgement does not establish inclusion or confirmation.

The original limits remain 0.25 CPU, 2 GiB memory, zero swap, 256 PIDs, four
seconds and 16 competing requests/workers, with the separate original lifetime
obligations. No timeout, roster, target or refusal classification has been
relaxed. Earlier `PUBLIC_REQUEST_DEADLINE`, history/lifetime and research HOLD
observations retain their own exact sources in the historical audit and current
qualification records.

The later exact `180c642` baseline retained the same failure. Four complete
GitHub artifact ZIPs and all their members were rehashed locally and in the
retained operator copy; the [continuation record](qualification/continuation-development.json)
binds their original identities. All four reported only `CONFIRMATION_TARGET`;
all named original tests and format checks passed. Every pressure phase still
acknowledged 7/7 submissions but confirmed 0/1 within the original window.

| Exact 180 lane | No-attack confirmation latency | Pressure independent replay | Pressure confirmation |
| --- | --- | --- | --- |
| arm64 cost | 1.811797494 s | 6/6 attempts; only six of seven history pages fetched | 0/1 |
| x64 cost | 3.214078118 s | 1/2; one failed or late | 0/1 |
| head protocol | 3.305055181 s | 1/2; one failed or late | 0/1 |
| prospective-merge protocol | 3.197675740 s | 1/2; one failed or late | 0/1 |

The latter three pressure records contain `PUBLIC_REQUEST_DEADLINE`. The
prospective merge is `7372dcef55cf984d071c46307b205355dee68c29` with the same
`8dfb0cad23a556efbbef04061ba8563d2dfe1787` tested tree. These failures remain
separate from the earlier branch observations above.

## Toolchain and evidence boundary

The pinned HIA source is `f33d8da316de8fdf27b504371f1a5310997ff548`.
The self-hosted native compiler SHA-256 is
`87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
The actual bootstrap reproduced that compiler. The retained
[cold binding](qualification/compiler-binding.json) has its own complete
execution and cleanup budgets; this continuation did not rerun the whole cold
gate. The original Rust references use the repository's pinned Rust 1.95.0.
The unchanged `trnm-types` all-targets run passed all 283 tests in 20 test
binaries, with no ignored or filtered tests.

Core v8 has a closed arithmetic/buffer/resource opcode set and internal calls.
The Linux adapters are emitted native code that performs real syscalls around
HIA policies; they are not a general portable HIA filesystem/network/process
API. GNU ld links machine objects. No failure switches silently to a host-language
implementation, and a compiler fixed point is not Node or cryptographic qualification.

## Repository consolidation and retirement

The exact initial branch tree contained 41,020 tracked entries. The complete
Git-blob duplicate scan found 2,187 duplicate groups with 11,904 redundant paths,
mostly historical evidence copies. It found no duplicate blob group containing
more than one active file under `hia/src`, `hia/platform`, `hia/storage` or
`trillionnium/crates`. Similar names are not evidence of redundant semantics.

This audit now keeps one current coverage/decision page; the superseded running
commentary is preserved at the immutable history link above. New implementation
files have one canonical owner and explicit shared-function composition. The
owner-cleared root README contract remains intact; `hia/README.md` is the native
entry point. There is no second final implementation directory.

The prior cleanup removed 1,622 current-tree archive copies totaling
1,628,294,407 original bytes through exact historical-object resolvers. Its
original denominator checks, eight archive indexes and failure records remain
in the historical audit and retained files. Other evidence is still consumed
by exact corpus readers and Rust `include_str!` inputs. It must be migrated to
an equally strict historical resolver before removing current-tree bytes.
Failed observations are not disposable intermediate implementations.

Whole-package deletion remains blocked by actual missing behavior and failed
original acceptance. Retirement requires the complete replacement, every
necessary consumer integrated, full original tests and service gates passed,
exact committed-source provenance and no remaining runtime dependency on the
old package. Python build/readback tooling and Rust differential references also
require an explicit final disposition before claiming an entirely HIA-native set.
