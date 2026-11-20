# Current HIA rewrite audit

## Decision and scope

The complete HIA-native replacement is **IN PROGRESS**. The current inventory has
**76 kernel components, 30 native foundations and 309 HIA source files**. All
26 original Rust packages remain: 22 are partially ported and 4 are not ported.
No package has an accepted retirement witness. All nine whole-project gates
remain OPEN; `whole_chain_native`, `old_stack_can_be_removed` and
`production_activation` remain false. Component counts are not a completion percentage.

This continuation extends published
`99bcfc11c00c393b7d48ac0f6352b9afe33e913f`, whose tree is
`566be40d4778211758c83994f35035ae9a1eb7e2`. The original main baseline remains
`59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`. The complete original package graph,
Cargo lock, Rust implementations and tests remain. Every HIA source has one
registered owner; all kernel/foundation Node-integration flags remain false.
Of the 76 kernels, 75 are implemented finite units and `mempool/lane_quota`
remains a candidate awaiting its separate qualification.

Fresh discovery finds **711 methods** in six disjoint groups: 516 general,
95 crypto-types, seven State-root, 22 Oracle, 37 ML-DSA and 34 Research.
The workflow expands to 68 jobs and 56 compiler bootstrap invocations from
50 source-admission blocks. Counts establish inventory, not successful execution.

Use the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[migration inventory](../config/hia-migration-v1.json),
[original ownership inventory](../config/portability-inventory-v1.json) and
[implementation guide](README.md) together. This is the current audit, not a
second plan. Complete previous findings and failures remain in the
[immutable predecessor audit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/99bcfc11c00c393b7d48ac0f6352b9afe33e913f/hia/AUDIT.md)
and the actual retained qualification records.

## Current implementation and observed failures

### Frozen combined development regression

The merged payload, signed-command, Authority, Bench-profile and relocated ACK
graph passed all 32 selected methods in 358.681 seconds. The unchanged formal
recording hooks observed nine actual native builds, 31,490 returned calls and
three expected native overflow traps. Every method started and finished, none
were skipped, all build provenance checks passed, and the complete qualification
source map was identical before and after execution. The separate 33 CI controls
also passed on this merged graph in 26.592 seconds. These are actual focused
development regressions; the new six-job hosted run and full-project gates
remain separate requirements.

### Published 99bcfc1: complete HIA workflow and Task qualification

All 67 jobs in the predecessor's
[HIA push workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44738516036)
completed successfully. This includes the complete Task Store and Settlement
gates, source/archive admission, all five original component partitions and
their independent combined reader, plus the dependent Work and typed-store gates.
The general execution took 759 seconds; the complete general job took 992 seconds.

The [combined component reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44738516036/job/136305805301)
accepted all 682 predecessor methods with complete disjoint coverage. Its exact
36,227-byte official artifact 14631936025 was downloaded and independently read
in full; SHA-256 is
`80f39df9eff6de59e2219db0ef259a8a09f797c43136fb4e375ce6ca4f8aaa7b`.
The reader verifies retained evidence and source/head/run identities; it does
not reexecute native runtime or revalidate the Rust build event chain. These
successful results do not qualify the new uncommitted graph or retire a package.

The exact 99bcfc1 local complete Task gate also passed in 289.648 seconds.
The unchanged 180-second allocator phase completed in 55.803 seconds: all
112 controls, 96 actual allocation failures, zero remaining live allocations
or bytes, and zero invalid frees. It retained all 41 original tests, strict
Clippy/fmt, 1,390 records, 445 public cases, 413 method calls, 1,877 getter calls,
1,182 provider pairs, 143 allocation pairs, 46 provider-reader refusals and
37 independent whole-gate tamper refusals. The actual source fence was unchanged.

The earlier 2679895 Task build rejection was real: three dynamic compositions
exceeded the original 8,192-operation limit. Reusing the metadata writer's cursor
preserved all 648 writes and reduced the two policy units to 7,927 and 7,949
operations. All 75 distinct inputs from 123 dynamic entries and 5,220 actual
memory/trap comparisons passed. The prior failure remains a failure.

### Research payloads, signed commands and authority values

The [Research implementation](src/research_protocol/README.md) now contains all
seven typed payloads, complete SignedResearchCommandV1 canonical and signing
bytes, strict decoding, validation/error precedence, native Ed25519 signing and
verification, exact fingerprint/payload hashes and Authority identity/set values.
The existing payload's seven methods passed 6,968 original/native pairs and
20 ABI controls. The signed composition uses 118 functions, 7,858 operations and
935 blocks under the unchanged compiler limits.

Eight signed-command methods passed 5,045 original/native pairs, 87 ABI controls
and 154 independent hash observations in 203.408 seconds; the unchanged formal
recorder observed one actual build and 5,132 returned native calls. The corpus
includes malformed CBOR, signature/role/field precedence, dalek noncanonical-Y
behavior, output guards and 39 seed-lifetime controls. Every admitted signing
exit clears the complete declared private scratch prefix after output copying.
An independent review found and corrected an earlier early-error seed-retention
gap; the corrected source and native artifact have their own recorded identities.

The [authority value layer](src/research_protocol/AUTHORITY.md) implements the
original constructors, exact tuple ordering/validation, both canonical encoders
and both authorization methods. It preserves binary-search behavior for public
raw unvalidated sets. Five methods passed 590 actual original/native pairs and
180 ABI controls in 43.759 seconds, with one build and 770 returned calls. The
composition has 50 functions, 2,882 operations and 356 blocks. Generic Serde,
the full state owner/snapshot graph, handoff and Node integration remain open.

The first combined 14-method payload/signing run failed after 223.280 seconds:
the test selected an arbitrary JSON key and attempted to replace a Boolean with
an array, causing the original adapter to reject the test fixture before native
execution. The fixture now selects each variant's explicit primary field. That
failed run remains distinct from the subsequent complete successful eight-method
signed run. No production behavior was changed to accept the invalid fixture.

### Bench logarithms and complete derived profiles

Three additional HIA kernels provide binary64 logarithms, all 51 original
derived profile fields and complete four-decimal field values. They build on
the existing native workload, seven-strategy scheduler, repeat/digest owner,
12 environment-value parsers and decimal/fixed-format components.

Seven profile methods passed in 42.368 seconds with four recorded native builds,
14,745 recorded calls and three separately captured real overflow traps.
The logarithm corpus contains 6,560 positive finite MPFR comparisons and
17 actual Rust special-value comparisons. Of the finite cases, 6,559 retain
400-bit directed interval enclosures; 6,553 finish at 128-bit refinement and
six at 256 bits, with the exact `ln(1)` case separate. The numerical argument,
rounding assumptions and independently sourced hard-case bound are documented
in [LOGARITHM.md](src/bench/LOGARITHM.md); testing does not prove compiler correctness.

All 317 complete profiles compare 16,167 raw fields and their final formatted
text. Of these, 84 profiles use 42 actual scheduler runs; 20 retain the documented
reader-high-water correction differences and the independent conflict checks.
Current observations found no raw Rust logarithm/entropy bit difference in this
corpus, without claiming universal Rust libm correct rounding. An earlier
negative test put a maximum value in grouped-count rather than transaction-count;
the actual original succeeded, the assertion failed, and the test input was
corrected. The failed run is retained. Full CLI, OS environment/clock acquisition,
ordered report and persistence ownership remain open. See the
[Bench contract](src/bench/README.md) and [profile contract](src/bench/PROFILE.md).

### Recovery ACK value codec

The [ACK implementation](platform/peer_payload_recovery/README.md) covers the
original fixed 188-byte encode/decode/checksum/error-order contract and wiring
to existing native peer values. Its sole pure kernel lives at
`hia/src/peer_lease/recovery_ack.hepta`; the migration guard continues to reject
kernel declarations outside `hia/src`. The relocation preserves all source bytes.
Five methods passed in 17.787 seconds: two builds, 3,858 actual returned calls,
3,175 Rust comparisons, 1,313 independent hashes and 673 ABI controls.
An independent reread verified all 3,848 ACK and ten value observations and their
actual compiler, original Cargo, buffer and source evidence. The earlier observer
optimization-profile mismatch remains retained. Full ACK journal/recovery, wide
Body qualification and complete Peer/Node ownership remain open.

### Six-partition CI and retained failures

The complete `hia.tests.test_research_*` family now has its own partition, with
the same original 20-minute job limit and compiler/runtime bounds. The combined
reader requires six successful jobs, six strict bundles, fresh actual discovery
and exact nonoverlapping start/finish coverage. All old methods remain.
Thirty-three controls passed, including real six-ZIP transport and refusals for
a missing, overlapping, repeated or failed Research group, ten SHA-reader controls
and four bootstrap controls over all 50 blocks (200 actual child checks).
Bench profile and ACK observations have separate always-uploaded artifacts;
the general strict bundle retains its original 60-file contract.

The earlier Bench locked/offline build failure is preserved. The explicit locked
dependency fetch and retained Cargo diagnostics repaired it on published 99bcfc1.
The two cancelled macOS process-cleanup jobs had no acquired runner and no steps;
their recorded annotation reports hosted runner capacity failure. They are
NOT_RUN observations, not successful tests. Targeted retries retain the same job,
source and limits and require their own readback.

Published 2679895 Settlement passed its full hosted gate and archive reread.
Its 689,199,037-byte artifact still exceeds the retrieval tool's 536,870,912-byte
limit, so local full-member verification of that particular artifact is not
claimed. The separate local attempt failed the unchanged Unix socket test with
EPERM after 135 of 136 tests and never started native execution. Earlier Task
allocator, Settlement wall-time, Body maximum-extent and original four-second
service failures remain recorded with their actual sources. No later finite
component PASS changes those historical outcomes or closes the nine gates.

## Original package coverage

“Partial” means named method/kernel or finite owner coverage, including native
foundations described in the guide. It does not permit removal of the package.
The exact component-to-source mapping is machine checked in the migration inventory.

| Package | Owner | Current coverage | Retained responsibility |
| --- | --- | --- | --- |
| [trnm-types](../trillionnium/crates/trnm-types) | M00 | Partial: `types/request-status`, `types/transfer`, `types/transcript` | Shared task/identity/transcript/transaction data; delete consumption-consensus governance controls. |
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Partial: `executor/schedule`, `math/binary64` | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Partial: `bench/workload`, `bench/digests`, `bench/repeat`, `bench/decimal`, `bench/environment`, `bench/format-fixed`, `bench/logarithm`, `bench/profile`, `bench/format-value` | Native workload, scheduling, configuration and exact text/numeric primitives; complete CLI/clock/report/persistence remains open. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Partial: `mempool/lane_quota`, `mempool/lane_owner` | Typed signed admission, nonce reservations and durable local-pool/Node handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Not ported: — | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Partial: `oracle/values`, `oracle/serde-json` | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Partial: `research-protocol/canonical`, `research-protocol/hash`, `research-protocol/external-key`, `research-protocol/payload`, `research-protocol/command`, `research-protocol/authority` | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root`, `protocol/state-root-compact` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Partial: `peer-lease/values`, `peer-payload-recovery/ack-codec` | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
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
