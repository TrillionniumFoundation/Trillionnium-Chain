# Current HIA rewrite audit

## Decision and scope

The complete HIA-native replacement is **IN PROGRESS**. The current inventory has
**54 kernel components, 22 native foundations and 143 HIA source files**. All
26 original Rust packages remain: 17 are partially ported and 9 are not ported.
No package has an accepted retirement witness. All nine whole-project gates
remain OPEN; `whole_chain_native`, `old_stack_can_be_removed` and
`production_activation` remain false. Component counts are not a completion percentage.

This audit covers the complete tracked-path and package ownership inventory,
all registered native implementation boundaries, the current CI wiring and
source-specific semantic tests of implemented units. It does not claim a manual
line-by-line review of all 702,001 original Rust lines, or successful execution
of every historical experiment. The original baseline is
`59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`; the branch inspected for this continuation
was `56c6e560dd3192f89cca40542286166b8284cb4b`. The detached-Oracle correction
was published as `2601aa95250d888cafe9bb4fdfe04a8aad0b7626`. Later component
observations identify their actual working-source hashes and do not inherit CI results.

Use the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[migration inventory](../config/hia-migration-v1.json),
[original ownership inventory](../config/portability-inventory-v1.json) and
[native implementation guide](README.md) together. This page is the current audit,
not another development plan. The full chronological audit, including prior
failures and source identities, remains in
[immutable Git history](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2601aa95250d888cafe9bb4fdfe04a8aad0b7626/hia/AUDIT.md).

## Findings addressed in this continuation

### Oracle exact-SHA checkout

The initial branch's general-component jobs invoked the development-only project
preflight while GitHub Actions used a detached exact-SHA checkout. The failure
occurred in Oracle class setup, before any Oracle test method ran. The test now
explicitly requests read-only `--audit`. Nineteen project-boundary and Oracle
setup regression tests pass, including foreign-origin and incorrect-project
refusal. Development/staged/push branch restrictions are unchanged. The original
[failed job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44338859559/job/134972635408)
remains a failure; its dependent readback correctly rejected incomplete evidence.

### Complete explicit RequestStatus, TransferTx and Transcript methods

[RequestStatus](src/types/request_status.md) implements all seven states, all
49 ordered transitions, terminal classification, exact Unicode trimming, ASCII
case/separator normalization, both Display methods and stable error codes.
The unknown-state payload retains the original trimmed bytes. The unchanged
original `trnm-types` crate supplies the independent comparison and all seven
original RequestStatus tests execute. Generic Serde consumers and the rest of
the types crate remain outside this completed method surface.

[TransferTx](src/types/transfer.md) implements the original signing-message,
address derivation, signing and strict-verification methods. It preserves the
existing signed domain, complete u128 amount/fee and u64 nonce, Unicode handling
and original error precedence. HIA executes the cryptography; Rust and Python
are independent test/build tools. Actual unaligned address inputs larger than
2 MiB and 4 MiB compare with the unchanged original crate and independent SHA-256.

Independent review found two real pre-final defects: two missing scratch bytes
at maximum decimal field widths, and checked arithmetic that trapped for
invalid hexadecimal `@`/backtick input instead of returning the original error.
The final minimum scratch includes the complete 144-byte fixed/numeric overhead;
all 106 non-hex ASCII characters are checked in private-key, public-key and
signature positions (318 original comparisons). The matching failed source
and actual trap observation are preserved in the development evidence, not in
a second active implementation. The earliest scratch failure has no confirmed
remaining complete source/stdout snapshot; that historical byte gap is explicit.
The initial Transcript borrow-check refusal similarly has a retained diagnostic,
not a complete snapshot of the superseded source.

[Transcript](src/types/transcript.md) implements all nine explicit original APIs,
including complete segment collection, materialized Merkle layers, repeated and
ordered proof targets, arbitrary typed proof verification and the exact envelope
hash field order. Its frozen development run passed nine tests with 1,309 original
comparisons, 1,512 shared-runner native calls and three separately bounded,
unaligned inputs above 2 MiB. All eight original module tests passed. Generic
Serde, relay authentication and durable Node ownership remain open.

### One shared SHA implementation per algorithm

[Incremental SHA-512](src/crypto/SHA512_STREAM.md) shares its canonical
initialization/compression/load/store functions with the retained arena ABI.
It supplies checked 128-bit message counts and incremental hashing for Transfer
without the old message-window ceiling. Regressions cover padding boundaries,
chunk boundaries, lifecycle refusal, count carry/overflow, unaligned native
calls and real messages through 4 MiB + 257 bytes, plus the earlier SHA-512 and
Ed25519 tests. No second compression implementation was introduced.

The SHA-256 stream likewise has one compression implementation. Its original
transport entry still enforces 2,098,176 bytes; the internal full-message helpers
allow at most 2^61−1 bytes, so the encoded 64-bit bit count cannot overflow.
The original transport cap, error order and refusal-without-mutation are tested
independently of the new larger address inputs. Manufactured near-limit contexts
validate arithmetic boundaries only; they are not huge-message performance evidence.

### Fixed consumers and compiler limits

The same shared-crypto change required explicit updates to the Node's fixed
Ed25519/settings function graph and the authenticated-request helper roster.
The request image initially exceeded the pinned compiler's 128-function limit.
Seven tiny literal-return helpers were folded into the existing literal dispatch;
5,676 original/merged input pairs, comprising 11,352 real native calls, matched.
The compiler limits and transport wire, cap and error order remain unchanged.

The final custom-consumer development source passed the Node's public build and
nine integrity groups with 379 controls and ten real CLI calls. On the configured
Linux host, the unchanged public transport qualifier passed 178 request controls,
14 SHA-256 controls and 170 comparisons against the actual original Rust crate
in 384.694 seconds. Those records bind that checkout and the frozen consumer
sources; subsequent committed-head CI remains separate.

### CI and provenance

The crypto-types job builds the unchanged `trnm-types` library with the locked
workspace graph and exports its exact rlib. It requires the real original
comparisons and always uploads Transfer's and Transcript's native libraries, original
adapters and executables, comparison observations and identities. Qualification binds all new
sources, tests, adapters and contracts. Full discovery is partitioned into
disjoint general, crypto-types and State-root rosters; incomplete setup, skipped
tests or missing actual executions cannot satisfy the independent readback.
Each job retains the original 20-minute limit. The new partition moves complete
cryptographic and types suites into their own job; it removes no cases.

The Oracle correction's exact
[push run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44442681639)
completed all 54 jobs successfully. Its separate
[PR run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44442705474)
completed all 472 general tests without failures or skips, but the job's actual
conclusion was CANCELLED after 20 minutes 6 seconds. Its dependent readback
correctly failed. The log does not contain an explicit cancellation cause; no
successful test summary is promoted to a successful job conclusion.

The initial combined development execution completed all 511 selected tests in
1,735.968 seconds, with one failure and five errors and unchanged source bytes.
Four evidence controls received `EPERM` when creating Unix sockets in this
execution environment; the complete original peer-lease suite also failed on
socket operations. The fifth error exposed a real reporting defect: a generated
near-limit SHA-256 fixture was incorrectly treated as a repository source path.
Those actual failures are retained. Later fixes and host executions have their
own source identities and cannot rewrite this result.

After the fixture and fixed-consumer corrections, the complete 74-test
crypto-types partition passed with zero failures, errors or skips in 273.387
seconds. The run made 10,792 self-hosted and 11 direct-backend shared-runner
calls, in addition to its bounded raw-pointer probes. Independent readback
rehashes all 15 actual build artifacts and all 1,200 source inputs, including the
single explicitly generated fixture. The sole plan's Git-blob pin was later
updated to document historical evidence gaps; that exact non-runtime delta is
retained separately. This development execution is not a whole-project or
future committed-head CI pass.

## Original package coverage

“Partial” means named method/kernel or finite owner coverage, including native
foundations described in the guide. It does not permit removal of the package.
The exact component-to-source mapping is machine checked in the migration inventory.

| Package | Owner | Current coverage | Retained responsibility |
| --- | --- | --- | --- |
| [trnm-types](../trillionnium/crates/trnm-types) | M00 | Partial: `types/request-status`, `types/transfer`, `types/transcript` | Shared task/identity/transcript/transaction data; delete consumption-consensus governance controls. |
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Partial: `executor/schedule`, `math/binary64` | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Not ported: — | Retained executor microbenchmark; not ledger throughput. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Partial: `mempool/lane_quota`, `mempool/lane_owner` | Typed signed admission, nonce reservations and durable local-pool/Node handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Not ported: — | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Partial: `oracle/values`, `oracle/serde-json` | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Not ported: — | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root`, `protocol/state-root-compact` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Partial: `peer-lease/values` | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Partial: `data-availability/rs46` | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Not ported: — | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Partial: `state/json_string`, `state/json_value`, `codec/json_primitives`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode` | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Not ported: — | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Partial: `control-plane/core`, `control-plane/registry`, `control-plane/local-guard` | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Not ported: — | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Not ported: — | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Not ported: — | Independent exact CAS and durable Unix service; generalized owner frontier only. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena`, `crypto/sha512_arena`, `crypto/ed25519_group`, `crypto/ed25519_verify`, `crypto/sha256_stream`, `crypto/ed25519-sign`, `crypto/sha512-stream` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
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

The current held-disk Node/M05 owner can construct a private default State and
consume a None-predecessor Parent through actual PNX1/SHA/Ed25519 admission.
It still needs Some/CheckedApply, complete successor authentication and expected
root checks, durable Node.db COMMIT, crash/reorg/rollback-floor/replay/outbox/ACK
ownership, and the same request's real deadline, Paid account and Host permit.
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
