# Current HIA rewrite audit

## Decision and scope

The complete HIA-native replacement is **IN PROGRESS**. The current inventory has
**62 kernel components, 30 native foundations and 293 HIA source files**. All
26 original Rust packages remain: 21 are partially ported and 5 are not ported.
No package has an accepted retirement witness. All nine whole-project gates
remain OPEN; `whole_chain_native`, `old_stack_can_be_removed` and
`production_activation` remain false. Component counts are not a completion percentage.

This audit accounts for all 41,494 paths in the baseline Git tree and every
original package and registered HIA source. The baseline has 291 HIA sources,
with no omitted or duplicate source owners; this continuation adds two research
kernels. All kernel and foundation Node-integration flags remain false. Of the
62 kernels, 61 are implemented finite units and `mempool/lane_quota` remains a
candidate awaiting its separate qualification. The baseline original Rust source
and the retained package graph are unchanged.

The audited continuation parent is
`62b4108946dead0688327c61aaa2afcb76bd0413`, with original `main` baseline
`59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`. Test observations below retain their
actual source identity; successful development checks do not assign a hosted
result to a later commit.

Use the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[migration inventory](../config/hia-migration-v1.json),
[original ownership inventory](../config/portability-inventory-v1.json) and
[native implementation guide](README.md) together. This page is the current audit,
not another development plan. The full chronological audit, including prior
failures and source identities, remains in
[immutable Git history](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2601aa95250d888cafe9bb4fdfe04a8aad0b7626/hia/AUDIT.md).

## Findings addressed in this continuation

### Current research encoding, Task validation and Metadata observation

The new research CBOR/hash primitives passed eight native test methods, 29,821
original/native CBOR comparisons, 45 original/native hash comparisons, 45
independent hash checks and 53 ABI/refusal controls. The unchanged original
research package passed all 53 active tests; its existing ignored test remains.
Strict Clippy and formatting passed. A separate review checked cursor advancement,
nonminimal/type-error precedence, UTF-8 boundaries, output capacity and exact
hash framing. The canonical and composed hash modules use 647 and 1,640 operations
under the original 8,192-operation compiler limit.

Task's validation cache is confined to private scratch and keyed by all 32
public-key bytes. It reuses decoded points and three comb tables while retaining
per-command message/R/S checks and the final group equation. The independent
cache regression and the original 1,390 records, 445 public cases and 112
allocation controls must complete on the current graph; the 180-second allocation
phase is unchanged.

Metadata's previous stack-size read reset the configured stack to the platform
default. The corrected observer records each actual 1 MiB pthread stack and
bounds glibc arena reservation to two within 512 MiB. Independent diagnostics
using the same baseline native images and cases measured VmPeak of 505,408 KiB
for the original observer and 178,580 KiB with both changes. Both local runs
passed; this is a measured explanation of the reservation pressure, not a
substitute for the failed hosted run. Every original native call, allocation
failure and concurrent owner remains required. Forty-five integrity controls
retain the original 41 and add four memory/stack report mutations.

The exact baseline has 24 completed workflows: 18 success and six failure.
Its HIA PR run is 66/67 and HIA push run is 64/67. The baseline failures include
Task's original allocation deadline, Metadata thread creation, Settlement's
native deadline and the original service/protocol cost gates. They remain
failures in their original runs.

PRs #972 and #973 have no missing functional increment: `fc867d2` incorporated
the complete 60-member SHA diagnostic readback, and `3adfedb` incorporated every
Payload Metadata source and control. Reapplying #972's older six-file upload
would break the current exact-member reader. The optimized-storage branch
`4e1c1ad` is an exact ancestor of the current integration branch. All these
histories remain reachable; no old implementation is removed without replacement.

### Prior shared SHA, native PQ owner and observed CI failures

The [current continuation record](qualification/shared-sha-pq-peer-development.json)
extends published `ae23b0a745186262eb8c987f714b5e9b7231e737`. Five additional
native HIA files bring the inventory to 260 sources and 27 foundations. The
public PQ owner passed all 343 original tests and two doc tests, 1,609 paired
cases, 24,671 ABI calls, 190 allocation controls, 1,329 lifetime calls, 49 reader
refusals and eight actual process controls on its frozen graph. All 34 original
test executables and required direct rlibs remain in its complete archive.
The integrated 966,824-byte native library reproduces the frozen image exactly.
This build is distinct from complete current-commit original/native CI.

The shared SHA change preserves all 440 observed word-boundary, wrapped-offset
and partial-write/trap outcomes. Its Task gate, regenerated Node composition,
all native Node groups and fresh Node/M05/Commitment originals passed. Actual
quota failures remain failed records; the successful repeats used another
temporary filesystem with unchanged source, compiler and limits.

The preceding push and PR each failed Task's unchanged 180-second test
controller and Peer Unix's inode-reuse fixture assertion. Peer product Rust and
HIA replies agreed before the assertion. The corrected fixture keeps both old
and rebound pathname inodes live and independently rechecks all raw bindings.
The complete corrected run passed 121 original tests, seven runtime groups and
14 integrity controls. Both predecessor CI archives and all corrective runs
were fully rehashed on two retained hosts. No original failure is relabelled.

Current discovery is 625 methods over disjoint 464/95/7/22/37 groups; the public
qualification graph contains 1,481 inputs. The workflow expands to 64 jobs,
including mandatory PQ qualification. All 66 root integration controls and
196 bootstrap cases passed; committed native execution remains required.
The reader cannot replace the producer's report, even with a zero exit code.
All previous source-specific records below remain historical observations.

### Prior Task Store, Peer Unix and source-specific CI binding

The [current owner record](qualification/additional-owners-development.json)
adds one final 48-source Task implementation and one final 14-source Peer Unix
implementation. Each development PASS retains its exact source identity,
complete original tests, native outputs, failed observations and independent
readback. The integrated audit-preflight and documentation changes require
fresh committed CI. Task's 29-operation project C provider, ArchiveStore,
StateImport, Peer payload/recovery ownership and live Node integration remain
open. No original package is eligible for retirement.

The frozen Peer Unix gate passed 121 outer original tests, seven runtime groups
and 13 integrity controls. The corrected fault observer stops only the pinned
tracee and lets strace reap it; earlier whole-group termination failures remain
in the complete 444,098,788-byte archive. Task source44 passed all 41 original
tests, full private/public Store observations, 112 allocator controls and 37
reader refusals. Four previously accepted evidence mutations now fail. Two
unavailable historical rlibs remain explicitly unavailable; all current final
archive references were resolved and checked.

The previous exact-head push passed 60 jobs. Its PR Work original job exceeded
the unchanged total 20-minute budget after actual runtime completion. The new
capture step preserves live-only observations and leaves full semantic review
to its mandatory successor; 92 controls passed, but the new hosted wall time is
unmeasured in that record. Its discovery was 624 methods and 1,460 source inputs. Three new
mandatory jobs expand the workflow to 63 jobs, all still limited to 20 minutes.
The four original compiler-admission cases passed for all 49 blocks. These
source/control checks do not certify the new commit's native execution.

Exact-head ML-DSA private and generic results were independently read back on
both push and PR. All four budget-control archives were also reread from
actual ELF identities and raw process observations. Original service and W1
confirmation under 0.25 CPU, 2 GiB, no swap, 256 live PIDs, four seconds and
16 workers remains unsuccessful. Cancelled macOS jobs without a runner remain
NOT_RUN. Whole-chain, cross-target, model/research and retirement gates stay open.

### Complete bounded ML-DSA and actual Host/CI corrections

The [ML-DSA contract](src/crypto/ML_DSA.md) and
[execution record](qualification/ml-dsa-development.json) add four HIA sources
for Pure ML-DSA-65/87 verify, keygen, sign and private Candidate ownership.
The 159-input frozen development gate passed 500 official mathematical checks,
669 comparisons with the unchanged original API, 1,213 shared native calls,
96 actual private allocation lifecycles and 12 capacity refusals. All 343
retained Rust tests, two doc tests, formatting and strict Clippy passed. Every
one of the 16 native methods and 20 evidence-integrity controls executed.
The 545,408,860-byte complete development archive was independently read back
on both retained hosts, including every one of its 1,432 members.

The original 12 overlapping-pointer probes remain explicit failed,
out-of-contract observations: the private legacy entry has no general foreign
ABI alias guard. The new source does not claim such a guard, automatic Drop,
constant-time behavior, ML-DSA-44, prehash support, PQ authorization or TLS.
The current integrated source has its own fresh qualification; earlier source
identities and results are not renamed as that run.

The [Work/Paid record](qualification/host-standalone-development.json) binds the
actual standalone constructor correction, complete 177-primitive/61-history
native run, 57-history original run, 44 retained tests, actual CLOCK/Paid faults
and 24 handshake schedules. Trace observations now correctly distinguish the
worker's real terminal and join phases. The reader-only follow-up changes the
stale original CLOCK count from 20/18 to its actual 32/30 and rejects old or
cross-module values; it does not claim another runtime execution. Fixed-parent
production acceptance and the original service budgets remain open.

On published source `88f610df3717b26f3c20e6455992da9004c144db`, both HIA
workflows failed despite successful Checkpoint, PeerLeaseStore and source/archive
jobs. The pull-request general component job reached its 20-minute limit;
Work original execution completed but the stale count reader rejected packaging.
The Oracle corpus and its preflight controls now have their own 22-method job.
A fresh isolated Oracle run actually passed all 22 methods, with both original
Cargo profiles and unchanged full retained original tests. Its old-source
archive has 21,164 complete content members and is independently verified on
both hosts. The new ML-DSA job executes its full original gate and all 36 native
component/integrity methods. The final consumer requires the exact five-way
600-method roster (440/95/7/22/36), each actual producer's success and one shared
source/run/attempt. All 60 jobs retain the original 20-minute limit.

### Native checkpoint authority and actual CI failures

The [checkpoint record](qualification/checkpoint-store-development.json) covers
29 HIA sources and all 48 owned implementation/qualification files. A fresh
original Rust 1.95 build passed all 77 retained tests with zero filtered or
ignored, strict Clippy and both format gates. Native execution completed 792
observation groups, 675 API and 31 CLI comparisons, ten actual daemon processes
and 23 durability cuts applied to both implementations. All 31 integrity
controls refused the altered evidence. This measures process termination and
injected I/O faults; it does not certify power-loss behavior.

The complete frozen development run belongs to 180 plus its exact owned overlay
(`c1d65794…`), not the current integration commit. The current integrated
106-input source set (`940c84f6…`) was actually rebuilt and independently read
back. Both 4,221,936-byte executables are identical to the qualified development
artifacts. No current runtime result is inferred from binary equality. The new
58th HIA CI job repeats the full original/native/readback sequence on its own
head. At that checkpoint increment there were 46 independent native bootstrap gates
and 557 discovered methods. The current five-partition roster is stated above.

The 419 PeerLeaseStore CI finished its complete tests and deliberate refusal
controls, then its archive step rejected a legitimate hard link. Runtime
observation packaging now copies each regular pathname's actual bytes into an
independent regular member and retains device/inode/link metadata. Six controls
cover real hard links, symlinks, FIFOs, source mutation, archive corruption and
refusal to overwrite an archive. The generic executable/source-bundle
`object_inventory` remains strict.

The [Darwin exit-race record](qualification/cleanup-exit-race-development.json)
preserves the failed prospective CI job and ten real reproductions: killpg
returned EPERM while immediate WNOWAIT had no exit result, followed by actual
exit and complete singleton census evidence. The correction allows at most
50 ms of read-only cleanup observation, then still requires both positive
checks. Linux and macOS each passed the 55 cleanup methods; 2,000 actual Darwin
EPERM cases retained the original output-cap failures after cleanup. Empty,
foreign, extra, unavailable or live process observations cannot authorize success.
The complete four-suite Linux attempt initially failed with 13 actual missing
GNU time errors. A fresh run of the same ten source inputs on ROG with the real
GNU time observer then passed all 87 methods with zero skips. Both observations
remain separate, and neither supplies a new hosted result.

### Current private owners and PQ foundations

The [current evidence record](qualification/continuation-development.json)
separates each actual execution from current-source admission and archival
availability. The restored source tree has one implementation per component;
the larger execution archives remain in verified operator copies. Complete raw
CI artifacts are still required after success or failure.

| Increment | Actual observed development result | Boundary still open |
| --- | --- | --- |
| [Some/CheckedApply](platform/node_commitment/README.md) | Five native Node partitions; 82 Some and 94 Checked methods; both 65,536/65,537 delta boundaries; original method comparisons | Durable Node.db COMMIT, reorg, recovery/outbox/ACK and the same request's Paid/Host authority |
| [PeerLeaseStore](platform/peer_lease_store/README.md) | 18 complete tests, 618 original comparisons, actual journal/head/lock/fsync and crash controls; partial and injected-failure runs both reject | Unix authority, Core authentication, payload custody, cross-target support and Node integration |
| [Work/Paid](platform/work_owner/README.md) | 61 native and 57 original histories, 177 primitives, 44 retained original tests, complete clock/Paid faults and independent private readback | Fixed-parent production positive, shared public admission, durable Node use and original service acceptance |
| [Keccak/SHA3/SHAKE](src/crypto/KECCAK.md) and [ML-DSA polynomials](src/crypto/ML_DSA_POLY.md) | Fresh complete 95-test crypto/types PASS, 17 native builds, 21,210 shared calls and 3,442 selected official byte vectors | Native ML-DSA now has a separate bounded gate; automatic secret ownership, timing qualification, authenticated identity and TLS remain open |

The published 419 private-owner/PQ 1,244-file component source map is
`36bf44bca1949b0c02ffcab9912e78635819fdf32472e43e24f83dc91aa2a0c5`.
Its complete discovery was 551 tests: 449 general, 95 crypto-types and seven
State-root. Discovery alone is not execution. The fresh crypto-types run passed
95/95, with zero failures, errors or skips in 515.760 seconds, and the complete
1,244-input graph was unchanged before and after execution. Its 38,816,692-byte
archive contains 1,366 logical files and 1,326 unique content objects; both
retained hosts independently reopened and hashed every object. This run does
not relabel the earlier 530-test result as execution of all current 551 tests.

Some's qualified 223-source graph is `0a934b54…`; the current graph differs in
the Peer composition registry entry and the corrected commitment README. Its
old results are not relabeled as current-graph qualification. The original
65,536-change native child completed in 201.143 seconds with no full-root pass;
65,537 completed in 178.247 seconds with one DeltaBudget fallback. Both retain
the original 240-second child and three-second cleanup bounds.

Review found duplicated SHA-256 compression in the Node's general and 94-byte
fork paths, additionally separate from the crypto arena/stream core. The old
README incorrectly called them a single shared compression implementation.
That statement is corrected. A real consolidation candidate passed all 78 hash
cases and 94 Checked methods, then timed out in both capacity cases at about
240.023 seconds; both children were killed and reaped. It was not integrated.
Host load was not recorded, so this failure does not prove deduplication is
fundamentally impossible. A new controlled implementation and capacity
comparison remain necessary.

Work/Paid's current 141 runtime inputs are byte-identical to the fully executed
development source. Its original 4,368-file snapshot is still the frozen c98
overlay and does not absorb later plan/config edits. The original stage took
1,113.411 seconds, including 325.849 seconds of fresh Cargo work. This leaves
little margin in the existing 20-minute CI job; no deadline or required method
was relaxed. Both old and Work/Paid handshake layouts have 24 actual controlled
cases. The new regression archive is a new compressed object containing the
same 76 verified original-build files; historical old-layout evidence resolves
through its immutable commit.

### Recovery and evidence availability

The temporary execution host was replaced during development. GitHub's exact
published source and the retained Mac/Desktop/ROG files supplied recovery.
Full530, both listed Some Node archives, PeerLeaseStore and Work/Paid archives
were independently rehashed in their surviving copies. This did not restore
three local-only archives: the Some/core direct-method archive, the failed SHA
consolidation archive and the old 95-test PQ archive whose transfer was incomplete.
Their previously observed identities and results remain explicit, but a complete
raw copy is currently unconfirmed. The fresh PQ execution has its own verified
source and raw archive; it does not recover the old run. Neither reconstructed
prose nor a partial upload is called a recovered original artifact.

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

### Shared crypto cores and the remaining Node SHA duplication

[Incremental SHA-512](src/crypto/SHA512_STREAM.md) shares its canonical
initialization/compression/load/store functions with the retained arena ABI.
It supplies checked 128-bit message counts and incremental hashing for Transfer
without the old message-window ceiling. Regressions cover padding boundaries,
chunk boundaries, lifecycle refusal, count carry/overflow, unaligned native
calls and real messages through 4 MiB + 257 bytes, plus the earlier SHA-512 and
Ed25519 tests. No second compression implementation was introduced.

The SHA-256 arena/stream family likewise has one compression implementation.
The separate Node general/fork implementations described above remain an open
deduplication obligation. Its original
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

The implementation was published as
[`c98fcbf7b2a0528ab1e87bdb8cb172f663331dd4`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/c98fcbf7b2a0528ab1e87bdb8cb172f663331dd4).
The [development record](qualification/types-development.json) and
[30-volume archive](qualification/types-development.parts/manifest.json) now
retain 27,110 logical files as 15,539 unique objects. The 182,921,280-byte archive
was fully decompressed, every regular member rehashed, then physically
reassembled from its published volumes. The exact original transport executable
is retained as an 86,524,208-byte XZ object; every one of its 610,853,352 decoded
bytes was independently checked against the executed binary's identity. The
consumer evidence remains bound to its actual 2601-plus-overlay source snapshot.
The initial failed full-run owner-specific raw stores remain at the explicit
external path in the record; their inclusion is not claimed. The two historical
source gaps above remain explicit. These archive operations do not change any
runtime qualification result.

The unchanged c98 source also completed the full 530-test component run in
2,249.150 seconds with zero failures, errors or skips. Its 1,200-input source
map matches the later 180 runtime map exactly. This was a controlled source
export with 6,061 materialized tracked files and explicitly absent historical
evidence paths; it was not a full tracked-checkout CI guard.

Both c98 HIA runs ([push](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44455017015),
[PR](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44455036414))
and both 180 HIA runs ([push](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44457316952),
[PR](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44457335753))
finished 55/55 jobs successfully. The c98 required baseline was cancelled.
The [180 required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44457335906)
has actual failures in both protocol lanes and both architecture cost lanes;
its remaining long jobs had not finished at this record's last observation.
Those independent failures are not masked by the HIA workflow's green result.
The current candidate has 57 jobs and 45 independent compiler bootstraps,
including complete commitment and private peer-store jobs. It still requires
its own exact-commit hosted execution.

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
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Partial: `research-protocol/canonical`, `research-protocol/hash` | Contribution/evaluation/lineage contracts independent of ledger consensus. |
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
