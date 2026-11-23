# HIA native implementation

This is the in-progress native HIA replacement of Trillionnium-Chain.
Run `python3 -B hia/tools/check_migration.py` from the repository root for the
current kernel, foundation, source and original-package counts. Each component
has one implementation directory. All **26 original Rust packages remain**,
zero retirements are accepted, and all nine whole-project gates remain open.

The [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets the migration sequence. The [migration inventory](../config/hia-migration-v1.json)
accounts for every original package and native source. The [audit](AUDIT.md)
retains source-specific findings, failures and remaining obligations.

## Current continuation

This continuation extends published `76381079bfc121a3a178dab8dab71e5290289169`.
Its PR HIA workflow completed successfully. All six push component partitions
and their independent 711-method reader also passed; all seven official ZIPs
were downloaded, verified and reread locally against the exact head and sources.
The push Settlement phase genuinely exceeded its original 240-second limit.
The current shared SHA-256 optimization completed that complete native phase in
206.720 seconds under the same limit, with independent native and allocation
readback. The new combined source requires its own committed qualification.
The [audit](AUDIT.md) retains the failure and its exact source-specific scope.

The [Research implementation](src/research_protocol/README.md) now adds
[raw state values](src/research_protocol/STATE_VALUES.md),
[indexing and graph admission](src/research_protocol/STATE_GRAPH.md),
[all seven state transitions](src/research_protocol/STATE_TRANSITION.md) and
[all seven getters, references and normalized export](src/research_protocol/STATE_QUERY.md)
to its existing signed-command and authority kernels. Actual state transitions
feed their native candidate into the next native step, with exact original
outcomes, canonical bytes and hashes checked throughout. The private continuations
require native signature validation and exclusive owner custody. The complete
opaque state owner, generic Serde, Hepta handoff and Node integration remain open.

The [Bench implementation](src/bench/README.md) adds
[integer/calendar text](src/bench/TEXT.md) and the
[complete ordered report and persisted bytes](src/bench/REPORT.md) to its native
workload, scheduler, environment and 51-field profile layers. Seven report methods
passed 2,572 native calls, including 42 real original-main runs, 21 complete
native profile/report chains, exact output bytes and real file-failure controls.
CLI parsing, OS environment/clock acquisition and file/process ownership remain
under implementation; prior scheduler safety differences remain explicit.

Fresh discovery has 738 methods in six disjoint groups: 523 general,
95 crypto-types, seven State-root, 22 Oracle, 37 ML-DSA and 54 Research.
The workflow retains its 68 jobs, 56 bootstraps, 50 source-admission blocks and
original 20-minute job limits. New Research state and Bench report observations
are retained on both success and failure. Enumeration does not establish a pass.
The exact published W1 service run still failed under the original four-second,
sixteen-worker limits; all nine whole-project gates remain OPEN.

## Transfer, request state, transcripts and continuous SHA-512

The [TransferTx implementation](src/types/transfer.md) executes the original
signing-message, address, signing and strict-verification methods. It keeps the
original signed domain, full u128 fields, Unicode validation and error order.
The [request-state implementation](src/types/request_status.md) covers all seven
states, the complete transition matrix, parsing, display and stable errors.
The [transcript implementation](src/types/transcript.md) covers all nine explicit
original APIs: envelope hashes, complete ordered segment collection, materialized
Merkle trees, single and batch proofs, root/leaf count and proof verification.
It preserves full u64/u128 fields, odd-leaf duplication, the original six errors
and the exact distinction between hashed fields and excluded raw payloads.
All three compare actual HIA machine code with the unchanged original `trnm-types`
library built with the repository's pinned Rust compiler. Generic Serde,
authenticated relay consumption and full Node integration remain open.

[Incremental SHA-512](src/crypto/SHA512_STREAM.md) shares one canonical compression
implementation with the original arena interface. It supports continuous
prefix/message hashing, checked 128-bit byte counts and finalization without the
old message-window ceiling. Real native controls include unaligned messages
through 4 MiB + 257 bytes and the complete earlier SHA-512/Ed25519 regressions.

The [types development record](qualification/types-development.json) binds the
complete 74-test native partition, exact original comparisons, generated-fixture
provenance, fixed-consumer checks and the separately identified failed 511-test
run. Its [canonical archive](qualification/types-development.parts/manifest.json)
retains 27,110 logical files through 15,539 unique content objects, including the
complete executed original transport binary in lossless compressed form. All
archive members, volumes and decompressed executable bytes were rehashed.
Two explicitly documented historical source gaps remain; this evidence does not
grant whole-project qualification or old-package retirement.

Oracle and ML-DSA qualification use the read-only project audit mode in an
exact-SHA detached checkout. ML-DSA now requires 21 integrity controls, including
a real detached Git checkout and refusals for foreign origins, production
activation and omission of the audit command or its source dependencies.
Development and push branch rules remain intact. The earlier CI preflight
failures and the complete dependent-reader refusals remain recorded.

## Current Oracle values and JSON

The [Oracle implementation](src/oracle/README.md) covers the unchanged original
library's 22 explicit public functions and methods, plus the six data types'
concrete JSON serialization and deserialization. Full i128/u128 values, original
hash framing without an added namespace, Unicode normalization, validation
precedence and both checked and wrapping arithmetic remain intact. Two separate
Cargo dependency graphs preserve the default and workspace arbitrary-precision
JSON configurations. These values do not grant network or settlement authority.

The [final development record](qualification/oracle-development.json) binds
19 actual tests, 10,259 native/original comparisons and 64 checked-overflow panic
and trap pairs. The complete original library runs all 118 retained tests in
each of four configurations, for 472 executions. Independent readback verifies
all 672 actual processes, all 26 artifacts and every referenced byte. Native
source sorting and cardinality use O(n log n) comparisons while retaining the
first original-order validation error. The actual old and new artifacts and
their full scaling observations remain in the canonical evidence archive.

The CI general component job builds both original dependency profiles and
uploads Oracle's complete separate process evidence. The final source still
requires its own committed hosted execution. Generic Serde providers, persistent
custody, authenticated source finality and live Node consumption remain open.

## Current private owners and Work concurrency fix

The [governance owner](src/governance/README.md) retains the complete original
GovernanceGuard public lifecycle, independent clones, roles, proposals, pause
state and both audit representations in private native state. Its
[final development record](qualification/governance-development.json) binds
10 tests, 94 original comparisons and 6,185 public operations plus 193 operations
through the fixed private boundary fixture. That fixture accepts no caller
state injection. Durable Node custody and activation remain open.

The [peer lease values](src/peer_lease/README.md) implement the original private
scope/token/namespace/frame and recovery value operations, projection decoding,
canonical hashes and the original 8 MiB body boundary. Thirteen tests cover
53 complete original comparisons and 8,095 operations. The
[complete record](qualification/peer-lease-development.json) includes an actual
unfiltered 121-test run of the unchanged Rust crate on the configured Linux host,
all 16 executed binaries/libraries and the exact original source archive.
Projection consistency does not establish Core authorization. The new
[persistent journal owner](platform/peer_lease_store/README.md) implements actual
FD/flock/fsync, journal/head replay and the private acquire/renew/revalidate/
release/drop lifecycle. Its 18 tests, 618 comparisons, crash cuts and I/O faults
have complete original execution and independent readback. Unix authority, Core
authentication, payload custody and live Node recovery remain open.

The [combined Work/Paid owner](platform/work_owner/README.md) retains one
same-thread Work/Paid worker, the corrected one-observation handshake and real
join/error lifetime handling. The current development record contains 61 native
histories, 175 primitive controls, three actual syscall traces, 57 original
histories, 44 retained original tests and complete clock/Paid faults. Independent
private readback passes. Both handshake layouts have 24 controlled scheduling
cases. Public request admission, fixed-parent production authority, persistent
Node use and the original four-second service budget remain open.

The [control-plane implementation](src/control_plane/README.md) provides the
original descriptor, action, plan and receipt digests, full signed 128-bit
parameter bounds, measurement checks and private ObserverRegistry lifecycle.
Native registration preserves generation ordering, exact capability ordering
for same-generation equality and retained workload measurements. The complete
unchanged original Rust crate supplies the independent comparison. The
[development record](qualification/control-plane-development.json) retains the
actual native artifacts, original executable, complete comparisons and allocation
failure observations. The [LocalPlanGuard implementation](src/control_plane/LOCAL_GUARD.md)
now evaluates the original policy with a real native Ed25519 verifier under an
explicitly new local provider profile and fresh signing domains. The
[guard record](qualification/control-guard-development.json) binds 14 tests,
1,361 original comparisons and 462 evaluations. This local profile is separate
from any production or post-quantum identity. Live authenticated plan application
and persistent Node integration remain open.

The [private SettlementVault](src/escrow/README.md) implements every original
public vault operation within a complete native session: full unsigned 128-bit
balances, lock/release/slash/transfer, owner checks, pause state, both audit logs,
independent clones and permanent request-ID replay protection. HIA owns all
mutable state and releases the complete session before returning. The
[development record](qualification/escrow-vault-development.json) binds the
unchanged original crate and all of its retained tests, complete native/original
operation histories, exact Unicode whitespace behavior and actual allocation
refusals. Live caller authentication, streaming custody and durable settlement
still require the Node owner.

These implementations use the pinned self-hosted HIA compiler. Their full
runtime observations and original binaries have separate CI artifacts; the
complete disjoint component-test consumer remains mandatory.

## Current data-availability codec

The [native RS(6,4) codec](src/data_availability/README.md) now implements the
original CRS1 encode and recovery operations through the complete **4 MiB**
source limit. It derives parity in GF(256), reconstructs every permitted four,
five or six shard set, checks the separate selected chunk pins, zero padding,
source SHA-256 and every extra shard before publishing output. It uses the
canonical HIA SHA compression functions and the pinned native compiler.

All **15 native tests** pass, including all 65,536 field products, 22 recoverable
subsets and the maximum 6,292,022-byte input. A late corruption in the sixth
shard leaves the entire 4 MiB output unchanged. The actual unchanged original
Rust crate passes its **12 retained tests** and matches **929 complete native
comparisons** (738 accepted, 191 rejected). The
[development record](qualification/rs46-development.json) binds the exact
artifacts, sources, raw observations and the initial failed original build.
TCM1/context ownership, provider storage, retention and Node adoption remain
required; this selected-chunk codec does not retire its original package.

## Current Node and transaction admission

The [held-disk Node/M05 owner](platform/mempool_node/README.md) opens or initializes
an isolated Genesis-format directory, retains its descriptors and constructs
private State from complete disk bytes. Actual PNX1/SHA/Ed25519 and State nonce
checks enter typed admission. Consuming Ready enters the same private Parent and
Prefix lifecycle as the public Node methods. Prepared is retired before Output
State; Prefix and Parent are retired before releasing the View lease.

The current private owner supports Some/CheckedApply snapshots and incremental
tree ownership alongside the existing None-predecessor path. Some has 82
explicit method observations and Checked has 94. Both exact 65,536/65,537 delta
boundaries execute with the original 240-second child and three-second cleanup
limits. Complete original Rust methods independently compare the snapshots,
changes, roots and errors. Persistent Node.db COMMIT, live successor authority,
reorg/local-pool recovery/outbox/ACK and the same request's Paid/Host permit
still require integration.

All five frozen native partitions and their mandatory traces passed. Actual
build-integrity controls total 379; the nonblocking writer has 30 physical
deadline controls. Those observations belong to the frozen 223-source graph.
The current registry and corrected README have a new graph identity, so current
CI rebuilds and requalifies it. The two surviving complete Node archives and
the separate unavailable local core archive are listed individually in the
current record; one is not represented as containing another's missing bytes.

Node currently has a general SHA-256 path and a specialized 94-byte fork path,
with separate compression code also distinct from the crypto arena/stream core.
An attempted consolidation passed hash and Checked-method tests but exceeded
both capacity deadlines; that candidate was not integrated. The corrected
[commitment guide](platform/node_commitment/README.md) records this remaining
deduplication obligation accurately.

## CI and evidence

The [Node/Work CI correction record](qualification/node-work-ci-corrections.json)
retains both complete 02f6 hosted outcomes: each has 45 successes, six failures
and two dependency skips. Five Node jobs failed because a negative test left a
hard link inside the complete controls output; the production packer correctly
refused it. Work returned the correct derived ticket, but its production reader
compared that ticket with the request target. Both reader/test defects are now
corrected without changing runtime images or resource budgets.

All seven Node reader profiles now pass, and the complete 12,020-entry /
3,112,724,764-byte output has been packaged and independently reread. The
409,242,432-byte transport archive is explicitly external and uses synthetic
transport lineage. Work passes all 22 production controls and 65 public source
controls; both historical real native outputs pass the complete corrected
validator. A fresh build reproduces every prior native section and all three
ELFs exactly. These observations require new commit-bound hosted execution.

The [Node development record](qualification/node-owner-development.json) binds the five native runs, two actual original Rust comparisons and the original integrated reader profiles. The correction record above binds the successor readers and complete transport regression. Full raw evidence and both independent original binaries remain explicitly external; this record does not claim hosted qualification.

The workflow expands to **67 jobs and 55 independent native compiler bootstrap
invocations**, with the original 20-minute job deadlines. The 49 source admission
blocks include one seven-owner matrix. Four bootstrap control groups exercise
196 positive/negative admission cases across those 49 blocks. The separate RS46 job
builds the full original crate and retains both actual executed binaries and
every comparison. Node adds five native
partitions, two original Rust comparisons and seven explicit evidence-reader
profiles. The additional commitment job checks complete Some/Checked methods,
both delta boundaries and the unchanged original Rust methods. The peer-store
job requires complete native/original execution plus actual incomplete/failure
refusal. Native child budgets remain 240 seconds plus three-second cleanup.

Current component discovery contains **667 methods** in five disjoint groups:
506 general, 95 crypto-types, seven State-root, 22 Oracle and 37 ML-DSA. The
Research, Bench, field/SHA boundary and Task CI methods belong to general. An independent coverage
consumer requires all five actual job successes. Every test must actually start and finish once, with
no failures or skips, on the same head/run/attempt and complete source map. Work/Host
uses native, original, complete qualification/package and independent readback
stages. Original executable bytes, complete raw streams, exact source trees and
actual started/completed rosters remain mandatory.

The published c98 and 180 predecessors each completed 55/55 HIA jobs in
both push and PR runs. Their exact run links and separate required-baseline
results are in the [audit](AUDIT.md). The 180 required baseline has actual
protocol and x64/arm64 service failures; the historical four-second confirmation
failure remains open. No new source or component test inherits a predecessor's
hosted result. The current 67-job candidate requires its own complete execution.

The [archive guide](qualification/ARCHIVES.md) identifies retained volume sets.
The [Work/Host development record](qualification/work-owner-development.json),
[toolchain follow-up](qualification/work-owner-toolchain-ci.json) and
[integration record](qualification/work-host-integration.json) retain the earlier
source graphs, complete raw observations and original failures. The
[portable Work/Host reader](tools/read_work_owner_development.py) verifies its
content-addressed development view and explicitly external original executable.
A development view is not a self-sufficient hosted qualification package.
Historical narratives remain in the audit, sole plan and Git history; this entry
point describes the active implementation.

## Foundations and whole-project gates

Earlier owners have separate contracts and records:
[OS](platform/README.md), [reactor](platform/reactor/README.md),
[transactions](storage/README.md), [requests](platform/transport_request/README.md),
[Delta](platform/node_delta/README.md), [private stacks](platform/private_stack/README.md),
[responses](platform/transport_response/README.md),
[Host checks](platform/host_checkpoint/README.md), [typed staging](platform/typed_store/README.md),
[Host resources](platform/host_resource/README.md),
[continuity](platform/continuity_store/README.md),
[Thread CPU](platform/thread_cpu/README.md), [Genesis](platform/genesis_store/README.md),
[Paid CPU](platform/paid_cpu/README.md), [State](platform/execution_state/README.md)
and [private Prepare](platform/execution_prepare/README.md).
The native syscall emitters and compiler are explicit trusted boundaries.
Core admission alone does not prove every emitted system-call effect.

| Whole-project gate | Outstanding acceptance |
| --- | --- |
| System I/O | Full filesystem, network, process and capability ownership in the actual Node. |
| Persistent Node | One durable transaction owner, original SQLite semantics, crash cuts, rollback floor and reorganization. |
| Cryptography | Complete PQ signatures, authenticated identity/TLS and every signature domain. |
| Node integration | Full transaction/application/mempool lifecycle, cancellation and private authority. |
| Service budget | Original 0.25 CPU, 2 GiB, zero swap, 256 PIDs, four-second and 16-attacker acceptance. |
| Cross-target | Original architectures/operating systems and exact artifact qualification. |
| Model loop | Actual train, independent evaluation, Adopt/NoUpdate, subsequent task and cold recovery. |
| Consensus research | Original work cost, public consensus, STARK/QROM and economic obligations. |
| Retirement | Complete equivalent replacement of all 26 packages and indispensable tools. |

Original service and history failures remain in the
[whole-project findings](qualification/whole-project-ci-findings.json),
[326 diagnosis](qualification/ci-326-observed-failures.json) and
[protocol supplement](qualification/ci-326-protocol-contract-failures.json).
A successful HIA workflow does not close those gates.

## Fixed sources and audit

| Input | Exact identity |
| --- | --- |
| Consolidated Chain baseline | `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88` |
| HIA toolchain | `TrillionniumFoundation/Hepta` at `f33d8da316de8fdf27b504371f1a5310997ff548` |
| Assembly / Core | `hia-asm.v1` / `hepta.hia.program.v8` |
| Executed target | Linux x86-64 |
| Qualified native compiler SHA-256 | `87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54` |

The original consolidated baseline audit counted 41,834 tracked files and 3,999,565,648 bytes.
`evidence/` accounted for 36,222 files and 3,804,721,963 bytes. The active Cargo
workspace contains 26 packages, with 1,621 Rust files and 702,001 physical lines
including tests. Repository history had already been consolidated into `main`;
these counts do not describe 26 independent final implementations.
The later `337fe8d` tree contains 40,920 tracked files. All 133 HIA sources in
this candidate have exactly one inventory owner; no original package has met
its retirement condition.

The ownership audit covers the entire tracked tree, the Cargo graph and all
18 long-lived modules. Semantic work in this increment concentrates on exact
wire parsing, integer work, hashing, replay, complete classical response codecs,
Settings construction, typed Delta semantics and native persistence. Existing
service, model-use, consensus-security and cross-architecture failures retain
their original status. Rewriting a deterministic function does not establish a
new proof of work hardness or satisfy an unexecuted service campaign.

## Implemented native components

The [M05 native lane owner](src/mempool/OWNER.md) now retains both physical
FIFO rings, exact ID membership and fairness across calls in one private
allocation. Its local native controls passed 41,365 owner calls and 2,042
canonical-policy regression calls. A separate real Rust compiler built the
complete unchanged original mempool crate and matched all 41,248 public
operations across 1,862 histories. The exact hosted test additionally compares
original Rust and native replies directly and cannot skip a missing oracle.
The [bound development record](qualification/mempool-owner-development.json)
retains both observations. Its typed fixture contract is separate from the held-disk
Node/M05 owner above. Persistent local-pool handoff and complete Node integration
remain open.

| Source | Implemented behavior | Native tests |
| --- | --- | --- |
| [RS(6,4) / CRS1](src/data_availability/README.md) | Full 4 MiB selected-chunk encode/recovery, independent pins, zero padding, source hash and all supplied shards | 15 native tests, 929 actual original Rust comparisons and 12 retained original tests |
| [AuditEvent](src/audit/README.md) | Complete public value constructor, six builders, Clone and Eq | 2,847 native calls; 1,849 actual original Rust cases and three original unit tests |
| [RawBindings](src/mempool/RAW_BINDINGS.md) | Actual private digest/body ownership and consume-before-mismatch semantics | 16,597 native calls; 16,471 actual original Rust operations across 1,220 histories |
| [ID](src/protocol/id.hepta), [hash text](src/protocol/hash.hepta) | Exact identifier alphabet/length and lowercase hash grammar | Complete byte alphabet and boundary controls |
| [PNH1](src/protocol/pnh1.hepta), [PGH2](src/protocol/pgh2.hepta) | Fixed header grammar and original error order | Original independent header oracle and byte mutations |
| [PNH1 encoder](src/protocol/pnh1_encode.hepta) | Candidate-only byte production; nine 32-byte hashes followed by height/time/nonce u64 LE in the descriptor, producing the exact 318-byte wire | Original Rust encoder and formal golden bytes; both native backends, per-field bytes, output tail and no-write length refusal |
| [ILF2](src/protocol/ilf2.hepta), [ILF3](src/protocol/ilf3.hepta) | Complete bounded factor/evolution witness grammar | Original vectors, every coefficient position, truncation and error precedence |
| [PNX1](src/protocol/pnx1.hepta) | Complete current envelope grammar, all 24 tags, funded contracts and nested witness validation | Independent byte specification, refusal precedence and original-Rust CI |
| [Sparse state root](src/protocol/state_root.hepta) | Original 256-level sparse root, exact domain framing, bounded heapsort and duplicate-path refusal | Independent bottom-up oracle, 65,536 actual rows, arena reuse and original-Rust CI adapter |
| [SHA-256](src/crypto/sha256.hepta) | Hash inputs through 1 MiB | Known vectors, `hashlib`, padding, real unaligned pointers and canaries |
| [SHA arena](src/crypto/sha256_arena.hepta) | One shared mutable arena for W1 hash input/output/work | Exact ranges, maximum length and no-write refusal |
| [SHA-512](src/crypto/sha512_arena.hepta) | Full SHA-512 and shared arena helper for Ed25519 | Independent hash oracle, padding, large messages, real unaligned pointers and canaries |
| [Ed25519 group](src/crypto/ed25519_group.hepta), [strict verifier](src/crypto/ed25519_verify.hepta) | Public field/group operations and strict signature verification through 128 KiB messages | Big-integer arithmetic, RFC vectors, all torsion/scalar boundaries and original-Rust CI |
| [PoN hash](src/crypto/pon_hash.hepta) | Original tag and per-part length framing | Original wire oracle, task/noise/header domains and ambiguous concatenations |
| [W1 encoding](src/work/encoding.hepta) | Fixed PNW1 size, magic and all canonical field words | All matrix rows and boundary words |
| [W1 field](src/work/field.hepta), [matrix](src/work/matrix.hepta) | Exact modular multiplication, addition, denoising and bounded matrices | Independent arbitrary-precision arithmetic, maximum values and dense products |
| [W1 verification](src/work/verify.hepta) | Complete deterministic non-cancelling PNW1 relation | Independent scalar transcript and direct `AB` product, target/trace/product attacks |
| [Replay](src/transport/replay.hepta) | Session/nonce/pending checks, ACK and pure successor proposals | Two native backends, original boundary vectors and Rust-reference CI |
| [Closed round](src/verification/closed_round.hepta) | Exact evaluator policy over canonical UTF-8 containers | Full-width scores, all arrival orders, Unicode, 1 MiB and Rust-reference CI |
| [Checkpoint V2](src/checkpoint/value_v2.hepta) | Canonical value construction/decoding, watermark, SHA binding and successor relation | Every record byte, truncation, field/error identity, full-width counters and original-Rust CI |
| [Binary64](src/math/README.md) | Shared exact finite binary64 arithmetic | Subnormal/exponent boundaries and 11,706 native arithmetic controls |
| [Executor](src/executor/README.md) | All seven scheduling strategies with explicit configuration and corrected maximum reader dependency | Independent conflict graph, 5,928 native calls, real 8,192-transaction arena and mandatory original-Rust comparison |
| [State String and Value](STATE_VALUE.md) | ASCII string codec and iterative typed Value construction, sorted last-wins objects, M06 grammar and canonical serialization | 1,518 native controls including a 7,280-level array; finite constructor profile and complete-State gate remain distinct |
| [Incremental SHA256](src/crypto/sha256_stream.hepta) | One continuous context, all compression blocks and one final padding | Fourteen controls through 2 MiB + 1,024 bytes |
| [Authenticated request](platform/transport_request/README.md) | All five classical request variants, complete 2 MiB frame and strict authentication equation | 178 native controls, complete payload mutation, original-default serde behavior and mandatory private original-Node oracle |
| [Shared JSON primitives](src/codec/json_primitives.hepta) | Single UTF-8, string and integer primitive closure, independently admitted before selection | 1,518 extraction controls; caller dependencies remain explicit |
| [JSON number](src/codec/json_number.hepta), [Value wire](src/codec/json_value_wire.hepta), [Value encoder](src/codec/json_value_encode.hepta) | Exact original-default serde number parsing/formatting, Unicode, complete Value construction and response serialization | 6,955 number, 3,546 Value parse and 372 Value encode controls; original Rust required in dedicated CI |
| [Ed25519 signing](src/crypto/ed25519_sign.hepta), [response verification](src/transport/authenticated_response.hepta), [signed response](src/transport/signed_response.hepta) | Complete classical response domains, signature production and strict verification | 73 signing, 33 producer and 125 verifier controls; producer uses a guarded private stack |
| [Settings development](src/node/README.md), [compact state root](src/protocol/state_root_compact.hepta) | Actual default configuration, four development keys, seven genesis rows and dynamically computed roots | 16 integrated tests, 102 shared-runner and 14 raw-pointer calls; 30 original-Rust cases required in CI |

The [cryptography guide](CRYPTO.md) specifies the SHA-512 and Ed25519 ABIs,
error order, arithmetic bounds and remaining key-ownership limitations. The
[state-root guide](STATE.md) defines the byte descriptor, scratch extent and
complete count/key/value limits. Its actual 65,536-row execution matched the
independent oracle in 299.705821145 seconds in exact `96a0846` CI; the prior
353.568397442-second local observation remains retained. These used small keys/values;
simultaneously maximal rows and values were not executed. The original service
time budget remains open. [Development observations](qualification/state-root-development.json)
retain the rejected over-capacity compiler optimization, the maximum-count run
and later controls with their distinct source and driver bindings.

The byte entries use `f0(readbuf, mutbuf, mutbuf) -> u32`. The scalar field
module uses explicit scalar exports. All tested algorithms execute emitted
machine code. Python supplies build orchestration and independent test inputs;
the Rust reference executable is a test oracle and is not a runtime dependency.

SHA-256 derives from Hepta's
`examples/hia_bootstrap/sha256.hepta` at the locked revision, original SHA-256
`93e97ac37f91fea4e0fa927f1af3b197bff31fb5f8edd2bfd4e70566fdc23c80`.
The public form changes the input bound to 1 MiB. The arena form combines the
views and moves only the digest/work offsets. No upstream license grant is
inferred from this repository's package metadata.

## Build and reproduce

Use a clean checkout of the exact Hepta revision in `toolchain.lock.json`.
Keep it outside this repository. The build driver refuses a different revision,
tracked modifications, an unsupported target or an unbound compiler executable.

```bash
export HIA_TOOLCHAIN_ROOT=/absolute/path/to/the/pinned/Hepta
python3 -B hia/tools/bootstrap.py --output /absolute/new/path/hia-bootstrap
```

Read `compiler` and `compiler_sha256` from the resulting `bootstrap.json` and
set `HIA_NATIVE_COMPILER` and `HIA_NATIVE_COMPILER_SHA256` to those exact values.
The bootstrap uses the official direct emitter for B0. Every successor and the
standalone compiler are emitted by HIA machine code. B1/B2/B3 must be identical;
the changed-source M1/M2/M3 witness must propagate and stabilize independently.

```bash
python3 -B hia/tools/build.py hia/src/work/verify.hepta \
  --backend selfhost --byte-export f0 --kind object \
  --compiler "$HIA_NATIVE_COMPILER" \
  --compiler-sha256 "$HIA_NATIVE_COMPILER_SHA256" \
  --output /absolute/new/path/work.o --receipt /absolute/new/path/work-build.json

python3 -B hia/tools/qualify.py --output /absolute/new/path/native-results.json
```

`selfhost` executes a sealed copy of the pinned native compiler with an empty
PATH. `direct` is a separately selected Python-hosted machine emitter used in
some differential controls. A refusal never switches between these routes.
GNU `ld` links generated objects for tests; it does not compile the algorithms
from another language. Calls execute in separate bounded processes. A signal,
timeout or missing report remains an execution failure.

### Shared HIA source

[components.json](components.json) selects named functions from single canonical
SHA, Ed25519, binary64, JSON and state-root sources. Storage v2 selects the existing
state-root SHA compression functions through its independently verified framing
component. There are no copied crypto or JSON helper implementations.
PNX1 explicitly includes the shared ILF2/ILF3 validators and coefficient scans. Their
entry files therefore require package composition before admission. The driver
checks each included source, joins only the named HIA functions and submits the
complete program to the official Core verifier and native compiler. It refuses
unknown names, duplicate symbols, traversal, symlinks and dependency cycles.
An included component may declare its own explicit dependencies. Core must
validate that entire component independently, even functions the caller does
not select. Only functions defined in the component's own source can be
selected; its imported helpers are not re-exported. The caller must still name
every helper in its own flat closure. Every source used for either independent
validation or final emission is captured and rechecked after compilation.
Sources are restricted to the explicit `src/`, `platform/` and `storage/` roots.
The separate migration inventory rejects any unaccounted HIA source, duplicate
owner, missing source or premature foundation-retirement claim.
Receipts bind every input, the composed assembly and the resulting Core. There
is no second copied SHA helper in the W1 or PoN source files.

### Original Rust differential

The first test adapter directly imports the retained `trnm-transport` and
`closed_round` modules. Four additional adapters link the unchanged original
`trnm-protocol`, `trnm-checkpoint-types`, `trnm-crypto-primitives` and
`trnm-mvcc-fee` crates with their locked dependencies. The State adapter calls
actual `serde_json::Value` construction/serialization and M06 root grammar.
The protocol adapter compares both PNX1 and the original
`state_root_from_entries` function. These adapters do not reimplement the
policies they compare.

```bash
rustc --edition=2021 -O hia/tests/rust_reference.rs -o /absolute/new/path/rust-reference
export TRNM_HIA_RUST_REFERENCE=/absolute/new/path/rust-reference
RUST_VALUE_TARGET=/absolute/new/path/rust-values
cargo build --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-protocol -p trnm-checkpoint-types -p trnm-crypto-primitives -p trnm-mvcc-fee \
  -p trnm-types \
  --target-dir "$RUST_VALUE_TARGET" --message-format=json > /absolute/new/path/rust-build.jsonl
export TRNM_HIA_RUST_TYPES_RLIB="$RUST_VALUE_TARGET/debug/libtrnm_types.rlib"
rustc --edition=2021 -O hia/tests/rust_protocol_reference.rs \
  --extern trnm_protocol="$RUST_VALUE_TARGET/debug/libtrnm_protocol.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-protocol
rustc --edition=2021 -O hia/tests/rust_checkpoint_reference.rs \
  --extern trnm_checkpoint_types="$RUST_VALUE_TARGET/debug/libtrnm_checkpoint_types.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-checkpoint
rustc --edition=2021 -O hia/tests/rust_crypto_reference.rs \
  --extern trnm_crypto_primitives="$RUST_VALUE_TARGET/debug/libtrnm_crypto_primitives.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-crypto
export TRNM_HIA_RUST_PROTOCOL_REFERENCE=/absolute/new/path/rust-protocol
export TRNM_HIA_RUST_CHECKPOINT_REFERENCE=/absolute/new/path/rust-checkpoint
export TRNM_HIA_RUST_CRYPTO_REFERENCE=/absolute/new/path/rust-crypto
python3 - /absolute/new/path/rust-build.jsonl "$RUST_VALUE_TARGET" /absolute/new/path/rust-state <<'PYCODE'
import json, pathlib, subprocess, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
serde = [row for row in rows if row.get('reason') == 'compiler-artifact' and row['target']['name'] == 'serde_json']
assert len(serde) == 1 and serde[0]['package_id'].endswith('serde_json@1.0.149')
assert set(serde[0]['features']) == {'default', 'std'}
rlibs = [name for name in serde[0]['filenames'] if name.endswith('.rlib')]
assert len(rlibs) == 1
base = pathlib.Path(sys.argv[2]) / 'debug'
subprocess.run(['rustc', '--edition=2021', '-O', 'hia/tests/rust_state_reference.rs', '--extern', 'trnm_mvcc_fee=' + str(base / 'libtrnm_mvcc_fee.rlib'), '--extern', 'serde_json=' + rlibs[0], '-L', 'dependency=' + str(base / 'deps'), '-o', sys.argv[3]], check=True)
PYCODE
export TRNM_HIA_RUST_STATE_REFERENCE=/absolute/new/path/rust-state
python3 -B hia/tools/qualify.py --require-rust-oracle \
  --output /absolute/new/path/native-and-rust-results.json
```

The five original reference executables and the unchanged `trnm-types` library
are required for a complete component run. The Transfer and Transcript suites
refuse a missing library; RequestStatus and Transcript also execute all seven
and eight original module tests, respectively. The workflow also builds both isolated Oracle dependency profiles and
exports their exact dependency directories. Follow its complete environment
setup when reproducing the full suite; the snippet above builds only the shared
reference adapters. CI preserves the exact head's observations, including the
Transfer and Transcript native libraries, original executables and full comparison
reports. The fixed
`SourceOk` in the test fixture only exposes pure transport boundaries; source
authentication is an independent integration obligation.

## Transaction and checkpoint value contracts

`pnx1.hepta` accepts the exact existing `PNX1` signed wire, including its opaque
64-byte signature. It preserves outer Limit/Length/Version order, exact payload
length, the complete 24-tag dispatch, nested ILF errors, then nonce and fee checks.
Fixed payloads stay opaque wherever the original decoder only checks their size;
decoding does not introduce signature or account authority. Codes 0–4 are the
original wire results. Output remains unchanged. For tags 23/24, scratch must
hold the payload; code 100 reports insufficient scratch before mutation. The
validator copies exactly that payload prefix and uses explicit shared loans to
the common ILF routines. The remainder of scratch stays unchanged.

`checkpoint/value_v2.hepta` accepts a local request header
`CPV2, version:u8(1), operation:u8, reserved:u16(0)` followed by the original
record or fields. Operations 0–3 decode a 672-byte record, construct from its
624 field bytes, check a predecessor/target pair, and construct a 104-byte
watermark. All original integers and hash length prefixes use big-endian order.
The HIA code builds the original 713-byte domain-separated SHA input itself.
Success writes the canonical result and preserves output suffixes; all failure
paths preserve output. Hash operations require 132,256 scratch bytes. The
watermark-only operation requires no scratch. Codes 1–28 preserve original error
and field identity; 100–103 report local envelope or capacity errors. The complete
mapping and independent constructors are in [test_checkpoint.py](tests/test_checkpoint.py).
No store trait, durable CAS, external freshness or actual node root is certified
by successful value validation.

## W1 contracts

`encoding.hepta` has the original wire-only precheck order: length, version,
field words. Codes 0/1/2/3 mean success/Length/Version/Field.

`matrix.hepta` takes the local descriptor
`rows:u8, inner:u8, cols:u8, version:u8(1), A:u32LE[], B:u32LE[]`.
Dimensions are 1–64. Input/output extents must be exact and every word canonical.
Output is the row-major product modulo `Q = 2^32 - 5`. Failure leaves output
and scratch unchanged. This descriptor is not a blockchain wire schema.

`verify.hepta` takes 49,284 bytes:
`challenge[32] + expected_task[32] + target[32] + PNW1[49188]`.
Output must contain exactly 16,384 bytes; scratch must contain at least 259,232
bytes. It preserves the original full-verifier order, including zero-target
rejection before C/A/B field checks and transcript verification before product
comparison. Codes 1–8 are Length, Version, Field, Task, Transcript, Product,
Target and NoiseBudget. Code 9 is an internal SHA-contract refusal. Only complete
success writes the external product. Scratch is private working memory and may
change on a late refusal; bytes beyond its declared working extent stay intact.

For canonical operands, every product is below `2^64`. Reducing each product
before adding keeps each sum below `2Q`, so the native u64 path equals the
original wider-integer sum modulo Q. Denoising computes
`C' - AF - E(B+F) mod Q`; the independent test oracle computes `AB` directly.
The exact 32,768 transcript updates and their hash order are preserved.

This low-level entry implements the complete deterministic relation with
cancellation disabled. The separate [Work/Host owner](platform/work_owner/README.md)
has its own cancellation, resource and private-ownership contract and source-bound
qualification. Complete same-request Node/Paid integration and original service
acceptance remain open.

## Retained compiler qualification

[compiler-binding.json](qualification/compiler-binding.json) binds the original
full cold report and its losslessly compressed nested report. The original gate
ran with 180 seconds for qualification and 3 seconds for cleanup. It completed
in 154.807339324 seconds, with 916 source inputs, 11 outer checks, 5,049 nested
checks and 38 phases. The generated standalone ELF is byte-identical to the
compiler used for these Chain components. The reports preserve the target,
trusted dependencies and precise qualification scope.

## Repository consolidation

The historical cleanup index records 1,622 redundant payload copies and
1,628,294,407 original bytes removed from the active tree. Original Git blobs,
source-bound archive readers, failed observations and qualification limits remain.
Current HIA components have one final implementation tree; authoring trees
and intermediate builds remain external.

Run the source inventory and complete retirement gate separately:

```bash
python3 -B hia/tools/check_migration.py
python3 -B hia/tools/check_migration.py --require-retirement
```

The retirement command currently refuses all 26 retained packages. The audit
trail and historical source-specific observations remain in [AUDIT.md](AUDIT.md)
and the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [published 876 overview](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/876eb577dac61854c535a91ab1480f312d1d6173/hia/README.md)
preserves the previous complete narrative.
