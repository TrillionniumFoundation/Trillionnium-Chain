# Next architecture and security evidence

**HOLD_NO_GO.** Failures and partial attempts are retained. This index packages observations; it does not run tests or establish native execution from source checks.

## Result of this increment

The six-stream program is implemented in [Draft PR #791](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/791). The source repair, bounded Cell components, research controls and qualification contracts are ready for review. Production, independent-node, external Hepta, PQ128 and sustainable-economics qualification remain **HOLD_NO_GO**.

The [corrected C4 CI run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42456517352) completed successfully on all four lanes: x86_64/head, x86_64/prospective-merge, ARM64/head and ARM64/prospective-merge. The [terminal job records](raw/ci-receipt-fixed-jobs-final.json) and all four imported artifacts are retained below. C4 changes only the new workflow's receipt wiring; the runtime implementation is unchanged from C3.

| Executed control | Observed result and scope |
| --- | --- |
| Complete default-feature P2P crate | 411 native unit/integration tests and 10 compile-fail doctests passed in each C4 lane. The 24 new BEP52/RS46 tests are included in that native total. Optional feature configurations are not inferred. |
| New native packet observer | 9 tests passed; live/recovery ownership, cold source immutability, corruption refusals and both supported backends remain covered. |
| Accepted-task integration target | 4 tests passed. One enhanced case uses actual native reserve/receipt/accept settlement and compares the complete live, cold API and CLI.result values on both backends, including the nonempty eight-field task binding. |
| Existing Hepta boundary controls | 4 classical receiver, 6 PQ receiver and 3 native accepted-task checks passed. These are local receiver tests, not external owner or Runtime FinalUse executions. |
| Existing native controls | 2 packet-status tests, the process-cut/recovery test, real heavier-fork test and original public Host outbox test passed in C4. Existing growth controls also passed. |
| Native transport replay | 4 additional local C3 library tests passed; these are separately recorded in attempt 4. |
| Research and arithmetic | 33 Python tests passed, with the exact finite research fixture preserved. |
| Source and build controls | Original full tracked-byte source checks, 43 source-integrity negative controls, locked dependency graph, all-source formatting, repository checks and strict default-feature Clippy for both affected crates/all targets passed in the corresponding recorded executions. |
| Native Cell process observations | Both complete observations passed with all 27 planned workload repeats. Source and executable hashes were checked, and actual child-process CPU and peak RSS are retained. |

The C4 original Host fixture is supported by its actual named child log, execution manifest, launcher and before/after kernel observations. For example, [the x86 head execution manifest](raw/ci-fixed-x86-head/public-fixtures/native_node/test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner/manifest.json) records the exact test, real start, exit 0, reaping and no cleanup errors; the [Host controller result](raw/ci-fixed-x86-head/public-fixtures/native_node/test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner-host/controller-result.json) records the original parent and its actual execution. The observed limits are 0.25 CPU, 2 GiB, zero swap and 256 PIDs. This one fixture does not replace the original complete four-second/sixteen-hostile-worker service campaigns. Preparation and lease documents correctly retain their own “no tests executed by this preparation/lease” scope.

### Failures remain part of the result

The initial Node compile failed on a snapshot-limit visibility boundary and was corrected without changing the limit. Initial C3 CI rejected the public Host fixture before child execution because the new workflow omitted the original launcher's required source.json; C4 supplies a byte-identical ordinary copy of the original verifier output and compares it again afterward.

Local source-B P2P execution retained 376 passed/1 failed and one failed exact diagnostic replay. Local C3 attempt 4 retained 374 passed/3 failed; the errors were two WouldBlock returns and one no-admissible-provider refusal. Its ordinary development-host outbox invocation failed PUBLIC_HOST_KERNEL_PARENT. These records are retained separately from complete CI passes, with no deadline relaxation and no claim that their cause has been established. Attempt 3's 600-second source-audit timeout and the earlier cancelled/uncertain setup incidents are also retained in the [incident ledger](raw/delivery-and-environment-incidents.json).

Cell inputs are deterministic synthetic bytes. The per-phase analysis and whole-run resource observations below do not establish consensus throughput, model-device loading, WAN service, VRAM use or real reward sustainability.


## Source identities

| Label | Reference commit |
| --- | --- |
| A | `539738590dbfd4449bc0ca2718462670245f3ab6` |
| B | `bced22f712552302848e3e04f7acf24068af2048` |
| C3 | `a93024cfdd4f4a4dfede03507f3b3289385bfc49` |
| C4-CI-only | `9f54b05c643185a5041fc1f78cef77e95877f52a` |

C4 changes only CI workflow; its CI observations remain separate from A, B and C3 local runs. The table reads summary.source_commit first, then explicit CI candidate/tested_commit fields; the cost wrapper uses repo_head. It does not infer source identity from arbitrary JSON text. Source-record byte equality compares the two raw JSON files, not a newly executed source check.

## Execution groups

| Raw group | Source commit / CI candidate | Tested commit | Recorded outcomes | Source record bytes equal |
| --- | --- | --- | --- | --- |
| [raw/attempt-1](raw/attempt-1) | 539738590dbfd4449bc0ca2718462670245f3ab6 | 539738590dbfd4449bc0ca2718462670245f3ab6 | commands recorded/attempted: 12; failed/timeout: native-packet-observer; incomplete fields: none | true |
| [raw/attempt-2](raw/attempt-2) | bced22f712552302848e3e04f7acf24068af2048 | bced22f712552302848e3e04f7acf24068af2048 | commands recorded/attempted: 12; failed/timeout: p2p-complete; incomplete fields: none | true |
| [raw/attempt-2-continuation](raw/attempt-2-continuation) | unknown | unknown | recorded outcomes unknown; inspect raw group | unknown |
| [raw/attempt-3](raw/attempt-3) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | commands recorded/attempted: 2; failed/timeout: source-before; incomplete fields: none | unknown |
| [raw/attempt-4](raw/attempt-4) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | commands recorded/attempted: 29; failed/timeout: p2p-complete, test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner; incomplete fields: none | true |
| [raw/b-tcp-diagnostic](raw/b-tcp-diagnostic) | unknown | unknown | recorded outcomes unknown; inspect raw group | unknown |
| [raw/cell-cost-observation](raw/cell-cost-observation) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | recorded outcomes unknown; inspect raw group | unknown |
| [raw/cell-cost-source-controls](raw/cell-cost-source-controls) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | commands recorded/attempted: 3; failed/timeout: none recorded; incomplete fields: none | true |
| [raw/ci-arm-head](raw/ci-arm-head) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | steps outcome/conclusion: failure/failure=1; success/success=14; failed/cancelled: native_packet; incomplete: none recorded | true |
| [raw/ci-arm-merge](raw/ci-arm-merge) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | 6b3c58f215087ba5f36218d05495f56132877ba7 | steps outcome/conclusion: failure/failure=1; success/success=14; failed/cancelled: native_packet; incomplete: none recorded | true |
| [raw/ci-fixed-arm-head](raw/ci-fixed-arm-head) | 9f54b05c643185a5041fc1f78cef77e95877f52a | 9f54b05c643185a5041fc1f78cef77e95877f52a | steps outcome/conclusion: success/success=15; failed/cancelled: none recorded; incomplete: none recorded | true |
| [raw/ci-fixed-arm-merge](raw/ci-fixed-arm-merge) | 9f54b05c643185a5041fc1f78cef77e95877f52a | bdf2fe11b63d04210bc3853613356928ac85369b | steps outcome/conclusion: success/success=15; failed/cancelled: none recorded; incomplete: none recorded | true |
| [raw/ci-fixed-x86-head](raw/ci-fixed-x86-head) | 9f54b05c643185a5041fc1f78cef77e95877f52a | 9f54b05c643185a5041fc1f78cef77e95877f52a | steps outcome/conclusion: success/success=15; failed/cancelled: none recorded; incomplete: none recorded | true |
| [raw/ci-fixed-x86-merge](raw/ci-fixed-x86-merge) | 9f54b05c643185a5041fc1f78cef77e95877f52a | bdf2fe11b63d04210bc3853613356928ac85369b | steps outcome/conclusion: success/success=15; failed/cancelled: none recorded; incomplete: none recorded | true |
| [raw/ci-x86-head](raw/ci-x86-head) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | steps outcome/conclusion: failure/failure=1; success/success=14; failed/cancelled: native_packet; incomplete: none recorded | true |
| [raw/ci-x86-merge](raw/ci-x86-merge) | a93024cfdd4f4a4dfede03507f3b3289385bfc49 | 6b3c58f215087ba5f36218d05495f56132877ba7 | steps outcome/conclusion: failure/failure=1; success/success=14; failed/cancelled: native_packet; incomplete: none recorded | true |
| [raw/source-io-incident](raw/source-io-incident) | unknown | unknown | recorded outcomes unknown; inspect raw group | unknown |

Incomplete CI steps remain unknown; outcome and conclusion are reported separately, including continued failures. Complete metadata and statuses are in [execution-index.json](execution-index.json); every literal test-result line is in [test-result-records.md](test-result-records.md). There is no cross-file, suite, attempt or source sum/deduplication. Unidentified stdout remains unspecified; local final counts are not assumed to be native tests or doctests.

## Whole-run Cell observations

The fixed planned denominator is 27 workload repeats (15 BEP52 + 12 RS46). Missing/failed observations do not reduce it. CPU/RSS cover the reaped child tree including timeout and optional GNU time overhead, not phase attribution or simultaneous summed RSS. All original counters, phase data and failures remain in [raw/cell-cost-observation/summary.json](raw/cell-cost-observation/summary.json).

| Example | Planned / reported verified | Validation / CPU-RSS complete | Wall seconds | User CPU seconds | System CPU seconds | RSS KiB | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- |
| "cell_bep52_cost_v1" | 15 / 15 | [true, true] | 37.811395984 | 0.865868 | 0.38509 | 18356 | [] |
| "cell_rs46_cost_v1" | 12 / 12 | [true, true] | 33.270224815 | 1.4948869999999999 | 0.443911 | 19508 | [] |

Earlier phase analysis: [raw/ci-x86-head-cost-analysis.json](raw/ci-x86-head-cost-analysis.json).

All supplied input bytes are preserved under `raw/`; runners are copied unchanged. [SHA256SUMS](SHA256SUMS) hashes every packaged file except itself. Integrity hashes do not authenticate operators, meters, payments or qualification.

## Program scope and source boundary

Trillionnium-Chain Next Architecture & Security Qualification continues the
existing integration lineage under the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [six-stream contract](../../docs/development/specs/pon/NEXT_ARCHITECTURE_SECURITY_QUALIFICATION_V1.md)
and [program registry](../../config/pon/next-architecture-security-v1.json)
define responsibilities and acceptance gates. The project aims to support
independent Hepta nodes creating, evaluating, preserving, distributing and
evolving neural capabilities, while retaining the original owners of artifacts,
effects, resources and execution authority.

Draft PR #791 continues the #784 integration line from the audited
`b5c655ebe9611b3d62cf739e61e6867decc053e3` baseline. The implementation source for the main local and initial CI observations is
`a93024cfdd4f4a4dfede03507f3b3289385bfc49`. The CI receipt-path repair is
`9f54b05c643185a5041fc1f78cef77e95877f52a` and changes only the new workflow.
The execution tables identify each source and outcome separately.

The [module maturity registry](../../config/pon/module-maturity-v1.json)
records `has_native_component=true` for all 18 modules, M00 through M17,
including M02, M07, M08 and M14. It records zero independently accepted modules;
all also retain `native_product_integrated=false`. The top-level
`runtime_implemented=false` describes the absence of a complete qualified
runtime. It must not be reported as absence of those native Rust components.

## Six streams: delivered boundaries and next gates

### 1. Consensus Research

The [consensus and PQ research specification](../../docs/development/specs/pon/NEXT_CONSENSUS_PQ_RESEARCH_V1.md)
adds fixed candidate-weight and sampling exercises implemented in
[counterexamples.py](../../formal/next-architecture-security/counterexamples.py).
Exact rational arithmetic keeps counterexamples reproducible without floating
point approximations or caller-selected formulas. Results distinguish a found
counterexample from `NOT_REFUTED_ON_FINITE_GRID`, and separately retain unknown
physical resource interpretations. The current PoN work rule, target and
chainwork are unchanged.

The next gate is a complete comparison of the existing PoN relation and
explicit hybrid alternatives against the cheapest legal preparation, cache,
delegation, reuse and execution strategies. Measurements must include losing
attempts, cancellation and cleanup. Resource units, calibration, admission,
DAA and network assumptions must be fixed before importing a security theorem.
A measured legal algorithm gives an achievable upper bound on minimum cost;
it does not establish a lower bound over every legal algorithm.

### 2. Native Runtime

The [native packet observation specification](../../docs/development/specs/pon/NATIVE_PACKET_STATUS_OBSERVATION_V1.md)
repairs the actual `packet-status` opening path for the existing Legacy and
authenticated-state backends. Reconciliation holds the original namespace
lock, copies a closed store into a bounded private snapshot and opens only
that copy through SQLite. It preserves schema, context, active-state,
replay/outbox, budget and ancestry checks without recovering or activating an
admitted packet. Shared read helpers preserve typed completed-journal,
recovery-candidate and activation-selection checks.

The next gate retains the original independent-node and complete-service
campaigns: startup, admission, fork recovery, durable state, client behavior
and fault handling under the original resource contract. This query repair
is a concrete component improvement. Its scope does not extend to external
owners or other backends by inference. Evaluation observation CLIs retain
their documented ordinary owner-open and recovery behavior.

### 3. P2P Cell Commons

The [BEP52 binding](../../docs/development/specs/pon/CELL_BEP52_BINDING_V1.md)
adds a restricted descriptor, BTMH magnet representation and CBP1 companion
proof over the existing owner-pinned TCM1 payload. The
[RS46 profile](../../docs/development/specs/pon/CELL_RS46_CHUNK_V1.md)
adds fixed RS(6,4) chunk reconstruction with explicit field, matrix, indices,
sizes, padding and context. Reconstructed bytes return to the original TCM1
chunk hash and complete-payload verification. A content address establishes
byte identity, not release selection or permission to execute.

The next gate is actual interoperable discovery and swarm retrieval, reviewed
shard placement, independent custody and repair, all charged to existing
reservations and original deadlines. These bounded offline components do not
implement a complete DHT, BitTorrent peer or distributed storage service.
The PN5 independent-administration and elapsed-time requirements remain intact.

### 4. Hepta Integration

The [owner binding map](../../docs/development/specs/pon/NEXT_HEPTA_OWNER_BINDINGS_V1.md)
connects real local receiver interfaces to the existing Learning Artifact,
Evaluation, kernel.operations and Runtime FinalUse responsibilities. It retains
fresh expected-context checks for classical and PQ artifact handoffs, exact
accepted-task observation and original effect reconciliation. The node's peer
transport outbox does not replace Hepta's business-effect journal.

The next gate requires a frozen paired consumer contract and three actual
Hepta lineage cycles. Each must use the actually installed parent, authorized
experience, frozen evaluation, original operation identity and actual
next-task loaded-model/generation readback. No-update outcomes remain valid;
revocation, cancellation, restart and reorg must preserve original receipts.
Current packet output is v3 with optional `accepted_task`, nested schema 1.
The handoff document's later schema-4 requirement remains unresolved; this
increment neither relabels the output nor relaxes that requirement.

### 5. PQ Security

The research specification preserves RISC0 join-v2 and Plonky3 W1 as separate
proof profiles. All fifteen inherited RISC0 obligations remain OPEN. Plonky3
must satisfy its own relation, AIR/PCS/FRI, restricted commitment, shared hash
and challenge-distribution obligations. RISC0 recursion counts and conditional
security estimates cannot be transferred to that profile.

The next gate is complete profile-specific noninteractive security, including
compiler/relation coverage, extraction, hash and Fiat-Shamir composition,
adaptive use and authenticated global lifetime query budgets. Signature
authorization, computation soundness and quantum work/chainweight remain
different claims. Neither standardized PQ primitives nor a component estimate
establish whole-chain PQ128. The sampling examples refute substitutions between
toy sampling laws; they establish no FRI attack or actual QROM distribution.

### 6. Performance and Economics

The program provides local synthetic Cell binding and erasure-recovery
observation programs, plus the
[campaign arithmetic reader](../../formal/next-architecture-security/performance_economics.py).
It requires one outcome for every declared planned operation and preserves
rejected, cancelled, timed-out, unknown and unstarted work. Metric kinds use
fixed units. Late success remains charged but earns no on-time goodput.
Missing meters or costs propagate as unknown. Per-operation memory peaks and
successful-only latency order statistics retain their limited scope.

The next gate requires same-source, same-resource complete campaigns covering
confirmation, verification and rejection, complete retrieval, device loading,
CPU/GPU, RSS/VRAM, bandwidth, storage byte-time and real service obligations.
Actual meters, settlement, independent customers and demand need original-owner
evidence. Local wall-time examples do not establish those properties.

## Preserved acceptance conditions

The original Host contract remains **0.25 CPU, 2 GiB RAM, zero swap, 256 PIDs,
four seconds and sixteen hostile workers**. The original complete service
campaigns, complete History, capacity/churn and independent WAN evidence retain
their separate gates. Resource ownership, cancellation and cleanup must remain
inside the original accounting. A larger development host supplies no waiver.

PN5 still requires at least **three independently administered failure domains**
and the preregistered **at-least-72-hour WAN experiment**. Multiple processes,
keys or advertisements do not establish independent administration. Replication
and successful chunk recovery do not establish persistent custody, funded
repair or long-term availability. The three real Hepta lineage cycles likewise
cannot be supplied by synthetic score transitions or fabricated owner objects.

## Interpretation of research and economic output

Finite formula enumeration supplies exact refutations where a witness exists.
An unrefuted grid is neither a necessary nor sufficient security proof for the
implemented chain. The retained fixture and its source digest provide
reproducibility, not cryptographic qualification. Upstream proof/backend
observations retain their exact source and experimental scope; this report
does not convert them into executions of the frozen candidate.

Economic arithmetic separates external customer revenue, refunds, protocol
subsidies and internal transfers. Only external revenue, less refunds and all
declared observed costs, enters the conditional external net. An observed
positive cashflow is not complete future-lifecycle profitability. Any declared
nonterminal lifecycle makes completed-lifecycle cost and net unknown. Even
terminal declarations do not authenticate omitted future storage, repair,
refund or service liabilities, payment origin or customer independence.

The reader therefore leaves meter authenticity, settlement authenticity,
future-obligation completeness and sustainable-reward qualification false.
The registry and research outputs retain **HOLD_NO_GO**. No static specification,
local regression, benchmark or arithmetic result grants public activation,
independent acceptance, a complete QROM proof or whole-chain PQ128.
