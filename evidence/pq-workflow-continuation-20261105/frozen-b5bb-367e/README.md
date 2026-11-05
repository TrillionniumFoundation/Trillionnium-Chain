# Fixed Chain / Hepta continuation — 2026-11-05 UTC

**Decision: HOLD. The requested P0–E blocker set is not closed.** This record binds the code, preserves actual successes and failures, and separates implementation changes from native acceptance. It is an evidence update under the repository's [sole development plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md), not a second roadmap or an activation approval.

## Fixed inputs and evidence identity

| Component | Selected code commit | Tree |
| --- | --- | --- |
| Chain | `b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c` | `8be28a72673ce318d60a464898ab610d9ba39216` |
| Hepta | `367e27fb6bf30443641b9e23a063d24e49eda9f7` | `6a2465606f0270eeecec83c2b7d9dbef5dc96076` |

[fixed-pair.json](fixed-pair.json) and [gate-ledger.json](gate-ledger.json) are machine-readable companions. Evidence-only successor commits do not turn older executions into new ones. No combined native run has accepted this pair.

The Chain source checks below actually ran at `b5bb`, with `29fcd2e88654d5bec2bf30134cc030b5bfa7831b` recorded as the then-selected runtime. They execute Chain source/model checks; they do not execute or validate Hepta. Their original receipts remain unchanged. The [runtime source map](../runtime-29-to-d206-source-map.json) establishes that `29fcd` to `d206c3c787f6b67c771b67a8e1d46c8261810042` changed one test file and evidence, with production source entries identical. `367e` adds the existing-workflow test entry and evidence after `d206`; it is the identity for future runtime execution, not a relabelling of historical tests.

Incoming `30b09171` Cell changes and `47b4a624` evidence were preserved. GitHub publication used expected-head, non-force updates with the configured noreply identity. Both integration PRs remain drafts: [Chain #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688), [Hepta #4812](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4812). No protected-main merge, production activation or CI dispatch/rerun was performed in this continuation.

**Late concurrent source boundary:** after these checks, the integration branch advanced from `ef1fa4d4` to `04be5f02c84cf5cb626a53f34bc03a5bd6ff5137`, changing eight code/configuration paths including Growth activation fences and M06 namespace scans. The [late integration record](late-integration.json) retains that exact comparison. This report's frozen observation pair remains `b5bb` / `367e`; the newer integration source is preserved, but its tree is different. The 233 checks, Growth RED observations, F0 run and prospective-merge source result do not become acceptance of `04be` or of a later evidence commit. Current combined-head validation remains open.

## Implemented changes

### GrowthV2 admission and successful state construction

[Chain code commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c) propagates the original `ExecutionControl` into actual SQL admission-delta writes and the existing paged readback. `AdmissionDeltaWrite` and `AdmissionDeltaReadback` checkpoints can now stop those operations. The immediate transaction, rollback behavior, error precedence and original resource policy remain in place.

Two new native tests construct 256 actual signed classical-development GrowthV2 transfers and complete W1 work. They exercise cancellation, deadline and CPU-budget refusal during partial writes/readback, unchanged durable rows/nonce/active state, cold reopen, legal retry, activation and a second cold reopen. They are intended to test transactional cancellation, not ordinary PQ/Growth integration or owned-VFS resource qualification.

The successful state path now moves `output.state` and receipt values after the successor/difference/delta-hash operations succeed, removing a redundant full successful-state clone. The parent clone and linear non-account retain remain. The existing account-prefix native selector covers complete roots, non-account working data including `account;boundary`, two successors, 0/64/4096 working rows, 256 dormant accounts, nonce and cold reopen. It has not run successfully on this new code; no measured speedup is claimed.

See the [four-attempt checkpoint](../../pon-growth-persistence-control-20261105/checkpoint-before-green.json) and [later resource-window checkpoint](../../pon-growth-persistence-control-20261105/checkpoint-resource-wait.json).

### Exact quantum resource-budget decisions

The [exact-budget evidence](../../pon-quantum-exact-resource-budget-20261105/README.md) preserves a genuine baseline RED: three additional controls produced two failures and one pass. Decimal rounding accepted a physical-error total infinitesimally above a `0.15` budget and erased positive headroom below `0.1`. The decisions now use exact `Fraction` arithmetic; display decimals, model assumptions, parameters and budgets remain unchanged. Equality remains allowed.

The resulting resource suite passed all 25 controls, including its original 22, and the two retained full-report examples remained unchanged. These 25 are included in the 118 quantum controls below; do not count them twice. This closes the demonstrated arithmetic-decision defects. It does not establish that the physical model is correct, that the oracle is optimal, or that the deployed consensus is quantum secure.

### Hepta recovery frontier V2 and exact CI selection

[Recovery integration `29fcd`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/29fcd2e88654d5bec2bf30134cc030b5bfa7831b) places migration/qualification/AuthBus and provider-effect frontier reads within one SQLite transaction. It includes intent, uncertainty and ACK state, validates stored JSON digests, uses bounded pages with a cumulative one-million-row ceiling, and binds kind, sequence, key, digest, time and ACK provenance into a fresh V2 snapshot/signature domain. It rejects nonpositive sequence IDs and old V1 input rather than upgrading a restored database implicitly. Startup provenance checks reject a `StatusLookup` ACK changed into a `DispatchResponse` claim, while retaining the legitimate opposite progression.

The guard is reached through the configured `EvidenceHost::open` path. It remains conditional on configuration. Its signer is Ed25519 with the retained V1 trust-file format. These changes do not provide an independently fresh anti-rollback root, make all Agentd startup paths guarded, establish PQ recovery attestation, or make external effects atomic with revocation.

[Test compilation fix `d206`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/d206c3c787f6b67c771b67a8e1d46c8261810042) replaces four dynamic SQL test expressions with fixed literals accepted by the repository's SQLx safety boundary. It preserves the mutation/restoration assertions and changes no production code, dependency or feature.

[CI entry `367e`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/367e27fb6bf30443641b9e23a063d24e49eda9f7) adds seven owner controls and two signed-frontier controls to the existing PQ-policy workflow. Each selection uses exact full test names, zero retries and one test thread, with a 600-second step bound. The original 14 dispatcher plus 3 product controls, four pull-request matrix lanes, job budget, permissions, toolchain and non-cancelling concurrency policy remain. The audit requires every expected test exactly once and rejects missing, skipped, unexpected or zero selections. Its validator passed 43 fixture cases; these are workflow-audit controls, not Rust native tests. [Workflow evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/367e27fb6bf30443641b9e23a063d24e49eda9f7/evidence/recovery-v2-native-20261105/workflow-entry).

## Actual validation and limits

| Observation | Actual outcome | Scope |
| --- | --- | --- |
| Chain source/command recorder | 47 PASS | Source and recorder controls |
| PQ integration/claim controls | 57 PASS | Research pins and claim refusal |
| Authority scanner controls | 11 PASS | Scanner behavior, not complete authority tracing |
| Six quantum model suites | 118 PASS | Finite model/arithmetic controls |
| Chain structural checks | PASS | CI contract, generated inventory, 472 source pins, format, shell syntax, 2,925 local links |
| Locked/offline Cargo graph | PASS | 26 members, 175 packages/nodes |
| Full tracked Chain source check | PASS | 9,587 entries / 954,728,186 bytes |
| Actual GitHub prospective merge source | PASS | Same tree, clean source; native tests NOT_RUN |
| Two early Growth RED attempts | Two intended failures in each | Actual missing-control observations; SQLite build marked UNQUALIFIED |
| Two canonical Growth RED attempts | ABORTED_RESOURCE | No tests executed |
| Growth GREEN2 and B1 account-prefix | NOT_RUN | Required native acceptance remains open |
| Final strict workspace Clippy attempt | ABORTED_RESOURCE | No completed lint result |
| Runtime new owner controls | BUILD_FAILED | Original RED E0277; corrected RED E0463; zero new tests executed |
| Runtime new signed controls | NOT_RUN | No native acceptance |
| Runtime workflow selection audit | 43 PASS | One accepted fixture plus 42 refusal fixtures |
| Completed fixed-Host F0 campaign at b5bb | FAILED | Original baseline failed; 0/6 four-second SLOs passed |
| New full W1 statement-v2 proof | EXECUTOR_LOST / completion UNKNOWN | Last known 1/43 segments; full verification unknown and 58 controls NOT_RUN |

The first four rows total **233 scoped Chain controls**. They are not 233 native, integration, adversarial or independently operated acceptance tests. Raw records are retained in [initial-checkpoint](../initial-checkpoint); additional raw graph and Clippy records are in [additional-checkpoint](../additional-checkpoint).

The original source check ran before native attempts. Each scoped command also recorded the unchanged clean Chain head afterwards. The actual prospective merge was `f135eb867d10ead2058073f78d9d82af2e174f29`, with parents `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and `b5bb`; it has the same tree. Its full ordinary history and original source checker were used, without replacement/graft metadata. [Prospective-source evidence](../../pon-prospective-source-b5bb-20261105/manifest.json). This does not qualify a later merge commit or native execution.

All four Growth RED attempts used `ffb43113b2e0065e6a8053bdb25fc5a9d7cf0637` with the recorded RED enum/test overlay; `b5bb` GREEN2/B1 were not executed. The overlay introduces the regression probes without the new callback calls, so the baseline can expose the original cancellation gap. The exact [overlay and attempt checkpoint](../../pon-growth-persistence-control-20261105/checkpoint-before-green.json) preserve that intentional source difference.

The canonical Growth runners use the real absolute Rust compiler and retain the 600-second bound and 512 MiB estimated-availability stop floor. They stopped after approximately 151.14 and 34.96 seconds. The separate strict Clippy attempt stopped after approximately 1.51 seconds. The monitor estimates reclaimable memory; it is not hard process isolation. Original attempts' OOM deltas remain zero. Shared-cgroup OOM counters later increased while this work's Cargo jobs were idle; those later events are separate observations, not retrospective causes assigned to the earlier attempts. Other work's processes were not terminated.

One subsequent, bounded [resource-window wait](../../pon-growth-persistence-control-20261105/checkpoint-resource-waiter-retry2.json) required 30 continuous seconds with at least 2 GiB estimated availability and no new OOM before starting canonical RED. It ended after 160.165350 seconds as `OOM_DURING_WAIT`, with shared `oom`/`oom_kill` counters rising from 4/4 to 5/5. No native process started; this is a scheduling refusal, not a fifth native attempt. No further wait/retry was started, and GREEN2/B1 remain NOT_RUN.

Runtime environment and compile failures are preserved in the [initial runtime checkpoint](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/3558ced0fd983603a3082a42359e8da63dfc8418/evidence/recovery-v2-native-20261105/checkpoints/restore-and-sqlx-blocker) and [corrected RED E0463 checkpoint](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/367e27fb6bf30443641b9e23a063d24e49eda9f7/evidence/recovery-v2-native-20261105/checkpoints/corrected-red-e0463). The latter is a compile failure, not an expected test RED. SQLx macro artifact inconsistency is an observed indication, not a proven root cause. The local AF_UNIX creation refusal also prevents the actual IPC product loop; transport was not substituted to manufacture a pass.

## Fixed-Host F0: a real performance failure

The already completed [run 41964674522 / job 127038806677](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/job/127038806677) built and ran the actual release binary at `b5bb`. Its [readback bundle](../../pon-fixed-host-root-f0-b5bb-readback-20261105/README.md) retains original results, finalization, source records, Host observations, job log and the complete original ZIP inventory/hash. The runner recorded `NATIVE_F0_FAILED` and `BASELINE_MUST_PASS`. The finalizer retained all six scheduled rounds and 42 planned packet exposures, observed all owned services empty, and correctly failed the campaign. This is not an established parser or cleanup defect.

This campaign is **AuthenticatedV1 / RawR14**, with 24 hostile producers and two 30-second phases. It does not execute the new GrowthV2 tests. It also differs from the unchanged [issue #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) four-second / 16-hostile-producer gate; neither campaign substitutes for the other.

In the baseline, 14 History network operations totalled 0.308889425 seconds, while 14 ordinary-client imports totalled 23.368586812 wall seconds and 5.401201965 calling-thread CPU seconds. The first two scheduled confirmations finished 14.102383267 and 23.812108308 seconds after their scheduled offsets; the third did not confirm. All three missed F0's predeclared four-second SLO.

Across those imports, 166,743 observed Host checkpoints totalled 4.038066182 CPU seconds. The account-graph stage measured 3.738849684 CPU seconds over 124 calls. These intervals are nested within import and sometimes each other: **do not add them**. They identify an actual replay/Host investigation target; they do not authorize omitting independent graph/state checks, dropping Host checks, or widening their interval. Under ROOT pressure, four imports succeeded and the fifth returned `PUBLIC_REQUEST_DEADLINE`; all three planned confirmation SLOs failed, including the two rounds never started.

The original Host was observed at `cpu.max=25000 100000` and 2 GiB RAM, with throttling and no CI OOM/kill. The unrelated local shared-cgroup OOM cannot explain this completed CI failure. The original time/resource limits and denominators remain unchanged.

The [exact source trace](../../pon-fixed-host-root-f0-b5bb-readback-20261105/source-trace.json) follows the observed ordinary importer through admission/activation, state readback, per-node account-graph progress, the original request checkpoint and fresh `kernel.verify`. Host counts also include W1, other progress and refill waits; they are not account-node counts. Existing code already eliminates several adjacent checks and uses bounded same-writer readback reuse. The review established no substantial safely removable validation. A small static receipt-root recomputation remains an unmeasured candidate with separate held/detached entry obligations; it was not modified or presented as a four-second solution.

## Full W1 proof and security research

The [retained continuation observation](../../pon-w1-statement-v2-20261105/continuation/checkpoint-observation-20261105.json) distinguishes the pre-disconnect native source from the current pair. A real preparation produced 43 segments; segment zero completed and segment one started before executor loss. The last known receipt was 255,842 bytes. Full completion and final independent verification are unknown; the 58 controls are NOT_RUN. Loss of the executor is not proof that its original process was terminated. Lost raw local proof bytes were not reconstructed or passed off as recovered evidence. The exact source projection is limited to its recorded 120 files/eight package inputs, not a complete reproducible-build theorem.

The exact resource arithmetic repair does not close fastest legal classical/quantum oracle selection, preprocessing/reuse, physical cost assumptions, private-branch attacks, DAA thresholds or concrete recursive QROM soundness. The proof candidate remains outside the Node acceptance path. No end-to-end benefit or production qualification is inferred from an intermediate segment, source checks, an older image or historical proof results.

## Remaining closure obligations

The original requested workstreams remain explicit in [gate-ledger.json](gate-ledger.json). In particular:

- **P0:** the pair and source/config anchors are fixed, but the source authority scanner still reports 83 unreviewed indicator files across 1,136 Rust files, with only 22 curated role mappings. This is not an exhaustive dynamic call graph or deployment key-custody inventory.
- **A1:** ordinary task/payment/CURRENT/FinalUse paths require their exact combined PQ acceptance, including negative authorization cases. A source-level policy or a guarded component does not establish every ordinary entry point.
- **A2:** activation/reorg migration, conservation, debts, nonces, tasks, key generations and permanent retirement must pass the original combined owner controls. No new whole migration acceptance was completed here.
- **A3:** the new recovery component still needs its native controls, whole-directory rollback/clone/crash/reorg campaigns, independent freshness/custody and unresolved-effect coordination. Ed25519 and optional recovery configuration remain material scope limits.
- **B1:** the new source change needs native account-prefix/Growth execution and the real ordinary business path. The observed old-backend F0 baseline already fails.
- **B2:** the new cancellation controls need qualified RED/GREEN execution, strict Clippy and the original four-second / 16-producer campaign with all subconditions. Fixed service classes, end-to-end cancellation, Cell/sync isolation and hostile resource campaigns remain separate acceptance work.
- **C1/C2:** the numerical bugs are fixed, while cost-model optimality/coverage and deployment-specific consensus/quantum conclusions remain open research obligations.
- **D:** complete current-image W1 proof, exact parameters/security conditions, independent verification and favorable full-cost benchmark remain open. The candidate stays disabled.
- **E:** the combined real Hepta task, exact multi-node version, independent operators/review and A/B plus C obligations have not passed. No global security gate is closed by this continuation.

The concrete execution order remains canonical Growth RED, GREEN2, B1 account-prefix, required strict Clippy, then runtime owner/signed/product controls after the preserved cache/IPC issues are resolved on a suitable host. Native tests may start only with an adequate resource window and their original guards. The failed fixed-Host business behavior requires an implementation fix and a new exact-source campaign; waiting for a green dashboard or relaxing the denominator is not a remedy.
