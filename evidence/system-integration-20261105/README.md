# Fixed Chain / Hepta integration continuation — 2026-11-05

**HOLD / NO-GO.** This continuation publishes one reviewable candidate source pair and preserves the exact scope of every earlier observation. It does not close any of the seven requested system exit conditions. The final pair has no built release binary set and no completed ordinary-entry native execution.

## Immutable inputs

| Component | Code commit | Code tree | Existing candidate |
| --- | --- | --- | --- |
| Chain | [`619c5f80856fb15bb6896d8008df91f58c215229`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/619c5f80856fb15bb6896d8008df91f58c215229) | `501607a6f76d4e5fc4e31a79bfdbff00c4bb007f` | [Draft PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688) |
| Hepta | [`f55752abbf516febfa0db89cb833dcf1fd1a2221`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/f55752abbf516febfa0db89cb833dcf1fd1a2221) | `039577d88899ddc1725f44dbf508e69d58506fe3` | [Draft PR #4812](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4812) |

[fixed-pair.json](fixed-pair.json) records full lockfile and configuration hashes, exact source-check receipts, historical execution identities and all open gates. Both commits were actually published with compare-and-swap updates to the existing candidate branches, preserving concurrent work. Later branch descendants and evidence publication commits do not change these fixed inputs or inherit their observations.

The Chain Cargo lock SHA-256 is `39ab5baeecb55c5445e6bbbbb359cb4ddcddd75a237e19ec243dc2f0f92849be`; the Hepta Cargo lock SHA-256 is `0f458d7746a0ca0b95bedc5404fd3347c1b0a7508f1c387f3b1f3f71ced08663`. The Chain PQ corpus SHA-256 at this input is `4b74e8c1239ca41f5948c5c76c5693504150b603da96d3929eb11f00b9971214`. A fixed source pair is only part of P0-1: `release_binary_set` remains null.

## Changes made and retained

**Sealed qualification and current-use authorization.** Complete qualification decisions are mandatory in evaluation, plasticity and self-evolution consumers. Use-time verification retains the current verifier/time, complete signed decision, temporal plan integrity, candidate bytes and current owner/profile bindings. The legal no-update path keeps independent evaluation proof and persists its evaluation inputs before later control refusals. The merge preserves Snapshot V3 / PQ Frontier V4 invocation history, authoritative intent joins, SQLite key checks and fallible provider decoding. These code changes have not yet completed the final Agentd/infer native or typecheck gates.

**Real native closure checks.** Dependency and interpreter resolution now checks actual ELF files and compatible profiles; dependencies must have the appropriate ET_DYN form and cannot smuggle an executable PIE through DT_NEEDED, while PT_INTERP requires an executable loader. Original false acceptances of text files, inappropriate ELF types and a nonexecutable loader are preserved alongside the later PIE observation. Twenty scoped tests passed on their recorded historical source. This is an ELF closure correction, not complete model storage, symbol resolution or real model-loader qualification.

**Authenticated-read source coverage.** Three dependencies whose plain filenames were omitted by the former discovery rules—`multiproof.rs`, `multiproof_tests.rs` and Growth `observation.rs`—are now explicitly mandatory and pinned. Six actual omission controls failed against the old checker. The updated source suite passes on the fixed Chain commit. Current Growth read epochs, authenticated timestamps, ordered preparation, owner cancellation controls and History/readback changes are preserved. Their original native liveness obligations remain open.

## What was verified on the fixed commits

| Scope | Result | Limit |
| --- | --- | --- |
| Chain real tracked source | 10,034 entries, 965,549,861 bytes; exact committed tree and clean worktree verified | Identity only; no native tests executed by this check |
| Chain PQ corpus | 505 exact source blobs checked; checker exits 0 with `HOLD_NO_GO` | Cryptographic acceptance, complete native authorization and activation remain false |
| Chain source controls, inventory and repository checks | 37 source controls passed, none skipped; inventory and repository checks passed on `619c5f80`, with stable before/after commit, tree and index identities | Python/source validation only; see individual raw receipts |
| Hepta real tracked source | 11,710 entries, 181,087,282 bytes; actual bytes, executable modes and symlink target checked | Identity only; no build/runtime qualification |
| Hepta Lane A verification, self-test, source registry and receipt check | Passed on `f55752ab` | Source/registration checks only |
| Final pair native/typecheck/strict Clippy/ordinary installation | **NOT RUN / incomplete** | Earlier successes cannot be transferred to this pair |

The historical Chain **141 native tests and strict full-workspace/all-target/all-feature Clippy** passed at `eaacd1ef4245f48cae5f16cf03d2fd7c3d2cd4f5`, before later Growth/owner changes. The historical Hepta **218 tests** passed on tree `285b7510cf7f247b84a4c55fa349af77810a3b4b`, before later source changes. Neither qualifies the fixed pair. The original 205-pass/13-fail Hepta run, missing-tool failure, resource-stopped attempts, final guard refusal before Cargo and source-coverage RED observations are retained rather than erased.

## Actual same-material cost observations

All numbers in this section belong exclusively to Chain **`6ee529046d295e3175f09112492abee373f1f54c`**, using the 817,128-byte release example with SHA-256 `ad4ddcb32a0128ce5b26b5c66628d851c593e916d88bfab3163a8169f7059ee1`. The frozen model is `hepta-source-owner-linear-256-v1`; this is a controlled local experiment, not a commercial language-model benchmark or an ordinary Hepta product call. The later grouped-operator research is a different implementation and receives none of these cost claims.

| Case | Native child wall ms | Ordinary warm median ms | Wall / warm | Ordinary cold ms | Wall / cold |
| --- | ---: | ---: | ---: | ---: | ---: |
| cell-t0-full-limb | 36.153159 | 0.116765 | 309.623 | 1.341258 | 26.955 |
| cell-t0-transposed | 155.605182 | 0.120639 | 1289.841 | 1.965537 | 79.167 |
| cell-t1-full-limb | 60.379635 | 0.092985 | 649.348 | 1.041195 | 57.991 |
| cell-t1-transposed | 62.079166 | 0.083350 | 744.801 | 1.962130 | 31.639 |

The numerator is a measured native child exchange, including startup, work/proof and verification, diagnostic serialization and local communication. It is not the cheapest legitimate solver cost or complete product cost. The warm baseline excludes reusable preparation; its separately recorded cold counterpart is shown so preprocessing is not hidden. The complete diagnostic flow also records source replay, material preparation, direct consumption, scalar/NumPy cross-checks and baseline repetitions; those phases are not omitted from the raw reports. The shared host was contended, energy and WAN costs were not measured, and no safety/benefit budget is certified by these ratios.

Two adversarial campaigns constructed **80 candidates**. They produced **360 rejected verifier calls: 80 native, 80 scalar-reference and 200 cache calls**. This is not 360 independent attacks. The raw verifier/attacker CPU ratios were **14.641114** and **6.040417**; no claim is made about the cheapest attacker. Cache owner recreation is not durable recovery or physical power-loss testing.

The offline settlement recomputation returned **`not_adopted`, model reward `0`**, because the preregistered statistical gate was not met. It used fixed logical time and a test unit with no market value; independent evaluation, an accepted future window, ordinary installation and funded settlement were not established. Legal no-update is preserved without claiming a completed evolution loop.

## Requested exit conditions

| Gate | Status | Concrete progress | Remaining exit condition |
| --- | --- | --- | --- |
| **P0-1** Unique integrated combination | **HOLD** | One immutable candidate source pair is published, including current owner/Growth/recovery/qualification changes and exact lock/configuration identities. | Build and identify the final pair binaries; execute the real ordinary entry and complete acceptance on that same combination. |
| **P0-2** Complete PQ effect authority | **HOLD** | Complete sealed decisions are required and rechecked at use; current owner and Snapshot V3/PQ Frontier V4 recovery are preserved. | Execute accounts, governance, release, recovery, CURRENT, FinalUse and consumption under the current root; reject wrong domain, old generation, downgrade, database rollback and concurrent copies end to end. |
| **P0-3** Original business liveness | **HOLD** | History/readback and Growth/owner integration are retained; three authenticated-read source dependencies are now mandatory and pinned. | Pass the original no-attack baseline, original four-second/16-hostile campaign and separate fixed-Host F0 without altered denominators or resource budgets. |
| **P0-4** PoN cost and usefulness | **HOLD** | Four actual same-material operator observations, two adversarial campaigns, optimized ordinary baselines, preprocessing and raw failures are retained at 6ee529. | Qualify competitive legitimate solvers, forged transcripts, preprocessing reuse and stale work against preregistered complete security/benefit budgets; rerun on the final artifact and measure missing physical/WAN costs. |
| **P1-1** Real evolution loop | **HOLD** | Sealed qualification consumers and retained no-update evidence are integrated; one frozen offline recomputation returns not_adopted and zero reward. | Execute independently administered evaluation, complete release, ordinary installation, next task, settlement and recovery; qualify future-window and full-combination benefit while allowing legitimate no update. |
| **P1-2** Model archive service | **HOLD** | The native ELF dependency/interpreter checker now validates actual file structure, type/profile and loader executability; historical negative observations are retained. | Qualify complete model closure, real model loader, independent copies/erasure coding, funding, renewal, repair and GC under author outage, node loss, restart and WAN faults. |
| **RELEASE** Independent system acceptance | **HOLD** | Source identities and evidence are reviewable; existing candidate PRs remain Draft and no activation is authorized. | Independent administrative operators must accept fixed release artifacts across cryptography, consensus, economics, malicious loads, physical power loss and long runs, then provide an explicit production activation basis. |

The original fixed Host parent `/sys/fs/cgroup/trnmponpublic.slice` was absent here. This run did not substitute a different cgroup, timeout, hostile count, denominator or resource budget. Earlier F0 and public-service failures remain failures attached to their original source; elapsed time from an offline diagnostic experiment cannot replace the original four-second/16-hostile gate.

## Evidence and reproduction

- [Fixed source pair and machine-readable gate record](fixed-pair.json).
- [Fixed Chain source verification and coverage controls](frozen-source-619/README.md).
- [Earlier observations through code `2a8fee`](observations-through-2a8/README.md), with [the immutable raw archive](observations-through-2a8/raw.zip), [its inventory](observations-through-2a8/evidence.json) and [verification program](observations-through-2a8/verify_evidence.py). The archive is 7,018,417 bytes, SHA-256 `20802bdb7828a6b634763a223d33a665cafde6ca486d87f83be8a44b7097d71b`.
- [Private Hepta source and execution evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/c90d13228514440e82d4bbb0da2bdaf13d145c8a/evidence/pq-sealed-composition-20261105). Private patches, source snapshots and detailed runtime logs are retained in that repository and are not copied into this public Chain package.

The historical directory deliberately keeps its original `final_chain=2a8fee` observation boundary. Read this top-level report and `fixed-pair.json` for the newer fixed pair; do not rewrite old receipts to newer commits. Source checks, local cross-review and multiple agents on a shared host are not independent administrative acceptance.

Only idle compiler intermediates were reclaimed for space; source, executables, logs and receipts were preserved. A small-file materialization precheck initially used nonprivileged available blocks and then separately recorded actual free blocks for the effective root process, maintaining a reserve. That correction applies to source/evidence writes and does not change old native guard outcomes or authorize a lower resource budget.

Both candidate PRs remain Draft/HOLD. No main merge, self-approval, protection bypass or production activation is part of this continuation.
