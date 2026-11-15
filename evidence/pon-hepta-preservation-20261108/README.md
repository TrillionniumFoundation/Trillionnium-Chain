# Hepta-preservation implementation and exact-source observations

This packet accompanies [Chain PR #824](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/824).
It records the factored grouped producer, native payment-readback fences, and
the operating boundaries between local execution, scoped learning and consensus.
The qualification remains **HOLD_NO_GO**. There is no production activation,
new work credit, independent model-benefit claim or joint Chain/Hepta execution.

## Source identities

| Role | Immutable identity |
| --- | --- |
| Integration base | `e798d7125724d4b9f98c24d00cc80031f2eab4a9` |
| Chain native-tested source | `91dd3082633ea0b3a5ec9b0ed91f28603229be01` |
| Native-tested tree | `8a14e5aa053af94d1f19cfb8b907a09c6ac4399b` |
| Complete tracked source checked before and after each command | 26,120 entries; 2,485,347,114 bytes |
| Separately published Hepta scoped-learning source | `d81cb97c5b01aea0df03d84d40336b25576337de` |
| Hepta tree | `49829b9efd25251907743d36fd9c87625ae2bdce` |

Native execution results belong to the Chain runtime commit above. The
subsequent evidence-and-documentation commit carries the original observations;
native tests were **not rerun against that child**. Its publication checks cover
the parent/diff boundary and artifact integrity. No result is relabeled with a
later source identity. The paired Hepta identity is a source reference only;
its own learning and real-model observations must be read in that repository.

The exact original command roster is in [commands.json](commands.json).
[summary.json](summary.json) gives every local command's actual terminal status;
its `all_commands_succeeded` field refers only to that 22-command local roster.
It is not a claim that all hosted CI, every workspace runtime test or the
production acceptance gates passed.

The original campaign finished with **21 successful commands and one failed
repository-control command**. That final fixture copy encountered `ENOSPC` in
the shared 4.9-GiB `/tmp` filesystem. Its original failed receipt and complete
raw output are retained. A separately recorded follow-up runs the **same full
original command at the same source** with a dedicated workspace `TMPDIR`.
[validation-resolution.json](validation-resolution.json) gives its actual
result, original/follow-up source equality, environment and filesystem readback.
The initial campaign's false success flag is never overwritten.
The follow-up completed **all 50 repository tests successfully**, with no
source or test changes. Each required local command scope therefore has a
passing original or separately recorded follow-up observation; the initial
21/22 campaign and its failure remain identifiable.

## What the native changes establish

The original grouped relation now accepts an explicit research producer that
keeps `B(Ax)` in its warm execution. Preparation checks all supplied factor
products against the original matrices, including unused coordinates; the
original independent verifier remains the acceptance check. Factor preparation,
router/base contractions and selected adapter contractions have separate
counts. Original merged, direct, sparse and reusable strategies remain valid.

The fixture has only three outputs. At rank one its hot arithmetic is
**1,802 MACs**, compared with **1,542 MACs** for the premerged path. This is not
a speedup claim. The constructor still owns the original matrices and merged
preparation; those setup and residency costs are not removed. Arithmetic
counts and finite timings do not qualify an all-algorithm physical lower bound.

Native V2 payment readback now checks the returned anchor against the complete
persisted journal, then refuses if a fresh SQLite snapshot observes an
intervening append. A different task's newer persisted anchor matters. The
existing operation and payment identities remain once-only. The readback is
read-only and adds a journal replay; it neither advances a durable recovery
anchor nor makes separate external owners atomic.

The [operating-boundary contract](../../docs/development/specs/pon/HEPTA_OPERATING_BOUNDARIES_V1.md)
keeps fast inference local, medium learning scoped, and slow base/work/credit
changes under their separate owners. Service fees, improvement awards and
consensus work credit retain distinct admission conditions. A completed
independent `NoUpdate` can be a paid service. The native `NoGain` outcome is a
lower-level resource result and does not by itself certify `NoUpdate`.

## Local execution and toolchain

The local campaign uses the unchanged source recorder
`scripts/ci/record_pq_native_command.py`, Rust/Cargo 1.95.0, locked offline
dependency graphs, one Cargo build job and the pinned OpenSSL 3.5.9 provider.
The raw source verifier checks the complete tracked worktree before and after
each original command. [native-receipts.json](native-receipts.json) exposes the
receipts for inspection; their exact original bytes also remain in the archive.

The runtime test results include:

| Runtime scope | Executed result |
| --- | --- |
| Service settlement, all features | 71 tests and 2 compile-fail doctests passed |
| Crypto library, all features | 186 tests passed, including the grouped algorithm cases |
| Grouped example sessions | 12 tests passed |
| Actual Python/Rust grouped CLI integration | 14 tests passed; none skipped |
| Lawful-optimization reference controls | 19 tests passed |
| Low-rank reference controls | 6 tests passed |
| Service/NoUpdate reference controls | 25 tests passed |
| Native task-operation V2 Node integration | 4 tests passed; coverage includes both retained backends |
| Native NoGain-fee Node integration | 2 tests passed, covering reopen and reorganization without double payment |

The remaining roster covers strict workspace/all-target/all-feature Clippy,
formatting, source-integrity negatives, CI-contract negatives, corpus controls,
the distributed source inventory and repository checks. Read their final exit
codes in the summary and the unedited terminal lines in
[test-summary-lines.json](test-summary-lines.json). Clippy is a compilation/lint
gate; it is not execution of the entire workspace test suite.

The provider receipt binds its preparation script and installed materials. Its
build/smoke success is not an upstream full-suite or whole-chain quantum
security qualification. [toolchain.json](toolchain.json) retains the actual
reported versions; original non-sensitive environment settings are archived.

## Development failures and provenance

All preliminary observations are separate from the frozen runtime campaign.
The three new payment regressions failed against the unchanged old readback
implementation plus the new tests: **0 passed, 3 failed**. After the patch the
development service package passed 71 tests and 2 doctests. The later clean
runtime campaign independently repeats that package at `91dd3082`.

The development red/green runs did not capture complete clean-tree before/after
receipts. Their full temporary tree identity remains unknown. The archive's
`review/settlement-red-green-provenance.json` records the actual known commits,
argv provenance, implementation/test blob equality and original log hashes.
Its tests-only patch is explicitly reconstructed from immutable Git objects;
it is not represented as a contemporaneous snapshot.

The initial factor cross-language run exposed a fixture metadata key sent to
the strict init decoder, along with a separate timeout observation. The fixture
adapter was corrected to send only the original model fields. The decoder and
original ten-second timeout were not relaxed. The original failure log and both
patch versions remain in `preliminary/factors/`; the timeout has no fabricated
single-cause attribution. The final frozen-source integration ran all 14 tests.

An early source-control invocation used the wrong Python module entry point and
failed import. The corrected original direct-script invocation and both logs
remain in `supervision/`. These preliminary errors are not hidden or promoted
to successful native qualification.

## Hosted CI failures remain failures

The archived GitHub observations are time-specific snapshots of the original
runtime head, not a certification of a later PR head. In particular:

| Hosted gate | Retained observation |
| --- | --- |
| [W1 QROM closure, run 42550894228](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894228) | Historical `store.rs` source pin disagrees with the current bytes. |
| [W1 QROM implementation, run 42550894232](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894232) | Historical verifier fixture bound is 9,233 bytes; the current file is 11,172 bytes. |
| [Required-baseline prospective external-evidence, job 128945998654](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894217/job/128945998654) | The reader expects `growth_observation_only`; the source uses `observation_only`. The log retains 84 failing subcases and 22 errors. |
| [Original native campaign, run 42550894105](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894105) | All three original campaign attempts returned 101 and did not meet the original criteria. Their original workload and limits were retained. |
| [Required-baseline protocol-contract, job 128945998935](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894217/job/128945998935) | The from-zero campaign's original format check timed out after 60.079 seconds; its five named native controls were not executed. |
| [Required-baseline cross-arch x64, job 128945998749](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42550894217/job/128945998749) | All five named native controls passed, but the original business confirmation target was not met. This remains a failed acceptance gate. |

For the first three mismatches, ten relevant checker/contract/input files are
byte-identical between the base and runtime commits. This shows that this PR
did not introduce those specific inconsistencies. It does **not** say base CI
was rerun, waive any gate, or explain the separate original-native failure.
The later timeout and confirmation failures are separate performance/acceptance
observations and are not classified as those three historical checker mismatches.
The original external-evidence job actually tested prospective merge
`f6fd573c86cd9fa4dbb33b0a2ca854913981d6e8`; its tree equals the runtime tree but
its tested commit is retained as the merge commit.

## Archive and remaining acceptance

[observations.tar.gz](observations.tar.gz) retains every original local receipt,
log and recorder output, provider observations, preliminary red/green and
fixture failures, supervision scripts, GitHub metadata/logs and independent
review observations. [archive-index.json](archive-index.json) binds the archive
and every original member by relative path, byte length and SHA-256. Packaging
verifies a full decompression round trip without changing the original bytes.
The repository-control follow-up and its original source recorder are retained
under `followup-repository-controls/`. The changed temporary-file location is
not a relaxation or a pass of the separate original resource-acceptance gate.

The open qualifications remain: actual cheapest-legal-work and shared-lifecycle
costs; joint time/difficulty/credit security; independent same-iteration learning
benefit with complete matched budgets; real external payment and effect
reconciliation; original public-service/WAN acceptance; and an independent
current anchor for full recovery. The component tests and this packet do not
close those obligations. `production_activation` and
`whole_chain_quantum_security_qualified` remain false.
