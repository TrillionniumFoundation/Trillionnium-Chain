# Remote CI findings and source-inventory follow-up

The first published review head, **`a28d62facc71ab4aa5b433a141cdd55f56d75fb0`**,
exposed two source-inventory omissions introduced by the adoption changes.
This follow-up fixes those omissions on local source
**`eb32162449eab623f69bbd7016b694600cb382c5`**. The original remote failures stay
failures. Passing the bounded checks below does not make the entire remote CI,
protocol acceptance or production activation pass.

## Original remote observations

The remote head has tree `fa3e59e39e8ce45e63cd377635f93276d17ca013`, identical to
the previously published local evidence continuation `2bb2c89dc2dd8cd530ff00eff878bf75c510431a`.
[Selected original job lines](remote-job-excerpts.json) retain the actual error
text. They are explicitly excerpts, not complete logs or new executions.

| Original job | Observed result | Follow-up scope |
| --- | --- | --- |
| [Head repository-truth](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943747030/job/130271440559) and prospective-merge repository-truth | Source identity and repository checks passed, including 6,630 local links; the next command refused with `distributed native source inventory differs; refresh before freezing source`. | Fixed the missing ten source entries. |
| [CPQ1 x64 native](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943747016/job/130271439587) and ARM native | Compiler, locked graphs and vectors completed before source-integrity exited 1. The retained x64 artifact says `HOLD_NO_GO: changed source: docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`. | Refreshed the six existing stale source pins, then the refreshed inventory's own seventh pin. |
| [Head protocol-contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943747030/job/130271440560) | Five from-zero named native invocations returned exit 0, and formatting passed. The original report acceptance failed with `CONFIRMATION_TARGET`; the overall service and job failed. | Unresolved here. Test execution and report acceptance remain different facts; the acceptance threshold was not changed. |
| [CodeQL export](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943746956/job/130271439747) | Sixteen offline exporter tests passed, but the exact-source analyses/checks did not complete and stabilize before the configured wait deadline. | Unresolved here; not relabelled as a source or model failure. |

The [artifact index](remote-artifact-index.json) records the complete ZIP byte
lengths and SHA-256 values obtained from GitHub and the selected original members
retained here. The downloaded x64 CPQ1 and protocol ZIP hashes matched their
GitHub artifact digests. This archive retains six exact original members, not
the complete ZIPs or every remote job. In particular, it does not present the
protocol's successful named invocations as successful business confirmation.

## Exact, limited repair

`scripts/refresh_distributed_source_inventory.py` regenerated the existing Rust
example's `include_bytes!` inventory. Its existing 1,572 entries remain; all ten
new adoption Rust files are now included, for **1,582**. No entry was removed.
The [inventory delta](inventory-delta.json) lists every added path and records
the unchanged PQ coverage rule's treatment of it.

The PQ research manifest retains all **1,079** pinned paths and its original
`required_paths`. Only **seven** blob values change: the sole development plan,
the learning-scope negative tests, the DA manifest, `cell.rs`, `residency.rs`,
`residency/version.rs`, and the regenerated example inventory. The other 1,072
pins are unchanged. No activation assertion, HOLD status, provenance parent,
coverage predicate or checker code changes. See the [exact pin changes](pin-refresh.json).

The ten new generic adoption paths do not match the existing PQ-name predicate
and are outside that checker's three complete-owner source directories. They
therefore do not require extra PQ pins under the existing rule. They are all
included in the distributed source inventory; this repair does not narrow
either inventory or alter the checker's protection semantics.

Forty-four existing controlled inputs had been omitted from this local sparse
checkout. They were restored from their exact current Git objects before the
checker ran, totaling 1,155,300 bytes. Their original Git blobs and SHA-256 values
are recorded in [materialized-source-inputs.json](materialized-source-inputs.json).
Missing worktree copies were not treated as permission to remove source pins.

## Validation on the exact committed repair

Every following command observed clean, unchanged
`eb32162449eab623f69bbd7016b694600cb382c5` before and after. Its full tree is
`c15f37e3f64456c9817019e8aec5d723a29549f0`.

| Check | Actual result |
| --- | --- |
| Original distributed inventory `--check` | Exit 0. |
| Original `check_pq_research_integration.py` | Exit 0, all 1,079 exact source blobs checked; output remains `HOLD_NO_GO`, with no cryptographic or activation acceptance. |
| PQ source and coverage negative controls | **59 passed**, no failures or skips. |
| CI source-integrity controls | **43 passed**, no failures or skips. |
| PQ claim controls | **55 passed**, no failures or skips. |
| Original locked/offline Cargo metadata | Exit 0; 26 workspace packages and 177 resolved packages/nodes. |
| Workspace `cargo fmt --all -- --check` | Exit 0, 23.485 seconds. |

The three Python suites account for **157 executions** in this round. They are
not added to the earlier 786 native tests or 94 supporting Python results as
independent cases; suites overlap across rounds. The original negative fixtures'
intentional refusal output is preserved inside their successful test logs.
Per-command arguments, environment, source identities, time and output hashes
are in [local-validation](local-validation), with the bounded summary in
[validation-summary.json](validation-summary.json).

The first metadata/format wrappers could not find `cargo` in the non-login
shell's PATH. No Cargo child started and no Cargo exit or elapsed duration is
invented for those two attempts. Their [failure record](cargo-command-discovery-failures.json)
is separate from the successful commands, which reused the exact installed
toolchain paths and Cargo home from the earlier retained validation record.
Repository configuration and build profiles were unchanged.

## Runtime and evidence binding

The original **2,103** code/configuration objects are no longer all identical:
**2,101** remain identical, and exactly the inventory and PQ pin JSON differ.
The [source binding](source-binding.json) identifies both changed Git objects.
The older all-2,103-equal assertion belongs to the earlier evidence continuation,
not to this repair.

The complete DA crate tree, all its files, the workspace manifest and Cargo
lock remain byte-identical to native-tested
`b9a38fd6d245e20849c7edd848dbbe18298cad7e`. Actual worktree bytes were checked
against the Git blobs for **175** DA/workspace input files; the [hash inventory](da-worktree-hashes.json.gz)
retains those comparisons. The DA tree remains
`edb975b936aebf92bd4ad00f4b402834bb4b0c75`.

The current 850,959-byte metadata output is byte-for-byte equal to the retained
`95a2a14771a655e8e59a0cb5fb7f37bf8f62cd13` metadata, with SHA-256
`81bb7691688e2d2ea4e36009b9136e6183a04b494ef8db3927f5b9c4be05e6f7`.
The Cargo lock SHA-256 remains
`759c42c62d7b9a72d93c533039b5bf47f3508efabf1f1ee63f5eee59b9b9e55f`.
The previous original-profile 786-test DA and strict Clippy results remain
bound to their original b9 runtime source. They were not rerun or reattributed
to this follow-up. The refreshed Rust example inventory is a changed compilation
input, so this record makes no new native-example execution claim.

The subsequent evidence-only commit adds this directory without further source,
configuration, plan or guard changes. Its actual local/remote commit mapping
belongs in the PR publication readback. [SHA256SUMS](SHA256SUMS) covers all
other files in this follow-up; gzip members decompress to the recorded original
bytes and use timestamp zero. None of this creates model benefit, settlement,
release or production authority.
