# Terminal History diagnostic integrity — HOLD

Stacked on [#880](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/880), exact parent `bcc0d2369e81d85c001190ea4c8ee0b1778e178d`.

The offline diagnostic previously classified incomplete, non-Boolean or contradictory terminal-stage flags as a definite deadline boundary or as no terminal import failure. The reader now retains the raw stage observations and returns `unknown` for these inconsistent records. Coherent success and observed deadline records remain distinguishable. No runtime, Host decision, budget, workload, output schema, signed domain or qualification predicate changes.

## Actual validation

The original two source Git blobs were fetched independently, rehashed and materialized on the original Mac. Original 12 controls pass; three added negative-control methods fail against the original reader (seven failing subcases); the fixed two-file source passes all 15 controls, including a coherent-success control. See [Mac receipt](mac-test-receipt.json), [original controls](mac-parent-controls.log), [preserved negative controls](mac-parent-new-controls.log) and [fixed controls](mac-fixed-controls.log). These are isolated exact-blob Python executions, not a full checkout or native service run. The [previous isolated package](prior-unpublished-package.zip) preserves its historical unpublished status, original negative results, source patch and three-report offline readback.

Fixed reader blob: `7586a9c5ec306c1111bc3dcfd892352690c9fa0f`.
Fixed test blob: `09a1783682117fdc52cf53c3a4ff63aa562ba52d`.

The original `aaa3c539` artifact remains 0/3 complete campaigns. Its three successful baseline last imports do not qualify their failed whole phases; the six hostile last imports retain submit_result deadline observations. The prior package records a source-bound offline readback, not another native execution. No business TPS or unique useful-task rate is inferred.

## Scope and preserved failures

Mac operational project-preflight passes (26 packages), while the existing sparse checkout stays at `81f00ca6`. Complete Rust/Cargo/Clippy/native qualification and whole-source/official-PQ closure are not claimed for this change; new hosted CI outcomes remain separate, pending gates. The original four-second, independent 3x30-second, long-History lifetime and historical cleanup failures remain unchanged. All four complete business throughput qualifications remain HOLD, with missing measurements null/unknown.

The restored local channel still encountered an HTTPS user-API timeout and an HTTPS promisor-blob retrieval failure before tests. The exact missing original blob was obtained independently and rehashed before writing the same identity into this repository's object store; no file or parent commit was substituted. The first standalone preparation also rejected an incomplete transfer payload before running controls. These preparation failures are not test successes. No old job was restarted or resource taken over.

Publication uses ProfHepta through the original Mac local GitHub channel, a separate index and a new child branch with an ordinary push. The original working tree, canonical origin, original branch and historical PR heads are preserved. No force push, main merge, self-approval or activation.

The initial default Git tree writer timed out on the sparse object's presence checks before creating a commit or pushing. The publication tree retains the fetched parent's unchanged entries, inserts only the verified changed blobs and evidence, and checks the exact changed-path set. This object-preserving partial-clone operation is not a full-source checkout or qualification.
