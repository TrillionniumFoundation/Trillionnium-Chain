# Node R4 retained evidence

[Immutable raw archive](node-observations-r4.tar.gz) and
[its exact member index](node-observations-index.json) preserve all listed logs,
including first compile failure, v3 controls, v4 correction/build, one new full
proof, nine independent CLI owners, merge-conflict inspection/resolution and
original production-slice readback. Original trailing bytes are not edited.
Binary/proof/database copies excluded from this metadata archive are individually
pinned and retained at their original paths; complete test inputs/proofs are in
`../fixtures/node-input-v1/`.

[Build binding](integrated-build-binding.json), [v4 command receipt](build-v4.json),
[new proof origin](new-proof-manifest.json), [independent process summary](node-controls-summary.json)
and [complete native observations](node-controls-observations.json) identify the
actual work. An exit-zero exercise record can contain a requested cancellation
or cryptographic error; its semantic fields and current native state are the
acceptance evidence.

[Focused source review](node_adapter_r4_independent_review.md) and
[review pins](node_adapter_r4_independent_review.json) bind the final three Rust
files. The reviewed README snapshot's free-function spelling was corrected
editorially afterwards; the source hashes did not change.

The [separate pressure archive](../resource_pressure/README.md) retains its own
source snapshot and negative results. None of these observations provides a
production-owned I/O qualification, global rejection bound or complete NI/PQ
proof. Exact final-commit receipts are produced after committing this evidence,
so a receipt does not falsely certify the later addition of its own bytes.
