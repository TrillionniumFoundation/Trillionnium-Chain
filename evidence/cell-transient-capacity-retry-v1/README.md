# Actual bounded transport retry evidence

This directory records the native Cell repair described in
[the component note](../../docs/security/CELL_TRANSIENT_CAPACITY_RETRY_V1.md).

The original client fails two actual TCP capacity-refusal regressions. The
repaired component passes all 141 native library tests and strict all-targets
Clippy. The original optimized full-model reset remains in the preceding
[model experiment](../smollm-cell-replica-research-v1/README.md).

`optimized-replay/` contains the exact native commands and full 272,190,131-byte
release observations from the repaired build. Both transfers and cache-only
materialization completed, the original publisher really exited, and its old
endpoint returned connection refused. `replay-qualification.json` explicitly
retains the post-success annotation wrapper's create-only-write error and the
subsequent successful readback; it does not reclassify the wrapper as exit 0.
This replay had no transient refusal, while the controlled TCP regressions
exercise the actual retry on both manifest and chunk paths.

`local-qualification.json` binds source blobs and retained logs. The cleanup
manifest records hashes of disposable experiment SQLite copies before removal;
all original public model inputs, three adapter generations, and success/failure
logs were retained. No model quality, deployment, PQ transport, independent
operators, public WAN or original Hepta FinalUse acceptance is granted here.
