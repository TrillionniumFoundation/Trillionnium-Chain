# Original incomplete full-W1 run and bounded continuation controls

`original-artifact.json` indexes every byte/member of the actual original
run-40511022475 artifact. `original-zip-parts/part-000.bin` through
`part-031.bin` reconstruct the unmodified 8,139,466-byte ZIP. Its SHA-256 is
`d862b93d949612e6fc764d82622d507b208743bc8e6b6701dbf481802b040e8b`.
`original-job.log` is the actual original job log. `original-observation.json`
preserves the observed 26/62 result and original failure.

`local-controls.tar.gz` retains the first 21-control pass and the later
35-control pass, including actual wrapper logs, subprocess settlement and
the recorded before/after source maps. The earlier source maps are helper
snapshots, not complete Git-tree attestations. The policy additionally checks
all thirty exact original-source pins and all 315 original artifact members.
`local-controls-manifest.json` records the lossless archive/member hashes.

Four static findings were fixed before publication: dangling policy links
could select generation; a zero-exit stage first polled after its deadline
could be accepted; the report did not compare the full shard source record;
and directory indexing collected entries before applying aggregate limits.
The 35-control run covers all four corrections. Its actual two owned Python
child controls are process-accounting tests, not proof-generation evidence.

No local control fabricates a successful STARK. At source freeze, fresh
same-session SDK export, missing segment generation, complete assembly,
whole-proof hostile-input costs and real-receipt propagation are **NOT_RUN**.
The actual original failed run is never relabeled as success. See the
[continuation protocol](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/CONTINUATION.md).

A subsequent [independent local review](final-review/README.md) retains seven
reproduced report-provenance failures, the minimal correction, all 37 passing
continuation controls, and the separate 14 passing loopback controls. The original
archive contains 35 tests in its second run; its earlier 36-test description was
incorrect and has been corrected against the raw archive.
