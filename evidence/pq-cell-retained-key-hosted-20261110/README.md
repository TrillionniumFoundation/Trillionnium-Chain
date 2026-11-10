# Hosted Cell retained-key observations

These records executed **a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667**, tree
`b621fde199f0e52a8410f765fbda0d633a32d5ff`. This later evidence delivery does
not relabel those executions as tests of another source.

The [PQ run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42776139426)
had **13 successful, one failed and two running jobs at 2026-11-10 09:22:42 UTC**.
That [snapshot](workflow-final-read-snapshot.json) is **not a terminal workflow
result**. Local checks are not counted as hosted passes.

The [failed x64 head job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42776139426/job/129694965028)
retained `native-41`: the first legitimate Submit returned `FRAME_EOF` at
`combined_tests.rs:586`, with the original 250 ms witness CAS exchange limit.
Its calling-thread CPU observation was about 11.4 ms; total exchange wall time
was about 250.1 ms. No authenticated successful CAS reply was observed. This
does not establish that an external CAS never happened; later replay/restart
assertions were not reached. The original limit remains an open blocker.

The new Cell key-pin cache is absent from this witness call chain, whose Node
and cryptography sources are unchanged from target `da1374a2`. There is no
same-environment causal baseline or complete scheduler/disk-wait trace. The
[analysis](analysis-no-rerun.json) therefore makes no unique host/concurrency
attribution and preserves the failure.

The [successful x64 head component job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42776139426/job/129694965008)
retained an actual [signed sealed pipeline invocation](successful-component/signed-sealed-pipeline.json)
and exact line-423 doctest readback, both exit zero. The synthetic pipeline
completed two localhost TCP fetches, 32,930 payload bytes and four chunk
references, sealed tensor/environment readback and bad-signature refusal.
Hepta, FinalUse and WAN qualification remain false. This is no comparative
performance measurement or whole-chain PQ qualification.

Two complete original ZIPs, receipts and complete merged stdout/stderr logs
are retained. [STREAMS.txt](STREAMS.txt) explains the original stream handling.
The unchanged [original manifest](manifest.json) and
[analysis supplement](supplement-manifest.json) retain their original logical
paths and hash relationship. [lossless-map.json](lossless-map.json) maps these
paths to deterministic gzip files where needed. Verify decompressed bytes,
receipt hashes and both manifest relationships with:

```sh
python3 evidence/pq-cell-retained-key-hosted-20261110/verify_retained_bytes.py
```

This command checks retained bytes; it reruns no native test. The separately
retained [actual publication records](publication/README.md) are outside this
observer manifest's scope and have their own file manifest. They preserve the
Mac channel timeouts, bounded object retry, successful publication of ee48626f,
and subsequent PR/commit metadata readbacks.
