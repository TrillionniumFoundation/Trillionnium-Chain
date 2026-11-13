# C8 fixed-base integration evidence

C8 is locally frozen at `4e007a87ceecbec8d265f6a70cfd71d512a514b5`, tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`, with ordered parents `40a3a45d6b8afc5c4706c5235fec47634f4aabbe` (C7) and `9417e495165865ef6c1288b39084856e31020634` (fixed upstream base). This package records the normal merge, its two real conflicts, exact blob resolution, candidate checks and local commit. It does not assign C7 qualification or lifecycle results to C8, and this integration job did not push.

## Changes and preserved boundaries

The final diff from C7 changes 8 paths, with 208 insertions and 16 deletions. The two conflicts were `.github/workflows/pon-recent-batch-acceptance.yml` and `config/pon/pq-cross-branch-corpus-v1.json`. Both original conflict files and unmerged index stages are in the raw archive. Resolution preserves the complete union and relative ordering of both parents' required paths, C7's W1 profile pin and all other corpus fields. The result has **652 exact source pins and 560 required paths**; all were checked against actual bytes. Six pin values differ from C7, including two newly pinned historical-cache source/test paths. The generated source inventory remains blob `c4fd4e40d80c2a2d0387c23432c56c57ca3fe135`; its `--check` passed without rewriting it.

The merged store source was retained from the automatic merge. The workflow change only binds its store pin to that actual source. Source/event guards, deadlines, acceptance conditions and existing controls were not relaxed. The sole plan records current candidate intent and that the C7 expensive-operation launch remains Unknown. C5/C6 real lifecycle results retain their own identities. This integration is fixed to the requested base and does not follow later branch movement.

## Actual checks and freeze

The single precommit run executed 9 commands, all exit 0: project preflight, staged whitespace check, pinned Rust formatting check, distributed source inventory check, PQ source contract, CI contract, and three Python suites. Raw output contains **115 + 39 + 6 = 160 ordinary method executions, all OK, 0 failed, 0 ignored**. The same candidate diff SHA `5d115e88325dcfb963e12c87591285a05d9c2323324301ee06b5da21edf6bd52` was checked before and after the run and bound to the committed diff. These are precommit candidate checks; they are not the subsequent full qualification of the committed C8 source.

The normal merge's exit 1 is the preserved expected two-conflict result, not a hidden test failure. Preparation, resolution, precommit and freeze all have authoritative succeeded/0, complete, durable job receipts. Freeze ran 19 recorded commands, verified exact ordered parents and tree, and left both the new checkout and original C7 checkout clean. No Cargo build, Rust test, expensive operation or complete proof was performed by this integration work. All old source checkouts and targets remain outside its write scope.

## Narrow source review

Two independent read-only reviews found no concrete new correctness defect in the reviewed cache boundary. Cache lookup still requires exact block identity plus the current SQL root. A hit supplies arithmetic material; the original actual-State canonical key/value comparison and resulting-root check remain. Node invalidation clears both caches and the replay anchor. The new Legacy replay preference protects at most seven entries and preserves an eight-entry limit, 2 MiB payload bound and 16 MiB software retained-charge bound; these do not establish a process RSS cap.

The 131 new Rust test lines extend two existing methods. The historical module still has **10 methods / 0 ignored by source inspection**; none were run by this integration. Existing SQL damage, rollback, final-writer corruption, wrong block/root and progress controls remain. Added subcases cover long replay, changed anchors, same-anchor forks, original-branch readback, equal warm/cold cancellation checkpoints and bounded eviction. The separate independent package reviews fixed base 9417; the main review and resolved diff cover the C8 integration. Neither is a whole-protocol security or performance qualification.

For later exact C8 qualification, use the C8 checkout and its independent owner target:

```sh
/home/qian-qi/.cargo/bin/cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::historical_commitment_tests:: -- --show-output --test-threads=1
```

Those method selectors do not overlap the owner legacy-admission or legacy-reorg modules. Shared runtime behavior still exists; reported totals should count actual method executions rather than assert globally unique tests.

## Original-record inventory

`raw-logs.tar.gz` contains 142 explicit regular-file members. `raw-output-index.json` gives each original path, byte count and SHA-256; packaging re-read all command streams, source-review records, both conflict originals, four exact drivers and the independent review manifest. Every archive member was read back and compared byte for byte. The package contains no ELF, SQLite database, process environment or credential file. `manifest.json` covers every top-level deliverable except itself. Source/build qualification, winning-W1 Node admission, full process-tree accounting, positive provider payment and all four engineering gates remain separate and unclaimed here.
