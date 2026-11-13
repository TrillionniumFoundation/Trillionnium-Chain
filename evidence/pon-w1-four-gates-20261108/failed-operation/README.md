# Preserved a5ec startup rejection

This is the earlier failed operation. It was never redispatched, its original deadline was never renewed, and no later successful observation was substituted into its journal.

| Field | Original value |
| --- | --- |
| Expected owner/config source | a5ec1ba30916400c345cb47679602cfb1b30a65f |
| Actual prepared runner manifest source | abab79dac0cb89eb2753d3f579119ac135650eb5 |
| Provider operation | f57598b2be2ed23e839bffbd2d2ea9c8f4b339a5e0a5e52923b207a6c6a3e5bc |
| Statement | 0dfcbc2b21d373b0384af92c4053f28298bcf6c3aaa2b6916c2ba4c85f18446b |
| Original target job | 7c74da9a53f46d5182caacfccaa3b5dea0205ea2b02c91fbc967d7eaed0de934 |
| Original boot | 14f92beb-43c6-4786-839e-b57307ae8048 |
| Original deadline | 1189048740638185 monotonic ns |
| Research budget | This operation's separately declared 120 s |
| Native principal | 1000 research units; no NativeCancel wire/refund observed |

The actual parent job 1a1b95d1b63-12894-13b7 exited 101. The source guard rejected startup with **ValueError: actual prepared full execution changed**. The old runner used its compiled-in Cargo manifest directory to read C3 while the owner/config expected a5ec. The guard remained intact.

The [original helper failure](raw/run/owner-cancel-start/failure.json), its [parent command record](raw/run/owner-cancel-start-command/result.json), [stderr](raw/run/owner-cancel-start-command/stderr.log), and [original mismatching manifest](raw/run/proof/checkpoint/manifest.json) preserve the failure. The manifest's 43 entries are prepared execution segments, not 43 completed proof segments.

## Unresolved dispatch and original cap

The [read-only failure observation](raw/failure-readback.json) records exactly sequence 1/tag 0 Prepare and sequence 2/tag 1 Intent. It observes no bound-job, typed failure, owner cancel, settlement or payment event. Target readback is child-intent, cancel 0 and result null.

Under the original a5ec state machine, these retained Prepare+Intent events leave dispatch **Pending** and preserve the full original resource cap. This is explicitly the **state-machine conclusion from the actual raw journal tags**. The reader did not invoke a new owner begin or synthesize a new lifecycle terminal record.

The original helper failure keeps the reservation, prohibits redispatch, and has no completed expensive-live observation. It establishes no running-prover timeout, refund or complete process accounting. GPU and historical process-tree accounting remain Unknown. The [config](raw/config.json) preserves the exact cap and clock values.

## Later read-only process observation

The [process readback](raw/failure-process-readback.json) was taken after the original deadline on the same boot. Exact known worker PID 3002189/start ticks 118894080 was absent, as were the original owner and child cgroup paths.

This reader sent **0 signals, 0 target cancel requests and 0 NativeTask transactions**. It preserved full historical wait/reap qualification as null. The observation neither repairs the absent target terminal result nor releases the original reservation.

## Publication allowlist

raw/ contains the original plan/config/driver, funding and source-binding records, real helper failure/caller logs, existing failure/process observations and authoritative parent job metadata. manifest.json binds exact bytes and source paths; raw-artifacts.tar.gz contains the same allowlist. No SQLite database or proc environment is copied.

The corrected [fresh C5 lifecycle](../lifecycle-c5/README.md) uses a different operation. It does not relabel or settle this failed operation.
