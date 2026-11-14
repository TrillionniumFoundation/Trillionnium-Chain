# C0 head protocol: original failure and bounded snapshot

Sealed: 2026-11-14T09:08:41.558511+00:00

The fresh non-atomic observation ran from 2026-11-14T09:04:00.215476+00:00 to 2026-11-14T09:04:07.997130+00:00. Run 43567821538 attempt 1 remains in progress: 8 failed, 7 successful and 4 running jobs. PR 847 remains open/draft at dc42ce4df5cff79cc61c5addbaf01074b56b06ca against main dd6e1c3cbeacbdc532b0679297835b3a0aac78f0, with auto_merge null. All four running Rust shards are in Run retained Rust shard, not artifact upload.

Head protocol job 132376957411 finished failure at 2026-11-14T08:39:09Z. Its original source before/after are identical, kind=head, commit dc42ce4df5cff79cc61c5addbaf01074b56b06ca and tree 9fda17fed2542b2baccaa34585bb00afd699e12b. This is distinct from prospective job 132376957499 at commit 34fd3082d9d8862d39178e0a5334387841c05af1, despite equal tree identity.

The actual rejection is CONFIRMATION_TARGET, recorded in from-zero-native/manifest.json and line 7 of from-zero-native-host/systemd-run.log. All five original named Rust children passed and returned without timeout. The Python acceptance sequence then returned 1. Host controller failure is null and final Host errors are empty. These test passes do not constitute business acceptance.

| Phase | Workers | Window | Signed-submit ACK | Replay records / accepted | Confirmed business |
|---|---:|---:|---:|---:|---:|
| Baseline | 0 | 4 s | 7 / 7 | 7 / 7 | 1 |
| Pressure | 16 | 4 s | 7 / 7 | 2 / 1 | 0 |

The baseline confirmed at 3.200564462 s. Pressure replay 1 ran from 1.895298265 to 3.797524870 s and succeeded: wall 1,902,226,605 ns, calling-thread CPU 89,332,169 ns. Replay 2 began at 3.896652901 s and returned PUBLIC_REQUEST_DEADLINE at 4.094626530 s: wall 197,973,629 ns, calling-thread CPU 7,936,872 ns. The original report keeps no-attack-accepted, accounting-closed and valid-receiver-prefix true; the independent verifier has not reached complete final state in pressure. These observations do not identify a unique cause of the wall/CPU difference.

The complete original job log is 219,279 bytes, SHA-256 d6e0f1d15764442488a69306c67136477216eadb810d7da6a764029ce5eb3b59. Artifact 14107050061 was acquired once through the official connector: 7,047,002 bytes, SHA-256 0cca9baae976a39bf7e38bec8f942e75053e44e9637233c89d177ee249a6c0a9. All 109 ZIP members passed CRC and SHA-256 verification. The 12,196,577-byte confirmation report remains whole in that ZIP, member SHA bcd60bf212739cd58633d2c1db85192d1460666b90aa6f3e309a64551e6aba03; this package avoids a second expanded copy.

No rerun, dispatch, cancellation, source/ref change, PR write, local native test or stage write was performed. No result here qualifies the later local M5 source.
