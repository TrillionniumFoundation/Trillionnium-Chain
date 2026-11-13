# Original source CI now has execution evidence

This packet supersedes the earlier all-queued observation without erasing it.
Read-only original run 42778406804 now has 19 jobs: eight completed failures,
eight completed successes, two runtime jobs still running, and one newly
materialized consistency job queued. The original run is not a complete PASS.
No workflow was retriggered and the failed ROG r1 was not resubmitted.

Three original artifact ZIPs were downloaded, checked against GitHub's exact
size/SHA256, and preserved without recompression. `archive-index.json` also
enumerates every original member and its uncompressed byte hash. The four
retrieved full job logs are preserved losslessly as deterministic gzip, with
separate decoded/stored hashes. These are original observations, not new runs.

## Distinct failure boundaries

* Repository-truth job 129702270227: the repository/link reader passed; the
  subsequent distributed-native source-inventory check failed. Read-only
  regeneration comparison identifies exactly one missing entry:
  `config/pon/joint-consensus-qualification-v1.json`. There are no obsolete
  entries. The inventory was not refreshed here and no requirement was removed.
* Quality job 129702270172: dependency policy refused both declared graphs.
  The original JSONL diagnostics identify RUSTSEC-2026-0459 for libsqlite3-sys;
  ordinary duplicate/license warnings also remain preserved. This reports the
  retained policy result, not an independently established vulnerability or
  exploit. Strict Clippy did not execute in this job after the policy refusal.
* Protocol job 129702269910: the original from-zero native sequence did run.
  All five named child processes returned exit 0 without timeout; original
  report acceptance failed with CONFIRMATION_TARGET. Service and sustained
  report validators passed. The confirmation observation reports 1/1 business
  transaction confirmed within the original four-second attack-free baseline,
  versus 0/1 under its original pressure condition (one unconfirmed, zero
  unknown). This single fixed offer is not saturated TPS or a security tail.
* Cross-arch x64 job 129702270086: the job conclusion is failure and its full
  log is retained. Its separate artifact has not been recovered in this packet;
  no exact subtest cause is inferred from the protocol artifact.

The protocol artifact binds the actual source to
4716bade250f327b012a098418f4eece6b73fcaa / tree
bbc0278f87282d9bcf4e22b167040233516da310 before and after, and binds the same
native test binary before/after to SHA256
68a31cc8b95aee51e6202c275807ee48b0fab8ffd4498d30e30f1a6dbac374e1.
The controller's retained initial/final host-error arrays are empty. These are
hosted source/functional observations; they do not convert the original ROG
r1 failure into a pass or qualify physical work, global delivery or CP/CG/CQ.

Head 89030fceebbb0e02261bfe5eb1ec64313ab842d3 separately had sixteen queued
or pending workflows at this read. Its current prospective merge and the
original run's merge source are distinct identities. Success/failure counts
above describe only the observed original run's job list. Only three of its
eighteen currently listed artifacts were recovered here; remaining artifacts,
running jobs and full prospectively merged conclusions remain unqualified.

Concurrent #868's new strict-Clippy success is scoped to its own source
da002c3227e92d625a73b26706420fab32cdf2d8 and is not borrowed for #863.
This packet changes evidence only. All thirteen actual joint obligations remain
open; native six-successor/lifetime failure bounds remain null and production
activation false. Qualification remains HOLD_NO_GO.

`python3 verify.py` checks archive checksums, every member, original manifest
bindings, actual child terminals and the separated conclusions. It performs
no native compilation, mining, network experiment or malformed-input execution.

The first Mac publication process failed on blob upload 13 with an observed
TCP i/o timeout. Its confirmed exit 1, exact request and error receipt are
retained in `publication-failure.json`. The branch remained at 89030fce; the
failed blob was not found on readback. The authorized ProfHepta connector
fallback preserves the same evidence-only tree content and nonforce expected
head. Prior successful blob objects are reused; no native job was repeated.
