# PQ local cancellation: original failure repaired in real native execution

**The bounded local regression passes. Whole-chain PQ, public paid service,
physical crash recovery and WAN acceptance remain open.**

The actual compiled and tested source is
`990aeb651f793ca44bf94b074356be06e58e75c1`, tree
`91b8178b05d867f063ce21264043c2a49fcc6e41`. All 6,381 tracked entries and
768,140,004 tracked bytes were verified again after execution. The later
evidence commit is not relabeled as that executed source.

## Original failure and minimal production fix

The [retained baseline](../pon-pq-native-readback-20261028-r8/README.md) first
encountered a test macro compilation failure, then genuinely reached the
unchanged ten-second post-intent deadline. The actual failure left an unfinished
reorganization intent and all three subsequent honest calls failed. Cold open
selected the retained target, while peer request and sequence/revocation ledgers
were preserved; this was not an observed nonce rewind.

The [reviewed source fix](../pon-pq-local-origin-source-review-20261028-r8/README.md)
changes three existing local checks to construct local-only typed cancellation
codes. Their diagnostic strings are deliberately absent from the generic error
parser. The original 138 parser mappings, deadline regression function bytes,
wire/schema, conditions and their order, nonce rules, and work relation remain
unchanged. The existing recovery path can now terminate an unpublished local
intent without granting that authority to received error text.

## Actual complete denominators

| Native group or observation | Actual result |
| --- | --- |
| Original PQ network suite plus four regression tests | 10 passed, 0 failed, 0 ignored |
| Original error suite plus origin classification test | 10 passed, 0 failed, 0 ignored |
| Original post-intent deadline | All 5 calls observed; 3/3 honest follow-ups succeed; 24 checks pass |
| Actual original signed expiry | All 5 calls observed; 3/3 honest follow-ups succeed; 23 checks pass |
| Actual signed remote refusal / corrupted-signature sockets | 6/6 calls observed; 12 checks pass |
| Explicit origin controls at genuine durable intents | 15/15 cases observed; 120 checks pass |

The expiry test uses original bytes signed before execution. Historical response
verification uses the original expiry explicitly; current-time verification and
live replay reject those same expired bytes. No signature lifetime is renewed.
The original deadline and expiry tests preserve the original owner lock, active
state, nonce/replay ledgers and cold recovery. All Unix identity checks executed.

The fifteen origin cases deliberately inject typed/local/quoted/remote error
origins through the existing fault hook. They establish the cleanup authority
boundary, not a physical kill or a genuine concurrent durable revocation.
Current production listener serialization does not expose a concurrent durable
revocation at this locked post-intent point.

## Resource and source qualification

Normal offline formatting, complete locked all-features metadata and strict
workspace/all-targets/all-features Clippy all pass. Clippy took 52.880318 seconds.
The PQ command took 461.281070 seconds including compilation; the native test
harness reports 19.56 seconds. The subsequent ten error tests took 0.088644
seconds including Cargo overhead.

The complete supervised run took 525.349589 seconds and captured 508.373779
child CPU seconds, with peak sampled RSS 2,602,369,024 bytes and peak target
growth 473,300,992 bytes. Declared limits were 800 wall seconds, 1,000 child CPU
seconds, 3 GiB sampled RSS, 768 MiB target growth and a 1 GiB free-disk floor.
There was no stop-trigger, retry, guard error or remaining owned process. A
separate readback found all 41 observed PID-plus-birth identities terminal.
These are sampled stop thresholds, not kernel cgroup hard limits.

Both earlier failed attempts remain in the cumulative three-attempt ledger.
All other earlier PQ suites and their interruptions remain in the preceding
packet; none is rewritten as this candidate's execution. The exact executable
was preserved as lossless gzip and completely decompressed to the original
SHA-256 before unlinking its redundant raw path. Its external preservation
receipt is included; the large executable archive is separate from this packet.

The [readback](readback.json) gives exact identities, costs and boundaries.
[Raw original records](raw-native-records.zip) retain every execution log,
all four full observations with synthetic signed wire bytes, source maps,
declarations, supervisor samples, runner/guard sources and terminal receipts.
The [manifest](manifest.json) independently binds every original ZIP member.
No production key, external service or deployed state was used.
