# Checkpoint socket probe follow-up — Draft HOLD

Tested source: 7d4303f1a9ba3c259b92e58b85126eef3c5378a1

Source tree: 2a580a0444f56c0e70e0d73a7fad1120367d1e9e

Parent evidence commit: 09e4801308366fac01e55bcbdcf8bdfd4e6d2810 (Root Draft #945).

The source change removes the redundant accept-time socket-owner check. A bounded complete request still reaches the original pathname fence before checkpoint export, lookup, compare-and-advance or any response. All three original socket tests remain unchanged; one complete-request negative control is added.

[Native summary](native/SUMMARY.json), [original command receipts](native/commands.json), [source qualification](SOURCE_QUALIFICATION.json), [ordered original-byte manifest](PUBLICATION_PACKAGE.json), [source preparation](source-preparation/FROZEN.json).

Only the fourteen listed commands ran on this new source. The complete checkpoint package uses the original 1200-second outer limit, original transport bounds and test-thread setting. Every command exit and timeout remains visible. The original Root V3/V4/V5/V6 results remain attached to the earlier source 87943f6229d8785c3f431ede5eadba62b634ab8c. They were not rerun by this follow-up and are not qualifications of this new source.

The evidence commit is a sole archival child of the tested source. It is not another execution. Files larger than the unchanged 4 MiB corpus cap are retained in ordered parts with whole-original length and SHA-256.

The old ignored-log staging refusal and narrowly scoped recovery receipt remain under prior-publication. The first socket validation attempt stopped during admission because the recorded old target directory was absent. Its unchanged FAILED.json, including the original traceback and zero completed command records, is retained under prior-validation-v1. The current attempt creates a different empty private target; it neither recreates nor reuses the missing old target. The fourteen original command arguments and limits are unchanged. This archived failure receipt is not a qualification or a runtime-owner terminal proof. Private native SDK records, input bodies and Git indexes are excluded.

This remains Draft HOLD. ARM, prospective GitHub merge validation, the original three 30-second campaigns, whole-chain post-quantum qualification, independent authority custody, actual external effects and production activation are not certified by these observations.
