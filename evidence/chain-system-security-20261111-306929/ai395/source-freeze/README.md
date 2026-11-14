# Combined source freeze and original metadata observations

These are source/metadata observations on AI395. The original final status is
**HOLD**, with `native_tests_executed: false` and production activation false.
Later native observations have their own receipts; they do not change these
historical flags or erase the failed intermediate corpus observation.

| Checkpoint | Original observation |
| --- | --- |
| Runtime composition `813620f387199bef3eae2493e2af07c70444db58` | Exact bundle/import and project boundary recorded. The stale authority map rejects with actual exit 2, as expected. |
| Reviewed metadata `f21d6be70d8880a4a81c00902fdaee1897a06e31` | Authority and Root checks pass, but the corpus checker returns 1 instead of expected 0 because the authority manifest still has its old corpus pin. |
| Corpus-only child `bac6b7659bd7e2d633e25c2da0add60f6a10c7fb` | Rebind exactly five reviewed metadata pins; preserve the other 1,157 pins, all 1,068 required paths and all qualification fields. All 17 recorded preparation/validation commands return 0. |

The native source is the last checkpoint, tree
`371c3f55de7940e276496efe2008b537ba4d8268`. Its complete source observations
before and after agree: **28,327 tracked entries / 2,578,801,275 bytes**, with a
clean checkout and no missing or mismatching entries. The default and
all-feature locked Cargo graphs, formatting, repository links, authority44,
Root43 and corpus1162 checks all complete. The two unittest groups execute
**65 authority/Root/runner methods** and **43 source-rejection methods**. These
108 source controls are separate from native Rust tests.

The [original archive](metadata-freeze-original-observations-20261112-306929.tar.gz)
is 188,878 bytes with SHA-256
`d2c41611e9e185b71fe78d52667fee6bff84f40307900a9feede5387f9056cab`.
It contains 89 original files and one inner member manifest, including the
three original operation directories, both actual metadata drivers, the
8,507-byte metadata bundle, source observations, command receipts and raw logs.
All 89 input files were unchanged by this copy-only archival operation.

The [member manifest](manifest.json) is the unchanged inner manifest. The
[independent readback](verification.json) verifies all 90 members, 26 recorded
command receipts and 52 raw stream bindings, both driver pins and the metadata
bundle. [Archive creation](archive-result.json) and [lossless transfer](download-receipt.json)
have separate records. The transfer retained intermediate observation timeouts;
the final complete byte stream matches the original archive digest. No source
gate or native test was rerun to produce this archive.
