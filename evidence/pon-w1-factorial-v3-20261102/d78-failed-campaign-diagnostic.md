# d78 V3 campaign failure — preserved

Measured source: `d78b67d7bd2b1e194e7679c46dc77ac1ffed286c`. Overall execution: **FAIL**. Qualification: **HOLD**.

The original manifest records **18 completed passing shards out of 30**, followed by **12 failed launches** (indices 18–29). Those launches fail with ENOENT for the live target executable and have `exit_code=null`, `timed_out=false`; the corresponding stdout/stderr files are empty and the strict reader records `missing complete end`. They are not native W1 refusal results and cannot be counted as zero-cost attempts.

The first 18 passing shards cover full-rank-field, zero and continuity-maintenance-v1. Both one-zero/rank-one material classes remain unexecuted in this run. Their original 12 failure records and full denominator remain intact. No full-grid performance summary is generated.

Source-before and source-after are equal, both committed-clean with 6,862 tracked entries. This records the two observed source endpoints. The live binary's after-execution hash is unavailable. A separate read now verifies the retained ELF SHA-256 `b5ce25e8853e14c03c2c03d62179280fbe807c0740cfbac0f36a31a80644e690` against its earlier retained hash; it does not retroactively complete the missing live-path identity check.

The prepared analyzer refused this incomplete manifest with exit 1 and `INCOMPLETE: final full-grid readback required`. No complete-analysis output directory was created. The original failure manifest is unchanged.

This diagnoses the observed missing-executable failure; it does not establish who removed the path or why. A new source/run must execute the entire thirty-shard grid in its own retained campaign. These eighteen shards must not be spliced into that later run or relabelled.
