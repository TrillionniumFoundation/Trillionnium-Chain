# Restore the embedded inventory and separate original runtime success

Source repair: `db9991c537e3469f1b7b6e1fa6f8466ac62edc4f`, tree
`64f5c864417aa567239dd67d3113eb8a0cef795e`, parent #863 head
`dd3cb8776a0e3be668f5ce95dd6d5eded7f2f80e`.

## Source omission repaired

The original source CI refused its generated distributed-native inventory.
The unchanged generator now adds exactly the existing
`config/pon/joint-consensus-qualification-v1.json` entry, with no obsolete entry
removed. That configuration's bytes and all qualification/source pins remain
unchanged. The source commit changes only this generated Rust inventory and
the sole development plan. Source bundles gain the missing existing file;
new compiled binaries and source identities must be qualified separately.

The original exit-1 inventory check, exact refresh command and exit-0 post-check
are retained. Fresh validation on the committed repair completed:

| Check | Result |
| --- | --- |
| Joint-tail methods | 27 PASS |
| Dynamic-participation methods | 28 PASS |
| Qualification methods | 34 PASS |
| CI-contract methods | 167 PASS |
| Source-integrity methods | 43 PASS |
| Embedded inventory, repository/link and CI-contract checks | PASS |
| Qualification consistency | Exit 0, HOLD_NO_GO |
| Promotion request | Expected refusal, exit 3 |
| Complete source before/after | Same 26,364 entries / 2,511,770,000 bytes |

These 299 methods are new executions at the repair source, distinct from the
earlier 299-method source4716 execution. All raw stdout/stderr and command
receipts are retained. New-source Cargo graph, Rust format, strict Clippy and
native-suite results are **not observed here**. Existing sourceCI's dependency
policy and business-confirmation failures remain unchanged historical failures.

## Original hosted runtime terminals, independently scoped

Original run 42778406804 now reports runtime job 129702270255 success on source
`4716bade250f327b012a098418f4eece6b73fcaa`, and runtime job 129702270195 success
on its original preview `bca89f4955de24a80d2540f0c0d0e29b2cae2619`.
Both original shard receipts bind their before/after tracked bytes to tree
`bbc0278f87282d9bcf4e22b167040233516da310`. Their exact ZIPs, raw decoded job
logs compressed losslessly with deterministic gzip, and all ten consensus test
names are retained. The two ZIP receipts bind the same command-script SHA256
`c2369d386856e03a4e6566b4232ccdfb43f2672ca49d2a7070ebd2bfe7d0e9ae`.

Every listed `consensus::tests` assertion passed in each original lane,
including target-window, retarget product, median-time/error-precedence and
time-deferred semantics. Each full job log contains 430 libtest summaries
summing 5,069 passed records and 83 ignored records. These are summary-record
totals across the original matrix, **not distinct test counts**. Ignored tests
remain ignored. Neither the logs nor these two small receipts independently
qualify every loaded binary/library; the larger observation ZIPs are named in
the retained artifact census but have not been recovered in this packet.

This functional evidence is not the failed ROG r1 job and is not execution on
the repaired source. It establishes neither physical cost nor CP/CG/CQ,
delivery/churn/clock hypotheses, all-legal-policy coverage, actual production
tails or lifetime spending. The original source's complete required-baseline
is still not passed; aggregate jobs remain queued in the retained census.
No workflow was manually retriggered and no native ROG task was resubmitted.

The old malformed-input CLI issue remains owned by concurrent #868 and is not
duplicated here. All thirteen actual joint obligations remain open. Native
six-successor and lifetime failure bounds remain null, production activation
false, and qualification **HOLD_NO_GO**. This evidence child does not borrow
the repair source's checks as a new execution at its later evidence-only head.

Run `python3 verify.py` to reconcile the retained sources, 299 method counts,
two original ZIPs, command hashes and exact original consensus rosters. It
performs no Rust compilation, consensus experiment or network test.
