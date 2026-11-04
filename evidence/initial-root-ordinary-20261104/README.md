# Initial-root ordinary regression evidence

This package preserves the original failures and the successful local verification of the one-use initial-root change for Chain PR #683. It contains data and a standard-library reader. The reader never runs a native test, Cargo command, downloaded script, or ELF.

## Source identities

| Role | Commit | Tree |
| --- | --- | --- |
| Local source actually built and executed | a09d2e3d70a89c69422583d020a732b9fd5a4011 | a32c5e3b169370b1c923bb9a6ef7094a3d3ef041 |
| Published canonical source | 4c46eca89a006616e9240d983c66919071f79b41 | a32c5e3b169370b1c923bb9a6ef7094a3d3ef041 |
| GitHub actual prospective merge | e0f831d0af21cc9eea69b5ec84788ef66e0b025c | a32c5e3b169370b1c923bb9a6ef7094a3d3ef041 |

The published source has parent 264049e359caad8c4bc1bb54c9a63bac26bfa86f. The prospective merge has ordered parents 2e72a989d001cf51bd0aed0e1401526e45db31f1 and 4c46eca89a006616e9240d983c66919071f79b41. The local execution commit is a distinct Git object; its exact source tree equals the published source. These results do not assert that the canonical commit itself was checked out and executed on Main.

The production change reuses only a successful pure root of the immutably borrowed initial State and Settings within one history walk. The private value is consumed once at the original second root expression. Fresh SQL reads, field short-circuiting, record checks, complete snapshot roots, accounts, conservation, progress callbacks and error order remain. Seven independent reference controls cover these boundaries. The failed handwritten State JSON encoder candidate d55 is excluded.

## Actual local results

| Frozen source | Actual outcome |
| --- | --- |
| 0878ee2b630c64ac67e742165c3f20df718c537a | Initial disk preflight stopped before Cargo. The explicitly authorized later build failed with exit 101 and five E0382 ownership errors in new test comparisons. No native tests or CPU selectors ran. |
| ecb54d9c7b1e3fe98b7889f5c89a8b06c27c0b71 | The five comparisons were changed to borrow their expected values. Build passed. All 27 original normal commands terminated: 52 passed, 1 failed and 1 original observation remained ignored. The sole failure was the new test fixture inserting an already existing genesis record. Clippy, host graph and CPU qualification did not run on this failed candidate. |
| a09d2e3d70a89c69422583d020a732b9fd5a4011 | The fixture updates the existing record, retains digest/canonical/size checks, requires one changed row and reads back the real record. All 27 normal commands passed: 53 passed, 0 failed, 1 original observation ignored. Strict Clippy and the complete locked offline host graph passed. Both original CPU selectors then passed once each, with no retry. |

Production and reference bytes did not change between these three initial-root candidates. The successive changes to the test file and necessary corpus pin are preserved with their source receipts and patches.

The local Node ELF was built with the original lib/default feature selection, optimization 3, debuginfo 2, debug assertions and overflow checks. Its recorded original and preserved-copy SHA256 is 107cf5c8589f5ce516d7d19ac9f786641ef9b17c1d57a70476b8615b13d2ddab. Original package cwd, selectors, exact-test readers and budgets were retained. The ELF remains on Main; no executable is embedded in this text package.

Normal durable job: 1a1a3cccaee-96a-7765. CPU durable job: 1a1a3f215de-96a-7797. Both have authoritative succeeded/exit-0/output-complete receipts. CPU admission freshly measured 43,098,816,512 free bytes, satisfying the unchanged strict greater-than-40-GiB guard.

## Original CPU observations

The first original selector contains Legacy and Authenticated observations; the second is the existing supplementary Authenticated selector. These are two native tests and three backend observations.

| Observation | Paid CPU, seconds | Credited refill, seconds | Remaining paid credit, seconds |
| --- | ---: | ---: | ---: |
| First selector, Legacy | 1.049385006 | 0.262279922 | +1.212894916 |
| First selector, Authenticated | 2.513975787 | 0.637140986 | +0.123165199 |
| Supplementary selector, Authenticated | 2.479645219 | 0.625187030 | +0.145541811 |

Every inner and outer result is Ok. The original budget remains a 2,000,000,000 ns burst, 250,000,000 ns per second refill, 100,000,000 ns start reserve and worker limit 2.

Each Authenticated observation records three initial-root reuses, two previously existing full-root reuses, eleven complete commitments, eleven subset projections, 23,145 compared rows, twenty-five actual root calculations and 29,534 newly hashed input rows. In the prior b73 successful first Authenticated observation, the same eleven complete commitments used twenty-eight root calculations and 35,855 newly hashed rows. The current counters therefore record three fewer actual root calculations and 6,321 fewer newly hashed input rows.

The prior b73 supplementary observation failed after ten complete commitments; current a09 succeeds after eleven. Their paid CPU totals are not an equal-work benchmark. Packet, persisted-root and History stage intervals overlap and must not be added. Each selector ran once; no repeated performance guarantee is inferred. The pre-execution snapshot observed one cargo, one make and one rustc process. Whole-host exclusivity is not claimed.

These are the original finite ordinary controls with their explicitly seeded legal State, not evidence for all default-genesis growth, service qualification, release readiness, or whole-chain post-quantum security.

## Contents and verification

The lossless payload contains 479 individually hashed files (original records plus clearly marked derived summaries), totaling 2,659,050 uncompressed bytes. It includes complete command logs and receipts, exact-test readers, resource records, source-bound build and graph logs, old failure logs, source export, the final workflow binding review and raw Git commit metadata. Every original input was read as a regular single-link file with unchanged stat identity around the read.

The immutable index is index.json. Its 23 payload JSON files contain bounded base64 chunks of a deterministic gzip stream. The reader checks outer delivery hashes, every chunk, the gzip and decoded payload digests, every embedded file's size/SHA256/Git blob ID, source bindings, normal execution totals and the original CPU results.

Run the authored data reader with:

    python3 verify_payloads.py

This only reads data. It does not extract or execute embedded source, scripts, tests or binaries. The raw payload.json and payload.json.gz retained on Main are transport conveniences and are not required in the Git archive; index.json and its 23 chunks reproduce them exactly.

Some historical preparation records correctly state CPU was not executed when they were created. Later CPU admission and terminal receipts are retained separately. No historical failure or preparation record was rewritten.

## Separate cloud verification and archive trigger audit

The ordinary four-lane workflow is immutable harness commit 01404de030c0d560e32a4b86620cea027878d2df, a direct child of the canonical source. It checks out exact H or actual M, retains the original complete workspace build, PQ feature set, CPU budgets and source/ELF checks, and adds the seven initial-root controls.

Its expected per-lane denominator is Node 46 + M06 18 + protocol 8 + original CPU 2 + lifetime 2 = 76. Four lanes would total 304 executions. Those are planned counts; this local package does not claim cloud success. Run 41748875721 was started once with push/attempt 1 and is audited separately from these local results. The ignored parser observation is excluded from its explicit selection.

For archive/chain-initial-root-evidence-20261104, the independent event audit read the fifteen immutable H workflow files and the one workflow at current default main dd6e1c3cbeacbdc532b0679297835b3a0aac78f0. None declares create or workflow_run. The only push declarations require the literal main branch and do not match this archive branch. The audit does not rely on skip-ci text as a substitute for trigger inspection.

All source publication, prospective-merge preservation and cloud dispatch were handled by the root agent. This package operation performed no Cargo or native test invocation and changed no source, original evidence, ELF or cache.
