# 819309f W1 — one authorized Range recovery

**Business acceptance remains HOLD.** This small supplement preserves the final authorized read of original artifact `13586509176`, plus full independent coverage across all 20 W1 components. It does not rerun CI, native work, a benchmark or any original business gate.

## Exact original bytes

The source is original run `42402618462`, real integration-branch push attempt 1, head `819309fd312298e099642e1253b1d4ba07113e98`. After v2 was fully terminal and sealed, one local ProfHepta GET requested only bytes `170967040-174175855`. The response was exactly HTTP 206 with `Content-Range: bytes 170967040-174175855/174175856`; only 3,208,816 body bytes were received, within the declared 120-second and 4-MiB bounds.

A new copy combined that tail with the preserved v2 partial. Its complete 174,175,856 bytes have the original GitHub SHA256 `d5e6720c1070b1772107be2d316aea6d27dfdf8dd68535103650730138e9bf38`. The original partial was read only and its before/after SHA256 remained `7915efca8e574436400a7d9bb5c8e59c8681ba0522f77dd5b119fddafac5dae2`.

[receipt.json](receipt.json) and [plan.json](plan.json) retain the actual response, source identity, exact bounds, process outcome and assembly checks. Signed URLs and authorization headers were not retained. [artifact/tail.bin](artifact/tail.bin) preserves the exact response body; the complete original ZIP remains external and is indexed in [EXTERNAL_ORIGINAL_ARCHIVE.json](EXTERNAL_ORIGINAL_ARCHIVE.json).

## Original reader and complete denominator

The restored ZIP passed the same full internal member hash, original native manifest, H/M source/context and ELF/binary checks. The unchanged pinned original pure-reader wrapper was then invoked once. [W1_FINAL_COVERAGE.json](W1_FINAL_COVERAGE.json) is the authoritative final coverage table and records the actual result; the authentic logs and all process/readback records remain under [artifact/](artifact/).

It retains the separate stages: v1 14 complete / 6 transfer UNKNOWN; v2 19 complete / 1 transfer UNKNOWN; and the final Range result. Original failures, partials, timeouts and both earlier seals are unchanged. [v2-reference/](v2-reference/) binds the immediate prior frozen package, which in turn binds v1.

The original 20/20 GitHub W1 component job successes remain separate from independent record verification. Full workflows still have 37 jobs (26 success / 11 failure) and 34 native lanes (24 success / 10 failure). The four service and two fresh pressure confirmations remain 0/1; all four History confirmers remain active genesis; the four State lanes passed their own controls. No service, TPS, hardness, production activation or COW qualification is granted. Missing historical artifact `11531476198` remains UNKNOWN and was not replaced.

## Observer preparation and integrity

[preparation/](preparation/) preserves the local CLI help/version and 12 parser refusal controls; these are observer preparation, not CI/native tests. Two prepared script versions are retained: the final version counts bytes received with a rejected HTTP header and labels truncated stderr hashes precisely before the one live request. No second live Range GET occurred.

[observer/](observer/) preserves code and authoritative job receipts. Large text files are lossless gzip with original/packed sizes and hashes in [FILES.json](FILES.json); every compression was decompressed and compared. [SHA256SUMS](SHA256SUMS) covers payload files; [SEAL.json](SEAL.json) freezes this separate supplement. Copy all three W1 packages, keeping their failures and identity chain.
