# Completed original CI failure evidence

All four requested job logs and both complete native artifact ZIPs are now preserved. Each ZIP matches GitHub’s original upload size and SHA256; all 158 members per ZIP passed CRC and SHA256 verification, and every one of the 51 files named by each native manifest matched its pinned SHA256.

Repository-truth head and prospective jobs fail at CurrentCiTests.setUpClass, where the old QROM source-drift consumer still fixes the difference count at two. Both cross-cost architectures complete their five native invocations but fail the subsequent confirmation-report acceptance with CONFIRMATION_TARGET. These are original e40d results, not final-candidate test results.

The two pressure traces are distinct: arm64 has 7 ACKs, 7 successful history responses and 6/7 in-window independent replays; x64 has 7 ACKs, 3 successful history responses and 2/3 in-window replays. Both retain the original 4-second window and 16 workers, with 0 confirmed business transactions under pressure and 1 in baseline.

The adjacent completion JSON names every complete raw log, ZIP, index, native manifest and confirmation report with exact size and hash. The range receipt records immutable ETags, exact byte ranges, partial-prefix verification and every downloaded part. Earlier timed-out and ignored-range requests remain preserved. No CI run was canceled or repeated, no source or budget was changed, and no qualification was granted.

ZIP indexing: use files[i].name exactly; there is no additional member prefix.
