# R1 required-workflow cross-architecture original evidence

This is a read-only acquisition and diagnosis. No native code or tests were executed. The original failed-network v1 and outer-only v2 observations are retained separately and pinned in review.json.

Run: 43604217412, attempt 1. Source: 2a86462a1ab20c68151719ba4635e3c294391e64, tree 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4.

## arm64
- Official artifact 14119000610; requested ZIP 9927038 bytes / SHA256 8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff.
- Actual GET exit 124; received 9142272 bytes; actual SHA256 cacd3e2ae5db448ee3e9b0d4e8383be9b5764c5984991bd7cf5f23b3c5527ada.
- Bounded acquisition incomplete/failed. Original partial bytes and error remain; inner cause UNKNOWN.

## x64
- Official artifact 14119380013; requested ZIP 9851618 bytes / SHA256 d46ce31d5db37912f19115160d8b46e0bf32597fb3c4976a9c80b70bcc3df456.
- Actual GET exit 0; received 9851618 bytes; actual SHA256 d46ce31d5db37912f19115160d8b46e0bf32597fb3c4976a9c80b70bcc3df456.
- Complete ZIP and every member CRC/SHA, exact native manifest filemap, source-before/after, and all original selector streams are retained.
- Actual native failures/validator results: {"all_named_tests_passed": true, "confirmation_report": null, "execution_finished": false, "failures": ["CONFIRMATION_TARGET"], "format_passed": true, "independent_wan_accepted": false, "passed": false, "production_activation": false, "source_recompiled": true, "work_hardness_accepted": false}.
- attack-free-baseline: workers=0, original window=4000000000 ns, confirmed=1; History=7, replay attempts=7; errors=[].
- from-zero-pressure: workers=16, original window=4000000000 ns, confirmed=0; History=1, replay attempts=1; errors=['PUBLIC_REQUEST_DEADLINE'].

The original report is retained inside its verified ZIP; bounded JSON pointers and original numbered line excerpts link the diagnosis to those bytes. Summed nested/parallel clock intervals are not additive elapsed time. No scheduling, throttle, or performance-fix conclusion is inferred.

This package is external evidence only; it has not been added to the frozen publication stage.
