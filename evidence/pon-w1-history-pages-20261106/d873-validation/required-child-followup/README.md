# Follow-up: four required-job failures resolved to CONFIRMATION_TARGET

The earlier 01:43:12 UTC CI snapshot retained only the Host wrapper's child-exit
failure. Reading the four original uploaded artifacts resolves that cause gap:
all four fail the unchanged finite-window business confirmation acceptance stage
with `CONFIRMATION_TARGET`. Their pressure reports record
`PUBLIC_REQUEST_DEADLINE` during independent replay. This is additional readback
of existing jobs; no tests, reruns, cancellations or new jobs were initiated.

## Actual child outcomes

| Job | Original artifact | No-attack control | Original four-second pressure |
| --- | --- | --- | --- |
| [cross-arch-cost (arm64)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/job/128244737679) | [13552739900](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/artifacts/13552739900) | 1.799873795 s; 1 confirmed | 7 ACKs, 1 successful History; 0 confirmed |
| [protocol-contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/job/128244737934) | [13553414025](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/artifacts/13553414025) | 1.783917101 s; 1 confirmed | 7 ACKs, 1 successful History; 0 confirmed |
| [prospective-merge (protocol-contract)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/job/128244738026) | [13553877465](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/artifacts/13553877465) | 2.392073284 s; 1 confirmed | 7 ACKs, 1 successful History; 0 confirmed |
| [cross-arch-cost (x64)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/job/128244738082) | [13553783434](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42320842015/artifacts/13553783434) | 3.098064568 s; 1 confirmed | 7 ACKs, 1 successful History; 0 confirmed |

Every job's five named Rust invocations returned exit 0, with no subprocess
timeout. The original `service_report` and `sustained_report` acceptance stages
passed. The only failed report acceptance stage is `confirmation_report`.
All Host error lists are empty; source identities and retained binary hashes
match before/after and preparation receipts.

The last Rust test asserts protocol/accounting invariants and records the finite
business outcome separately. Cargo exit 0 therefore does not imply business
confirmation. The original runner correctly rejects the failed business outcome
after reading its report. The 90-second subprocess limit does not extend the
original four-second business window.

Head jobs test `d87357de197db5ff750d08c96d52432e5d22a0b4`; the prospective job
tests `6f03626963aa2145b53acce3f5f9254e7ff81410`, bound to base a3e9002 and
candidate d87357d. All four trees are `323d99df3155b2242aec70c1cc11215bbade2807`.
This is PR #753 into the #688 integration branch, not main qualification.

## Scope and retained originals

[secondary-child-failure-audit.json](secondary-child-failure-audit.json) records
each artifact's digest, source/binary receipts, Host result, five actual test
terminals and report acceptance results. All four original ZIPs were accessible
and matched their GitHub artifact digests.

[required-wrapper-scope-audit.json](required-wrapper-scope-audit.json) binds the
four workflow steps to the five exact tests and sequential report validators.
Ten complete relevant source files have identical Git blobs at 0ca272d,
a3e9002 and d87357d. The two actually imported reader functions also retain
their original text. Production code changes remain separately attributable.
For protocol-contract, this wrapper is the first command under `set -e`;
its failure does not imply later protocol/formal checks executed.

[original-child-reports-and-receipts.tar.gz](original-child-reports-and-receipts.tar.gz)
preserves all twelve complete raw service/sustained/confirmation reports and
the original minimal child/Host/source receipts without reserialization.
[archive-members.json](archive-members.json) records every member's exact
SHA-256 and byte count; decompression and member hashes were verified locally.
The original four artifact URLs above retain their full ZIPs, including binaries
and other outputs not copied into this archive.

This evidence supersedes only the earlier uncertainty about those four child
failures. It does not certify all native correctness suites, make a causal
cross-runner performance claim, or close the original availability gate.
The tested d873 source remains unchanged and the PR remains a draft.
