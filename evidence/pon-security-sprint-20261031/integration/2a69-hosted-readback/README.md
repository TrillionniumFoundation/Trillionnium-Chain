# Published 2a69 source: native controls and stale workflow rosters

These are actual completed hosted observations of candidate
`2a69a989046489c212619dd337ee74a083f101de`, tree
`e6d2e1d84e0ce7eae374fc635f79179026653545`. They do not inherit an earlier
local executable's identity or certify a later workflow/evidence commit.

## Final kernel source executed on ARM and x64

The recent-batch run
[41159178300](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178300)
completed these ARM and x64 jobs:

| Job | Actual source and architecture | Kernel suite | Authenticated owner suite | Whole-job result |
| --- | --- | --- | --- | --- |
| [124412660880](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178300/job/124412660880) | ARM exact head `2a69a989` | 19 passed, 0 failed; exactly the named manual cost test ignored | 22 passed, 0 failed, 0 ignored; 19.96 s | Failure at the obsolete 20-pass grep |
| [124412660981](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178300/job/124412660981) | ARM actual prospective merge `2a11f30b6c2e0bc28edfa75e003381de18db7b88` | 19 passed, 0 failed; exactly the named manual cost test ignored | 22 passed, 0 failed, 0 ignored; 19.66 s | Failure at the obsolete 20-pass grep |
| [124412660631](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178300/job/124412660631) | x64 actual prospective merge `2a11f30b` | 19 passed, 0 failed; exactly the named manual cost test ignored | 22 passed, 0 failed, 0 ignored; 11.63 s | Failure at the obsolete 20-pass grep |

For all three jobs, the before/after full source receipts are identical and verify
7,935 tracked entries and 1,010,919,750 bytes. The prospective merge's ordered
parents are actual main `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and the
candidate; its tree is exactly the candidate tree. This source is the final
kernel implementation, including the later test-only reporting and Clippy-loop
corrections. It is separate from the first locally compiled kernel observation.

The raw logs show all 22 named authenticated tests succeeding, then shell exit
1 because the workflow still grepped for `20 passed`. Its subsequent strict
Clippy and other later steps did not execute. The manual kernel cost observation
was intentionally ignored; none of these jobs measured a new quota-file speedup or
qualified the complete History/admission service.

The [head record](arm-head-124412660880/observation.json) and
[merge record](arm-prospective-merge-124412660981/observation.json) retain both
source receipts and the exact passed/ignored names. Both ARM directories retain the
complete original ZIP, its verified GitHub digest/size, a losslessly compressed
decoded job log, selected exact members and a file manifest. The separate
[x64 merge record](x64-prospective-merge-124412660631/observation.json) retains
the complete provider-decoded log and the source JSON extracted from its
stdout; it explicitly does not claim a downloaded artifact ZIP. The prior workflow
failure remains a failure.

## Correcting the two stale rosters

The existing recent-batch workflow now requires the current complete 22-name
owner roster, one exact 22-pass summary, zero failures and zero ignored tests.
It preserves the existing seven independently selected regression invocations.

A read-only module/declaration review also found that the subsequent
`store::native_authenticated:: --include-ignored` selector has **60** current
tests, while the workflow still required 56. The correction requires all 60
exact names once and one exact 60-pass/zero-ignore summary. The existing
`--include-ignored` is retained, so its one originally ignored measurement must
still execute in that suite. The [inventory](native-auth-complete-names.json)
and [source hashes](native-auth-static-inventory.json) document the current
module linkage. This suite was not reached in these failed jobs, and this static
count is not a native pass. The precise historical identity of all four additions
relative to the old 56 count is not inferred from the arithmetic difference.

The [remaining fixed-count review](recent-count-static-review.json) found no
other mismatch among the fifteen inspected count/selector cases. It does not
claim to enumerate every named singleton or replace hosted execution.
No Rust source, test assertion, lock, timeout, quota, original selector,
ordered-parent check or native/consensus acceptance predicate is changed by this correction.

## Readback controls

[Twenty executed controls](roster-controls.json) exercise the actual modified
workflow predicates. The 22-name positive input is the authentic retained ARM
merge transcript. The 60-name positive input is explicitly a **synthetic reader
fixture** built from the source inventory, because the original job never
executed that suite. Each arm also rejects nine deliberately missing, duplicate,
renamed, ignored, failed, old-summary, duplicate-summary, failed-summary or empty
inputs. These are log-reader controls, not invented native executions.

From the repository root, reproduce those checks with:

```bash
python3 evidence/pon-security-sprint-20261031/integration/2a69-hosted-readback/check_rosters.py \
  --workflow .github/workflows/pon-recent-batch-acceptance.yml \
  --artifact evidence/pon-security-sprint-20261031/integration/2a69-hosted-readback/arm-prospective-merge-124412660981/artifact.zip \
  --inventory evidence/pon-security-sprint-20261031/integration/2a69-hosted-readback/native-auth-complete-names.json \
  --output /tmp/trnm-recent-roster-readback.json
```

The candidate also reran 97 CI contract controls and 34 negative source-integrity
controls successfully. Their raw stdout/stderr are in `validation/`. Those
checks do not establish minimum legal work cost, fresh-identity service,
quantum security, or production readiness. Final whole-workflow execution and
strict Clippy remain their own gates.

## Actual complete-W1 hosted success

The [separate W1 receiver job](w1-receiver-124412661337/README.md) also completed
successfully on exact `2a69a989/e6d2e1d8`, with matching before/after full source
guards. It actually ran 21 host tests, release/locked strict Clippy, the real
historical Composite positive proof and all 16 original mutation rejections,
eight receiver cases, and 24 paired public-claim observations. Its 39 fixture,
15 original-reader and eight new-reader controls pass. All 17 reported source
inputs match the immutable commit's Git blobs.

The new path rejects three inconsistent public-claim cases in 22.74–22.91 ms
with fresh prepared state or 4.127–4.189 ms with fixed state reused, compared
with roughly 1.19–1.23 seconds in the same executable's original SDK ordering.
Matching-claim corrupt seals and coordinated public forgery still execute the
full SDK and take 1.21–1.23 seconds to reject. Valid proofs still take about
1.23–1.25 seconds. These are single warmed observations, not medians or public
ingress throughput. The fixture is the historical 62-segment, 15,862,780-byte
Composite proof, not the separate 256,886-byte Succinct experiment; no new proof
was generated. Worst-case rejection, minimum work and practical proof economics
remain open.

The W1 package contains 63 selected original artifact members, full source
receipts and provider-decoded logs. Its full downloaded artifact digest was
verified against GitHub; the package does not duplicate the ZIP or four native
binaries. Every retained byte and every omission is labeled in its manifest.
These completed 2a69 results cannot be relabeled as a later full-source CI pass.

## Focused native job still running at capture

At 2026-10-31 02:41:12 UTC, the [provider step snapshot](focused-live-step-status.json)
for [focused job 124412661152](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178368/job/124412661152)
reports completed-success for the two named real-wall mining controls and the
strict all-target/all-feature Clippy command for the three modified native
crates. It is then running the retained producer campaign. Its complete raw
job log and final source-after guard are not yet available in this capture.
This is a live step-status observation of 2a69, not a whole-job success, an
independently parsed terminal mining transcript or a later-source qualification.
