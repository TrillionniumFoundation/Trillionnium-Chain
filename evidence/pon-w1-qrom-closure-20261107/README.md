# W1 QROM continuation: evidence and scope

Implementation baseline: `7150d96a2112875b4afcf3023361a5cef4a0e4b1`.
Publication: [Draft PR #778](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/778).
Full analysis: [continuation report](../../docs/security/W1_QROM_CLOSURE_CONTINUATION_20261107.md).

This packet records engineering progress against the fifteen original QROM
obligation identities. It does not issue a complete QROM bound, owner
authorization certificate, quantum-work theorem or production acceptance.
The fixed v2 release's observed feature/profile sub-scope is complete; other
completed artifact calculations are separately named in the linked reports.

## Evidence map

| Record | Meaning |
| --- | --- |
| [obligation-disposition.json](obligation-disposition.json) | Reviewed disposition of all fifteen original IDs, completed narrow facts, remaining premises and false/null security qualifications |
| [publication.json](publication.json) | Initial normal Git push through Hepta, exact 7150 remote readback and Draft PR creation |
| [publication-1a14](publication-1a14/) | Normal-hook publication of the continuation/inventory repair, exact remote head and unchanged Draft PR identity |
| [hosted-7150-readback.json](hosted-7150-readback.json) | Actual hosted head and ordered prospective-merge source/status records |
| [hosted-7150-qrom.tar.gz](hosted-7150-qrom.tar.gz) | All 52 downloaded files from the successful 7150 hosted QROM run |
| [hosted-7150-all-checks-snapshot.json](hosted-7150-all-checks-snapshot.json) | Time-specific complete PR check snapshot, including failures and still-running checks |
| [hosted-1a14/verification.json](hosted-1a14/verification.json) | Four complete hosted QROM artifacts for exact 1a14 head/ordered merge; 105 closure and 81 implementation names per source, source before/after and actual stage outcomes |
| [hosted-1a14](hosted-1a14/) | Original API records, complete artifact ZIPs and members, repository-truth logs and a separate time-specific broader-check snapshot |
| [repository-truth-7150-inventory-failure.json](repository-truth-7150-inventory-failure.json) | Original required-check failure: two new QROM configs were absent from the generated distributed-source roster |
| [inventory-refresh.json](inventory-refresh.json) | Exact three-entry follow-up repair, including the new closure roster, and successful unchanged generator check |
| [hosted-gate-forensics-42374726461.json](hosted-gate-forensics-42374726461.json) | Original logs and selected artifact records locating three distinct required-check failures |
| [hosted-gate-source-comparison-42374726461.json](hosted-gate-source-comparison-42374726461.json) | Exact source comparison and reproduction of the pre-existing schema-reader failure on both baseline and 7150 source |
| [native-selected](native-selected/) | Original selected outputs for actual receipt verification, native replay, official image and fixed release features; a partial checkpoint, not a full-workspace source certificate |
| [native-summary.json](native-summary.json) | Completed 7150 native observations, including strict Clippy success, the workspace timeout and retained source-check refusals |
| [native-7150-observations.tar.gz](native-7150-observations.tar.gz) | Complete immutable native packet with 133 payload files and raw stdout/stderr |
| [native-7150-manifest.json](native-7150-manifest.json) | Size/SHA-256 identity of every native payload file |
| [native-7150-transfer.json](native-7150-transfer.json) | Chunked transfer and complete archive identity verification |
| [failure-classification.json](failure-classification.json) | Cross-reviewed classification of all three actual outer-harness failures and the unfinished full-workspace result |
| [native-7150-failure-diagnostics](native-7150-failure-diagnostics/) | Subsequent exact single-test executions on the unchanged 7150 binary: ingress passes in isolation; root replay and sealed identity fail with concrete error messages |
| [root-role-decode-probe](root-role-decode-probe/) | Exact old/new role-decoder mechanism probe, canonical serializer equality and malformed-key refusal; full native crate regressions are separate |
| [native-7150-sealed-fields](native-7150-sealed-fields/) | Native syscall field observations, real ctime-only mutation probe and the correction of the test's timestamp assumption; production identity guards remain intact |
| [source-pin-followup/refresh.json](source-pin-followup/refresh.json) | Exactly five reviewed source-pin updates, original inventory-pin refusal and successful unchanged 688-blob/source-inventory guards |
| [native-7150-release-owner-failure-review.json](native-7150-release-owner-failure-review.json) | Independent classification of two observed outer-harness failures; no guessed panic cause |
| [independent-review](independent-review/) | Independent composition, joint-oracle, lifetime, named-runner and workflow probes with explicit reviewed source hashes |
| [local-validation-initial-index.json](local-validation-initial-index.json) | Hash-indexed initial and final-stage local observations, including the preserved temporary extraction-harness failure |
| [local-validation-initial.tar.gz](local-validation-initial.tar.gz) | Raw commands, logs, workflow trials and small-fixture readbacks covered by the index |
| [local-validation-final-index.json](local-validation-final-index.json) | Final 314-test W1 run and disjoint 147 retained controls; this earlier checkpoint predates native completion, whose subsequent outcome is in native-summary.json and failure-classification.json |
| [local-validation-final.tar.gz](local-validation-final.tar.gz) | Complete final W1 test stdout/stderr and command observation |
| [semantics evidence](../pon-w1-qrom-semantics-20261107/README.md) | Six complete locked crate archives, independent image/AIR audit, complete ZKR inventory and actual code-commitment reconstruction |
| [formal bridge evidence](../pon-w1-qrom-formal-bridge-20261107/README.md) | Indexed statement review, exact conditional 10.6 calculations and finite joint-oracle diagnostics |
| [theorem-source-followup.json](theorem-source-followup.json) | Public author/publisher source follow-up and the remaining latest-full-manuscript retrieval boundary |
| [theorem-native-retrieval.json](theorem-native-retrieval.json) | Subsequent ordinary official-PDF request from the native host returned HTTP 403; recorder success is not retrieval success |
| [lifetime evidence](../pon-w1-lifetime-20261107/README.md) | Project inputs with unknown budgets, selected source survey, exact accounting and counterexamples |

The original 7150 hosted run is
[42374726537](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42374726537).
Its prospective merge is `525f75b49cf20849f5dec6a4c0e0b2a40776744f`, with ordered
base `cb114b13bf848a77634e40a08b31b30c7c758e7b` and candidate 7150. Both tested
trees are `c8acae01f6fed538fabd918b6d7b63da348538df`. Each before/after verifier
checks 11,052 tracked entries and 1,095,556,148 bytes. These are records for
those exact sources, not acceptance of a subsequent publication commit.

The archive is 53,156 bytes with SHA-256
`5f740183a548101ea7ce671d7406139b7f763fdfedd72f8cc4d89d726c9cab25`.
The readback was obtained with the configured host's existing GitHub session;
no credential value is part of this evidence.

The failed `repository-truth` inventory check is repaired by the separate
three-entry refresh. Two other original required-check failures have distinct
causes and remain failures in this evidence. The protocol job's native tests
and build completed, but its original four-second, sixteen-worker pressure
confirmation target returned zero of one independently confirmed request and
`PUBLIC_REQUEST_DEADLINE`. No baseline pressure experiment was replayed, so
that source comparison does not prove a timing cause. The external-evidence
job's schema reader expected direct bindings in `open_selected`; both the
baseline and 7150 native sources already delegated them to
`open_selected_mode`. The same original reader rejects both source snapshots.
The full log and selected raw records are preserved by the forensics index;
neither target nor schema check is relaxed by this continuation.

The subsequently published 1a14 has its own successful
[closure run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42379162582)
and [implementation run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42379162380).
Their ordered prospective merge is
`f14298a2728b22fda625267e2e4844b70f829b37`, with parents cb114 then 1a14 and
tree `e08b5dcd9ae2e90d0a36cb5d85e6ce1def387e85`. All four artifacts record
11,144 tracked entries and 1,100,983,593 bytes verified before and after.
Closure records 105 exact successful names and seven entire-byte report
reproductions per source; implementation records its own 81 exact names per
source. Neither count is added to the local 314-test total. Both
repository-truth/inventory jobs passed; the same collection retains other
failed or unfinished jobs and claims no all-green PR result. Subsequent
changes still require their own source-bound validation.

## Named controls and interpretation

The new [fixed roster](../../config/pon/w1-qrom-closure-required-tests-v1.json)
has 105 actual names across seven modules: lifetime 19, composition 16,
joint-oracle 10, semantics 22, ZKR shape 9, ZKR control-ID arithmetic 8 and
completion controls 21. The 105 are included in the complete 314-test W1
discovery run. A separate run passes 147 retained CI-contract/source controls.
Do not add the subset to the whole when reporting totals.

The [runner](../../scripts/ci/w1_qrom_closure_controls.py) verifies the roster
digest, actual registered/started/successful names, counts and qualification
scope. The [workflow](../../.github/workflows/pon-w1-qrom-closure.yml) reserves
a fresh directory, performs exact head or prospective-merge source checks,
executes the runner and a separate checker, reproduces seven complete reports,
checks source again and validates both outcome and conclusion of each required
GitHub stage.

The independent workflow review uses real small Git fixtures, actual source
verification and actual tiny test modules. Its stage-state negative cases are
synthetic inputs to the real completion code. It checks that matching JSON
cannot excuse a failed, skipped or missing execution stage; it does not claim
those fixtures are the complete Chain checkout. Earlier review hashes refer
to the precise earlier version reviewed; later roster growth and the final
source-bound named run are retained separately.

`check` alone verifies a record's structure and claimed completion. It is not
a signed execution attestation against arbitrary malicious Python replacing
its own test callbacks. Normal source review and the fresh controlled CI run
remain part of the interpretation of these observations.

## Native and formal boundaries

The frozen native checkout has the complete selected code, locks, configuration
and fixtures but lacks unrelated historical evidence bodies. Its selected
source inventory must not be relabeled as complete tracked-source validation.
The full-source verifier's refusal is preserved. The separate hosted 7150
checks do have complete tracked-byte coverage.

The completed native packet is 1,067,844 bytes, SHA-256
`e11d0f9d28621b459795e5c692ed05636275cf7d4461bda2cc7cbe5960a60e3e`.
Its selected 2,462 project files match 7150 before and after. The separate
dependency review covers 310 packages and 16,395 registry source files; its
first successful checkpoint occurred after the v2 build, during workspace
testing. Before/after dependency equality is not a pre-compilation source
attestation or a hermetic-build claim.

Formatting, the three v2 tests, the release build, receipt verification,
complete native relation replay, negative controls and strict workspace
Clippy passed. The full workspace did not: its 2,700-second budget expired
with exit -9 and an unfinished node harness. Its stdout contains three actual
outer-harness `FAILED` test records, not expected child-process negative
controls. The absent final failure summary prevents assigning precise causes
from that run. Completed parent/child result-block counts cannot be summed
as unique workspace tests. The original packet and its outcome remain
immutable when later isolated diagnostics are added.

The observed v2 release has exactly `std` and `disable-dev-mode` in its resolved
zkVM features. Its configured context and explicit environment rejection
probes exclude the alternate outer proof/dev paths at that fixed build. Debug
symbols in the release profile are not development-mode receipt acceptance.
The source-to-binary compiler, every recursive program's semantics and a full
QROM extraction argument are independent questions.

The authoritative latest full CDHZ PDF was not obtained in this trial. The
January indexed statements, March metadata and publisher chapter record are
kept distinct. No guessed correction is used to instantiate Theorem 11.3.
All conditional arithmetic examples are labeled assumed/hypothetical; unknown
project budgets and security bits remain null.

PQ signatures protect authorization; complete proofs protect a specified
computation relation; quantum-work analysis protects the correspondence
between resources and chain weight. The complete decisions for these three
lines remain independent and unqualified here.

## Committed source A and final B evidence packet

The [final summary](candidate-1e4b-final-summary.json) binds the observations
below to source A, `1e4bffc371bcdc53aabc621b6b6cb2485ab36f53`, tree
`23c95cb4acfcfd2b1355d9d6e33c4c18b3f332a0`. The
[packet manifest](candidate-1e4b-final-manifest.json) records every new file
and the three changed Markdown records. Existing historical records and the
fifteen-item obligation disposition retain their original bytes.

| Record | Scope |
| --- | --- |
| [Native A summary](candidate-1e4b-native/native-summary.json), [complete archive](candidate-1e4b-native/observations.tar.gz) | 33 recorded stages; release-owner module 40 passed, 1 failed, 1 ignored; narrow gate false |
| [Critical fifteen](candidate-1e4b-native/key-fifteen-completion.json) | Seven root and eight sealed cases actually pass within the unsuccessful module run |
| [Unique service diagnostic](candidate-1e4b-service-diagnostic/diagnostic-summary.json), [raw archive](candidate-1e4b-service-diagnostic/observations.tar.gz) | One same-A/same-binary isolated pass; original module failure and unknown timing cause preserved |
| [Independent service-window review](candidate-1e4b-source-review/service-window-source-review.json) | Exact A source and raw native/diagnostic log review |
| [Fresh Python report](candidate-1e4b-python/report.json), [full raw archive](candidate-1e4b-python/observations.tar.gz), [member manifest](candidate-1e4b-python/manifest.json) | 314 + 147 + 38 distinct named tests, with 2,830 selected A files / 52,119,220 bytes before and after |
| [Original repository failure](candidate-1e4b-repository/initial-report.json), [later successful check](candidate-1e4b-repository/restored-report.json), [complete raw archive](candidate-1e4b-repository/observations.tar.gz) | Original exit 2 retained; later exact-A repository/link check exits 0 |
| [Exact link restoration](candidate-1e4b-repository/link-restoration.json) | 124 existing A targets / 18,864,814 bytes; no source rewrite |
| [Initial preparation and five source-pin recoveries](candidate-1e4b-preparation/manifest.json), [raw archive](candidate-1e4b-preparation/observations.tar.gz) | Original missing-source/full-source failures, exact Git blob/API identities and subsequent source-pin success |
| [A transfer](candidate-1e4b-transfer/transfer-report.json) | Original two large-request timeouts, verified create-only parts and complete bundle hash |

A's formatting, strict Clippy and fixed v2 verification/replay controls pass.
The A full workspace was not rerun, and native selected identity covers
2,805 files rather than the complete tracked worktree. The ignored native
consumer case is not counted as a pass. The failed service test's one isolated
pass does not turn the module or its narrow controller green.

The fresh Python report intentionally still says its repository check was
pending. Its later independent repository record passes 3,717 local links,
26 workspace packages and 1,275 Rust files after exact-blob restoration. The
later 11,036 materialized entries / 1,017,004,928 bytes retain all original
2,830 Python-scope rows; 359 historical evidence omissions still prevent a
whole-source certificate. Neither later restored targets nor the separate
hosted 81/105 rosters are added to the 499-test count.

B changes only the sole plan, continuation report, this README and newly added
closure evidence. The native/Python observations remain labeled tested A;
fresh B hosted source/completion results must be collected after publication.
This packet supplies no new theorem, compiler proof, quantum resource bound
or production permission. All three complete acceptance lines remain HOLD,
and all fifteen full obligations remain unclosed.
