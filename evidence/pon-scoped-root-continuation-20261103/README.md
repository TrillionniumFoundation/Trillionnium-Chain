# Scoped graph and complete-root continuation — retained evidence

Status: development candidate, HOLD / NO-GO. This directory preserves complete
prior outcomes and intermediate controls. It does not close P0 service,
whole-chain PQ, independent review or production activation.

## Source and measurement boundaries

The hosted observations are for HEAD
`469c4d4bb36efb37045d968f35f83cb2c1771933`, tree
`383a3cbc8a4a71f27e4f18d7df089b860f302439`, and the actual tested merge
`bfe1f33959a02d0766b33f6acc082e5990d82ea1` with ordered parents
`9a05cae09b175a51773db398541b14ab76061a39` and that HEAD.

The PR subsequently selected main
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; its prospective merge
`e27525b026b9723c901519e58d8c77a3821b2324` differs from 469 only by the
README deletion, as checked by an actual Git diff. This continuation preserves
that main parent. Older results remain labelled with the merge they executed.

The [final 469 inventory](469-hosted/469-final-outcomes.json) links individual
artifact IDs, digests, exact source identities, original counts and cutoff times.
[File integrity](file-integrity.json) hashes the retained small metadata and logs.
Large ELF, database and ZIP duplicates are not included; original GitHub artifact
locators and verified digests remain in the metadata. File identity is not native
execution or an independent security review.

## Actual prior gates

| Original gate | Retained 469 outcome |
| --- | --- |
| Four-second HEAD/merge, original/fresh | Four attack-free phases each confirm 1/1; four 16-hostile phases each confirm 0/1. Seven signed packets per phase remain in each denominator. |
| Fixed-root F0 | 1/6 confirmations in the original thirty-second window, 0/6 within four seconds; 42 planned packet exposures. |
| Three original thirty-second campaigns | 3/27 confirmations; 189 planned packet exposures, 84 actual timely ACKs. Fifteen unobserved rounds remain in the planned denominator. |
| Recent batch | All four lanes pass the same 79 unique native tests, including 19 post-write tests in one actual log. |
| W1 matrix | Sixteen legal/false-trace jobs pass; the two fresh public-service jobs fail. |
| Release CPU | Four lanes pass their release profile. This does not qualify the original ARM test profile. |
| Original workspace CPU | Four ARM test-profile samples refuse with PUBLIC_MUTATION_CPU_BUDGET. |
| PQ selected controls | 172 actual executions: 166 pass and 6 fail; x64 HEAD 42/43, x64 merge 38/43, both ARM lanes 43/43. |
| PQ complete Node library | Both x64 lanes 928 pass / 0 fail / 23 ignored; both ARM lanes 926 pass / 2 fail / 23 ignored. All strict Clippy lanes pass. |
| Required baseline | 21 jobs: 9 success and 12 failure. Runtime delivery invariants and actual service failures remain; fetch refusal is separately localized below. |
| CodeQL / priority | CodeQL source acquisition fails on GitHub HTTP 503; priority is cancelled, with cancellation cause unknown. |

The [service detail](469-hosted/service-outcomes.json),
[thirty-second detail](469-hosted/original-thirty-second-outcomes.json),
[CPU detail](469-hosted/workspace-cpu-outcomes.json),
[PQ final supplement](469-hosted/pq-final-supplement.json) and
[baseline log scope](469-hosted/required-baseline-final-log-scope.json)
retain the distinct workloads and outcomes. Successful complete-library x64
execution does not erase the earlier selected-control failures.

The independent workspace ARM refusals stop after nine complete commitments;
its successful x64 samples complete eleven. The 2.902–9.106 ms debt at refusal
is not the cost of the remaining work. The separate PQ-library ARM samples have
the same two large-state CPU failures and larger 40.930–62.595 ms debts.
Their nine complete-root calculations consume about 0.533–0.536 s inclusive CPU;
five account-graph calls consume about 0.934–0.992 ms. Nested intervals cannot be
added, and release results cannot replace these original-profile failures.

Correction: F0 account-graph snapshots also cover later confirmation/read-active
work. The previously reported 80.5% graph/import ratio is invalid. Preserve raw
scopes instead of dividing incompatible cohorts. Host checkpoints inside an
import are nested within that import and are not an extra additive cost.

## Concrete fetch refusal

[Four original logs and exact inputs](469-hosted/required-fetch-lock-refusal.json)
show the same error in HEAD/merge quality and fuzz:
`cargo fetch --locked --manifest-path tests/fuzz/Cargo.toml` exits 101 because
the independent fuzz lockfile needs updating. All four 301-byte error logs have
SHA-256 `b8cc63ec3bc045865321a56fd4cd4867310822b42e132712c4d9c2787eca8669`.
The preceding main-workspace fetch succeeds in both quality lanes. These are
lock-consistency refusals; subsequent fuzz targets and advisory audit did not
obtain passing evidence in those jobs. Preserve the original `--locked` gate.

## Concrete fuzz-lock repair

The [package comparison](fuzz-lock/package-diff.json) records one missing
trnm-data-availability to rustix dependency edge. All 146 package identities,
versions and sources and all 134 registry checksums remain unchanged. The
original locked metadata refusal was reproduced before repair; complete
[offline locked metadata](fuzz-lock/metadata-offline-locked-after.json) and
[offline locked fetch](fuzz-lock/cargo-fetch-offline-locked-after.json) then pass.
Three previously absent, already-pinned package archives were downloaded and
checked against their original lock checksums. No package version, production
profile, original budget or fuzz selector is changed. This resolves the observed
lock-consistency cause; hosted fuzz execution and advisory results still require
fresh evidence on the combined source.

## Scoped account-graph prototype

The [intermediate source binding](local-intermediate/frontier-source-binding.json)
identifies 469 plus the six exact Rust files in the retained source archive.
It is explicitly an uncommitted intermediate source using the original default
features and test profile. It precedes the complete math/PQ continuation.

The prototype compiles and passes 113 distinct selected native tests:
83 authenticated (including four new subtree controls and the explicitly invoked
original delta observer), 21 state, six reorg and three ancestry. The separate
four-test run duplicates four of those 113 and must not be added to the total.
The new cases exercise actual different-root partial reuse, re-encoded missing
or wrong-side children, complete-current-State negatives, cancellation, no-row
writes, final callback deletion and later writes after a consumed result.
Original reorg assertions and rollback/error checks remain unchanged.

The first LLVM emission failed because the shared filesystem was full. The first
new-test command used the wrong module prefix and matched zero tests; that
successful process exit is an invalid test observation, not four passing tests.
Both failed preparations remain. The corrected runner requires a nonzero actual
count and supports exact expected counts. The corrected four-test command and
complete 83-test invocation pass. Logs and binary hashes are retained even where
completed intermediate artifacts were removed after disk exhaustion.

The delta observations are debug functional controls, not release performance
or original Host qualification. CLI/integration artifacts were built but not
executed in this intermediate cohort. They are not included in the 113 total.

## Complete-root math and PQ diagnostic scopes

The [eight math source identities](local-intermediate/math-integration-files.json)
bind the opaque exact-string implementation. Nine protocol arithmetic controls
and the private-field injection compile-fail doc test pass; their raw logs are
retained. M06, combined Node and original Host acceptance must be executed on
the completed source before promoting their status.

The [fixed-source PQ audit](469-hosted/pq-witness-cost-scope-audit.json) establishes
provider and operation counts, not stage CPU attribution. A successful witness
exchange contains two signatures and four canonical verifications. In the
intentional late-CAS test, four signatures and seven verifications precede the
forced delay; the last reply verification follows it. ConnectionReset 104 alone
does not establish a timeout or the server's actual refusal reason.

See the [native storage contract](../../docs/protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
for the fixed sixteen-subtree scope and same-pool exact-string boundaries.
Complete State, original errors, cancellation, current authority, old nonces,
liabilities, recovery and final publication fences remain mandatory. Retained
payload limits do not measure RSS or transient allocation peaks. No end-to-end
speedup or blocker closure follows from the component controls above.

## Preserved f66 continuation and exact final-source limits

This candidate overlays only the recorded file changes onto published
f66f7f741ac8c78b795ed0bc789ca8f7d23f3b8d, tree
c27b9918037068f697199d7b3398415a0dd3c543. It preserves the concurrent Cell
retirement fix, W1 failure diagnostics, all earlier evidence and the empty README
contract. Its actual historical merge 63cca8bafbe88be1a2882181a137beb8cfc38960
is separately identified in the [f66 CI snapshot](f66-hosted/ci-overview-20261103T143816.json).

The f66 [CodeQL producer and exact export](f66-hosted/codeql-producer-export.json)
succeed. The [warning triage](f66-hosted/codeql-warning-triage.json) retains
504 Rust warnings (498 hard-coded-value and six logging results), not 504 proven
vulnerabilities. Six inspected test sinks contain public hashes or numerical
counts; the two production-source hard-coded flags initialize fully overwritten
public-key buffers. Other test/example results are grouped, not bulk dismissed.
The export still reports target_pr_gate_authenticated=false and no authenticated
PR verdict; independent security acceptance remains open.

Original f66 [ARM workspace CPU refusals](f66-hosted/workspace-arm-cpu.json),
[x64 merge PQ full-library failures](f66-hosted/pq-x64-merge-full-library.json)
and [locked fuzz refusal](f66-hosted/fuzz-lock-refusal.json) remain failures for
that exact source. Four-second/F0 confirmation counts not read in that snapshot
remain unknown; older 469 counts cannot substitute for them.

The new PQ observer is test-only and explicitly scoped. It retains fixed typed
failure categories, bounded phase aggregates, a recent-operation ring, explicit
unfinished/unwind counts and bounded child-process diagnostics on normal stop,
startup failure and parent drop. It does not print requests, keys, signatures,
roots, nonces or arbitrary error strings. Nested outer errors preserve the last
specific service/TCP cause. Sign measurements explicitly include self-verify.
A child error checkpoint precedes process exit and is not proof that the service
has stopped. The original selected 43 controls and all timeouts are unchanged;
two new observer controls are added to normal library execution.

The combined math/M06/Node/PQ source has not been built or run locally. Shared
disk exhaustion required removal of completed build artifacts and a sparse source
checkout; exact blob identity and a complete-base Git tree composition do not
replace compilation, full source/link gates, original HEAD/prospective-merge
execution, x64/ARM measurements or independent review. The retained intermediate
113 native tests, nine protocol tests and one compile-fail doc control keep their
actual source scope. No end-to-end speedup, all-blockers-closed claim or production
activation is established by this publication.
