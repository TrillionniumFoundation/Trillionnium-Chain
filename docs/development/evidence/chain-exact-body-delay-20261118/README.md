# Exact invalid-body grant delay: candidate and retained failures

This is a research candidate based on `119cbdc8b7060df28b74230fa9265ada7bc75541`
from PR #954. The original four-second pressure campaign remains the business
acceptance gate. No process exit code, test count, source pin, or this document
grants public-network, work-profile, resource-fairness, or production qualification.

## Problem and candidate

The retained original x64 and arm64 campaigns admitted all seven honest blocks,
but the independent client did not replay enough History pages before the
original four-second deadline. Both pressure cases confirmed 0/1 transactions.
Their repeated invalid requests continued to consume caller, authentication,
body decoding, response, and receiver CPU in the same 0.25-CPU envelope as the
independent verifier. The original evidence and business failures remain in
[the original cost record](../chain-original-window-cost-20261118/evidence.json).

The candidate adds a 500-ms delay to the existing authenticated `WaitGrant`
stage for an exact request-body digest after a completed native W1
Transcript/Product refusal. It uses 256 fixed slots with four ways per set.
Unknown, contended, poisoned, evicted, and fresh-body lookups take the original
path. Only a completed typed negative work fact can install a hint; successful
work and cancelled verification cannot install one. Lookup never extends the
hint's expiry. Delayed requests do not occupy a paid body, lane, or CPU permit,
and they cannot head-block ready requests with other bodies.

After the delay, the original paid body authentication, current owner/context,
native or negative-cache work verification, absolute deadlines, cancellation,
and CPU settlement still determine the result. The delay does not return a
validity verdict. The publishing worker's small hint update remains inside its
original CPU interval; a later unknown settlement still disables mutations by
the existing rules. This candidate creates no additional worker, queue, CPU
credit, durable guest row, or deadline.

The changed scheduling contract has the distinct signed resource namespace
`r21-exact-invalid-body-grant-delay-v1`. Independent policy vectors and the
separate arithmetic namespace are updated; r10 through r20 history remains
readable, and correctly signed predecessor cookies are still rejected by the
current owner. Existing resource numbers and the original campaign are unchanged.
The hypothesis is limited to repeated exact invalid bodies. Fresh challenges,
distinct bodies, and general anonymous/Sybil fairness remain separate questions.

## Exact source and validation

The native-tested patch against the pinned base has SHA-256
`95637696bdc9bf2bcaec8924215a7cde616805264272e8d3eb5f0c067388f079`.
The same patch was read back from the native worker and byte-compared with the
staged administrator publishing worktree. The source manifest has 2,617 exact
blob pins and retains every qualification assertion as false.
The publication also updates the applicability roster to the renamed r21
predecessor-cookie test and refreshes that configuration's source pin. The
native Rust code remains byte-identical to the tested patch; `validation.json`
records both the native-test and publication file digests.

| Check | Actual result |
| --- | --- |
| Native debug `ingress::public_v3::` module suite | 288 passed, 0 failed, 2 existing ignored; 40.17 s execution |
| Native Clippy, library and both affected integration targets, `-D warnings` | Passed; 21.42 s check |
| Whole-workspace `cargo fmt --all --check` | Passed |
| Multiprocess arithmetic/raw policy binding control | 1 passed, 24 filtered out |
| Complete source-integrity negative-control suite | 114 passed; 297.429 s |
| Independent public-resource policy reader suite | 7 passed |
| Actual source inventory and PQ source closure | Passed; `HOLD_NO_GO`, 2,617 blobs, no qualification or activation |
| Project preflight, staged preflight, exact patch comparison, whitespace | Passed |

Native local checks used Cargo/Rust 1.99.1 on ai395. The unchanged hosted
workflow installs its own pinned native release compiler and must independently
verify the published commit in the original kernel resource envelope.

## Business outcomes and cost remain explicit

The local baseline and candidate each ran the original confirmation function
without pretending to be the hosted resource controller. Both reports retained
`finite_target_met=false`: the independent importer returned
`PUBLIC_HOST_KERNEL_PARENT` sixteen times in each phase because the required
original root cgroup parent was absent. Both versions admitted 7/7 honest
submissions, accepted no attacking work, and closed their observed accounting.
Neither version confirmed the business transaction. Those runs cannot establish
the original pressure-window outcome or a speedup.

The following values are diagnostics from those unqualified local pressure
phases, not a matched fixed-resource performance claim:

| Observed quantity | Base 119cbdc8 | Candidate |
| --- | ---: | ---: |
| Confirmed business transactions | 0 | 0 |
| Honest submissions admitted | 7 | 7 |
| Completed work refusals | 418 | 128 |
| Accepted connections | 551 | 260 |
| Attacker thread CPU, ns | 174,714,422 | 72,251,558 |
| Charged receiver mutation CPU, ns | 109,886,140 | 52,078,347 |
| Whole observed phase process CPU, ns | 515,068,036 | 304,293,951 |
| Whole observed phase wall time, ns | 4,077,455,767 | 4,063,015,271 |

The archive retains the complete reports, original phase process-cost intervals,
file observations, native logs, and per-file hashes. Nested CPU intervals must
not be added together. Missing energy, monetary billing, build process CPU, and
physical WAN cost are unknown; this record does not turn missing measurements
into zero or claim complete research-wide cost accounting.

## Failed attempts remain retained

The initial four-file prototype is retained as
[prototype-source.patch.gz](prototype-source.patch.gz). Its release module run had
282 passes, six failures, and two ignored tests. Five failures were the previous
resource-policy vectors, subsequently updated with the new namespace while
preserving predecessor rejection controls. The sixth was the unchanged
`continuously_distinct_bad_products_exhaust_one_original_prepaid_domain`
control: 512 distinct attempts consumed 299,043,264 ns and did not reach its
expected budget-exhaustion event. That release observation remains a failure;
the loop cap and exhaustion assertion were not weakened. The same original
control passed in the final debug suite. No release baseline comparison is
claimed for that failure.

The first formatter attempt also failed because a sparse checkout omitted the
existing fuzz fixture. The missing original sources were restored before the
successful full formatter checks. An initial Mac preflight used the system
Python without `tomllib`; it failed before patch application. The existing
Homebrew Python 3.14.3 then passed the preflight. A subsequent sparse-file apply
check failed without applying the patch; the exact original affected files
were checked out before the successful byte-identical application. These
environment failures were not suppressed or counted as passing executions.

## Retained material and next gate

- [native-evidence-v2.tar.xz](native-evidence-v2.tar.xz) contains both full native
  reports, their execution/build logs, the prototype release failure, the final
  debug suite, strict Clippy, a concise report summary, and per-file SHA-256s.
- [validation.json](validation.json) binds the exact source, observed checks,
  environment failures, cost unknowns, and the archive identity.

Run the unchanged `trnm-required-baseline` workflow on the published candidate.
Read its x64 and arm64 original confirmation reports and kernel-parent
observations. Business acceptance requires the actual independent transaction
confirmation in the same four-second window, with attack overlap, all original
invariants, and complete retained failures. Continue diagnosis from that report
if any original business target remains false.
