# Actual hosted continuation for c5dd and b4bdf

This evidence snapshot preserves completed executions of the fixture/diagnostics
candidate and its one-line W1 source-receipt correction, executed at C1 and C2
below. The integration target remains Draft
[PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688).
The original four-second service, F0 and three-campaign business gates remain
failed. This evidence publication grants no performance, independent-operation,
whole-chain PQ, release or activation qualification.

The [earlier continuation](../README.md) retains the original failures, local
builds, local EPERM result, intermediate attempts and dated prepublish snapshots.
Those records are not rewritten by this directory.

## Executed source identities

| Cohort | Candidate | Actual merge | Tree |
| --- | --- | --- | --- |
| C1, fixture and diagnostics | `c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1` | `7a3e125cb343bd85fb806aba87a21f99eac082de` | `30f59a8ec2abdc269bf91e228c58206b23add43d` |
| C2, W1 source filename | `b4bdf142f513081715ecc8d1f9674291e85302cc` | `d9efb0f3bc4dfdbfd8fcb609375dfeb852407bfb` | `3e141fb9bcec9bf2a49d55647f46f12bd3ca28bb` |

Both actual merges have ordered parents main
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` then their own candidate. Each merge
tree equals its own head tree. C1 has 7,723 tracked entries / 882,506,480 bytes;
C2 has 7,757 / 884,109,821. Their 1,190 native source paths are byte-identical;
C2 changes the fresh-service workflow's output basename and evidence/docs.
Each execution retains its own before/after source receipts. Byte equality
does not turn C1's execution into a second C2 execution.

Source bindings: [C1](c5dd/source-binding.json),
[C2](b4bdf/source-binding.json). An evidence commit containing these records
is the publication identity, not the native execution identity.

C2's [original exact-commit checks](b4bdf/exact-commit-gates.json) preserve all
98 original files, including 28 command records, complete output streams and
the three locked Linux Cargo graphs. All declared command expectations pass,
both locks remain unchanged and native source parity covers all 1,190 paths.
That gate finished at 22:36:13 UTC and executed no compiler or native test.

## Corrections with actual execution evidence

### Full original-profile Node suite

All four C1 head/actual-merge and x64/ARM lanes have completed. Each accounts
for the same complete 974-name registry:

| C1 lane | Passed | Failed | Original ignored | Original libtest duration |
| --- | ---: | ---: | ---: | ---: |
| x64 head | 951 | 0 | 23 | 1,247.22 s |
| x64 actual merge | 951 | 0 | 23 | 1,375.07 s |
| ARM head | 951 | 0 | 23 | 2,162.34 s |
| ARM actual merge | 951 | 0 | 23 | 2,172.33 s |

All three new diagnostics tests pass in every lane. The original 43 PQ selectors
also pass in each lane and overlap the complete suite; they do not add 172
unique tests. Strict Node Clippy passes. Original Cargo artifacts identify
optimization level 3, debug information level 2, enabled debug assertions and
enabled overflow checks. These are functional test-profile results, separate
from the release-profile business campaigns below.

The [four-lane readback](c5dd/pq-original-node-four-lane-readback.json) links
the exact native command records, full raw logs, source receipts and registry.
The original artifacts contain no ELF. No binary hash is invented from source
equality, Cargo labels or a different local executable.

The local final composition's 950 PASS / one actual UnixListener EPERM / 23
original ignored result remains a failure with native exit 101. Actual hosted
execution provides separate successful coverage; it does not erase the local
kernel refusal. Full workspace and runtime results have their own scopes.

The [complete C2 four-lane readback](b4bdf/pq-original-node-four-lane-readback.json)
independently verifies the same 951 / 0 / 23 complete registry, the three new
diagnostics tests, original 43 selectors and strict Clippy in every lane:

| C2 lane | Passed | Failed | Original ignored | Original libtest duration |
| --- | ---: | ---: | ---: | ---: |
| x64 head | 951 | 0 | 23 | 1,379.80 s |
| x64 actual merge | 951 | 0 | 23 | 1,384.25 s |
| ARM head | 951 | 0 | 23 | 2,175.89 s |
| ARM actual merge | 951 | 0 | 23 | 2,163.15 s |

Their own before/after source receipts identify C2 or its actual merge, not C1.
The earlier [two-x64 snapshot](b4bdf/pq-two-x64-terminal-handoff.json) remains
unchanged; its pending ARM status is historical. Neither cohort contains an ELF.

### Original workspace CPU lanes and complete Host fixtures

The [C1 CPU readback](c5dd/workspace-cpu/readback.json) and
[C2 CPU readback](b4bdf/workspace-cpu/readback.json) each qualify their own four
head/actual-merge and x64/ARM lanes. Each lane compiles the full workspace with
`--all-targets --all-features --no-run`, then executes the same 50 named native
selectors with 50 PASS and zero failures. This is 50 unique selectors repeated
in eight lanes; the 400 executions are not 400 additional unique tests and are
not added to the full Node suite above. Full workspace compilation is not full
workspace test execution.

Node uses opt3 and M06 opt1; both retain debug2, debug assertions and overflow
checks. The original CPU policy remains 2-second burst, 250 ms/second refill,
100 ms reserve and two workers. Each finite growth observation retains 72
measured blocks, nine cancelled admissions and nine cold reopens, with p99 null
and no service-performance acceptance. The artifacts retain runner-side ELF
hash receipts but no ELF bytes; no independent binary rehash is claimed. The
original 1,264 text members per cohort are preserved and verified byte-for-byte.

Both C1 runtime lanes actually execute all nine original fixed-Host selectors
successfully. The [two-lane terminal readback](c5dd/runtime-two-lane-terminal-readback.json)
retains all 18 real controller executions: each native selector passes, each
controller reports no failure/final Host error, and every original resource
limit and empty-child cleanup holds. Evaluation full sync takes 623.11 seconds
on head and 584.11 seconds on actual merge. Its original CPU-owner fixture
blocker is closed. The original 18-sample architecture reader also passes in
both lanes while its performance-acceptance flag remains false.

The complete workspace invocation subsequently fails in
`tests/public_submit_recovery.rs`. In each lane its 24-name registry has six
observed PASS, three explicit FAILED and one entered selector interrupted by
an original worker panic followed by a destructor panic/SIGABRT; the remaining
14 have no observed execution. There is no final libtest summary. The worker
failure is `OWNER_REORG_TERMINATION_CPU_REQUIRED` during an unmetered scripted
fork activation on an already bound public owner. Original stdout/stderr and
both complete job logs remain intact. The three earlier assertion details were
not emitted by the aborted hosted harness; a separate original-source local
reproduction exposes them, as recorded in the follow-up Submit repair.

The runtime collector's first aggregate attempt wrongly required
`native_execution_authenticated=true`; the original producer contract explicitly
sets that scope flag false. The original false value remains unchanged and the
collector refusal is retained. This correction neither changes a native outcome
nor makes the controller report an authentication authority.

### History registry and W1 source-receipt filename

The W1 reader now follows its actual 25 passed / one original ignored History
registry. All four C1 lanes and all four C2 lanes actually execute those 26
names with zero failures. These are release/default-feature shards with 932
filtered tests and a total registry of 958, separate from the all-feature 974
Node registry. Complete original job logs bind the command and source:
[C1 History](c5dd/w1-history-four-lane-terminal-readback.json),
[C2 History](b4bdf/w1-history-four-lane-terminal-readback.json).
The four large grid ZIPs in each cohort were not downloaded for this readback;
their metadata digests are not presented as locally verified ZIP or ELF hashes.

C1's fresh-service jobs failed before Host/native preparation: the producer
wrote `source-before.json`, while the existing source guard reads `source.json`.
C2 changes only that producer basename. Both actual C2 head and merge lanes now
pass source verification and genuine Host preparation. The original fixed
parent limits remain CPU `25000 100000`, zero burst, 2 GiB memory, zero swap and
256 pids. Both preserve known-empty owned-process cleanup and have no final
Host errors.

The [head](b4bdf/w1-fresh-head-terminal-readback.json) and
[merge](b4bdf/w1-fresh-merge-terminal-readback.json) each verify the actual
release ELF SHA256
`14caa7cea78f1d5850e5e80b73f7bec67ffa27084e055342acfd42dff6bcd12f`.
The source/Host wiring blocker is closed. The original native selector's PASS
and the fresh selector's FAIL retain the business outcomes below.

### Bounded error diagnostics in actual traffic

The [diagnostic summary](diagnostics/summary.json) covers 19 receiver snapshots
and 10,372 retained records from eight complete original business reports.
Every record passes the exact C1 v4/diagnostics reader. All snapshots retain
zero dropped records, zero measurement failures and no counter overflow.
These are retained-record denominators, not a claim that every offered network
attempt entered this observer.

| Actual execution scope | Retained records | ROOT dispatch | WORK:Transcript dispatch | WORK:Product dispatch | Typed dispatch cancellation | Typed terminal EOF |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| C1 F0 | 430 | 315 | 0 | 0 | 64 | 85 |
| C1 three campaigns | 8,780 | 0 | 4,480 | 4,026 | 11 | 123 |
| C2 head, original W1 | 300 | 0 | 191 | 0 | 0 | 4 |
| C2 head, fresh W1 | 281 | 0 | 173 | 0 | 0 | 8 |
| C2 merge, original W1 | 306 | 0 | 197 | 0 | 2 | 12 |
| C2 merge, fresh W1 | 275 | 0 | 168 | 0 | 1 | 9 |

Dispatch and terminal counts can describe the same record and must not be
added as independent failures. There are also 14 typed terminal cancellations
and 24 untyped terminal IO resets. ROOT, WORK:Transcript and WORK:Product keep
their original null typed code and unclassified kind. Display text remains
untrusted and has no control authority.

All 315 F0 ROOT records have an accepted full-W1 phase and a rejected execution
phase. Three also retain terminal EOF. The 379 F0 dispatch error attachments
contain 377 explicit rejected dispatch outcomes and two originally unknown
outcomes captured before dispatch began. The original null outcomes remain
null. Repeated body digests associate these ROOT records with 24 hostile body
groups, but do not identify a unique attempt within each repeated group.

The longest observed message is 43 UTF-8 bytes. This traffic does not exercise
the 96-byte truncation boundary, non-ASCII truncation, capacity overflow or
capture contention; their native controls retain their separate scope. The
observer preserves the first 16,384 records without eviction. No old 116
record is backfilled or included in these counts. Ninety-six-byte diagnostic
capture is measured work where it executes, and is not claimed to be free.

## Local Submit recovery correction after the runtime abort

The actual C1 runtime abort exposed a separate production recovery regression.
The [local Submit repair](submit-recovery/summary.json) records its original
source reproduction and subsequent bounded validation. `Error::remote` correctly
has no local `ErrorCode`, so the former local-code checks could never select the
documented authenticated `UNKNOWN_PARENT` or `PUBLIC_MUTATION_CPU_BUDGET`
responses. A private response-recovery enum now selects exactly those two
already authenticated Submit fields, after the original signature, full request
context, deadline and error-field validation. It grants no local EOF, storage,
owner-stop or generic retry identity. The original call/attempt/parent/epoch
limits and complete Head–History–Head membership proof remain unchanged.

The fixture's three scripted mutations on an already bound Node now use its
original metered CPU domain, with a real pinned Head establishing startup.
Full W1 remains required for new packets. Original 30-second listener and
two-second request policy limits remain. Normal worker join failures still
fail; joining during an existing assertion panic retains both errors without
causing a second panic/SIGABRT that hides subsequent tests.

The original 24 test names and 194 test-body assertions remain unchanged.
Six additional signed prefix/owner/state lookalikes strengthen an existing
negative matrix. The original local reproduction preserves the same abort and
reveals three distinct cap assertions: attempt-limit and call-limit expected
but remote CPU-budget refusal returned, and parent-limit expected but
UNKNOWN_PARENT returned. The first corrected run actually completes 21 PASS /
3 FAIL because a newly added fixture check misread `physical_execution` as a
W1-execution bit. Production ordinary and duplicate replies both keep that
qualification flag false. The corrected check retains that original false
meaning; no W1 or CPU requirement was waived. The next complete original-profile
run is 24 PASS / 0 FAIL / 0 ignored in 16.21 seconds. Both failed attempts remain
in the byte archive. This is local scoped validation, not a completed hosted
workspace or a new performance result.

The final local source also passes ten existing error-identity controls and the
one original typed EOF/stage control. Cargo records opt3, debug2, enabled debug
assertions and enabled overflow checks. Formatter, strict whole-workspace /
all-target / all-feature Clippy and 68 final-source pin/integrity controls pass.
The repeated 68-control invocation is not another 68 unique tests. The new Node
ELF lists the original 974 names; only the 11 stated library controls were run.
The 24 integration tests execute their own binary and are a separate population.

The final 1,190-path native source manifest is
`aab2fa9de01f64a8739fbf941287d06c80a0ec2e16719845aaf5717e4f14b9df`.
It differs from C2 only at `src/public_submit.rs` and
`tests/public_submit_recovery.rs`. The actual local executables are independently
hashed: TCP integration
`e20402b7b585c778d0b524acdbf539bfcf04f91e65bed9c759a5cdd0cb4a0c4c`,
Node unit library
`3b362ab33622e6c9c34a0ee585aaf0a64c8d4ff4e7f272c9a343bfc625901289`,
and CLI `08c51b5cb34634e117ad319d29f957a942a8e882e3fb23a709cb38d83ebf64b0`.
These identities do not inherit any previous ELF's full-suite or Host result.

An initial local terminal summarizer stripped the wrong-length libtest suffix
from PASS names. Its successful native counts and streams were unchanged. The
original summary and collector are retained; corrected names are read directly
from the original stdout, with the metadata correction explicitly recorded.

## Original business gates remain failed

| Executed gate | Actual native result | Original business denominator |
| --- | --- | --- |
| C1 protocol head/merge and x64/ARM from-zero lanes | Five named native tests PASS per lane; separate reader fails CONFIRMATION_TARGET | Baseline 1/1, pressure 0/1 in the original four-second window |
| C2 original W1, head and merge | One native PASS per lane; separate reader fails CONFIRMATION_TARGET | Baseline 1/1, pressure 0/1 |
| C2 fresh W1, head and merge | One actual native FAIL per lane | Baseline 1/1, pressure 0/1; original four seconds and six-depth confirmation |
| C1 F0 and independently executed C2 F0 | One actual native FAIL in each cohort | Baseline 1/3, ROOT 0/3 in the original 30-second windows; scheduled four-second SLO 0/6 |
| C1 three campaigns and independently executed C2 three campaigns | Three actual native failures in each cohort | Each run: baseline 1/3, from-zero 0/3, late-product 0/3; each cohort 3/27 |

F0 has two observed baseline rounds and one observed ROOT round; unstarted
scheduled rounds stay in the denominator. Each original campaign likewise
retains two baseline observations and one in each pressure phase, with a fixed
three-round denominator per phase. There is no post-window confirmation or
drain credit. Native failures are the original assertions, not outer timeout
substitutes. Verified Host readiness and known-empty cleanup do not imply that
the business gate passed. Different lanes retain their actual error lists;
an unconfirmed run with no recorded verifier error is not relabeled as a
deadline error.

Complete reports and original streams:
[C1 F0](c5dd/f0-two-phase-terminal-readback.json),
[C2 F0](b4bdf/f0-two-phase-terminal-readback.json),
[C1 campaigns](c5dd/original-three-campaign-compact-terminal-readback.json),
[C2 campaigns](b4bdf/original-three-campaign-compact-terminal-readback.json).

## What the measured critical path establishes

The [baseline correlation](service-path/c5dd-baseline-critical-path/small-readback.json)
matches all 69 Submit/History body digests to unique receiver connections across
the three C1 baseline phases. Imported packet identities match the acknowledged
Submit block and the History next pointer. This establishes the observed client
path without correlating unrelated observer-local clocks.

The first actual round takes 22.81–22.91 seconds, with 20.48–20.64 seconds in
independent client import. Complete-page-six import takes about 7.56–7.57 seconds;
its nested activation takes about 5.48–5.50 seconds wall and 1.25–1.26 seconds
calling-thread CPU. The 29,928 Host checkpoints belong to that entire import,
not exclusively to activation. Host CPU may include several calling threads;
it is not added to enclosing operation CPU or wall time.

The final failed History import in each baseline is height 13, already
acknowledged at Submit. Full W1, admission preparation and execution succeed;
commit reaches the original request deadline. The original sequential client
loop begins later rounds only after the previous round returns. Scheduled but
unstarted rounds remain failed opportunities, rather than being removed from
the service denominator.

The [current-writer scope review](service-path/c5dd-graph-scope-review/review.json)
finds no missing propagation of an existing valid PostWriteReadback. The
observed aggregate is 95 verify-state and 71 account-graph calls per baseline.
A reconstruction using source and retained SQL shapes matches the counts, but
is not per-call full/partial/hit telemetry. The actual H4-to-H11 activation uses
nine independent write transactions: intent, seven attach steps and final
publication. All already establish readback after their final write and retain
active/history and owner checks.

There are two same-writer repeated partial traversals, each exposing 279 nodes
from a 2,055-node graph. Existing proof rules and negative tests explicitly
prevent a partial traversal becoming a whole-root receipt. They cannot be
described as two redundant complete graph scans.

The [internal traversal review](service-path/c5dd-graph-internal-review/review.json)
confirms one prepared SELECT per graph and fresh SQL bytes per exposed node.
Across the three actual client phases, exact-input decode hit rates are about
99.79%; further decode caching is not supported as the main remedy. A successful
complete-commitment MISS could hand its freshly parsed account map to the same
call's subsequent graph, while HIT preserves parsing at the original graph
position. This is a possible pure-math implementation boundary, but the repeated
projection has no separate measured cost. It was not implemented, compiled or
benchmarked as a claimed service improvement.

H4-to-H5 has two account and two non-account deltas; H6-to-H11 each has two
non-account deltas. Equal account roots do not mean equal complete states.
Existing attach cuts run after each durable cursor commit. A cancellation rolls
back the current uncommitted step while retaining the previous durable cursor,
and typed cancellation records that cursor. Group commit needs explicit local
persistence/cancellation/recovery semantics and their fault acceptance. There
is no existing drop-in helper preserving those observations. Current evidence
does not separately time physical COMMIT, so activation wall time is not a
measurement of amortizable commit cost.

The [Host checkpoint review](service-path/host-checkpoint-cost-review/review.json)
retains fresh boot, current parent identity, current thread cgroup and all five
current limit reads. Its syscall counts are derived from pinned source, not a
strace observation. No authorization/FD cache or reduced check frequency was
introduced. The previously rejected Host optimization keeps its original failed
p95 comparison; an unmeasured decimal-parse shortcut is not a qualified gain.

The additional
[cross-transaction dependency-proof review](service-path/c5dd-private-graph-proof-review/review.json)
finds the present trace/owner machinery insufficient for the proposed strict
invalidation contract. Original tests allow a raw foreign SQLite connection to
modify the account graph after COMMIT. The local connection's trace cannot
observe that foreign connection's no-row writes or rollback attempts between
cursor transactions. Pinned SQLite 3.51.3's `data_version` is a connection-side
u32 change indicator, without the checked increment/sticky-overflow guarantee
of the local observer; it is not a complete global attempt history. No version
wraparound or new attack was executed in this source-only review.

The existing owner scope therefore cannot certify the requested cross-commit
history. This is a NO-GO for this proposed use of current mechanisms, not a
claim that every future immutable-snapshot or dependency-proof design is
impossible. The review also preserves hook ownership, schema/VM, original
intent scope and final generation-change constraints. All 17 reviewed project
paths match between C1 and C2. Its initial source-reader failure is retained
separately from the corrected source read, and is not a failed project test.

## Retention and verification boundaries

The initial frozen package contains 86 original files / 29,736,639 bytes and
six packaging records, totaling 92 files / 30,279,274 bytes. The
[manifest](manifest.json), [verification](verification.json),
[embedded-record index](embedded-records-index.json) and
[reference check](reference-check.json) preserve original paths, bytes, hashes
and explicitly external dependencies.

All 45 strong handoff references resolve and all copied original files match
byte-for-byte. Eighteen gzip files retain their original compressed bytes.
Their 1,285 original records with supplied byte lengths and SHA256 values all
match. Eight complete decoded GitHub job logs lack original per-log SHA fields;
their original whole-gzip hashes are verified and separately computed log
hashes are recorded without inventing an original hash. All 89 diagnostic
samples are independently relocated in the four complete original report
packages and match by value and canonical-row hash. Each report package is
retained once; samples do not replace full reports.

Large ZIPs, SQLite databases and ELFs are not duplicated here. Their original
metadata and the precise scope of any actual rehash remain in the receipts.
Original analysis scripts retain their actual input paths and Git dependencies;
copying the directory does not make them dependency-free executables. Two
formal diagnostics reader attempts both exited zero. Earlier successful draft
data and two actual local F0 collector assumption failures are retained with
their actual meaning: the collector wrongly required native/derived shape
equality and the same cleanup label. These are not additional native or
business-gate refusals. No failed reader, missing terminal result or native
execution is invented by packaging.

The [additional package](additional/manifest-v1.json) appends 22 files /
2,871,589 bytes: the original C2 two-x64 observations, all 98 original C2 source
gate records in a verified byte archive, the 13-file dependency-proof review,
and its packaging records. The initial 92-file manifest is unchanged. Additional
data verification does not create another native execution.

The [second additional package](additional/manifest-v2.json) appends 70 files /
8,308,502 bytes. It contains the C2 ARM terminal observations and complete
four-lane aggregate, both original workspace-CPU cohorts and the two C1 runtime
terminal streams. All 3,246 records in its 15 gzip archives match their original
length, hash and bytes, covering 75,346,301 original text bytes. Its verification
distinguishes included, earlier-package, archived and external references. The
initial 114 files are unchanged. Full reports and raw logs remain available;
the compact summaries do not replace them.

This is evidence retention and data verification. Work-security economics,
independent hardware/operators/review/evaluation, quantum/DAA, beneficial model
releases, custody, external effects, whole-chain PQ, release and activation
retain their original HOLD exit conditions. The sole development plan remains
the existing project plan; this record creates no new roadmap or acceptance flag.
