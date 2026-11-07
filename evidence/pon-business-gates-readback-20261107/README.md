# Original business gates and bounded component follow-up

**Status: HOLD.** The original 4-second, 16-worker pressure gates and the
4,105-block History gates did not pass on the measured `d26e047` source.
Later component controls and cost observations support limited implementation
changes; they do not close those business gates or qualify a release.

This record preserves the actual denominators, failures and source identities.
Its main CI authority is [the frozen d26 gate core](ci-d26/GATE_CORE.json).
The combined follow-up source still requires fresh exact-source controls and
the unchanged real CI matrix.

## 1. Measured source, authority and complete CI denominator

| Identity | Exact value |
| --- | --- |
| Pushed head H | `d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89` |
| Resolver-observed main B | `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` |
| Ordered-parent prospective merge M | `7805f1445aec6a31152b50c3d28f5eb6db63305c` |
| H and M tree | `cef3563653b982a8043326ad4b53a4b93ab63906` |
| Priority run | `42383368690`, attempt 1 |
| W1 run | `42383368504`, attempt 1 |

The [publication receipt](publication-d26/receipt.json) records GitHub-confirmed
`ProfHepta` (user ID `102159240`) with repository admin/push authority before
and after a normal fast-forward push to the existing integration branch.
Main remained B. The user designated this administrator and the HeptaRuntime
local GitHub channel. Publication did not assert that pending native tests passed.

Both real push workflows froze the same H/B/M. The complete outcome was:

| Denominator | Success | Failure | Skipped / pending |
| --- | ---: | ---: | ---: |
| 37 workflow jobs | 22 | 15 | 0 / 0 |
| 34 native lanes | 20 | 14 | 0 / 0 |
| 2 source resolvers | 2 | 0 | 0 / 0 |
| 1 historical-original retention job | 0 | 1 | 0 / 0 |

The native families were service 0/4, State 4/4, History 0/4, false-trace 4/4,
legal V1/V2 8/8, factorial 0/4, fresh-challenge 0/2 and rank/batch 4/4.
All 136 source-control steps succeeded: materialization, before-check,
after-check and context retention for each of 34 lanes.
The original dense source observations covered 11,017 tracked entries and 1,031,001,045 bytes with equal before/after identities.
These source and Host checks establish execution provenance, not business success.

The service Host remained `cpu.max=25000 100000`, burst 0, 2 GiB memory,
swap 0 and 256 PIDs. The 4-second window and 16 attack workers were unchanged.
This developer-harness deadline is separate from the protocol's target block
interval. No confirmed TPS or production finality claim follows from this run.

## 2. Original service and fresh-challenge confirmation gates

Every original service lane returned all seven honest Submit calls successfully. Each also completed all five native invocations with exit 0; the strict reader
still rejected `CONFIRMATION_TARGET` because pressure confirmation was 0/1.

| Service lane | Baseline confirmed / target | Baseline seconds | Pressure confirmed / target | Attack calls | History requests |
| --- | --- | ---: | --- | ---: | ---: |
| x64 H | 1/1 | 3.089871221 | 0/1 | 323 | 3 |
| x64 M | 1/1 | 2.200594307 | 0/1 | 446 | 6 |
| ARM H | 1/1 | 1.880231159 | 0/1 | 433 | 7 |
| ARM M | 1/1 | 1.813400169 | 0/1 | 427 | 6 |

The x64 H third History request ended with EAGAIN at 4.050486544 seconds
of the pressure phase. The other lanes retained `PUBLIC_REQUEST_DEADLINE`.
Pressure confirmation latency is unknown/null, not a successful 4-second sample.

Each fresh-challenge job retained both the original-proof and fresh-proof cohorts. All four cohorts submitted 7/7 honest packets, but none confirmed the target.

| Source / cohort | Baseline seconds, 1/1 | Pressure confirmed / target | Attack calls | Native exit |
| --- | ---: | --- | ---: | ---: |
| H / original | 3.091485863 | 0/1 | 310 | 0 |
| H / fresh | 3.015196232 | 0/1 | 205 | 101 |
| M / original | 2.809179884 | 0/1 | 375 | 0 |
| M / fresh | 2.681831260 | 0/1 | 247 | 101 |

Original-cohort strict failures were `CONFIRMATION_TARGET`; fresh-cohort failures
were `FRESH_BUSINESS_TARGET`. The wrapper also retained
`FRESH_NATIVE_PROCESS_REQUIRED` for the fresh native exit 101.
These are observed business/native failures, not missing Host or source receipts.
Both fresh cohorts observed the actual 256-slot, 30-second cache and zero exact-fact
hits; their cache-path checks passed. Full replay counts were H 202 and M 243,
which are distinct from 205 and 247 attack-call denominators.

For H/original, the [retained path readback](ci-d26/factorial-and-original-path/fresh-head-original-path-read.json.gz)
found 249 cached rejections, 49 native full-replay rejections and seven native
acceptances: 56 actual full replays, not the old 305 complete-relation attempts.
All seven honest submissions finished by 1.608335327 seconds. Independent History
replay occupied 1.708156770–3.003120619 and 3.103967401–3.902756122 seconds;
the third RPC ended with EAGAIN at 4.001784181 seconds.
Nested CPU intervals must not be added to infer the wall-clock critical path.

The frozen v2 core explicitly corrects the older derived original-cohort cache
subcheck from default `false` to `null / not_applicable_original_retained_proof`.
The original raw reports and every 0/1 business result remain unchanged.

## 3. State controls and 4,105-block History

All four State lanes passed six named controls and a main migration suite of
40 tests each. Two FIFO subprocess summaries each reported one pass; they are
nested subprocess results, not an additional two main tests or a 42-test suite.

All four original History native executions exited 101. Validators reached active height 4,105. Confirmer rows, successful import returns and active state differed:

| Lane | Successful import returns / 4,105 | Stored non-genesis packets | Active height / generation / slot | Cancelled cursor | Failure |
| --- | --- | ---: | --- | ---: | --- |
| x64 H | 3,917/4,105 | 3,917 | 0 / 0 / 0 | none | Connection refused |
| x64 M | 3,917/4,105 | 3,917 | 0 / 0 / 0 | none | Connection refused |
| ARM H | 4,104/4,105 | 4,105 | 0 / 0 / 0 | 3,916 | PUBLIC_REQUEST_DEADLINE |
| ARM M | 4,104/4,105 | 4,105 | 0 / 0 / 0 | 3,923 | PUBLIC_REQUEST_DEADLINE |

Including genesis, the x64 confirmers contain 3,918 rows and ARM 4,106 rows. ARM's last packet was stored despite the failed final return; activation was
cancelled and active remained genesis. Both x64 confirmers had no reorg journal.
These d26 results are separate from earlier e70 observations of x64 2,362 returns
and ARM cursor 3,404, and from the still older 3,322 / 3,407 observations.

The [native outcome readback](ci-d26/history/readbacks/native-outcome-core-v1.json)
retains the original server-exit observations: x64 H/M line 27 reports
`lifetime_expired` at the original 1,800-second server lifetime; ARM H/M line 29
reports `stop_requested`, without reaching that lifetime. This uses `loop_exit_before_internal_shutdown`, not a stop flag sampled after shutdown.
History's original per-call deadline is 30 seconds; neither deadline was extended.

The [SQL readback](ci-d26/history/readbacks/retained-sql-core-v1.json) used
read-only, immutable SQLite with query-only mode, without `Node::open`, recovery
or writes. All eight database hashes were unchanged. Their exact CI bytes are
retained as deterministic gzip: 1,745,207,296 raw bytes, 176,597,049 compressed.
Source and native binary identities also matched before and after these four runs.

## 4. Local full-suite failures and exact lint repair

The [local d26 full Node result](local-d26/node-final-summary.json) is
**1,161 passed, three failed, 31 ignored**, native exit 101.
The failures were the original >8 MiB Legacy paid-CPU test, NPQ6 exact replay
(TCP reset), and cached-permission's first Head call (EAGAIN).
The complete original failure log and source identities remain retained.

Two [fresh one-attempt PQ diagnostics](local-d26/pq-diagnostics-once/diagnostics.json)
then passed the exact named tests using the preserved binary and original limits.
The full process had reached its 256 KiB phase-log cap before those failures;
the diagnostic processes supplied previously unavailable phase observations.
The original failure causes remain unconfirmed. These passes do not erase the original failures.

Commit `6193489c2fb2a1bdab1128ebed2296f19176401b` replaces the test fixture's
`drop(owner)` with lexical scoping, fixing strict Clippy's `drop_non_drop`
at `store/legacy_admission_readback/tests.rs:434` without a production change.
The [original selector record](lint-619/original-selector/validation.json)
retains an exit-0 invocation that executed zero named tests.
The [corrected exact selector record](lint-619/exact-selector/validation.json)
retains its rejection and the actual named test pass; workspace/all-targets/
all-features strict Clippy also passed on 619. None of these reruns changes d26 CI.

## 5. Adopted components: measured scope and remaining limits

The [205 ingress validation](ingress-205/NATIVE_VALIDATION.md) covers
`205ae38ff01bbf968f3fc2ef0297bee986224684`: 22 exact tests, 22 strict
execution readers and workspace/all-targets/all-features Clippy passed.
The immutable borrowed canonical packet text preserves complete framing, authentication, Cookie-before-Packet ordering and the original full packet decoder.
Ordinary classical Submit uses the borrowed representation; no Work, Host,
state, cancellation or paid-CPU obligation is removed.

The [predeclared ingress observation](ingress-205/BENCH_RESULT.md) retained
768/768 trials, including all 384 expected malformed-codec errors, with no
oracle mismatch or missing CPU sample. All 12 groups met the fixed criteria:
CPU median B/A at most 1.05, and both 64-transaction groups at most 0.90.
Observed median CPU reductions were 12.85–13.48%; the 64-transaction groups were
about 13.4%. The actual Cargo-selected binary and its before/after hash were bound. This unoptimized body/Packet component excludes full Work replay, queues,
networking, Node/state and persistence. It does not establish a service TPS gain.

The [5fdf native validation](state-5fdf-native/validation.json) covers
`5fdf7c236bd0f63a2f544ec006a427d786e6b235`: seven exact tests, seven
required readers and strict workspace Clippy passed.
The bounded memo reuses an adjacent identical canonical Cell value within one SQL scan. It still performs the complete scan and State materialization.

The [state cost observation](state-5fdf-cost/outcome-summary.json) retained
128/128 ABBA trials, zero discarded samples and zero reruns:

| Case | CPU median candidate / original | Predeclared upper bound |
| --- | ---: | ---: |
| Small, adjacent equal values | 0.7893682912 | 1.05 |
| Small, all misses | 0.9977684586 | 1.05 |
| Large, adjacent equal values | 0.1416891668 | 0.90 |
| Large, all misses | 1.0046438260 | 1.05 |

All four component criteria passed. The subsequent original >8 MiB test still
failed, exit 101, with `PUBLIC_MUTATION_CPU_BUDGET`: actual CPU
3,376,700,755 ns versus 2,000,000,000 ns initial credit plus 850,860,305 ns
credited refill, leaving −525,840,450 ns. Both workers completed; active was
unchanged after refusal. The later Authenticated arm did not execute.
Zero Legacy stage counters mean unmeasured work, not free work. The [original failed log](state-5fdf-cost/records/original-large-parent.log)
is retained alongside prior prototype, formatting and fixture failures.

This fixture has 2,100 repeated 4,080-byte strings, not 65K scalar keys. The original History confirmer's eight active rows offer only three adjacent
equal-value opportunities totalling 90 bytes; ARM's 28 staged rows offer one
30-byte opportunity. This is derived read-only SQL analysis, not a new CI run.
Whole-snapshot serialization, historical delta/root work and Work/Host checks
remain outside the memo. General high-cardinality benefit remains unknown.
The d26 and 5fdf whole-case failures are not a paired performance comparison. Neither component completes touched-set authenticated state or COW atomic commit.

## 6. CodeQL, missing historical evidence and local readback coverage

The [CodeQL audit](codeql-d26/README.md) retains two automatic H producers:
six jobs and 69 steps succeeded. Exact push source-before/after checks passed;
the default producer also checked out H. Neither producer establishes M coverage.
Each producer reported Rust 568 findings (562 hard-coded values, six cleartext
logging), Python two `py/redos`, and Actions zero. These are overlapping producer
results, not 1,140 distinct findings. Rust also retained one internal
type-inference error and 19 extraction warnings. Successful execution is not
zero alerts or proof of complete extraction.
Raw paths named in that audit README are members of the retained
[observation archive](codeql-d26/retained-observation.tar.gz).

Historical artifact `11531476198`, run `37730166589`, head
`560d44ac28fee7b073d1740e372839ab52f057b6`, remains **UNKNOWN**.
The original retention job reported “Found 0 artifact(s)”; artifact GET returned
404 and the run's artifact list was empty. A bounded 43-ZIP text search did not
identify the exact local original. Expiry/deletion is not inferred, and a similar
source package cannot substitute for the original artifact.

The fixed d26 package fully verifies service 4/4, fresh 2/2, State 4/4 and History 4/4 artifacts. Other W1 components remain 14/20 verified and six UNKNOWN.
The [late-observer addendum](late-observer-d26/SUMMARY.json) preserves subsequent
digest mismatches, timeouts and a recovered ZIP whose internal manifest was
not verified; it does not retroactively expand the frozen package's coverage.

## 7. Integration boundary and next exact-source gates

The [concurrent Cell integration](concurrent-acc2/integration/core.json) preserves
`acc2ec24fac7e6fbebb49384fc7efc7c9f8b2030` and its source, formal tests,
native consumers, docs and evidence. The [state integration receipt](state-integration/receipt.json)
also confirms the measured component source bytes were preserved.
No constituent branch's tests certify the combined source.

The subsequent remote `04bbc81e4aad9b29fef29385d3262297e2cb17df` was
also merged normally after reviewing all 174 changed paths: two documentation
files and 172 evidence files, with no computational-source change from acc2.
The [recovered concurrent Cell record](../pon-cell-concurrent-revalidation-20261107/README.md)
and both parallel plan additions are preserved. This evidence recovery does not
change any original business qualification gate.

[Cell preparation](cell-formal-preparation/PREPARATION_CORE.json) verified all
415 required historical objects and the three original model fixtures, preserving
the initial preparation failures. It changed no runtime or 30-second child
timeout. The actual interpreter was Python 3.12.3; historical V3's 3.12.14
identity is distinct. Preparation itself did not execute the formal tests.

The final combined source still needs all eight Cell formal files (202 tests), 103 CI contract controls, 12 native Cell integration tests, retained readers,
exact graph/lock/format/source-integrity controls, required native suites and
strict Clippy. It also needs the unchanged real H/M business matrix with source
and Host receipts. New remote changes require review and integration before
that exact source can be frozen. None of these pending gates is marked passed here.

Copy provenance is retained in [RETAINED_COPY.json](RETAINED_COPY.json),
[ADDITIONAL_COPY.json](ADDITIONAL_COPY.json) and
[STATE_CELL_COPY.json](STATE_CELL_COPY.json); the last covers 156 raw files
and 887,995 bytes, omitting only two native binaries with their identities recorded.
The [CI copy plan](ci-d26/COPY_PLAN.json) fixes the original bytes and compression
identities. Existing raw failures are evidence, not replaceable expected-green output.

## 8. First combined-source controls and canonical lock creation

The first frozen combined head was
93277a001f4f8a42be65166f6513177b46cddf5b, tree
3e6cdf8a7532145069c9282f9b59d2fc8a8cd081. Its
[source-control readback](combined-93277-readback/CORE.json) records the complete
single attempt: 665 methods, 663 passed, one failure and one error, zero skips.
All 202 Cell formal tests passed. In total, 16 of 17 suites passed. The original
summary counts 587 methods in entirely successful suites; the Host suite's
additional 76 successful methods are included in the 663 total.

Both failures occurred in PublicFixtureLockControls, before the intended
inode-replacement or cross-receipt-root lock condition: the exact owner/mode
check refused FIXTURE_PARENT_LOCK_OWNER. The [original Host log](combined-93277-source/logs/06-test_from_zero_host_ci.log)
and all 84 source-control files are retained unchanged. The before/after source
receipts match across 12,390 tracked entries and 1,274,925,144 bytes.

The same head's [native prepush receipt](combined-93277-prepush/manifest.json)
passed strict workspace/all-targets/all-features Clippy and full Node --no-run.
Actual linked inventory contains 67 test harnesses (library, binary unit harness,
65 integration targets), 1,573 tests including 57 default-ignored tests, and
12 nonignored Cell tests. The 1,516 default native bodies were not executed by
this preparation. Compilation and inventory are not native test passes.

Source inspection showed that the original privileged lock creator requested
0444 through os.open, which remains subject to its process umask, while the
existing validator requires exact 0444. The retained later live-process
observation reported umask 0077; it is not an observation of the original
already-exited control process. The [reviewed patch](host-lock-review/new-lock-canonical-mode.patch)
makes only an exclusively created new descriptor canonical using fchmod(0444)
and closes it in finally. Existing paths are never repaired or chmodded.
All ownership, exact mode, inode, size, symlink, source/context, nonblocking flock
and original 30-second checks remain.

One added regression executes the real creator in real unprivileged child
processes with child-only umasks 0077 and 0777, checks actual ownership and
mode, and requires an existing 0400 file to remain unchanged and refused.
The old inode-replacement fixture now keeps all non-inode fields equal explicitly.
The source roster therefore grows from 78 to 79 Host methods and from 665 to 666
total methods. These new-source results remain pending here; the failed 93277
attempt is not reclassified or discarded.

[COMBINED_93277_COPY.json](COMBINED_93277_COPY.json) records every copied byte,
including the original source and native readers. No additional native body,
benchmark or business-gate result is inferred from these observations.
