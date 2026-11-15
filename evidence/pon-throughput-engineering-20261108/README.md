# Native throughput engineering continuation

**Status: HOLD_NO_GO.** This is engineering and diagnostic evidence, not qualified
public throughput or runtime activation.

The implementation was executed at commit
`92529f8492545e6c395044165b4f5d7c3fb0972a`, tree
`e96be99451284479b474acb5dce7443ef0a957b4`, starting from the user-pinned
`dbc1ca09c3db57ae683671a0e7c37ca0aca01f71`.
The publication child adds evidence only. Native results retain their actual
implementation commit, features, toolchain, binaries and command environments;
an evidence-only child does not acquire a new native execution identity.

The [execution profile](../../formal/throughput-v1/EXECUTION_PROFILE_V1.md)
describes implementation scope. The existing development plan remains the sole
plan. The [validation index](validation-index.json) verifies exact before/after
source identity and each retained command log digest. The
[binary inventory](native-binary-inventory.json) retains five actual Cargo test
outputs; it does not claim an independent reproducible build.
[SHA256SUMS](SHA256SUMS) binds the retained files.

## Separate original acceptance families

This table describes the retained local execution before PR publication; later CI
results require their own head/merge identities and evidence.

| Family | Immutable original obligations | Current-source execution |
| --- | --- | --- |
| Host service | Strictly before 4 seconds; 0.25 CPU, 2 GiB, zero swap, 256 PIDs; baseline / 16 hostile workers; original depth 6 and cumulative-work multiplier 6 | Original campaign not executed: prerequisites not met |
| Complete campaign | Strictly before 30 seconds per phase; 3 runs x 3 phases x 3 rounds = 27 planned slots; 0/24/24 attack load; original controller and independently observed receiver budgets | No new original campaign executed |

The [frozen Host prerequisites](host-prerequisites-frozen.json) retain
`FIXED_PARENT_IDENTITY`, `KERNEL_OBSERVATION_UNAVAILABLE`,
`ORIGINAL_FINITE_LIMITS` and `REVIEWED_UNIT_BYTES`. The required root-owned
parent and reviewed unit were unavailable. Exit 1 is a prerequisite HOLD, not
a four-second business execution or a measured zero-confirmation result.
The [source-bound command receipt](frozen-controls/frozen-host-prerequisites.json)
preserves this outcome.

The [historical campaign readback](historical-campaign-execution-report.json)
rechecks 27/27 original confirmation observation slots at historical source
`9e705ccf75b7318dcc4bda4815956f58beb10e72`; it remains HOLD. These are
retained observations, not 27 independent trials or execution of this candidate.
Its reader exits 1 for valid HOLD evidence. The
[command receipt](frozen-controls/frozen-historical-campaign-readback.json)
records that expected result. Historical success does not replace a missing
current-source run, a failed original window, an independent receiver limit,
or missing physical-clock/WAN/risk obligations.

## Implementation

- Optional native observations retain each first error's own phase, typed cause
  and observer clock. Dispatch and terminal errors, response delivery, socket
  close and final task-owner close remain distinct.
- Six reactor-frame slots retain returned wrapper calls, progress, no progress,
  failures, wall/thread CPU and unknown-clock denominators. Capture remains
  bounded and nonblocking; disabled observers do not start these new clocks.
- A bounded account conflict hint suppresses disposable state prediction for
  already touched senders or exactly shaped PNX1 transfer recipients.
  Preparation and signatures remain complete; prepared results/errors and
  state application are consumed in canonical order. Exact-read validation and
  at most one replay per transaction remain.
- For the 256-transfer common-recipient fixture with multiple senders and
  2, 4 or 8 workers, the oracle's 256 predictions plus 255 replays become
  one prediction plus 255 direct canonical applications. Both verify
  256 signatures and compare complete state, receipts, roots and errors.
  This is 511 versus 256 state applications, not a CPU ratio or TPS claim.
- Peer polling reuses the original absolute end across all protected calls.
  The real two-attempt TCP regression verifies no fresh retry allowance,
  both failures retained, socket release and unchanged cursor/native state.
- Existing Cell persistence, bounded I/O, multisource scheduling and task
  observations are reused and validated. Public signed ingress is not changed
  to a new multiple-request connection protocol. Complete model learning,
  adoption, every preparation-cache boundary and WAN service qualification
  are not established by these component controls.

## Fixed-source validation

Native commands use the original test profile, default crate features, Rust
1.95.0, the locked offline Cargo graph, two build jobs and serial libtest
execution. This is not a resource-matched performance comparison with the
earlier baseline.

| Native group | Passed | Ignored | Receipt |
| --- | ---: | ---: | --- |
| Complete MVCC library | 146 | 9 | [record](frozen-native/frozen-mvcc-library.json) |
| Request observation, including actual socket I/O | 30 | 0 | [record](frozen-native/frozen-node-request-observation.json) |
| Peer polling | 15 | 0 | [record](frozen-native/frozen-node-peer-polling.json) |
| Disconnect/queued-submit cancellation | 1 | 0 | [record](frozen-native/frozen-node-disconnect-cancel.json) |
| Unknown worker CPU clock | 1 | 0 | [record](frozen-native/frozen-node-unknown-clock.json) |
| Correctly selected scoped-work cancellation/settlement | 1 | 0 | [record](frozen-native/frozen-node-cancel-settlement-corrected.json) |
| Cell persistent transport and associated retained cases | 36 | 0 | [record](frozen-native/frozen-cell-persistent.json) |
| Accepted-task restart/reorg/alteration observations | 4 | 0 | [record](frozen-native/frozen-task-observation.json) |
| Real request-accounting integration | 1 | 0 | [record](frozen-native/frozen-request-accounting.json) |
| **Total without strace** | **235** | **9** | Observer instrumentation is still present where each test enables it |

The same request-accounting test was separately repeated with strace and passed
once. It is not an additional independent trial or an uninstrumented baseline.

All **400 Python control methods** passed: throughput readers 96, original
full-path controls 109, native phase reader 65, command receipts 8, negative
source-integrity controls 43 and original Host controls 79. The throughput
suite includes the new 26 report methods and nine syscall-reader methods.

Exact source/pin controls, 3,811 local Markdown links, generated native source
inventory, CI contract checks, original report reproduction, formatting and
both default/all-feature Cargo metadata commands passed. The strict workspace
all-target/all-feature Clippy command with `-D warnings` passed; see
[the pinned-provider receipt](frozen-controls/frozen-clippy-pinned-provider.json).
The original lockfile, profiles, resource limits and deadline assertions remain.

## Real same-invocation component profile

The [component profile](frozen-instrumentation/component-profile.json) combines
the actual [request snapshot](frozen-instrumentation/request-snapshot.json) with
the separately scoped [syscall profile](frozen-instrumentation/sqlite-profile.json).
The [raw strace](frozen-instrumentation/accounting.strace),
[capture receipt](frozen-instrumentation/accounting-capture.json) and
[source-bound native command](frozen-instrumentation/frozen-instrumented-accounting.json)
are retained. The original full stdout remains in
[the native log](frozen-instrumentation/frozen-instrumented-accounting.log).

This existing test has a 15-second service upper limit. It stops after its five
requests and joins its owners; it is not a completed 15-second pressure cohort
and is neither original acceptance campaign. It runs partial Hello/EOF, an
invalid Product Submit, a valid Submit, Head and History, then compares native
state against a separately opened oracle.

| Observed scope | Actual retained result |
| --- | --- |
| Connection coverage | 5 seen / 5 retained / 5 closed; zero capture failures, zero omitted records, no counter overflow |
| Application socket bytes | 199,132 read; 108,850 written; physical framing/retransmissions unknown |
| Returned reactor wrapper calls | 32 = 28 progressed + 3 no-progress + 1 failed |
| First errors | One dispatch error and one terminal EOF event; one unknown typed dispatch code retained |
| Selected WAL write-family calls | 254 successful pwrite64 returns across two exact paths; 519,184 returned bytes |
| Selected WAL synchronization | 14 fsync calls; strace elapsed sum 2.395923 seconds; maximum 0.594580 seconds |
| Selected syscall diagnostic closure | No parser issues, unknown results or unclosed selected calls; both original contract flags remain false |

WAL scope includes test setup, the native service, the independent oracle and
teardown. The two exact database paths are not merged into a per-request
attribution, and path order is not used to infer roles. Returned bytes are not
unique data, file growth, device writes or durability. Syscall elapsed sums may
overlap; they are not CPU time or a proven request critical path. These measured
synchronization costs justify further original-campaign profiling, not a
conclusion that a particular request exceeded or satisfied its contract.

New statistical fields have at most five known request samples, and fewer for
some stages/errors. Their p95/p99 thresholds are 20/100, so those new statistics
remain null. Preserved older summaries retain their explicitly descriptive
small-sample values. No field establishes a future worst-case refusal bound.

No request-role input is supplied to the component adapter: all five role
attributions remain unknown. The report does not relabel them as an authenticated
attack cohort. Whole-request CPU, physical network bytes, all-lock wait, queue
occupancy high-water, cancellation signal-to-stop and recovery time remain
unknown. Named owner waits, entered queue intervals, inclusive CPU stages,
error appearance and final owner lifetime keep their individual scopes.

## Retained failures and non-executions

- The [exact baseline receipt](baseline-mvcc-library.json) and
  [baseline log](baseline-mvcc-library.log) retain 141 passes and nine ignored
  tests on `dbc1ca09`. Development commands are separately labeled and are
  not final-source or original-acceptance evidence.
- [First account-conflict build](dev-account-conflict-01.log) failed because a
  test-only Growth initializer still used the renamed field. The corrected
  development run and all final MVCC tests are retained.
- [Initial pin validation](pq-source-guard-dev.log) rejected a stale generated
  inventory hash; [the corrected check](pq-source-guard-dev2.log) retains the
  same unchanged checker and HOLD qualification. A pre-freeze whitespace
  check rejected an extra workflow EOF blank line, corrected before commit.
- [The zero-test selection](frozen-native/frozen-node-cancel-settlement.log)
  had process exit 0 but selected no tests. The
  [required-test guard rejected it](zero-test-selector-rejection.log).
  The [linked inventory](frozen-native/frozen-node-linked-inventory.log)
  supplied the actual Linux module name; the corrected one-test run and
  [named execution verification](corrected-selector-verification.log) passed.
  The zero-test attempt is excluded from 235 passes.
- [Initial all-feature Clippy](frozen-controls/frozen-clippy-all.log) failed
  because the system OpenSSL did not expose the required
  `private_key_from_seed` API. The unchanged repository preparation script
  built its pinned OpenSSL 3.5.9 in an isolated directory and performed actual
  signing, verification and wrong-message rejection. Its
  [provider receipt](provider-preparation/pq-provider/provider.json) and
  [build/smoke log](provider-preparation/pq-provider/build-and-smoke.log)
  are retained. Only the subsequent Clippy command uses that provider; earlier
  default-feature native executions keep their actual build identities.
- Independent reader review found that unknown execve/execveat results could
  inherit an earlier binary binding. The implementation was corrected before
  the frozen commit, with six unknown-result negatives and an explicit
  ENOENT positive control in the nine-method syscall suite. No real trace was
  accepted using the superseded parser.

The final publication source checks remain a separate receipt outside their
own commit, as required by exact source identity. No merge, activation or
relaxation of either service contract is authorized by this record.
