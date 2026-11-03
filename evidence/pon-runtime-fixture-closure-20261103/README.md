# Runtime fixture and committed-CAS continuation — 2026-11-03

**DRAFT / HOLD.** This continuation fixes concrete native and fixture failures,
retains the original business failures, and does not claim all-blocker closure.
The original Host limits, service/request deadlines, complete W1, nonce,
liabilities, recovery and independent confirmation conditions remain required.

## Committed CAS and late live use

A real witness COMMIT can cross its original deadline after the last pre-COMMIT
check. Previously, `ServiceFinal` then discarded the fully signed successor
receipt. The local owner could not align its already committed external outcome.
The CAS path now preserves that receipt after successful commit, storage
readback, signing and self-verification. Current retains its deadline refusal;
`serve_one` and `write_until` retain their original absolute connection deadline.
An authenticated late CAS permits exact local reconciliation, followed by refusal
of late live use. It creates no new authorization interval or transport budget.

The [old-production counterexample](pq-original-final-failure.log) uses an actual
SQLite commit hook with the original 200 ms boundary. It fails with
`PQ_WITNESS_DEADLINE` at `service_final` after `cas_committed=true`. The corrected
control returns `LIVE_DEADLINE`, keeps 61 charged bytes and matching local/witness
checkpoints, then completes the original one-byte follow-up and cold reopens at
62 bytes. Three complementary controls retain pre-COMMIT rollback, late Current
refusal and late-CAS socket-write refusal. The last uses a real Unix stream pair;
it does not qualify Unix listener creation or WAN transport.

The concurrent pre-CAS consistency guard remains before signing and transport.
The later published `8a74a9e` control distinguishes the observed client's local
`PQ_WITNESS_OBSERVATION_ROLLBACK` refusal from a fresh, unobserved client's real
owner `PQ_WITNESS_CAS` refusal. It checks both persistent heads and keeps the
observed client usable. That complete test extension is preserved. The temporary
local error-category compatibility candidate is withdrawn; its earlier failures
and passing observations remain source-bound history in the
[PQ and History execution record](pq-and-history-controls.json). No production
error-category change is retained in the final candidate.

## History completion evidence

The concurrent History change checks the original deadline after mandatory CPU
settlement and epoch closure. Only a previously successful result changes into a
late-success refusal; cleanup and original native errors retain their priority.
All 25 meaningful controls in that module pass, with its one original ignored
child entry retained, including all three new deadline controls.

The bounded green phase ring retains the final `LIVE_DEADLINE` and local COMMIT
marks. Its later client/service CAS rows are the subsequent one-byte charge,
not a complete retained trace of the earlier late service COMMIT.

Those controls expire before cleanup. They do not independently inject expiry
only inside cleanup, and the final alive check is cooperative rather than
preemption of a blocking call. Exact completion identity is scoped to the live
CPU owner. The cold-reopen control follows exact retry; it does not independently
prove the activation's durable state immediately after the earlier error.

## Original fixtures under an actual fixed Host

Nine declared public integration selectors require the original kernel Host for
client import. Their new adapter launches the **current libtest ELF** and, where
required, the CLI ELF compiled into that test, under the existing fixed-parent
controller. It invokes no nested Cargo. It binds source/tree/job, ELF hashes and
inodes, actual parent process identities, original native working directory and
both live owner pidfds. A marker alone cannot authorize execution: the native
child still runs the original kernel checks and every original test assertion.

The signed-DAG selector retains its 120-second bound, 18 complete samples,
original predicate and separate business reader. The other eight selectors keep
their own original lifetimes; they do not inherit a new common 120-second cutoff.
Owner exit terminates and reaps the owned native process group. Timeout, native
failure, missing report or uncertain cleanup cannot become a pass. The bounded
failure diagnostics added concurrently remain after complete timing and report
persistence.

The existing required workflow and `ci_job.sh` already set `RUST_TEST_THREADS=1`.
The fixed parent has one nonblocking, root-owned lock independent of receipts
paths. Concurrent ownership is refused; there is no lock wait or native retry.
A root-owned create-once lease seals the first real provision. Only the exact
public-fixture mode may reuse it after checking current source/job/caller,
receipt context, seal/mirror identity, boot ID, cgroup and unit identity, all
original limits, systemd configuration and an empty prior child group. The old
from-zero, fresh-service and History modes still refuse a preexisting parent.
Only this invocation's child service is cleaned up; the shared parent is not
stopped, deleted or reconfigured. Independent static review found and caused the
cross-receipts lock-identity correction before publication.

Actual hosted execution remains required. Local mocked controller controls,
process-lifecycle tests, compilation and marker-refusal controls cannot certify
that the nine positive selectors pass in the original Host.

The formatter's temporary source copy now includes the original nested
`public_v3_from_zero/fresh_challenge.rs` module. Missing input fails before child
execution. The retained formatter failure was separate from the already observed
`CONFIRMATION_TARGET` acceptance failure; correcting the copy does not change
that original service verdict.

## Paid pinned-peer fixture

The original test failed after 10.1185 seconds waiting for its local service
account. The first fixture correction exposed a second real refusal,
`OWNER_REORG_TERMINATION_CPU_REQUIRED`; both failures are retained. The completed
fixture starts the same Node's actual V3 service, prepares the fork before
service startup, and publishes it through the public metered Submit entry with
the existing remote domain and real termination checkpoint. It verifies paid
CPU and the actual returned block/active tip. It stops and joins the old local
service before cold reopen and starts the next service with the original domain.

The [actual paid positive](pinned-peer-actual-paid-pass.json) passes in 0.7609
seconds of observed process wall time. The original 30-second polling runtime,
10-second owner-binding wait, 2-second request policy, ten calls, eleven response
frames and all 34 original assertions remain. This is one local paid TCP/native
recovery control, not a multi-host or public-service acceptance campaign.

## Full Node and source scopes

The [terminal readback](full-node-terminal-readback.json) accounts for all 971
registered entries: **947 passed, 1 failed, 23 originally ignored**, in 1,451.803
seconds without supervisor timeout. Both original 65,536-account continuity
controls pass. The [failure](full-node-original-failure.log) is the independent
witness-process selector: this executor refuses `UnixListener::bind` with EPERM
before ready, transport or CAS. It remains a failed test, with no bypass or
retry. The original 43 separately selected PQ controls likewise retain 42 passes
and that one environment refusal. Six new/pre-CAS controls and four observer
controls pass separately.

The first local line parser missed four identities because child-process stdout
interrupts ordinary libtest announcement lines. A separate readback of the same
unchanged raw log uses libtest's terminal success/failure lists and original
ignored announcements, checks disjoint sets against every registered name and
matches the final 947/1/23 summary. It does not rerun the native suite or overwrite
the preliminary parser record. Stdout parsing is an execution receipt, not an
independent authentication oracle.

The library build records retain their compiled source manifests and ELF hashes.
The pinned-peer receipts retain the exact test-file hash, build command and ELF
hash; they do not independently inventory the whole source tree at those runs.
The first composed selector record likewise retains its actual per-test outcomes
and logs without upgrading that subset to final-tree qualification. The library
suite preceded later integration-fixture/diagnostic composition. Two
library modules embed the complete source inventory, so these fixture changes
also change the library ELF. The final combined build and full-suite execution
are recorded separately. Earlier native
observations are not relabeled as a different executable or hosted source.

## Original business and scientific gates remain open

The [retained hosted readback](hosted-original-readback.json) identifies its exact
`116a3caf` / actual prospective-merge source and separate initial-status and
supplemental artifact-readback timestamps. In that source,
the pressure four-second confirmations remain 0/1, F0 remains 1/6 in thirty
seconds and 0/6 in four seconds, and the three original native campaigns confirm
3/27 planned transactions. Missing rounds, failed requests and cancellations
stay in their original denominators.

The F0 baseline client graph/Host/caller CPU scopes overlap and must not be added
or divided into an exact attribution. The separate ROOT phase never imports:
its actual honest grant median is about 1.212 seconds and paid-queue median about
0.409 seconds inside the original two-second request policy. These measurements
motivate separate server and importer work; they do not establish a speedup from
this fixture or CAS change.

No cross-write graph cache, live authorization cache, larger Host allocation,
longer confirmation deadline, PQ aggregation assumption or successful stub is
introduced. Original public-service, cheapest-legal-work and rejection economics,
heterogeneous/quantum assumptions, independent operators/security/model evidence,
custody, external effects, whole-chain PQ and activation remain under their
original exit conditions. This record belongs to the existing sole development
plan and existing Draft PR.

## Prior validation snapshot and final composition

[Validation records](validation.json) and the
[changed-source identity](candidate-source-files.json) bind the actual tested candidate
source. The `3898`-based original test-profile build, formatting, strict complete
workspace/all-target/all-feature Clippy and 255 source/CI/claim controls pass.
The 376-pin checker remains `HOLD_NO_GO`. Main default/all-feature Linux locked
graphs and the separate `tests/fuzz` Linux graph pass; the first mistyped fuzz
manifest path and its failure remain in the record. The actual original DAG
negative control passes, while the new child marker without a real Host is
correctly refused. That candidate's final 971-entry Node suite was interrupted by loss of its executor before
a terminal result. Its incomplete log and UNKNOWN outcome are retained; it is
not replaced by the earlier different-ELF result. Restored native/config files
match the compiled manifest. A fresh combined execution is required.

Reproduction uses the repository's pinned compiler/provider and original
profiles. Commands are retained verbatim in `validation.json`. The existing CI
entrypoint `python3 scripts/ci/test_from_zero_host_ci.py` executes all 78 Host
adapter/lease/process controls; `python3 scripts/ci/test_run_from_zero_native.py`
executes the 104 formatter/driver controls. Native positive fixed-Host execution
is restricted to the already defined hosted job and source context. No local
workstation provisioning or fabricated CI environment is part of reproduction.

The [later original-job status supplement](hosted-completion-supplement.json)
records all four `116a3caf` PQ/full-library/Clippy jobs and original workspace
test-profile CPU jobs as successful in GitHub. It is a job/step status readback,
not a new native-log count, and does not qualify this new source.

The final source additionally preserves the subsequent published `8a74a9e`
local/owner CAS test split. Its temporary preflight error-code compatibility
change is removed, and all three affected corpus pins bind the real combined
files. The earlier `3898` source/ELF observations are retained without relabeling.
Fresh build, strict checks and native execution for this final composition are
recorded independently; the executor interruption is not a passing full run.
