# Final History resource completion and honest-path continuation

This candidate continues PR #688 from
`362fbebe5027d731f16c88f710bfef7e922cd230`, composing the five concurrent commits
through `be0d5f978dc86008115524a6be85c38e03982b33`. It preserves the original deadlines,
Host checks, CPU account, consensus rules, business denominators and failed
observations. Local implementation controls and hosted executions have separate
source identities. Public service, work hardness and release remain unaccepted.

## Implementation changes

### Finish after the last actual resource observation

The inner History importer already fenced successful results after CPU settlement
and epoch close. Three outer page wrappers then performed another original Host
observation and returned the saved result without checking the same deadline.
The new private completion helper keeps that last observation exactly once and
checks the original deadline only after an otherwise successful native result.
The existing error priority is preserved: final resource error, existing native
error, then a newly late successful result. The observed wrapper finishes its
`Final` Host measurement before the time check, so deadline failure is not
misreported as a failed Host measurement.

The four complete sync exits also check the same absolute deadline after their
own last Host observation. Their existing early errors and incomplete final-page
errors retain their original order. There is no new CPU operation, refund, work
retry, authority, rollback or changed stored representation. A durable block and
activation remain facts even when the outward result has become late.

Two new ordinary local controls cover error priority, one final callback, a real
valid import/activation, settled CPU, exact persisted packet identity and cold
reopen. Their delayed resource callback is local test control, not actual fixed
Host provisioning or a public-service qualification run.

### Avoid a discarded wire allocation for a new block

The original header-context encoder validated the packet and copied all wire
bytes before checking whether its block already existed. Only the duplicate
branch used that buffer. Header precheck now invokes the same checked wire-length
and grammar helper at the same position; an existing block still receives full
encoding and byte-for-byte comparison. The legacy and all PQ profile encoders
already begin with the same helpers and perform only fixed-field construction
and copying afterward. Owner fingerprinting and actual persistence encoding
remain unchanged.

The duplicate path performs one extra pure grammar/length check. No timing gain
is claimed. Two small valid signed-transfer controls cover legacy and current PQ
V6 new admission plus exact duplicate. They retain complete wire identity, all
512 transcript tiles, actual M06 execution and persisted state, and require no
repeated W1/M06 on the exact duplicate.

### Distinguish a terminal child from failed acceptance

The native driver retains the top-level v3 receipt, original native invocations,
timeouts, sequential report validators, success predicate and failure exit.
Its new independently versioned `terminal` diagnostics record each child's
observed terminal status, each report validator's actual status, the original
failure, unexecuted later stages and bounded identities of retained report files.
An unvalidated or failed report remains unaccepted. `execution_finished` keeps
its prior full-sequence meaning; its false value is explicitly not a process
liveness observation. A native exit of zero cannot override a failed business
gate. Pure simulated driver controls do not execute the native workloads.

### Preserve the failed request and observe its actual fixture owners

The combined PQ/witness fixture now keeps the original legitimate-send error
while collecting cleanup observations. A worker reaper reports only after its
actual join has returned. A separate owner retains the exact `Child` and its
private directory until observed exit; no PID-only signalling is used. Anonymous
regular files capture child output from spawn, with bounded reads after exit.
An observation timeout or error cannot be reported as a successful reap.

Worker and child cleanup share one ten-second deadline. After recording actual
join/exit facts and checking their original errors, successful completion is
fenced against that same deadline, including an already observed outcome.
`cleanup_complete`, `worker_join_observed` and `child_exit_observed` remain
separate facts. If observation is incomplete, the living owners retain their
temporary directory. This bounds the caller's channel waits and rejects late
success; it does not promise complete reclamation during an arbitrary OS or
filesystem hang.

The original test selector and all its acceptance assertions remain. Two added
controls use only a legitimate Submit: one continues through exact replay and
independent witness restart, and the other exercises cleanup with a local error
sentinel after successful Submit. The sentinel enters no transport and causes
no retry. The original 250 ms witness exchange, ten-second request, thirty-second
service and sixty-second child lifetime are unchanged. These controls do not
establish that the original witness availability failure is fixed.

## Honest-path evidence and elapsed-time correction

[honest-critical-path-readback.json](honest-critical-path-readback.json) is a
read-only derivation of retained C1 observations. The three first rounds last
22.903326238, 22.906293095 and 22.813969019 seconds. Independent client import
uses 20.48–20.64 seconds. Its admission phase uses about 12.90–13.05 seconds,
including about 9.38–9.53 seconds labelled commit; complete-page activation uses
about 5.48–5.50 seconds. Commit includes verification and is not isolated physical
SQLite COMMIT/fsync time. Parent and child phases are not additive.

The [derived elapsed correction](elapsed-time-correction.json) distinguishes
round duration from the approximately 23.81–23.91-second phase-epoch end.
The original hash-pinned summary and all original timestamps stay unchanged.
Host checkpoints belong to their entire import, and Host CPU can aggregate
different invoking threads; it is not an additive or full-worker CPU measure.

The retained C1 counts do not measure the eligible complete-commitment MISS-to-
graph call count or exclusive second-parser cost. They establish no large
improvement. During this continuation, the concurrent `29586a77` commit introduced
a same-call immutable account projection and its own complete-call controls.
That implementation is preserved in the composition and requires its own
execution evidence. No throughput benefit is inferred from the older C1 counts.

## Concurrent composition

The branch advanced through `ed7d45a9`, `bbcb3804`, `29586a77`, `f35ee6dc` and
`be0d5f97` while this work was in progress. Their state merge, inline History
decode, exact-key preparation cache, W1 cache probe, same-call account projection,
History owner release, controls and workflow denominators remain intact. The
three merge conflicts were resolved by retaining the current workflow and its
expanded assertions, all 384 corpus pins and both sets of plan entries, then
refreshing only reviewed changed-file identities. Local results from before
this integration cannot qualify the combined source.

The later concurrent `5a677aae` adds only archival CI readback to an existing
diagnostic workflow. It is preserved byte-for-byte; it changes no runtime source
or corpus binding and supplies no new native acceptance by itself.

## Hosted source 362 readback

The [initial hosted snapshot](hosted-362-readback.json) binds candidate `362fbebe`
and actual merge `b2e6ac4963855d98ebb351072b866742686f43d9` to tree
`5a7a2eadfcfb75b9fdf38fa0e8a05c6a503d776d`. Five downloaded artifact ZIP digests
were independently compared with GitHub's upload digests. They were read as data;
none of their executables or scripts were run for this continuation.

The initial five completed failures are protocol confirmation, the two fresh
service lanes, F0 and the original three-campaign gate. The current F0 has 2/6
original-window confirmations and 0/6 scheduled four-second SLO confirmations;
the original campaign remains 3/27. Historical C1/C2 F0 remains 1/6. Native
process completion, component test success and complete business acceptance stay
separate. These observations do not execute or qualify this new candidate.

The [bounded business readback](hosted-362-business-readback.json) retains JSON
member hashes and exact pointers for those results. F0 observed four of its six
scheduled slots: two confirmed and two did not; the remaining two slots stay in
the denominator without an invented execution result. The campaign observed
twelve of twenty-seven slots: three confirmed and nine did not; fifteen absent
observations retain null outcomes. No four-second campaign SLO is inferred.

### Newly completed original Node failure remains a blocker

The later [source-bound Node terminal](hosted-362-node-head-terminal.json)
retains x64 head job `126300605830`: 950 PASS, one FAILED, 23 original ignored,
zero filtered from the original 974-name registry; native exit 101 after 1196.51
seconds. The [original log](hosted-node-original/node-lib.log.gz),
[command receipt](hosted-node-original/node-lib.json) and
[source receipt](hosted-node-original/source.json) are retained unchanged.

The failed combined PQ/witness control receives `FRAME_EOF` at its first valid
Submit, before replay or independent-process restart. The
[bounded parent phase readback](hosted-362-witness-phase-readback.json) records a
witness CAS transport ending at its original 250 ms exchange limit while the
outer business deadline still has about 9.75 seconds remaining. The child
snapshot is explicitly missing or invalid. Parent flags cannot establish whether
the independent witness had already committed, and do not identify a child CPU,
storage, scheduling or signing cause. This failure is not dismissed as noise or
overridden by the merge lane's successful job metadata.

The [status refresh](hosted-362-status-refresh.json) has its own observation time;
runtime and ARM lanes were still running then. Their unobserved terminal results
are not filled in from C1/C2 or from local selected controls.

### Later runtime terminal identifies an oracle compatibility defect

The [final four-job readback](hosted-362-final-status.json) resolves those old
pending states with actual source receipts. Both ARM Node lanes completed their
974-name registries with 951 PASS, zero FAILED and 23 original ignored; strict
Clippy also exited zero. Both runtime lanes likewise completed the Node library
with 951/0/23. Their later Python storage oracle failed: 28 tests, 15 failures and
nine errors, step exit one. The two
[original head error](hosted-362-runtime-126307454181-oracle-error.json) and
[merge error](hosted-362-runtime-126307453978-oracle-error.json) excerpts retain
`NATIVE_STORAGE_TABLE_NAME`. Multiple nested Rust summaries are not added into
one test count, and these successful Node invocations do not erase the separate
x64 head failure already recorded above.

The oracle first verifies the complete SQLite catalog against source-derived
native DDL, then its row reader incorrectly restricts table identifiers to
letters and underscores. The real `reorg_lifecycle_v1` table therefore passes
the schema contract and is rejected for its numeric version suffix. The fix
allows ASCII digits after the original first letter/underscore. It leaves the
exact catalog comparison, all retained tables, row/byte/column budgets, typed
values and complete state replay unchanged; punctuation and leading digits
remain outside the grammar.

A new independent ordinary SQLite control creates the actual legacy and native
DDL in memory and reads every table, including `reorg_lifecycle_v1` and
`sqlite_sequence`, without changing data. It constructs no Packet or work
certificate and does not inherit the synthetic storage fixture. All 28 original
test methods remain unchanged; the registry is now 29. The one selected ordinary
control passed locally before source freeze. That result is not a new execution
of the complete oracle or runtime lane; their original failed receipts remain.

## Validation and remaining gates

The restored original-profile baseline compiled its 974-name Node registry and
passed the three retained deadline controls. Before concurrent integration, the
first candidate passed twelve selected ordinary Node controls, 68 source-control
tests, 63 simulated driver controls and strict complete-workspace Clippy. The
subsequent fixture build succeeded, but both new legitimate-request controls
failed at independent witness startup: this executor denied `UnixListener::bind`
with `Operation not permitted`, before any Submit. They are not passed, skipped
or substituted. The final cleanup-time fence and concurrent composition still
require their own validation records. A list or `--no-run` build is never
reported as executing the registry.

The [pre-freeze manifest](pre-freeze-validation.json) retains these distinct
scopes and identifies every member of the [raw validation archive](pre-freeze-validation.tar.gz).
It includes both failed fixture attempts and grants no final-composition success.

Work cost/hardness, effective output share across hardware and reuse, independent
operators/evaluators/review, original service capacity, DAA/quantum assumptions,
useful model release evidence, durable custody, economics, irreversible external
effects, whole-chain PQ and release/activation keep their original exit gates.
This continuation does not relabel them as closed.
