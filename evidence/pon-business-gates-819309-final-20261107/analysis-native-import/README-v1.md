# Actual 819 native import / Host readback

This is a read-only derivation from the two original Actions reports identified in native-import-core-v1.json. It runs no native code, benchmark, profiling workload, or business harness. The source remains frozen at 819309fd312298e099642e1253b1d4ba07113e98. All 21 replay rows are retained: 20 accepted and one PUBLIC_REQUEST_DEADLINE. This analysis does not qualify either original business gate.

## Accounting boundaries

The outer independent_replay_and_confirmation_cpu_ns timer begins before the History network loop (tests/public_v3_from_zero.rs:1430-1431, ends1516). It includes caller work in network calls, JSON conversion/records, each independent replay and final confirmation. Therefore fresh baseline 542.515822 ms is not the sum of seven replay rows: those sum to 534.997037 ms. Pre-service acquisition 37.715309 ms measures all process threads over a different interval and different work. Subtracting these numbers cannot identify root computation, locks, or verification overhead.

Each row's replay_thread_cpu_ns is caller-thread CPU, not whole-process/receiver/worker CPU. Native page history_import contains the packet history_import; packet work and admission sit within that packet interval. admission contains admission_prepare, execution and commit. root_commitment is a child of execution. Final activation is the last complete packet's submit_result. Host checkpoint spans intersect these phases and CPU refill checks; resolve, initial and final Host spans are outside native import but inside client replay. Never add inclusive parent and child CPU, or add Host CPU to the phases that include it.

The original flags remain true for cpu_intervals_are_nested_not_additive, host_checks_are_nested_not_additive, phase_cpu_excludes_scoped_workers and host_cpu_includes_each_calling_thread; host_cpu_is_full_worker_cpu and observation_has_consensus_authority remain false. In this specific common fixture the independent Node is opened with workers=1 (public_v3_from_zero.rs:1277-1286); M06's count<=1 branch runs on that caller (pon_executor.rs:3027-3033), and W1's FullLimb verifier is synchronous. This supports comparing the Host checkpoint magnitude with the importer caller CPU here; it does not turn either diagnostic into complete worker/process CPU or a general multiworker accounting rule.

## Measured CPU (milliseconds; columns overlap)

| Original report / phase | Replay rows | Caller replay | Host checkpoint | Packet Work | Admission | Commit within admission | M06 root within execution |
|---|---:|---:|---:|---:|---:|---:|---:|
| fresh H fresh / baseline | 7 accepted | 534.997037 | 474.142861 | 432.661929 | 57.194996 | 36.736624 | 1.203437 |
| fresh H fresh / pressure | 1 accepted | 85.559084 | 78.222604 | 75.300652 | 6.023900 | 3.811870 | 0.277990 |
| service x64 M / baseline | 7 accepted | 413.636870 | 368.123867 | 333.344715 | 45.077209 | 29.926809 | 0.856879 |
| service x64 M / pressure | 5 accepted + 1 deadline | 326.423472 | 297.271034 | 279.826748 | 27.153673 | 17.733225 | 0.596781 |

Checkpoint counts in the same order are 8,734 / 1,185 / 8,765 / 6,825. The corresponding observed CPU per invocation is about 54.29 / 66.01 / 42.00 / 43.56 microseconds. All recorded Host calls completed and accepted, all Host clock-unknown counts and all native measurement_failures are zero. Host rejection is not the cause shown by these records. The deadline failure can occur in Control::alive before the next Host observation.

Work is the largest stage, and live Host checking is the largest measured nested component over the importer. Work is full PNW1 plus original progress/Host/CPU checks, not isolated matrix/transcript arithmetic. Host aggregates have no per-stage attribution, so the reports do not give an exact split of pure W1 arithmetic versus Host time within Work. SQL, full-State reconstruction, root verification, SQLite persistence and Host checks remain combined in commit/admission preparation. root_commitment measures the executor's BeforeCommitment-to-AfterCommitment interval only; it does not measure all historical roots or the final persisted active-State fence.

Fresh pressure's only imported page runs from 2.459026970 to 3.858738888 s: 1.399711918 s wall, 85.559084 ms caller CPU. Its page cpu_wait is 399.142797 ms wall / 2.074946 ms CPU; Work 807.756858 / 75.300652 ms; admission 96.367990 / 6.023900 ms. These are not independent additions to enclosing history_import. No activation ran. The following RPC failed without another importer invocation.

Service pressure's last replay remains included: 3.733988302 to 4.031969218 s, 34.785871 ms caller CPU, 724 Host checkpoints / 32.410169 ms. Work returns PUBLIC_REQUEST_DEADLINE after 32.923002 ms CPU. admission, commit, root_commitment and activation were never entered for that packet. The proposed final-admission-root optimization would not execute on this failed packet; any earlier-page effect must be measured separately.

The observed importer uses Owner::Exclusive (ingress.rs:2597-2598); context_owner_wait, admission_owner_wait and commit_owner_wait are unentered in all 21 rows. The data therefore do not attribute their long walls to the shared Node mutex. The explicit cpu_wait phase is the original reservation/refill wait. Other wall-minus-caller-CPU remains unassigned: it can include kernel throttling/scheduling, I/O and waits, and cannot be labelled lock time or whole-worker CPU.

## Once-per-check source audit

At host_kernel_parent.rs:336-361, one KernelBudget::check performs, in order:

1. One fresh complete boot_id read, then comparison with the bound boot.
2. One symlink_metadata of the actual parent path, checking directory type, root owner, nondelegated write permissions and device/inode identity.
3. One fresh complete /proc/thread-self/cgroup read and current calling-thread membership validation.
4. One fresh complete read of each of cpu.max, cpu.max.burst, memory.max, memory.swap.max and pids.max, followed by all-five syntax/limit validation and exact comparison.

There is no duplicate live-file read inside this check. Five immutable path spellings are already retained; dynamic values and verdicts are not. Limit reads use bounded 129-byte stack buffers; boot/membership use a 257-byte common stack path and continue the same live stream on the original heap path for longer input. Membership parsing borrows the complete current text. canonicalize and initial setup reads belong to resolve, not each checkpoint. cpu.stat/resource_sample is not part of this checkpoint path.

On the usual successful short-file path, each of seven complete fresh reads needs a data read and an EOF read, in addition to open/close; parent metadata is separate. This is source-level operation accounting, not a syscall trace or a measured subdivision. The second read is not redundant: a short read is not EOF. The current code already avoids per-check path joins, normal-path heap Strings and file-size metadata reads.

No substantial safe same-check duplicate-read/parse removal was found. Reusing open descriptors alone would read stale objects after same-path replacement; retaining a parent descriptor also needs current path-to-inode binding, current boot/thread membership and all current limits. Shared descriptors additionally require correct seek/EOF behavior and independent concurrent offsets. These requirements cannot be replaced by a prior authorized result or by fewer checks. Adding those guards may remove the hoped-for savings, and these reports contain no evidence that an fd design improves the actual complete check.

The narrowly scoped final active-State root arithmetic proposal remains a separate correctness/performance experiment inside commit, not a demonstrated remedy for the dominant Host cost. Its whole-path benefit is unknown, including one-entry cache churn. Do not infer a saving from the M06 root_commitment column or remove any full-State/SQL/fence obligation.

## Required counterexamples for any later Host-reader design

Preserve every original checkpoint and failure order, boot changes, parent symlink/ownership/mode/inode replacement, current worker migration while its process leader stays put, each changed/missing/unreadable live limit, malformed/oversized/invalid UTF-8/short/EINTR reads, complete EOF and long-context continuation. Preserve late I/O-before-earlier-parse rejection, cancellation/deadline ordering and all failed cost accounting. Any fd experiment must explicitly test file replacement and concurrent read offsets. No such implementation, experiment or new performance test was performed here.
