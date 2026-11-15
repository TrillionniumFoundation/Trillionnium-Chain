# Prospective W1 collector: retained process controls

This folder contains actual finite-process observations for the new collector. No
control generated a W1 proof, changed an existing owner operation, released a
resource cap, or authorized payment. GPU usage remains unknown. The raw directories
are an explicit allowlist of process records, logs, target request/readback and
control payloads; intentionally malformed JSON copies and SQLite internals are
excluded.

## Source and verification

The isolated commit is `6e8f3be3f1ea9e715020926b47b2c457b6504aa6`, based on
`abab79dac0cb89eb2753d3f579119ac135650eb5`. It contains only
`scripts/w1_owned_process_collector_v1.py` and
`scripts/test_w1_owned_process_collector_v1.py`.

The implementation SHA-256 is
`e250f1a75794c35d9583e55e56f159366b5d15fa13118d7a142d10a38fd6394f`.
The final test SHA-256 is
`2d9912f9bd4dfe7f708a5b9125e7ce72e7cbe7396be2aad1119401d136db0b8d`.
The 14-test full runs used the preceding test bytes
`7ad0296617f6d5aaf46e8e3ca8a099ea6910e7966113448d41a70aa03632ea06`.
The only subsequent test change is the cancellation control's startup-marker
wait from 3 seconds to 5 seconds. Its original command deadline remains 5 seconds.
The implementation bytes and every retained old declaration are unchanged.

Run the mandatory controls with:

```sh
python3 scripts/test_w1_owned_process_collector_v1.py -v
```

| Observation | Result | Retained evidence |
| --- | --- | --- |
| Initial local controls | 11 of 13 passed; two cleanup controls failed | `local/collector-controls-local-01` |
| Final local full controls | 14 of 14 passed in 3.407 seconds | `local/collector-controls-local-03` |
| Initial desktop full controls | 13 of 14 passed; cancellation startup marker exceeded 3 seconds | `desktop/collector-controls-desktop-ec265-01` |
| Independent integrated desktop full controls | 14 of 14 passed in 10.354 seconds | `root-independent-controls.stdout.log`, `root-independent-controls.stderr.log` |
| Desktop cancellation control after the test-only wait change | 1 of 1 passed in 1.825 seconds | `desktop/collector-controls-desktop-ec265-02` |

Authoritative terminal metadata is in `runtime-terminals.json`. The full-suite
integrated desktop job is `1a1b9581043-12894-138d`; it exited 0 and published complete,
durable logs. The initial desktop job is `1a1b94cec42-12894-1349`; its exit 1 remains
retained. The targeted follow-up/commit job is `1a1b95aac34-12894-13a2`; it exited 0.

## Failures retained and the limited corrections

The first local run found that this cloud kernel does not expose
`/proc/<pid>/task/<tid>/children`. The collector had no way to discover a still-live,
detached grandchild for cancellation. It truthfully retained missing ECHILD and
cleanup uncertainty. The implementation now declares either `task-children` or
`bounded-proc-stat-index` in its original intent. In the latter mode it indexes
bounded process metadata and validates ancestry and PID birth identity before
holding a pidfd. It signals only those bound descendant handles.

The initial desktop cancellation case retained an intent and its first event,
but no `root-created` or `root-exec-released` event. The 3-second control-side marker
wait ended, its test teardown sent SIGTERM, and the collector rejected its
pre-exec gate with `owner/deadline/cancel pre-exec gate failed`. The payload did not
start. Increasing only that control-side wait to 5 seconds avoids the earlier test
cutoff; the independent command deadline still rejects late execution. No old
failed run was overwritten or reclassified.

## Ownership and actual target chain

The collector is a new executable process. It sets and reads back
`PR_SET_CHILD_SUBREAPER`, verifies a single thread and an initially empty wait
domain, and owns one fork/exec root. The caller remains the owner of its `Popen`
handle for the collector. Existing `Popen` objects inside the wrapped owner or
worker retain their own direct children and statuses.

For the retained target-chain control, the arrangement is:

1. The caller test process starts the collector in the existing outer job cgroup.
2. The collector starts the real `w1_generation_target_v2.py dispatch` command.
3. Dispatch starts the original target `_worker`; that worker starts `_exec`.
4. The real target's `_exec` executes the pinned finite payload. The worker reaps
   its direct child. Once dispatch exits, the collector adopts and reaps the
   worker. The target's own original `all_descendants_reaped: null` is preserved.

This target control uses the target's explicit `process-group-research` mode; it
does not fabricate dedicated cgroup ownership. Actual outer cgroup snapshots are
retained separately. In a prospective delegated-cgroup target run, the collector
and dispatch/worker remain in the outer job cgroup while the original `_exec`
enters the target-created child cgroup. The collector does not rewrite that
configuration, migrate unrelated processes, or turn shared counters into bills.

A root that exits before its descendants is not completion. The collector keeps
waiting for adopted children under the original deadline. Cancellation, owner
loss or deadline exhaustion starts a bounded TERM/KILL cleanup through pidfds.
The original root exit/signal is retained separately from an intervention's
wrapper exit code. The controls preserve an internal Popen exit 37, root exit 23,
and an outside sibling exit 29. A natural root signal is mirrored to the caller.

## Callable interface

Use a new output directory and the already declared deadline and boot identity:

```text
python3 scripts/w1_owned_process_collector_v1.py
  --out /absolute/new-collector-output
  --deadline-monotonic-ns ORIGINAL_ABSOLUTE_DEADLINE_NS
  --deadline-boot-id ORIGINAL_LINUX_BOOT_ID
  --cleanup-grace-seconds 2
  --cwd /absolute/repository
  --executable-sha256 SHA256_OF_THE_RESOLVED_PYTHON_ELF
  -- /usr/bin/python3.12 /absolute/repository/scripts/w1_generation_target_v2.py
     dispatch --root /absolute/new-target-state --target NEW_TARGET_ID
     --request /absolute/new-request.json
```

Arguments after `--` are executed as argv, never as shell text. Direct shebang
scripts are explicitly rejected; use the pinned real Python ELF to run Python
scripts. Inherited nonstandard descriptors are closed and target stdout/stderr
are drained into bounded files. A FIFO supplied as an input record or executable
is rejected without waiting for a writer.

The caller must retain its actual `Popen` result and original-clock completion:

```python
observed = read_result(
    collector_directory,
    observed_returncode=process.returncode,
    observed_boot_id=original_boot_id,
    observed_completed_monotonic_ns=actual_parent_completion_ns,
    expected_intent_sha256=previously_retained_intent_sha256,
)
```

Without actual terminal status, the reader returns UNKNOWN. Without the caller's
same-clock completion time, command deadline qualification remains false. If the
collector is killed with SIGKILL, a missing final record remains UNKNOWN even if
another process subsequently reaps the orphan. Strict UTF-8, finite numbers,
exact boolean/integer types, raw-log hashes, event order, root birth identity,
waitid/wait4 status agreement and final ECHILD are checked before accepting the
limited observation.

Do not put a collector with the proof's deadline around an entire Rust/M12 owner
that still needs to perform refund/reorganization work after that deadline. Its
cleanup would also stop that owner. The tested interface wraps the fresh target
execution chain; business-owner reconciliation remains outside it.

## Limits that remain explicit

`collector_wait_domain_reaped` only concerns the surviving collector's owned and
adopted waitable children in this invocation. It does not enumerate every child
that an intermediate parent already reaped, certify the full historical process
tree, or form an adversarial sandbox. An external ptracer, hostile owner, or
exported process handles are not security-qualified by this collector.

An empty cgroup is not a substitute for wait/reap. Shared cgroup CPU counters must
not be added to the wait4 records, whose resource values can already include
children reaped by the waited process. RSS is not a simultaneous tree peak.
`gpu_ns` stays null, `resource_billing_complete` stays false and
`can_authorize_payment` stays false in every control.

The relevant kernel semantics are documented in the Linux man-pages for
[PR_SET_CHILD_SUBREAPER](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[wait/waitid](https://man7.org/linux/man-pages/man2/wait.2.html),
[pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and the
[kernel cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## Archive

The raw directories and per-file hashes referenced above are retained in [collector-controls.tar.gz](collector-controls.tar.gz), SHA256 `56b4ef357ca4006f10bfbcfd3690a79dca845c58f1a06736d5a5e22fa84696d0` (97,717 bytes). Extract into a new directory to inspect the relative paths. This archive preserves the control history; the later exact-source qualification records the final integrated test run.
