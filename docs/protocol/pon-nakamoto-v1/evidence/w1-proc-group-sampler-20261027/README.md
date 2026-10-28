# Optional W1 proving process-group observations — 2026-10-27

This change adds `--sample-proc-group` to the research `measure_step.py` runner.
It does not modify the W1 relation, guest, prover, verifier, security parameters,
receipt policy, production admission or any earlier proof attempt.
The original 1800-second proving timeout remains a timeout with no receipt.
These controls create only short CPU/sleep subprocesses; they generate no proof.

## Usage and limits

From the repository root, use the optional flag for a new long proving attempt:

```sh
python trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/measure_step.py \
  --out "$OUT" --name prove --timeout 5400 --sample-proc-group \
  -- "$HOST" prove "$PROGRAM" "$INPUT" "$RECEIPT"
```

Without the flag, no sampler file or sampler summary is created. With the flag,
`prove.proc-group.jsonl` retains the start observation, observations at roughly
15-second intervals, an observation before timeout termination, and a final
`exit_observed`, `terminated_timeout` or `terminated_runner_error` record.
The corresponding `prove.process.json` contains the last observations and the
sampling summary. Output files are exclusive-create and flushed after each
sample. A missing `/proc` identity is reported as unavailable, not zero cost.
Observation errors do not become successful command outcomes.

The runner creates a fresh session/process group. Numeric `/proc` PID names are
filtered using `getpgid` and `getsid` before process resource files are read,
including the initial leader and subsequent leader checks. Resource reads use
only `stat` and `status`; neither command lines nor process environments are
read. PID plus start ticks identifies each observed process. New identities
require the original leader identity to remain live before and after discovery;
known identities can retain their final actual observations after leader exit.
This is best-effort non-atomic observation, with identity checks around resource
reads, not a kernel accounting or isolation facility.

For CPU, only each distinct identity's maximum observed **own** user/system ticks
is counted. Child CPU fields are excluded, and successive samples are not added
again. This is a **sampling lower bound**: short-lived processes, escaped process
groups, processes first seen after leader exit and work after the final sample
can be missed. The identity cap is 4096 and any truncation is explicit. Exit does
not replace previously observed values with synthetic zeros or full accounting.

Sampled RSS sums can count shared pages more than once, are not simultaneous
physical-memory measurements, and can miss between-sample peaks. They are **not
physical peak memory**. Each process's `VmHWM` is retained separately and is not
summed. The pre-existing `RUSAGE_CHILDREN` fields remain separate observations:
when a timed-out parent and grandchild are terminated together, they need not
include the grandchild's CPU. Neither field set certifies a consensus cost bound.

## Actual controls and preserved failures

All raw command outputs, process JSON, sampler JSONL, unit-test logs and source
hashes below are retained. Directory names describe stages; `committed-controls`
was executed before this commit and binds its three exact source files by SHA256.

| Observation directory | Actual result | Interpretation |
| --- | --- | --- |
| `sandbox-control` | 1 control, 1 failure | Child PID namespace did not match the mounted `/proc`; identity unavailable. This is a retained environment failure. |
| `native-controls` | 6 controls, 1 failure | First discovery implementation depended on `/proc/PID/task/TID/children`, absent on this kernel; grandchild was missed. Exact old sources are retained in `source-before-discovery-fix`. |
| `final-controls` | 6 controls, 1 failure | Group/session discovery observed the grandchild, but the control incorrectly required user CPU alone; worker CPU included system time. Exact old sources are retained in `source-before-control-fix`. |
| `verified-controls` | 6 controls pass, 16.556150 s | Self user plus system CPU control passes; resource source hashes and raw observations retained. |
| `committed-controls` | **6 controls pass, 16.347788 s** | Final leader prefilter boundary, parser, ownership, PID reuse, unavailable identity, default/normal exit and real grandchild timeout controls pass. Source hashes match this change. |

The final actual timeout control returned 124 after 16.003697 seconds. It observed
two distinct process identities, a periodic record, and a final termination
record. The observed self CPU lower bounds were 0.07 seconds user plus 0.06 seconds
system, or **0.13 seconds**. The separate waited-family observations were
0.023597 seconds user plus 0.009951 seconds system, or **0.033548 seconds**. This
difference demonstrates why timeout evidence should retain both observations;
it is not a completeness claim or a proof throughput result. The maximum sampled
RSS sum was 15,204,352 bytes, subject to the memory limitations above.

The parser control includes process names containing parentheses and newlines,
large child-CPU fields that must be ignored, malformed/truncated statistics and
unavailable high-water marks. Ownership/PID controls reject foreign groups and
reused identities, retain last observed values, and avoid repeated-sample CPU
double counting. Actual subprocess controls run in the authorized native PID
namespace, where child PIDs match `/proc`. They preserve the optional default
path and exercise the 15-second periodic observation before a 16-second timeout.

Reproduce the six controls on Linux with a matching process namespace:

```sh
cd trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0
python -m unittest test_proc_group_sampler -v
```

`artifact-hashes.json` records the retained evidence bytes. No historical source,
failed observation or original proving result is rewritten by this change.
