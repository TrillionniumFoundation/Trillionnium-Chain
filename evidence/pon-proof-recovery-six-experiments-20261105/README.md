# Experiment 5 and 6: proof costs and uncertain trial reconciliation

These are separate acceptance conclusions. This increment derives costs from the
archived complete W1 v2 observation and adds a real durable-ledger recovery path.
It does not run a new succinct proof, activate a model, or certify an installed
next-generation task.

## Experiment 5 — complete proof backend

**The observed W1 v2 proof does not beat native full W1 recomputation.** Full Cell
proof coverage and lowest-node delivery economics remain open.

The existing `w1_full_staged_run.py` now emits `observed_cost_comparison` only after
a complete v2 observation. It checks the exact image/profile, sample counts,
receipt/artifact binding, transferred bytes, receiver digest and equal offered
rates. Failed/incomplete observations cannot emit a comparison. Reusing one
receipt 100 times remains one independent proof trial. A faster verification
sample still cannot set the minimum-node, full-delivery or production gates.

[proof-comparison.json](proof-comparison.json) is a new arithmetic readback of the
[archived complete result](../pon-w1-full-v2-20261105/proof-result.json), not a new
cryptographic verification. Its derivation records the original bytes and source
SHA-256 values.

| Observation | Native complete W1 | Succinct complete W1 v2 |
| --- | ---: | ---: |
| Replay samples | 1,000 native executions | 100 reuses of one receipt |
| Verification median | 0.9549835 ms | 28.8823595 ms |
| Body bytes | 49,188 | 257,014 |
| Local envelope bytes | 49,603 | 257,429 |
| Loopback send/receive/durable write at 1,000,000 B/s | 0.051178386 s | 0.259438411 s |
| Envelope encoding | 0.024401 ms | 0.701264 ms |
| Durable local file write | 1.211276 ms | 1.699299 ms |

The receipt path is **30.243831 times** the native verification median,
**5.189787 times** the envelope bytes and **5.069296 times** the observed loopback
time. The archived fresh proof pipeline takes 6,248.484107 seconds; initial input
to verified local delivery takes 6,248.950041 seconds. The successful controller
observation totals 6,253.711474 seconds. Its new stages record 44,039.733324 user
CPU seconds and 358.916421 system CPU seconds; this is observed `wait4` accounting,
not complete accounting for every descendant or a measured aggregate peak RSS.

The [earlier 7,200-second failure](../pon-w1-v2-deadline-20261105/summary.json)
remains a separate failed observation: 7,200.081220 observed seconds, 43 successful
segments, no final succinct receipt and zero executed saved-receipt controls. The
two retained controller observations sum to 13,453.792694 seconds. That sum is
not a probability estimate, a p99 claim, or a fair expected-cost estimate across
randomized independent trials.

The complete relation here is **W1 v2**. It does not prove the whole Cell encoder,
mask, routing and state transition. Build/setup, aggregate process-tree peak
memory, failures across a representative trial population, queueing, WAN,
production Node admission and independent confirmation remain unmeasured. A
minimum-node configuration was not measured by these archived records.

The independent verifier's normal path decodes the bounded receipt and uses the
fixed image with public-journal and cryptographic checks; failures propagate.
Native recomputation is an explicit `--native` benchmark invocation, not an
error fallback. This increment changes no cryptographic acceptance or fallback.

## Experiment 6 — automatic adoption and recovery

**The durable trial ledger now has precise readback for an uncertain operation;
real installed-generation recovery remains unproven.**

`TrialLedger.reconcile(trial, expected_plan, minimum_checkpoint)` replays the
existing immutable event history under the existing SQLite transaction and binds
all three caller inputs. The current history may extend the retained checkpoint;
it must still contain it. A database restored before that checkpoint is rejected.
A reused trial with another plan is rejected. The output names the committed
trial events, child receipt hashes, frozen roster hash and terminal record hash.
It never writes another event, refunds allowance or authorizes replay.

The existing pilot CLI exposes the same operation:

```sh
python3 scripts/llm_runtime_pilot.py trial-ledger-reconcile \
  --ledger EXISTING_AUTHORITY.sqlite3 --policy POLICY_SHA256 \
  --trial ORIGINAL_TRIAL_SHA256 --plan ORIGINAL_REGISTERED_PLAN_SHA256 \
  --minimum-checkpoint EXTERNALLY_RETAINED_CHECKPOINT_SHA256
```

Ledger-only commands can now run with just the pilot and ledger source files;
parsing a historical readback no longer imports today's model/parent-step/native
backend dependency graph. The isolated two-file CLI control uses a real SQLite
ledger and a real subprocess.

A missing reservation is reported as `not-observed`, with external effects still
`UNKNOWN`. It is not proof that an external operation never happened. The
checkpoint must be retained outside a rollback domain. Restoring both the
SQLite database and its caller-held old checkpoint remains an explicit
counterexample outside this local guarantee. No stored event format or policy
namespace is reinterpreted, and no existing allowance is increased.

The control suite covers real committed debit with lost ACK; real process exit
after debit; rollback before COMMIT; stale restored database; a later unrelated
trial extending the original checkpoint; wrong plan; corrupt history; and
historical reads with no current model dependencies. Uncertain observations
retain `retry_authorized=false`, `refund_authorized=false`,
`installation_verified=false` and `final_use_verified=false`.

This does not bridge CURRENT, FinalUse, protected executable installation,
revocation/reorganization or actual next-task readback. Those require the same
native source combination and a real installed run. The existing exhausted
model campaign remains exhausted; these SQLite fixtures are not additional
model experiments.

## Reproduction and scope

[validation.json](validation.json) records exact source SHA-256 values and the
commands for **78 passing tests**: 24 trial-ledger, 20 immutable-history replay,
and 34 staged proof-observer tests. Logs are retained beside it. Proof parser
and arithmetic fixtures are explicitly controls, never fake proof evidence.
The existing observer suite also exercises actual local TCP byte transfer and
process timeout/cleanup. Cargo/rustc/r0vm and a configured native model daemon
are unavailable in this executor, so no new Rust, proof-generation or installed
model acceptance is claimed.

To reproduce the archived arithmetic without running a proof:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=formal/pon-nakamoto-v1/experiments python3 - <<'PY'
import json
from pathlib import Path
from w1_full_staged_run import read_json, observed_cost_comparison
source = Path('evidence/pon-w1-full-v2-20261105/proof-result.json')
print(json.dumps(observed_cost_comparison(read_json(source)), indent=2, sort_keys=True))
PY
```
