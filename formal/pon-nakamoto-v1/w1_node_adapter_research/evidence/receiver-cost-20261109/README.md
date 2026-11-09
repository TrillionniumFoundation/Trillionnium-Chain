# W1 receiver costs: completed comparisons, failed deadline gate

**HOLD_NO_GO.** Both two-CPU comparisons completed and show that proof-plus-native
reception costs substantially more than native reception. Under the quarter-CPU,
four-second profile, **all four proof receivers timed out in each CI run**.
The [push workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42629992145)
and [PR workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42630053802)
both concluded **FAILURE**. Their two-CPU comparison `PASS` records successful
measurement completion; their quarter-CPU failure remains a failed gate.
[Push observation](hosted/push/hosted-observation.json);
[PR observation](hosted/pr/hosted-observation.json).

This continuation starts from `e2a02f9271b49f146e70806c8a66e161b5973971` (#835).
It establishes a matched development-Node receiver baseline. It does not replace
native replay, activate production, or establish end-to-end benefit.

## Experiment and identity

`N` runs `native-admit`: independently bind the operator plan and packet, open a
fresh Node, admit through the existing native path, activate, and read back exact
storage and current chain membership. `P` runs `exercise`: reserve a durable proof
start, bind and persist the bundle, verify both real STARKs, then perform the real
Node admission, activation, and readback. Production validation remains intact.

Each profile uses order **NPPNNPPN**, eight independent receiver processes and
fresh Node directories: four N and four P. There is **one distinct task, one
retained proof pair, and zero new complete proofs**; each profile attempts four
replays of that pair. Owner initialization and final status are separate processes.
The [push plan](hosted/push/two-cpu/plan.json) and
[PR plan](hosted/pr/two-cpu/plan.json) identify the same inputs. These samples do
not extend R4's eight-fresh-proof population.

External measurements cover fork through `wait4`, including the same pre-exec
kernel observer, startup, receiver work, and teardown. CPU is child user plus
system time; peak RSS is the child's high-water mark. Fresh processes do not
flush OS caches, and the host was not exclusive.

Both runs record candidate head
`acd3edaab4a7aad358d4d174ea23000d619f70ea` and tree
`4a184e053ac73fdc456472b00cb78f2a7acafce8`, verifying **26,169 tracked entries and
2,501,223,504 tracked bytes**. Before/after source receipts match. Both use
`kind=head`; the PR-triggered run supplies no prospective-merge qualification.
[Push source](hosted/push/source-before.json),
[after](hosted/push/source-after.json);
[PR source](hosted/pr/source-before.json),
[after](hosted/pr/source-after.json).

Executable SHA-256 records differ:

- Push: `733eedf0f3c1922a232fc373f3a0c014748225f7b11b24bae0cdc5e537bbb58c`.
- PR: `e6c84401d443e8de17a767e9d4e1ed5b1ab7777049eb423b821af41cc934c3c4`.

The cause is **unknown from retained evidence**. Executable bytes were not
retained. Checks establish consistency between each run's checksum receipt and
its four harness before/after records, not independent rehashing of executable
originals. Keep runs separate; do not pool them as one binary or interpret their
difference as an optimization. [Resource audit](hosted-audit-resources.json).

## Two-CPU results

Each N/P entry below is the direct median of four completed processes. Delta is
P median minus N median; ratio is P median divided by N median. No paired-difference
estimator was computed. Sources:
[push summary](hosted/push/two-cpu/summary.json),
[PR summary](hosted/pr/two-cpu/summary.json), and the
[independent cost audit](hosted-audit-cost.json).

### Push run 42629992145

| Metric | N | P | Delta per receiver | P/N |
|---|---:|---:|---:|---:|
| Whole-process wall, s | 0.0191823225 | 1.996227183 | +1.9770448605 | 104.066 |
| Whole-process CPU, s | 0.0145695 | 3.784444 | +3.7698745 | 259.751 |
| Peak RSS, KiB | 14,510 | 124,916 | +110,406 | 8.609 |
| Application input, B | 49,508 | 4,023,864 | +3,974,356 | 81.277 |

### PR run 42630053802

| Metric | N | P | Delta per receiver | P/N |
|---|---:|---:|---:|---:|
| Whole-process wall, s | 0.0161170865 | 1.3876273605 | +1.371510274 | 86.097 |
| Whole-process CPU, s | 0.0123485 | 2.572917 | +2.5605685 | 208.359 |
| Peak RSS, KiB | 14,638 | 125,140 | +110,502 | 8.549 |
| Application input, B | 49,508 | 4,023,864 | +3,974,356 | 81.277 |

P includes the native packet plus statement and two proofs. The independent plan
and owner policy are provisioned separately; transport framing is unmeasured.
Owner initialization/final-status wall costs are respectively 7.248/5.630 ms
(push) and 6.479/5.143 ms (PR), separately billed and excluded from receiver medians.
The old approximately 1.8 ms internal native primitive excluded startup and Node
admission, so it is not the denominator for these receiver comparisons.

### Disjoint phases and nested work

The [phase audit](hosted-audit-phases.json.gz) retains every sample. Top-level
phases are disjoint. Each grouped median below first sums that group's stages
**within each sample**, then takes the median. Shares use **the sum of sample
bucket costs divided by the sum of sample enclosing costs** within that run.
Component medians are never added to manufacture a total. All phase costs are
wall time; phase CPU and phase peak RSS were not measured.

| P top-level group | Push median, ms | Push wall share | PR median, ms | PR wall share |
|---|---:|---:|---:|---:|
| Complete proof verification | 1,960.714 | 98.167% | 1,348.629 | 97.145% |
| Node open, admission, activation, readbacks | 11.479 | 0.576% | 9.454 | 0.682% |
| Bundle persistence | 7.314 | 0.367% | 15.208 | 1.178% |
| Other completed top-level phases | 7.409 | 0.407% | 5.475 | 0.393% |
| Whole-process unitemized remainder | 9.280 | 0.484% | 7.983 | 0.602% |

The remainder includes observer/startup, event reporting, final result persistence
and serialization, and teardown. Their individual costs are not isolated.
Nested proof stages below are already inside complete proof verification:

| Nested proof stage | Push median, ms | PR median, ms |
|---|---:|---:|
| Fixed-shape scans/decode | 5.206 | 4.214 |
| Canonical plans/public-only AIR | 12.051 | 10.516 |
| SHA independent preprocessing | 512.049 | 345.652 |
| SHA proof verification | 98.431 | 86.077 |
| Arithmetic independent preprocessing | 1,318.007 | 889.314 |
| Arithmetic proof verification | 13.374 | 11.279 |

Combined independent preprocessing has per-sample-sum medians of **1,830.077 ms**
and **1,234.947 ms**, accounting for **93.318% / 91.556%** of enclosing proof wall.
Arithmetic preprocessing alone accounts for **67.208% / 65.893%**. This identifies
the dominant cold-path optimization target; no cache/reuse benefit was measured.
Native admission remains inside P, with nested medians 2.470/2.033 ms. Nested
proof/native stages must not be added to their enclosing top-level measurements.

## Quarter-CPU deadline outcome

Both profiles are `INCOMPLETE_OR_INCOMPARABLE`; comparison medians and changes
remain `null`. The table preserves completed N medians and **P costs spent until
termination**, whose ranges are not successful verifier latency or completed-arm
medians. Input bytes are the same declared payloads as above.
[Push summary](hosted/push/quarter-cpu/summary.json);
[PR summary](hosted/pr/quarter-cpu/summary.json).

| Run/arm | Completed | Wall, s | CPU, s | Peak RSS, KiB | Input, B |
|---|---:|---:|---:|---:|---:|
| Push N | 4/4 | 0.094818972 median | 0.0149975 median | 14,560 median | 49,508 |
| Push P | 0/4 | 4.007299–4.093350 | 1.015698–1.020478 | 64,368–65,304 | 4,023,864 |
| PR N | 4/4 | 0.090386783 median | 0.012503 median | 14,658 median | 49,508 |
| PR P | 0/4 | 4.031664–4.098915 | 0.990879–1.023923 | 123,060–125,052 | 4,023,864 |

Every P records `timed_out=true`, exit `-9`, and missing final result receipt.
Observed ends span **4.007299–4.098915 seconds** across runs. Four seconds is the
requested process deadline, not an established four-second kill-and-cleanup
guarantee; scheduling and cleanup remain charged in external wall time.

All P attempts finish reservation, input binding, and bundle persistence, then
start `complete_proof_verification`. Push's last checkpoint is `BeforeShaSetup`
in all four cases; PR's is `BeforeArithmeticSetup` in all four. The latter follows
a successful SHA verification return in the matched source, but establishes
neither arithmetic success nor complete-pair success. There are no retained
partial nested durations, Node-open events, final admission receipts, or archived
Node files for these P attempts. Missing receipt facts remain unknown. **Timeout
is not a cryptographic rejection**, and the last checkpoint cannot identify the
exact interrupted instruction. All four owner slots remain spent and exhausted.
[Phase audit](hosted-audit-phases.json.gz).

## Actual resources and qualification boundaries

The resource audit checks **120 kernel snapshots**: four run/profile cells times
ten processes (eight receivers plus two owner operations) times three observations
(parent before fork, child before exec, parent after wait). All match their plans:

| Setting | Two CPU | Quarter CPU |
|---|---|---|
| `cpu.max` | `200000 100000` | `25000 100000` |
| Memory maximum | 2,147,483,648 B | 2,147,483,648 B |
| Swap maximum/current observed | 0 / 0 | 0 / 0 |
| PID maximum | 256 | 256 |
| Observed child affinity | `[0,1]` | `[0,1]` |
| Configured Rayon workers | 2 | 2 |
| Process deadline | 120 s | 4 s |

Quarter-CPU uses a quota with two available worker CPUs. CPU throttling is visible;
observed OOM-kill counters remain zero. These are sampled observations, not continuous
attestation. Visible non-root ancestor caps are unlimited; root cap fields are
null. Shared-cgroup counters include the harness and cannot substitute for child
CPU accounting. [Resource audit](hosted-audit-resources.json).

The ephemeral research scopes do not establish the original production owner,
`trnmponpublic.slice`, pressure-lane behavior, WAN transport, or production service
qualification. UID/GID 1001 and systemd runtime/stop limits were requested, but
child UID/GID and those systemd property readbacks are absent. R4's eight-core,
4-GiB environment remains separate. Both builds retain the SQLite boundary warning:
`UNQUALIFIED: external native build override CARGO_ENCODED_RUSTFLAGS`.
Passing research tests does not remove that warning.

## Validation and failed preparation

Each hosted raw log records **27 Rust tests: 12 bridge, 10 owner, 5 receiver
metrics**, with zero failed, ignored, or filtered tests. Empty unit harnesses are
excluded from 27. Each CI also passes **17 reader controls**, locked dependency
graph checks, formatting, and strict Clippy. Reader controls include synthetic
and benign subprocess cases; they are not additional W1 samples.
[Push Rust log](hosted/push/native-tests.log.gz),
[PR Rust log](hosted/pr/native-tests.log.gz),
[push Clippy](hosted/push/clippy.log), [PR Clippy](hosted/pr/clippy.log).

[Local validation](local-validation.zip) retains 43 passing source-integrity
controls, 166 passing CI-contract tests, and a passing repository check. The
166-test/repository observations began before publication without a complete
surrounding source freeze; their retained provenance explicitly limits attribution.
Later source receipts do not retroactively qualify those earlier executions.
Separate frozen-source reader and source-control receipts are retained.

Failures remain evidence. Partial materialization and early compilation hit
ENOSPC; another materialization ended with exit 137 of unestablished unique cause,
followed by executor recovery trouble. Recovery initially lacked the toolchain.
Local build attempt 3 failed with ENOSPC after **978.686 seconds**, exit 101;
it is preparation, not a performance sample. The archive preserves available
setup/build receipts, failed offline metadata attempts, and later successful
locked fetch/metadata results. Earlier tool observations are not relabeled as
complete process logs. An early reader-test scheduling assumption was corrected
to accept genuinely empty captured output; timeouts remain failures.

ROG lookups encountered capacity refusal and two empty-log timeouts; **no ROG
clone/build actually occurred**. The original cloud CPU evaluation remains
**UNKNOWN**, with no allocation, plan, or execution. Resource discovery is not
substitute benchmark evidence.

## Retained evidence and verification

[Index](hosted/index.json) and [member bundle](hosted/all-member-records.zip)
retain all **434 original member files**, 217 per hosted archive. Deduplication
stores 232 unique objects inline and resolves four fixed input objects from the
immutable candidate Git commit. Original archive identities/hashes are recorded.
Retention reproduces member bytes, not original ZIP container bytes, permissions,
ownership, or a live operational owner/Node directory. Executable originals are
absent. Separate readable copies expose each run's summaries, manifests, plans, tests,
source receipts, and checksum records.

The retained-member verifier has actually checked **434/434**. From the repository
root, verify without executing a receiver:

```bash
python3 formal/pon-nakamoto-v1/w1_node_adapter_research/evidence/receiver-cost-20261109/verify_retained_artifacts.py --repo .
```

Optional `--extract /tmp/w1-receiver-retained-members` writes diagnostic member
files beneath an absent destination, after validating all objects. It does not
restore a live owner. The independent [cost](hosted-audit-cost.json),
[resource](hosted-audit-resources.json), and
[phase](hosted-audit-phases.json.gz) audits add no executions or proofs.

## Benefit condition and remaining decision

For a chosen additive cost dimension, let ΔP be additional producer cost
and ΔR additional cost per receiver against the matched native route. A
benefit requires:

`ΔP + nΔR < 0`.

Evaluate CPU-seconds, application bytes, or an explicitly priced monetary model
separately. Do not add seconds, bytes, and RSS; peak memory and concurrent network
latency are not automatically additive across receivers. The measured two-CPU
receiver CPU increments and payload increments are positive. Increasing receiver
count therefore increases those measured increments. Fresh producer cost,
actual transmission, and a qualifying proof-replacement route remain unmeasured.
No transport saving, TPS conversion, exact whole-chain acceleration, or receiver
break-even is established. The deadline failures and production gates retain
**HOLD_NO_GO**.
