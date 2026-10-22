# Bounded public decoder runtime experiment

`llm_runtime_pilot.py` executes the author's frozen public
`HuggingFaceTB/SmolLM2-135M-Instruct` revision
`12fd25f77366fa6b3b4b768ec3050bf629380bac`. Its dependencies are isolated optional
experiment libraries; the native node does not import Torch or receive a second
training/state owner. The [public family](../config/pon/model-family-smollm2-135m-v1.json)
pins architecture, all seven source files, the derived float32 backbone and tokenizer
roots, ordinary q/v LoRA, four required controls and nonpositive-gain rejection.

The bounded runtime uses the existing
[material/ports contract](../formal/pon-nakamoto-v1/llm_adapter_contract.py) without
rewriting its network or parameter roots. A future native registration must bind its
own real network/parameters/genesis/family/plan to these explicit reference roots.
Ports validation, a runtime receipt and an artifact hash do not certify native
inference, independent custody, computational hardness or public reward authority.

## Execution

Use a fresh output directory and retained exact `material-manifest.json` with the
seven pinned public files. The source hashes are checked against code constants,
including tokenizer/configuration bytes; a self-rehashed replacement is rejected.
No model code is downloaded/executed. Only safetensors are loaded,
`trust_remote_code=False`, and inference remains offline after preparation.

```sh
python scripts/llm_runtime_pilot.py run --materials /isolated/materials \
  --output /isolated/runs/cpu-pilot-unique --backend cpu --threads 4 --steps 10
python -m unittest discover -s scripts -p test_llm_runtime_pilot.py -v
```

The first actual CPU environment used Python 3.12.3, Torch 2.9.1+cpu,
Transformers 4.57.3, PEFT 0.18.0, safetensors 0.7.0, tokenizers 0.22.2,
NumPy 1.26.4 and accelerate 1.12.0. The retained wheel manifest hashes every wheel
and the installed lock records transitive versions. This is separate from the
native/formal qualification environment and does not inherit its qualification.

The experiment freezes public training/calibration/evaluation bytes, recipes,
source/family hashes and resource caps before candidate training. Loader pilots use
training fixtures. Actual candidate, immutable parent, fresh budget-matched LoRA,
budget-matched full tune and randomized rank-matched LoRA are then prepared.
All five distinct artifacts are frozen before calibration/evaluation decoding.
All three trained participants use the same steps and token/label schedule, common
wall/RSS caps and thread count; this does not assert equal actual consumption.
Missing controls, subprocess failure, time/RSS exhaustion, wrong material or replay
context cause explicit abort with no adoption/reward and retained partial records.

CPU FP32 eager forward and fixed-count greedy decoding check actual logits device,
dtype, finite values, token count and tokenizer output. There is no EOS early stop,
silent truncation, remote model code, quantization or TF32. Declared source BF16 and
derived FP32 tensor hashes are separate. Ordinary rank4/alpha8 adapters target q/v
in all 30 layers (230400 trainable parameters); immutable backbone hashes must stay
unchanged. Full-tune weights and all adapters are saved and reloaded into fresh
workers before scoring. Float adapter bytes do not prove functional equivalence.

The first real short pilot completed 12 phases. Each trained role used 10 steps,
526 total tokens and 40 supervised tokens. Candidate, fresh LoRA and full tune each
scored 1/2 on calibration and evaluation; parent/random scored 0 under exact-byte
matching. The trained participants all answered `yes`, so this measures formatting
and a constant answer on a tiny balanced fixture, not improved general reasoning.
Gain over the strongest control was zero: no adoption or reward is supported.
All fixture tasks are public and controlled by one operator. Different byte IDs,
machines or timestamps do not establish independent future tasks.
The three-round engineering loop may use these or other frozen reproducible
public/previously seen tasks; training-side unfamiliarity is not a prerequisite.
Report the actual dataset results, parent lineage, controls and next-task use.
This scope does not claim future-task generalization or change reward admission.

## Measurement and retained limitations

Each phase has a fresh process, 50ms sampled RSS, exact owned-child Linux `wait4`
CPU, observer CPU and end-to-end phase wall time. A held `pidfd` binds termination
to that child. RSS reads use the kernel's own fdinfo PID namespace mapping and
verify the child PID, parent and namespace before and after observation; a local
numeric PID is not assumed to name the same process in the mounted `/proc` view.
Under the default `strict-v1` observer, missing RSS while an exact wait observes
a live child is a sticky failure.
Such failures now retain the exact read-boundary reason and a bounded post-gap
snapshot through the original held pidfd: leader state/RSS, group thread states
and identity continuity. The snapshots occur after the missing sample and cannot
replace it, establish memory bounds or turn a failed observation into success.
New missing-sample traces also retain the original status read's state, thread
count, timestamp and owned-observer precondition, plus whether classification was
attempted and its fixed rejection code. This adds no procfs reads or acceptance
authority. Historical samples without these fields retain an unknown initial state.
Exit-drain recheck failures additionally record only a closed set of fixed observer
refusal codes and valid OS error numbers from that exact exception. Unknown or
arbitrary messages are omitted; all such failures remain sticky. Earlier records
without the code retain an unknown specific recheck refusal.

Linux workers whose leader is already a zombie can still be running kernel exit
cleanup before the group becomes waitable. The explicit
`--exit-observation-profile linux-owned-exit-cleanup-v2` option freezes a fresh
`llm-runtime-public-pilot-plan-v2`, including both observer source hashes. During
the original missing-VmRSS sample it borrows the supervisor's original pidfd and
holds every task directory FD across two complete observations. Classification
requires a zombie leader, an unchanged complete task set and thread count, stable
identity/starttime, and all tasks `PF_EXITING`, non-`PF_KTHREAD`, with no observable
VmRSS and stat vsize/RSS fields zero. Malformed, missing or changed observations
reject. A trace dictionary or later diagnostic cannot authorize this branch.

The classified state permits at most 100ms from the original missing sample,
bounded by the original wall deadline, to obtain the exact terminal wait4 receipt.
Every intervening live poll rechecks the held directories and identities. Any
fault, task-set change, unknown wait or timeout is sticky, including a later zero
exit. Reservations and the original pidfd remain held through terminal cleanup;
valid waited peak RSS/CPU and the original RSS/wall caps still govern success.
No zero-RSS sample is inserted. Kernel exit can detach `current->mm` before its
final release, so this classification establishes neither physical page release
nor zero resource consumption. Historical failed observations retain their
original strict-v1 outcome. The unit fixtures and live-user-thread refusal test
qualify this boundary; they do not establish model efficacy.

The separate opt-in
`--exit-observation-profile linux-owned-exit-terminal-subset-v3` freezes
`llm-runtime-public-pilot-plan-v3`, binding the new observer, reused V2 parser/FD
owner and diagnostic source hashes. Strict-v1 remains the default; V2 retains
its unchanged complete-task-set rule. Parent-step requires the exact schema and
profile pairing and cannot infer V2 merely from an `exit_observation` member.

V3 first requires the complete initial V2 double frontier. Only afterward may
two complete stable frontiers show a strict subset of the previous task set.
The leader must remain, counts must match, and every remaining task must retain
its original FD identity/starttime, namespace, `PF_EXITING`, non-`PF_KTHREAD`,
absent VmRSS, zero stat vsize/RSS and current zombie state. Additions, reappearing
TIDs, running remaining tasks, inconsistent frontiers and unknown reads reject.
Every failure is sticky; an initially unknown task cannot become acceptable by
disappearing. All original task FDs, identities and reservations remain held.

Missing tasks are recorded as pending retirement, without claiming that their
memory was released or that they terminated. Only the same owned child's exact
terminal wait4 and valid CPU/peak-RSS receipt close that pending state. The
original 100ms deadline starts at the original missing sample, never at subset
discovery; the original wall/RSS caps still govern. No zero-RSS sample, later
diagnostic, cleanup-only wait or trace dictionary supplies acceptance authority.
New same-call refusal context is diagnostic only. A valid normal exit can still
fail if it cannot be observed within the unchanged deadline. Historical strict
and V2 failures retain their original outcomes; source/unit checks do not prove
a successful full model pilot, model improvement, native installation or the
three-round Hepta loop.

The first fixed-environment V3 real-model attempt on2026-10-22 failed in its
first loader despite exit code zero after loading and eight forward/decode
steps. An ENOENT made the same-call task frontier incomplete; the supervisor
retained `rss-exit-cleanup-observation-unavailable`. The last complete two-task
recheck was64.536ms from the original gap, refusal ended at66.641ms, and the
post-refusal diagnostic showed one task at67.581ms. None supplies the missing
stable subset or a timestamped timely terminal wait4. Raw evidence and the
earlier V2 failure remain unchanged. Training and adoption did not run. This
demonstrated blocker requires a reviewed observer change and a fresh frozen
attempt; it cannot be passed by retrying inside the original record.

The separate opt-in
`--exit-observation-profile linux-owned-exit-worker-pidfd-v4` freezes the distinct
`llm-runtime-public-pilot-plan-v4`. It binds the new worker observer and the
unchanged V2 parser/FD owner and diagnostics; it does not import the V3 observer.
CLI and parent-step dispatch require the exact schema/profile/source pairing.
Strict-v1 remains the default and the frozen V2/V3 predicates do not change.

V4 requires the full original V2 double frontier before acquiring a kernel
`PIDFD_THREAD` for every original nonleader, using the task's validated parent
PID-namespace coordinate. Each retained descriptor is bound to fdinfo Pid/NSpid,
the original held task directory, parent/group identity and starttime across
acquisition, then the complete V2 frontiers and bindings are checked again.
Any acquisition disappearance, unsupported API/flag or changed binding refuses;
there is no ordinary-pidfd fallback or later numeric-TID rebinding.

Only that previously bound worker descriptor's actual `POLLIN` event, optionally
with `POLLHUP`, can prove that original worker terminal. An absent directory or
ENOENT/ESRCH alone cannot. A mid-frontier worker read failure with this proof may
request two new complete remaining frontiers in the same call. Each recapture
must consume a newly proved original worker retirement, at most the original
worker count, within the unchanged deadline. Every remaining task must satisfy
the original predicates and, after a shrink, be Z in both status and stat.
The complete frontiers must agree on task names/counts and original starttimes;
this does not require every unrelated stat flag to remain identical.
Already observed malformed, live-memory, wrong-identity or unqualified fields
are sticky and cannot be erased by a later worker event. Additions, reappearance,
count mismatches, missing terminal events and changed/closed FDs also refuse.

The leader always needs its original proc observations and cannot disappear.
The [Linux v7.0 UAPI](https://github.com/torvalds/linux/blob/v7.0/include/uapi/linux/pidfd.h)
defines `PIDFD_THREAD` as `O_EXCL`; its
[poll implementation](https://github.com/torvalds/linux/blob/v7.0/fs/pidfs.c)
delays an early zombie leader while other threads remain. Controlled own-child
probes confirmed a worker event with held task-proc ENOENT while the group was
still live, and separately confirmed that delayed-leader limitation. No early
leader event is required or used. Probe harness failures and the failed general
leader-event expectation remain retained alongside the explicit negative case.
These are tiny-child capability observations, not full-model qualification.

All original task/thread FDs and bindings remain held, including kernel-reaped
workers whose fdinfo later reports `-1`; that marker never replaces their
original identity. Worker events create only pending group retirement. The
same owned child's exact terminal wait4 and valid CPU/peak-RSS receipt within
the original missing-sample 100ms and wall/RSS caps remain mandatory. No event
creates zero RSS or releases a resource reservation. Acquisition or recapture
crossing 100ms refuses. The V3 full-pilot failure above remains FAIL; the V4
component and its tests do not establish a successful new full model attempt,
training gain, installation or a completed three-round engineering loop.

`sampled_peak_rss_bytes` remains the direct-child sampling result.
`waited_child_peak_rss_bytes` separately records that exact child's Linux `wait4`
`ru_maxrss` in KiB times 1024. A quick exit can succeed without a sample only when
its exact terminal status and positive resource receipt are available. Wall and
RSS budgets are checked again at termination, including an exit-zero child that
exceeded RSS between samples. These high-water figures can include inherited
waited-descendant accounting; they are neither simultaneous process-tree RSS nor
a kernel hard memory limit. RSS maxima are not added. Child CPU is not obtained
by subtracting the caller's aggregate `RUSAGE_CHILDREN` observations.

Exit observation and resolved reaping are separate receipt fields. Only a valid
exact terminal wait, or held-pidfd exit readiness plus genuine `ECHILD`, resolves
cleanup. Cleanup-only `waitpid` cannot provide RSS or CPU success credit. Other
unresolved wait/signal faults retain a failed receipt and the owned handle in a
cleanup exception. A caller that exits instead of resolving this exception cannot
claim successful cleanup. Killed children may lack a complete stage event/CPU
receipt; this is an incomplete failure, never a fabricated zero-cost success.
Linux `read_bytes`/`write_bytes` are kernel IO accounting, not logical input sizes,
network bytes or total economic resource cost. Profiler FLOPs cover supported
operators only, not all training work. Bootstrap downloads/install and SSH/controller
work remain separate observations. No energy price or hardware-cost lower bound is
inferred from timings. Stage/phase walls overlap and must not be double counted.

The bounded supervisor requires Linux `wait4`, `pidfd_open`, `pidfd_send_signal`,
default `SIGCHLD` handling and exclusive ownership of this child's reaping.
Unsupported capabilities reject the run before spawn; concurrent external reapers
are outside this contract. A pidfd acquisition fault after spawn fails closed and
can leave explicitly unresolved cleanup. Process controls exercise the supported
owner and fault paths. Historical pilot receipts retain their original observation
scope and do not inherit this revised resource qualification. CUDA and
ROCm branches require the actual respective Torch runtime and actual GPU availability;
they reject silent CPU fallback. Their GPU-time/resource and numeric qualification
remain separate work. MPS additionally needs a macOS RSS/budget owner and actual
backend execution; the Linux supervisor is not a macOS qualification. A CPU profile
must not be registered as a GPU profile. All current runtime/native/independent/future/
reward acceptance flags stay false; ordinary successful phase execution is recorded
separately. Native adoption/consumer/outbox and independent evaluation remain their
existing owners' responsibility.

## Explicit parent material preflight

This entry currently reuses the Linux pilot utilities. Its checked-byte result
does not establish native Windows material loading or cross-platform installation.

After the existing native Cell release fetch has provided complete bytes, the
read-only parent preflight checks the original target contract, wrapped adapter
and actual safetensors against three independently retained identities:

```sh
python scripts/llm_parent_material.py \
  --contract /isolated/parent/target-contract.json \
  --adapter /isolated/parent/wrapped-adapter.json \
  --artifact /isolated/parent/artifact.safetensors \
  --expected-contract "$parent_contract_id" \
  --expected-adapter "$parent_adapter_id" \
  --expected-file-sha256 "$parent_file_sha256"
python -m unittest discover -s scripts -p test_llm_parent_material.py -v
```

The contract must preserve the pinned SmolLM2 FP32 backbone and tokenizer roots,
all 60 rank4 q/v insertion sites and the fixed ports. The bounded parser checks
all 120 F32 factor tensors, exact shapes and byte ranges, complete nonoverlapping
payload coverage, factor hashes and finite values using the existing adapter
contract. A self-rehashed file cannot replace the independently retained adapter
identity. The command writes no installation or CURRENT state, loads no remote
code and imports no optional model runtime. Its JSON result proves only the
supplied material preflight. It does not verify the unavailable full backbone
bytes, evaluation, adoption, lineage authorization, actual reload/inference or
three-round execution. The original single-round pilot and its five controls
retain their existing semantics; inheriting a trained parent requires a separately
qualified runtime integration and control plan.

## Native negative bridge input and public output

The [zero-gain bridge](../trillionnium/crates/trnm-pon-node/examples/llm_zero_gain_round.rs)
accepts `contract` only as the existing producer's 64-character lowercase hexadecimal
digest in both the evaluation roster and candidate metadata. The two parsed IDs must
match. Objects, arrays, missing/null values, numbers, booleans, non-hex text, uppercase,
wrong lengths and whitespace are rejected before creating the output directory or a
native owner. Input parsing and public projection failures report fixed error codes,
without serializing the rejected value.

The [public receipt allowlist](../trillionnium/crates/trnm-pon-node/examples/support/llm_public_report.rs)
names the scalar, digest and compiled-source-inventory fields in the existing binding
and summary schemas. Unknown members are omitted at every report level; objects in
scalar fields reject. Both stdout and `summary.json` use the same projected canonical
bytes, and `binding.json` passes through the same binding allowlist. Original roster,
assessment and metadata copies remain local evidence in a fresh mode-0700 directory
with mode-0600 files; these raw inputs are not public reports. The valid digest IDs,
receipt field names, consensus domains and zero-gain rejection rules are unchanged.

Run the fast input/output regressions with:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example llm_zero_gain_round
```

The tests exercise both contract inputs, equal invalid objects, mismatched valid IDs,
malformed JSON, nested sensitive extra fields and non-scalar public fields. Synthetic
canaries and phase fixtures test the boundary; they do not establish real training,
independent evaluation, model quality, production readiness or CodeQL gate acceptance.

Primary materials: [frozen author repository](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/tree/12fd25f77366fa6b3b4b768ec3050bf629380bac),
[PyTorch version installers](https://pytorch.org/get-started/previous-versions/),
[PEFT LoRA](https://huggingface.co/docs/peft/main/package_reference/lora),
[Ryzen ROCm matrix](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityryz/native_linux/native_linux_compatibility.html).
