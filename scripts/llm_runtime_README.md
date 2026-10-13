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

## Measurement and retained limitations

Each phase has a fresh process, 50ms sampled RSS, exact owned-child Linux `wait4`
CPU, observer CPU and end-to-end phase wall time. A held `pidfd` binds termination
to that child. RSS reads use the kernel's own fdinfo PID namespace mapping and
verify the child PID, parent and namespace before and after observation; a local
numeric PID is not assumed to name the same process in the mounted `/proc` view.
Missing RSS while an exact wait observes a live child is a sticky failure.

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

Primary materials: [frozen author repository](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/tree/12fd25f77366fa6b3b4b768ec3050bf629380bac),
[PyTorch version installers](https://pytorch.org/get-started/previous-versions/),
[PEFT LoRA](https://huggingface.co/docs/peft/main/package_reference/lora),
[Ryzen ROCm matrix](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityryz/native_linux/native_linux_compatibility.html).
