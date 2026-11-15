# Same-material W1 preparation, verifier fanout and complete cost boundaries

This continuation belongs to the sole PN1/PN3 work plan and existing PR #688.
It extends the [complete operator experiment](SHARED_CELL_WORK_V1.md), preserving
the frozen model, inputs, targets, optimized ordinary control and model refusal.
The consensus relation remains `pon-matmul-transcript-64-v1`. No work profile,
signature domain, proof wire, target, reward, authorization or activation changes.

## Explicit legal preparation comparison

`legal_attempt::Task::new` retains the existing dense preparation. The explicit
`Task::with_preparation` alternative accepts `Preparation::Dense` or
`Preparation::Sparse` independently of the existing full-limb/transposed
challenge arithmetic. Both validate every canonical A and B word before preparing
the same A/B/C proof prefix. Sparse preparation indexes nonzero B entries and skips
only zero products. Its u128 accumulator covers the full canonical field range;
it does not assume that a caller supplied small signed model coefficients.

This is a legal producer optimization, not a verification shortcut. Every attempt
still computes all 512 challenge transcript tiles, the original trace and ticket.
Preparation choice and verifier count never change the challenge stream. Matched
arms must produce identical attempts, proof bytes, typed products and final model
outputs. Invalid words, shapes and cancellation remain refusals. Neither producer
preparation exposes a verified-work capability.

The original v1 command and output namespace remain available. Explicit
`--preparation dense|sparse` or `--verifiers N` selects the research observation
namespaces `pon-shared-material-v2` and `pon-shared-cell-operator-v2`. This is not a
new consensus or transparent-proof backend. In v2, each winning proof undergoes
N actual sequential, complete native verifier calls (1 through 64), plus the
existing scalar reference diagnostic. All typed products must agree before the
consumer receives one. These calls run in the same process; they are not
independently managed network validators or a deployment qualification.

## Clocks, coverage and overlap

The raw stream retains setup, every winning and losing attempt, complete search
envelopes, each native verifier, the scalar diagnostic, typed copying, record
construction and serialization. The reader recomputes advertised additive
subtotals and checks that parent clocks cover their children. A modified zero
subtotal cannot erase nonzero attempts or verification. Serialization is an
instrumented aggregate rather than independently recomputed per-record timings.
The research reader checks consistency; it does not authenticate a measurement's
author or replace native W1 verification.

The first native verifier appears both in the legacy `native` field and in v2's
`native_verifiers[0]`. These are aliases. The subtotal charges the complete list
exactly once. Likewise, search includes its attempts, producer includes setup
and searches, and the child process includes all its inner phases. Never add a
parent measurement to its own breakdown. All-child CPU includes source-replay
and identity subprocesses; per-tile native CPU is a subset. Cumulative child RSS
is a high-water mark, not additive memory or a reliable per-child difference.

CPU and wall time are reported separately for the ordinary baseline and Python
phases. CPU comparisons use CPU on both sides. The warm ordinary baseline still
caches base plus delta and evaluates only the router and chosen expert. The
input phase includes model/task reading, validation and optional historical source
replay. It is not an isolated measurement of production model/device loading.
The entire experiment also runs baseline repetitions and correctness diagnostics;
its duration is not one production inference latency.

For one observed batch, the following disjoint native CPU terms can be summed:

`producer setup + all complete searches (including misses) + all observed native
verifier calls + typed product copying`.

That is a measured work subtotal, not the total system cost. A complete deployment
account must also cover all competing miners and their abandoned work, every
actual verifier, admission and state execution, transmission/propagation,
confirmed and stale blocks, model distribution/loading, consumer execution and
the relevant recovery/effect costs. Unknown measurements remain null and keep
`full_system_cost`, net benefit and qualification unresolved. Bytes, CPU, device
work, energy and elapsed time remain distinct quantities; any economic conversion
requires a separately frozen cost model.

Canonical matrix bytes, proof bytes and copied product bytes overlap actual local
pipe traffic. They must not be summed again. Local pipes do not measure WAN.
An exhausted or interrupted run retains its process cost, raw output prefix and
unstarted work. Missing internal attempts remain unknown, and an incomplete batch
receives no complete-output credit.

## Repeated outputs and hypothetical sensitivity

The five tiles and any number of challenge cycles over the same model/request
batch yield one distinct application result. Alternative solver arms, winning
proofs and additional verifiers create no additional useful demand. The reader
rebuilds the material and output identities and refuses duplicate physical logs
or a mixed-material comparison.

Optional scenarios explicitly assume N identical verifier costs and an independent
whole-batch stale fraction s. Their partial CPU expression is

`(observed producer CPU + N * first full verifier CPU + typed copying CPU) / (1-s)`.

Nonce misses are already charged by the observed searches and are not multiplied
again. This scenario is not measured propagation, a mining-security lower bound,
a latency prediction or a full economic result. If a different stale/reuse model
applies, this expression is not transferable. No scenario grants adoption or
overrides `not_adopted` / zero model reward.

## Reproduction on the original frozen materials

Use the original `model.json`, `consumer.json` and `evaluation-bundle.json` from
the retained first experiment. No training or additional model trial is requested.
The bundle domain hash is
`0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5`.
The source corpus is `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`.

On a clean committed source:

```bash
bash scripts/project-preflight.sh
cargo +1.95.0 build --offline --locked --release \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_shared_material_v1
python3 scripts/ci/run_shared_material_campaign_v2.py \
  --model-dir /absolute/path/to/original-frozen-model \
  --bundle-hash 0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5 \
  --runner /absolute/path/to/pon_shared_material_v1 \
  --out /absolute/path/to/new-campaign
```

The driver saves its source, binary/input hashes and complete case plan before
execution. Three alternating repetitions cover both targets, both transcript
kernels and both preparation methods. Six additional observations measure 3/8
native verifier calls and four repeated challenge cycles. One separate bounded
exhaustion control retains the failing process and unstarted tiles. These local
research controls do not replace the original 0.25 CPU / 2 GiB / four-second /
16-hostile-work / depth-six service gate.

Reconcile any retained run directories with the
[strict cost reader](../../../../scripts/ci/shared_material_cost_v2.py):

```bash
python3 scripts/ci/shared_material_cost_v2.py \
  --run /absolute/path/to/new-campaign/paired-r0-t0-full-limb-dense \
  --run /absolute/path/to/new-campaign/paired-r0-t0-full-limb-sparse \
  --out /absolute/path/to/new-cost-readback.json
```

Include the exhaustion directory when reconciling the entire campaign. The reader
then exits 2 with `incomplete_local_observations`, retaining all measured failures;
this is not a successful complete workload. Pairwise costs and campaign research
costs are distinct. Ordinary model adoption, independent future evaluation,
global cheapest legal work, independent WAN/deployment and full net benefit
remain separately unclosed until their own evidence exists.
