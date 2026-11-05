# PoN executable contracts and bounded experiments

The Python ledger is the existing modules' executable design and persistence reference,
not a second production owner. Native M01 work/strict crypto, M00 wire and M06 twelve-command
execution are composed explicitly. A selected missing/failed backend never silently falls
back. A native application engine plus this reference database is not a native full node.

## Reproduce exact regressions

Use the pinned Rust toolchain and the Python versions in the execution receipt. Installation
of `requirements.txt` belongs to an isolated development environment, not a public node.
Use a private Cargo home/target for concurrent projects; do not share their writable caches.

```bash
bash scripts/project-preflight.sh --audit
cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee -p trnm-transport --examples
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_invariants_registry.py
python3 formal/pon-nakamoto-v1/test_invariants.py
python3 formal/pon-nakamoto-v1/test_contracts.py
TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_native_execution.py
TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
```

The native test runners locate binaries beneath `CARGO_TARGET_DIR` when supplied, otherwise
`trillionnium/target`. To run the persistent ledger with both native components, explicitly
set `TRNM_NATIVE_EXECUTOR` to the built `release/examples/pon_execute`, `TRNM_NATIVE_WORK`
to `release/examples/pon_work_io`, and `TRNM_EXECUTION_WORKERS=8`, then run `test_contracts.py`.
The work relation, transaction/state bytes and parameter commitment are still checked.

The complete command set also covers bounded child I/O, strict signatures, model/receipt
binding, clustered evaluation, malformed work and all workspace tests/Clippy/fmt. Actual
commands and environment belong to each [source-bound package](../../docs/modules/README.md#responsibility-and-evidence); v3 is historical, not the global current receipt.
A test class name, new heading or passing document parser cannot stand in for those runs.
Vectors are immutable test inputs; generating replacement vectors is an explicit protocol
change and must never be part of a test's pass path.

## Honest work-rate sensitivity on one time axis

The bounded [honest-rate model](honest_rate_model.py) uses the installed development
profile and existing reference target, timestamp and required-work arithmetic.
It does not change consensus parameters. The [campaign](experiments/honest_rate_campaign.py)
compares steady supply, a fourfold rate increase followed by restoration, a quarter-rate
period followed by restoration, and a 300-second outage followed by restoration over the
same default 7,200-second horizon. The cases deliberately have different total assumed
attempt budgets; a common time axis is not an equal-compute comparison.

```bash
python3 formal/pon-nakamoto-v1/test_reference.py
python3 formal/pon-nakamoto-v1/test_honest_rate_model.py -v
python3 formal/pon-nakamoto-v1/experiments/honest_rate_campaign.py --include-events --output /tmp/new-pon-honest-rate.json
```

The existing required baseline's `fuzz-smoke` lane runs the new tests immediately after
the reference tests, on both the candidate and prospective-merge source. The standalone
campaign creates a new receipt and refuses to overwrite an existing file. Its file
hashes identify the model inputs and source; they do not attest native execution.

Rates mean assumed complete legal attempts per modeled second, never machine counts or
nominal FLOPs. Exact `Fraction` arithmetic carries unfinished success hazard across rate
changes, charges the unfinished tail, and retains markers that have not been included or
confirmed when the horizon ends. Marker confirmation requires both installed depth and
required-work thresholds, with their distinct arrival times reported.

One modeled event consumes one integrated success-hazard unit. This deterministic fluid
path is neither a stochastic mining sample nor the expected trajectory of the nonlinear
stochastic process. Displayed times are floored to nanoseconds for serialization, not
measured at that precision. No W1 proof, network, partition, queue, quantum computation,
cheapest legal algorithm, physical cost or model-learning benefit is exercised. Work
hardness, public-network qualification and production activation remain false, as do
`finalized` and `execution_authority`.

## Separate measured workloads

Run every campaign with a NEW output path. The following are different claims:

```bash
python3 formal/pon-nakamoto-v1/experiments/parallel_cost.py --out /tmp/new-pon-parallel --native /path/to/cargo-target/release/examples/pon_execute
python3 formal/pon-nakamoto-v1/experiments/long_history.py --height 4106 --out /tmp/new-pon-history
python3 formal/pon-nakamoto-v1/experiments/learning_cycles.py --source e7b36311fe5306bf63b7f88985801307e9e47d8c --out /tmp/new-pon-learning
```

The parallel campaign requires the built native executor and reports application-only
cost, conflict retries, full state roots and missing inclusion/confirmation counters.
Long history requires explicit native work/application selection for native-component
measurements, retains real certificates and performs a shallow fork above4096. Its fixed
logical timestamps do not establish a live block rate. Record whether output is on ext4,
tmpfs or another filesystem; a process restart is not a physical power-loss test.

The three-cycle learning producer optimizes real parameters on distinct file groups of
a fixed public retrospective corpus. It may emit no-update in every cycle. New models
must beat their locked strongest control with the required evidence; zero reward and
unchanged public parameters are valid outcomes. This is not ordinary Hepta user experience
or independently certified future-window efficacy.

## Owned multi-host execution

`multihost_campaign.py` accepts an exact source manifest and already-authorized SSH aliases.
Use an isolated copy with an explicitly declared new test chain label and recent genesis
timestamp, hashing every modified configuration. The frozen logical-time genesis is not
silently reinterpreted as today's production network. No service install, public listener,
firewall change, paid provider, user credential or private learning data is needed.

Each host verifies its manifest/context, receives framed SSH requests, checks work/state,
recovers a real process exit and preserves local effect identities through reorg. Delivery
withholding tests a controlled partition schedule; it does not simulate every WAN failure.
Model copies, actual inference, finite sponsored quota and replay rejection are measured
separately from adoption. Hosts controlled by one operator do not become independent actors.

[The historical v3 evidence package](../../evidence/pon-v3/README.md) binds raw outputs, code, inputs,
clock overrides and remaining limits. Historical [v1 evidence](../../evidence/pon-v1/README.md)
is not edited or promoted to current acceptance. Work hardness, fair public proof admission,
ordinary Hepta integration, long-term DA, physical power loss and independent acceptance
remain separate work; all production flags stay false.

## Immutable evaluation caller

The current model producer writes `evaluation-bundle.json` and returns its digest.
Evaluation requires `--evaluation-bundle`, `--bundle-hash`, the locked `--calibration` input and `--partition`;
`--reference` alone is rejected. Settlement additionally requires `--bundle-hash` and
recomputes the two bound evaluator partitions before signing test attestations. Use new
output directories. `run_campaign.py` forwards the producer's returned digest.

Run `python3 formal/pon-nakamoto-v1/test_evaluation_bundle.py` for exact substitution,
leakage, statistical-unit, worker and settlement counterexamples. Three-cycle learning
uses the same sealed controls/parent, while keeping retrospective/no-public-update scope.


The controlled `client_confirmation.py` CLI adds bounded full-history delivery and a
receiver-computed transaction confirmation query. It is not a succinct proof or native
network host. `test_client_confirmation.py` executes actual work and signed state replay,
with the same tests additionally selecting native work/execution in protocol CI.

## Explicit native session

Build `pon_execute_session` with the existing M06 examples and select it using
`TRNM_NATIVE_SESSION=/absolute/path/to/pon_execute_session`; `TRNM_NATIVE_WORK` may
independently select the existing verifier. Do not also set `TRNM_NATIVE_EXECUTOR`.
The session is a bounded disposable compute cache owned by the reference Ledger, not a
native persistent node or new database. Run `test_native_session.py` and
`test_work_precheck.py`; client single/batch confirmation retains complete-ancestry
clock checks. Missing/changed binaries and ambiguous replies cannot silently fall back.

## Model operations reported-acceptance sidecar

Run `python3 formal/pon-nakamoto-v1/test_model_acceptance.py` for synthetic adversarial
and package-ingestion regressions. The owner-pinned offline verifier and exact package
contract are in [Model operations acceptance](../../docs/protocol/pon-nakamoto-v1/details/MODEL_OPERATIONS_ACCEPTANCE_V1.md).
It replays existing target-decoder controls and adds prospective-record separation,
poison/backdoor/forgetting probes, unique reported consumer uses and retention costs.
A contract pass never establishes real model efficacy or independent acceptance.
