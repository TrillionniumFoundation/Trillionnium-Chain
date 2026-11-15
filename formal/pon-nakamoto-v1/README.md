# PoN executable contracts and bounded experiments

## Joint difficulty, time, credit and participation qualification

The [joint qualification contract](../../docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_QUALIFICATION_V1.md)
binds 23 reviewed source files, both native owner profiles, the actual development
parameters and the original unproved MU1 cost contract. It reports 18 unknown
environment inputs and 13 open obligations for one joint CP/CG/CQ argument.
`--check` verifies this research contract; `--require-qualified` deliberately
refuses with exit 3. Both keep native failure probabilities null and production
activation false. No successful finite report calibrates six confirmations.

The [dynamic participation continuation](../../docs/protocol/pon-nakamoto-v1/details/DYNAMIC_PARTICIPATION_V1.md)
checks declared cohort eligibility, inherited delivery deadlines and retained
task/resource debt across joins, departures and rejoining. It supplies no native
membership authority, authenticated clock, positive production-rate law or
all-algorithm work lower bound.

```bash
python3 formal/pon-nakamoto-v1/joint_consensus_qualification.py --check
python3 formal/pon-nakamoto-v1/test_joint_consensus_qualification.py
python3 formal/pon-nakamoto-v1/test_dynamic_participation_v1.py
```

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

## Mandatory work and native execution certificates

The [MU1 research relation](MANDATORY_UNITS_RELATION_V1.md) freezes a complete,
domain-separated fixed-target envelope over one to eight native W1 units. Each
unit retains the full original relation; one aggregate lottery binds the ordered
canonical outputs. The profile is not enabled in the native node. The conservative
query certificate grants unit work for free, charges preprocessing and public
oracle help, and requires a complete-output budget. It is not a lower bound on
the cheapest physical W1 strategy.

The [stateful resource theorem](STATEFUL_RESOURCE_TAIL_V1.md),
[fork witness](NATIVE_FORK_MAPPING_V1.md) and
[execution accounting](NATIVE_EXECUTION_CERTIFICATE_V1.md) keep initial inventory,
oracle-correlated residual state, honest off-branch work, availability and
selection deficits explicit. Complete declared model traces can be checked;
unseen native candidates, physical time and an environment probability law are
not authenticated by a trace label or a passing parser.

```bash
python3 formal/pon-nakamoto-v1/mandatory_units_tests.py ContextContractTests QueryCertificateTests -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_execution_certificate.py' -v
MU1_NATIVE_WORK=/absolute/path/to/release/examples/pon_work_io MU1_NATIVE_PREPARED=/absolute/path/to/release/examples/pon_zero_io python3 formal/pon-nakamoto-v1/mandatory_units_tests.py -v
```

## Actual local observations and remaining scientific certificates

[Native owner census](NATIVE_OWNER_OBSERVATION_V1.md) is an opt-in diagnostic
over a held native PNP1 owner. It enumerates the complete current admitted
relation in a consistent read snapshot and replays native W1, application state,
receipts and deltas. Its [independent score bridge](NATIVE_OWNER_SCORE_BRIDGE_V1.md)
recomputes 512-bit work, ancestor timestamp eligibility, the actual confirmation
AND and full local comparison deficits from fresh native executions.

[WLC1](WORK_LIFECYCLE_CERTIFICATE_V1.md) authenticates bounded observation
fragments with externally pinned ML-DSA-65 keys and first/last checkpoints.
It verifies full work artifacts and public-help source links, while keeping
signature validity separate from the truth or completeness of resource reports.
Its fixed finite classical-help theorem requires a global complete transcript
alphabet and admits a vacuous bound when that alphabet is too large.

[Observability and repeated starts](CERTIFICATE_OBSERVABILITY_V1.md) prove
why local records alone cannot determine hidden world inventory or correlated
initial advice. A shared-lifetime interval-packing witness avoids counting the
same work repeatedly across adaptively chosen windows. Predictable risk spending
is checked against an explicitly supplied full joint law, never a fresh-reset
assumption at a selected start.

These components narrow the two actual-certificate obligations. They do not
establish all-algorithm physical work costs, authentic global budgets, physical
clock and availability envelopes, or a native common-prefix failure probability.
The three candidate qualifications and the unknown six-successor risk remain
as recorded in the sole development plan.

The repository-truth and protocol-contract lanes retain these controls alongside
the existing checks. [Source and raw evidence](../../evidence/pon-work-native-certificates-20261107/README.md)
separate the previously delivered abstract models from new complete native W1/MU1
executions. Neither three-candidate safety qualification nor a numerical risk
for the current six-successor rule is asserted.

## One lifetime, persistent local debt, and exact composition

[LQC1](lifecycle_query_charging_v1.md) keeps one coalition-wide terminal
oracle and one irreversible first-coherent-query boundary. A complete paid
classical prefix is averaged under its explicit ideal-oracle law; subsequent
queries, helper activity and retained state share one lifetime budget. A
fixed-output-index union removes analysis-only virtual verification queries.
Actual oracle-dependent validator feedback is still charged. The declared
caps and complete joint initial-state independence are assumptions, not facts
certified by a signed log or a newly started process. MU1 research credit is
never substituted for native block work.

The [persistent owner journal](NATIVE_OWNER_JOURNAL_V1.md) adds durable intent,
complete packets and actual post-call census to an opt-in owner wrapper. It
records native opening/recovery as an operation, keeps unadmitted outputs
across restart, and exposes unfinished calls, outside-lease intervals,
validation-clock regressions and orphan artifacts. The sidecar is separate
from the native database transaction. A real process exit after a native
commit cannot be relabeled a completed observation, and a hash chain does not
authenticate the newest physical history without an independently retained
expectation.

[CC1](CERTIFICATE_COMPOSITION_V1.md) joins exact signed packet bytes to the
actual journal's native-valid packet bindings, deduplicates native identities
and retains that unresolved debt. Its controls distinguish a valid signature
from production, the same header ID from the same valid packet, a global
probability from a conditional probability at a selected start, and message
payload from the entire observable helper channel. It supplies no route to
turn these local observations into a native failure probability.

```bash
python3 formal/pon-nakamoto-v1/lifecycle_query_tests.py -v
LQC_NATIVE_WORK=/absolute/path/to/pon_work_io LQC_NATIVE_PREPARED=/absolute/path/to/pon_zero_io python3 formal/pon-nakamoto-v1/lifecycle_query_evidence.py --out /tmp/new-lqc-run
/absolute/path/to/native_owner_journal_v1 /tmp/new-owner-journal
NATIVE_OWNER_JOURNAL_RUN=/tmp/new-owner-journal/run.json python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_native_owner_journal.py -v
python3 formal/pon-nakamoto-v1/native_owner_journal.py --run /tmp/new-owner-journal/run.json --output /tmp/new-owner-checked.json
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p certificate_composition_tests.py -v
python3 formal/pon-nakamoto-v1/certificate_composition_evidence.py --native-run /tmp/new-owner-journal/run.json --output-dir /tmp/new-composition
```

The native reader and composition driver require fresh raw journals and
complete packet files; missing artifacts fail. Cryptographic composition
tests run in protocol CI's pinned Python environment. The
[continuation evidence](../../evidence/pon-lifecycle-closure-20261107/README.md)
preserves initial failures, exact source/binary bindings, actual Linux native
runs and the unchanged qualification table. Physical all-algorithm work
losses, authentic joint initial state, full-world coverage, clocks, inventory
and honest-progress laws remain the two actual scientific obligations.

## Explicit finite joint initial states

[FJS1](FINITE_JOINT_STATE_CERTIFICATE_V1.md) checks every oracle table and the
complete declared conditional advice density matrix with exact rational PSD
arithmetic. One common independent reference state and explicit positive excess
give the proved probability transfer `lambda * B + epsilon`. The reference
query/list bound is recomputed, and selected-start probability scopes are
refused. Five complete finite models include coherent advice, noisy advice,
singular independent state, full truth-table advice and a paid positive excess.

This certifies the supplied finite state, its operator-order loss, and the
unconditioned model event. Authenticity of actual worker/environment states,
future helper coverage, actual hash idealization, physical resources and native
confirmation risk remain separate unproved obligations.

```bash
python3 formal/pon-nakamoto-v1/finite_joint_state_tests.py -v
python3 formal/pon-nakamoto-v1/finite_joint_state_certificate.py --evidence-dir /tmp/new-finite-joint-state
```

## Complete finite execution-event coverage

[EC1](CERTIFICATE_EVENT_COVERAGE_V1.md) derives all confirmed starts and every
later recorded observation or replayed selection cut from every leaf's raw
execution. Allocations must cover exactly that complete catalogue and its
failure leaves before the existing predictable risk bank is applied under the
same declared joint law. Exact recorded prefixes must agree inside each history
cell; future-outcome labels alone cannot create a cheaper conditional start.

The controls expose an omitted second confirmation, an omitted failure leaf,
temporary removal followed by restoration between observations, and identical
inventory/progress marginals with different joint failure risks. No actual
network probability law, physical filtration, unrecorded event or extension
beyond the declared horizon is authenticated.

```bash
python3 formal/pon-nakamoto-v1/certificate_event_coverage_tests.py -v
```

## Durable local confirmation risk registration

[PNRL1](NATIVE_RISK_LEDGER_V1.md) privately wraps the actual persistent native
owner and syncs each fixed-scope confirmation registration and declared allowance
before dispatch. Every repeated, failed or interrupted start remains charged.
The independent reader reconciles **every** confirmation intent in the complete
supplied native journal, including native calls that bypassed the risk wrapper.

The fresh native scenario exercises pre-dispatch and post-native process exits,
reopening, unsuccessful confirmations, exact owner binding and cumulative budgets.
Its tests also retain a real bank-only rollback counterexample before native
intent, and coherent after-the-fact allowance rewrites. An independently retained
newer checkpoint rejects those old or rewritten histories; the files alone do
not authenticate the latest history or physical pre-registration.

```bash
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_risk_ledger
cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example native_risk_ledger_v1
/path/to/release/examples/native_risk_ledger_v1 /tmp/new-native-risk-ledger
NATIVE_RISK_LEDGER_RUN=/tmp/new-native-risk-ledger/run.json python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_risk_ledger.py' -v
python3 formal/pon-nakamoto-v1/native_risk_ledger.py --run /tmp/new-native-risk-ledger/run.json --output /tmp/new-native-risk-ledger/checked.json
```

This is declared local expenditure and raw-history reconciliation. Conditional
failure probabilities, world-wide start coverage, physical time, hidden inventory
and a common native failure law remain uncertified. The report retains a null
native failure bound and false probability qualification flags.

## Conditional joint production tails

The [joint tail interface](../../docs/protocol/pon-nakamoto-v1/details/JOINT_PRODUCTION_TAIL_V1.md)
composes ready credit, entry debt and honest pacer progress under one conditional
history. Exact finite-state controls compare direct joint moments, conditional
Cauchy-Schwarz and adaptive Bellman first-passage probabilities. Initial residual
potential is retained; supplied scope labels do not authenticate an actual law.
The [calibration distortion proof](../../docs/protocol/pon-nakamoto-v1/details/CREDIT_CALIBRATION_DISTORTION_V1.md)
quantifies the mismatch of ideal classical and quantum cost scaling. Both results
retain HOLD and null native security bounds.
