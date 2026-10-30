# Separate complete W1 cost observation

This candidate adds one explicit `cost-only-14400-v1` observation profile and
one [dedicated workflow](../../.github/workflows/pon-complete-w1-cost-observation.yml).
It does **not** change the [original 5400-second workflow](../../.github/workflows/pon-complete-w1-proof-research.yml)
or turn its failed result into a pass. No full proof was generated while
preparing this candidate. The new hosted cost run has not yet executed.

The base is Chain commit `974932be6dcfe830ce1ce92d58cb10e89cb8358d`, tree
`d4435ebdecac15e9a3fb2852eb1f835b336e452e` (the E source in PR #545).
All changes are confined to three Python observation/reading helpers, a new
profile-control test file, the new workflow, and this evidence directory.
The full relation, guest, native fixture producer, host prover/verifier, parser,
backend manifest, compiler pins and Cargo locks retain their E bytes.

## Why a separate cost window is warranted

The [original E run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40845715591)
and job `123352574943` finished with a real `work-timeout`: return code 124,
the original 5400-second prove budget, and measured owner wall time
5400.129219818 seconds. Its last host phase was `sdk-prove-enter`. Its artifact
has no receipt, independent verification result or adversarial audit result.
This remains an **original-budget failure**.

The preserved artifact is `12890157117`, 305,935 ZIP bytes, SHA-256
`5bd0f32b18dcc3af29905a7655728ec8e23402ecbac550333b68a10ac7262d7f`.
[The retained original failure](original-E-failure.json),
[independent ZIP audit](original-E-terminal-audit.json), and
[raw backend log](original-E-prove.backend-stdout.log) preserve that outcome.
The audit checked all 55 ZIP members and source/executable bindings recorded
in the artifact; it did not reconstruct or rebuild all tracked Git files.

The actual session contained 62 segments. The backend log recorded 31 core
entries with 30 observed intervals, averaging 179.83561683333335 seconds.
The separately reviewed pinned SDK serial-loop premise implies that the prior
30 segment calls returned before the 31st began; these are not retained partial
receipt files. Across the sampled backend process, CPU use continued at roughly
2 CPU seconds per wall second without a zero-CPU sampling interval. The adopted
backend wait4 row records 10,812.793775 CPU seconds. That row is not a complete
historical family CPU total and must not be added to sampled `/proc` ticks.

These observations support continuing computation as the reason this window
expired; they do not demonstrate a pipe/logging deadlock. Extrapolating the
observed mean interval to 62 segments gives **185.830137 minutes**, roughly
186 minutes. This is only planning arithmetic conditional on the cadence
persisting. It excludes final receipt work, separate verification and audit,
and is neither a completed-proof cost nor a guarantee that the new run finishes.

## Exact profile separation

| Boundary | Original profile | Explicit cost profile |
| --- | --- | --- |
| Selection | Default, or `original-5400-v1` | `--proof-profile cost-only-14400-v1` |
| Public observed prove entry | Exactly 5400 seconds | Exactly 14400 seconds |
| Ordinary non-observer measurement | Original 1–5400 second range | Refused |
| Host command | `trnm-w1-risc0-host prove`, po2 18, fixed guest/input/receipt paths | Identical command shape and fixed paths |
| Process namespace | `pon-w1-observed-process-v2` | `pon-w1-cost-observed-process-v1` |
| Observer namespace | `pon-w1-proof-process-observer-v1` | `pon-w1-cost-proof-process-observer-v1` |
| Checked result namespace | `pon-complete-w1-actual-proof-observation-v1` | `pon-complete-w1-cost-observation-v1` |
| Maximum accepted sample count | 1082 | 2882 |
| Original 5400-second qualification from cost data | Not applicable | Always `original_5400s_budget_passed: false` |

Unknown profiles, an original-profile 14400-second request, a cost profile with
any other timeout, a cost request without `--observe-proof`, and altered command
shapes are refused before creating observation output or spawning work. The
internal cost owner also refuses custom stream caps, custom sampling intervals,
a different backend index or disabled phase observation. The original low-level
short-duration controls remain available with their original 5400-second ceiling.

The reader must explicitly select the cost profile and require the observer.
It checks the process and supplement namespaces, exact budget, profile label,
source/shim/raw-log bindings, result types and complete cleanup evidence. Both
directions of old/new schema mixing are refused. The original supplement also
refuses either cost-only metadata field, even if its hash was rebound. A false
qualification boolean by itself cannot grant admission to either profile.

The owner implementation and its self-contained backend shim are shared.
The 5-second sampling interval, 16 MiB sample-byte cap, 65,536-byte sample-line
cap, all stdout/stderr caps, held executable/source bindings, leader reservation,
signal/reap ordering and separate 5-second cooperative cleanup allowance stay
unchanged. Only the explicitly selected cost profile uses the 2882-sample
count ceiling needed for its longer fixed window. Blocking kernel operations
retain the original disclosed lack of a hard real-time guarantee.

## Workflow scope and resources

The new workflow has one cost job: `ubuntu-24.04`, `timeout-minutes: 300`,
`RAYON_NUM_THREADS=2`, `CARGO_BUILD_JOBS=2`, and `contents: read`. Its only automatic
PR path is its own new workflow file; `workflow_dispatch` is also available.
It has a distinct concurrency group with cancellation disabled and distinct
output/build/artifact names. It has no matrix and no resume or segment-reuse
entry. A fresh output/build directory and the original independent fixture
producer support a from-zero observation.

The original install/build, native differential controls, independent execution,
locked guest/host build, boundary tests, strict Clippy, proof verification,
16-case actual-proof audit, source-after check and artifact retention paths
are retained. Separate verification and audit still each have 900 seconds.
The 14400-second prove window covers the same owner setup, proof work and
recording stages as the original window; it does not extend those subsequent
budgets. The overall 300-minute job cap still applies to all stages. Original
`always()` source/retention steps remain present, subject to hosted job lifetime.

Changing the shared helpers under the guest directory naturally matches the
original workflow's existing PR paths too. Publication may therefore start both
an unchanged 90-minute regression job and the one new cost job. Neither original
path is disabled or cancelled, and the new result does not replace the E failure.

Two additional resource snapshots retain actual `/proc/cpuinfo`, this snapshot
process's CPU affinity, raw process limits, membership/mount information and
available mounted-root cgroup control files. Reads are bounded and truncation
is explicit. Missing values are recorded as unavailable, never as unlimited.
The report keeps effective CPU quota and whole-family affinity unqualified:
it does not resolve every cgroup ancestor or certify each descendant's affinity.
The existing live proof-owner samples are unchanged. No affinity, quota, CPU,
memory or proof-system parameter is set or relaxed by the new snapshots.

No PoN transcript, matrix, domain, ticket predicate or admission PoW setting is
changed. Proof-system parameters remain the pinned E parameters; this cost
profile does not introduce an extra PoW puzzle or make a PQ128 security claim.

## Validation and retained corrections

[The actual local control log](local-controls.stderr.log) contains **44 passing
tests**: the original 30 reader/owner controls plus 14 new profile controls.
They include short real cost-profile processes with exits 0 and 7, finite
cleanup, original-reader refusal of cost data, exact-budget and pre-spawn
refusal cases, cross-profile/schema mutations, both sample-count boundaries,
and unchanged sample-line/byte bounds. The successful short child emits
synthetic owner-phase metadata only; it calls no SDK and writes no receipt.
It is not a proof, a throughput measurement or a cost estimate.

[Validation details](validation.json) also retain:

- The unmodified baseline rejecting the requested new profile, and the candidate
  still rejecting a default/original four-hour request.
- A real copied-interpreter fixture initially failing because its standard
  library root was not preserved. The observer correctly retained
  `host-phases-incomplete`, direct-child exit 1 and outer exit 125. Only the
  synthetic test environment was corrected to retain that interpreter's actual
  `sys.base_prefix`; the production workflow environment was not changed.
- The independent review's metadata-only counterexample: the first candidate
  accepted cost-only fields in an old-schema supplement. The exact former
  checker was reconstructed by hash; the original-field-absent control still
  passes, and all three added-field mutations now fail.
- Parsed workflow comparison against E, with only the listed profile/name and
  observation additions normalized. All other original steps and settings
  matched. All 12 shell run blocks passed `bash -n`; both inline Python blocks
  and the four changed/new Python source files parsed successfully.
- A local resource-reader smoke check, unavailable-file control and bounded
  truncation control. This local smoke data is not hosted-runner evidence.

`actionlint` was unavailable. No full workspace Rust build, hosted proof,
new proof verification, new actual-proof audit or propagation measurement is
claimed by these local checks. The dedicated workflow retains the real build
and proof gates that must execute on its published exact source.

To replay the Python controls from the repository root:

```sh
cd trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0
python3 -B -m unittest -v test_check_observations test_proof_observer_v1 test_cost_observation_profile_v1
```

To replay the original failure audit using the exact preserved ZIP and a fresh
output filename:

```sh
python3 evidence/pon-w1-complete-cost-profile-20261029/audit_original_E.py \
  --archive /absolute/path/to/complete-w1-12890157117.zip \
  --output /new/path/to/original-E-audit.json
```

A future successful cost run can provide a full receipt and its observed prove,
verify and finite negative-case costs. It still cannot by itself establish
the original 90-minute qualification, globally worst invalid-proof cost, real
network propagation cost, cheapest legal PoN solver or quantum security.
