# Quantum winner resources and DAA event experiments

Status: **conditional research and implementation checks; quantum mining security
remains unqualified**. This continuation adds no consensus activation, new chain
score or production confirmation guarantee. The machine-readable
[reproduction manifest](reproduction.json) binds the source bytes, commands and
observed results. The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Changes and source scope

The continuation uses the existing PR #688 integration branch. It preserves the
concurrent evaluation-integrity commit `d0737cf5434894ce47fad8082376fc417313c2cb`
and Legacy-observation commit `bd2777f9cc74df10ba07ae8202584ed0fb90a519`, whose
actual tree is `2cba5b274d0d09074a5716c802bc58e5c3735678`.
The tested research checkpoint is `9cecbf32ddbeb56c8556730d2d0102aff1e54310`,
tree `8d6a81ace525dec80be79932dc1272aef2575983`. The new code is confined to formal
research, tests and CI invocation; native DAA, chainwork and fork choice are
unchanged. Native checks below ran on that committed native source, with 1,176
native/configuration input files verified against their Git blobs before and
after execution. Git comparisons confirm the native/configuration inputs also
match the tested research checkpoint. All 74 Python research tests and the
30-run campaign were repeated at that checkpoint; the campaign's committed-source
claim is true and independently checked. Within this continuation, finalization
only updates prose and the reproduction record; its executable research and CI
bytes are unchanged.

Publication also preserves concurrent recovery/release-authority commit
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818` by retaining both histories and both
development-plan additions. Its checkpoint-store/release-bundle, PQ transport,
source inventory and lockfile changes have their own evidence. The 1,176-input
native observation above remains bound to the tested checkpoint; it is not a
claim that every native/configuration file is unchanged in the combined tree.
The publication-boundary check in the manifest compares the actual DAA test
dependency/source scope separately. No whole-workspace or PQ-release result is
transferred from this continuation's DAA tests.

Fresh locked/offline metadata retains the same 149-package Node dependency
closure and 11 local crates, including identical resolved features, edges,
package/target metadata and applicable lock entries. The two changed security
crates are outside that closure. All 412 local runtime/source/manifest files and
250 retained native dep-info inputs match the tested scope; none of the 24
incoming files intersects those retained inputs. This is a dependency/source
equivalence review, not a new native execution or merged-workspace qualification.

- [quantum_oracle_resources.py](../../formal/pon-nakamoto-v1/quantum_oracle_resources.py)
  accounts for task preprocessing, per-search setup, trial preparation, forward
  compute, inverse compute, marking, diffusion and abandoned work. Every measured
  candidate pays a classical winner check, including failed and zero-iteration
  trials. Full proof generation and propagation are charged after a winner.
- [quantum_network_sim.py](../../formal/pon-nakamoto-v1/quantum_network_sim.py)
  models classical Poisson arrivals, finite Grover trials, proof completion,
  message delay, participation shocks and private-fork release. Required work
  and timestamp rules are branch local. Equal work retains the receiver's tip.
- [quantum_network_campaign.py](../../formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py)
  writes bounded seeded traces, verifies source/commitment claims, independently
  checks integer work and ancestor admission time, and replays each run.
- The [research contract](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
  states the minimal-predicate, protocol and literature boundaries. The two new
  unit suites are included in the existing `repository-truth` CI job.

No complete W1 reversible oracle was synthesized. Its logical qubits, gates,
depth and physical cost remain unknown. A complete **non-W1 hypothetical example**
exercises the accounting and conditional surface-code calculation. Caller-supplied
error rates, factory throughput, routing, gate decomposition and clock periods
are assumptions, not device measurements or lower bounds.

## Observed checks

| Check | Observed result | Interpretation |
| --- | --- | --- |
| New resource tests | 22 passed | Compute/uncompute, all measured candidates, interrupted work, parallel costs, strict inputs and error budgets |
| New network/campaign tests | 22 passed | Timing, native confirmation work/depth, private future parents, replay, bounds and tamper rejection |
| Retained DAA arithmetic tests | 18 passed | Existing periodic/isolated-policy controls retained |
| Retained quantum sensitivity tests | 6 passed | Existing claim and scenario boundaries retained |
| Retained reversible component tests | 6 passed | Basis-state component controls, including dirty-ancilla rejection; not a full W1 oracle |
| Seeded network campaign | 30/30 horizons; 77,847 trace rows; replay passed | Ten scenarios at seeds 4101, 4102 and 4103 |
| Original native release DAA suite | 2 passed; zero failed, ignored or filtered | Original complete-proof admission and store tests |
| Separate scalar proof readback | 84 unique full proofs; 85 observations | Full transcript/product recomputation, 83 observed native-admitted packets and two time rejections |
| Original malformed-reader controls | 10 passed | Edited reports, proof/ancestry/work/reopen/rejection changes and false qualification rejected |
| Rust formatting / scoped strict Clippy | Both passed | Workspace formatting; release/all-feature DAA test target with `-D warnings` |
| Locked offline Cargo graph | 26 workspace members, 180 packages | Actual retained dependency graph; no dependency fetches |
| Source/claim controls | 22 claim-guard tests and 16 project-boundary tests passed | Whole-chain PQ claim remains `HOLD` / `UNQUALIFIED` |

The native fresh report has SHA-256
`c08f5c11419656408ee179ea49f41701c2edcb25178dc9b963b995a460cb62db`.
Ordinary, lower-clamp and upper-clamp next-block work is respectively 31, 123 and
7; selected cumulative required work is 761. The scalar reader does not itself
perform native database admission or reopen: those actions belong to the native
tests. The separate development review is not an external cryptographic audit.

An early DAA-model test invocation lacked a usable Git HEAD; it passed unchanged
after the exact Git objects were restored. Two project-boundary subprocesses
initially exceeded their existing ten-second timeout under shared-host load;
the unchanged 16-test suite then passed. No timeout, acceptance budget or test
selection was relaxed. Full archived-evidence repository checks and the whole
Rust workspace test suite are not claimed here. Source Markdown links were
checked using materialized files plus the exact Git tree for historical targets.

## What the finite campaign shows

Each row below lists results for seeds 4101 / 4102 / 4103. These are observations
under synthetic clocks, not attack probabilities or security thresholds.

| Scenario | Selected observation |
| --- | --- |
| Quantum miner following the public tip | 101 / 119 / 109 canceled searches |
| Quantum miner retaining a private branch | 0 / 0 / 0 canceled searches; 25 private blocks in each run |
| Long proof and network delay | Maximum observer reorg depths 3 / 5 / 4 |
| Faster hypothetical private oracle | Reorg depths 77 / 88 / 84; one confirmed-probe reversal per run |
| Fixed 540-round overshoot | 14 failed trials and one unfinished trial per run; no winning block |
| Phased private timestamps over 3,600 seconds | 1,805 blocks per run were future-dated when privately built; no observed deep reorg |

The fast-oracle scenario changes the assumed iteration time from 0.15 to 0.01
seconds. Its miner is initially faster than all classical miners together. It is
**not an empirical small-quantum-miner difficulty attack**. The public/private
comparison also does not establish profit or a lower bound: fixed iterations or
the first probability peak are merely configured strategies, not a search over
the cheapest possible adversary.

Private mining may extend a future-dated parent. Receiving miners defer each
ineligible ancestor and may adopt an eligible prefix in the meantime. A child
with an earlier timestamp cannot make its future parent admissible sooner.
Confirmation requires both six descendants and six times the inclusion block's
required work, excluding the inclusion block from those counts. These details
are checked because simpler treatments would distort attacker cost and timing.

## Reproduction

Run from the repository root with Python 3.12. The observed Rust toolchain was
1.95.0; the optional all-feature provider was OpenSSL 3.5.9. Python-only research
uses the standard library. Choose new output directories for every campaign;
existing outputs are rejected rather than overwritten.

```bash
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_oracle_resources.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_network_sim.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_daa_model.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_reversible_components.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_pq_quantum_daa_scenarios.py' -v
python3 formal/pon-nakamoto-v1/quantum_oracle_resources.py --demo
python3 formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py --out /tmp/trnm-quantum-campaign
python3 formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py --verify /tmp/trnm-quantum-campaign
```

For native reproduction, use the existing
[provider preparation](../../scripts/ci/prepare_pq_provider.sh) and its emitted
environment, or an already verified matching provider. Preserve `Cargo.lock`.
The observed run used a separate target directory, two build jobs, one Rust test
thread and an already populated offline dependency cache. `--offline` requires
that cache; it is not a promise that a clean machine has the dependencies.

```bash
export CARGO_TARGET_DIR=/tmp/trnm-quantum-native-target
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1
export TRNM_DAA_EVIDENCE_DIR=/tmp/trnm-quantum-native-evidence
cargo metadata --locked --offline --all-features --manifest-path trillionnium/Cargo.toml --format-version 1
cargo test --locked --offline --release --all-features --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test daa_adversarial_schedule -- --nocapture
python3 scripts/pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR" --expected-report-sha256 c08f5c11419656408ee179ea49f41701c2edcb25178dc9b963b995a460cb62db
python3 scripts/ci/test_pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR" -v
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo clippy --locked --offline --release --all-features --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test daa_adversarial_schedule -- -D warnings
```

The repository stores code and this compact reproduction record. Generated trace
archives, native packets, binaries and build directories are regenerated by the
commands. Reproducing seeded event rows does not require matching measured CPU
time, local output paths or the enclosing report hash across machines. Exact
floating-point event replay assumes compatible Python/RNG/math behavior;
cross-architecture identity was not tested. Integer credit is checked separately.

## Open research conditions

1. Synthesize and adversarially optimize the complete W1 winner predicate,
   including data access, legal precomputation and reuse. Account for error
   correction and actual hardware before estimating quantum competitiveness.
2. Reproduce the complete CRYPTO 2026 Fast Difficulty Adjustment protocol and
   parameter conditions before comparing it as a protocol. Its abstract and
   institutional explainer were accessible; the full ePrint PDF returned 403.
   The requested backend therefore raises an explicit unimplemented error.
3. Establish joint DAA/fork-choice security under a justified mixed-resource
   model. The current arithmetic, isolated ASERT sensitivity and finite network
   observations establish no common-prefix, chain-growth, chain-quality or
   transaction-liveness theorem. They do not justify `sqrt(D)` chain weight.

The pure-PoN engineering line retains its native rules. These open conditions
remain visible in the [research contract](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
and the single development plan.
