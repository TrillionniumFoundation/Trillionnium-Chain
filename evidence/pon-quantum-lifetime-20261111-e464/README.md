# Persistent-domain policies and upstream proof withdrawal — HOLD

This is a successor of draft PR #908, source
`6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d`. The implementation checkpoint is
`1f2b0187d4522b5248294ddab318f34a63bdc5a3`. The
[single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
owns integration. These changes do not activate a protocol or qualify the
whole chain. A frozen report's reproducibility is independent of whether its
upstream implementation remains eligible for current use.

The completed observations are bound to frozen B commit
`523a4f431b65f8a52128962f5880c4030e3e05db`, tree
`51b57df779e46bb16518c5c6c7aef90e48faa06d`. The
[execution record](EXECUTION_RECORD.md) and
[machine-readable summary](execution-summary.json) retain actual results and
the separate C archival-successor scope. B has 272 completed scoped Python
methods, 105 QROM control executions and 293 CI outer methods; these counts
overlap and are not a combined unique-test total. Three strict-Clippy
attempts did not complete successfully, and regular Rust/doc tests were not
run. Whole-chain qualification remains HOLD.

## The complete reversible construction remains an existing result

The [original construction](../pon-quantum-construction-20261104/README.md)
covers nonce, noise, transcript, ticket, phase marking and uncomputation for its
declared fixed context. This successor does not relabel that result as absent.
Its gate/qubit counts remain resource upper bounds for the implemented circuit.
They are not lower bounds on an attacker's best algorithm. No quantum hardware,
physical fault-tolerance calibration or joint W1/DAA/timestamp/chainwork theorem
was produced by these changes.

## 1. Reject internally impossible Toffoli models

The prior `PhysicalModel.validate()` accepted a declared T depth larger than
either its total Toffoli decomposition depth or its T count. The retained
[counterexample](resource-model-counterexample.json) was actually evaluated
against the original source above. One such input gave 308 cycles per distance
in the old aggregate estimate, while its own serial stages require
`100 + 100 + max(1, 3) + 7 + 100 = 310`.

The corrected model refuses these contradictory inputs with
`T_DEPTH_EXCEEDS_DECOMPOSITION_DEPTH` or `T_DEPTH_EXCEEDS_T_COUNT`. Equal-depth
boundaries remain admissible. This is an internal consistency fix; it neither
calibrates a machine nor establishes an optimal implementation. The original
default physical model and the resource schema retain their meanings.

## 2. Exact finite policies after failed measurements

The [policy module](../../formal/pon-nakamoto-v1/quantum_posterior_policy.py) and
[mathematical scope](../../formal/pon-nakamoto-v1/QUANTUM_POSTERIOR_POLICY_V1.md)
add exact rational Bayes updates and Bellman optimization for a persistent
hidden marked count. Processors share the same count, and their measurements
are independent only conditional on that count. Failures update the posterior;
they do not silently draw a new domain. Refresh has an explicit setup cost.

The policy observes Boolean batch success/failure only. Each batch re-prepares
a uniform state, and candidate identities and residual coherent state are
discarded. The action set, fixed processor count and finite budget are declared
inputs. All processors pay preparation, iterations, readout and candidate
checks, including failed and zero-iteration trials. An ideal successful batch
assumes one acceptable proof at the declared proof cost. No real proof verifier
or delivery protocol is executed by this calculation.

The retained example uses `N=4`, an explicitly assumed independent ticket
probability `1/4`, one processor, iteration choices `0,1,2`, and budget `20`.
Setup/preparation/iteration/readout/check/proof costs are `2/1/1/1/1/2` in one
declared additive unit, not calibrated wall-clock time.

| Policy class | All-failures path selected by the solver | Delivery probability | Expected resource spent |
| --- | --- | --- | --- |
| Persistent domain | `q1`, then four `q0` batches | `11089/16384` | `97735/8192` |
| Paid independent refresh | `q1`, refresh, `q1`, refresh, `q1` | `29393/32768` | `195377/16384` |

The [persistent request](persistent-request.json),
[persistent report](persistent-report.json), [refresh request](refresh-request.json)
and [refresh report](refresh-report.json) retain every selected action,
posterior and charge. This finite-class optimum does not cover arbitrary
coherent, variable-time, identity-aware or adaptive network/DAA algorithms.
The actual W1 prior and independent refresh mechanism remain unproved.

## 3. RISC Zero 3.1.0 withdraws current eligibility of the selected profile

The official [v3.1.0 release](https://github.com/risc0/risc0/releases/tag/v3.1.0)
has release ID `441049704` and publication timestamp
`2026-11-10T23:26:01Z`. It states that each receipt format, including succinct,
is affected by at least one repaired issue. Upgrading and regenerating receipts
is required. The accompanying primary advisories are
[GHSA-g6qg-9j8p-7j87](https://github.com/risc0/risc0/security/advisories/GHSA-g6qg-9j8p-7j87)
and [GHSA-qvmf-qrrq-p2w4](https://github.com/risc0/zirgen/security/advisories/GHSA-qvmf-qrrq-p2w4).
This is an upstream finding, not a reproduced exploit against W1.

The new [security register](../../config/pon/w1-upstream-security-v1.json)
and [reader](../../scripts/ci/w1_upstream_security.py) inspect the actual selected
mapping, manifests, lockfiles, verifier identity, image, saved receipt, guest
ELF and original proof result. The current source-bound
[upstream report](upstream-security-report.json) finds:

| Selected backend | SDK | Recursion circuit | rv32im circuit | zkp | Groth16 dependency |
| --- | --- | --- | --- | --- | --- |
| v2 verifier | 3.0.6 | 4.0.5 | 4.0.5 | 3.0.5 | 3.0.5 |
| Hardened verifier | 3.0.6 | 4.0.5 | 4.0.5 | 3.0.5 | 3.0.5 |
| Guest v2 | 3.0.3 | 4.0.5 | 4.0.5 | 3.0.5 | 3.0.5 |
| Published patch family | 3.1.0 | 4.1.0 | 4.1.0 | 3.0.6 | 3.0.6 |

The 15 affected locked-package entries are five packages across three
backends, not 15 independent vulnerabilities. A Groth16 dependency's presence
does not establish that the selected succinct/Poseidon2 path uses Groth16.
Registry checksums are read declarations; installed crate authentication and
fresh verifier execution are not claimed.

The mandatory upstream check is now part of the proof-profile binding reader.
Its [result](proof-profile-binding-report.json) uses the fresh output namespace
`trnm-pq-proof-profile-binding-result-v2` and status
`PROFILE_BOUND_UPSTREAM_REVOKED_HOLD`. The input schema and original descriptor
semantics are retained. Both readers must observe the same source and proof
identities. Ordinary inspection succeeds as a diagnostic; `--require-current`
returns 2 with the complete diagnostic and an explicit refusal.

No profile is approved by this policy snapshot. Changing only version strings,
removing the succinct withdrawal, forging report booleans, or inserting a
self-approved profile cannot grant eligibility. A future migration needs a
reviewed coherent dependency/circuit/toolchain build, regenerated receipts and
bound verifier/control/parameter identities. The guest image may remain the
same after rebuilding and review; this change does not require gratuitously
changing the guest program. Old locks and proof bytes are retained unchanged.

## 4. Lifetime source successor without numerical security promotion

The [current input](lifetime-input.json) is byte-identical to both earlier
unknown project inputs. The [current report](lifetime-report.json) binds the
twenty reviewed sources to the implementation checkpoint above. Relative to
the prior #908 report, only the checkpoint, corrected resource-module identity
and size, and that observation's matching identity change. The other nineteen
selected sources and all arithmetic, unknowns and independent acceptance
fields remain unchanged.

The [d4d2 report](../pq-chain-convergence-20261111-d4d2/lifetime-report.json)
retains SHA-256
`ed80f8de4f4880406242411fdfeef45fdcdc0667b410a2ced18abd99f2af344e`.
The [fa62381e report](../pq-live-retry-20261111-fa62381e/lifetime-report.json)
retains SHA-256
`2c3915cd2ab8bf0e93ea47728d82ec76762ba028416da17ea21a959fd506f81e`.
The tests check these original bytes, refuse the actual old resource module,
and compare the complete successor report after only the reviewed field
substitutions. The hosted QROM comparison selects this new namespace.

The lifetime error upper bound and security bits remain null. PQ
authorization, the complete computation relation, and quantum work/chain weight
are separate acceptance lines, and all remain unqualified. STARK/FRI names,
receipt success and finite policy optimization supply no missing QROM premises
or lifetime query envelope.

## Reproduction and execution evidence

From the repository root:

```bash
python3 scripts/ci/test_w1_upstream_security.py -v
python3 scripts/ci/test_pq_proof_profile_binding.py -v
python3 scripts/ci/test_w1_lifetime_ledger.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_posterior_policy.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_oracle_resources.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_resource_clock.py -v
python3 scripts/ci/pq_proof_profile_binding.py --require-current
python3 formal/pon-nakamoto-v1/quantum_posterior_policy.py --example --require-qualified
```

The last two commands deliberately return 2 and 3 respectively after emitting
their complete unqualified diagnostics. They are refusal observations, not
successful current eligibility checks. CI requires the new controls and tests
that deleting, relocating, duplicating or suppressing them is rejected.

The implementation checkpoint is a source identity, not a claim that every
retained suite passed on that commit. The [execution record](EXECUTION_RECORD.md)
now binds the complete scoped and CI runs to B and preserves the incomplete
formal exploration that began before B and crossed HEAD changes, both
environment interruptions and all three native attempts. The third
strict-Clippy attempt returned 101 after a compiler-child
SIGKILL; its cause remains unknown. The earlier two attempts were stopped by
the owner's resource guard. Regular Rust and doc tests remain `NOT_RUN`.

The [2,377,812-byte archive](validation-evidence.tar.xz),
[159-member manifest](validation-evidence.members.json) and
[packaging record](validation-evidence.packaging.json) retain the original
streams, receipts, observers and source guards. Before/recovered/after physical
B snapshots matched 28,341 tracked entries and 2,578,941,912 bytes. The archive
fits the unchanged 4 MiB reader cap. This C evidence/documentation successor
does not relabel B executions as tests on C, and no earlier native PASS is
transferred to either source.
