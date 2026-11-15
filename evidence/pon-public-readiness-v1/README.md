# Source-bound local engineering evidence

Measured source: `c2b1ca2503aeca35873d20d1b188689369edc752`; tree: `5df72527b22520b27f5ad858bbca98456c7ad9cf`.
All 15 qualification commands passed, including the existing 48-command native/reference
regression, four new reference suites, actual socket attacks, durable transfer campaigns
and small-model training/consumption. The report retains exact source/binary hashes,
environment versions, packets, closed databases and measured outcomes. Later evidence or
documentation publication is not another runtime measurement.

**Public readiness, production activation, independent acceptance, future-window acceptance,
qualified work hardness and physical power-loss acceptance remain false.** This package
is candidate engineering evidence. Its passing commands do not authorize public activation.

## Live transfer observations

Each case has 20 blocks of 256 signed tag1 transfers at 10-second pacing and then six
empty confirmation-drain blocks. Two durable owners on one host use real TCP; the client
independently verifies transaction membership and its local depth/work confirmation policy.
The workload is closed loop: no transaction RPC/mempool, WAN, saturation, general VM or
GPU/VRAM deployment claim is made.

| Case | Confirmed transfers | Whole-campaign transfers/s | Inclusion p95 ms | Confirmation p95 s | Two-owner ledger bytes |
|---|---:|---:|---:|---:|---:|
| hot-legacy | 5120 | 20.471 | 59.787 | 60.073 | 4964352 |
| hot-protected | 5120 | 20.443 | 193.209 | 60.367 | 4964352 |
| disjoint4-protected | 5120 | 20.469 | 135.805 | 60.217 | 5029888 |
| growth-protected | 5120 | 20.256 | 2274.647 | 62.727 | 9920512 |

Inclusion-window and whole-campaign denominators remain separate. Twenty block samples
permit empirical p95 resolution; p99 and confidence guarantees are unavailable. Ledger
bytes exclude measurement artifacts; both SQLite owners are closed/checkpointed first.
All proofs, signatures, roots, confirmations and both durable stores are independently
replayed by the aggregate checker.

## Protected socket observations

Each phase requests ten seconds of attack or baseline traffic. Paid false proofs still
require full work verification; these measurements do not close that cost-amplification gate.

| Phase | Honest Submit success/attempts | Honest Head success/attempts | Cheap rejections | Paid full-work rejections | Slow preface connections |
|---|---:|---:|---:|---:|---:|
| baseline | 57/57 | 57/57 | 0 | 0 | 0 |
| unpaid_false_transcript | 62/62 | 62/62 | 369 | 0 | 0 |
| paid_false_transcript | 51/51 | 51/51 | 0 | 243 | 0 |
| slow_hello_occupancy | 44/44 | 44/44 | 0 | 0 | 201 |

These are pre-generated distinct empty blocks, not online mining or business confirmation
under attack. The v2 log separates request-template size, successfully written attacker
bodies and unknown write outcomes. It retains high-level honest/attacker attempt outcomes
and retry-inclusive elapsed times plus aggregate socket/refusal counters; individual
reconnect attempts are not separately attributed. Two fake-proof streams or three rotating
slow-preface streams are controlled loopback observations, not open-Sybil/WAN fairness,
attacker hardware lower bounds or a production service guarantee.

## Model and environment limits

The attribution campaign actually runs the existing small integer classifier trainer and
consumer on retained public retrospective inputs. Its executable profile is a fixed router
and 3x257 integer-linear insertion, at most eight contribution groups and finite subset
enumeration. Exact BA equivalence does not prove arbitrary neural-network equivalence;
finite empirical optimum does not prove globally optimal neural circuits. Synthetic
complementarity is retained separately from the actual model experiments.

The LLM adapter suite validates supplied material and plans; it does not load a real LLM,
run forward/decode or measure GPU/VRAM. The evaluator lifecycle is a separate off-chain
contract, not native public reward execution. Useful-cost accounting is limited to supplied
stages and does not cover all exceptional paths, trainers or independent verifiers.

The actual run uses Python3.12.14, NumPy1.26.4, cryptography50.0.2 and bundled OpenSSL4.0.3;
CFFI and hardware observations are retained. Pins are checked against outer and baseline
observations. These tests and the dependency update are not a complete security audit.
Source preparation reads declarations from the exact measured Git snapshot, retrieves the
declared source after squash publication and refuses arbitrary nested observation imports.

## Preserved failures and exact versions

A preserves an incomplete missing-historical-corpus-object qualification. B preserves a
complete command run whose original aggregate checker confused template bytes with total
attacker traffic; its detached-source failure is retained. B also retains eager per-transfer
nonce-query costs; current transfer construction reads once per sender per block.

C preserves its actual 1213 source/environment and successful 15-command qualification
and aggregate replay. Its later hosted/local publication job failed because it combined
`--historical` with the current-only `--native-node` selector. Original publication metadata,
raw failures and hosted results remain separately retained.

D preserves its actual a77 source, upgraded crypto environment, successful 15-command
qualification and aggregate replay. Its complete publication job then failed in the
historical native-session negative-test setup, which compared old measured source with
the newer runtime. The next source fixes that test setup by using the original measured checkout for
positive and mutated controls, and explicitly rejects using that old receipt as current
qualification. It does not weaken the actual evidence validator or rewrite historical data.

E preserves a failed qualification of the same879 source. The launch did not activate
the venv PATH, so model subprocesses selected a system Python without NumPy. F explicitly
binds every child Python search path to the observing interpreter, records its actual
executable and dependency versions, and checks them against both qualification layers.
A real poisoned-PATH negative test verifies selection; the original E failure is preserved.

The C CodeQL gate reported 11 test-transaction-sequence alerts and one conservative
identity-to-output trace. The original annotations and read-only triage are retained.
Analysis execution success is not security-gate success; alerts are not dismissed and
rules are not weakened. This package does not claim that the security gate passed.

Original nested manifests, source declarations, failed logs and historical packages remain
immutable. Root byte hashes record these observations without granting current acceptance.
Relocated publication README snapshots use `.txt` to preserve bytes without reinterpreting
relative Markdown links. Runtime changes require a new exact-source qualification.

See [PUBLIC_READINESS](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md) for
remaining implementation, resource and independent-owner obligations. Validate the tracked
package using `python3 scripts/ci/check_public_readiness_evidence.py` with pinned dependencies
and the original Git objects available. Full publication CI must be checked separately
against the final delivery commit.
