# Joint source closure and bounded component repairs — 2026-11-04

**Status: HOLD / NO-GO. All production acceptance gates remain open.** This packet
records two bounded source repairs, actual source-integrity counterexamples in the
Hepta companion, and the limits of their validation. It does not qualify the
combined Chain/Hepta system, activate PQ policy, or replace the native W1 verifier.
The [machine-readable summary](summary.json) contains exact source and record hashes.

## Source identities and P0 boundary

| Observation | Frozen identity and scope |
| --- | --- |
| Component experiments | Chain `d0737cf5434894ce47fad8082376fc417313c2cb` plus the selected source SHA-256 hashes in `summary.json`. This is the base for the scan measurements, extracted controls, original/retry Node builds, and QIR checks. |
| Preserved concurrent integration | Delivery parent `245146c7d2e6f7dfcda463f6a7dd342d4d7ca818`, tree `3081dfefa8b56506a61770d6de3adc49f55cba2c`. This preserves the earlier `bd2777f9` Legacy reorg observations and the subsequent complete-journal recovery pins, PQ release roles and fixed-provider TLS controls. Earlier component measurements and the separate bd2777 library lint are not relabelled as this later combination. |
| Delivered candidate | The Git commit containing this packet identifies the delivered candidate. Candidate sources were not finally committed when the component runs occurred; no final self-referential SHA is invented here. |
| Separate combined library lint | The preserved `bd2777f9` parent plus the two native admission files passed strict Node library Clippy. Its record hashes 101 dependency-listed source/config files and observes no drift among 1,126 tracked Rust/Cargo files. It executes no Node tests. |
| Actual V8 counterexamples | Hepta runtime repository `TrillionniumFoundation/hepta-private-ci`, commit `e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53`; its V8 contract selects Chain `73ab6e9a83bcc836e261d93f9bb23ceafe556758`, tree `65a2100f3feccc29a096a3348c109d77f0a656c2`. This is an explicitly older pair. |

This is a frozen set of **candidate source inputs**, not completion of P0. There
is no claim that all observations used one Chain/Hepta pair or one deployment
profile. Final delivery-commit source controls and the final Hepta source pin are
recorded separately by the integrator; earlier observations retain their identities.

### Existing assets, authority paths, work configuration, and thresholds

The existing [PQ authority surface audit](../../docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md)
is the first-pass asset inventory: classical Ed25519 authorities, ML-DSA-65 PQ
authority, and separate account/transport/Hepta protocol surfaces. Its own limits
remain in force; a scanner inventory is not a complete current authority proof.
The [whole-chain claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
keeps successful diagnostic execution distinct from PQ acceptance.

| Surface | Actual path or existing specification | Configuration and unresolved boundary |
| --- | --- | --- |
| Chain ordinary development CLI | [main.rs](../../trillionnium/crates/trnm-pon-node/src/main.rs) development `Settings` / `PublicServer` path | Classical development identity is not automatically replaced by the separately selected PQ owner. |
| Chain PQ application / continuous owner | [pq_application_v6.rs](../../trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs), [operator_continuous_owner.rs](../../trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs), [PQ continuous startup](../../docs/security/PQ_CONTINUOUS_STARTUP_V3.md) | Explicit PQ application construction and continuous-owner selection have their own policy and state. Their existence does not prove every ordinary entry requires PQ. |
| Hepta effect host and explicitly selected PQ authorizer | At frozen runtime `e0b4c82e`: [automation_effect_host.rs](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-agentd/src/automation_effect_host.rs) → [authorized_effect.rs](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-automation/src/authorized_effect.rs); separately [final_use_authorizer.rs](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-infer-worker-host/src/final_use_authorizer.rs) and [pq.rs](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-infer-worker-host/src/final_use_authorizer/pq.rs) | The inspected automation-host V1/V3 configuration uses classical `FinalUseAuthority` / `SignedFinalUseGrant`. The runtime authorizer explicitly selects `ml_dsa65_v2`, calls the PQ path, and requires its external clock/frontier and revocation feed. This confirms distinct configured paths, not universal PQ policy or complete governance/recovery coverage. |
| GrowthV2 and PQ state owners | [store.rs](../../trillionnium/crates/trnm-pon-node/src/store.rs), [growth profile](../../trillionnium/crates/trnm-pon-node/src/store/growth/profile.rs), [growth transport](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs) | `PermanentAccountGrowthV2` is distinct from PQ owners. `with_native_growth` rejects PQ identity; growth operations are 6–8 and do not supply a Growth History route. Their production composition remains open. |
| Fixed work / transition inputs | [work profile](../../config/pon/work-profile-v1.json), [devnet](../../config/pon/devnet-v1.json), [PQ transition](../../config/pon/post-quantum-transition-v1.json), [work security acceptance](../../config/pon/work-security-acceptance-v1.json) | Hashes are recorded in `summary.json`. Existing candidate and diagnostic assumptions do not establish fastest-adversary cost or deployment security. |
| Original performance gate | [six-axis performance contract](../../config/pon/performance-six-axis-v1.json) | 4 seconds, 16 hostile workers, at least one unique confirmed transaction at depth 6, Host CPU quota 250 ms/second, and 2 GiB Host memory, with its existing subconditions. None is weakened by this packet. |

## A: actual V8 source-integrity bypass; V9 companion repair

The unmodified V8 verifier was exercised against its real selected commit/tree,
with 584 tracked scoped paths materialized. The exact baseline accepted 42 pinned
files. Changing an omitted local dependency, `scripts/llm_runtime_release.py`,
while setting either `assume-unchanged` or `skip-worktree` also **incorrectly
accepted**. The same change without hidden index flags was rejected, and a hidden
change to a listed pinned file was rejected by the direct byte check. These
controls distinguish a real coverage gap from an indiscriminately accepting test.

An ignored `scripts/llm_runtime_pilot/__init__.py` additionally shadowed the
unchanged pinned module: verification accepted and normal Python import executed
the unlisted package sentinel. No verifier monkeypatch was used. The omitted
release module is imported on `llm_cell_release.py`'s runtime-material branch;
this observation does not claim that every training invocation enters that branch.

The inspected local dependency closure grows from 42 to 43 required members. V9
source checking, hidden-index rejection, ignored importable-extra rejection, and
validation of the actual ordered merge are being delivered in a **separate Hepta
companion candidate**. This Chain packet does not assert that companion's final
commit or execution status. Static local Python closure is not a complete Python
sandbox or an inventory of all external package code. These repairs do not close
A1 current authorization, A2 migration, or A3 effect/recovery semantics.

## B1: count canonical bytes without allocating the temporary output

The [admission scan](../../trillionnium/crates/trnm-pon-node/src/store/detached_admission.rs)
now sends the same `serde_json` serialization to a checked counting writer instead
of allocating each cell's canonical output `Vec`. Locked `serde_json` 1.0.149 was
checked against its Cargo archive checksum: `to_vec` allocates an initial 128-byte
Vec and invokes the same `to_writer`. Serialization order, escaping and number
formatting therefore retain the same serializer; the destination changes.

Sticky byte-count overflow still lets serialization finish, so a serializer error
retains priority over a capacity error. Checked outer key/value sums, the exact
8 MiB inclusive boundary, progress callbacks before indices 0, 256, 512, …, and
held fallback/epoch/commit checks remain. The added
[controls](../../trillionnium/crates/trnm-pon-node/src/store/detached_admission/tests.rs)
cover canonical values, escapes/UTF-8, overflow/error ordering, threshold edges,
empty input and cancellation.

**The preparation scan still holds the original Node mutex and still traverses
the parent State up to the threshold.** This change removes temporary serialized
buffers. It neither removes the whole-State scan nor establishes GrowthV2/PQ
composition, native end-to-end latency, or the original hostile-producer gate.

### Finite paired observation, including the regressions

The copied [observer](measure_snapshot_payload.py) mechanically extracts the old
and current scan functions and uses actual M06 State/ExecutionControl and Node
Error types. Four synthetic State families had four warmup scans per arm and 32
paired rounds, alternating AB/BA order. Separate allocation and timing binaries
retain all 256 sample batches per binary; the timing binary has no custom
allocator. This is a scan-only harness, without Node, SQL, Host, or public ingress.

| State family | Repeats per timing batch | Paired median time change | Buffered batch p95 (ms) | Counted batch p95 (ms) | Batch p95 change |
| --- | ---: | ---: | ---: | ---: | ---: |
| account64 | 64 | −12.99% | 5.292146 | 8.097355 | **+53.01%** |
| account1024 | 32 | −10.15% | 34.818039 | 40.221044 | **+15.52%** |
| escaped1024 | 16 | −50.27% | 78.647007 | 41.986361 | −46.61% |
| large2048 | 4 | −7.21% | 57.267030 | 50.791066 | −11.31% |

The paired median is the median of each pair's percentage change, not the ratio
of the two arm medians. The p95 is nearest-rank over 32 **whole batches**, not
independent per-request or per-scan latency. Both account cohorts exceed the
existing 10% maximum p95 regression. **The complete cohort does not pass the
paired performance acceptance condition**, despite lower medians.

The counted scan observed zero allocator calls within these sampled scans.
Buffered allocation counts were 64, 1,024, 1,024 and 2,043; the last case returned
held after 2,043 visited entries at 8,390,601 bytes. Allocation columns measure
requested allocator traffic, not RSS, live heap or physical copy volume.

### Native validation and retained failures

| Run | Actual result | Allowed conclusion |
| --- | --- | --- |
| Qualified SQLite boundary, d073 candidate | 13 passed / 0 failed / 0 ignored | Pass for `sqlite-3.51.3-normal-native-linux-layout-v3`; no Node admission acceptance. |
| Extracted exact new controls with actual dependency types | 2 passed / 0 failed / 0 ignored | Finite semantic controls only. The original 1-pass/1-fail error-message comparison is retained; the test was corrected to compare the same Node error conversion. |
| Original-profile Node detached module | Cargo exit 101; rustc SIGKILL (signal 9) during lib-test compilation | **No Node tests executed.** No passed or failed Node-test count can be inferred. |
| Command-line `codegen-units=64` retry | Cargo exit 101; rustc SIGKILL (signal 9) | **No Node tests executed.** Source Cargo profiles were unchanged. |
| Strict Node production library Clippy, d073 candidate | Exit 0 with `-D warnings` | Rust library lint only. Optional SQLite layout unqualified in this lint environment. |
| Separate strict library Clippy, bd2777 combined candidate | Exit 0 with `-D warnings` | Combined library lint only; no lib-test execution and the same optional SQLite limitation. |

The shared build cgroup had an 8 GiB limit; retained postfailure snapshots showed
memory near that limit and its shared `oom_kill` counter changing from 12 to 13.
Concurrent work shares those counters, so neither all counters nor a fully
independent causal OOM diagnosis is attributed to these runs. Three earlier
interrupted setup attempts and a boundary run with an unqualified loader layout
remain recorded. Clippy injected a different rustup loader path than the selected
absolute runtime compiler; it cannot replace the separately qualified SQLite run.

## C2: validate reversible artifact construction, not just sample outputs

The [QIR decoder](../../formal/pon-nakamoto-v1/reversible_components.py) now checks
the declared compute/copy/exact-inverse structure before accepting an artifact:
compute may target scratch only, inputs cannot be written, outputs cannot be used
during compute, output copies use only X/CNOT and cannot duplicate targets, and
the cleanup suffix must exactly reverse the compute prefix. This is a structural
condition for the restricted construction, rather than a finite sample standing
in for cleanup on all inputs. It does not prove the claimed function is correct.

Running the expanded suite against the old implementation exposed 16 failing
adversarial subcases and one zero-gate reader error across 17 test methods. The
fixed suite passed **17/17**, with no errors or skips. Complete generated component
netlists were written, reopened through the decoder and basis-simulated:

| Component | Logical qubits | Compute gates | Total gates | Serialized bytes | Independent numerical / cleanup checks |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fq32 multiplication | 6,550 | 9,701 | 19,434 | 156,051 | 113/113 |
| SHA-256 compression, all 64 rounds | 117,293 | 193,885 | 388,026 | 3,109,204 | 7/7 complete messages |

The output hashes equal the earlier component artifacts. Neither generated bytes
nor wire fields changed. A zero-gate all-zero function already emitted by
`Circuit.finish()` is now readable, fixing a constructor/decoder mismatch. Old
readers still reject that case; new readers reject some structures previously
accepted. Therefore complete reader compatibility is not claimed. QIR1 remains
an internal construction format; any future generic external exchange must
state its acceptance profile explicitly. Direct construction/metrics/encoding
APIs are not substitutes for `decode` validation. Input-mutating arbitrary
reversible circuits remain outside this construction even if later restored.

The [component specification](../../formal/pon-nakamoto-v1/REVERSIBLE_COMPONENTS.md)
retains its scope: no complete W1 quantum oracle, coherent rejection sampler,
quantum hardware execution, physical fault-tolerant resource model, fastest legal
adversary, private-branch security theorem or DAA closure is established. No
signature domain, native W1 relation, consensus encoding or activation changed.

## C1 / D: historical results stay historical

The existing [complete W1 Succinct proof](../pon-w1-complete-succinct-20261028/README.md)
uses source `64be7c4ad51d432e7736ad135476262e23e968f5` and its separately pinned
hardened verifier. Its 256,886-byte receipt is 5.2225 times the 49,188-byte native
witness; fixed-input hardened decode-and-verify median 16.660953 ms is about
30.0526 times native decode-and-replay median 0.5543925 ms. That candidate failed
its practical benefit criterion. The original timeout and interrupted controller
remain historical nonpasses, despite a verified saved proof.

Those proof observations, earlier work-cost studies and published quantum models
are not rerun evidence for this candidate pair. This packet does not replace W1,
turn honest FLOPs into an adversarial lower bound, or close a post-quantum claim.

## Source controls and reproducibility

Before the concurrent integration, six source-negative-control modules passed
101/101. Inventory and CI-contract checks passed. The first repository check
failed because the plan linked this README before it existed; that original
failure remains recorded. The preserved concurrent commit fixes four preexisting
PQ pin mismatches; this candidate adds the production admission file pin and
updates its test pin. After preserving the recovery/release/TLS integration, the current manifest has
**411 pinned blobs / 326 required paths**. Intermediate candidates had 399 / 311
and 394 / 306. Those scopes are not interchanged. Default locked offline Cargo metadata resolved **26 workspace
packages / 175 packages**; workspace formatting passed. Final delivery-commit
controls are separate from these earlier observations.

Run component controls from the repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_reversible_components.py -v
python3 formal/pon-nakamoto-v1/reversible_components.py --output /absolute/fresh/qir-observation
```

The scan observer preserves the actual run's execution logic and command-line
parameters. Its module docstring alone is clarified to state that Node call-graph
validation requires a separate native run. Supply a fresh
output directory, an absolute compatible compiler, and a target directory whose
`debug/deps` contains exactly one matching rlib for each required dependency
(`serde`, `serde_json`, `trnm_mvcc_fee`, `trnm_transport`, `rusqlite`). It refuses
ambiguous or absent dependencies. Cached dependency identity and compile flags
are recorded by the script; rerunning with different dependencies is a new
observation, not reproduction of an identical frozen binary.

```sh
python3 evidence/joint-source-closure-20261104/measure_snapshot_payload.py \
  --repo /absolute/Chain-checkout \
  --target /absolute/compatible-cargo-target \
  --rustc /absolute/rustc \
  --base d0737cf5434894ce47fad8082376fc417313c2cb \
  --output /absolute/fresh/scan-observation \
  --native-dir /absolute/native-library-directory
```

`--native-dir` is optional and repeatable. The script writes harnesses, binary
identities, allocation samples and timing samples; it does not run Node tests or
produce the summary statistics itself. The formulas and sample counts above and
in `summary.json` specify the aggregation. Both actual Node lib-test attempts in
this packet failed to compile and executed no tests.

The exact unsuccessful original and retry commands are retained in `summary.json`:

```sh
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-pon-node --lib store::detached_admission::tests:: -- --nocapture
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline --config profile.test.package.trnm-pon-node.codegen-units=64 -p trnm-pon-node --lib store::detached_admission::tests:: -- --nocapture
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-pon-node --lib -- -D warnings
```

This packet includes the small summary and reproducible observer, not raw logs,
compiled binaries or QIR files. Hashes identify the original local records; they
do not claim those omitted records are publicly available here.

## Acceptance ledger

| Workstream | Status after this packet |
| --- | --- |
| P0 | Open: candidate inputs and explicit historical identities, without one fully accepted deployment pair and complete current authority audit. |
| A1 / A2 / A3 | Open: source-integrity repairs do not prove universal PQ authorization, normal migration, external-witness recovery or exactly-once effects. |
| B1 / B2 | Open: allocation reduction is measured; full scan and original lock remain, account batch tails regress, native detached tests did not run, and the 4-second / 16-producer gate is unqualified. |
| C1 / C2 | Open: legal solver cost, reuse, deployment quantum thresholds, branch/reorg risk and DAA assumptions remain to be closed. |
| D | Open: no beneficial replacement proof backend is accepted for this combination. |
| E | Open: no fixed-pair real-task multi-node independent acceptance is established. |

The [single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the workflow owner. Production activation, whole-chain PQ qualification,
public-network readiness and independent acceptance all remain **false**.
