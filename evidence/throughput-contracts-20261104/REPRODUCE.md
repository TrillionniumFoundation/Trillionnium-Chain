# Throughput path and request accounting continuation

This continues the existing [PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688)
from `47b4a62463d8e1371a175c74196d52d99c5fccb8` under the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not change the original [#639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639)
four-second, sixteen-hostile-producer, six-deep independent confirmation gate,
its fixed Host, CPU credit/refill, memory allowance, proof checks or activation.

## Verification scope

The accompanying [verification record](verification.json) pins the executed
component checks to commit `fc86ed8e927a8eb4e048b160437126a6c0b96c0d` and tree
`bd26fb15aa023cbd090662384c25fa52f52b0bc8`. Subsequent integration commits can
preserve this record without inheriting its native test qualification. The record
keeps every attempted command's actual outcome, including failed compilation and
interrupted earlier checkpoints. Its five product metrics remain unmeasured.

Raw logs and binaries are not added here. Log hashes are indexes of the retained
local execution receipts, not a portable raw-log archive or independent acceptance.
The committed test sources, complete exact-test roster, lossless argv templates,
pinned toolchain/provider inputs and commands support fresh reproduction.

## Recorded component checks

All results in this table belong to the frozen commit above, with its tracked
source verified before and after each recorded command.

| Check | Recorded result | Scope |
| --- | --- | --- |
| `trnm-mvcc-fee`, all targets and features | 250 passed, 0 failed, 8 ignored | 25 harnesses, including 7 zero-test examples; ignored cost observations were not run. |
| Exact Node regression roster | 50 passed, 0 failed or ignored; 50 required-test validators passed | Request lifecycle, intake domain, parallel preparation, durable owner and Growth activation controls. |
| Python request/report controls | 282 passed | 140 native-report reader, 78 Host runner, 20 W1 fresh-service and 44 phase-reader controls. |
| Source/claim controls | 100 passed | 43 source-integrity, 35 PQ integration and 22 claim-guard controls; 486 source pins retain `HOLD_NO_GO`. |
| Strict Clippy | Passed | Workspace, all targets, all features, `-D warnings`; this type-checking does not execute native tests. |
| Repository links, formatting and locked Cargo graph | Passed | Source inventory, CI contract, repository checker, `cargo fmt --check` and locked/offline all-feature metadata. |

The first Node attempt on this source failed in compilation with SIGKILL and
Cargo exit 101, before any native test executed. Its full fifty-case denominator
is retained. The later unchanged-profile compile-only retry and the fifty actual
executions have distinct successful receipts. Compiler affinity and shared-build
admission are recorded as development build settings. Historical failed and
interrupted attempts are preserved separately, including the zero-build disk-wait
interruption; no earlier source result is promoted to this checkpoint.

The original `public_v3_from_zero` confirmation/clock acceptance test remains
unexecuted here. The original fixed-Host gates and all five product measurements
remain open or unmeasured. Component regressions do not close those gates.

## Actual changes

Non-progress continuity capacity and Growth partition/mandatory-owner checks
seek the complete relevant ordered namespaces. Future liabilities, zero-valued
rewards, all state keys in capacity totals, canonical bytes, nonce floors and
proof-account callbacks remain checked. The public `capacity_with_progress`
entry retains its full-source traversal and original callback positions: skipping
unrelated rows there would change cancellation versus malformed-state error
precedence. Both independent full-map oracles and all interruption positions are
retained. This composition preserves incoming Growth activation fences and
monetary scans from `04be5f02c84cf5cb626a53f34bc03a5bd6ff5137` plus the concurrent
records at `2e7fbaeabc396d501d9d802adc63df963f1d288c`. Complete state cloning, roots,
public progress traversal and other global validation remain separate costs.
No throughput improvement is inferred from source inspection or callback counts.

Public service startup reserves its existing shared listener slot before entering
Node/profile work. Its second owner acquisition and Growth observation checkpoints
keep the original startup deadline and stop flag. Exhausted listener capacity
cannot first block on the Node mutex. Durable epoch cleanup after service startup
still belongs to the original owner; a timeout cannot erase its recovery duty.

Optional request observation records successful socket acceptance and actual
connection/task-owner closure in `public-v3-request-lifecycle-v1`. The task may
outlive a disconnected client, or complete while response output still owns the
connection. Both timestamps remain distinct. Once-only clock publication avoids
waiting for the snapshot's row mutex. Unknown clocks remain unknown and make
measurement coverage incomplete; observations never authorize native effects.
Live snapshots expose a closure timestamp only after acquiring its close flag;
observing task closure also observes the earlier task-creation publication.

The original finite signed-confirmation test adds a same-process clock binding
after the unchanged traffic window. It retains the first business packet's exact
public request digest and converts the existing traffic/final-observation instants
to the observer epoch. A Hello digest is a peer claim, not authenticated body
receipt. The latency origin is the same-process socket accept observation; this
binding does not establish independent-operator end-to-end receipt or confirmation.
Incomplete binding or clock coverage cannot yield an exact whole-cohort latency.
Every matching retry and every unbound or unretained connection must be kept. The final verifier method may return an unconfirmed observation; a timestamp
alone never establishes successful confirmation.
Positive v2 confirmation observations additionally bind the actual required
transaction, network/parameters/genesis, included block, six-deep tip/work,
non-reorg status, returned final observation and final accepted History replay.
These report consistency checks do not replace native signature/work checks or
require another phase to pass. Contradictory positive claims are refused, not
silently converted to successful observations or measured zero.

The v2 report keeps client statuses, receiver dispatch outcomes, typed terminal
causes, late returns, unfinished observations and missing records separately.
The original v1 derivation remains explicitly reproducible. Contradictory deadline
flags cannot populate the v2 successful-ACK histogram. Receiver nested work CPU,
dispatch CPU, joined attacker-worker CPU and client CPU are separate scopes; they
are not added as an all-worker total. Missing CPU/RSS/network/disk observations
remain missing, including absent scheduled workers.

## Reproduction

Use the unchanged Rust 1.95.0 toolchain, Cargo.lock and package test profiles.
Prepare the pinned OpenSSL 3.5.9 provider through the existing
`scripts/ci/prepare_pq_provider.sh`; its exported environment and exact binary
hash must accompany all-feature runs. A reused local provider must still match
its retained preparation receipt. Keep outputs outside the checkout and preserve
failed, cancelled and incomplete attempts. Never substitute a different source
or host result for this composition.
The provider preparation script requires existing absolute `RUNNER_TEMP` and
`GITHUB_ENV` paths and writes the environment keys to `GITHUB_ENV`; a local caller
must explicitly load and export those recorded keys before invoking Cargo.

```sh
bash scripts/project-preflight.sh
cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --all-features --format-version 1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-targets --all-features -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib request_observation::tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib intake_domain_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib parallel_preparation -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test public_v3_from_zero --no-run
python3 -m unittest discover -s scripts/ci -p 'test_run_from_zero_native.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_from_zero_host_ci.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_run_w1_fresh_service_v1.py' -v
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/check_ci_contract.py
python3 -m unittest discover -s scripts/ci -p 'test_ci_source_integrity.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_pq_research_integration.py' -v
python3 scripts/ci/check_repository.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

These commands are a reproduction recipe, not a claim that every command ran.
Exact executed commands, input source identity, exits and remaining gates belong
in the accompanying verification record. Compile affinity or one compiler job
are build settings and cannot stand in for the original acceptance Host.

For mandatory single-test execution identity, invoke each complete libtest name
with `--exact --format pretty --color never`, preserve its Cargo exit and complete
log, then run `scripts/ci/check_required_native_test.py LOG --test FULL_NAME`.
That checker requires exactly one passed, nonignored invocation. Module-filter
exit zero alone is not proof that its expected tests ran.

The exact Node case roster and command templates are under
`completed_current_source_commands.node_50_exact_regressions` in the verification
record. The accompanying [exact regression helper](run-node-regressions.py) is
byte-for-byte the helper used for the recorded executions; its SHA-256 is in the
record. It predeclares all fifty cases, records each Cargo and execution-checker
exit, and keeps failed, interrupted and unexecuted cases.

For a fresh run, copy the helper outside the checkout. Place it directly beside
an isolated checkout directory named `chain`, as required by the unchanged
helper's `ROOT`. Select `fc86ed8e927a8eb4e048b160437126a6c0b96c0d` on an allowed
`fix/` development branch in that checkout, load the pinned provider environment,
and run the following from `chain`. Use new absolute output paths:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/record_pq_native_command.py \
  --kind head \
  --candidate fc86ed8e927a8eb4e048b160437126a6c0b96c0d \
  --tested fc86ed8e927a8eb4e048b160437126a6c0b96c0d \
  --output /absolute/path/to/new-node-logs \
  --label node-regressions -- \
  python3 /absolute/parent-of-chain/run-node-regressions.py \
    --expected-head fc86ed8e927a8eb4e048b160437126a6c0b96c0d \
    --output /absolute/path/to/new-node-logs/node-cases
```

The outer recorder verifies every tracked source byte before and after execution.
The helper saves the complete case denominator, both process exits and both logs;
an abrupt termination of the recorder remains incomplete. This is a new execution
of functional component controls, not original fixed-Host acceptance.

The native clock binding is exercised only by the original
`public_v3_from_zero` integration test named
`from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline`.
Compiling that target or running Python reader controls does not execute the
original fixed-Host baseline/pressure acceptance. Use its existing Host runner
and unchanged eligibility checks on an eligible host; do not provision this
shared development container as a replacement acceptance Host.

## Metric boundaries and outstanding gates

| Measurement | Required observation |
| --- | --- |
| Confirmation TPS | Unique business transactions independently confirmed within the original window, with all requested business outcomes retained. Seven block ACKs are not seven business transactions. |
| Complete release download | Verified complete release closure bytes and complete transfer duration, including retries, failures and cold preparation. |
| First token latency | Actual requested-model execution through its first generated token; downloading a Cell does not measure it. |
| Inference throughput | Actual generated-token/task counts under the same pinned runtime/model/profile and full failure denominator. |
| Model benefit per unit cost | Independent future-window utility with all training, evaluation, transfer, residency and execution costs. |

The finite confirmation fixture supplies no download, token-generation or model
utility observation. Those metrics stay unavailable. One offered transaction in
four seconds cannot establish saturated capacity or a production p99.

PQ account authorization, GrowthV2 authenticated accounts, public mutation and
recovery are still distinct supported configurations. The classical Growth
listener must not be made PQ-compatible by deleting its mismatch refusal.
Full-host isolation across Work, commit, History, Cell, cold recovery and model
execution remains open. The original fixed-Host attack-free and hostile gates,
4,105-block recovery, full ordinary model loop and independent acceptance also
remain open until their own exact-source observations pass.
