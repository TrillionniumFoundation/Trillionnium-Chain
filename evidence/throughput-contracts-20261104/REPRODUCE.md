# Throughput path and request accounting continuation

This continues the existing [PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688)
from `47b4a62463d8e1371a175c74196d52d99c5fccb8` under the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not change the original [#639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639)
four-second, sixteen-hostile-producer, six-deep independent confirmation gate,
its fixed Host, CPU credit/refill, memory allowance, proof checks or activation.

## Actual changes

Continuity capacity and Growth partition/mandatory-owner checks seek the complete
relevant ordered namespaces. Future liabilities, zero-valued rewards, all state
keys in capacity totals, canonical bytes, nonce floors and proof-account callbacks
remain checked. An independent retained full-map capacity oracle covers outputs,
malformed rows, error precedence and cancellation. This removes unrelated-row
traversal in these functions; complete state cloning, roots and other global
validation remain separate costs. No throughput improvement is inferred from
fewer traversal callbacks.

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

The original finite signed-confirmation test adds a same-process clock binding
after the unchanged traffic window. It retains the first business packet's exact
public request digest and converts the existing traffic/final-observation instants
to the observer epoch. A Hello digest is a peer claim, not authenticated body
receipt. Every matching retry and every unbound or unretained connection must be
kept. The final verifier method may return an unconfirmed observation; a timestamp
alone never establishes successful confirmation.

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

```sh
bash scripts/project-preflight.sh
cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --format-version 1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-targets --all-features -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib request_observation::tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib intake_domain_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib parallel_preparation -- --test-threads=1
python3 -m unittest discover -s scripts/ci -p 'test_run_from_zero_native.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_run_from_zero_host.py' -v
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
