# Exact-source CI failure evidence — 2026-11-01

This is a finite diagnostic collection, not release approval or whole-chain PQ qualification.

## Source and provenance

Current candidate: `d2fabdd3757b89db84763d632aeedfe84f9fce4f`.
Tree: `b4d4cca6da8244cf9c7d479eca0974559f4a1005`.
Base: `64cb26b53ed82be14049000387040ba119f00e1e`.
Actual prospective merge: `66a0a0e9f7679bcbdef0aab5c111ef0bdde6a927`, with the same tree.

The manifest binds every included file's exact bytes, source job/artifact and original archive SHA-256. All eight downloaded archives were checked against GitHub's artifact digest before extraction. ZIP archives, ELF executables and SQLite databases are omitted from this collection. Their absence is explicit: the runner's recorded ELF check and stable executable hash are evidence of its validation, not a local independent re-read of ELF bytes.

## Original workspace test profile

Run `41333398659` built the complete workspace with:

```text
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features --no-run --message-format=json
```

All four builds and profile/ELF checks passed. Actual Node artifacts have opt-level 3, and M06's ordinary dependency rlib has opt-level 1. Both retain debug assertions and overflow checks. The actual feature sets are `default,pq-native-openssl`. Compiler metadata, build command/environment, before/after source identity and stable binary hashes are retained per lane.

The two unchanged original large-state selectors both failed with `PUBLIC_MUTATION_CPU_BUDGET` in every lane. The two unchanged reactor-exit controls each passed in every lane. The result is **eight capacity failures and eight exit-control passes**, not workspace or complete Node-suite acceptance.

| Lane | Ordinary complete-state CPU | Authenticated complete-state CPU |
| --- | ---: | ---: |
| x64 head | 2,911,730,384 ns | 2,845,037,907 ns |
| x64 prospective merge | 2,561,012,338 ns | 3,029,933,751 ns |
| ARM head | 2,908,861,528 ns | 3,529,302,552 ns |
| ARM prospective merge | 2,867,237,992 ns | 3,508,753,160 ns |

These are original owner/worker settlement receipts, not an invented absolute two-second limit. The raw logs also retain refill, balance and refusal observations. Successful default-release run `41333398587` is a different profile and does not satisfy this gate.

## Original four-second business confirmation

The current protocol-head, cost-x64 and cost-ARM artifacts in run `41333398704` each show five successful named native invariant/accounting controls. The independent aggregate reader then rejects `CONFIRMATION_TARGET`: the same offered business transaction is confirmed without pressure but is not confirmed inside the original four-second hostile window. No post-window drain is credited.

| Source / lane | Unattacked confirmation | Pressure confirmation |
| --- | --- | --- |
| d2 protocol x64 | 1/1 in 3.401745147 s | 0/1 |
| d2 cost x64 | 1/1 in 2.395907559 s | 0/1 |
| d2 cost ARM | 1/1 in 2.194912207 s | 0/1 |
| Earlier b97 protocol x64 | 1/1 in 2.897804531 s | 0/1 |

The earlier artifact is from `b97f63254df260243186f14c6e177ab96fffdcd8`, tree `a61aa2029758386a6278bc6d58debc0f590e6d15`, run `41293784189`, artifact `13079060614`. Its raw report establishes that this business-gate failure predates the witness change. The direct 64cb parent's relevant lane was cancelled; this collection does not claim zero new performance effect or a controlled performance comparison.

The complete raw confirmation JSON is preserved for all four observations. Full finite-service/sustained raw reports are omitted because this collection diagnoses the failed confirmation gate; their original manifest hashes and full artifact identities remain available. The transcript reader does not independently authenticate work, signatures, state transitions or operator independence.

## Other failures and isolated repair

The original external-evidence job failed at `durable backend variants`: the strict source reader did not yet recognize the newly introduced `PqWitnessV4` mapping. The included narrow repair recognizes its exact namespace, three-part DDL composition and owner inputs while continuing to export only the legacy evidence schema. It rejects attempts to relabel ordinary evidence as witness evidence. The original 51 tests plus four new tests passed locally, 55 total, in 255.508 seconds, exit zero. This does not retrospectively turn the failed CI run green.

The required prospective runtime shard stopped in M06: 91 passed, one failed and six ignored. Its concurrent callback probe failed `arithmetic.0.try_lock().is_ok()` and produced `WORKER_PANIC` instead of the expected cancellation. The preserved file came unchanged from upstream 8a77/64cb. The source diagnosis is that concurrent test probes can contend with each other's temporary guard; the original raw failure is retained. This collection does not record a repaired M06 execution, and that failed shard did not reach the Node suite.

History, W1/work competition, production network, full Node suite and whole-chain PQ acceptance remain outside these results.

## Readback

```text
python3 recheck.py --repo /absolute/path/to/exact-candidate-checkout
```

The script validates the retained file hashes and original reader bytes, re-reads named test transcripts and applies the original confirmation reader. It does not compile or execute native code. `readback.json` records the actual local readback, including all rejected outcomes. Source and process receipts remain required; this diagnostic is not a new security authority.
