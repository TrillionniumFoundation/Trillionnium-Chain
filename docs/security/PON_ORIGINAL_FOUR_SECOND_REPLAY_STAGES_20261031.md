# Original four-second W1 confirmation: per-page replay instrumentation

**Research-only · HOLD · no production activation · not PQ-128.**

This is a source-level observation extension for the unchanged native `from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline` test. It adds no grants, timeouts, threads, scheduling preference, admission bypass, signature/proof shortcut, or extra CPU credit.

## Exact prior measured failure

The original [required baseline run 41182805121](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41182805121) at SHA `4aee60b75d87b974b1d82bd1694d2eb3159c29fd` retained `from-zero-native/confirmation/report.json` in [its native artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41182805121/artifacts/13035259479).

- No attack: seven signed transactions finished around 208 ms, all seven History calls around 2,297 ms, six-deep independently verified client confirmation around 2,681 ms, inside original 4,000 ms.
- Sixteen hostile W1 producers: seven signed submits finished around 1,462 ms, only three History calls completed around 1,561 / 2,859 / 3,660 ms; no independent confirmation before 4,000 ms.
- Under pressure, the total `pending_grant_wait_ns=18,520,483,411` and `queue_wait_ns=4,159,440,905` are **aggregates across waiters**; neither is one request's latency nor measured p99. No invalid W1 was accepted.
- Old aggregate replay CPU/wall encompass different completed page counts; comparing attack-free and pressured totals is not an equal-workload efficiency proof.

See the [P0 actual 4s failure #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) and [whole-chain security #629](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/629).

## New actual native evidence

Every **successful in-window History response** produces one item in `independent_history_page_replay`, keyed by its exact index into `honest_history`. It records request completion, actual native import start/end/wall nanoseconds, current-caller-thread CPU nanoseconds (or null if OS clock unavailable), prior/next page cursor, and success/failure. Failed network calls remain in `honest_history` but create no fabricated replay interval. The final `independent_final_confirmation_stage`, if reached, measures the true independent confirmation call; otherwise it stays null.

The observations are diagnostics and do not grant effect authority. They do **not** claim W1 work hardness, quantum resistance, production capacity, physical resource lower bounds, or a successful 4s business target.

## Independent acceptance before any blocker is closed

```bash
bash scripts/project-preflight.sh --audit
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test public_v3_from_zero from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline -- --nocapture
bash scripts/ci/ci_job.sh protocol-contract
```

Retain raw failed/native report and exact head/prospective-merge identities. Compare per-page replay, queue pressure, CPU and response latency across repeated hardware-matched runs, keeping original 16 attackers and the 4s gate. **Only real native business success on the original constraints plus independent review can close #639.** The six separate PQ-128 qualification gates remain open.
