# Stage2 Observation Window (Rust L1)

Date: 2026-02-20
Scope: `rust-l1-nightly-health` with default `THRESHOLD_PROFILE=stage2`

## Objective
Confirm a stable observation window before GA promotion:
- Window length: >=24h
- No hard-fail regressions on nightly hard gates

## Evidence Collected (current)
Recent successful nightly runs:
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22217009176
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22213079988
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212857297
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212698732
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212430161
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212233282
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212130031
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22211994785
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22211546536

Observed signal:
- Hard gates passed (workspace tests / state-root audit / parallel sanity / v1 event freeze / regression gate).
- Non-blocking annotation observed: `tuning-recommended` (advisory only, not a release blocker).
- One overlapping manual nightly dispatch was auto-cancelled (`22217007203`), while the latest nightly run (`22217009176`) completed successfully.

## Testnet Preflight (supporting signal)
Recent successful testnet-preflight runs on current mainline:
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22217011583
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22213082298
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212856463
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212698755
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212429718
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212232767
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22212126726
- https://github.com/ProfAlexQI/TrillionniumChain/actions/runs/22211994589

## Window Assessment
Current status: **GO (owner override)**

Reason:
- Nightly signal is continuously green across recent runs.
- Decision owner authorized immediate GA progression before formal >=24h closure.

## Next Checkpoint
1. Continue collecting nightly stage2 samples until >=24h window is satisfied.
2. Reconfirm no hard-fail regressions within that window.
3. Issue final GA decision note (Go/No-Go).
