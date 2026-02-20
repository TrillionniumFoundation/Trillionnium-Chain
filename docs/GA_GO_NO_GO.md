# GA Go/No-Go Decision (Rust L1 P2.2)

Date: 2026-02-20
Decision owner: Trillionnium Rust L1 release gate

## Gate Criteria
GA requires all of:
1. Stage2 nightly observation reaches >=24h with no hard-fail regression.
2. Testnet preflight has >=2 consecutive successes on current mainline.
3. Clean-environment `release_rc.sh` reproduction remains pass.

## Current Evaluation

### 1) Stage2 nightly observation
- Status: **PENDING**
- Signal: currently green on multiple consecutive runs (latest includes `22213079988`).
- Gap: >=24h observation window not yet formally closed.

### 2) Testnet preflight consecutive success
- Status: **PASS**
- Evidence:
  - `trillionnium-rust/run/preflight/go-no-go-20260220-123300.txt` (`status=GO`)
  - `trillionnium-rust/run/preflight/go-no-go-20260220-123431.txt` (`status=GO`)

### 3) Clean-environment reproduction
- Status: **PASS (carried from Post-RC record)**
- Reference: Post-RC clean-environment verification remained pass.

## Decision
**NO-GO (temporary)**

Rationale:
- Only one blocking item remains: stage2 >=24h observation window closure.
- All other release-gate signals are currently pass.

## Release Risk Snapshot
- Functional risk: low (hard gates green).
- Consistency risk: low (state-root audit clean in preflight).
- Performance-threshold risk: low-to-moderate (non-blocking `tuning-recommended` advisory present).

## Aggressive Strategy Technical Decision (2026-02-20)

### Scope
Recent mainline changes evaluated in this window:
- `288b7d5` — CI hard gate for aggressive/original regression with workload-specific thresholds
- `70ff424` — aggressive hot-path clone removal + hotspot analysis doc
- `f3cc0c3` — aggressive keyset allocation/intersection overhead reduction
- `d6b0b53` — profiling metric `candidate_groups_scanned`
- `f4bbc58` — aggressive profile summarizer script
- `10c3269` — configurable aggressive scan window (`TRNM_AGGR_SCAN_WINDOW`, default full scan)

### Current empirical signal
Representative mixed workload (`txs=20000 keys=2000 read_fanout=3 write_every=2`):
- Original: ~`37ms`
- AggressiveGreedy: ~`84-87ms`
- Ratio: ~`2.3x`
- Candidate scan metric: `~21749`

### Decision
- **AggressiveGreedy remains experimental/non-default**.
- Keep nightly hard gate to prevent silent regression.
- Aggressive optimization may continue, but not a GA blocker.

### Promotion condition for aggressive path
To enter default-candidate discussion, aggressive must satisfy both:
1. Stable ratio target on representative mixed workload: **<1.8x Original**.
2. Clear candidate-scan reduction with no safety regression (tests + nightly hard gates green).

## Immediate Next Step
- Continue nightly stage2 sampling and close the 24h window.
- Keep aggressive optimization in experimental lane with the above promotion condition.
- Once stage2 window closes without hard-fail regressions, update decision to **GO** and tag non-RC GA release.
