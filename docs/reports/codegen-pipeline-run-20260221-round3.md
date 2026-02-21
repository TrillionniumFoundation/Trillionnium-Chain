# Codegen Pipeline Run Report (2026-02-21, Round 3)

- pipeline: `scripts/run_codegen_pipeline.sh`
- run_id: `relay-20260221-125141-77886`
- result: **ok=21, fail=0**
- summary: `data/auto-relay/relay-20260221-125141-77886/summary.md`

## Coverage (updated)
- A1/A2/A3 + v1 protocol/event gates
- B1/B2/B3 governance path gates
- C1/C2/C3 ecosystem path hooks
- `scripts/v2/worker_agent_full_loop.sh`
- `scripts/v2/worker_replay_guard_test.sh`
- `scripts/v2/worker_failed_receipt_test.sh` (**new hard gate**)
- `scripts/v2/post_vote_verification.sh`
- `scripts/v2/emergency_pause_drill.sh`
- `scripts/demo_storyline.sh`

## Outcome
- 全链路 21 步全部通过；新增 worker failed-receipt 门禁稳定通过。
- 当前 pipeline 可作为 worker 回执硬门禁落地后的基线验收入口。
