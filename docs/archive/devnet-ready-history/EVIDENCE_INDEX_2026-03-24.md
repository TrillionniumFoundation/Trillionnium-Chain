# Evidence index — devnet-ready (2026-03-24)

BL09 retirement-prep note: 本索引中保留的 `trnm-pouw` crate / test inventory / devnet evidence 引用，仅应用于内部 bring-up 历史留痕、迁移期兼容说明与 provenance / audit evidence 汇总，不能解读为当前默认 payout authority，也不重新授权默认 work-unit payout path。若 PoCO settlement 已成为主结算路径，对外付款判断与默认结算 authority 仍应以 PoCO settlement anchor 为准。

## Positive evidence

- Stage-1 checklist:
  - `docs/release/TRNM_STAGE1_DEVNET_READY_CHECKLIST_2026-03-24.md`
- 4-node BFT smoke:
  - `trillionnium/run/bft4-smoke-20260324-163130.txt`
  - `trillionnium/run/bft4-node1-20260324-163130.log`
  - `trillionnium/run/bft4-node2-20260324-163130.log`
  - `trillionnium/run/bft4-node3-20260324-163130.log`
  - `trillionnium/run/bft4-node4-20260324-163130.log`
- Test inventories:
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-state.tests.list`
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-rpc.tests.list`
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-node.tests.list`
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-pouw.tests.list`
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-worker-agent.tests.list`
  - `trillionnium/artifacts/devnet-ready/testlists/trnm-cli.tests.list`

## Blocking evidence

- Repo hygiene snapshot:
  - `docs/archive/devnet-ready-history/repo-hygiene-2026-03-24.json`

## Interpretation guardrail

这些证据只支持以下表述：
- “最小内部 devnet bring-up 路径存在且 4-node smoke 通过”；
- “关键 crate 的测试面已固化为可审计 inventory”；
- “当前仓库仍有大规模 dirty tree，因此不能直接上升为 RC-ready / release-ready。”
