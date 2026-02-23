# TRNM PR-1 Tests & Docs Acceptance Checklist (2026-02-23)

> 范围：仅补齐 PR-1 配套测试与文档说明，不涉及核心业务逻辑改动。

## 1) 执行命令

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/rpc_query_hardcap_enforcement_test.sh
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/worker_real_cli_fake_wrapper_block_test.sh
```

## 2) 通过标准

- [ ] RPC hard cap：`clamp_limit_*` 用例全部通过（超限 clamp、生效默认值、范围内透传）。
- [ ] Governance value schema：
  - [ ] 非法 u64 值被 reject。
  - [ ] `emergency_pause` 非严格 bool（如 `TRUE/1/yes`）被 reject。
- [ ] Strict real-cli gate：
  - [ ] fake wrapper 路径在 strict gate 下被拦截（脚本返回非 0）。
  - [ ] 拒绝原因为“缺少有效 tx_hash / query 生命周期不可验证”等真实性失败原因。

## 3) 文档落点

- 运维入口：`OPERATIONS.md` → `PR-1 安全补丁配套门禁（Tests-Docs）`
- 测试脚本：`scripts/v2/*_test.sh`

## 4) 建议合并前最小核对

- [ ] 三个新增脚本均可直接从仓库根目录执行。
- [ ] 脚本均采用 `set -euo pipefail`。
- [ ] 未修改 `trillionnium-rust/crates/*` 核心业务逻辑文件。
