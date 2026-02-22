# Trillionnium Rust L1 工业级就绪门禁清单（2026-02-22）

目标：从“预生产”收口到“可宣称工业级”。

## G0 语义与状态机一致性（必须）
- [x] Request 状态机单一源（`trnm-types::request_status`）
- [x] 非法迁移守卫 + 稳定错误码
- [x] Worker/RPC 接入迁移守卫
- [x] 状态机相关单测通过（本地 `cargo test`）

## G1 Adapter 稳定性（必须）
- [x] timeout 可配置（`TRNM_LLM_ADAPTER_TIMEOUT_MS`）
- [x] retry budget + backoff
- [x] adapter 失败统一收敛到 `FAILED_ADAPTER`
- [x] `trnm-worker-agent` 相关测试通过

## G2 CI/Gate 可持续稳定（必须）
- [ ] Nightly 连续 3 次绿色（硬条件）
- [x] request->tx binding gate 通过
- [x] request fault-injection gate 通过
- [ ] merge gate + nightly gate 在同一口径下连续稳定（建议 3 天）

### 最新检查（2026-02-22）
执行：
```bash
./scripts/check_nightly_green_streak.sh ProfAlexQI TrillionniumChain 3
```
结果：
- `nightly.green_streak=0`
- `nightly.required_streak=3`
- 判定：**未达标（阻塞工业级声明）**

## G3 可审计性与回滚（必须）
- [ ] RC evidence 包（测试摘要、脚本入口、关键日志路径）
- [ ] challenge re-exec 从模板态变为可复跑流程态
- [ ] 发布回滚演练（至少 1 次成功样本）

## G4 生产运维（建议）
- [ ] SLO/错误预算定义（延迟、失败率、恢复时间）
- [ ] 告警路由与值班策略
- [ ] 数据保留与审计周期策略

---

## 下一步执行顺序（建议）
1. **先补 G2：nightly 连续 3 绿**（每天自动检查并留痕）
2. 并行推进 G3：challenge re-exec 实跑 + RC evidence 包模板化
3. 当 G2+G3 均达标后，再对外宣称“工业级可用”
