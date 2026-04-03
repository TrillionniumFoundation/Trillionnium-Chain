# Web4 6点修复补丁序列收口证据（2026-03-04）

> 历史证据说明：本文档仅证明 **2026-03-04 这组 Web4 修复序列** 当时通过了列出的门禁；不应被解读为当前整个仓库或当前 Web4 状态已自动 release-ready。当前口径请以仓库根 `RELEASE_READINESS.md` 为准。
>
> 审计边界字段（引用本页时建议连同以下字段一起引用，避免脱离当前 truth-source）：
> - `truth_source=RELEASE_READINESS.md`
> - `historical_evidence_only=true`
> - `evidence_scope=web4_fix_sequence_2026-03-04_historical_gate_evidence_only`
> - `evidence_date=2026-03-04`

## 固定补丁序列 SHA（本次6点任务）

1. `42a67a45` `fix(frontend): require ChainTask.createdAt across contract`
2. `a24b68b4` `fix(frontend): remove inferred task owner semantics in rpc adapter`
3. `7f451483` `fix(api): harden capability-audit subject token reverse lookup`
4. `4ca762e9` `fix(rpc): harden HTTP request-line parsing without split_whitespace`

> 注意：分支存在自动迭代并行提交，当前分支头部已前移到 `12507900`，但上述4个提交构成本次修复序列的固定审计锚点。

## 门禁执行结果

- `cargo test --workspace`：PASS
- `./scripts/v2/web4_release_aggregate_gate.sh`：PASS（日志尾部确认 `[WEB4-RELEASE][PASS] all required Web4 high-risk gates passed`）
- 前端相关步骤（1/2）额外门禁：
  - `npm run lint`：PASS
  - `npm run typecheck`：PASS
  - `npm run test --if-present`：PASS
  - `npm run build`：PASS

## 回滚说明

按步骤独立回滚（建议逆序执行）：

```bash
git revert 4ca762e9
git revert 7f451483
git revert a24b68b4
git revert 42a67a45
```

若仅回滚某一步，可单独执行对应 `git revert <sha>`。

## 复现命令

```bash
# 前端（步骤1/2）
cd web4-frontend
npm run lint && npm run typecheck && npm run test --if-present && npm run build

# 全仓
cd ../trillionnium-rust
cargo test --workspace

cd ..
./scripts/v2/web4_release_aggregate_gate.sh
```
