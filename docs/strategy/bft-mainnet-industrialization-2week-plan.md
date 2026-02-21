# BFT 主网工业化两周执行计划（P0/P1）

更新：2026-02-21  
目标：从“BFT 原型 + 门禁”推进到“主网前工业化候选版本”。

---

## 总目标（2 周）

- 建立可持久化的 BFT 共识状态机（round/lock/vote WAL）。
- 建立真实节点间共识消息链路（签名、去重、重放保护）。
- 建立双签证据 -> slashing 事件 -> 参数化处罚闭环。
- 完成 20~50 节点混沌验证首轮（分区/抖动/重启）。

---

## Week 1（P0，阻塞项）

### P0-1 共识状态持久化（WAL + 恢复）
**交付**
- `trnm-node` 增加 `consensus_wal/`：
  - `height/round/step`
  - `locked_block_hash`
  - `prevote/precommit` 摘要
- 崩溃恢复：重启后从 WAL 恢复，不回退 safety。

**验收门槛**
- 新增 `check_bft_restart_recovery.sh`：连续 kill -9/重启 20 轮无 safety 违例。
- 日志必须出现：`[bft-recover] restored height=... round=... lock=...`

---

### P0-2 共识消息与签名（最小 P2P）
**交付**
- 消息类型：`Proposal/Prevote/Precommit/RoundChange`。
- 每条消息带 `height/round/type/hash/signer/sig/nonce`。
- 本地签名校验与 nonce anti-replay。

**验收门槛**
- `check_bft_message_auth.sh`：伪造签名、重放包、旧 nonce 必须被拒绝。
- 必须产出拒绝事件：`[bft-net] reject reason=bad_sig|replay|stale_nonce`。

---

### P0-3 Round-change 与 timeout 参数化
**交付**
- timeout 参数：`propose/prevote/precommit`。
- round-change 触发条件和 backoff 策略。

**验收门槛**
- `check_bft_round_change.sh`：注入 1 轮 no-quorum 后可在后续轮提交。
- 指标门槛：`bft_round_change_total > 0` 且 `bft_committed_heights > 0`。

---

## Week 2（P1，工业化增强）

### P1-1 双签证据与 slashing 执行闭环
**交付**
- 双签证据结构化落盘：`evidence/double_vote/*.json`。
- 链上/状态层处罚事件：`slash_validator`（先最小实现）。

**验收门槛**
- `check_bft_double_vote_slash.sh`：注入双签后必须出现：
  - `[bft-slash] event=double_vote`
  - `[bft-slash] action=slash_validator`

---

### P1-2 规模与混沌测试（20~50 节点）
**交付**
- 新增 `run_bft_chaos_matrix.sh`：
  - 场景：网络分区、随机延迟、节点重启、少量拜占庭
- 输出统一报告：`run/health/bft-chaos-matrix-<ts>.md`

**验收门槛**
- 安全性：无 conflicting commit（同高度双块提交）。
- 活性：恢复窗口内持续推进高度。

---

### P1-3 SRE/运维最小集
**交付**
- 指标面板字段（Prometheus 文本先行）：
  - `bft_round_change_total`
  - `bft_double_vote_total`
  - `bft_commit_latency_ms_{p50,p95}`
- runbook：故障处理、回滚、参数调整。

**验收门槛**
- 新增 `docs/runbooks/bft-mainnet-readiness.md`。
- nightly 与 merge gate 均纳入 BFT 关键 smoke。

---

## 强门禁（完成态）

合并前必须全部通过：
1. `check_bft_4node_smoke.sh`
2. `check_bft_restart_recovery.sh`
3. `check_bft_message_auth.sh`
4. `check_bft_round_change.sh`
5. `check_bft_double_vote_slash.sh`

---

## Go / No-Go 标准（两周末）

**Go 条件（全部满足）**
- Safety：无双提交冲突。
- Liveness：故障恢复后持续出块。
- Security：重放/伪造/双签具备可审计拒绝与处罚链路。
- Ops：runbook + metrics + gate 完整可复现。

**No-Go 任一触发**
- 出现 conflicting commit。
- 恢复后高度停滞超过阈值。
- 关键攻击路径（重放/双签）无法稳定复现或处罚。
