# TRNM Challenge Scripts (Top 5)

这组脚本对应“下一周挑战计划”前 5 项，目标是**快速复现实证风险**。

## Scripts

1. `01_rpc_pending_pool_spam.sh`
   - 非法签名交易批量打入 `send-tx`，观察 pending 池膨胀
2. `02_rpc_pending_to_fail_probe.sh`
   - 抽样 `get-tx`，验证“先 pending 后 fail”的延迟验签路径
3. `03_relay_from_spoof_probe.sh`
   - 同 session 下切换 `from` 身份，检查是否可冒用
4. `04_relay_source_quota_bypass_probe.sh`
   - 轮换 `source` 字段，评估配额绕过可能
5. `05_bft_message_auth_gate_strength_probe.sh`
   - 生成最小伪日志，检测 gate 脚本对计数异常的敏感度

## Quick Start

```bash
cd TrillionniumChain
chmod +x scripts/challenges/*.sh

# 1) 垃圾池挑战
scripts/challenges/01_rpc_pending_pool_spam.sh

# 2) 延迟验签挑战
scripts/challenges/02_rpc_pending_to_fail_probe.sh

# 3) relay 身份冒用
scripts/challenges/03_relay_from_spoof_probe.sh

# 4) source 轮换绕过
scripts/challenges/04_relay_source_quota_bypass_probe.sh

# 5) BFT gate 证明力
scripts/challenges/05_bft_message_auth_gate_strength_probe.sh
```

## Notes

- 脚本默认尽量“轻量、可回滚、可重复”；不会删除仓库内容。
- 需要本地已可用 `trnm-rpc`/`cargo` 环境。
- 若某脚本因环境缺失失败，先记录“环境阻塞”，再继续其他脚本。
