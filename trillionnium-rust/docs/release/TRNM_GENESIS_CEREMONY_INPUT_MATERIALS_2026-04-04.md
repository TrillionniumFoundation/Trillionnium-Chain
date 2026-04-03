# TRNM Genesis Ceremony Input Materials (2026-04-04)

评估快照：`origin/main = 35da4109e`

## 目标

把当前“已有 checklist / runbook / helper”的状态，推进到**第一份真实 genesis ceremony packet** 可以生成的程度。

这份文档不声称 TRNM 已完成 public-mainnet genesis closure。
它只回答一个更窄的问题：

> **如果现在要从当前 mainline 生成一份真实的 validator genesis ceremony packet，还缺哪些材料？**

---

## 1. 当前已验证的前置条件

### 1.1 Validator config bundle 路径
当前仓内可用的 validator config bundle 实际路径是：
- `trillionnium-rust/configs/node1.toml`
- `trillionnium-rust/configs/node2.toml`
- `trillionnium-rust/configs/node3.toml`
- `trillionnium-rust/configs/node4.toml`

说明：
- 相关 runbook 中原先有一层路径漂移，写成了根级 `configs/node*.toml`；
- 本轮已修正为真实路径 `trillionnium-rust/configs/node*.toml`。

### 1.2 Validator config bundle checker 可运行
已实际运行：

```bash
python3 trillionnium-rust/scripts/v2/check_validator_config_bundle.py \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
```

结果：
- `validator config bundle OK`

说明：
- 当前四节点 config bundle 至少在 node_id / rpc_addr / p2p_addr 一致性和唯一性层面是可接受的。

### 1.3 Ceremony packet skeleton 生成链路已打通
本轮发现并修复了 `trillionnium-rust/scripts/v2/check_validator_config_bundle.py` 中缺失的 packet validation helper：
- `validate_packet_line_value`
- `validate_packet_atom_value`
- `validate_packet_path`

修复后已实际验证：
- `python3 -m unittest trillionnium-rust/scripts/v2/test_check_validator_config_bundle.py` ✅
- `--emit-ceremony-packet` 能成功输出 packet skeleton ✅

这意味着：
- 从“能校验 config bundle”到“能吐出 public-mainnet-input 形态的 packet skeleton”，当前工具链已经可用。

### 1.4 Artifact discovery 现实结论
本轮还额外验证了两件最关键的事实：

1. **仓里当前没有已提交的真实 genesis artifact 文件**
   - 未找到真实 `genesis*.json` / `genesis*.toml` 等候选文件；
   - 当前仓里出现的只是 runbook / release 文档，而不是实际可分发的 genesis artifact。

2. **仓里当前也没有明确暴露的 genesis 生成入口**
   - `trnm-cli --help` 未暴露 genesis 生成子命令；
   - `trnm-node --help` 未暴露 genesis 生成子命令；
   - repo 内也未定位到一条明确的“生成并落盘 genesis artifact”的脚本/命令路径。

这意味着：
- 当前阻塞点已经不是 config bundle checker 或 packet skeleton 生成器；
- 当前真正缺的是 **真实 genesis artifact 及其来源工作流**。

---

## 2. 当前仍缺的真实输入材料

下面这些不是脚本骨架，而是**生成第一份真实 ceremony packet 时必须明确填写的真实输入**。

| 材料 | 当前状态 | 说明 |
|---|---|---|
| `genesis_artifact_path=` | 缺失 | 需要一份真实 genesis 文件或 bundle 的绝对路径 |
| `genesis_artifact_sha256=` | 缺失 | 需要与上面的真实 artifact 严格绑定的 64-char SHA256 |
| `ceremony_id=` | 缺失 | 需要一个非模板、可审计、可引用的唯一 ceremony id |
| `packet_generated_at=` | 可现场生成 | 需要在生成 packet 当时写入 UTC 时间戳 |
| `packet_distribution_path=` | 缺失 | 需要一个真实共享分发路径（绝对路径 / ticket / artifact folder） |
| `validator_set_version=` | 缺失 | 需要一个真实版本标签，不能继续用默认 `v1` |
| `startup_order_note=` | 缺失 | 需要明确启动顺序或说明顺序不敏感 |
| `rollback_owner=` | 缺失 | 需要明确谁有权宣布本轮 ceremony abort / rollback |
| `validator_owner=` per node | 缺失 | 每个 validator 要有真实 owner，不是 `<owner>` |
| `operator_contact=` per node | 缺失 | 每个 validator 要有真实联系入口 |
| `operator_ack=` per node | 缺失 | 需要真实 acknowledgment，而不是 placeholder |
| `operator_ack_signature_path=` or digest | 缺失 | 若要进入可审计 mainnet packet，需要 durable ack evidence |

---

## 3. 当前已知可直接复用的真实值

这些值现在已经可以直接从当前 mainline 和现有 bundle 里拿：

### 3.1 Config bundle files
- `trillionnium-rust/configs/node1.toml`
- `trillionnium-rust/configs/node2.toml`
- `trillionnium-rust/configs/node3.toml`
- `trillionnium-rust/configs/node4.toml`

### 3.2 Validator identities / addresses（从当前 bundle 推出）
- `node1`: `p2p_addr=127.0.0.1:26656`, `rpc_addr=127.0.0.1:26657`
- `node2`: `p2p_addr=127.0.0.1:27656`, `rpc_addr=127.0.0.1:27657`
- `node3`: `p2p_addr=127.0.0.1:28656`, `rpc_addr=127.0.0.1:28657`
- `node4`: `p2p_addr=127.0.0.1:29656`, `rpc_addr=127.0.0.1:29657`

### 3.3 当前 bundle 下已可稳定生成的 `validator_entry_hash`
- `node1` → `b1ce42b559cf4ec88ef6f9e116d7d00f029595fca0922eab191bb4694d5cc6f9`
- `node2` → `63492f510bdd87d87ab9bce5d5514586f2ed525ee8c9e76fab2f4ef4e60c9cd1`
- `node3` → `1aed1224c589b35402852190d2e475d92844f4caa0125c721c6c1824aa2cfb71`
- `node4` → `d53c3a6e5b4fee138ae14663bc1029a4eaeeed2b0a28eec2a05469bce7755441`

说明：
- 这些 hash 依赖于当前 `validator_name/node_id/config_path/p2p_addr/rpc_addr` 组合；
- 如果 config path 或监听地址变化，这些 hash 也会随之变化。

---

## 4. 第一份真实 packet 需要的最小材料包

如果现在就要生成一份**不再是 placeholder 的 ceremony packet**，最少需要先补齐下面这一包：

### 4.1 Genesis artifact 基础信息
1. 真实 genesis 文件的绝对路径
2. 该文件的 SHA256
3. 该 genesis 对应的 validator set version
4. genesis source note（谁生成、从哪条 workflow/命令生成）

### 4.2 Ceremony metadata
1. `ceremony_id=`（例如 `mn04-bootstrap-20260404-0130Z`）
2. `packet_generated_at=`（UTC）
3. `packet_distribution_path=`
4. `startup_order_note=`
5. `rollback_owner=`

### 4.3 Operator ownership / acknowledgment
1. `node1..node4` 各自的 validator owner
2. 各自 operator contact
3. 每个 operator 对同一 packet 的 acknowledgment
4. 每个 operator acknowledgment 的持久化证据（signature path 或 digest）

---

## 5. 可直接复用的生成命令模板

等上面的真实输入都准备好后，可以直接用下面这条命令生成第一份真实 packet：

```bash
python3 trillionnium-rust/scripts/v2/check_validator_config_bundle.py \
  --emit-ceremony-packet \
  --ceremony-scope public-mainnet-input \
  --ceremony-id <real-ceremony-id> \
  --packet-generated-at <real-utc-timestamp> \
  --packet-distribution-path <absolute-packet-path> \
  --validator-set-version <real-validator-set-version> \
  --startup-order-note '<real-startup-order-note>' \
  --rollback-owner <real-rollback-owner> \
  --genesis-artifact-path <absolute-genesis-artifact-path> \
  --genesis-artifact-sha256 <real-64-char-sha256> \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
```

---

## 6. 现在离“第一份真实 packet”最近的阻塞点

如果只看当前最短路径，离第一份真实 packet 最近的不是代码，而是**输入材料缺失**：

### 当前最直接 blocker
1. **没有真实 genesis artifact path**
2. **没有真实 genesis hash**
3. **没有 validator owners / contacts / acknowledgments**
4. **没有真实 packet distribution path**
5. **没有在 repo 内定位到明确的 genesis artifact 生成入口**

也就是说：

> 现在已经不是“脚本不会跑”的阶段，
> 而是“缺真实 ceremony 输入材料”的阶段。

---

## 7. 下一步最小动作建议

如果要继续往前推进，最小可执行顺序是：

1. **先确定真实 genesis artifact 路径与 SHA256**
2. **给 node1~node4 填上真实 validator owner / contact**
3. **确定 packet distribution path 与 rollback owner**
4. **然后再生成第一份非 placeholder ceremony packet**

在这四步里，当前最值得先做的是：

> **先把真实 genesis artifact path + SHA256 定出来。**

因为没有它，后面的 packet 仍然只是格式正确的骨架，而不是可用于 ceremony 的真实输入。
