# TRNM Genesis Operator Handoff — Reply Template (2026-04-04)

用途：
- 直接复制到聊天里回填。
- 填完后发回，即可据此生成下一版 **filled operator-handoff packet**。

对应文件：
- minimal inputs checklist:
  - `trillionnium/docs/release/TRNM_GENESIS_OPERATOR_HANDOFF_MINIMAL_INPUTS_2026-04-04.md`
- fillable packet:
  - `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`

---

## Copy-paste reply template

```text
GENESIS_OPERATOR_HANDOFF_REPLY

ceremony_id=
packet_generated_at=
packet_distribution_path=
validator_set_version=
startup_order_note=
rollback_owner=

node1.validator_owner=
node1.operator_contact=
node1.operator_ack_status=
node1.operator_ack_signature_path=
node1.operator_ack_digest=

node2.validator_owner=
node2.operator_contact=
node2.operator_ack_status=
node2.operator_ack_signature_path=
node2.operator_ack_digest=

node3.validator_owner=
node3.operator_contact=
node3.operator_ack_status=
node3.operator_ack_signature_path=
node3.operator_ack_digest=

node4.validator_owner=
node4.operator_contact=
node4.operator_ack_status=
node4.operator_ack_signature_path=
node4.operator_ack_digest=
```

---

## Allowed shorthand

### `operator_ack_status`
推荐值：
- `acknowledged`
- `pending`
- `blocked`
- `acknowledged` 只有在同一 node 的 `operator_ack_signature_path` 或 `operator_ack_digest` 已经填入真实值时才可使用
- 如果 durable acknowledgment evidence 还没落盘，先用 `pending` 或 `blocked`，不要提前写成 `acknowledged`

### `operator_ack_signature_path` vs `operator_ack_digest`
- 如果有文件路径，填 `operator_ack_signature_path`
- `operator_ack_signature_path` 如果填写，必须是该 acknowledgment artifact 的**明确绝对文件路径**，不能只写目录、ticket、聊天线程名或相对路径
- 如果只有摘要，填 `operator_ack_digest`
- `operator_ack_digest` 如果填写，必须是该 acknowledgment artifact 的 **64 字符 SHA-256**
- 两者都填也可以
- 至少填一个
- 如果 `operator_ack_status` 还不是 `acknowledged`，这两项应保持为空，不要先填目录、ticket、聊天线程名或 placeholder 路径/摘要

### 未知值
- 只有非门槛备注字段才允许临时写 `TBD`，例如某个 validator 的补充说明
- `ceremony_id / packet_generated_at / packet_distribution_path / validator_set_version / genesis_artifact_path / genesis_artifact_sha256` 这些门槛字段不要写 `TBD`
- `rollback_owner / validator_owner / operator_contact / operator_ack_*` 如果仍是 `TBD` 或等价 placeholder，只能把它视为 draft，不算 usable handoff packet，更不能拿去当 `public-mainnet-input`

---

## Fastest fill order

建议按这个顺序回：
1. 先填 `ceremony_id / packet_generated_at / packet_distribution_path / validator_set_version / startup_order_note / rollback_owner`
2. 再填 4 个 `validator_owner`
3. 再填 4 个 `operator_contact`
4. 最后填 `operator_ack_*`

补充约束：
- `packet_generated_at` 必须是这次实际发出的 packet 生成时间；如果重发 packet，不要沿用旧时间戳
- `packet_distribution_path` 必须填写为共享给所有 operator 审阅的同一份 ceremony packet 文件绝对路径，不能只写目录 / ticket / artifact folder
- `packet_distribution_path` 不能与 `genesis_artifact_path` 指向同一文件
- `validator_set_version` 必须是具体、非默认的版本标签，不要回落到模板默认 `v1`
- 本模板默认上一版 packet 中的 `genesis_artifact_path=` 与 `genesis_artifact_sha256=` 仍然构成有效冻结锚点；如果其中任一项需要变化，先停止使用这份 reply template，回到 input sheet / packet generator 同步更新两项并重生成 packet

---

## What happens after you reply

收到回填后，可直接生成：
1. updated / filled operator-handoff packet
2. 对应的缺口检查（哪些字段还不能进 public-mainnet-input）
3. 如需要，再生成一版 operator-ready summary
