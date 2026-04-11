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

### `operator_ack_signature_path` vs `operator_ack_digest`
- 如果有文件路径，填 `operator_ack_signature_path`
- 如果只有摘要，填 `operator_ack_digest`
- 两者都填也可以
- 至少填一个

### 未知值
- 还不知道时可先写：`TBD`
- 但如果 `rollback_owner` / `validator_owner` 全是 `TBD`，我不会把 packet 视为 usable handoff packet

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

---

## What happens after you reply

收到回填后，可直接生成：
1. updated / filled operator-handoff packet
2. 对应的缺口检查（哪些字段还不能进 public-mainnet-input）
3. 如需要，再生成一版 operator-ready summary
