# TRNM Genesis Operator Handoff — Minimal Required Inputs (2026-04-04)

用途：
- 这是 **极简待填字段清单**。
- 只保留现在必须由人提供/确认的值。
- 不重复 candidate bundle / SHA256 / validator_entry_hash 等已冻结锚点。

对应文件：
- fillable packet:
  - `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`
- 详细输入表：
  - `trillionnium-rust/docs/release/TRNM_GENESIS_OPERATOR_HANDOFF_INPUT_SHEET_2026-04-04.md`

---

## A. Global fields

```text
ceremony_id=
packet_distribution_path=
validator_set_version=
startup_order_note=
rollback_owner=
```

说明：
- `packet_generated_at=` 建议在最终回填/重生成 packet 时由脚本自动使用当时 UTC 时间，不需要现在先定死。
- `genesis_artifact_path=` 与 `genesis_artifact_sha256=` 当前已经冻结，不在此清单中重复要求。

---

## B. Validator ownership / contact / acknowledgment

### node1
```text
validator_owner=
operator_contact=node1=
operator_ack_status=
operator_ack_signature_path=
operator_ack_digest=
```

### node2
```text
validator_owner=
operator_contact=node2=
operator_ack_status=
operator_ack_signature_path=
operator_ack_digest=
```

### node3
```text
validator_owner=
operator_contact=node3=
operator_ack_status=
operator_ack_signature_path=
operator_ack_digest=
```

### node4
```text
validator_owner=
operator_contact=node4=
operator_ack_status=
operator_ack_signature_path=
operator_ack_digest=
```

---

## C. Completion rule

当且仅当下面这些都齐了，才值得从 fillable packet 生成下一版 **filled operator-handoff packet**：

- Global 5 项全部有值
- `node1..node4` 的 `validator_owner` 全部有值
- `node1..node4` 的 `operator_contact` 全部有值
- `node1..node4` 的 `operator_ack_status` 全部明确（例如 `acknowledged` / `pending` / `blocked`）
- 每个节点至少有：
  - `operator_ack_signature_path` **或**
  - `operator_ack_digest`

---

## D. Fastest next move

最快的推进顺序是：
1. 先填 **Global 5 项**
2. 再填 4 个 `validator_owner`
3. 再填 4 个 `operator_contact`
4. 最后补 `operator_ack_*`

这样就能最快把当前状态从：
- draft / fillable template

推进到：
- usable operator-handoff packet
