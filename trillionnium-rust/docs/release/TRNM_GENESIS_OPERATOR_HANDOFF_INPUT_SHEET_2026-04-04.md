# TRNM Genesis Operator Handoff Input Sheet (2026-04-04)

适用范围：
- 当前 `local-rehearsal genesis candidate` 的 **operator-handoff** 填表输入
- 不是 public-mainnet-input 最终 packet

评估快照：
- `origin/main = 35da4109e`
- candidate 来源 HEAD = `b74758fac`

---

## 1. 当前绑定的 candidate artifact

### Candidate bundle
- path:
  - `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.tar.gz`
- sha256:
  - `0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f`

### Candidate anchor facts
- `checkpoint_height = 1`
- `checkpoint_state_root_hex = a965ffa8c1777b4cd4009fd1a940fd2fba58fd3faa6dcd3e11655f28b213d46e`
- `checkpoint_wal_entry_hash_hex = 4f8a336dd57a0daaf1051f27362a31d21ecd4604e16076eb28a7e9b181655756`

### Existing packet files
- local-rehearsal packet:
  - `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.packet.txt`
- operator-handoff draft packet:
  - `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-draft-2026-04-04-b74758fac.packet.txt`
- operator-handoff fillable packet:
  - `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`

---

## 2. Global handoff fields to confirm/fill

这些字段是 packet 级别的，不属于某一个 validator。

| Field | Current draft value | Action needed |
|---|---|---|
| `ceremony_scope` | `operator-handoff` | keep |
| `ceremony_id` | `genesis-operator-handoff-draft-20260404-0100Z` | 可保留，或在正式发出前改成最终 ticket id |
| `packet_generated_at` | `2026-04-04T01:00:16Z` | 若重发 packet，应重新生成 |
| `packet_distribution_path` | candidate tar path | 确认最终共享路径 / artifact folder / ticket 附件路径 |
| `validator_set_version` | `operator-handoff-b74758fac` | 确认是否保留，或替换成更正式版本标签 |
| `startup_order_note` | 当前是 draft note | 需要改成真实 4-node controlled bootstrap 顺序 |
| `rollback_owner` | `primary-operator` | 需要确认真实责任人 / 值班 owner |
| `genesis_artifact_path` | candidate tar path | keep unless artifact path changes |
| `genesis_artifact_sha256` | `0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f` | keep unless artifact changes |

### 建议最终填写区

```text
ceremony_id=
packet_generated_at=
packet_distribution_path=
validator_set_version=
startup_order_note=
rollback_owner=
```

---

## 3. Validator ownership / contact / acknowledgment sheet

### 3.1 Tabular sheet

| validator_name | node_id | config_path | p2p_addr | rpc_addr | validator_entry_hash | validator_owner | operator_contact | operator_ack_status | operator_ack_digest_or_sig_path |
|---|---|---|---|---|---|---|---|---|---|
| node1 | node1 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node1.toml` | `127.0.0.1:26656` | `127.0.0.1:26657` | `b1ce42b559cf4ec88ef6f9e116d7d00f029595fca0922eab191bb4694d5cc6f9` |  |  |  |  |
| node2 | node2 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node2.toml` | `127.0.0.1:27656` | `127.0.0.1:27657` | `63492f510bdd87d87ab9bce5d5514586f2ed525ee8c9e76fab2f4ef4e60c9cd1` |  |  |  |  |
| node3 | node3 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node3.toml` | `127.0.0.1:28656` | `127.0.0.1:28657` | `1aed1224c589b35402852190d2e475d92844f4caa0125c721c6c1824aa2cfb71` |  |  |  |  |
| node4 | node4 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node4.toml` | `127.0.0.1:29656` | `127.0.0.1:29657` | `d53c3a6e5b4fee138ae14663bc1029a4eaeeed2b0a28eec2a05469bce7755441` |  |  |  |  |

### 3.2 Ready-to-fill block per validator

#### node1
```text
validator_owner=
operator_contact=node1=
operator_ack=<owner> checked genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node1.toml;validator_name=node1;validator_entry_hash=b1ce42b559cf4ec88ef6f9e116d7d00f029595fca0922eab191bb4694d5cc6f9
operator_ack_signature_path=
operator_ack_digest=
```

#### node2
```text
validator_owner=
operator_contact=node2=
operator_ack=<owner> checked genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node2.toml;validator_name=node2;validator_entry_hash=63492f510bdd87d87ab9bce5d5514586f2ed525ee8c9e76fab2f4ef4e60c9cd1
operator_ack_signature_path=
operator_ack_digest=
```

#### node3
```text
validator_owner=
operator_contact=node3=
operator_ack=<owner> checked genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node3.toml;validator_name=node3;validator_entry_hash=1aed1224c589b35402852190d2e475d92844f4caa0125c721c6c1824aa2cfb71
operator_ack_signature_path=
operator_ack_digest=
```

#### node4
```text
validator_owner=
operator_contact=node4=
operator_ack=<owner> checked genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium-rust/configs/node4.toml;validator_name=node4;validator_entry_hash=d53c3a6e5b4fee138ae14663bc1029a4eaeeed2b0a28eec2a05469bce7755441
operator_ack_signature_path=
operator_ack_digest=
```

---

## 4. Definition of done for `operator-handoff`

当前这份 input sheet 被视为“填完即可把 draft packet 从 skeleton 推到 operator-handoff usable”的最小条件。

### 最小完成标准
- 4 个 `validator_owner=` 全部填写
- 4 个 `operator_contact=` 全部填写
- 4 个 `operator_ack=` 全部填写
- 每个 validator 至少有：
  - `operator_ack_signature_path=` **或**
  - `operator_ack_digest=`
- `rollback_owner=` 已明确
- `startup_order_note=` 已明确成真实 bootstrap 顺序
- `packet_distribution_path=` 指向一个真实共享位置，而不是仅本地临时路径

### 仍然不等于 public mainnet closure
即便上面都填完，仍然还差：
- controlled 4-node bootstrap rehearsal evidence
- signer / network / bootstrap topology 联动闭环
- public-mainnet-input scope 下的最终 packet 与分发/回滚证据

---

## 5. Recommended next action

拿这份 input sheet 去补齐：
1. 4 个 validator owner
2. 4 个 operator contact
3. 4 条 operator acknowledgment
4. rollback owner
5. startup order note

优先编辑的文件建议改为：
- `trillionnium-rust/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`

然后再生成下一版：

> **filled operator-handoff packet**

而不是继续停留在 draft packet。 
