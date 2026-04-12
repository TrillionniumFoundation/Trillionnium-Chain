# TRNM Genesis Operator Handoff Input Sheet (2026-04-04)

适用范围：
- 当前 `local-rehearsal genesis candidate` 的 **operator-handoff** 填表输入
- 不是 public-mainnet-input 最终 packet

快速入口（只看必须回答的字段）：
- `trillionnium/docs/release/TRNM_GENESIS_OPERATOR_HANDOFF_MINIMAL_INPUTS_2026-04-04.md`

评估快照：
- `origin/main = 35da4109e`
- candidate 来源 HEAD = `b74758fac`

---

## 1. 当前绑定的 candidate artifact

### Candidate bundle
- path:
  - `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.tar.gz`
- sha256:
  - `0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f`

### Candidate anchor facts
- `checkpoint_height = 1`
- `checkpoint_state_root_hex = a965ffa8c1777b4cd4009fd1a940fd2fba58fd3faa6dcd3e11655f28b213d46e`
- `checkpoint_wal_entry_hash_hex = 4f8a336dd57a0daaf1051f27362a31d21ecd4604e16076eb28a7e9b181655756`

### Existing packet files
- local-rehearsal packet:
  - `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-local-rehearsal-2026-04-04-b74758fac.packet.txt`
- operator-handoff draft packet:
  - `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-draft-2026-04-04-b74758fac.packet.txt`
- operator-handoff fillable packet:
  - `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`

---

## 2. Global handoff fields to confirm/fill

这些字段是 packet 级别的，不属于某一个 validator。

| Field | Current draft value | Action needed |
|---|---|---|
| `ceremony_scope` | `operator-handoff` | keep |
| `ceremony_id` | `genesis-operator-handoff-draft-20260404-0100Z` | 可保留，或在正式发出前改成最终 ticket id |
| `packet_generated_at` | `2026-04-04T01:00:16Z` | 若重发 packet，应重新生成 |
| `packet_distribution_path` | `<absolute-path-to-ceremony-packet>` | 确认最终共享的 **ceremony packet 文件绝对路径**；必须是 absolute path、必须指向**单一 packet 文件**、不能包含 `.` / `..` path segment、不能出现重复 `//` path separator、并且必须与 `genesis_artifact_path` 指向不同文件，避免把共享审阅 packet 和 genesis artifact 混成同一物 |
| `validator_set_version` | `operator-handoff-b74758fac` | 保留或替换都可以，但最终值必须是**真实、具体、非默认**的版本标签，且不能含 `;` / `=` separator |
| `startup_order_note` | `<controlled-4-node-bootstrap-order>` | 需要改成真实 4-node controlled bootstrap 顺序 |
| `rollback_owner` | `primary-operator` | 需要确认真实责任人 / 值班 owner |
| `genesis_artifact_path` | `<absolute-path-to-genesis-artifact>` | keep unless artifact path changes, but if this path changes you must re-freeze `genesis_artifact_sha256` in the same update; final handoff must still point to one exact artifact file/bundle absolute path，不能只写目录，且不要带 `.` / `..` path segment 或重复 `//` path separator |
| `genesis_artifact_sha256` | `0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f` | keep unless artifact bytes change；如果 `genesis_artifact_path` 改了，必须对新路径指向的同一份 artifact 重新计算完整 64-char SHA-256，不能沿用旧 hash |

### 建议最终填写区

```text
ceremony_id=
packet_generated_at=
packet_distribution_path=
validator_set_version=
startup_order_note=
rollback_owner=
```

### 2.1 Fail-closed fill contract for the two highest-risk globals

在把 draft / fillable packet 往前推进时，优先把下面两项按**脚本会拒绝坏值**的口径填死，而不是只填一个“看起来像值”的字符串：

- `packet_distribution_path=`
  - 必须是给所有 operator 审阅的**同一份 ceremony packet 文件绝对路径**
  - 不接受目录、artifact folder、ticket 根、聊天线程名、相对路径、带 `.` / `..` path segment 的路径，或包含重复 `//` path separator 的别名路径
  - 不得与 `genesis_artifact_path=` 指向同一文件
- `validator_set_version=`
  - 必须是**真实、具体、非默认**的版本标签
  - 不接受模板默认 `v1`
  - 不接受包含 `;` 或 `=` 的拼接值，避免 packet key-value 边界被破坏

如果准备切到 `public-mainnet-input`，应按上面口径先用 `trillionnium/scripts/v2/check_validator_config_bundle.py --emit-ceremony-packet --ceremony-scope public-mainnet-input ...` 预检；不要等 operator 收到 packet 后才发现字段本身不可用。

### 2.2 Fail-closed contract for the frozen genesis artifact anchor

- `genesis_artifact_path=` 与 `genesis_artifact_sha256=` 视为同一个冻结锚点: 要么两者都保持不变，要么两者一起更新；不接受只改 path 不改 hash，或只改 hash 不改 path
- 如果其中任一项要变，应先回到 genesis artifact source / input sheet 重新冻结，再生成新的 handoff packet；不要在 operator reply 阶段临时口头修补
- `genesis_artifact_path=` 必须指向一个明确 artifact 文件或 bundle member，不能只写目录、ticket、artifact folder 或“最新版本”别名
- `genesis_artifact_sha256=` 必须是 `genesis_artifact_path=` 当前指向内容的完整 64-char SHA-256，而不是历史 checksum、简写标签或聊天里口头确认的摘要

---

## 3. Validator ownership / contact / acknowledgment sheet

### 3.1 Tabular sheet

| validator_name | node_id | config_path | p2p_addr | rpc_addr | validator_entry_hash | validator_owner | operator_contact | operator_ack | operator_ack_status | operator_ack_signature_path | operator_ack_digest |
|---|---|---|---|---|---|---|---|---|---|---|---|
| node1 | node1 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node1.toml` | `127.0.0.1:26656` | `127.0.0.1:26657` | `b1ce42b559cf4ec88ef6f9e116d7d00f029595fca0922eab191bb4694d5cc6f9` |  |  |  |  |  |  |
| node2 | node2 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node2.toml` | `127.0.0.1:27656` | `127.0.0.1:27657` | `63492f510bdd87d87ab9bce5d5514586f2ed525ee8c9e76fab2f4ef4e60c9cd1` |  |  |  |  |  |  |
| node3 | node3 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node3.toml` | `127.0.0.1:28656` | `127.0.0.1:28657` | `1aed1224c589b35402852190d2e475d92844f4caa0125c721c6c1824aa2cfb71` |  |  |  |  |  |  |
| node4 | node4 | `/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node4.toml` | `127.0.0.1:29656` | `127.0.0.1:29657` | `d53c3a6e5b4fee138ae14663bc1029a4eaeeed2b0a28eec2a05469bce7755441` |  |  |  |  |  |  |

表内 fail-closed 约束：
- `operator_ack` 这一列必须直接填写该 validator owner 的真实确认文本，且要原样复用共享 packet 里的同一 `ceremony_id=`、`genesis_artifact_sha256=`、`config_path=`、`validator_name=` 与 `validator_entry_hash=`，不要只在 3.2 的 block 里另存、也不要手工改成相对路径或重算 hash
- 只有当同一 validator 的 `operator_ack=` 已经形成真实确认文本，且 `operator_ack_signature_path` 或 `operator_ack_digest` 至少一项已有真实值时，才可把 `operator_ack_status` 标记为 `acknowledged`
- 如果 durable acknowledgment evidence 还没落盘，就把 `operator_ack_status` 保持为 `pending` 或 `blocked`，并把 `operator_ack_signature_path` / `operator_ack_digest` 留空，不要先塞 placeholder 路径、ticket、聊天线程名或伪摘要

### 3.2 Ready-to-fill block per validator

#### node1
```text
validator_owner=
operator_contact=node1=<chat/email/oncall-for-node1>
operator_ack=<owner> checked ceremony_id=genesis-operator-handoff-draft-20260404-0100Z;genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node1.toml;validator_name=node1;validator_entry_hash=b1ce42b559cf4ec88ef6f9e116d7d00f029595fca0922eab191bb4694d5cc6f9
operator_ack_signature_path=
operator_ack_digest=
```

#### node2
```text
validator_owner=
operator_contact=node2=<chat/email/oncall-for-node2>
operator_ack=<owner> checked ceremony_id=genesis-operator-handoff-draft-20260404-0100Z;genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node2.toml;validator_name=node2;validator_entry_hash=63492f510bdd87d87ab9bce5d5514586f2ed525ee8c9e76fab2f4ef4e60c9cd1
operator_ack_signature_path=
operator_ack_digest=
```

#### node3
```text
validator_owner=
operator_contact=node3=<chat/email/oncall-for-node3>
operator_ack=<owner> checked ceremony_id=genesis-operator-handoff-draft-20260404-0100Z;genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node3.toml;validator_name=node3;validator_entry_hash=1aed1224c589b35402852190d2e475d92844f4caa0125c721c6c1824aa2cfb71
operator_ack_signature_path=
operator_ack_digest=
```

#### node4
```text
validator_owner=
operator_contact=node4=<chat/email/oncall-for-node4>
operator_ack=<owner> checked ceremony_id=genesis-operator-handoff-draft-20260404-0100Z;genesis_artifact_sha256=0cf37d6ae68baa3ac1af1db89c3b225cf669f072aa3f531681448dbcf995108f;config_path=/Users/qianqi/.openclaw/workspace/TrillionniumChain/trillionnium/configs/node4.toml;validator_name=node4;validator_entry_hash=d53c3a6e5b4fee138ae14663bc1029a4eaeeed2b0a28eec2a05469bce7755441
operator_ack_signature_path=
operator_ack_digest=
```

---

## 4. Definition of done for `operator-handoff`

当前这份 input sheet 被视为“填完即可把 draft packet 从 skeleton 推到 operator-handoff usable”的最小条件。

### 最小完成标准
- 4 个 `validator_owner=` 全部填写
- 4 个 `operator_contact=` 全部填写
- 4 个 `operator_ack=` 全部填写，且必须原样复用同一 validator 的 `ceremony_id=`、`config_path=` 与 `validator_entry_hash=`，不要手工改成相对路径、改写 ceremony id，或重算 hash
- 每个 validator 至少有：
  - `operator_ack_signature_path=`，且如果填写路径，必须是那份 acknowledgment artifact 的**明确绝对路径**，不能只写目录、ticket 或相对路径
  - **或** `operator_ack_digest=`，且如果填写 digest，必须是该 acknowledgment artifact 的 **64 字符 SHA-256**
- `rollback_owner=` 已明确
- `startup_order_note=` 已明确成真实 bootstrap 顺序
- `packet_distribution_path=` 指向一个真实共享的 **ceremony packet 文件绝对路径**，而不是仅本地临时路径、目录、artifact folder 或 ticket 根
- `packet_distribution_path=` 与 `genesis_artifact_path=` 必须指向不同文件，避免 operator 把共享审阅 packet 误当成 genesis artifact 本体

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
- `trillionnium/run/genesis-artifact-candidates/trnm-genesis-candidate-operator-handoff-fillable-2026-04-04-b74758fac.packet.txt`

然后再生成下一版：

> **filled operator-handoff packet**

而不是继续停留在 draft packet。 
