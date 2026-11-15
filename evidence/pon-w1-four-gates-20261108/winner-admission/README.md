# 保留 W1 声明的 Node admission 阻碍

**结论：11 月 7 日的两份 fresh proof 不能在保持原声明不变的前提下，补成当前 Growth Node 的 admission 证据。** 它们使用固定的 **318 字节 PNH1 v1** header；Growth 使用 **354 字节 PGH2** header，并把账户 witness 纳入另一个 challenge domain。legacy PNH1 入口也仍缺少对应的合法父链、完整 Packet 和父状态任务资格。

本记录仅执行原件读取和源码对照。**Node submit 为 0，实际负向 admission 事件为 0，新 proof 为 0。** `UNKNOWN_PARENT`、`ROOT`、`GROWTH_PACKET_REQUIRED` 等是源码中的条件拒绝点，不是本轮执行结果。两份原证明各 43 segment / 43 lift / 42 join 的原数学证明事实保留，Node admission 继续 HOLD。

完整机器记录在 [diagnosis.json](diagnosis.json)，逐文件源码身份及精确引用位置在 [source-pins.json](source-pins.json)。源码取自整合 worktree 的逐文件读回；这不是最终已提交候选的资格证明。

## 原 318 字节 header

SHA-256 为 `7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f`。它与原 49,506 字节 `input.bin` 的前 318 字节逐字节相同。两份 receipt 共享这一个声明；本诊断没有再次验证 receipt。

| 字段 | 原件中的值 | admission 尚需的依据 |
| --- | --- | --- |
| magic / version | `PNH1` / `1` | 与选择的 Node backend/wire profile 一致 |
| parent | `05` 重复 32 字节 | 该精确 ID 的合法父区块、父 State 和祖先记录 |
| height / timestamp | `1` / `1` | 父高度加一及该分支实际时间规则 |
| target | `ff` 重复 32 字节 | 由同一父分支计算出的 target；未把字面值直接判为非法 |
| miner | `07` 重复 32 字节 | 真实候选构造所用 miner |
| transactions | `08` 重复 32 字节 | 完整交易体的 `sequence_root` 必须精确匹配 |
| state / receipts | `09` / `0a` 分别重复 32 字节 | 原父状态与执行结果所建立的承诺 |
| work_task | `ec934f3a9f196a9d5d4555a6361d8d200ea4e95145db4bf19db1eca84f15ff6a` | 原父状态中的任务资格、实际材料，以及适用的 manifest/lease |
| nonce | `0` | 原实际搜索记录；不能改写后沿用旧证明 |

`pon_w1_native_winner_v2.rs` 读取外部 header template，只修改 `[310,318)` 的 nonce。它验证 A/B、task、外部 commitments 和完整 native W1 ticket，输出明确保留 `parent_eligibility_checked=false` 与 `node_admission=false`。源码并未构造或验证上述父链及状态上下文。

## 两个具体入口的边界

`pon_wire::Header::challenge()` 使用 `hash("challenge", header.encode())`。`pon_growth::GrowthHeader::challenge()` 使用 `hash("permanent-account-growth-challenge-v2", PGH2 || ledger || witness)`；PGH2 长度为 354。`GrowthWorkCheckedPacket::verify_with_progress()` 按后者验证。给旧 header 外包 PGH2 结构会改变工作声明，不能保留原 proof 的资格。

`Node::admit(&Packet, observed_now)` 的 `precheck_owner_packet()` 在 Growth backend 上拒绝 PNH1 Packet，条件错误为 `GROWTH_PACKET_REQUIRED`。在受支持的 legacy backend 上，`check_admission_header_context()` 仍读取精确 parent、校验 height、分支 target、时间和交易根；`record()` 无对应行时返回 `UNKNOWN_PARENT`。`check_admission_parent()` 进一步取得真实父 State、判定任务资格并绑定 manifest 的 A/B commitments。现有保留材料没有提供与固定父 ID、固定根对应的这些上下文；不能从单个 receipt 验证成功补出它们。

资金研究 Node 的 NativeTask/M12 维护区块属于自己的完整 Packet 与上下文。它们的 Reserve、Cancel 或退款事实不能代替这个固定 PNH1 中奖 header 的 admission。

## 下一次 full generation 前的最小合法材料配方

1. **先确定实际 Node backend 和 wire profile。** 当前 Growth 要求 PGH2/PNP2；现有 native-winner/proving 接口接受 318 字节 PNH1。Growth 需要先实现并资格验证兼容 witness/challenge 的 proving 接口，本次未做该协议扩展。保留的 PNH1 研究入口只能按其自身受支持配置使用。
2. **从隔离研究 Node 的正常 API 建立候选。** 保留实际 parent block/State、祖先 target/time、完整交易体、任务资格和 A/B。现有入口包括 Growth 的 `make_growth_consensus_maintenance`，以及适用 PNH1 配置中的 `prepare_with_task` / `make_with_task` 或显式 `make_consensus_maintenance`。
3. **在 Node owner 的候选构造阶段形成真实根并固定材料。** 导出原 canonical header、完整 packet body、实际 A/B 和独立 expected-artifacts。用于外部搜索的导出应位于 nonce 搜索前；这样的只读导出是下一步的小型接线，本诊断没有实现。若使用已含搜索的 builder，其搜索与准备成本必须进入原计时。
4. **先实测同一完整 Packet 的 native Node admission，再投入昂贵 zkVM。** 保留同一个 header/block ID、真实终态和父状态重查。这个控制只建立 native admission，不证明 Node 已用 zkVM receipt 替代 native replay。
5. **为这个新声明生成新 proof。** 在实际搜索前声明研究期限和资源条件，沿用原父时钟及真实 winner 事件；生成、独立接收与验证始终绑定这一份新 header 和材料。原两份 proof、原失败样本及原业务预算结论继续保留。

这里的“不能闭合”限定于现有保留材料和当前入口，不是对所有可能匹配状态的数学不存在性证明，也没有通过构造数据库记录或改写旧声明来制造 admission。
