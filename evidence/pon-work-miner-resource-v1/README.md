# W1 分阶段资源、条件归约与链安全证据

本轮已完成冻结源码、两轮各58项的真实采集、完整重放、对抗读回修复和修正提交的指定本地门禁。**O01–O07按原关闭标准仍未全部闭合，production activation及hardness acceptance仍为false。** 纯矩阵PoN保留为主研究方向；混合基础工作与ZK保持条件研究义务。

## 阅读入口

- [结果与协议含义](RESULTS.md)：最终计数、比率、反例和限制。
- [摘要](summary.json)、[58项逐作业结果](job-results.json)、[54组预注册比较](comparisons.json)。
- [完整blocker账本](blockers.json)：继承C01–C14，新增C15–C23的有界关闭项；七个全局项和hosted执行分开。
- [验证与交叉复核](validation.json)、[精确模型输出](model-results.json)、[失败记录说明](failure-history.json)。
- 原始数据包名为`W1_miner_resource_evidence_20261026.tar.gz`；[实际交付状态](delivery.json)记录已生成且逐字节验证的137665313字节、SHA-256及完整payload索引hash。持久保存被自动审批阻止，等待用户对该具体数据包和自有ChatGPT Library目的地的明确授权；尚未声称上传成功。原始完整proof、失败日志、独立读回、真实测量可执行文件均在该包中。仓库源码以不可变Git提交为准。

## 固定来源

| 项目 | 固定值 |
| --- | --- |
| 最终实测提交 | `42bea72eb74409d72d580dad9bde08c1bce3f8f2` |
| 最终实测tree | `070942d172e3fa87e657a24b2bae7c5a6c43ce37` |
| plan SHA-256 | `bc4b57a47c84e69f32d5235536df7a60de30dc45985367fad39aa91b90db1381` |
| 实测可执行文件 SHA-256 | `1a8ad8b5680aa6b716c61c8cd3d5da31f3e01a51af3898a84e9e517fe5dd6dea` |
| corrected campaign manifest SHA-256 | `f945085845b48251d3a79a07cb0d8134a63b88a45ecbc93fc1f1cfde7e00f454` |
| 完整读回 SHA-256 | `3fd96bcf3d2a65bd1e4a1b8a5a9550d422a28ab4ffd2ece5df504f87636a5262` |
| 冻结分析器输出 SHA-256 | `121c7aa8dcacfe68389ad51af78a4a694401105f736841b4c6a6e44c792980f6` |

第一轮提交`36a47400138220244728bdd5fc7bb0a338c9ba85`的6343条完整记录独立保留。其嵌入式源码清单门禁失败，所以没有用这一轮替代修正源码的重采集。两次fresh build的实测可执行文件字节一致，计划、种子、预算、算法、阈值和顺序未变；计时结果仍是两次不同观察，不能选择性拼接或跨轮计作唯一票据。

## 可复核流程

取得实测提交`42bea72eb74409d72d580dad9bde08c1bce3f8f2`的干净完整Git checkout，保留Git对象，不替换reader或其转移依赖。后续只含报告的发布提交不替代这个实测源身份。解开主证据包中的`campaigns/corrected-42bea72.tar.gz`到一个新目录，其中`raw/`是完整309文件采集目录，`raw-index.json`是逐文件索引。主包内的owner pins来自采集者，不由待验证bundle自报替代。

```bash
python3 -B scripts/read_w1_resource_research.py \
  --bundle /path/to/extracted-corrected/raw \
  --out /path/to/new-readback.json \
  --expected-head 42bea72eb74409d72d580dad9bde08c1bce3f8f2 \
  --expected-tree 070942d172e3fa87e657a24b2bae7c5a6c43ce37 \
  --expected-plan-sha256 bc4b57a47c84e69f32d5235536df7a60de30dc45985367fad39aa91b90db1381 \
  --expected-miner-binary-sha256 1a8ad8b5680aa6b716c61c8cd3d5da31f3e01a51af3898a84e9e517fe5dd6dea \
  --expected-manifest-sha256 f945085845b48251d3a79a07cb0d8134a63b88a45ecbc93fc1f1cfde7e00f454 \
  --replay-workers 4
```

读回检查全部保留的完整proof、原命令、时钟单位、阶段、外部pins以及`scripts/formal/config`的394文件、6491725字节闭包。字节码缓存或未列入的文件会被拒绝；应使用干净checkout，不放宽文件集合规则。Python不会重新执行Node状态机，也不会认证机器、时钟或独立操作者。

重新做物理采集应使用[冻结collector](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/42bea72eb74409d72d580dad9bde08c1bce3f8f2/scripts/run_w1_resource_research.py)、[冻结plan](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/42bea72eb74409d72d580dad9bde08c1bce3f8f2/formal/pon-nakamoto-v1/experiments/w1_miner_resource_campaign_v1.json)、Rust1.95.0、真实GNU time及新的空build/output目录。记录实际可用CPU和硬件。每次新采集都是新的物理观察，不能冒充这批原始证据。

## 协议文档

[成本游戏](../../docs/protocol/pon-nakamoto-v1/details/W1_COST_SECURITY_GAME.md)、[资源归约](../../docs/protocol/pon-nakamoto-v1/details/W1_RESOURCE_REDUCTION_V1.md)、[分阶段原生实验](../../docs/protocol/pon-nakamoto-v1/details/W1_MINER_RESOURCE_RESEARCH_V1.md)、[链安全包络](../../docs/protocol/pon-nakamoto-v1/details/W1_CHAIN_SECURITY_ENVELOPE_V1.md)、[真实硬件与Hepta接受边界](../../docs/protocol/pon-nakamoto-v1/details/W1_EXTERNAL_QUALIFICATION_V1.md)共同限定这些证据的含义；工程顺序仍属于[唯一开发计划](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)。
