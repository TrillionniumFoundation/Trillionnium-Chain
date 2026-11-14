# Hepta 原生 owner 验收互操作记录

已通过 HeptaRuntime 的本地 GitHub 通道推送，并建立 [Draft PR #5318](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5318)，堆叠在 PR #5316 的精确 `b8d12ad02a2d8311581a4aa69e6cdf07d18f9758` 上。本记录可用于 Chain 的来源对账；它不证明两个仓库已组成真实业务部署。

## 精确来源

- 已测源码：`e0a3bd2bde77c58a0ae7d211214f326371a72a4a`；tree `a28ed8f9dbc3569b8108e7f5fe5096b16c881792`。
- 已推发布头：`9c352c77d21923eb7c2022c96496228ee428d278`；tree `25d16999e4bdf0adc1ab7f9875cd4c4575e725df`。
- 后续两个提交只包含 qualification 证据。远端分支、PR head/base、commit tree、manifest 和关键原始日志均已读回验证。
- PR 保持 draft/open；本轮没有 main 合并或生产激活。

## 本轮完成

保留 #5315/#5316 的既有 evaluated-NoUpdate 原生路径，在原认证和 source 校验之后增加完整 bundle 相等检查。生产代码增加 19 行，原四阶段范围、签名/trust/time 重认证、owner checkpoint 语义、digest/operation 域和独立 FinalUse 权限均保留。重复的 `34060ab` API 已弃用，其原始失败、PASS、patch 和 git bundle 仅作为历史开发证据保存。

| 同源门 | 实际结果 |
| --- | --- |
| Crate Clippy fixer | exit 0，源码前后不变；保留两条既有 vendored warning |
| 实际 helper 构建 | exit 0，Cargo artifact 给出的可执行文件及 SHA 已绑定 |
| 原 nextest selector/profile | 60 passed、0 failed、662 skipped；exit 0 |

上述三个结果都绑定 `e0a3bd2`，不是借用弃用候选的 PASS。662 项属于既有 selector 以外，不能称整个 workspace 全通过。

新负例使用真正重新签署的四阶段 fixture：仅 heads 改变的完整 bundle 在 prepare/observe 都落到准确的 bundle 错误；另一真实 request/head 不能认领原 Control publication。公共 channel 验证的是已由固定时钟 fixture owner 形成的终态读回。CURRENT 和 FinalUse 撤销各用独立 fixture；每例均实际计算、持久交付、ACK、drain、原生 reopen，并保持一次模型执行和一次 nonce。

## 可核验材料

[完整报告](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/9c352c77d21923eb7c2022c96496228ee428d278/qualification/pon-evaluated-no-update-20261107-525798/README.md) 和 [MANIFEST](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/9c352c77d21923eb7c2022c96496228ee428d278/qualification/pon-evaluated-no-update-20261107-525798/MANIFEST.json) 已在 Hepta 仓库同一发布头保存。共提交 130 个证据文件，其中 128 份 raw 共 4,974,975 字节；54 个 native fixture 导出物共 146,271 字节。所有提交 blob 已逐一核对，原始日志没有裁剪或替换失败。manifest SHA-256：

`56443a7d04a33c2f8de1b311a61d3281939c70be62744c1aeb21da1563545135`

原生最终 stderr SHA-256：

`36205963dd330dcdb66428336312c27d41f9ae0423782eefa55559fde75320b7`

## 仍需真实材料的验收

这些结果证明指定源码的原生机制，仍不提供真实独立客户控制关系与外部预算、独立评价数据、前瞻且成本匹配的真实评价、完整训练/评价/保存/服务成本，或生产 canary/安装/真实下一任务/撤回回滚验收。学习 checkpoint 是内存 fixture，trainer/evaluator/签名密钥是工程测试材料；不能替代生产 learning owner 跨进程恢复和独立主体资格。

原 observation 的 terminal 条件是 STOP、无待决请求和输出 ACK；实际 drain 是另一个测试断言，不能添造 observation 内不存在的 flag。序列化读回保持 DENY_ALL，也不能把成功步骤或相同 fixture 的多次记录计成不同外部客户任务。

用户要求优先 Colab/Kaggle；本轮可调用工具与限定已跟踪项目元数据中未发现配置好的入口，因此该 CPU owner 资格使用 HeptaRuntime desktop，两项 Cargo build jobs。没有宣称进行 Colab/Kaggle 训练或真实收益测量。

Chain `690f710c1b6808787996e86aa4c36bd53e1f3939` 只是另一路来源引用；本 manifest 不给它与 Hepta 颁发组合资格。历史跨仓库证据和各分支测试数不能相加生成新的验收结论。
