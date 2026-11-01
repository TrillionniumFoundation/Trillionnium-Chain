# 全链 PQ 授权候选：Application V6

状态：开发候选，**HOLD**。这是既有 PN0–PN5 工作的实施契约，不是第二份开发计划。
生产激活、全链抗量子、量子工作难度、证明系统安全、独立 WAN 与模型有效性均未获此文档授权。
本候选延续 [唯一开发计划](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)。

## 1. 来源与可复现边界

本轮从可验证的 Chain `58d533877ccdf56f2fc2b87e0b60c485300955a5` 与 Hepta
`bcb8f97164cefe494918fb0efe482029d7dfe6be` 恢复。此前环境中声称存在的未保留工作副本、
提交和测试结果不能作为本轮证据。NPQ2–NPQ5 账户、额度、任务和续约源文件逐项取自
Chain `42ab57f1c5065d50f981cc337c417ef0ab7dc096`；没有把其分叉分支整体覆盖到本基线。
源输入、实际失败和最终验证结果由 [资格记录](../../qualification/full-pq-v6-r2/README.md) 维护。
后续 R3 源码、原容量失败的重新测量及新验证由
[R3 资格记录](../../qualification/full-pq-r3/README.md) 单独维护，不能继承未保留源码的通过结论。

## 2. 一条规范集成路径

M01 的默认实现是固定版本 `ml-dsa = 0.1.1` 的纯 ML-DSA-65，使用规范 SPKI、空签名
上下文及 FIPS 204 的消息接口。SPKI 头、算法、密钥长度、签名长度、消息长度和 TPQ1
上下文必须完全匹配。内部预哈希/raw-mu 形式不能冒充消息签名。

另一实现保留为独立差分来源：固定 OpenSSL 提供者通过独立测试程序生成和验证签名；
它不为验证失败提供自动重试或接受路径。固定的 Wycheproof 材料具有来源、许可证和
摘要；通过向量及互操作测试不能替代密码实现的独立审计或侧信道审计。

## 3. 版本选择和授权归属

配置选定 `pon-native-pq-application-v6` 后，只接受 `NPQ6` 命令与 `PQP6` 区块包。
选择发生在受保护的启动配置中，不能由入站魔数、算法列表或验证结果协商。
既有经典以及 NPQ2–NPQ5 研究配置保有各自域；它们不能在 V6 中提供替代授权。

V6 是新 genesis 上的明确协议选择。已有余额迁移需要独立固定的源检查点与在量子威胁前
可信建立的 PQ 预承诺，继续保留旧 nonce 下界和负债。一个经典签名在 Shor 威胁发生后
不能独自证明新 PQ 密钥的合法归属。本候选不把 fresh-genesis 构造器称为在用主网的
自动高度激活或已完成资产迁移。

| 授权关系 | 实际执行入口 | 约束 |
| --- | --- | --- |
| 账户注册、转账、轮换、迁移领取 | 原 M06 `pq_accounts_v2` | 当前状态解析密钥；轮换双方签名；稳定账户地址；旧代次不可支出 |
| 任务双方、请求／撤销／续约 | 原 M06 `tasks_v5` 与 Node mining | requester 和 source 独立授权；实际 parent、租约、材料与输出绑定 |
| 额度、双方结算 | 原任务／quota 状态机 | 两角色验证；原 nonce、费用、余额守恒和负债规则 |
| 评估、争议、发布、领取 | 原应用与 public evaluation | 显式 PQ 评估轮次；冻结密钥代次；完整争议证据仍可在轮换后核验 |
| operator | 原 continuous 策略、Journal、controller | 明确 PQ 身份 schema；不同角色独立域；旧认证服务与 PQ 身份不能组合 |
| paid History | 原 public reactor、CPU 域和导入器 | PQ challenge／cookie／响应；严格选定 Page 与 packet 格式；完整再验工作和 M06 |
| Cell release 与 discovery | 原 Cell CLI、cache、directory | manifest 与目录公告签名；授权 pins、撤回高水位和绝对截止时间 |
| Hepta CURRENT／安装／FinalUse | 对应 Hepta 工作副本的原 owner | 必须以该副本的实际验证记录为依据；不能用 Chain 的通过结果代替 |

## 4. 资源合同

ML-DSA-65 原始公钥 1,952 字节，规范 SPKI 1,974 字节，签名 3,309 字节。
单签普通转账的 NPQ6 编码为 3,751 字节，已经超过经典交易 2,048 字节上限。

| V6 资源 | 上限或规则 |
| --- | --- |
| 单命令编码 | 16,384 字节 |
| 每块命令数 | 64 |
| 每块命令字节合计 | 524,288 字节 |
| 每块交易签名验证数 | 64；双签计 2，外层加两份争议证据计 3 |
| 完整区块包 | 1,048,576 字节，包含原工作证明 |
| 状态叶 | 原 4,096 字节值、160 字节 key 和 65,536 个 key 边界 |
| 验证费用 | 在原基础费用和按字节费用之上，每次预期签名验证加 1,000 记账单位 |

记账单位不表示毫秒或实际 CPU 时间。64 是交易授权验证上限，不能遗漏工作证明、任务
资格重验、传输签名和本地响应生成的额外成本。任务材料接口在当前实现中实际重验四个
签名（资格两次，材料准入两次），计数测试必须明确这一事实。21 份三签争议命令可占用
63 次验证，22 份应在启动密码验证前拒绝。

真实密码调用之前消耗验证额度；失败不退款。单个前缀构建器的坏签名重试共享同一额度，
不能通过状态回滚重置。明显不足的 `max_fee` 在密码操作前拒绝，未经认证的账户不扣费。

PNQ2 的 loopback 开发网络具有原 SQLite owner 内的持久预算：64 个连接、32 MiB 声明
入站字节、64 次入站签名尝试。正文分配前检查长度和预算；重开与链重组不恢复额度。
这是一项有界开发合同，**不是可无限提供服务的公网限流／收费方案**。paid History 则沿用
它自己的原 Host／intake／mutation CPU 域和恢复屏障，两种预算不能混称同一个账本。

## 5. 评估、历史证据与分块

每轮冻结 roster 以及按同一顺序排列的密钥代次，round 摘要覆盖该计划。当前提交和揭示
仍要求当前账户权限；历史冲突只能使用冻结代次，不能取得支出权限。轮换不会抹除已发生
的双重签名证据，也不会把新密钥的陈述移植到旧轮次。

对抗复核发现，退役密钥日后泄漏时仍可签出旧轮次的两份冲突陈述；签名不能证明创建
时间。因此 V6 的 `pq_conflict_scope = frozen-authority-round-v1` 必须进入冻结计划和
round 摘要。冲突只影响对应 candidate、round 和冻结 generation，不写入或读取经典的
永久稳定账户黑名单，不能影响其他轮次或轮换后的身份。本轮冲突仍排除其提交／揭示，
冻结 quorum 分母不随之降低；已关闭结果和既往支付不被重写。未来撤销属于另一个明确
授权的策略，不可由缺少可信时间锚的旧签名推导。证据沿用原有 archive 生命周期，
不是无限期无界存储。

PQ 评估存储使用独立 revision 6/7 和 `ev-pq-v6` 命名空间。完整签名证据以 1,024 字节
规范分块保存，每项至多 65,536 字节，元数据包含长度、块数和 SHA-384。重组恢复时检查
精确覆盖、顺序、长度、规范编码和摘要；缺块、多块和错块均拒绝。状态根继续承诺全部叶。

当前 Rust Cell 的 `CPR2` 发布声明签名绑定 `TCR1` release manifest 内容 ID，后者绑定
排序、唯一的 `TCM1` Cell manifest ID；Cell manifest 再绑定有序块的长度、SHA-256 和
完整 payload 摘要。该原生路径没有 Merkle sibling 证明、BEP 52 或 magnet/DHT 协议，
不能用另一个 PCC1/PCQ1/PCR1 研究实现的 Merkle 证明来描述它。一个块的多个下载来源
不需要各自拥有模型发布权限，现有原生路径也没有为每个下载块附加独立大型 PQ 签名。
现有 configured-peer 目录与持久撤回能支持可核验的取回，但不等于已经
完成开放 DHT、抗 Sybil、跨故障域副本、长期留存激励和所有历史版本的可用性证明。

## 6. 身份认证与保密是两个门槛

当前 PNQ2 显式声明 `loopback-signed-plaintext-dev-only`，提供消息认证和重放约束，
没有加密。生产网络候选可以采用 RFC 10024 的混合 ML-KEM TLS 1.3 密钥协商；它本身
不提供对端 PQ 身份认证。PQ 证书链、端点名、角色 pins、CertificateVerify、撤销和
会话重连必须一同验收，不能因为 TLS 协商了 ML-KEM 就宣称全部认证抗量子。

截至 2026-10-29 查阅，TLS ML-DSA 的认证文件为 `draft-ietf-tls-mldsa-06`，应按当日
IETF 状态处理，不能把草案标成已发布标准。应用签名也不能被描述为已完成 PQ TLS。

## 7. 不能由本轮局部测试关闭的门槛

1. **continuous owner 与 NPQ6 的产品验收。** R3 的
   [独立启动契约](PQ_CONTINUOUS_STARTUP_V3.md) 先固定只含公钥配置的 genesis，再导入真实
   签名的 OPEN/REGISTER 工作块；catalog、TaskV5、原 Journal、Controller 非空搜索和
   续约使用各自明确 PQ 域。它仍是受保护目录下的受限 owner，不自动切换 bootstrap 前缀，
   不把普通 History 改成 continuous Journal，也不证明全网任意分叉同步已完成。
2. **运行中网络迁移。** 新 namespace 不能证明旧链终局、旧钥匙先验可信或源余额锁定。
3. **密码实现与证明审计。** 差分成功不等于独立审计；全部证明关系、Fiat–Shamir 的
   QROM 假设、哈希宽度、批量／递归组合及工作标识必须另行审计。
4. **量子工作与公平性。** ML-DSA 不修复 PoN 工作搜索可能的量子加速、预处理优势、
   重复模型／矩阵利用、硬件集中、DAA 适应性或概率确认安全。
5. **性能和可用性。** 需要真实设备上的坏签名拒绝成本、p50/p95/p99、混合载荷 TPS、
   块传播、fork rate、重组和持续耗尽服务测试。仅按签名字节计算不能给出可部署 TPS。
6. **Hepta 产品闭环与独立运维。** 原安装读回、撤销、失效、崩溃恢复、合法 no-update，
   以及原计划规定的至少三组独立管理员和 72 小时 WAN 证据，仍需各自实际证据。
7. **未迁移的实际入口。** Chain 的研究 authenticated archive、主 CLI 的经典提交／
   父恢复仍需单独接线。Hepta R3 的 AuthBus message／time／settlement 采用独立 PQ-only
   owner 域、一次性时间挑战和持久 issuer/replay 屏障，需以对应 Hepta 版本的实际验证为准。
   RunStart／ObjectiveStart、automation PoN caller、旧 plasticity bootstrap 和独立
   intelligence authority 的覆盖必须逐个核实，未迁移的经典接口在 PQ-only 域内应明确拒绝；
   不能从 learning、CURRENT 或 FinalUse
   局部通过推导整仓迁移完成。Cell 缓存 stdout 收据也不是跨进程安装授权。

因此，“9.6”只能作为用户提出的验收目标；本候选不自行授予该分数。

## 8. 标准来源

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)，包括 2026-07-31 勘误提示。
- [RFC 10024：TLS 1.3 的 PQ/T 混合密钥协商](https://www.rfc-editor.org/rfc/rfc10024.html)。
- [TLS ML-DSA draft-06](https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-06)。
- [固定 RustCrypto ml-dsa 0.1.1 文档](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)，独立审计状态需单独核对。
