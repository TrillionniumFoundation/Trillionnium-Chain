# 本轮研究成果到 production Node 的最小可执行缺项

这是接入验收建议，**不是已经完成的 Node 接入或生产资格**。本目录运行的是固定 selected-event 参考关系；其仿射算法与局部 witness 不能被静默替换成 full W1 公共证明。

## 已读到的具体边界

本次只读检查本地 Node checkout `b66e66d2465258d808c0f56ff851123306d4bdb4`：

- `trillionnium/crates/trnm-pon-node/src/mining.rs` 的 `PreparedCandidate` 保有普通 `pon_work::PreparedTask`；`src/store.rs` 构造同一类型。
- `src/pq_application_v6.rs::checked_length_for_profile` 要求 `packet.proof.len() == pon_work::PROOF_BYTES`。研究证明/新 envelope 需要明确版本接入，不能把研究进程成功退出当作此入口已接纳。
- `docs/protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md` 的 `maintenance_paired_conformance` 已有真实 parent-bound block、普通 packet、激活和 reopen 的旧关系回归模式，可作为验收方式参考；它没有授予本次研究 profile 资格。

这些是该已读 source head 的事实。根任务在最终提交/远端合并前应核对同名路径的最新源码；本说明不把旧 checkout 的观察冒称最新远端状态。

## 最小新的端到端接入用例

在拟发布的同一候选源码上执行一个真实双 Node、受限资源、冷启动到 reopen 的新 profile campaign。可按以下验收结果拆成少数用例，必须通过实际公共 wire/ingress 入口，不只直接调用库 verifier。

1. **精确版本与外部 statement 绑定。** 实际完整 W1 证明经过新版本 codec 与入口长度/资源检查；接收 Node 从本地当前 parent、chain、target、任务原始 A/B 承诺和已限定 profile 构造期望 statement。证明本身提供的字段不得自授权。版本/锁定 verifier key、image或PCS参数必须明确。旧 profile 与新 profile 互相拒绝串用。
2. **成功后的真实状态生命周期。** 发送方完成一个实际候选，接收方完成完整密码学验证，普通 block admission、持久化、链头激活、close/reopen 与重放读取。两边得到相同 block/task/work identity。必须展示实际成功的 wire 字节、source SHA、profile、日志和存储结果；研究 envelope / 零开销 stub 不能替代。
3. **接入后的关键否定样本。** 在上述同一实际入口分别注入错误 parent/header、错误 A/B 承诺、错误 target、旧 profile 重放、截断/超长 wire、最后阶段错误证明。每次拒绝均无 capability、credit 或持久化污染；cancel/timeout后资源确实释放。至少测试成功缓存跨 parent/reorg 后不能替代当前授权，再执行一个合法请求确认服务继续。
4. **原预算下的完整观测。** 同一进程树/队列/带宽/内存预算下运行合法请求与拒绝负载，记录从准备、证明、发送、接收、完整验证到持久化/激活的时间与峰值资源。根任务当前96 rejection benchmark可作为局部输入，不能替代此 Node 服务的持续运行、聚合限额与善意服务结果。

这四项会关闭一个明确的“该 exact-source 新 profile 可以在真实 Node 生命周期中正确运行”的有限接入缺口。它们仍不自动提供完整非交互/PQ128证明、普遍物理成本、生产全局恶意成本上界、公开网络确认/过期率或独立生产资格。这些分别需要原五门槛中的对应证据，不能由24个本地算法测试或旧21个组合测试升级出来。
