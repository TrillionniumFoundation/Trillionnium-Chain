# 3bbc 原预算服务失败：独立证据复核

本报告只读分析 GitHub run **41330488677** 的原始 head / prospective-merge artifacts；没有执行新的成本或服务实验，也没有修改原始报告、日志或 SQLite。精确数值与校验结果见 `analysis-service.json`。

## 当前结论

**四个无攻击 baseline 全部完成六深概率确认；四个 pressure 全部失败。接收端都已 ACK 七块且激活到高度 7，独立客户端在原四秒截止前均未完成整条 History 的验证及激活，最终 active 高度仍为 0。** 没有攻击输入被接受；失败在业务可用性验收，不是已观察到的无效工作入链。

| 源码场景 | baseline 最后 ACK / 确认完成（秒） | pressure 最后 ACK（秒） | 已取得 History 响应页数 | 独立库最高已存块 / active 高度 | 失败位置 |
|---|---:|---:|---:|---:|---|
| head / original | 0.232 / 1.699 | 1.579 | 3 | 3 / 0 | 第 4 次 History 网络 I/O 在截止后返回 |
| head / fresh | 0.232 / 1.692 | 1.751 | 3 | 2 / 0 | 第 3 页原生重放 PUBLIC_REQUEST_DEADLINE |
| prospective-merge / original | 0.311 / 3.401 | 2.368 | 1 | 0 / 0 | 首个 History 页原生重放 PUBLIC_REQUEST_DEADLINE |
| prospective-merge / fresh | 0.377 / 3.477 | 2.851 | 1 | 0 / 0 | 首个 History 页原生重放 PUBLIC_REQUEST_DEADLINE |

表中的“已取得 History 响应页数”仅统计在窗口内收到成功网络响应的页数，**不表示原生验证、导入或激活成功**。head/fresh 收到三页但仅存入两块，merge 两场各收到一页但未存入该页区块。

History 先保存经过原生验证的块，只在完整页到达目标 tip 时激活。head/original 已存高度 1–3，head/fresh 已存 1–2，都不能记成已激活或已确认；merge 两场仅保存 genesis。所有 receiver 的完整状态、根和数据库文件相同，所有 baseline 独立客户端也与 receiver 状态一致。四个 pressure 的 active 状态仍是 genesis。

## 来源与原 Host 预算

- head：`3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129`；实际 merge：`ea43b65fdd91b741b8f9e577061710dd2aebbb2e`，有序 parents 为 `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0` 与 head；两者 tree 都是 `f52299288ca23426e5186f37fb3a58788e40dbee`。
- 两个 ZIP 的 SHA-256 / size 与已保存 GitHub API 相符；解包文件逐字匹配 ZIP。每 lane 的 26 项 manifest 文件哈希、前后源码和 build 身份通过。
- 两 lane 的实际 ELF 完全相同，SHA-256 为 `aabb0484e94022a28bde90107bd5070a376255e7befe18c9d0a5cb86ae1972e3`。内层 runner 将当前 checkout 泛称 `kind=head`；merge 的实际 commit 仍是 ea43，merge 有序父关系由外层前后 source identity 和保存的 API 证明。
- `cpu.max = 25000 100000`（0.25 CPU），burst 0，memory 2 GiB，swap 0，pids 256；父 cgroup 身份、限额前后不变。运行 UID/GID 1001、CapBnd 0、NoNewPrivs 1。没有 Host read error、OOM 或准备失败。
- 每个业务窗口仍为 4,000,000,000 ns，pressure 为 16 workers；没有延长窗口。原 named test 只断言协议/计账不变量，进程 exit 0 仍被外层以 `CONFIRMATION_TARGET` 判失败；fresh test 写完原始报告后明确 panic，exit 101。控制器失败来自 native 业务结果。

## CPU 证据与失败边界

| pressure 场景 | receiver 全 W1 CPU（毫秒） | receiver mutation 总 CPU（毫秒） | 独立 History+确认线程 CPU / wall（毫秒） | 攻击客户端 calls / 完整 Transcript 拒绝响应 |
|---|---:|---:|---:|---:|
| head / original | 252.422 | 471.467 | 130.596 / 2486.586 | 281 / 265 |
| head / fresh | 221.421 | 423.108 | 117.260 / 2300.806 | 248 / 232 |
| prospective-merge / original | 285.115 | 529.706 | 76.517 / 1691.085 | 208 / 192 |
| prospective-merge / fresh | 250.692 | 471.604 | 45.058 / 1198.219 | 184 / 168 |

全 W1 CPU 包含在 mutation 总 CPU 内，不能相加。fresh head / merge 分别实际构造并提交 **248 / 184** 个唯一挑战，收到 **232 / 168** 个 `WORK:Transcript` 响应，其余保留为截止附近的客户端 I/O 错误。全部挑战、尝试序列、ticket、packet digest 和嵌套 CPU 关系已独立重算；没有删除失败或构造次数。攻击端构造 CPU 包含在 joined worker CPU 中，不能再次相加。

软件 mutation meter 每场初始 credit 2 秒，refill 为每秒 0.25 秒 CPU，worker limit 2；四个 pressure 的 mutation CPU refusal 都为 0，结束 credit 约 1.99–2.00 秒。Host 仍存在明显节流；这说明软件余额充足和原四秒业务目标完成是不同验收对象。现有记录把失败定位到独立 History 获取/重放/最终激活未完成，不能再细分为某个 syscall 或内核检查的因果占比。

两个 Host 的 before/after cgroup 计数覆盖整个控制器命令，包含 original 与 fresh 测试及源码/build/readback 工作；不能用这些总量除以四秒或分配给某一场。observer 的 dispatch、work、submit 阶段也有嵌套关系。本报告不将它们拼成攻击放大系数。

## 与 7c5 历史证据的关系

此前本会话已核实的历史 run **41299973417**（源码 7c5，证据提交 `8668c817ad4fa7ca02f940d69bc32a056a15cc24`）四个 pressure 都是首个 History 页重放 `PUBLIC_REQUEST_DEADLINE`、没有存入非 genesis 块、没有独立确认。此次是另一个实际源码和 run：merge 两场保留该失败形态，head 两场存入了三个/两个有效块，业务目标仍未达成。旧记录未在本轮重新取回，也不充当本次结果。

不能将 head 较快的 baseline 或多存入几块因果归功于本次 Host 检查去重。当前两 lane 已是完全相同 tree 和 ELF，baseline 的独立重放 CPU 仍相差约 2.3–2.4 倍，说明 hosted 环境差异足以影响结果；这里没有受控的前后性能对照。

本服务入口使用 `PublicServer::new`，没有启用 `with_arithmetic_facts`；因此独立 cache microbenchmark 的 FullLimb 改善不能用来解释这份原服务验收。此次 History 修改只移除了紧邻且无中间工作的重复 Host 读取，每个真实 W1 progress boundary 的检查和原 deadline 仍保留。

## 证据位置

- 机器可读复核：`analysis-service.json`。
- 当前原始材料：`head/fresh-service/{original,fresh}/report.json`、`prospective-merge/fresh-service/{original,fresh}/report.json`；各自 `fresh-service-host/`、source-before/after、manifest、ELF 与 SQLite。
- GitHub run：https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41330488677
- 本地数据库全部以 `mode=ro&immutable=1` 打开；读取前后 SHA-256 不变，且不存在 WAL。
