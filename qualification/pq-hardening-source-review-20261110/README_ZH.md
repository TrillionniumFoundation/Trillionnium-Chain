# Trillionnium-Chain 抗量子边界修补与审阅包

日期：2026-11-10。基线：`da1374a200022bc14dc2bd325cc9ba29dbcd24ab`。

## 当前交付状态

本包包含三个修补组、原始源码选集、修改后的源码选集、失败记录、已执行的 Python 验证记录、原生验证脚本及后续集成说明。**本包尚未形成最终 Git 集成提交，未推送到远程；Rust 原生测试、严格 Clippy、rustfmt、完整候选源码绑定及 hosted CI 均未取得通过结果。全链安全结论保持 HOLD / NO-GO。**

本次确认的工程进展是可检查的代码和证据。它不构成全链 PQ128 认证、STARK 完整安全证明、最低量子攻击成本证明或公网部署资格。

2026-11-10 08:17:04 UTC 只读检查显示，现有联合候选 [PR #847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847) 仍为 draft，head 为上述基线，mergeable state 为 blocked。不要把本包与 #849 / #857 / #843 / #852 等不同分支上的通过结果相加成“同一候选通过”。

## 1. 本次修补

### 完整公钥绑定

`identity/exact-spki.patch` 在 `PqClient::new`、TLS 本地身份配置和双向 TLS 对端准入中补充完整 ML-DSA SPKI 字节比较。32 字节身份索引继续用于查找独立 pin，准入还要核对完整密钥。已有 `PqServer::new` 的完整公钥校验予以保留。

新增三项控制覆盖本地客户端、TLS 两种本地角色，以及真实 TLS 握手中客户端/服务端两种拒绝方向。负控在测试私有策略中保留索引并放入另一把真实 ML-DSA 公钥，模拟条件别名。**没有构造 SHA-256 碰撞，也没有据此宣称当前存在可实施利用。**

`identity/negative-controls-only.patch` 仅把控制加到未修改的生产源码上，供原生环境先观察失败。它不能与完整补丁直接叠加；原生脚本会在检查后撤回控制补丁，再应用完整补丁。真实 TLS 线程使用同一个绝对截止时间覆盖 accept 与 handshake，避免错误路径悬挂。

Rust 补丁的源码适用性已经检查，但编译、执行和格式化仍待原生结果。包内补丁摘要因此是**格式化前的审阅版本**；若 rustfmt 改变字节，应重新记录摘要及相关绑定。

### STARK 审计辅助源码的来源绑定

旧审计器通过普通 Python import 加载有限域证书 helper，而该 helper 不在原有 18 项冻结输入内。保留原始 18 项输入，在导入缓存中注入 helper 并配合 registry 后，可把可约的 `X²` 报为 field certified。原始复现保存在 `stark/helper-injection-before.json`。这暴露的是审计结果的来源约束缺口，**不是成功伪造链上 STARK 证明**；原生产资格标志仍为 false。

修补将 helper 纳入 19 项冻结输入，并执行刚完成校验的确切字节，不再复用 import 缓存或搜索路径中的同名模块。负控覆盖缓存注入、路径替换、helper 源码和 JSON pin 一起替换。现有 RISC Zero / BabyBear、Plonky3 / Goldilocks、tagged SHA3-512 三条路线仍分别审计。

STARK 主包同时汇入 #849 / #857 的字段证书和条件 sampler/domain 分析，保留它们的历史来源，不用旧分支的映射覆盖当前候选的 QROM 映射。后续补丁把 10 项 STARK 和 4 项 quantum 依赖写入独立字面量 roster，并把 corpus 测试与实际 checker 接入 repository-truth 的前台必经命令。

### 量子计算器数值边界

有限的极小正时钟输入可在旧模型中导出无穷吞吐量；部分输入还会将 bool、数值对象或 None 隐式当作十进制参数处理。修补增加派生量有限性检查、明确的文本输入契约、文本长度和指数范围限制，并修正极端 Decimal 时间跨度下的取整顺序。

这些是离线研究计算器的实现约束，不改变链上难度、chainwork、协议目标、接受预算或攻击成本下界。11 个标准场景的完整输出在修补前后逐字节相等。

## 2. 已实际执行的验证

| 范围 | 实际结果 | 解释 |
| --- | --- | --- |
| STARK route | 32 / 32 | 提取源码选集；包含 helper 来源负控 |
| 有限域证书 | 16 / 16 | 素数、不可约、根及参数控制 |
| 条件 ideal sampler | 7 / 7 | 条件分布结论，不证明实际 FS 独立性 |
| 保留的 query replay | 13 / 13 | 原有回放控制 |
| Quantum 原始选集 | 71 / 71 | 固定基线原件 |
| Quantum 修补后选集 | 75 / 75 | 原 71 项保留，新增 4 个测试方法 |
| 新增 quantum 回归负控 | 原件失败，修补后 4 / 4 | 所有原始失败和中间修补失败保留 |
| 标准场景完整输出 | 11 场景，109,190 行逐字节相等 | 50,534,673 未压缩字节 |
| Corpus suite | 63 / 63 | 使用选集和合成目录夹具，不等于完整仓库 corpus 已通过 |
| CI 命令控制选集 | 12 / 12 | 前台、位置、次数和失败传播控制 |
| 限定外层重绑定工具 | 7 / 7 | 工具自身控制；尚未对真实最终提交生成重绑定结果 |
| Rust / TLS / Clippy / fmt | **未确认执行结果** | 不可记为通过或失败；部分运行请求的实际启动状态未知 |
| 最终候选、hosted CI、GitHub 推送 | **未完成** | 缺少真实最终源码提交和执行回执 |

标准输出流 SHA-256：`53f1a902a01ed57b0de2285b928801b323d11a273bcc79b828e46371e28cddb3`。两个 `.jsonl.gz` 解压后的完整内容相同；gzip 文件本身可因头部元数据不同而具有不同摘要。

`stark/supplemental-integration/after-pack-review.json` 中的 4 项字面量 roster 控制属于 corpus 测试，不能额外相加计算总测试数量。它们覆盖 42 个缺失情形和 14 个旧 pin 下的字节篡改情形。表内不同 suite 的测试范围可有交集，不给出误导性的全仓总通过数。

## 3. 原生执行阻塞与恢复

本机没有所需 Rust 工具链。经指定 HeptaRuntime 通道确认过 ProfHepta 身份，但 main 主机上的隔离 worktree 创建在 240 秒后超时；随后执行、查询、PTY 与异步健康接口连续返回 MCP 超时。ROG 上的完整 TLS 验证已按同一幂等 key 提交和恢复，尚未取得任务句柄或日志确认。

以 `quantum/NATIVE_STATUS.md` 和逐次 `rog-tls-start-attempt*.json` 为原生状态记录。超时不证明任务没有启动；恢复时应复用 `quantum/rog-tls-request.json` 的**原始请求及同一幂等 key**，先恢复已有任务，不创建新的重复验证或新的推送请求。

`quantum/rog_tls_validate.py` 包含控制补丁与完整补丁的固定字节，限定新隔离目录，先检查 ProfHepta 和项目 preflight，再运行原生流程。要求项目固定的 Rust 1.95.0 与独立 OpenSSL 3.5.9 构建；观察到的系统 OpenSSL 3.5.5 不能替代这项验证。该脚本不推送、不清理其他工作树、不改变全局默认工具链。

## 4. 正确集成顺序

必须使用完整 Git checkout，并先运行仓库现有 `bash scripts/project-preflight.sh`。本包的 `original`、`working`、`joint-ready`、`integration-base`、`after-pack-work` 均是明确标注的源码选集，不能初始化一个假仓库来冒充原始完整历史。

1. 在真实联合候选中核对基线及并发更改；不丢弃别人的提交或工作树更改。
2. 应用 identity 完整补丁、quantum 数值补丁。
3. 解开 `stark/stark-integration.tar.gz`，审阅并复制其中 `files/` 的 10 个完整文件，应用 `shared-integration.patch`。
4. 在上述状态上应用 `stark/after-pack.patch`。**不要再应用 `stark/historical-intermediate/integration-stark-roster.patch`**；其内容已并入补充补丁。
5. 完成原生测试、严格 Clippy、Rust 格式化和源码审阅，确定实际最终源码字节，形成真实 source checkpoint。
6. 按 `stark/AFTER_PACK_INTEGRATION.md`，用限定重绑定工具生成和审阅 4 文件外部补丁。只允许已审阅的 `pq_network.rs` 与 `quantum_daa_model.py` 两项源 pin 变化；其他 29 项选定源必须保持。当前 lifetime report 的算术、独立接受对象及 unknowns 必须原样保留。
7. 更新当前映射说明，保留历史报告与历史 source-observation。向现有唯一开发计划追加审阅后的记录；合并两份 append 文本时去除重复描述，不另立平行计划。
8. 最后按明确路径清单更新 distributed inventory 与 corpus 的受影响 Git blob pin。不要全量重算 1,079 项 pin 来掩盖非预期变化；14 项新依赖同时进入 required paths 和 pinned blobs。
9. 在最终完整树运行指南列出的源码、lifetime、corpus、CI、inventory、格式和文档检查，保留失败及修复记录。
10. 通过授权的 HeptaRuntime / ProfHepta 本地 GitHub 通道推进既有联合候选并检查真实 head 与合并候选 CI。没有实际成功回执前，不记录“已推送”“已合并”或“已上线”。

外层绑定故意保持待办：`pq128-source-lock-v1.json` 和当前 W1 lifetime 来源都需要真实源码 checkpoint。不能把尚未生成的提交 ID 写进报告，也不能将条件源更新变成安全预算提升。

## 5. 对原审计章节的当前修正

- ML-DSA-65 实现属于实质进展；NIST category 3 不能作为整个链的认证。
- Ed25519 profile 的存在本身不能证明降级路径。当前经典入口拒绝 PQ profile，选定 PQ owner 后的相关路径也拒绝经典 fallback；迁移来源、原网络退役、历史 finality、撤销和恢复信任仍需分别证明。
- 当前已有混合 TLS 1.3 路径：X25519MLKEM768、ML-DSA-65、AES-256-GCM/SHA-384、双向证书与独立 pin。它和 PNQ2 明文开发路径目前都限制 loopback，因此原文“只有签名明文”的说法需要按源码时间修正，公网资格结论仍为否。
- Cell 的 CCH1/TCM2、TCC2、TCV2、CPV4 及 sealed FD 路径已有对实际内容的加强绑定；TCV1/CPV3、默认/可选入口和若干短摘要权威命名空间仍要分别评估。不能把所有强路径描述成只给旧摘要套 SHA-512，也不能把它们的保障外推到旧路径。
- W1 特定可逆构造仍只是某种攻击实现的上界。标准场景不变、数值检查通过或某个 oracle 昂贵，都不证明最优攻击下界或联合 DAA / timestamp / fork-choice 安全。
- 三条 STARK 路线的完整 noninteractive、quantum、lifetime security bits 继续为 null。有限域证书与排除某个反例的假设匹配，不替代实际实例的完整密码证明。

详细来源和逐组件说明见 `identity/PQ_BOUNDARY_HARDENING_20261110.md`。这是拟放入仓库 `docs/security/` 的审阅稿；其中少数相对链接按该目标位置书写。

## 6. 包结构与校验

- `identity/`：精确 SPKI 补丁、仅负控补丁、原件/修改件、审阅文档、唯一计划追加草稿。
- `quantum/`：数值补丁、21 项原件/修改件、完整标准输出、失败记录、局部复现脚本、原生请求及其结果。
- `stark/`：两个集成包、最终应用顺序、来源选集、负控与测试记录、限定重绑定工具。
- `integration/`：基线观察与 main 通道原始超时回执。
- `SHA256SUMS.json`：包内文件字节数与 SHA-256。用于传输和复核，不是协议安全证书。

解压后可运行 `python3 verify_bundle.py` 校验文件。脚本只读取文件，不启动原生验证、不修改仓库、不发送或推送任何内容。局部 Python 复现见各子目录的说明及脚本；完整集成以仓库 preflight 和上面的顺序为准。
