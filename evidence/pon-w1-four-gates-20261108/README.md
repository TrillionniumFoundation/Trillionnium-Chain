# W1 四个工程门：新代码、严格证据与仍未闭合的资格

本轮以 C3 `abab79dac0cb89eb2753d3f579119ac135650eb5` 为基线，整合 M12 topic `a5ec1ba30916400c345cb47679602cfb1b30a65f`、新的 receiver / 成本证据绑定、独立 ABBA 审计及前瞻式进程 collector。旧证明、原实验 deadline、旧 operation、原资源保留及失败样本均未改写。本目录是提交前已经实际取得的证据；最终精确提交构建、测试和新增真实生命周期由后续独立资格 attestation 固定，关联 PR 的索引指向该原件。

## 工程门状态

| 工程门 | 本目录已经建立的增量 | 仍需实际证据 |
| --- | --- | --- |
| winner / receiver 采集 | 修复实际 stdout 与 observer digest 未绑定的缺口；11 项真实 receiver 控制通过。新增独立 subreaper 的有限真实进程控制，保留父/子退出、pidfd 与 wait4 / ECHILD。 | 原 winner 的合法 Node 父状态与 admission、部署 WAN、所有历史进程身份及完整资源计费。新 collector 不补写旧树。 |
| 完整后端同资源实验 | 两份旧结果的 80 行 / 20 个 ABBA block 经严格类型、原始字节和闭合 pin 重审，未生成新 proof。 | 两个完整生成方案仍各 n=1，配置差异、总体尾延迟与因果加速未闭合；原业务资源条件未通过。 |
| 真实异步 owner 接线 | `begin()` 在持久化 owner cancel 后不会再派发；新的 typed terminal reconciliation 绑定原身份、时钟和 deadline。资源未知仍占全额 cap，reorg 不回退本地历史。旧本金退款费用独立验算。 | 新昂贵自然超时、退款、实际 fork 与冷恢复需要独立新 operation 原件；正向 provider 付款和完整资源结算仍未建立。 |
| 部署收益与安全资格 | 两个真实证据接收反例已修复并加入 mandatory CI；系统级 CPU 隔离短探针实际执行成功；C3 业务 CI 失败原件完整保留。 | 验证/传输收益、业务预算、完整密码学及协议安全资格仍未建立。 |

所有四门保持 HOLD，局部测试通过不改变该状态。

## 可核验的增量

### 1. 证据接收不能只信 JSON 中的数值

原 C3 reader 接受将真实保留行的 verifier 内部时间从 33,114,440 ns 改为 1 ns、却保留旧 observer stdout digest 的副本。独立审计器另接受把原始行整数 `0` 改为布尔 `false` 的类型别名。新路径绑定实际读取字节，严格检查 UTF-8、重复键、类型、有限值、原时钟、退出/超时状态及所有输入的最终 pin。

[复现、修复边界及真实 receiver 控制](evidence-binding/README.md) 保留第一版和后续差量的原始记录。整合树已实际通过 12 项绑定、20 项审计、10 项 CI 接线负控制和 11 项真实 receiver 控制。真实 receiver 重用已资格 C3 verifier 及既有完整 v2 receipt，未产生新完整 proof。

### 2. 原 winner 的链上上下文尚不成立

[header 与 admission 源规则诊断](winner-admission/README.md) 对原 318-byte PNH1 header 完成逐字段解码/重编码。它包含固定 parent `05×32`、height/time=1 和占位承诺；native winner 明确没有检查 parent eligibility。当前 Growth Node 要求 354-byte PGH2 及独立的 growth challenge 域，不能用包壳方式替换原声明。Legacy admission 仍需要原父状态、交易 body、分支规则与 task eligibility；旧原件没有提供这些上下文。本轮只有源码与材料诊断，实际 submit / negative admission 事件均为 0。

### 3. 80 行 ABBA 仍是验证阶段比较

[独立审计](abba-audit/README.md) 全部接受 80 行。按 block 均值比再取中位数，proof/native 为 12.0628448679 与 13.7398970544；原边际中位数比仍是 13.0634904873 与 13.4308277868。两个统计口径分开保留。全部 20 个 block 中 proof 验证更慢，不能把这些行计为新的生成实验或生成加速。

### 4. 进程 collector 只结算自身真实 wait 域

[collector 控制与接口](collector-controls.md) 保留首次缺少 `/proc/.../children` 导致的两次本地清理失败、修复后 14/14、本机首轮启动等待失败、独立桌面 14/14 和最小等待窗修正后的定向复验。原 target 的 `dispatch → _worker → _exec` 实际链已被新 collector 包裹并执行有限载荷，原 `Popen` 状态未被窃取。

collector 使用单线程初始空 wait 域、subreaper、原 boot/PID birth、pidfd、waitid/wait4、真实父进程返回码及原钟闭合；最终 ECHILD 只证明该存活 collector 所拥有/收养的可等待后代已回收。它不枚举中间父进程早已回收的所有历史孩子，不将共享 cgroup 与 wait4 CPU 重复累加，也不授权付款。完整历史树、GPU 与 billing 字段保持未资格。

### 5. 新系统级隔离能力不回填旧任务

[CPU 隔离探针](cpu-system-scope/README.md) 保留 systemd 255 transient 属性不兼容的首轮失败和成功后 12/12 条件。新动态 UID 的短服务对 7 个真实 GPU 设备的原路径/备用映射共 28 次 open 全部拒绝；socket、ptrace、继承 fd 控制和 null/zero 正向控制均实际执行。父进程壁钟为 4.612593864 秒。

这是一个 0.25 CPU、256 MiB 的新短探针。尚未证明完整 zkVM 在相同隔离下可运行；旧 `gpu_ns=null`、full cap 与计费状态不变。

### 6. 旧取消费用已有独立推导

[旧取消费用审计](old-cancellation-fees/README.md) 从 exact C1b config/wire 计算 reserve 419、cancel 291，验证两份 Ed25519 签名及金额关系：本金 1000，cancel 余额净增 709，reserve+cancel 合计净减 710。读回只打开既有私有分析副本，SQLite SHA 前后相同；没有新签名、提交、退款或资源返还。

### 7. C3 业务失败不因新单测通过而消失

[C3 CI 原件](ci-c3/README.md) 固定三份公开 artifact 的 ZIP 哈希及 41 个原始记录。3 次完整原生 campaign 的 9 个原 30 秒阶段均未通过 finite criteria；baseline 均只确认计划 3 项中的 1 项，压力阶段均为 0/3。固定 .25 CPU / 2 GiB 的 4 秒控制也有真实业务失败，不能说成工具启动失败。

本轮是这些 C3 结果的保留与诊断，不是重跑，也没有将短控制升级为新的业务预算通过。

## 源资格边界

M12 topic 的 20 项 Node 短控、11 项 M12 短控及 strict Clippy 已实际通过，4 个资源密集入口按既有显式开关保持 ignored；这 4 个入口不计为已完成的昂贵实验。mandatory W1 Python command block 固定为 151 个实际测试，真实 receiver 为 11 个，并对删除、重复、吞错、移 lane、降计数及 skip 设置负控制。

最终集成必须使用干净的精确 commit、锁定 Cargo graph 与实际父进程状态。构建缓存复用与保留 verifier / guest / upstream r0vm 必须分别声明；尤其 staged runner 的 `source_commit()` 从编译时 checkout 查询 Git，不能把旧 C3 ELF 重标为新源码。本轮首个新 timeout operation 正因该严格检查而失败，原失败 operation 保留且禁止重派。新源码必须重新构建该 runner 后，以新的 operation 和预声明 deadline 再测。
