# 完整 W1 研究验证器：原资源数值下的两次 16 请求实验

**结果：guarded baseline 与最终 packed 候选各执行一次 16 请求、共用 4 秒截止时间的实验。两次均实际启动全部16个 verifier；截止前密码学拒绝为0；16个未完成进程均被整组 SIGKILL，全部退出状态已回收，清理确认通过。超时／取消不是密码学拒绝，外层实验脚本 exit0 仅表示留证与清理完成。资格仍为 HOLD_NO_GO。**

本结果只否定“这些完整研究验证在本次规定预算内全部完成”的说法，不自动否定能丢弃、排队、去重或限流的 Node 设计。没有测量善意服务、原生 Node 确认或全生命周期／队列全局成本界。

## 固定对象与实际资源

两个运行复用逐字节相同的 `run_pressure.py`，SHA256：

```text
83d2277d254731225451b5735329dde360f71284eb4147055df82442f7dd4e5c
```

所有验证进程及其后代共用**一个** transient systemd unit。启动前读取 systemd 配置及 kernel cgroup 文件；启动前读数不符合以下值即终止，不扩大预算。请求运行中继续采样留证，未实现限额漂移的持续检测与自动终止：

| 项目 | 实际核对值 |
|---|---|
| CPU | `cpu.max = 25000 100000`，合计约0.25个CPU配额 |
| 内存 | `memory.max = 2147483648`，2 GiB |
| Swap | `memory.swap.max = 0` |
| Tasks | `pids.max = 256`，包括线程 |
| 请求数／截止时间 | 16个 fresh verifier 进程，共用自首次 fork 前起算的4秒窗口 |
| Rayon | 每个进程 `RAYON_NUM_THREADS=8`，沿用原测量设置 |

这是自有用户 transient unit，**不是**原生产契约要求的 root-owned、固定且持久的 `/sys/fs/cgroup/trnmponpublic.slice`，不授予 Host 或 Node 资格。`cpu.max.burst` 配置值未直接采集；baseline 的采样 `nr_bursts/burst_usec` 为0，不能将其改写成该文件的完整核验。

## 两次实际结果

| 项目 | Guarded baseline | 最终 packed |
|---|---|---|
| 观测 Git HEAD（源码范围见下文） | `cae1e3657b0913991d9465995e709a544218a27c` | `2632d3e5bca93fccc062db6ff4a8470cfc2fa51f` |
| 二进制 SHA256 | `44c0d3b88a1d8198c4db0ba3b27ed1072faf69377773fa97e835c8ccb8e2bd94` | `2774f3d718bf3831a79b3e348747be1117255b433219e8d2bad5c299da6462ad` |
| 输入组合 | SHA／arithmetic 的末轮 query value 与 authentication sibling 四类，各4次 | 指定 packed `arith-last-fold-auth-sibling`，重复16次 |
| fork／exec 已确认 | 16／16 | 16／16 |
| 截止前密码学拒绝 | **0** | **0** |
| 截止后完成的受控拒绝 | 0 | 0 |
| 未完成后 SIGKILL | **16** | **16** |
| 未观测退出 | 0 | 0 |
| `wait4` user／system CPU合计 | 0.669200／0.417083秒 | 0.647480／0.456978秒 |
| 含退出回收和清理的观察窗口 | 4.360192811秒 | 4.368416075秒 |
| harness 清理确认 | true | true |

本批次进行时，packed checkout 尚含未提交的 wire admission 与元数据整合；表内 `2632d3e5…` 仅为当时 HEAD。原生构建和 guarded ABBA 的源码前后 hash 记录了这些修改，不能把该二进制说成仅由该 HEAD 原样构建。集成发布检查另行将同一二进制和源文件绑定到最终提交。

**两批输入组合不同，不是有效的性能A/B对照。** 这两次4秒截断观察不能替代完整验证耗时或端到端收益测量。baseline 的 kill 在起点后4.000742180秒发起、4.000934658秒返回，最后一个 wait4 在4.307157839秒；不能声称整棵进程树在严格4秒内已清理完毕。

“晚期错误输入”是由原 typed mutation 和既有完整拒绝记录界定的输入身份。本次 baseline 全部16个完成了 shape/decode，11个完成后续 canonical planning，没有完成 SHA／arithmetic 密码学验证阶段，也没有最终 verifier verdict。因此本轮没有测得16次晚期密码学拒绝的完整成本。

baseline 的76次 kernel采样捕获 `memory.peak` 最大345,640,960 bytes（约329.63 MiB）、`pids.peak` 最大97；这是已捕获的峰值下界。终止后 cgroup 已消失，systemd 保留的 `MemoryPeak=262144` 不能当作本轮真实峰值。原始逐样本计数、逐进程 CPU／RSS／退出码均保留，CPU汇总包含退出清理；`throttled_usec` 不当作请求墙钟延迟。

## 留证和计量边界

验证器先在 gate 上等待，确认已进入自有受限 cgroup 后才放行 exec。外部 observer 保留每个进程真实的 `wait4` 状态和资源数据，在截止时写入自有 `cgroup.kill`，再核对已回收退出、旧 PID 身份消失及 cgroup 为空／消失。baseline 后续另有独立只读清理复查；packed 没有追加第二次独立复查或重测。

Observer、准备／pinning、fork与迁移管理不属于验证执行配额；初始化前已读入文件，未清空缓存。测试使用既有完整 proof 的正确形状修改，未计入攻击者从零生成原 proof 的成本。它没有生产网络、七个善意提交、实际 Node 工作队列、持久 CPU debt 或独立确认；不能继承原业务4秒门槛的资格。

远端原件保持在相互独立的目录，baseline未被packed覆盖：

```text
/home/qian-qi/work/w1-pressure-f16ac5-20261108/
/home/qian-qi/work/w1-pressure-packed-f16ac5-20261108/
```

每个目录包含 `run_pressure.py`、输入pin脚本、`binary-staged.json`、`inputs/manifest.json`，以及 `campaign-01/result.json`、`events.jsonl` 和16组 stdout/stderr。完整固定后的二进制和 proof 输入保留在各自 `inputs/` 下。baseline 还包含 `independent_cleanup.json` 和原契约快照 `contracts/`。代码／输入快照不替代原构建收据。

重复实验需使用已有固定 `inputs/`、新的输出目录，并先协调主机上其他性能运行；脚本不会修改原 checkout、扩大资源或覆盖旧结果：

```bash
python3 -B run_pressure.py \
  --inputs /absolute/path/to/pinned/inputs \
  --output /absolute/path/to/new/result-directory \
  --coordination-cleared 'Retained coordination record for this new run'
```

## 原契约引用

以下文档在 baseline `contracts/manifest.json` 中固定到 commit `cae1e3657b0913991d9465995e709a544218a27c`。本实验借用其中资源数值，没有重新执行或修改原服务验收：

- [PON_WORK_REJECTION_COST_V2_PLAN.md](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cae1e3657b0913991d9465995e709a544218a27c/docs/research/PON_WORK_REJECTION_COST_V2_PLAN.md)：原独立公共服务门槛为4秒、25%单CPU、2 GiB、256 PIDs、七个善意提交及十六个攻击生产者。
- [PUBLIC_POOL_INTAKE_V3.md](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cae1e3657b0913991d9465995e709a544218a27c/docs/protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) 与 [trnmponpublic.slice](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cae1e3657b0913991d9465995e709a544218a27c/config/systemd/trnmponpublic.slice)：固定 root-owned parent、100 ms周期、burst0、swap0和持久资源归属要求。
- [PON_ORIGINAL_FOUR_SECOND_REPLAY_STAGES_20261031.md](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cae1e3657b0913991d9465995e709a544218a27c/docs/security/PON_ORIGINAL_FOUR_SECOND_REPLAY_STAGES_20261031.md)：只有原约束下实际 native 业务成功及独立验收才能关闭对应门槛。
