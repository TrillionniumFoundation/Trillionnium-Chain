# Cell 双物理机原生传输与接收后模型执行

本包记录一次在**同一运营方、rog 与 ai395 两台物理机、USB4 私有直连**上的原生 Cell 冷接收，以及这份新接收 adapter 的实际模型 forward 和冷读回。执行源码固定为 `58851cf923f6a8b7190b50228b30f3e82a682f9c`。三次此前的原生连接失败和选定的准备失败均保留。

资格仍为 `HOLD_NO_GO`。独立运营方、公网发现、长期托管、完整基座权重分发、生产激活、FinalUse 和完整 Hepta daemon 重启资格均为 false。

## 原生结果与限额

成功方向为 rog 原生 provider `10.77.0.1:39264` 到 ai395 新建的 consumer.db。原生协议为 `persistent-v2`；三份文件均为零缓存块接收，payload SHA256 与 manifest 匹配，并由原生 verify 再核验。

| 文件 | 数据字节 | 块 | 原生响应字节 | fetch 子进程秒数 |
| --- | ---: | ---: | ---: | ---: |
| artifact.safetensors | 933,544 | 15 | 934,465 | 0.108836 |
| target-contract.json | 56,809 | 1 | 57,100 | 0.016932 |
| wrapped-adapter.json | 20,962 | 1 | 21,253 | 0.011485 |
| 合计 | **1,011,315** | **17** | **1,012,818** | 各文件独立计时 |

provider 保持原来的 12 秒服务期限、2 个 bounded worker、16 MiB 总响应限额、16 连接、2 秒请求期限、128 次请求及每连接 64 次请求限额。每个 fetch 保持 3 秒 overall、2 秒 request、parallelism=1、最多 2 连接、4 MiB 响应预算及 64 次请求限额。缓存限额仍为 16 MiB payload、128 chunks、16 manifests、16 MiB database。

provider 实测为 3 连接、23 request attempts、20 completed、0 overloaded、peak_active_workers=1。客户端 cached_chunks 和 rejected_responses 均为 0。原始计数保留原含义，不把 request attempts 当作全部成功请求。

timed runner 保存 provider 的 native PID、spawn 前后、native ready、退出时间，以及每个 fetch 的 native PID、开始和结束时间。三个 fetch 均完整落在 provider ready 到退出的实际时段内。原生设置仍为 12 秒；控制器观察到的进程生命周期约 12.002457 秒，含进程启动/收尾观察开销。UTC 屏障等待、源码/编译准备及 TLS 暂存不计入 Cell 接收数据或时长。

## 必须同时保留的失败

| provider | consumer | 实际监听入口 | 结果 |
| --- | --- | --- | --- |
| ai395 | desktop | 192.168.0.5:39261 | 原 request-ms=2000 下 connect elapsed_ms=2001 超时 |
| ai395 | desktop | 192.168.0.11:39262 | 原 request-ms=2000 下 connect elapsed_ms=2001 超时 |
| ai395 | rog | 10.77.0.2:39263 | 原 request-ms=2000 下 connect elapsed_ms=2001 超时 |

三次 provider 均真实 ready、按固定 12 秒终止且 exit 0，但各自均为 0 连接、0 请求、0 响应字节；consumer 在第一份 manifest 的连接阶段失败，成功 payload 为 0。provider 的有限生命周期通过不构成跨机接收通过。没有从这些观察推断具体防火墙或网络根因，也没有修改网络、端口规则或长期服务配置。

准备失败另行保留：初始 git bundle 空包失败；旧稀疏对象库缺少 preflight；完整新 worktree checkout 达到 120 秒准备上限；新 --no-checkout worktree 尚未填充 index 时的 preflight 127；编译成功后，初版 dep-info 核验器未规范化 `../` 路径导致的断言失败。后续在独立 sparse worktree 填充真实源码并修正证据路径归一化，原记录未覆盖。准备运输不是 Cell 原生业务预算的一部分。

## 准备运输与实际模型执行

因原始保留文件位于 ai395，先由 ai395 主动连接 rog 的短寿命 TLS1.3 接收端进行一次受限暂存。上传限定为同一三个文件、合计 1,011,315 字节，并逐文件核验 hash；服务已退出，临时 private key 已删除。该步骤的记录明确 `native_cell_transfer=false`，其数据未加入上表的原生 Cell 接收指标。

随后原生 Cell 从 rog 向 ai395 的另一全新缓存和 replica 目录传回字节。原模型 worker 从该新 replica 载入保留 adapter，执行一次新的 forward；gradient_steps=0、optimizer_calls=0。第二个 worker PID 冷打开同一操作，读回完全相同的 open/probe 响应，关闭时 forward_examples 仍为 1。两个 worker 均经受控 stdio EOF 以 exit 0 结束，总模型操作约 7.078 秒。原文件和接收文件 hash 始终不变。

模型部分使用既有 helper/worker 的原始研究边界（4 CPU threads、最多 1 forward example、1 patch candidate、worker request 120000ms），与另外的 Hepta 原生学习 60 秒操作分列。它不提供新训练、泛化收益、独立评价、native CURRENT、FinalUse 或完整 daemon 重启资格。公开模型记录是明确标注的投影，含原始记录 SHA、worker/helper/package SHA、PID/时段、输出 hash 和资格标志；不包含私有 Hepta 源码、owner 数据库/目录或模型输入输出 payload。

## 源码身份与 F0 对应

成功实验两端执行的 Chain 源码均为 `58851cf923f6a8b7190b50228b30f3e82a682f9c`。两端二进制分别固定：

- rog：`c7e530965245bfef7130aac901888ead31bc65b6dda087367c365a6616dbb9fd`
- ai395：`479dc3392b3b704501fa6c64520c967d09842774270128b40518a666748a8d3d`

rog 使用完整 `trillionnium/`、配置和必要项目边界文件组成的 sparse checkout；2,014 个实际 materialized 文件、34,249,944 字节在编译前后逐 Git blob 核验相同。Cargo 为 1.95.0、locked/offline、默认 feature、独立 target，编译 exit 0。两端实际 `trnm-cell.d` 列出的 **96 项仓库输入**的规范化路径、Git blob 和 SHA256 完全相等。

将这 96 项与冻结 F0 `4505a598d6ec2644a175e47398d4a5f3f054bc5e` 比较，全部 Git blob 相同；另 **29 项 Cargo/lockfile/工具链配置**也全部相同。闭包外差异逐项列在 [source-correspondence.json](source-correspondence.json)。

**这是一份源码对应核验；实测身份保持 58851cf。没有把实验重标为 F0，也没有声称在 F0 重编译或重跑了上述实验。** dep-info 记录覆盖其报告的仓库输入，不充当编译器、系统库、依赖供应链或全链安全证明。

## 复核与文件布局

执行：

```sh
python3 -B verify.py
sha256sum -c SHA256SUMS
```

离线 verifier 检查三个包及每个内嵌文件的原始字节 hash、原生请求限额、数据/响应字节分列、全部 fetch 与 provider 的时段重叠、三次原生失败、模型投影的原始 receipt 绑定、两端输入集合及 F0 对应。它验证已保留观察的完整性和一致性，不启动新服务或重跑模型，也不产生独立运营方资格。

- [summary.json](summary.json)：主要结果、实际时段、每文件数据、失败和明确的资格边界。
- [manifest.json](manifest.json)：三份原始字节包及源码对应报告的 SHA。
- [desktop-evidence.json.gz](desktop-evidence.json.gz)：desktop 原始 consumer 超时、其构建记录、早期准备失败和成功实验的完整 PTY 文本观察。
- [rog-evidence.json.gz](rog-evidence.json.gz)：原生 provider、失败/成功准备、sparse 输入核验及受限暂存记录。
- [ai395-evidence.json.gz](ai395-evidence.json.gz)：三个失败 provider、成功原生 consumer、两端对应所需输入审计及明确的公开模型投影。
- [verify.py](verify.py)：标准库离线复核器。

包采用 content-addressed 字节去重。普通记录保留原始文件字节；模型摘要明确为公开投影，完整原始私有记录仍留在实验主机。未打包 keys、私有 Hepta 源码、owner 数据库/目录或模型材料 payload。
