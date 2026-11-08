# bb026697 性能原合同只读审计

**结论：HOLD。** 本次只读源码、GitHub run 元数据和已完成的原始 artifact；没有构建、执行 native workload、dispatch workflow、改动服务或转账。审计文件写在本任务独立目录。

后续入口核验见 **DISPATCH.md / dispatch-verification.json**：实际 F0 注册项已确认为 active；原 main 404 和无 run 查询仍分别保留。随后 root 合法触发的一次 F0 已由只读查询确认为 run **42509669473**、workflow_dispatch、精确 head bb，见 **f0-dispatch-run-first-observation.json**。下文初轮状态保留其原时间；后续执行证据不覆盖初轮观察。

原 campaign 已完成且三个 native attempts 全部失败，完整归档、资源/来源复核及 27 槽结果见 **original-campaign-run-42508015918/README.md**。最终复核来自完整 clean bb clone，记录在 **archive-verification-v3.json**；build 成功和原记录完整未被转作性能 PASS。

唯一合法 F0 run **42509669473** 现已完成真实 native failure（exit 101）。六槽严格四秒成功 **0/6**：一个在 30 秒阶段内确认但花费 22.602926924 秒，两个已观察失败，三个未观察；42 个 packet exposures 均保留。原 ZIP、全部 manifest/source/ELF/resource 复核和 finalizer 回算见 **f0-run-42509669473/README.md / artifact-audit.json**。三个服务最终均已知为空，finalization 红灯保留性能失败，不是 cleanup 故障。下方初轮状态不被回写成后来结果。

| 来源 | 固定身份 |
| --- | --- |
| Chain head | `bb026697a972521009bc133ae6ed2b653e18e931` |
| Chain tree | `18175756871bf341586fc37be1b17a00ef1dd099` |
| 配对 Hepta | `36d5eff44f4071bb1f250b1c7706dc690cf0a875` |
| PR | [#817](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/817)，draft，base #812 |
| 审查来源 | `/workspace/scratch/3a200666069f/chain`；18 个相关文件均逐字节等于上述 commit 的 blob，SHA256 在 audit.json |
| 预定 desktop 来源 | `/home/qian-qi/workspace/chain-seven-gates-20261108-3a20/source-exact`；本审计没有重跑该 checkout 的 build/source guard |

## 1. 已有原生入口及最关键的合同区别

| 原生路径 | 保留的 workload | 当前成功条件与边界 |
| --- | --- | --- |
| 原 campaign：`separate_process_work_and_signed_confirmation_campaign` | release / Rust 1.95.0 / RawR14 / authenticated-v1；3 次完整运行，每次 baseline、from-zero、late-product；每 phase 30 秒，hostile 24 个独立进程 | depth 6 且在整个 30 秒压力窗口内确认。t=1、5、9 是调度时间；现有 finite PASS **没有**逐轮严格四秒断言 |
| F0：`fixed_public_host_root_rejection_and_signed_confirmation_diagnostic` | 同一已准备业务字节的一次 baseline 与 valid-work-root；各 30 秒，hostile 24 个进程，1 个 M06 worker | 每个预定槽从 scheduled offset 到结束严格小于四秒，包含排队及前轮延迟；6 槽必须全部满足。仍明确 `original_campaign_qualified=false` |
| native fullpath | valid / duplicate / late_product / cancelled 四个预登记 component attempts | 检查原生接受、去重、拒绝和取消；不是 matched pressure confirmation 或业务容量合同 |

F0 runner 和 workflow **已在 bb**；`formal/throughput-v1` **不在 bb**。本审计没有借用未合并 #804 的源码或通过记录。

原 campaign 的 deadline 证据在 [native confirmed predicate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1105) 与 [原 reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/read_original_native_campaign.py#L610)。F0 的新增严格 SLO 在 [f0_rounds](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/run_fixed_host_root_f0.py#L307)。因此，原 campaign workflow 绿色本身不足以关闭用户的四秒合同；不能将四秒间隔解释为四秒 deadline。

### 不能混淆确认数和包数

每个 phase 的 21 个 business packets 是三组，每组一笔 signed transfer 所在块，加六个空维护后继块以达到 depth 6。**每 phase 只有 3 笔业务确认。** F0 两个 arm 共有 42 次 packet exposures、6 个确认槽；两个 arm 重放同一批字节，不是 42 笔业务交易。原三次 campaign 总计 9 phases、189 包暴露、27 个确认观察槽，亦不能称为 189 笔已确认业务。

1,024 笔 seed transfer 和业务块均由真实开发链 Node 签名、搜索、执行和持久化产生，但在测量 phase 之前准备；其 CPU/wall 另记。phase 延迟不包含新任务首次挖掘/证明生成的全部成本。依据：[signed business preparation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1569)。

## 2. 资源与执行上下文不能放宽

公共接收端及普通 History verifier 使用固定 `trnmponpublic.slice`：

- `cpu.max=25000 100000`，`cpu.max.burst=0`；
- `memory.max=2147483648`，`memory.swap.max=0`；
- `pids.max=256`，非 root UID/GID、NoNewPrivileges、空 capability bounding set。

外部 controller 保持 `cpu.max=400000 100000`、16 GiB、nice 10、至少 4 个 affinity CPUs，且读取全部祖先限制；hostile 进程留在该 controller domain。F0 controller 为实际 systemd service，校验 MainPID、birth/cgroup、prior intent、receipt、KillMode 和 600 秒 RuntimeMax；phase service 上限 300 秒。原 CPU 信用 burst 2 秒 CPU、refill 每秒 0.25 秒 CPU、start reserve 0.1 秒 CPU 不变。上限是 ceiling，不能称为物理资源预留。

两个固定 Host launcher 都要求真实 GitHub CI 上下文。普通 desktop 未设 phase-host 时走历史 local diagnostic；设固定 profile 后仍要求 CI 身份与真实 service。**不能填写虚构 GITHUB_ACTIONS/run/job，复用别人 service，或降低限制使本地运行被接受。** 已有 2 CPU / 8 GiB job 不满足该 controller 合同。

依据：[Host limits](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/ci/public_host_ci_observation.py#L15)、[原 launcher CI guard](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/ci/run_native_phase_host.py#L302)、[F0 launcher](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/ci/run_fixed_root_phase_host.py#L447)。

## 3. 当前真实 CI 状态；不重复触发

fullpath 原始 artifact 于 2026-11-08 18:11:19 UTC 后读取；原 campaign 随后更新为 in_progress（GitHub updated_at 为 18:13:58Z）。状态可能继续变化。

| Run | 固定来源与观察 | 本次结论 |
| --- | --- | --- |
| [42508015918](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015918) 原 campaign | pull_request、attempt 1、head=bb；in_progress | 已自动启动流程，等待现有运行；未重复 dispatch |
| [42508015727](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015727) native fullpath | pull_request、attempt 1；18:10:59Z completed/success | 已下载并读取原 artifact，组件 HOLD，见下 |
| F0 | 该 head 的 19 个 PR runs 中没有 F0；相对 #812 的实际改动也未命中 F0 workflow 的 path filters | 本轮未观察到 F0 执行 |

默认分支为 `main`，F0 和原 campaign workflow 的 main 文件 GET 均返回 404；候选 bb 的 F0 文件读取成功。本次没有尝试 dispatch API，也没有证实当前可用的手动 dispatch 入口，不能把文件读取结果写成已观察到的 API 拒绝。保留缺口，不通过修改 guard 或伪造环境补齐。

### 已完成 fullpath 的原始回执

Artifact `13628047668`，原 ZIP 130,012 bytes / 51 members；SHA256：

`d9e23a88ec31be8d73054eaa519456989fed309b4c5f9801989e5c2de45f6646`

下载后的 ZIP SHA256 等于 GitHub artifact digest。原 before/after source receipts 一致：

- `kind=head`，`tested_commit=bb026697a972521009bc133ae6ed2b653e18e931`；
- `tested_tree=18175756871bf341586fc37be1b17a00ef1dd099`；
- `prospective_merge=null`，实际 tracked bytes 检查成功。

原 reader：`overall_gate=HOLD`、`security_gate=HOLD`、`performance_gate=COMPONENT_OBSERVATION_ONLY`。4/4 attempts 为 accepted / duplicate / rejected / cancelled，唯一新块 1、有效 attempt canonical depth 0、`timely_accepted_progress=0`、production activation false。collector 记录 9 个原生进程、source/binary unchanged；这些不是完整 build/load closure 或当前性能资格。

原 ZIP、reader stdout/stderr、collector、before/after receipts 原字节均随本目录保留。这里按 **head bb** 记录；没有借 tree 相同而改称 prospective merge 测量。

## 4. 已有尾延迟代码与尚缺的资格

现有 `pon_public_v3_phase_read.py` 有 known/unknown 数、经验 p50/p95/max，以及包含接受和拒绝结果的 retained terminal request p99。p99 仅在该 retained entered cohort 所有结果结束、耗时已知时提供；unfinished、缺时钟、未进入或丢失记录不能删掉后当作完整尾延迟。

但 `whole_request_population_p99_ns`、`business_tps_capacity`、原 reader 的 `sustainable_business_tps` 明确为 null。F0 是每 arm 三个业务确认观察，不是持续负载容量测量；当前本审计又没有 F0 原生样本。因此：

- qualified goodput：未建立；
- 原合同四秒下的完整业务尾延迟：未建立；
- 小 cohort request p99、网络 ACK、21/42 包暴露、build/source-control 成功均不能代替上述指标；
- 必须保留失败和 Unknown 分母，不能只统计成功响应。

依据：[tail reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/pon_public_v3_phase_read.py#L60)、[explicit capacity scope](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb026697a972521009bc133ae6ed2b653e18e931/scripts/read_original_native_campaign.py#L808)。

## 5. 可执行前置命令与边界（本审计未执行）

普通 desktop 合法工作范围是 **prepare**；本来源没有可在普通 desktop 合法完成固定 Host 资格的完整命令。下列准备放在当前 32+17 工作结束后的独立 target/output；要求 Rustup 1.95.0、rustfmt、clippy 已安装，锁定依赖可用，且没有 undeclared RUSTC/RUSTFLAGS/wrapper/profile overrides。runner 对该类 override 会拒绝，保留失败，不应绕过。

```bash
set -euo pipefail
cd /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/source-exact

test "$(/usr/bin/git rev-parse HEAD)" = bb026697a972521009bc133ae6ed2b653e18e931
test "$(/usr/bin/git rev-parse 'HEAD^{tree}')" = 18175756871bf341586fc37be1b17a00ef1dd099
/bin/bash scripts/project-preflight.sh --audit

/home/qian-qi/.cargo/bin/rustup run 1.95.0 rustc -Vv
/home/qian-qi/.cargo/bin/cargo +1.95.0 -Vv
/usr/bin/env CARGO_HOME=/home/qian-qi/.cargo RUSTUP_HOME=/home/qian-qi/.rustup \
  /home/qian-qi/.cargo/bin/cargo +1.95.0 fetch --locked \
  --manifest-path trillionnium/Cargo.toml --target x86_64-unknown-linux-gnu

/usr/bin/env CARGO_HOME=/home/qian-qi/.cargo RUSTUP_HOME=/home/qian-qi/.rustup \
  CARGO_INCREMENTAL=0 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B scripts/run_fixed_host_root_f0.py prepare \
  --out /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/perf-f0-bb026697-prepare-01 \
  --target-dir /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/target-perf-f0-bb026697-01 \
  --cargo /home/qian-qi/.cargo/bin/cargo \
  --expected-head bb026697a972521009bc133ae6ed2b653e18e931 \
  --expected-tree 18175756871bf341586fc37be1b17a00ef1dd099
```

`--cargo` 必须是具有相邻 `rustup` 的 shim，不能传 toolchain/bin/cargo。成功准备产物是 `prepared.json` 和 chmod 0500 的 `public_v3_multiprocess.bin`；来源前后检查、fmt、strict Clippy、release build、七个精确 native source controls 均需要成功。实际 selector 仍未执行。profile 必须 opt-level 3、debug assertions false、overflow checks false、debuginfo 0；锁图和二进制 hash 原样保留。

这不是运行时间估计：源码 cap 是 Clippy 900 秒、build 1,800 秒、每个 control 30 秒；F0 真正 native selector 外层 540 秒、controller 600 秒，只有两段各 30 秒测量窗口。原 campaign workflow 上限 80 分钟、build 1,800 秒、每次完整 native campaign 600 秒、controller 4,200 秒，三次测量窗口共 270 秒。实际排队、准备与失败时间不能从这些上限预测。

### 读取现有原 campaign，仍不新触发

```bash
/usr/bin/gh api repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015918 \
  --jq '{id,head_sha,event,status,conclusion,run_attempt,path,html_url}'
```

完成后（成功或失败）下载它的既有 artifact 到新目录；不要改 attempt，也不要删失败结果：

```bash
/usr/bin/gh run download 42508015918 \
  --repo TrillionniumFoundation/Trillionnium-Chain \
  --name pon-native-campaign-x64-head-release-bb026697a972521009bc133ae6ed2b653e18e931-1 \
  --dir /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/perf-original-bb026697-attempt-1
```

随后用本来源的 `scripts/read_original_native_campaign.py`，显式输入该 artifact 的 manifest SHA256 和上述完整 head/tree。它是只读回执验证器，不会执行 native test；若原运行失败，它应拒绝，而不是从其他 run 拼齐。原始 `run-*-raw/report.json` 及 retained `run-*-phase-readback.json` 可继续解释失败、时钟及请求尾部，但不能覆盖原失败。

## 6. 资金和外部效果

开发网络 fixture 使用确定性的 development identities 和 `Settings::development_with_profiles`，真实验证签名和本地 Node 状态；没有真实钱包付款或外部 payment provider 调用。`paid_cpu_debit_ns` 是 CPU 信用结算，不是货币转账。此性能入口本身不需要真钱授权，也不能证明真钱付款、Hepta 训练付款采用闭环、外部 FinalUse 效果或八域 PQ 安全通过。

需要系统管理能力的是固定 Host launcher：缺少 runtime slice 时会通过 `sudo -n` 安装经过哈希固定的 `/run/systemd/system/trnmponpublic.slice`、daemon-reload/start，再创建并按精确 ownership 清理服务。这只能在既有授权 CI 上下文执行。独立 WAN、外部 operator、设备加载、真实资金与外部 effect 的验收仍需各自证据。

**后续动作：观察现有 bb 原 campaign；保留 fullpath 的组件 HOLD；为真正的四秒、同资源同安全同负载 qualified goodput/完整业务尾延迟补齐来源内入口和原生观测。当前不改变 HOLD。**

