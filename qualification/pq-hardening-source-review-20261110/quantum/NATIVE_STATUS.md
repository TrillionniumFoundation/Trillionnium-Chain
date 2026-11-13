# Native TLS validation status

**状态：BLOCKED — 实际启动和完成状态未知；没有可确认的 Rust / TLS / Clippy / fmt 通过结果。**

记录日期：2026-11-10。候选基线：`da1374a200022bc14dc2bd325cc9ba29dbcd24ab`。全链资格维持 **HOLD_NO_GO**。

## 已实际确认的只读发现

| 项目 | 已观察结果 |
| --- | --- |
| 主机与用户路径 | `rog`；`/home/qq/work` 不存在，实际目录在 `/home/qian-qi/work` |
| 可读源码工作树 | `/home/qian-qi/work/chain-cell-native-shard-674c72-20261110-publish` |
| 该工作树 HEAD | `06233be630f8eff6cea59cd5111e5941135a4aa5`；不是本次待验证的 da1374 |
| 默认 Rust | cargo / rustc 1.94.0 |
| 仓库要求 | Rust 1.95.0，clippy 与 rustfmt |
| 系统 provider | OpenSSL 3.5.5；真实列出 ML-DSA-65、ML-KEM-768、X25519MLKEM768 |
| 证据合同 | 原仓库 provider 脚本固定 OpenSSL 3.5.9；不能将系统 3.5.5 记为此合同通过 |

只读发现 job：`1a1c46bab2c-cf39-313`；provider 检查 job：`1a1c46eb785-cf39-32d`。原始 stdout 分别为 9,548 和 9,746 字节，stderr 均为空；保存在 `rog-discover.*.log` 与 `rog-provider.*.log`。这些观察没有确认 Rust 1.95.0 已安装或 ProfHepta 身份检查已通过。

## 已提交的验证请求与失败回执

稳定 idempotency key：

```text
chain-pq-0c8e-linux-tls-verify-da1374-20261110-v1
```

完整、可恢复的请求：`rog-tls-request.json`。规范化 JSON 请求 SHA-256（不含文件末尾换行）：

```text
7cff1de656bb285c15b71648a1ed36ca9d8646eeae820d0652f4aff113712be9
```

脚本：`rog_tls_validate.py`；SHA-256：

```text
6a762abce1f09c8ae2f652dc967a74ad3761a8ad6f2699edd9298f6058e79e49
```

请求使用 `h_process_start`，host=`rog`、executable=`python3`、args=`["-u","-","--execute"]`、stdin 为上述完整脚本；timeout=3,600 秒，CPU quota=200%，MemoryMax=8 GiB，nice=5。完整参数及摘要保存在 `rog-tls-request-manifest.json`。

三次**同一请求、同一 key**的提交或恢复均返回：

```text
tool call error: tool call failed for codex_apps/h.process_start
Mcp error: -32603: MCP request timed out
```

原始回执依次保存在 `rog-tls-start-attempt1.json`、`rog-tls-start-attempt2.json`、`rog-tls-start-attempt3.json`，三者均为 `isError: true`，均未提供 job handle。第三次恢复在收到停止连续重试的指示前已经提交；此后没有新增远端请求。尚未完成的辅助 host-inventory 等待已结束；**没有调用取消原生 durable job 的接口**。

这些是 MCP 回执超时，不是已经观察到的编译失败或测试失败。它们不能证明任务没有启动，也不能证明任务已经完成。专属目录是否创建、基线是否检出、preflight 是否通过、provider 是否构建、负控是否运行，均未确认。

## 脚本计划执行的范围

脚本已做本地 Python 语法检查，未获得远端执行日志。它先核对 ProfHepta 身份、Rust 1.95.0 与源工作树 preflight，再新建独占目录 `/home/qian-qi/work/chain-pq-0c8e-linux-20261110`；目录已存在即拒绝重建。它不删除其他目录、不修改其他项目的工作文件、不推送远端，也不修改全局 Rust default。构建输出和证据位于专属目录，Rust/Cargo 使用现有配置的工具链与依赖缓存。

计划步骤为：独立 checkout 固定 da1374 并核验四个原始 Git blobs；运行仓库原始 OpenSSL 3.5.9 builder 和真实 smoke；先仅应用新增测试，登记并分别运行三个负控，要求它们在原实现上实际失败；逆转测试补丁后应用完整修复；运行 canonical 与 TLS 两个既有完整 scoped suites、node scoped strict Clippy、workspace fmt check，以及 lockfile 摘要检查。所有命令的原始 stdout、stderr、退出码均由脚本保存。

补丁摘要：

| 补丁 | SHA-256 |
| --- | --- |
| negative-controls-only.patch | `24f142a6fca0f25d8d525ef4fd22c3f0b03485bf484f17463d4959d37830082b` |
| exact-spki.patch | `939910be8e0941fae8f5431d3977de0182a82bcfeda255888e87648c0c9e90e8` |

以上均为**待观察的执行范围**，不能写为已通过。独立完成的 Python 数值模型结果见 `review-summary.json`，不构成此原生验证的替代。

## 恢复方式

只能读取 `rog-tls-request.json` 中的精确参数，再调用相同 `h_process_start`；保留上述 key、stdin、资源参数和目标目录。取得 handle 后先读取原任务状态与日志。不要换 key 创建第二份验证，也不要覆盖已有专属目录。先前 `rog-runtime-observations.json` 是完整验证提交前的只读阶段快照；本文件记录当前未知执行状态。
