# Hosted 原始 native campaign 失败只读诊断

本目录保留 #800 与 #801 的原始 hosted 失败诊断。没有修改仓库源码或最终证据 tree，没有重新构建、运行 native 测试、触发 CI，也没有改变原 Actions artifacts。结论是**原始压力资格仍未通过**；这里不是新的 PASS 证据。

## 来源与获取边界

| 分支 | 被测 source | Actions run / job | Artifact ID |
| --- | --- | --- | --- |
| #800 loader | `059e149ccf683a69e6dad4e7f5a21fdd76b671fc` | `42477996505` / `128723533540` | `13616134240` |
| #801 effects | `1910baa6c3421cc17ea5578b5eae431038212e88` | `42477998311` / `128723539762` | `13616159095` |

Actions job 链接：[#800 原始 campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42477996505/job/128723533540)、[#801 原始 campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42477998311/job/128723539762)。

使用 HTTP Range 读取 ZIP 中央目录和选定成员；没有全量下载 ZIP，所以不声称重新计算过整个 ZIP 的 SHA。每个 ZIP 提取的 10 个成员均经过 ZIP CRC 检查，并逐项核对其长度和 SHA256 与保留的 `artifact-files.json` 一致。其中包括三份 stderr、三份 phase readback、第一轮完整 raw report、results、runner 和 hardware。六份 stderr 还逐项匹配了原 campaign attempt 的 SHA；两份完整 raw report 匹配了各自 attempt 的 SHA。两份第一轮原始报告又通过项目现有 `pon_public_v3_phase_read.read_report` 重算；除输入文件本地路径外，重算结果与 hosted 保留的 readback 完全一致。

第二、三轮读取了完整 stderr 和 phase readback，没有再获取完整 raw report 或独立重算它们。所有核对结果与完整 SHA 列于 [diagnosis.json](diagnosis.json)。

## 已确定的失败

每个 source 的三次原 campaign 均 Cargo exit `101`，`original_criteria_met=false`，没有 `phase_startup_errors`。stderr 指向 `public_v3_multiprocess.rs:1765` 的最终 finite experiment 断言；`:1541` 是保留失败后的重新抛出，不是另一个起因。

| 阶段 | 六次 campaign 的共同结果 | 未满足的原准则 |
| --- | --- | --- |
| baseline，无攻击进程 | 每次仅确认 1/3 轮；receiver/client 最终状态不同 | 三轮全部在窗口内确认、最终状态一致 |
| from-zero，24 个攻击进程 | 每次 0/3 轮；仅 7 个按时 Submit；没有预算耗尽；`PUBLIC_REQUEST_DEADLINE` | 三轮确认、最终状态一致、无 verifier error、三轮 overlap、至少 21 个被接受 work、轮内真实 depletion |
| late-product，24 个攻击进程 | 每次 0/3 轮；仅 7 个按时 Submit；没有预算耗尽；`PUBLIC_REQUEST_DEADLINE` | 同上 |

全部 18 个阶段 `native_phase_criteria_met=false`。全部 observer 记录完整；hostile 阶段都是 24/24 actors ready，actor report 成功且没有 cap 或强制 kill。没有证据把这些失败归于本地 AF_UNIX `EPERM`，也不是没有进入实际阶段的启动失败。

三次 loader baseline 的按时 Submit 数为 13、13、14；effects baseline 均为 14，原目标为 21。loader baseline 第一、二次的 verifier error 列表为空，第三次有 deadline；effects baseline 三次均有 deadline。具体 18 行结果见 [phase-summary.json](phase-summary.json)。

## 超时实际发生的位置

第一轮两份完整 raw report 中，hostile 失败保留在 `client_import` / `receive_public_page_from_before_observed`，使用原固定 30 秒绝对截止时间。loader 的前三次 history import 分别约 7.1–8.0 秒，第四次在 deadline 返回失败；effects 前五次约 4.4–5.2 秒，第六次返回失败。拒绝的具体 page/packet interval 保存在每个目录的 `run-1-timeout-readback.json`。

固定 phase Host 仍为 `cpu.max=25000 100000`、内存 2 GiB；controller 是 `400000 100000`、16 GiB。没有修改这些资格参数。loader 第一轮 Host 约消耗 8.4–8.8 秒 CPU，整个 phase（含 setup/收尾）约 34–35 秒墙钟；baseline 的 346 个周期中 332 个发生 throttling，两个 hostile 分别为 351/353 和 352/354。这些计数描述原固定资源下的实际运行，不能作为放宽配额或窗口的理由。

第一轮 loader 两个 hostile 的 paid mutation CPU 分别约 4.05、4.23 秒；原预算 refill 是每秒 0.25 秒 CPU，最终 credit 分别仍约 1.9992、1.9999 秒，`mutation_cpu_refusals=0`。全部 12 个 hostile 阶段都没有观测到真实 depletion。确认超时与未观测到耗尽共同造成未过门；不能把未耗尽改述为耗尽后恢复成功。Host、importer、packet 和 worker CPU 有嵌套/排除关系，不把这些不同口径相加。

## 与本轮 loader 改动的关系

实际 campaign 从 `StateBackendChoice::open` 调用普通 `Node::open_with_authenticated_state`；`NativeOwners` 中 policy、mining、continuous、pq_network、pq_witness 全部为 `None`。该路由没有进入本轮 `HeldCatalog::read_role` 或 M15 环境、profile、ELF 加载入口。

已对 Git blob 原始字节计算 SHA：七个 campaign/support/runner/reader 文件及 `ingress/history_import.rs` 在 base `8d8f055...`、source `059e149...`、source `1910baa...` 三处一致。另核对 `store.rs`、`ingress.rs`，它们在 loader base→source 完全一致，但 effects 与 loader 不一致。完整十文件对照见 [source-common-paths.json](source-common-paths.json)。

这些是静态调用路径与文件身份事实，**不构成同环境性能对照，不能证明失败来自旧版本，也不能排除不同二进制或本轮改动的间接性能影响**。没有把两个分支都失败作为继承失败的证据。另两个 `run_from_zero_native.py` CI gate 未在本诊断中读取，不能仅由名称相近把它们归为同一个谓词或同一原因。

## 可直接复核的原始文件

两目录分别为 `loader/` 与 `effects/`，均有 `run-{1,2,3}.stderr.log`、`run-{1,2,3}-phase-readback.json`、`run-1-raw-report.json`、`artifact-files.json`、`results.json`、原 `run-native-campaign.py`、`hardware.json`。`run-1-predicate-readback.json` 是对应 Rust 合取准则的逐项计算；`run-1-timeout-readback.json` 提取原始 import 错误、期间和 Host 计数。

| 完整原报告 | 字节数 | 已核对 SHA256 |
| --- | ---: | --- |
| loader/run-1-raw-report.json | 26,388,453 | `674d230d5ad33b5d55df9ac4a483c77e7cd725cfdba08db70aabe91dc5bb68e7` |
| effects/run-1-raw-report.json | 48,646,566 | `c634909a593ca8e513b492df6fe640e15d40af31c9ec9d13e1fc4e7391a486fb` |

所有完整压力、独立管理节点与 production activation 资格继续 HOLD。

## Durable publication

This is a separate evidence branch, with no modification to any implementation
or the tested heads of PRs #797, #800, #801 or #802. The complete acquired and
derived lane records are retained in [raw-and-derived-records.tar.gz](raw-and-derived-records.tar.gz).
[The archive manifest](archive-manifest.json) records each member and a second
byte/hash check against the original artifact references. Archive file metadata
was normalized for reproducibility; member bytes were not changed. The files
described under `loader/` and `effects/` above are members of this archive.

This publication does not rerun any native test, change limits, or promote the
failed original campaigns to success. Whole-ZIP hashes remain GitHub-reported
values; this archive contains the verified selected members, not the original
whole ZIP.
