# e70 原公开入站与完整 History：失败证据只读回读

本目录只增加失败证据、可重复读数和源码审查结论。没有修改运行时、
资源限制、业务规模、截止时间、计费、progress callback、SQLite 校验或激活条件。
没有重新执行原负载，也没有提升任何安全、模型、生产或公开网络资格。

## 固定身份及结论

被测提交是 `e70f13448aad715286fb8eb56fc802b09db643a3`，tree 是
`1fc19c44ab2d4b35672b25d0f4e4039b769cadea`。本目录之后的文档提交不继承该提交的
native 资格。PR 描述中的旧提交身份不能替代 artifact 的 source-before/source-after。

| 原入口 | GitHub run / artifact | 原结果 |
| --- | --- | --- |
| 固定宿主 F0，x64/head | [42352433638](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42352433638)，artifact `13565944759` | `NATIVE_F0_FAILED`；`BASELINE_MUST_PASS`；4 秒 SLO 成功 `0/6` |
| 原三轮 native campaign，x64/head/release | [42352433857](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42352433857)，artifact `13566067509` | `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`；三轮均 exit 101；三轮九个 phase 全部未满足原有限验收 |
| 原完整 History，x64/head | [42352433738，job 128343246264](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42352433738/job/128343246264)，artifact `13568123690` | 原 4105 块测试失败；独立 confirmer 未完整同步，未激活到 4105 |

全部结构化回读见 [readback.json](readback.json)。它保留源记录中的失败、未知值和资格
标志。读回脚本 exit 0 只代表读取并核对指定 artifact 成功。

## F0：诚实 baseline 本身已经不满足原 SLO

原输入保留 1024 个 seed transfers、4 个 seed blocks、21 个业务块、30 秒 phase、
baseline 与 valid-work-root 两个 phase、ROOT 24 个 attacker、每 phase 在第 1/5/9 秒
计划发起三轮、确认深度 6，合计 6 个确认和 42 个业务包 exposure。
没有缩小分母，也没有把未启动的轮次从分母移走。

baseline 第 0 轮实际从 `1,000,466,856 ns` 开始，在 `28,383,077,029 ns` 结束，
调用耗时 `27,382,610,173 ns`。从计划时点计算则是 `27,383,077,029 ns`。
它在原 30 秒压力窗口内确认，但未达到原 4 秒 SLO。baseline 后两轮与 ROOT 的
三轮也均未满足原 SLO。`controller_resources_complete=true` 和
`all_services_known_empty=true` 没有把 `complete_success=false` 变成成功。

### 计时必须区分累计快照与阶段差值

| baseline 客户端阶段 | 开始累计次数 | 结束累计次数 | 阶段增加次数 | 阶段 CPU ns | 阶段 wall ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| account_graph | 34 | 96 | 62 | 4,108,729,032 | 18,545,875,529 |
| verify_state | 47 | 131 | 84 | 4,235,189,074 | 18,750,493,674 |

`account_graph` 结束累计值是 CPU `4,179,403,962 ns`、wall `18,839,053,285 ns`，
不是 baseline 阶段增量。读回 JSON 同时保留 before、after 和机械相减的 delta。
这些是嵌套区间，不能求和当成完整成本；调用线程 CPU 不包含 scoped workers。
这证明当前 baseline 中 account graph 是显著成本，但不能据此判断每次验证都冗余。

## 三轮原 campaign：记录齐全不等于成本问题关闭

三个原 run 都正常产生 report，`phase_startup_errors=[]`，无 report validation failure，
且记录 `economics_complete=true`。然而三轮都 `original_criteria_met=false`，九个 phase
均 `finite_phase_criteria_met=false`、`all_signed_rounds_confirmed_in_window=false`、
`receiver_client_state_equal=false`。三轮 `best_observed_cold_legal_method` 均为
`maintenance-limb`。

该入口自己的原参数与外层资源记录在 JSON 的 `original_inputs` 与 `expected_resources`；
它与固定宿主 F0 是两个不同原入口，不能混用资源及通过判据。
有限同宿主 TCP loopback 的记录齐备，不能证明跨 receiver、Sybil、失败与取消成本下
的公开服务公平性，也不能替代 WAN、独立运营方或密码工作硬度资格。

## History：4105 是否已激活，需要区分两个节点

原配置 `blocks=4105`、`renew_every=900`；artifact 中有 4105 个 packet 文件。
服务端原 lifetime 为 1800 秒，真实退出记录为 `reason=lifetime_expired`，
退出前 `stop_requested_before_shutdown=false`，`server_exit_ok=true`。
内部 shutdown 之后的 `stop_requested_when_exited=true` 不能解释成外部取消。

独立同步在总 elapsed `3,205,285,317,767 ns` 时记录
`IO: Connection refused (os error 111)`，失败位置为 `history-rpc`，此前成功返回的
import call 为 2362。原错误观测中的 `durable_committed_blocks` 和 `activation_cursor`
仍为 `null`；本目录没有把成功返回次数重标成该观测的持久提交计数。

对 artifact 中两个 SQLite 主文件额外做了独立只读查询：

| 留存节点 | blocks 行数（含 genesis） | 最大留存高度 | active 高度 | active generation | pending reorg 行数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| validator | 4106 | 4105 | 4105 | 4105 | 0 |
| 独立 confirmer | 2363 | 2362 | 0 | 0 | 0 |

validator 的 active tip 为
`d36d62758db50cdb3a27fd2ddbafb174f6860eb07bca32fb9a87bc44b86db215`；
confirmer 的 active tip 仍是 genesis
`13632417743090d77acfc37438d343953a79181379d57f8351e71c279f07d294`。
因此生产者本地链到了 4105，但完整 History 采用方未完成到 4105 的同步及激活。
主文件读回不能新增重启、WAL 恢复或崩溃一致性的验收结论。

原 time 记录是 user 335.58 秒、system 465.67 秒、wall 53:25.28、最大 RSS 16,596 KiB、
swap 0、文件系统 outputs 3,216,832（time 原单位）。其中 socket counters 为 0
不能解释成网络使用为零。原 manifest 仍是 `passed=false`、
`native_execution_authenticated=false`、`named_execution=null`，并保留全部三项失败。
source-before/source-after 与 binary-before/binary-after 元数据一致，仍不构成成功验收。

## 源码判断：不能直接删除重复验证

审查只针对上述被测提交。以下现成优化已经在 e70 中，不能重复提出为尚未实现的修复：

- [verify_state_with_readback](../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs)
  每次重新读取 record，校验当前 complete State，保留首尾 progress；只在私有 scope
  满足条件时复用 graph。尾部 callback 写入会失效 scope 并回到原完整 verifier。
- [PostWriteReadback](../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs)
  只在原 writer transaction 中工作，不留存于 Node，不序列化、不克隆，也不授予恢复权限。
  同一 Root 或受限 subtree 的复用有独立当前性边界。把它扩展到独立 read_active/state_at、
  跨 callback、跨 transaction 或重启后的有效性缓存，会改变现有完整性合同。
- [NodeReader](../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_node_reader.rs)
  已复用 SQL 程序、读取当前 BLOB 并在 callback 前释放 cursor；
  [native_node_decode](../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_node_decode.rs)
  已在相同 expected ID 与当前实际字节一致时复用解析。它们不缓存 SQL 行或有效性判定。
- [history_page](../../trillionnium/crates/trnm-pon-node/src/store/history_page.rs)
  已按 64 个祖先一批读取，最多保留 16 个页 ID，保留真实 ancestry 和当前行检查。
  [reverse_path](../../trillionnium/crates/trnm-pon-node/src/store/reverse_path.rs)
  已用 128 个 locator 的有界缓存和分批 spool；不存在简单的每块一次文件 seek 修复机会。
- [host_kernel_parent](../../trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs)
  的当前宿主路径、cgroup 与限额检查及
  [history_import](../../trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs)
  的期限、真实 CPU owner 结算和错误优先级都是合同边界，不能为了性能跳过。

本轮没有找到能仅靠局部测试证明安全、又足以关闭原失败的运行时小改。
下一步可用原负载继续定位 legacy History 的完整 RPC/import 累计开销，以及每类
account graph 调用的 role 和有效 scope；当前错误记录只给最后一个 RPC 和成功返回
计数，不能据此选定安全删减点。任何后续优化都应保留 callback、SQL mutation、reorg
及实际输入当前性检查，然后在相同原入口和原资源下重跑。
不能通过延长 lifetime、扩大 CPU、缩小 4105、放宽 SLO 或换成合成案例关闭该门。

## 重复回读与本轮验证

从上述 GitHub runs 取得原 ZIP，以 `readback.json.artifacts` 中的文件名保存到一个目录。
[reproduce.py](reproduce.py) 先核对三个完整 ZIP 的 SHA256，再核对 F0/campaign 留存二进制、
内部 report 及 History 的 preparation/log/resources/summary 哈希与身份。
History ZIP 没有留存其 native 二进制；其 binary SHA 是原 manifest 的前后元数据，
本目录明确保留这个区别。SQLite 只复制两个固定成员到临时目录，以
`mode=ro&immutable=1` 打开，结束后确认字节不变并删除临时副本。

```bash
python3 evidence/pon-current-inbound-history-e70-20261107/reproduce.py /path/to/original-zips > /tmp/e70-readback.json
cmp evidence/pon-current-inbound-history-e70-20261107/readback.json /tmp/e70-readback.json
```

本轮仅验证证据读回，不运行 native 验收；当前本地容器也没有原固定 root cgroup。
独立 worktree 与 evidence 目录隔离于其他并行任务。无需新 Cargo target 或远端负载。

已完成的本地验证：三份原 ZIP 与内部引用哈希核对；两次 JSON 输出逐字节一致；
错误 ZIP 在解析前因 SHA256 不符被拒；全部三项原验收保持 false；只读 SQLite 前后
字节一致；`check_repository.py` 通过（26 个 workspace packages、25 条 normal dependency
edges、1169 个 Rust 文件、3453 个本地 Markdown 链接）；现有 source-integrity 43 项与
原 evidence-source 38 项测试通过；`git diff --check` 通过。
这些是证据及源身份校验，不是新 native 测试或原负载重跑。
