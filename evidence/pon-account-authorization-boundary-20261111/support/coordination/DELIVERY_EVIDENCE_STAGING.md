# 账户授权边界：证据整理与交付方案

目标目录名：`evidence/pon-account-authorization-boundary-20261111`。当前只准备仓库外 staging；本方案与 helper 不改源文件、不运行 Cargo／测试、不操作 Git、不触发远端动作，也不写最终项目 README。

## 输入与归属

`delivery-evidence-plan.json` 明确列出输入，没有“只复制 PASS”筛选：

| 输入 | 主机及精确源 | 内容 |
| --- | --- | --- |
| `validation/90ee…` | local-cloud／Y `90ee47159e32e9014410a1823bed05d84c17b858` | 全部原始记录、原始失败和 native-receipts |
| `validation/cdd9…` | local-cloud／Z `cdd984808a088e6c2e13b1e1ae6630a94d500c89` | 全部原始记录、同文件系统／GNU time 修复前后记录、后续 SIGKILL／ENOSPC 原始结果 |
| `primary-evidence-v1` | desktop／Z | 5 条已完成 primary 记录、工具准备首次失败和后继修复、原 archive／transfer 校验 |
| `repository-truth-evidence-v1` | desktop／Z | 首次完整 lane 失败、Python runtime 依赖修复、针对性控制、完整重跑及全部 raw files |
| `full-rust-evidence-v1` | desktop／Z | 原四条真实终态及 native exports 已逐字节收齐核验，3 PASS／1 FAIL；四个空 export 目录只保留目录清单 |
| `node-retained-evidence-v1` | desktop／Z | 原 `node-retained-preflight` 为 PASS；`node-retained-all-targets` 的原结果文件存在但为零字节，保留为 `INCOMPLETE_EMPTY_RESULT`。缺失的 source-after 目录单列为未证明执行的观察，不制造第三条 receipt |
| `node-retained-data-evidence-v1` | desktop／Z | 独立 `/data` 重试的 `node-retained-data-preflight`、`node-retained-data-source-before`、`node-retained-data-all-targets`、`node-retained-data-source-after` 四条记录；仍须等待真实终态及固定包哈希 |

原始 command 文件保留 context／result／stdout／stderr 和所在记录目录的所有其他普通文件。新旧主机与 source cohort 分开存放；相同记录的精确重复副本可以保留多个路径，但不重复计数。相同主机／source／ID 若出现不一致副本会阻止 staging。

原 `rust-baseline` 的 DA 测试实际为 713 通过／2 失败，完整门禁因此失败，后续原 oracle／release 步骤未到达。独立 Node 全包队列只补充被该失败挡住的 Node 验证范围；即使其后通过，也不替换原 baseline FAIL，不构成完整 workspace 门禁通过。原 Node 全包编译日志存在 LLVM ENOSPC，但 supervisor 没有权威终态，因此该命令不计 PASS／FAIL。后来 target 目录消失的原因未知，不归功于本任务的清理，也不据旧 ELF 哈希声称文件现在仍在。待接收包在本地核验完成前不计作已收集结果；未完成的队列不预填 PASS。

汇总、环境修复前后快照、collector 源码和静态审阅放在显式 `support/` 路径，并标注适用 source；它们不变成新的 execution receipt。二进制仅索引原已测量的尺寸／SHA-256／stat／测量范围，不复制 Cargo target 或 ELF。执行后的 binary hash 不能表述成执行时签名证明。

## 整理规则

- 普通缺失、空或损坏的结果仍阻止 staging；`require_terminal_records` 必须为 `true`。唯一归档例外是下节绑定完整原字节的原 Node 零字节结果，不进入终态 PASS／FAIL 数，不补写 result。新的 `/data` 四条记录仍全部要求真实终态。
- 有终态也须核对确切 source、tree、命令、finish、returncode、原 `pass` 与两个日志哈希。原始 FAIL 保持 FAIL；无法理解或自相矛盾的 receipt 阻止 staging，原始文件不改。
- 每个 desktop 包先核对 plan 中固定 archive SHA，再只读流式核对归档内全部原始成员，包括 manifest 自身。拒绝绝对／上跳路径、链接／特殊文件、重名、漏项、尺寸／哈希漂移；不解包执行。只检查当前解包 manifest 与文件彼此一致是不够的。
- 支持显式额外 transfer／collector 元数据，但它们必须在计划中列明；不能借此悄悄删掉未列入 archive manifest 的原始文件。
- 默认大文件阈值为 64 MiB。先列出准确路径、尺寸和 SHA；若需纳入，由审阅者在 `approved_large_files` 填入同一 `path`／`bytes`／`sha256` 三元组后重新 inspect。ELF／Cargo target 不因大文件批准而放行。没有自动截断日志、缩减 native exports 或自动替换成摘要。
- inspect 报告和 staging 均不能写入任何输入树或受保护源码目录。所有输出使用新文件／新目录，拒绝覆盖；发生失败保留部分目录，缺少最终 seal 时不得当作完整包。
- `final-validation-inventory.json` 的每条已列记录必须实际收集且哈希匹配；后来新到的记录另标 `listed_in_inventory_snapshot=false`，仍完整保留。不要把历史 inventory 快照中尚缺的条目当成成功或丢弃理由。

## 原 Node 未完成记录的精确例外

允许归档的身份固定为 `desktop`／Z／`node-retained-all-targets`，输入固定为 `desktop-node-retained`，原 job 固定为 `1a1c8980187-135c4-111`。白名单要求四个原文件都存在，并逐一匹配尺寸及 SHA-256：context 为 4,332 字节；result 和 stdout 均为 0 字节；stderr 为 4,193 字节。context 还必须具有实际 Z／tree；原 manifest 只能把该命令列为 incomplete，不能同时宣称 complete、PASS 或已知返回码。例外缺失、漂移、重复使用或根本未收集到均拒绝。

原 `result.json` 和冻结 tar 的同名成员保持原字节。为使一个本来就不是有效 JSON 的空文件不违反仓库对 `*.json` 的解析规则，只有这一个精确白名单成员在展开后的 staging 中投影为 `result.json.empty`。`record-index.json` 同时保留原逻辑名／哈希、原文件清单、实际 staging 路径列表和明确投影表；目标文件已存在则拒绝。程序在原 manifest、全部 tar 成员和原始 receipt 核验后才改变 staging 索引中的名字，没有修改原件、修复空 JSON、改变仓库检查器或对其他损坏文件采用此规则。

该记录的 `completed_result=false`，`recorded_pass`、`returncode`、`finished_utc`、执行后 `source_identity_intact` 均为 `null`。导出时观察到 Z clean 是另一个观察，不能代替缺失的执行后检查。最终 manifest 如包含该例外，`all_selected_records_terminal` 必须仍为 `false`，资格字段始终为 `false`。

helper 的正控、负控和旧行为回归只在私有副本上检查证据读取，包括 hash 漂移、错 host／source／ID／输入／job、缺白名单、非空坏 JSON、缺原件、错误 terminal 声明、投影冲突、重复消费和精确 terminal 副本只计一次。它们不执行任何收集到的 command，不执行项目测试，不执行 stage，也不形成 native 或全量 CI 资格。

## 最终目录与无循环哈希

目录层次为 `hosts/<host>/sources/<完整 commit>/validation/…` 或 `packages/…`，另有 import archive 和 transfer 记录。派生文件为：

| 文件 | 契约 |
| --- | --- |
| `record-index.json` | schema `trnm-account-authorization-delivery-record-index-v1`；逐记录原结果分类、四份 receipt 的 SHA、原始其他文件、来源分组、未完成项、导入校验和限制 |
| `binary-identities.json` | schema `trnm-account-authorization-recorded-binary-identities-v1`；原测量值及其证据文件／JSON pointer，无新测量或执行声明 |
| `manifest.json` | schema `trnm-account-authorization-delivery-manifest-v1`；全部 payload 与派生 index 的相对 POSIX 路径、尺寸、SHA-256；原路径和 stat 只描述来源 |
| `manifest.sha256` | 仅哈希完整 `manifest.json` 字节；该 sidecar 与 manifest 自身都不进入 manifest 文件列表 |

`record-index.json` 记录的 payload digest 仅绑定排序后的 `{path, bytes, sha256}` 表，覆盖 raw、support、helper、plan 和 owner 写好的 README；不包含派生 index／manifest／seal。manifest 再绑定派生 index，sidecar 最后绑定 manifest，**没有自我哈希循环**。helper 始终写 `full_ci_acceptance_granted=false`、`production_qualification_granted=false`、`whole_chain_pq_qualification_granted=false`；收集证据不授予这些资格。

## 最后执行顺序

1. primary、repository-truth、full Rust 和原 Node incomplete 包已按实际字节核验；原 Node 使用专门的 `desktop-node-incomplete-evidence-export-v1` schema。继续等待独立 `/data` Node 包的四条真实终态，采用普通 `desktop-primary-evidence-export-v1` schema、空 member prefix 和 `primary/validation/<Z>` 布局。把真实 archive／transfer 哈希及必要元数据填入计划；在完整本地核验前，不将请求参数、job 请求已提交或远端报告的哈希当成已经收齐。
2. root 根据最终 receipts 写 `/workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-README.md`。注明测试源始终是 Z；以后只增加 evidence 的提交不能倒算成已经执行了那个新提交的测试。报告本轮 M06／Node／完整 lane 的准确范围和所有保留失败，明确原 full Rust baseline FAIL、独立 Node 范围与未到达的 oracle／release 步骤，保留五项生产资格缺口。
3. 运行只读 inspect；输出名称每次使用新的编号。它只读原证据并写仓库外报告：

```bash
python3 /workspace/scratch/a4188f5c86b5/coordination/prepare_delivery_evidence.py \
  --plan /workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-plan.json \
  --readme /workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-README.md \
  --inspect-report /workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-inspection-final-1.json
```

4. 审阅全部 `staging_blockers`、按 host/source 分组的结果、完整文件大小与哈希、binary identity 范围、旧 FAIL 保留和 README。若计划或任何输入变化，重新 inspect。以下命令中的占位字符串必须换成刚审阅的 `payload_sha256`；helper 会拒绝任何不同的 payload：

```bash
python3 /workspace/scratch/a4188f5c86b5/coordination/prepare_delivery_evidence.py \
  --plan /workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-plan.json \
  --readme /workspace/scratch/a4188f5c86b5/coordination/delivery-evidence-README.md \
  --expected-payload-sha256 EXPECTED_SHA256_FROM_REVIEWED_INSPECTION \
  --stage /workspace/scratch/a4188f5c86b5/delivery-staging/pon-account-authorization-boundary-20261111
```

5. helper 在复制后逐字节回读、复核原输入仍未改变，最后写 manifest 和 seal。root 再把整个 staging 目录纳入未来的 `evidence/pon-account-authorization-boundary-20261111`，核对最终 diff 仅包含该证据目录。Git preflight、commit／push 和任何后续门禁仍由 root 按项目原规则处理；helper 不替代或修改它们。

本阶段没有执行步骤 4 的 staging 命令，没有生成最终证据目录，也没有把当前 inspection 的缺包状态称作测试失败或通过。
